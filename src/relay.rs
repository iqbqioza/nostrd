use std::sync::Arc;

use secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};
use tokio::sync::{RwLock, broadcast, mpsc};

use crate::config::{AccessControl, Config};
use crate::db::{DbClient, PutOutcome};
use crate::event::Event;
use crate::nips::nip29::{self, GroupStore};
use crate::nips::nip43::{self, RoleStore};
use crate::nips::{nip01, nip09, nip13, nip26, nip62, nip70};
use crate::stats::{Stats, unix_now};

pub struct Relay {
    pub config: Arc<RwLock<Config>>,
    pub access: Arc<RwLock<AccessControl>>,
    pub db: DbClient,
    pub stats: Arc<Stats>,
    /// Batched live events: the bus task accumulates events and broadcasts
    /// `Arc<Vec<Event>>` batches so that idle connections wake up once per
    /// batch instead of once per event.
    pub live: broadcast::Sender<Arc<Vec<Event>>>,
    live_tx: mpsc::Sender<Event>,
    live_rx: Option<mpsc::Receiver<Event>>,
    live_batch_interval_ms: u64,
    live_batch_size: usize,
    pub groups: Arc<RwLock<GroupStore>>,
    /// NIP-43 role definitions and member assignments.
    pub roles: Arc<RwLock<RoleStore>>,
    /// The relay's own keypair (from `relay.private_key`), used to sign
    /// NIP-29 and NIP-43 relay-generated events.
    key: Option<Keypair>,
    secp: Secp256k1<secp256k1::All>,
}

impl Relay {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: Arc<RwLock<Config>>,
        db: DbClient,
        stats: Arc<Stats>,
        private_key_hex: &str,
        live_buffer: usize,
        live_batch_interval_ms: u64,
        live_batch_size: usize,
    ) -> Relay {
        let (live, _) = broadcast::channel(4096);
        let (live_tx, live_rx) = mpsc::channel(live_buffer.max(16));
        let live_batch_interval_ms = live_batch_interval_ms.clamp(1, 1000);
        let live_batch_size = live_batch_size.max(1);
        let secp = Secp256k1::new();
        let key = if private_key_hex.is_empty() {
            None
        } else {
            match hex::decode(private_key_hex) {
                Ok(bytes) if bytes.len() == 32 => Keypair::from_seckey_slice(&secp, &bytes).ok(),
                _ => {
                    log::warn!("invalid relay.private_key: ignoring");
                    None
                }
            }
        };
        Relay {
            config,
            access: Arc::new(RwLock::new(AccessControl::default())),
            db,
            stats,
            live,
            live_tx,
            live_rx: Some(live_rx),
            live_batch_interval_ms,
            live_batch_size,
            groups: Arc::new(RwLock::new(GroupStore::default())),
            roles: Arc::new(RwLock::new(RoleStore::default())),
            key,
            secp,
        }
    }

    /// Spawns the live batching task. Must be called once, after the relay
    /// is created.
    pub fn start_live_bus(&mut self) {
        let Some(mut rx) = self.live_rx.take() else {
            return;
        };
        let tx = self.live.clone();
        let interval_ms = self.live_batch_interval_ms;
        let batch_size = self.live_batch_size;
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut batch: Vec<Event> = Vec::with_capacity(batch_size);
            let flush = |batch: &mut Vec<Event>| {
                if batch.is_empty() {
                    return;
                }
                let _ = tx.send(Arc::new(std::mem::take(batch)));
            };
            loop {
                tokio::select! {
                    event = rx.recv() => match event {
                        Some(event) => {
                            batch.push(event);
                            if batch.len() >= batch_size {
                                flush(&mut batch);
                            }
                        }
                        None => {
                            flush(&mut batch);
                            return;
                        }
                    },
                    _ = interval.tick() => flush(&mut batch),
                }
            }
        });
    }

    /// Queues an event for live delivery to subscribers. The event is
    /// dropped (never stored) when the live buffer is full, as it remains
    /// available through subscriptions.
    pub fn broadcast(&self, event: Event) {
        let _ = self.live_tx.try_send(event);
    }

    /// Hex pubkey of the relay's own key, if configured.
    pub fn relay_pubkey(&self) -> Option<String> {
        self.key
            .as_ref()
            .map(|keypair| XOnlyPublicKey::from_keypair(keypair).0.to_string())
    }

    pub fn secp(&self) -> &Secp256k1<secp256k1::All> {
        &self.secp
    }

    pub fn has_relay_key(&self) -> bool {
        self.key.is_some()
    }

    /// Validates and stores an event. Returns the storage outcome and, when the
    /// event was accepted, the event to broadcast.
    pub async fn accept_event(
        &self,
        event: Event,
        authed: Option<String>,
    ) -> (PutOutcome, Option<Arc<Event>>) {
        let now = unix_now();
        let cfg = self.config.read().await;
        let access = self.access.read().await;

        if let Err(reason) = self.validate(&cfg, &access, &event, now, authed.as_deref()) {
            self.stats.bump(&self.stats.events_rejected, 1);
            return (PutOutcome::Invalid(reason), None);
        }

        // NIP-62: request to vanish — delete everything by this pubkey and
        // never accept anything from it again.
        if cfg.nip_enabled(62)
            && nip62::is_vanish(&event)
            && nip62::targets_us(
                &event,
                &cfg.server.host,
                cfg.server.port,
                &cfg.relay.public_url,
            )
            && let Some(pubkey) = event.pubkey_bytes()
        {
            let pubkey_hex = hex::encode(pubkey);
            drop(cfg);
            drop(access);
            let removed = self.db.apply_vanish(pubkey).await;
            self.stats.bump(&self.stats.events_deleted, removed as u64);
            // Remove the pubkey from every NIP-29 group (its moderation
            // events were deleted along with everything else).
            if self.config.read().await.nip_enabled(29) {
                let mut groups = self.groups.write().await;
                for group in groups.groups.values_mut() {
                    group.members.remove(&pubkey_hex);
                }
            }
            return (PutOutcome::Stored, None);
        }

        // NIP-43: join requests carry an invite code, which this relay never
        // issues; every claim therefore fails (NIP-43 mandates an OK reply).
        if cfg.nip_enabled(43) && event.kind == 28934 {
            return (
                PutOutcome::Invalid("restricted: this relay does not issue invite codes".into()),
                None,
            );
        }

        // NIP-29: group write access control.
        if cfg.nip_enabled(29) {
            // Group metadata events (39000-39005) MUST be created and signed
            // by the relay's own key; events signed by anyone else are
            // rejected.
            if (nip29::GROUP_META..=nip29::GROUP_PINS).contains(&event.kind)
                && Some(event.pubkey.as_str()) != self.relay_pubkey().as_deref()
            {
                return (
                    PutOutcome::Invalid(
                        "blocked: group metadata must be published by the relay".into(),
                    ),
                    None,
                );
            }
            if nip29::group_id(&event).is_some() {
                // Late publication prevention for group events.
                if cfg.limits.group_late_publish_secs > 0
                    && event
                        .created_at
                        .saturating_add(cfg.limits.group_late_publish_secs)
                        < now
                {
                    return (
                        PutOutcome::Invalid("invalid: event is too old for this group".into()),
                        None,
                    );
                }
                let groups = self.groups.read().await;
                if let Err(reason) = groups.validate_write(&event) {
                    return (PutOutcome::Invalid(reason), None);
                }
                if !nip29::previous_tags(&event).is_empty() {
                    for prefix in nip29::previous_tags(&event) {
                        let Ok(prefix) = hex::decode(&prefix) else {
                            return (
                                PutOutcome::Invalid("invalid: malformed previous tag".into()),
                                None,
                            );
                        };
                        if !prefix.is_empty() && !self.db.event_id_prefix_exists(&prefix).await {
                            return (
                                PutOutcome::Invalid(
                                    "invalid: unknown previous tag reference".into(),
                                ),
                                None,
                            );
                        }
                    }
                }
            }
        }

        let outcome = self.db.put(event.clone(), now).await;
        let groups_enabled = cfg.nip_enabled(29);
        let roles_enabled = cfg.nip_enabled(43);
        drop(cfg);
        drop(access);

        match outcome {
            PutOutcome::Stored | PutOutcome::Replaced => {
                self.stats.bump(&self.stats.events_accepted, 1);
                if self.config.read().await.nip_enabled(9) && event.kind == nip09::DELETION_KIND {
                    let removed = self
                        .db
                        .apply_deletion(
                            nip09::deletion_targets(&event),
                            nip09::deletion_addresses(&event),
                            Some(event.pubkey.clone()),
                            event.created_at,
                        )
                        .await;
                    self.stats.bump(&self.stats.events_deleted, removed as u64);
                }
                if roles_enabled && event.kind == nip43::LEAVE {
                    // NIP-43: leave requests update the member list.
                    self.apply_leave_request(&event).await;
                }
                let is_group_event = groups_enabled
                    && ((nip29::MOD_MIN..=nip29::MOD_MAX).contains(&event.kind)
                        || event.kind == nip29::JOIN
                        || event.kind == nip29::LEAVE);
                if is_group_event {
                    self.apply_group_event(&event, now).await;
                }
                self.broadcast(event.clone());
                let arc = Arc::new(event);
                (outcome, Some(arc))
            }
            PutOutcome::Duplicate => {
                self.stats.bump(&self.stats.events_duplicate, 1);
                (outcome, None)
            }
            other => {
                self.stats.bump(&self.stats.events_rejected, 1);
                (other, None)
            }
        }
    }

    /// Applies a stored NIP-29 event to the group state and publishes the
    /// relay-generated metadata events.
    async fn apply_group_event(&self, event: &Event, now: u64) {
        let relay_pubkey = self.relay_pubkey().unwrap_or_default();
        // Relay-generated events are stamped strictly after the event that
        // triggered them so that a startup rebuild replays them in the
        // correct order even when everything happened within the same second.
        let generated = self.groups.write().await.apply(
            event,
            &relay_pubkey,
            now.max(event.created_at.saturating_add(1)),
            self.has_relay_key(),
        );

        if event.kind == 9005 {
            // Group moderation delete-event: admins may delete any event.
            let removed = self
                .db
                .apply_deletion(nip29::delete_targets(event), vec![], None, u64::MAX)
                .await;
            self.stats.bump(&self.stats.events_deleted, removed as u64);
        }

        for mut ev in generated {
            self.store_relay_event(&mut ev).await;
        }
    }

    // ----- NIP-43 roles -----

    /// Signs, stores and broadcasts a relay-generated event. For replaceable
    /// or addressable kinds the event is stamped strictly newer than the
    /// stored version so that NIP-01's same-timestamp tie-break (lowest id
    /// wins) can never keep an older version.
    async fn store_relay_event(&self, event: &mut Event) -> bool {
        let Some(keypair) = &self.key else {
            return false;
        };
        if (crate::nips::nip01::is_replaceable_kind(event.kind)
            || crate::nips::nip33::is_param_replaceable_kind(event.kind))
            && let Some(old_created) = self
                .db
                .replaceable_created_at(event.kind, &event.pubkey, &relay_dtag(event))
                .await
        {
            event.created_at = event.created_at.max(old_created.saturating_add(1));
        }
        if nip01::sign(event, keypair, &self.secp).is_err() {
            return false;
        }
        let now = unix_now();
        let outcome = self.db.put(event.clone(), now).await;
        if matches!(outcome, PutOutcome::Stored | PutOutcome::Replaced) {
            self.broadcast(event.clone());
            true
        } else {
            false
        }
    }

    /// Signs, stores and broadcasts a relay-generated event.
    async fn publish_relay_event(&self, mut event: Event) {
        let _ = self.store_relay_event(&mut event).await;
    }

    /// Publishes the current membership list and an add/remove user event.
    async fn publish_membership(&self, change: Option<(bool, String)>) {
        let Some(relay_pubkey) = self.relay_pubkey() else {
            return;
        };
        let now = unix_now();
        let (add, pubkey) = match change {
            Some((add, pubkey)) => (add, Some(pubkey)),
            None => (false, None),
        };
        let events = {
            let roles = self.roles.read().await;
            let mut events = vec![roles.membership_event(&relay_pubkey, now)];
            if let Some(pubkey) = pubkey {
                events.push(if add {
                    roles.add_user_event(&pubkey, &relay_pubkey, now)
                } else {
                    roles.remove_user_event(&pubkey, &relay_pubkey, now)
                });
            }
            events
        };
        for event in events {
            self.publish_relay_event(event).await;
        }
    }

    /// NIP-43 role management, used by the NIP-86 RPC methods.
    pub async fn create_role(
        &self,
        id: &str,
        label: &str,
        description: &str,
        color: &str,
        order: Option<i64>,
    ) -> bool {
        if !self.config.read().await.nip_enabled(43) || self.key.is_none() {
            return false;
        }
        let relay_pubkey = self.relay_pubkey().unwrap_or_default();
        let event = {
            let mut roles = self.roles.write().await;
            roles.create(id, label, description, color, order);
            roles.role_event(id, &relay_pubkey, unix_now())
        };
        self.publish_relay_event(event).await;
        true
    }

    pub async fn delete_role(&self, id: &str) -> bool {
        if !self.config.read().await.nip_enabled(43) || self.key.is_none() {
            return false;
        }
        let removed = self.roles.write().await.delete(id);
        if removed {
            self.publish_membership(None).await;
        }
        removed
    }

    pub async fn assign_role(&self, pubkey: &str, role: &str) -> bool {
        if !self.config.read().await.nip_enabled(43) || self.key.is_none() {
            return false;
        }
        let assigned = self.roles.write().await.assign(pubkey, role);
        if assigned {
            self.publish_membership(Some((true, pubkey.to_string())))
                .await;
        }
        assigned
    }

    pub async fn unassign_role(&self, pubkey: &str, role: &str) -> bool {
        if !self.config.read().await.nip_enabled(43) || self.key.is_none() {
            return false;
        }
        let changed = self.roles.write().await.unassign(pubkey, role);
        if changed {
            self.publish_membership(Some((false, pubkey.to_string())))
                .await;
        }
        changed
    }

    /// NIP-43 leave request: removes the user from the member list and
    /// republishes it with a remove-user event.
    async fn apply_leave_request(&self, event: &Event) {
        let removed = self.roles.write().await.remove_pubkey(&event.pubkey);
        if removed {
            self.publish_membership(Some((false, event.pubkey.clone())))
                .await;
        }
    }

    fn validate(
        &self,
        cfg: &Config,
        access: &AccessControl,
        event: &Event,
        now: u64,
        authed: Option<&str>,
    ) -> std::result::Result<(), String> {
        let limits = &cfg.limits;

        // NIP-01: kind is an integer between 0 and 65535.
        if event.kind > 65535 {
            return Err("invalid: kind out of range".into());
        }
        // NIP-01: each tag is an array of one or more strings.
        if event.tags.iter().any(|t| t.is_empty()) {
            return Err("invalid: empty tag".into());
        }

        if event.content.len() > limits.max_content_bytes {
            return Err("invalid: content too large".into());
        }
        if event.tags.len() > limits.max_tags {
            return Err("invalid: too many tags".into());
        }
        if event
            .tags
            .iter()
            .any(|t| t.iter().any(|v| v.len() > limits.max_tag_value_bytes))
        {
            return Err("invalid: tag value too large".into());
        }
        // Events with a future created_at (beyond the tolerated skew) are
        // dropped silently with the NIP-01 `mute:` prefix instead of being
        // rejected as invalid.
        if event.created_at > now.saturating_add(limits.max_created_at_future) {
            return Err("mute: event creation date is in the future".into());
        }

        // Security: events carrying secret key material (bech32 `nsec1`
        // strings) are dropped silently as well.
        let leaks_secret = contains_secret_key(&event.content)
            || event
                .tags
                .iter()
                .any(|t| t.iter().any(|v| contains_secret_key(v)));
        if leaks_secret {
            return Err("mute: event contains secret key material".into());
        }

        if !access.allows_pubkey(&event.pubkey) {
            return Err("blocked: pubkey not allowed".into());
        }
        if !access.allows_kind(event.kind) {
            return Err("blocked: kind not allowed".into());
        }

        nip01::verify(event, &self.secp)
            .map_err(|_| "invalid: signature verification failed".to_string())?;

        if cfg.nip_enabled(26) && !nip26::verify(event, &self.secp) {
            return Err("invalid: delegation failed".into());
        }

        if cfg.nip_enabled(13)
            && limits.require_pow > 0
            && !nip13::verify(event, limits.require_pow)
        {
            return Err("pow: difficulty requirement not reached".into());
        }

        // NIP-42: auth events are ephemeral and must never be stored or
        // broadcast.
        if cfg.nip_enabled(42) && event.kind == crate::nips::nip42::AUTH_KIND {
            return Err("invalid: authentication events cannot be published".into());
        }

        if cfg.nip_enabled(42) && cfg.server.require_auth && authed.is_none() {
            return Err("auth-required: this relay requires authentication".into());
        }

        if cfg.nip_enabled(70) && nip70::is_protected(event) && authed.is_none() {
            return Err("auth-required: protected events require authentication".into());
        }

        Ok(())
    }
}

/// The `d` tag value of an event, or an empty string (the identifier of
/// regular replaceable events).
fn relay_dtag(event: &Event) -> String {
    event
        .tags
        .iter()
        .find(|t| t.len() >= 2 && t[0] == "d")
        .map(|t| t[1].clone())
        .unwrap_or_default()
}

/// A bech32-encoded nsec secret key is `nsec1` followed by 58 characters
/// (52 data characters plus a 6-character checksum), 63 characters in total.
const NSEC_PREFIX: &[u8; 5] = b"nsec1";
const NSEC_BODY_LEN: usize = 58;

/// Bech32 data character set (lowercase).
fn is_bech32_char(byte: u8) -> bool {
    b"qpzry9x8gf2tvdw0s3jn54khce6mua7l".contains(&byte)
}

/// Returns `true` when the text contains a secret key: an `nsec1` prefix
/// (case-insensitive) followed by at least 58 bech32 characters.
fn contains_secret_key(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i + NSEC_PREFIX.len() + NSEC_BODY_LEN <= bytes.len() {
        if bytes[i..i + NSEC_PREFIX.len()]
            .iter()
            .zip(NSEC_PREFIX)
            .all(|(b, p)| b.to_ascii_lowercase() == *p)
            && bytes[i + NSEC_PREFIX.len()..i + NSEC_PREFIX.len() + NSEC_BODY_LEN]
                .iter()
                .all(|b| is_bech32_char(*b))
        {
            return true;
        }
        i += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::contains_secret_key;

    #[test]
    fn nsec_detection() {
        // A real-looking 63-character nsec string.
        let nsec = "nsec1";
        let body: String = (0..58)
            .map(|i| "qpzry9x8gf2tvdw0s3jn54khce6mua7l".as_bytes()[i % 32] as char)
            .collect();
        let key = format!("{nsec}{body}");
        assert_eq!(key.len(), 63);
        assert!(contains_secret_key(&format!("look at my key {key} here")));
        assert!(contains_secret_key(&key));

        // Embedded in tags.
        assert!(contains_secret_key(&format!("prefix-{key}-suffix")));

        // Too short: not a key.
        assert!(!contains_secret_key("nsec1"));
        assert!(!contains_secret_key(&format!("nsec1{}", &body[..40])));

        // Invalid bech32 characters are not matched.
        let mut bad = body.clone().into_bytes();
        bad[0] = b'B'; // 'B' is not in the bech32 charset
        let bad: String = bad.into_iter().map(|b| b as char).collect();
        assert!(!contains_secret_key(&format!("nsec1{bad}")));

        // Case-insensitive prefix.
        assert!(contains_secret_key(&format!("NSEC1{body}")));
    }
}
