//! The relay: event acceptance (single and batched), live
//! broadcasting, NIP-29/NIP-43 group and role state, and the
//! relay-generated event publishing. Event validation lives in
//! [`validate`].

mod roles;
mod validate;

use std::sync::Arc;

use secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};
use tokio::sync::{RwLock, broadcast, mpsc};

use crate::config::{AccessControl, Config};
use crate::db::{DbClient, PutOutcome};
use crate::event::Event;
use crate::nips::nip09;
use crate::nips::nip29::{self, GroupStore};
use crate::nips::nip43::{self, RoleStore};
use crate::stats::Stats;
use crate::util::unix_now;

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

/// Tuning of the live fan-out bus.
#[derive(Debug, Clone, Copy)]
pub struct LiveBusConfig {
    /// Bound on the queue of events waiting to be broadcast.
    pub buffer: usize,
    /// The bus flushes at least this often (milliseconds).
    pub batch_interval_ms: u64,
    /// Maximum events per flushed batch.
    pub batch_size: usize,
}

impl Relay {
    pub async fn new(
        config: Arc<RwLock<Config>>,
        db: DbClient,
        stats: Arc<Stats>,
        private_key_hex: &str,
        live_bus: LiveBusConfig,
    ) -> Relay {
        let (live, _) = broadcast::channel(4096);
        let (live_tx, live_rx) = mpsc::channel(live_bus.buffer.max(16));
        let live_batch_interval_ms = live_bus.batch_interval_ms.clamp(1, 1000);
        let live_batch_size = live_bus.batch_size.max(1);
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
            // Seed the access control from the config so operator bans and
            // allowlists survive restarts.
            config: Arc::clone(&config),
            access: Arc::new(RwLock::new(config.read().await.access.clone())),
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

    /// Validates and stores a single event. The live path batches events
    /// through [`Self::accept_events_batch`], which falls back to this
    /// method for batches containing group-state events.
    pub async fn accept_event(
        &self,
        event: Event,
        authed: &[String],
        known_prefixes: Option<&std::collections::HashSet<Vec<u8>>>,
    ) -> (PutOutcome, Option<Arc<Event>>) {
        let now = unix_now();
        let cfg = self.config.read().await;
        let access = self.access.read().await;

        match self
            .precheck(&cfg, &access, &event, now, authed, known_prefixes)
            .await
        {
            crate::relay::validate::Precheck::Reject(reason) => {
                self.stats.bump(&self.stats.events_rejected, 1);
                return (PutOutcome::Invalid(reason), None);
            }
            crate::relay::validate::Precheck::Vanish => {
                // NIP-62: delete everything by this pubkey and never
                // accept anything from it again.
                let Some(pubkey) = event.pubkey_bytes() else {
                    return (PutOutcome::Invalid("invalid: bad pubkey".into()), None);
                };
                drop(cfg);
                drop(access);
                self.vanish_pubkey(pubkey).await;
                return (PutOutcome::Stored, None);
            }
            crate::relay::validate::Precheck::Accept => {}
        }

        // First-seen trust check: a pubkey's first accepted event records
        // its arrival; events from pubkeys first seen within the configured
        // window are rejected (spam from freshly created accounts).
        if cfg.limits.new_pubkey_min_age_secs > 0
            && let Some(pubkey) = event.pubkey_bytes()
        {
            let first_seens = self.db.touch_first_seen_batch(vec![(pubkey, now)]).await;
            let Some(&(created, first_seen)) = first_seens.first() else {
                // The database is unavailable or overloaded: fail closed.
                self.stats.bump(&self.stats.events_rejected, 1);
                return (
                    PutOutcome::Invalid("error: database unavailable".into()),
                    None,
                );
            };
            if !created && now.saturating_sub(first_seen) < cfg.limits.new_pubkey_min_age_secs {
                self.stats.bump(&self.stats.events_rejected, 1);
                return (
                    PutOutcome::Invalid("restricted: your account is too new".into()),
                    None,
                );
            }
        }

        let outcome = self.db.put(event.clone(), now).await;
        let nip_flags = (cfg.nip_enabled(9), cfg.nip_enabled(43), cfg.nip_enabled(29));
        drop(cfg);
        drop(access);

        match outcome {
            PutOutcome::Stored | PutOutcome::Replaced | PutOutcome::Ephemeral => {
                self.stats.bump(&self.stats.events_accepted, 1);
                self.after_put(&event, now, nip_flags.0, nip_flags.1, nip_flags.2)
                    .await;
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

    /// Accepts a batch of events from one connection, returning the outcome
    /// of each. The database layer commits the whole batch in a single write
    /// transaction, so the commit cost is paid once per batch instead of
    /// once per event. Ordering and per-event replies are preserved.
    pub async fn accept_events_batch(
        &self,
        events: Vec<Event>,
        authed: &[String],
    ) -> Vec<(String, PutOutcome)> {
        // Group moderation events mutate the in-memory group state; their
        // effects must be visible to later events of the same batch (e.g. a
        // put-user followed by the new member's post), so batches containing
        // them are processed sequentially.
        if events.iter().any(|e| {
            nip29::group_id(e).is_some()
                || (nip29::MOD_MIN..=nip29::MOD_MAX).contains(&e.kind)
                || e.kind == nip29::JOIN
                || e.kind == nip29::LEAVE
        }) {
            // Check every `previous` tag reference of the whole batch in one
            // database round trip: a single event must not be able to
            // amplify into thousands of database requests.
            let mut prefixes: Vec<Vec<u8>> = Vec::new();
            for event in &events {
                for prefix in nip29::previous_tags(event) {
                    let Ok(prefix) = hex::decode(&prefix) else {
                        continue;
                    };
                    if !prefix.is_empty() && !prefixes.iter().any(|p| p == &prefix) {
                        prefixes.push(prefix);
                    }
                }
            }
            let known: std::collections::HashSet<Vec<u8>> = if prefixes.is_empty() {
                std::collections::HashSet::new()
            } else {
                let existing = self.db.prefixes_exist(prefixes.clone()).await;
                prefixes
                    .into_iter()
                    .zip(existing)
                    .filter_map(|(p, exists)| exists.then_some(p))
                    .collect()
            };
            let mut out = Vec::with_capacity(events.len());
            for event in events {
                let id = event.id.clone();
                let (outcome, _) = self.accept_event(event, authed, Some(&known)).await;
                out.push((id, outcome));
            }
            return out;
        }
        let now = unix_now();
        let cfg = self.config.read().await;
        let access = self.access.read().await;
        let mut results: Vec<(String, PutOutcome)> = Vec::with_capacity(events.len());
        let mut puts: Vec<Event> = Vec::new();
        let mut put_slots: Vec<usize> = Vec::new();
        let mut vanishes: Vec<(String, Event)> = Vec::new();

        // This path only sees events without group involvement: batches
        // containing group events (an `h` tag or a moderation/join/leave
        // kind) are routed to the sequential [`Self::accept_event`] path
        // above. The shared `precheck` still runs for every event.
        for event in events {
            let id = event.id.clone();
            match self
                .precheck(&cfg, &access, &event, now, authed, None)
                .await
            {
                crate::relay::validate::Precheck::Reject(reason) => {
                    self.stats.bump(&self.stats.events_rejected, 1);
                    results.push((id, PutOutcome::Invalid(reason)));
                    continue;
                }
                crate::relay::validate::Precheck::Vanish => {
                    vanishes.push((id, event));
                    continue;
                }
                crate::relay::validate::Precheck::Accept => {}
            }
            put_slots.push(results.len());
            results.push((String::new(), PutOutcome::Invalid(String::new())));
            puts.push(event);
        }

        let groups_enabled = cfg.nip_enabled(29);
        let roles_enabled = cfg.nip_enabled(43);
        let nip9_enabled = cfg.nip_enabled(9);
        let min_age = cfg.limits.new_pubkey_min_age_secs;
        drop(cfg);
        drop(access);

        // First-seen trust check: pubkeys first seen within the configured
        // window may not publish (their first event established the
        // account). Performed in one database round trip for the batch.
        if min_age > 0 && !puts.is_empty() {
            let entries: Vec<([u8; 32], u64)> = puts
                .iter()
                .map(|e| (e.pubkey_bytes().unwrap_or([0u8; 32]), now))
                .collect();
            let first_seens = self.db.touch_first_seen_batch(entries).await;
            if first_seens.len() != puts.len() {
                // The database is unavailable or overloaded: every pending
                // event of the batch fails closed.
                for (event, slot) in puts.into_iter().zip(put_slots) {
                    self.stats.bump(&self.stats.events_rejected, 1);
                    results[slot] = (
                        event.id,
                        PutOutcome::Invalid("error: database unavailable".into()),
                    );
                }
                puts = Vec::new();
                put_slots = Vec::new();
            } else {
                let mut kept = Vec::with_capacity(puts.len());
                let mut kept_slots = Vec::with_capacity(put_slots.len());
                for ((event, slot), (created, first_seen)) in
                    puts.into_iter().zip(put_slots).zip(first_seens)
                {
                    if !created && now.saturating_sub(first_seen) < min_age {
                        self.stats.bump(&self.stats.events_rejected, 1);
                        results[slot] = (
                            event.id,
                            PutOutcome::Invalid("restricted: your account is too new".into()),
                        );
                    } else {
                        kept.push(event);
                        kept_slots.push(slot);
                    }
                }
                puts = kept;
                put_slots = kept_slots;
            }
        }

        let mut outcomes = if puts.is_empty() {
            Vec::new()
        } else {
            self.db
                .put_batch(puts.iter().map(|e| (e.clone(), now)).collect())
                .await
        };
        if outcomes.len() != puts.len() {
            // A timed-out (or failed) request returns no outcomes: every
            // pending event is reported as failed instead of being replied
            // with an empty id.
            outcomes = vec![PutOutcome::Invalid("error: database timeout".into()); puts.len()];
        }

        for ((event, outcome), slot) in puts.into_iter().zip(outcomes).zip(put_slots) {
            let id = event.id.clone();
            match outcome {
                PutOutcome::Stored | PutOutcome::Replaced | PutOutcome::Ephemeral => {
                    self.stats.bump(&self.stats.events_accepted, 1);
                    self.after_put(&event, now, nip9_enabled, roles_enabled, groups_enabled)
                        .await;
                }
                PutOutcome::Duplicate => {
                    self.stats.bump(&self.stats.events_duplicate, 1);
                }
                _ => {
                    self.stats.bump(&self.stats.events_rejected, 1);
                }
            }
            results[slot] = (id, outcome);
        }

        for (id, event) in vanishes {
            if let Some(pubkey) = event.pubkey_bytes() {
                self.vanish_pubkey(pubkey).await;
            }
            results.push((id, PutOutcome::Stored));
        }

        results
    }

    /// Shared side effects of a stored event: NIP-09 deletion handling,
    /// NIP-43 leave requests, NIP-29 group state and the live broadcast.
    async fn after_put(
        &self,
        event: &Event,
        now: u64,
        nip9: bool,
        nip43: bool,
        nip29_enabled: bool,
    ) {
        if nip9 && event.kind == nip09::DELETION_KIND {
            let removed = self
                .db
                .apply_deletion(
                    nip09::deletion_targets(event),
                    nip09::deletion_addresses(event),
                    Some(event.pubkey.clone()),
                    event.created_at,
                )
                .await;
            self.stats.bump(&self.stats.events_deleted, removed as u64);
            // NIP-59: gift wraps are signed by random keys, so their
            // recipient cannot delete them via NIP-09; the relay
            // deletes wraps addressed to the deleter instead.
            if let Some(pubkey) = event.pubkey_bytes() {
                let purged = self.db.delete_gift_wraps_to(pubkey).await;
                self.stats.bump(&self.stats.events_deleted, purged as u64);
            }
        }
        if nip43 && event.kind == nip43::LEAVE {
            // NIP-43: leave requests (ephemeral kinds) update the member
            // list without being stored.
            self.apply_leave_request(event).await;
        }
        let is_group_event = nip29_enabled
            && ((nip29::MOD_MIN..=nip29::MOD_MAX).contains(&event.kind)
                || event.kind == nip29::JOIN
                || event.kind == nip29::LEAVE);
        if is_group_event {
            self.apply_group_event(event, now).await;
        }
        self.broadcast(event.clone());
    }

    /// NIP-62: deletes every event by `pubkey` and removes the pubkey from
    /// every NIP-29 group (its moderation events were deleted along with
    /// everything else).
    async fn vanish_pubkey(&self, pubkey: [u8; 32]) {
        let pubkey_hex = hex::encode(pubkey);
        let removed = self.db.apply_vanish(pubkey).await;
        self.stats.bump(&self.stats.events_deleted, removed as u64);
        if self.config.read().await.nip_enabled(29) {
            let mut groups = self.groups.write().await;
            for group in groups.groups.values_mut() {
                group.members.remove(&pubkey_hex);
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
}

fn relay_dtag(event: &Event) -> String {
    event
        .tags
        .iter()
        .find(|t| t.len() >= 2 && t[0] == "d")
        .map(|t| t[1].clone())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::validate::contains_secret_key;

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
