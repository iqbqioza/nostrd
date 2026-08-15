//! Event acceptance checks: base validation (NIP-01 signatures, limits,
//! NIP-13/26/42/43/70 and access control), the shared [`Precheck`] used by
//! both accept paths, and the nsec-leak detector.

use crate::config::{AccessControl, Config};
use crate::event::Event;
use crate::nips::{nip01, nip13, nip26, nip29, nip43, nip62, nip70};

/// A bech32-encoded nsec secret key is `nsec1` followed by 58 characters
/// (52 data characters plus a 6-character checksum), 63 characters in total.
const NSEC_PREFIX: &[u8; 5] = b"nsec1";
const NSEC_BODY_LEN: usize = 58;

/// Outcome of the shared pre-acceptance checks.
pub(crate) enum Precheck {
    Accept,
    Reject(String),
    /// NIP-62: the event is a valid request to vanish.
    Vanish,
}

impl super::Relay {
    /// Runs the acceptance checks shared by the single and batched accept
    /// paths: base validation, NIP-62 vanish detection, NIP-43 join
    /// rejection and the NIP-29 write-access rules (h tag, relay-signed
    /// metadata, late publication, membership and `previous` references).
    /// `known_prefixes` supplies the batch's pre-fetched `previous` tag
    /// references; `None` falls back to per-reference database lookups.
    pub(crate) async fn precheck(
        &self,
        cfg: &Config,
        access: &AccessControl,
        event: &Event,
        now: u64,
        authed: &[String],
        known_prefixes: Option<&std::collections::HashSet<Vec<u8>>>,
    ) -> Precheck {
        if let Err(reason) = self.validate(cfg, access, event, now, authed) {
            return Precheck::Reject(reason);
        }
        // NIP-62: request to vanish — delete everything by this pubkey.
        if cfg.nip_enabled(62)
            && nip62::is_vanish(event)
            && nip62::targets_us(event, &cfg.relay_identity())
        {
            return Precheck::Vanish;
        }
        // NIP-43: join requests carry an invite code, which this relay
        // never issues; every claim therefore fails (NIP-43 mandates an
        // OK reply).
        if cfg.nip_enabled(43) && event.kind == nip43::JOIN {
            return Precheck::Reject("restricted: this relay does not issue invite codes".into());
        }
        // NIP-29: group action events MUST carry an `h` tag.
        if cfg.nip_enabled(29) && nip29::is_group_action(event) && nip29::group_id(event).is_none()
        {
            return Precheck::Reject("invalid: group events must carry an h tag".into());
        }
        if cfg.nip_enabled(29) {
            // Group metadata events MUST be signed by the relay's own key.
            if (nip29::GROUP_META..=nip29::GROUP_PINS).contains(&event.kind)
                && Some(event.pubkey.as_str()) != self.relay_pubkey().as_deref()
            {
                return Precheck::Reject(
                    "blocked: group metadata must be published by the relay".into(),
                );
            }
            if nip29::group_id(event).is_some() {
                // Late publication prevention for group events.
                if cfg.limits.group_late_publish_secs > 0
                    && event
                        .created_at
                        .saturating_add(cfg.limits.group_late_publish_secs)
                        < now
                {
                    return Precheck::Reject("invalid: event is too old for this group".into());
                }
                let reason = {
                    let groups = self.groups.read().await;
                    groups.validate_write(event).err()
                };
                if let Some(reason) = reason {
                    return Precheck::Reject(reason);
                }
                // NIP-29 `previous` timeline references must exist.
                let mut unknown: Option<&str> = None;
                for prefix in nip29::previous_tags(event) {
                    let Ok(prefix) = hex::decode(&prefix) else {
                        unknown = Some("invalid: malformed previous tag");
                        break;
                    };
                    if !prefix.is_empty() {
                        let exists = match known_prefixes {
                            Some(known) => known.contains(&prefix),
                            None => self.db.event_id_prefix_exists(&prefix).await,
                        };
                        if !exists {
                            unknown = Some("invalid: unknown previous tag reference");
                            break;
                        }
                    }
                }
                if let Some(reason) = unknown {
                    return Precheck::Reject(reason.into());
                }
            }
        }
        Precheck::Accept
    }
}

impl super::Relay {
    pub(crate) fn validate(
        &self,
        cfg: &Config,
        access: &AccessControl,
        event: &Event,
        now: u64,
        authed: &[String],
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

        // NIP-11's `max_content_length` is a count of unicode characters,
        // so the enforcement counts characters (the byte size is bounded by
        // the websocket message limit instead).
        if event.content.chars().count() > limits.max_content_bytes {
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

        nip01::verify(event, self.secp())
            .map_err(|_| "invalid: signature verification failed".to_string())?;

        if cfg.nip_enabled(26) && !nip26::verify(event, self.secp()) {
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

        // NIP-43: role definitions, membership lists and add/remove user
        // events MUST be signed by the relay's own key ("the pubkey
        // specified in the `self` field of the relay's NIP-11 document");
        // events signed by anyone else are rejected.
        if cfg.nip_enabled(43)
            && matches!(
                event.kind,
                nip43::ROLE_DEFINITION
                    | nip43::MEMBERSHIP_LIST
                    | nip43::ADD_USER
                    | nip43::REMOVE_USER
            )
            && Some(event.pubkey.as_str()) != self.relay_pubkey().as_deref()
        {
            return Err("blocked: relay metadata must be published by the relay".into());
        }

        // NIP-43: leave requests must be signed at the time of sending
        // ("created_at MUST be now, plus or minus a few minutes") and MUST
        // carry the NIP-70 `-` tag.
        if cfg.nip_enabled(43) && event.kind == nip43::LEAVE {
            if event.created_at.abs_diff(now) > 600 {
                return Err("invalid: leave request is too old".into());
            }
            if !nip70::is_protected(event) {
                return Err("invalid: leave request must carry a `-` tag".into());
            }
        }

        // NIP-70: reposts must not embed a protected event; relays SHOULD
        // summarily reject such reposts (kind 6 embeds the note JSON in the
        // content, kind 16 embeds replaceable events the same way).
        if cfg.nip_enabled(70)
            && (event.kind == 6 || event.kind == 16)
            && let Ok(embedded) = serde_json::from_str::<Event>(&event.content)
            && nip70::is_protected(&embedded)
        {
            return Err("restricted: repost of a protected event".into());
        }

        if cfg.nip_enabled(42) && cfg.server.require_auth && authed.is_empty() {
            return Err("auth-required: this relay requires authentication".into());
        }

        // NIP-70: protected events may only be published by their author,
        // so the event's own pubkey must be among the authenticated keys.
        if cfg.nip_enabled(70)
            && nip70::is_protected(event)
            && !authed.iter().any(|pk| pk == &event.pubkey)
        {
            return Err(
                "auth-required: protected events may only be published by their author".into(),
            );
        }

        Ok(())
    }
}

fn is_bech32_char(byte: u8) -> bool {
    b"qpzry9x8gf2tvdw0s3jn54khce6mua7l".contains(&byte)
}

/// Returns `true` when the text contains a secret key: an `nsec1` prefix
/// (case-insensitive) followed by at least 58 bech32 characters.
pub(crate) fn contains_secret_key(text: &str) -> bool {
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
