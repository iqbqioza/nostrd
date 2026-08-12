//! NIP-26: Delegated Event Signing.
//!
//! A `delegation` tag `["delegation", <pubkey>, <conditions>, <sig>]` lets a
//! delegator authorize another key to publish events matching the conditions.

use secp256k1::Secp256k1;
use sha2::{Digest, Sha256};

use crate::event::Event;

pub const DELEGATION_TAG: &str = "delegation";

/// Returns `[delegator_pubkey, conditions, sig]` when a delegation tag exists.
pub fn delegation(event: &Event) -> Option<[&str; 3]> {
    event.tags.iter().find_map(|t| {
        if t.len() == 4 && t[0] == DELEGATION_TAG {
            Some([t[1].as_str(), t[2].as_str(), t[3].as_str()])
        } else {
            None
        }
    })
}

/// Evaluates delegation conditions such as `kind=1&created_at<1682500000`.
pub fn conditions_allow(conditions: &str, kind: u64, created_at: u64) -> bool {
    conditions.split('&').all(|cond| {
        let cond = cond.trim();
        if cond.is_empty() {
            return true;
        }
        if let Some(value) = cond.strip_prefix("kind=") {
            return value
                .split('|')
                .any(|k| k.parse::<u64>().map(|k| k == kind).unwrap_or(false));
        }
        for (op, rhs) in [
            ("created_at>=" as &str, ">="),
            ("created_at<=", "<="),
            ("created_at>", ">"),
            ("created_at<", "<"),
        ] {
            if let Some(value) = cond.strip_prefix(op) {
                if let Ok(value) = value.parse::<u64>() {
                    return match rhs {
                        ">=" => created_at >= value,
                        "<=" => created_at <= value,
                        ">" => created_at > value,
                        _ => created_at < value,
                    };
                }
                return false;
            }
        }
        false
    })
}

/// Verifies a delegation tag when present. Events without a delegation tag
/// are always accepted (they are signed by their own key).
pub fn verify(event: &Event, secp: &Secp256k1<secp256k1::All>) -> bool {
    let Some([delegator, conditions, sig]) = delegation(event) else {
        return true;
    };
    let Ok(delegator_pk) = hex::decode(delegator) else {
        return false;
    };
    let Ok(sig) = hex::decode(sig) else {
        return false;
    };
    if sig.len() != 64 {
        return false;
    }
    let payload = format!("nostr:delegation:{delegator}:{conditions}");
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    let message: [u8; 32] = hasher.finalize().into();
    let Ok(pk) = secp256k1::XOnlyPublicKey::from_slice(&delegator_pk) else {
        return false;
    };
    let Ok(sig) = secp256k1::schnorr::Signature::from_slice(&sig) else {
        return false;
    };
    secp.verify_schnorr(&sig, &message, &pk).is_ok()
        && conditions_allow(conditions, event.kind, event.created_at)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conditions() {
        assert!(conditions_allow("kind=1", 1, 1_600_000_000));
        assert!(!conditions_allow("kind=1", 2, 1_600_000_000));
        assert!(conditions_allow("kind=1|2", 2, 1_600_000_000));
        assert!(conditions_allow("created_at<1700000000", 1, 1_600_000_000));
        assert!(!conditions_allow("created_at<1600000000", 1, 1_600_000_000));
        assert!(conditions_allow(
            "kind=1&created_at>1500000000",
            1,
            1_600_000_000
        ));
    }

    #[test]
    fn no_delegation_tag_accepted() {
        let ev = Event {
            id: "a".repeat(64),
            pubkey: "b".repeat(64),
            created_at: 1,
            kind: 1,
            tags: vec![],
            content: String::new(),
            sig: "c".repeat(128),
        };
        let secp = Secp256k1::new();
        assert!(verify(&ev, &secp));
    }
}
