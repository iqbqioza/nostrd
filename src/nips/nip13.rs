//! NIP-13: Proof of Work.
//!
//! The difficulty of an event is the number of leading zero bits of its
//! NIP-01 id. Miners adjust a `nonce` tag `["nonce", <value>, <target>]` and
//! recompute the id until it starts with the desired number of zero bits.
//! The third entry of the tag commits to the target difficulty, which lets
//! relays reject lucky low-difficulty events.

use crate::event::Event;

pub const NONCE_TAG: &str = "nonce";

/// Count of leading zero bits in a 256-bit digest.
pub fn leading_zero_bits(digest: &[u8]) -> u8 {
    let mut count = 0u8;
    'outer: for byte in digest {
        for bit in (0..8).rev() {
            if byte & (1 << bit) == 0 {
                count += 1;
            } else {
                break 'outer;
            }
        }
    }
    count
}

/// Target difficulty committed to by the event's nonce tag.
pub fn pow_target(event: &Event) -> Option<u8> {
    event.tags.iter().find_map(|t| {
        if t.len() >= 3 && t[0] == NONCE_TAG {
            t[2].parse().ok()
        } else {
            None
        }
    })
}

/// Returns `true` when the event's id has at least `required` leading zero
/// bits and the nonce tag commits to a target difficulty of at least
/// `required`.
pub fn verify(event: &Event, required: u8) -> bool {
    let Some(target) = pow_target(event) else {
        return false;
    };
    if target < required {
        return false;
    }
    let Some(id) = event.id_bytes() else {
        return false;
    };
    leading_zero_bits(&id) >= required
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event_with_nonce(nonce: u64, target: u8) -> Event {
        Event {
            id: "a".repeat(64),
            pubkey: "b".repeat(64),
            created_at: 1_600_000_000,
            kind: 1,
            tags: vec![vec![
                NONCE_TAG.into(),
                nonce.to_string(),
                target.to_string(),
            ]],
            content: String::new(),
            sig: "c".repeat(128),
        }
    }

    /// An event whose id has exactly `zero_bits` leading zero bits.
    fn event_with_id(zero_bits: u8, target: u8) -> Event {
        let mut id = [0u8; 32];
        let zero_bytes = zero_bits as usize / 8;
        let remainder = zero_bits as usize % 8;
        if zero_bytes < 32 {
            id[zero_bytes] = if remainder > 0 {
                0x80 >> remainder
            } else {
                0x80
            };
        }
        let mut ev = event_with_nonce(42, target);
        ev.id = hex::encode(id);
        ev
    }

    #[test]
    fn bits() {
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0x80]), 16);
        assert_eq!(leading_zero_bits(&[0x40]), 1);
        assert_eq!(leading_zero_bits(&[0x80]), 0);
    }

    #[test]
    fn tag_parsing() {
        let ev = event_with_nonce(42, 20);
        assert_eq!(pow_target(&ev), Some(20));
    }

    #[test]
    fn no_nonce_fails() {
        let ev = event_with_nonce(42, 20);
        let mut no_nonce = ev.clone();
        no_nonce.tags.clear();
        assert!(!verify(&no_nonce, 1));
    }

    #[test]
    fn id_difficulty_is_checked() {
        // 12 leading zero bits, committed target 20: passes at required 12.
        let ev = event_with_id(12, 20);
        assert!(verify(&ev, 12));
        // ...but fails when more bits are required.
        assert!(!verify(&ev, 13));
        // A lucky id without a sufficient committed target is rejected.
        let lucky = event_with_id(40, 4);
        assert!(!verify(&lucky, 12));
        assert!(verify(&lucky, 4));
    }
}
