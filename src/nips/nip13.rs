//! NIP-13: Proof of Work.
//!
//! The difficulty of an event is the number of leading zero bits of its
//! NIP-01 id (NIP-13 defines this as the difficulty). Miners adjust a
//! `nonce` tag and recompute the id until it starts with the desired number
//! of zero bits; the third entry of the tag may commit to the target
//! difficulty, which lets *clients* reject lucky low-difficulty events.
//! For relays the requirement is only the id's leading zero bits.

use crate::event::Event;

/// Count of leading zero bits in a 256-bit digest. A `u16` (not `u8`):
/// a fully zero digest counts 256 leading zero bits, which would overflow
/// an 8-bit counter (and panic in debug builds).
pub fn leading_zero_bits(digest: &[u8]) -> u16 {
    let mut count = 0u16;
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

/// Returns `true` when the event's id has at least `required` leading zero
/// bits. The committed nonce target is a client-side convention and is not
/// part of the relay's requirement.
pub fn verify(event: &Event, required: u8) -> bool {
    let Some(id) = event.id_bytes() else {
        return false;
    };
    leading_zero_bits(&id) >= required as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event_with_nonce(target: u8) -> Event {
        Event {
            id: "a".repeat(64),
            pubkey: "b".repeat(64),
            created_at: 1_600_000_000,
            kind: 1,
            tags: vec![vec!["nonce".into(), "42".into(), target.to_string()]],
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
        let mut ev = event_with_nonce(target);
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
    fn id_difficulty_is_checked() {
        // 12 leading zero bits: passes at required 12, fails at 13.
        let ev = event_with_id(12, 20);
        assert!(verify(&ev, 12));
        assert!(!verify(&ev, 13));
        // The committed target is a client-side convention: a note with the
        // required id difficulty passes even without a nonce tag, and the
        // committed target does not substitute for the actual difficulty.
        let mut no_nonce = ev.clone();
        no_nonce.tags.clear();
        assert!(verify(&no_nonce, 12));
        let lucky = event_with_id(4, 40);
        assert!(!verify(&lucky, 12));
        assert!(verify(&lucky, 4));
    }
}
