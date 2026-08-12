//! NIP-40: Expiration Timestamp.
//!
//! An `expiration` tag carries a unix timestamp after which the event should
//! be removed from storage and queries.

use crate::event::Event;

pub const EXPIRATION_TAG: &str = "expiration";

/// Expiration timestamp of an event, if present.
pub fn expiry(event: &Event) -> Option<u64> {
    event
        .tags
        .iter()
        .find(|t| t.len() >= 2 && t[0] == EXPIRATION_TAG)
        .and_then(|t| t[1].parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event_with(tag: Option<&str>) -> Event {
        let tags = tag
            .map(|v| vec![vec![EXPIRATION_TAG.into(), v.into()]])
            .unwrap_or_default();
        Event {
            id: "a".repeat(64),
            pubkey: "b".repeat(64),
            created_at: 1,
            kind: 1,
            tags,
            content: String::new(),
            sig: "c".repeat(128),
        }
    }

    #[test]
    fn expiry_parsing() {
        assert_eq!(expiry(&event_with(Some("1700000000"))), Some(1_700_000_000));
        assert_eq!(expiry(&event_with(Some("not-a-number"))), None);
        assert_eq!(expiry(&event_with(None)), None);
    }
}
