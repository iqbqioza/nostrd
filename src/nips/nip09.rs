//! NIP-09: Event Deletion.
//!
//! Deletion requests are kind-5 events whose `e` tags reference event ids
//! and whose `a` tags reference addressable events
//! (`<kind>:<pubkey>:<d-identifier>`) to delete. Relays delete referenced
//! events authored by the same pubkey as the deletion request; deletion
//! requests themselves can never be deleted.

use crate::event::Event;

pub const DELETION_KIND: u64 = 5;

/// An `a`-tag address of an addressable (replaceable) event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    pub kind: u64,
    pub pubkey: String,
    pub d: String,
}

/// Event ids referenced by `e` tags of a deletion request.
pub fn deletion_targets(event: &Event) -> Vec<String> {
    event
        .tags
        .iter()
        .filter(|t| t.first().map(String::as_str) == Some("e") && t.len() >= 2)
        .map(|t| t[1].clone())
        .collect()
}

/// Addressable events referenced by `a` tags of a deletion request.
pub fn deletion_addresses(event: &Event) -> Vec<Address> {
    event
        .tags
        .iter()
        .filter(|t| t.first().map(String::as_str) == Some("a") && t.len() >= 2)
        .filter_map(|t| parse_address(&t[1]))
        .collect()
}

fn parse_address(value: &str) -> Option<Address> {
    let mut parts = value.splitn(3, ':');
    let kind = parts.next()?.parse().ok()?;
    let pubkey = parts.next()?.to_string();
    let d = parts.next()?.to_string();
    Some(Address { kind, pubkey, d })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(tags: Vec<Vec<String>>) -> Event {
        Event {
            id: "a".repeat(64),
            pubkey: "b".repeat(64),
            created_at: 1_600_000_000,
            kind: DELETION_KIND,
            tags,
            content: String::new(),
            sig: "c".repeat(128),
        }
    }

    #[test]
    fn targets_from_e_tags() {
        let ev = event(vec![
            vec!["e".into(), "abc".into()],
            vec!["e".into(), "def".into()],
        ]);
        assert_eq!(deletion_targets(&ev), vec!["abc", "def"]);
        let ev = event(vec![vec!["p".into(), "abc".into()]]);
        assert!(deletion_targets(&ev).is_empty());
    }

    #[test]
    fn addresses_from_a_tags() {
        let ev = event(vec![
            vec!["a".into(), "30023:abcd:post-1".into()],
            vec!["a".into(), "garbage".into()],
        ]);
        assert_eq!(
            deletion_addresses(&ev),
            vec![Address {
                kind: 30023,
                pubkey: "abcd".into(),
                d: "post-1".into(),
            }]
        );
    }
}
