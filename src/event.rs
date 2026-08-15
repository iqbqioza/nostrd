//! The wire representation of a Nostr event.

use serde::{Deserialize, Serialize};

use crate::nips::nip01;

/// A Nostr event as defined by NIP-01. NIP-specific behaviour lives in the
/// `nips` modules; this struct only holds the data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u64,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

impl Event {
    pub fn id_bytes(&self) -> Option<[u8; nip01::ID_BYTES]> {
        hex::decode(&self.id).ok()?.try_into().ok()
    }

    pub fn pubkey_bytes(&self) -> Option<[u8; nip01::PK_BYTES]> {
        hex::decode(&self.pubkey).ok()?.try_into().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> Event {
        Event {
            id: "a".repeat(64),
            pubkey: "b".repeat(64),
            created_at: 1,
            kind: 1,
            tags: vec![vec!["t".into(), "rust".into()]],
            content: "hello".into(),
            sig: "c".repeat(128),
        }
    }

    #[test]
    fn id_bytes_validates_length() {
        let ev = event();
        assert_eq!(ev.id_bytes().unwrap().len(), 32);
        let bad = Event {
            id: "abc".into(),
            ..event()
        };
        assert!(bad.id_bytes().is_none());
    }
}
