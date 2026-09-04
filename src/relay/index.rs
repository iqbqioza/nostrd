//! The live-delivery subscription index.
//!
//! Each connection registers the filter components of its subscriptions
//! (kinds, authors, tag constraints, and the "match everything" `{}`
//! case) with a connection id. When the live bus produces a batch, it
//! looks up the candidate connections for each event and delivers only
//! to them — an event wakes the connections that *can* match it instead
//! of every subscriber. The per-connection filter match remains the
//! final check, so the index only narrows the delivery set; it never
//! loosens it.

use std::collections::{HashMap, HashSet};

use crate::event::Event;

/// The filter components → connection ids.
#[derive(Default)]
pub(crate) struct SubscriptionIndex {
    kinds: HashMap<u64, HashSet<u64>>,
    authors: HashMap<[u8; 32], HashSet<u64>>,
    tags: HashMap<(String, String), HashSet<u64>>,
    /// Connections with at least one `{}`-style filter (match anything).
    all: HashSet<u64>,
}

/// The components of a filter that can be indexed ahead of the full
/// in-memory match.
pub(crate) enum FilterComponents {
    /// The filter matches every event.
    All,
    /// The indexed components (kinds, authors, tags). An empty set means
    /// "no indexed component": the filter still matches via `since`/
    /// `until`/`ids`, which the index cannot narrow.
    Indexed {
        kinds: Vec<u64>,
        authors: Vec<[u8; 32]>,
        tags: Vec<(String, String)>,
    },
}

impl FilterComponents {
    /// Derives the indexable components of a filter.
    pub(crate) fn of(filter: &crate::filter::Filter) -> FilterComponents {
        if filter.kinds.is_none()
            && filter.authors.is_none()
            && filter.tags.is_empty()
            && filter.ids.is_none()
            && filter.since.is_none()
            && filter.until.is_none()
            && !filter.has_search()
        {
            return FilterComponents::All;
        }
        let kinds = filter.kinds.clone().unwrap_or_default();
        let authors = filter
            .authors
            .as_ref()
            .map(|authors| {
                authors
                    .iter()
                    .filter_map(|a| hex::decode(a).ok())
                    .filter(|b| b.len() == 32)
                    .map(|b| {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&b);
                        arr
                    })
                    .collect()
            })
            .unwrap_or_default();
        let tags = filter
            .tags
            .iter()
            .filter(|(name, _)| name.starts_with('#'))
            .flat_map(|(name, value)| {
                let tag_name = name.strip_prefix('#').unwrap_or(name).to_string();
                crate::filter::tag_values(value).map(move |v| (tag_name.clone(), v.to_string()))
            })
            .collect();
        FilterComponents::Indexed {
            kinds,
            authors,
            tags,
        }
    }
}

impl SubscriptionIndex {
    /// Registers a connection's filter components.
    pub(crate) fn register(&mut self, conn: u64, components: &[FilterComponents]) {
        for component in components {
            match component {
                FilterComponents::All => {
                    self.all.insert(conn);
                }
                FilterComponents::Indexed {
                    kinds,
                    authors,
                    tags,
                } => {
                    for kind in kinds {
                        self.kinds.entry(*kind).or_default().insert(conn);
                    }
                    for author in authors {
                        self.authors.entry(*author).or_default().insert(conn);
                    }
                    for tag in tags {
                        self.tags.entry(tag.clone()).or_default().insert(conn);
                    }
                }
            }
        }
    }

    /// Removes a connection from every entry.
    pub(crate) fn unregister(&mut self, conn: u64) {
        self.all.remove(&conn);
        for set in self.kinds.values_mut() {
            set.remove(&conn);
        }
        for set in self.authors.values_mut() {
            set.remove(&conn);
        }
        for set in self.tags.values_mut() {
            set.remove(&conn);
        }
    }

    /// The candidate connections for an event (the union of the index
    /// entries its components hit). The per-connection filter match is
    /// the final check.
    pub(crate) fn candidates(&self, event: &Event) -> HashSet<u64> {
        let mut out: HashSet<u64> = self.all.clone();
        if let Some(set) = self.kinds.get(&event.kind) {
            out.extend(set.iter().copied());
        }
        if let Some(pubkey) = event.pubkey_bytes()
            && let Some(set) = self.authors.get(&pubkey)
        {
            out.extend(set.iter().copied());
        }
        for tag in &event.tags {
            if tag.len() >= 2
                && tag[0].len() == 1
                && let Some(set) = self.tags.get(&(tag[0].clone(), tag[1].clone()))
            {
                out.extend(set.iter().copied());
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(kind: u64, tags: Vec<Vec<String>>) -> Event {
        Event {
            id: "0".repeat(64),
            pubkey: "ab".repeat(32),
            created_at: 1_600_000_000,
            kind,
            tags,
            content: String::new(),
            sig: "0".repeat(128),
        }
    }

    #[test]
    fn candidates_union_kinds_authors_and_tags() {
        let mut index = SubscriptionIndex::default();
        index.register(
            1,
            &[FilterComponents::Indexed {
                kinds: vec![1],
                authors: vec![],
                tags: vec![],
            }],
        );
        index.register(
            2,
            &[FilterComponents::Indexed {
                kinds: vec![],
                authors: vec![],
                tags: vec![("p".into(), "aa".repeat(32))],
            }],
        );
        index.register(3, &[FilterComponents::All]);
        let e = ev(1, vec![vec!["p".into(), "aa".repeat(32)]]);
        let candidates = index.candidates(&e);
        assert!(candidates.contains(&1), "kind match");
        assert!(candidates.contains(&2), "tag match");
        assert!(candidates.contains(&3), "match-everything filter");
        assert_eq!(candidates.len(), 3);
        // A non-matching event hits only the match-everything connection.
        let e = ev(30001, vec![]);
        let candidates = index.candidates(&e);
        assert_eq!(candidates, HashSet::from([3]));
    }

    #[test]
    fn unregister_removes_every_entry() {
        let mut index = SubscriptionIndex::default();
        index.register(
            1,
            &[FilterComponents::Indexed {
                kinds: vec![1, 2],
                authors: vec![[7u8; 32]],
                tags: vec![("p".into(), "x".into())],
            }],
        );
        index.unregister(1);
        assert!(index.candidates(&ev(1, vec![])).is_empty());
        assert!(index.candidates(&ev(2, vec![])).is_empty());
    }

    #[test]
    fn filter_components_derivation() {
        let filter: crate::filter::Filter =
            serde_json::from_value(serde_json::json!({"kinds": [1], "authors": ["ab".repeat(32)]}))
                .unwrap();
        match FilterComponents::of(&filter) {
            FilterComponents::Indexed {
                kinds,
                authors,
                tags,
            } => {
                assert_eq!(kinds, vec![1]);
                assert_eq!(authors, vec![[0xab; 32]]);
                assert!(tags.is_empty());
            }
            _ => panic!("indexed expected"),
        }
        let empty: crate::filter::Filter = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(matches!(
            FilterComponents::of(&empty),
            FilterComponents::All
        ));
    }
}
