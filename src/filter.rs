//! NIP-01 subscription filters and the in-memory match.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::event::Event;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Filter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authors: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search: Option<String>,
    #[serde(flatten)]
    pub tags: BTreeMap<String, Value>,
}

impl Filter {
    /// Performs an in-memory match (used for live events and final checks).
    pub fn matches(&self, ev: &Event) -> bool {
        if let Some(ids) = &self.ids {
            // NIP-01: `ids` entries may be full ids or prefixes.
            let matches = ids
                .iter()
                .any(|id| id == &ev.id || (id.len() < ev.id.len() && ev.id.starts_with(id)));
            if !matches {
                return false;
            }
        }
        // NIP-26: events published under a delegation tag match filters on
        // the delegator's pubkey as well as on the event's own author.
        if let Some(authors) = &self.authors
            && !authors.iter().any(|a| a == &ev.pubkey)
            && !ev
                .tags
                .iter()
                .any(|t| t.len() >= 2 && t[0] == "delegation" && authors.iter().any(|a| a == &t[1]))
        {
            return false;
        }
        if let Some(kinds) = &self.kinds
            && !kinds.contains(&ev.kind)
        {
            return false;
        }
        if let Some(since) = self.since
            && ev.created_at < since
        {
            return false;
        }
        if let Some(until) = self.until
            && ev.created_at > until
        {
            return false;
        }
        // NIP-50: an event matches when at least one search term appears in
        // the content; the database scan ranks full matches first.
        if let Some(search) = self.search.as_deref()
            && !search.trim().is_empty()
        {
            let content = ev.content.to_lowercase();
            if !crate::nips::nip50::terms(search)
                .iter()
                .any(|term| content.contains(term.as_str()))
            {
                return false;
            }
        }
        self.tags.iter().all(|(name, value)| {
            let tag_name = name.strip_prefix('#').unwrap_or(name);
            let values = tag_string_values(value);
            values.iter().any(|v| {
                ev.tags
                    .iter()
                    .any(|t| t.len() >= 2 && t[0] == tag_name && &t[1] == v)
            })
        })
    }

    pub fn has_search(&self) -> bool {
        self.search.as_deref().is_some_and(|s| !s.trim().is_empty())
    }
}

/// The string values of a filter tag attribute (a single
/// string or an array of strings); other value kinds yield nothing.
pub(crate) fn tag_string_values(value: &Value) -> Vec<String> {
    match value {
        Value::String(s) => vec![s.clone()],
        Value::Array(items) => items
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(kind: u64, tags: Vec<Vec<String>>) -> Event {
        Event {
            id: "a".repeat(64),
            pubkey: "b".repeat(64),
            created_at: 1_600_000_000,
            kind,
            tags,
            content: "hello world".into(),
            sig: "c".repeat(128),
        }
    }

    #[test]
    fn basic_match() {
        let e = ev(1, vec![vec!["t".into(), "rust".into()]]);
        let f = Filter {
            kinds: Some(vec![1, 2]),
            ..Default::default()
        };
        assert!(f.matches(&e));
        let f = Filter {
            kinds: Some(vec![3]),
            ..Default::default()
        };
        assert!(!f.matches(&e));
    }

    #[test]
    fn tag_match() {
        let e = ev(1, vec![vec!["t".into(), "rust".into()]]);
        let f: Filter = serde_json::from_value(serde_json::json!({"#t": ["rust"]})).unwrap();
        assert!(f.matches(&e));
        let f: Filter = serde_json::from_value(serde_json::json!({"#t": ["go"]})).unwrap();
        assert!(!f.matches(&e));
    }

    #[test]
    fn time_match() {
        let e = ev(1, vec![]);
        let f: Filter =
            serde_json::from_value(serde_json::json!({"since": 1_700_000_000})).unwrap();
        assert!(!f.matches(&e));
    }

    #[test]
    fn search_match() {
        let e = ev(1, vec![]);
        let mut hit = e.clone();
        hit.content = "Rust Nostr Relay".into();
        let f: Filter = serde_json::from_value(serde_json::json!({"search": "nostr"})).unwrap();
        assert!(f.matches(&hit));
        assert!(!f.matches(&e));
        // At least one term must be present; partial matches pass.
        let f: Filter =
            serde_json::from_value(serde_json::json!({"search": "nostr bitcoin"})).unwrap();
        assert!(f.matches(&hit));
        let miss: Filter =
            serde_json::from_value(serde_json::json!({"search": "bitcoin only"})).unwrap();
        assert!(!miss.matches(&hit));
        // Empty search strings are ignored.
        let f: Filter = serde_json::from_value(serde_json::json!({"search": "  "})).unwrap();
        assert!(f.matches(&hit));
    }
}
