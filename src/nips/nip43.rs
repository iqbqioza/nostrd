//! NIP-43: Relay Access Metadata and Requests.
//!
//! The relay can define roles (`kind:33534`, addressable by `d` tag) and
//! publish membership lists (`kind:13534`, replaceable) signed with its own
//! key. The NIP-86 role methods manage them; add/remove user events
//! (`kind:8000`/`kind:8001`) are published on assignment changes and leave
//! requests (`kind:28936`) update the member list.

use std::collections::HashMap;

use serde_json::json;

use crate::db::DbClient;
use crate::event::Event;
use crate::filter::Filter;
use crate::stats::unix_now;

pub const ROLE_DEFINITION: u64 = 33534;
pub const MEMBERSHIP_LIST: u64 = 13534;
pub const ADD_USER: u64 = 8000;
pub const REMOVE_USER: u64 = 8001;
pub const LEAVE: u64 = 28936;

#[derive(Debug, Clone, Default)]
pub struct Role {
    pub label: String,
    pub description: String,
    pub color: String,
    pub order: Option<i64>,
}

#[derive(Debug, Default)]
pub struct RoleStore {
    pub roles: HashMap<String, Role>,
    /// pubkey -> role ids.
    pub assignments: HashMap<String, Vec<String>>,
}

impl RoleStore {
    pub fn create(
        &mut self,
        id: &str,
        label: &str,
        description: &str,
        color: &str,
        order: Option<i64>,
    ) {
        self.roles.insert(
            id.to_string(),
            Role {
                label: label.to_string(),
                description: description.to_string(),
                color: color.to_string(),
                order,
            },
        );
    }

    pub fn delete(&mut self, id: &str) -> bool {
        self.roles.remove(id).is_some()
    }

    pub fn assign(&mut self, pubkey: &str, role: &str) -> bool {
        if !self.roles.contains_key(role) {
            return false;
        }
        let roles = self.assignments.entry(pubkey.to_string()).or_default();
        if !roles.iter().any(|r| r == role) {
            roles.push(role.to_string());
        }
        true
    }

    pub fn unassign(&mut self, pubkey: &str, role: &str) -> bool {
        let mut changed = false;
        if let Some(roles) = self.assignments.get_mut(pubkey) {
            let before = roles.len();
            roles.retain(|r| r != role);
            changed = roles.len() != before;
            if roles.is_empty() {
                self.assignments.remove(pubkey);
            }
        }
        changed
    }

    /// Removes a pubkey from the member list (leave request). Returns true
    /// when the pubkey was listed.
    pub fn remove_pubkey(&mut self, pubkey: &str) -> bool {
        self.assignments.remove(pubkey).is_some()
    }

    // ----- relay-generated events -----

    fn base(kind: u64, relay_pubkey: &str, now: u64) -> Event {
        Event {
            id: String::new(),
            pubkey: relay_pubkey.to_string(),
            created_at: now,
            kind,
            tags: vec![vec!["-".into()]],
            content: String::new(),
            sig: String::new(),
        }
    }

    /// `kind:33534` role definition for a role id.
    pub fn role_event(&self, id: &str, relay_pubkey: &str, now: u64) -> Event {
        let mut event = Self::base(ROLE_DEFINITION, relay_pubkey, now);
        event.tags.push(vec!["d".into(), id.to_string()]);
        if let Some(role) = self.roles.get(id) {
            if !role.label.is_empty() {
                event.tags.push(vec!["label".into(), role.label.clone()]);
            }
            if !role.description.is_empty() {
                event
                    .tags
                    .push(vec!["description".into(), role.description.clone()]);
            }
            if !role.color.is_empty() {
                event.tags.push(vec!["color".into(), role.color.clone()]);
            }
            if let Some(order) = role.order {
                event.tags.push(vec!["order".into(), order.to_string()]);
            }
        }
        event
    }

    /// `kind:13534` membership list: every assigned pubkey with its roles.
    pub fn membership_event(&self, relay_pubkey: &str, now: u64) -> Event {
        let mut event = Self::base(MEMBERSHIP_LIST, relay_pubkey, now);
        let mut members: Vec<(String, Vec<String>)> = self
            .assignments
            .iter()
            .map(|(pk, roles)| (pk.clone(), roles.clone()))
            .collect();
        members.sort();
        for (pubkey, roles) in members {
            let mut tag = vec!["member".to_string(), pubkey];
            tag.extend(roles);
            event.tags.push(tag);
        }
        event
    }

    pub fn add_user_event(&self, pubkey: &str, relay_pubkey: &str, now: u64) -> Event {
        let mut event = Self::base(ADD_USER, relay_pubkey, now);
        event.tags.push(vec!["p".into(), pubkey.to_string()]);
        event
    }

    pub fn remove_user_event(&self, pubkey: &str, relay_pubkey: &str, now: u64) -> Event {
        let mut event = Self::base(REMOVE_USER, relay_pubkey, now);
        event.tags.push(vec!["p".into(), pubkey.to_string()]);
        event
    }

    /// Rebuilds the role store from the stored role definitions and
    /// membership lists (only the latest addressable/replaceable versions
    /// are retained in the database).
    pub async fn rebuild(&mut self, db: &DbClient) {
        let filter: Filter =
            serde_json::from_value(json!({ "kinds": [ROLE_DEFINITION, MEMBERSHIP_LIST] }))
                .expect("static filter");
        let (events, _) = db.query(vec![filter], 1_000_000, unix_now()).await;
        for event in events {
            match event.kind {
                ROLE_DEFINITION => {
                    let Some(id) = tag_value(&event, "d") else {
                        continue;
                    };
                    self.roles.insert(
                        id.to_string(),
                        Role {
                            label: tag_value(&event, "label").unwrap_or("").to_string(),
                            description: tag_value(&event, "description").unwrap_or("").to_string(),
                            color: tag_value(&event, "color").unwrap_or("").to_string(),
                            order: tag_value(&event, "order").and_then(|o| o.parse().ok()),
                        },
                    );
                }
                MEMBERSHIP_LIST => {
                    for tag in &event.tags {
                        if tag.len() >= 2 && tag[0] == "member" {
                            self.assignments.insert(tag[1].clone(), tag[2..].to_vec());
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

fn tag_value<'a>(event: &'a Event, name: &str) -> Option<&'a str> {
    event
        .tags
        .iter()
        .find(|t| t.len() >= 2 && t[0] == name)
        .map(|t| t[1].as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_lifecycle() {
        let mut store = RoleStore::default();
        store.create("king", "king", "ruler", "37", Some(1));
        assert!(store.roles.contains_key("king"));
        assert!(store.assign("abc", "king"));
        assert!(!store.assign("abc", "ghost"), "unknown role rejected");
        assert!(store.unassign("abc", "king"));
        assert!(
            store.assignments.is_empty(),
            "empty assignments are dropped"
        );
        assert!(store.delete("king"));
    }

    #[test]
    fn role_events_are_wellformed() {
        let mut store = RoleStore::default();
        store.create("king", "king", "ruler of the relay", "37", Some(1));
        store.assign("c308e1f8", "king");

        let now = 1_700_000_000;
        let role = store.role_event("king", "relaypub", now);
        assert_eq!(role.kind, ROLE_DEFINITION);
        assert_eq!(role.tags[0], vec!["-"]);
        assert!(role.tags.contains(&vec!["d".into(), "king".into()]));
        assert!(role.tags.contains(&vec!["label".into(), "king".into()]));
        assert!(role.tags.contains(&vec!["order".into(), "1".into()]));

        let members = store.membership_event("relaypub", now);
        assert_eq!(members.kind, MEMBERSHIP_LIST);
        assert_eq!(members.tags[0], vec!["-"]);
        assert!(
            members
                .tags
                .contains(&vec!["member".into(), "c308e1f8".into(), "king".into()])
        );

        let add = store.add_user_event("c308e1f8", "relaypub", now);
        assert_eq!(add.kind, ADD_USER);
        assert!(add.tags.contains(&vec!["p".into(), "c308e1f8".into()]));
    }
}
