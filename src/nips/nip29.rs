//! NIP-29: Relay-based Groups.
//!
//! Groups are identified by an id carried in the `h` tag of user and
//! moderation events and in the `d` tag of the relay-generated metadata
//! events (kinds 39000-39005). The relay maintains the authoritative group
//! state in memory, rebuilt from the stored moderation events on startup.
//!
//! Moderation policy implemented here: any user with at least one role (from
//! a `kind:9000` put-user event or a `kind:9007` group creation) is an admin
//! and may send moderation events; the relay's own key is always an admin.

use std::collections::{HashMap, HashSet};

use serde_json::json;

use crate::db::DbClient;
use crate::event::Event;
use crate::filter::Filter;
use crate::stats::unix_now;

pub const GROUP_META: u64 = 39000;
pub const GROUP_ADMINS: u64 = 39001;
pub const GROUP_MEMBERS: u64 = 39002;
pub const GROUP_PINS: u64 = 39005;
pub const MOD_MIN: u64 = 9000;
pub const MOD_MAX: u64 = 9020;
pub const CREATE_GROUP: u64 = 9007;
pub const DELETE_GROUP: u64 = 9008;
pub const JOIN: u64 = 9021;
pub const LEAVE: u64 = 9022;

const H: &str = "h";
const D: &str = "d";
const P: &str = "p";
const E: &str = "e";
const A: &str = "a";
const ROLE: &str = "role";
const CODE: &str = "code";

fn tag_value<'a>(event: &'a Event, name: &str) -> Option<&'a str> {
    event
        .tags
        .iter()
        .find(|t| t.len() >= 2 && t[0] == name)
        .map(|t| t[1].as_str())
}

/// Values of every occurrence of `name` in the event's tags.
fn tag_values<'a>(event: &'a Event, name: &'static str) -> impl Iterator<Item = &'a str> {
    event
        .tags
        .iter()
        .filter(move |t| t.len() >= 2 && t[0] == name)
        .map(|t| t[1].as_str())
}

/// Group id of a user or moderation event (from the `h` tag).
pub fn group_id(event: &Event) -> Option<&str> {
    tag_value(event, H)
}

/// Whether the event is a group event at all: user and moderation events
/// carry an `h` tag, relay-generated metadata events are kinds 39000-39005
/// identified by their `d` tag. Cheap enough to run per live event; mirrors
/// the `gid` selection in [`GroupStore::visible_to`].
pub fn is_group_event(event: &Event) -> bool {
    group_id(event).is_some()
        || ((GROUP_META..=GROUP_PINS).contains(&event.kind) && group_id_d(event).is_some())
}

/// Group id of a relay-generated metadata event (from the `d` tag).
pub fn group_id_d(event: &Event) -> Option<&str> {
    tag_value(event, D)
}

/// The `previous` tag values of an event (NIP-29 timeline references).
pub fn previous_tags(event: &Event) -> Vec<String> {
    tag_values(event, "previous").map(str::to_string).collect()
}

/// `e`-tag target ids of a `kind:9005` delete-event moderation action.
pub fn delete_targets(event: &Event) -> Vec<String> {
    tag_values(event, E).map(str::to_string).collect()
}

#[derive(Debug, Clone, Default)]
pub struct GroupSettings {
    pub private: bool,
    pub restricted: bool,
    pub closed: bool,
    pub hidden: bool,
    pub supported_kinds: Option<Vec<u64>>,
    pub name: String,
    pub picture: String,
    pub banner: String,
    pub about: String,
}

#[derive(Debug, Clone, Default)]
pub struct Group {
    /// pubkey -> set of roles.
    pub members: HashMap<String, HashSet<String>>,
    pub settings: GroupSettings,
    pub parent: Option<String>,
    pub children: Vec<String>,
    /// Pinned events as (tag, value) pairs.
    pub pins: Vec<(String, String)>,
    /// Valid invite codes.
    pub invites: HashSet<String>,
}

impl Group {
    /// The relay's own key and any member carrying at least one role counts
    /// as an admin.
    pub fn is_admin(&self, pubkey: &str) -> bool {
        self.members
            .get(pubkey)
            .is_some_and(|roles| !roles.is_empty())
    }

    pub fn is_member(&self, pubkey: &str) -> bool {
        self.members.contains_key(pubkey)
    }

    pub fn has_invite(&self, code: &str) -> bool {
        self.invites.contains(code)
    }
}

#[derive(Debug, Default)]
pub struct GroupStore {
    pub groups: HashMap<String, Group>,
    deleted: HashSet<String>,
}

impl GroupStore {
    pub fn group(&self, id: &str) -> Option<&Group> {
        self.groups.get(id)
    }

    /// Validates a write against the current group state. Returns the reason
    /// string for the `OK` message on rejection. Access control is based on
    /// the event's author (`event.pubkey`), not on connection authentication.
    pub fn validate_write(&self, event: &Event) -> Result<(), String> {
        let Some(gid) = group_id(event) else {
            return Ok(());
        };
        if self.deleted.contains(gid) {
            return Err("blocked: the group has been deleted".into());
        }
        let Some(group) = self.groups.get(gid) else {
            // Unknown groups are open: only a create-group event may target
            // them explicitly.
            if event.kind == CREATE_GROUP {
                return Ok(());
            }
            return Err("restricted: unknown group".into());
        };
        let pubkey = event.pubkey.as_str();

        if event.kind == JOIN {
            if group.is_member(pubkey) {
                return Err("duplicate: you are already a member of this group".into());
            }
            if event_code(event).is_some_and(|c| group.has_invite(c)) {
                return Ok(());
            }
            if group.settings.closed {
                return Err("restricted: this group is closed".into());
            }
            return Err("restricted: your join request is pending review".into());
        }

        if event.kind == LEAVE {
            return Ok(());
        }

        if (MOD_MIN..=MOD_MAX).contains(&event.kind) {
            if !group.is_admin(pubkey) {
                return Err("restricted: you are not an admin of this group".into());
            }
            if event.kind == 9002 {
                validate_edit_metadata(self, gid, group, event)?;
            }
            return Ok(());
        }

        if group.settings.restricted && !group.is_member(pubkey) {
            return Err("restricted: only group members can post".into());
        }
        if let Some(kinds) = &group.settings.supported_kinds
            && !kinds.contains(&event.kind)
        {
            return Err("restricted: this kind is not supported by the group".into());
        }
        Ok(())
    }

    /// Applies a stored event to the group state and returns the unsigned
    /// relay-generated events to publish (empty when `emit` is false, e.g.
    /// during startup rebuild).
    pub fn apply(&mut self, event: &Event, relay_pubkey: &str, now: u64, emit: bool) -> Vec<Event> {
        let Some(gid) = group_id(event) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        match event.kind {
            JOIN => {
                // Only valid invite codes reach this point; admit the user.
                if let Some(code) = event_code(event)
                    && self.groups.get(gid).is_some_and(|g| g.has_invite(code))
                {
                    let member = event.pubkey.clone();
                    if let Some(group) = self.groups.get_mut(gid) {
                        group
                            .members
                            .entry(member.clone())
                            .or_default()
                            .insert("member".into());
                    }
                    if emit {
                        out.push(build_put_user(gid, &member, &["member"], relay_pubkey, now));
                        out.extend(self.membership_events(gid, relay_pubkey, now));
                    }
                }
            }
            LEAVE => {
                let member = event.pubkey.clone();
                if let Some(group) = self.groups.get_mut(gid) {
                    group.members.remove(&member);
                }
                if emit {
                    out.push(build_remove_user(gid, &member, relay_pubkey, now));
                    out.extend(self.membership_events(gid, relay_pubkey, now));
                }
            }
            9000 => {
                if let Some(group) = self.groups.get_mut(gid) {
                    // NIP-29: roles are carried as the elements after the
                    // pubkey in each `p` tag (["p", <pubkey>, <role>...]);
                    // a separate `role` tag is also accepted for leniency.
                    for tag in event.tags.iter().filter(|t| t.len() >= 2 && t[0] == P) {
                        let pk = &tag[1];
                        let roles = group.members.entry(pk.clone()).or_default();
                        for role in &tag[2..] {
                            roles.insert(role.clone());
                        }
                    }
                    for pk in tag_values(event, P) {
                        let roles = group.members.entry(pk.to_string()).or_default();
                        roles.extend(tag_values(event, ROLE).map(str::to_string));
                    }
                }
                if emit {
                    out.extend(self.membership_events(gid, relay_pubkey, now));
                }
            }
            9001 => {
                if let Some(group) = self.groups.get_mut(gid) {
                    for pk in tag_values(event, P) {
                        group.members.remove(pk);
                    }
                }
                if emit {
                    out.extend(self.membership_events(gid, relay_pubkey, now));
                }
            }
            9002 => {
                let (parent_before, parent_after) = {
                    match self.groups.get_mut(gid) {
                        Some(group) => {
                            apply_settings(group, event);
                            group.children =
                                tag_values(event, "child").map(str::to_string).collect();
                            let before = group.parent.clone();
                            let after = tag_value(event, "parent").map(str::to_string);
                            (before, after)
                        }
                        None => (None, None),
                    }
                };
                if parent_before != parent_after {
                    if let Some(old) = parent_before
                        && let Some(parent_group) = self.groups.get_mut(&old)
                    {
                        parent_group.children.retain(|c| c != gid);
                    }
                    if let Some(new) = &parent_after
                        && let Some(parent_group) = self.groups.get_mut(new)
                        && !parent_group.children.iter().any(|c| c == gid)
                    {
                        parent_group.children.push(gid.to_string());
                    }
                    if let Some(group) = self.groups.get_mut(gid) {
                        group.parent = parent_after;
                    }
                }
                if emit {
                    out.push(build_meta_event(
                        gid,
                        self.groups.get(gid),
                        relay_pubkey,
                        now,
                    ));
                    if let Some(parent) = self.groups.get(gid).and_then(|g| g.parent.clone()) {
                        out.push(build_meta_event(
                            &parent,
                            self.groups.get(&parent),
                            relay_pubkey,
                            now,
                        ));
                    }
                    for child in self
                        .groups
                        .get(gid)
                        .map(|g| g.children.clone())
                        .unwrap_or_default()
                    {
                        out.push(build_meta_event(
                            &child,
                            self.groups.get(&child),
                            relay_pubkey,
                            now,
                        ));
                    }
                }
            }
            9005 => {
                // The referenced events are deleted by the relay itself.
            }
            CREATE_GROUP => {
                if !self.groups.contains_key(gid) {
                    let mut group = Group::default();
                    group
                        .members
                        .entry(event.pubkey.clone())
                        .or_default()
                        .insert("admin".into());
                    self.groups.insert(gid.to_string(), group);
                }
                if emit {
                    out.push(build_meta_event(
                        gid,
                        self.groups.get(gid),
                        relay_pubkey,
                        now,
                    ));
                    out.extend(self.membership_events(gid, relay_pubkey, now));
                }
            }
            DELETE_GROUP => {
                if let Some(group) = self.groups.remove(gid) {
                    // Children become roots.
                    for child in group.children {
                        if let Some(child_group) = self.groups.get_mut(&child) {
                            child_group.parent = None;
                            if emit {
                                out.push(build_meta_event(
                                    &child,
                                    Some(child_group),
                                    relay_pubkey,
                                    now,
                                ));
                            }
                        }
                    }
                    // The deleted group leaves its parent's child list.
                    if let Some(parent) = group.parent
                        && let Some(parent_group) = self.groups.get_mut(&parent)
                    {
                        parent_group.children.retain(|c| c != gid);
                        if emit {
                            out.push(build_meta_event(
                                &parent,
                                Some(parent_group),
                                relay_pubkey,
                                now,
                            ));
                        }
                    }
                }
                self.deleted.insert(gid.to_string());
            }
            9009 => {
                if let Some(group) = self.groups.get_mut(gid) {
                    for code in tag_values(event, CODE) {
                        group.invites.insert(code.to_string());
                    }
                }
            }
            9010 => {
                if let Some(group) = self.groups.get_mut(gid) {
                    group.pins = event
                        .tags
                        .iter()
                        .filter(|t| t.len() >= 2 && (t[0] == E || t[0] == A))
                        .map(|t| (t[0].clone(), t[1].clone()))
                        .collect();
                }
                if emit {
                    out.push(build_pins_event(
                        gid,
                        self.groups.get(gid),
                        relay_pubkey,
                        now,
                    ));
                }
            }
            _ => {}
        }
        out
    }

    /// Whether a stored event may be served to `authed` (NIP-29 read access).
    pub fn visible_to(&self, event: &Event, authed: Option<&str>) -> bool {
        let gid = match event.kind {
            GROUP_META..=GROUP_PINS => group_id_d(event),
            _ => group_id(event),
        };
        let Some(gid) = gid else {
            return true;
        };
        // Content of a deleted group is never served: the group is gone,
        // and its (possibly private) history must not become readable by
        // everyone.
        if self.deleted.contains(gid) {
            return false;
        }
        let Some(group) = self.groups.get(gid) else {
            return true;
        };
        let member = authed.is_some_and(|pk| group.is_member(pk));
        if group.settings.private && !member {
            return false;
        }
        if group.settings.hidden && (GROUP_META..=GROUP_PINS).contains(&event.kind) && !member {
            return false;
        }
        true
    }

    fn membership_events(&self, gid: &str, relay_pubkey: &str, now: u64) -> Vec<Event> {
        vec![
            build_admins_event(gid, self.groups.get(gid), relay_pubkey, now),
            build_members_event(gid, self.groups.get(gid), relay_pubkey, now),
        ]
    }

    /// Rebuilds the in-memory group state from the stored moderation events.
    pub async fn rebuild(&mut self, db: &DbClient) {
        let kinds: Vec<u64> = (MOD_MIN..=MOD_MAX).chain([LEAVE]).collect();
        let filter: Filter =
            serde_json::from_value(json!({ "kinds": kinds })).expect("static filter");
        let (mut events, _) = db.query(vec![filter], 1_000_000, unix_now()).await;
        // Chronological order (the scan is per-kind, not globally ordered) so
        // that later events win.
        events.sort_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
        for event in events {
            self.apply(&event, "", unix_now(), false);
        }
    }
}

fn event_code(event: &Event) -> Option<&str> {
    tag_value(event, CODE)
}

/// Validates the subgroup rules of a `kind:9002` edit-metadata event.
fn validate_edit_metadata(
    store: &GroupStore,
    gid: &str,
    group: &Group,
    event: &Event,
) -> Result<(), String> {
    // A parent value must not create a cycle or self-reference, and the
    // parent must exist and the author must be its admin.
    if let Some(parent) = tag_value(event, H).and_then(|_| tag_value(event, "parent")) {
        let mut cursor = Some(parent);
        while let Some(current) = cursor {
            if current == gid {
                return Err("restricted: would create a cycle".into());
            }
            cursor = store.groups.get(current).and_then(|g| g.parent.as_deref());
        }
        let parent_group = store
            .groups
            .get(parent)
            .ok_or_else(|| "restricted: parent group does not exist".to_string())?;
        if !parent_group.is_admin(event.pubkey.as_str()) {
            return Err("restricted: you are not an admin of the parent group".into());
        }
    }
    // Metadata edits must carry the full child list.
    let children: HashSet<&str> = tag_values(event, "child").collect();
    if !group.children.iter().all(|c| children.contains(c.as_str())) {
        return Err("restricted: missing child tags in metadata edit".into());
    }
    Ok(())
}
/// Applies metadata tags of a `kind:9002` event to the group settings.
fn apply_settings(group: &mut Group, event: &Event) {
    let mut settings = GroupSettings::default();
    for tag in &event.tags {
        if tag.is_empty() {
            continue;
        }
        match tag[0].as_str() {
            "name" | "picture" | "banner" | "about" => {
                if let Some(value) = tag.get(1) {
                    match tag[0].as_str() {
                        "name" => settings.name = value.clone(),
                        "picture" => settings.picture = value.clone(),
                        "banner" => settings.banner = value.clone(),
                        _ => settings.about = value.clone(),
                    }
                }
            }
            "private" => settings.private = true,
            "restricted" => settings.restricted = true,
            "closed" => settings.closed = true,
            "hidden" => settings.hidden = true,
            "supported_kinds" => {
                settings.supported_kinds =
                    Some(tag[1..].iter().filter_map(|k| k.parse().ok()).collect())
            }
            _ => {}
        }
    }
    group.settings = settings;
}

fn base_event(kind: u64, gid: &str, relay_pubkey: &str, now: u64) -> Event {
    Event {
        id: String::new(),
        pubkey: relay_pubkey.to_string(),
        created_at: now,
        kind,
        tags: vec![vec![D.to_string(), gid.to_string()]],
        content: String::new(),
        sig: String::new(),
    }
}

fn build_meta_event(gid: &str, group: Option<&Group>, relay_pubkey: &str, now: u64) -> Event {
    let Some(group) = group else {
        return base_event(GROUP_META, gid, relay_pubkey, now);
    };
    let mut event = base_event(GROUP_META, gid, relay_pubkey, now);
    let s = &group.settings;
    for (name, value) in [
        ("name", &s.name),
        ("picture", &s.picture),
        ("banner", &s.banner),
        ("about", &s.about),
    ] {
        if !value.is_empty() {
            event.tags.push(vec![name.to_string(), value.clone()]);
        }
    }
    if s.private {
        event.tags.push(vec!["private".into()]);
    }
    if s.restricted {
        event.tags.push(vec!["restricted".into()]);
    }
    if s.closed {
        event.tags.push(vec!["closed".into()]);
    }
    if s.hidden {
        event.tags.push(vec!["hidden".into()]);
    }
    if let Some(kinds) = &s.supported_kinds {
        let mut tag = vec!["supported_kinds".to_string()];
        tag.extend(kinds.iter().map(u64::to_string));
        event.tags.push(tag);
    }
    if let Some(parent) = &group.parent {
        event.tags.push(vec!["parent".to_string(), parent.clone()]);
    }
    for child in &group.children {
        event.tags.push(vec!["child".to_string(), child.clone()]);
    }
    event
}

fn build_admins_event(gid: &str, group: Option<&Group>, relay_pubkey: &str, now: u64) -> Event {
    let mut event = base_event(GROUP_ADMINS, gid, relay_pubkey, now);
    if let Some(group) = group {
        let mut admins: Vec<(String, Vec<String>)> = group
            .members
            .iter()
            .filter(|(_, roles)| !roles.is_empty())
            .map(|(pk, roles)| (pk.clone(), roles.iter().cloned().collect()))
            .collect();
        admins.sort();
        for (pk, roles) in admins {
            let mut tag = vec![P.to_string(), pk];
            tag.extend(roles);
            event.tags.push(tag);
        }
    }
    event
}

fn build_members_event(gid: &str, group: Option<&Group>, relay_pubkey: &str, now: u64) -> Event {
    let mut event = base_event(GROUP_MEMBERS, gid, relay_pubkey, now);
    if let Some(group) = group {
        let mut members: Vec<String> = group.members.keys().cloned().collect();
        members.sort();
        for pk in members {
            event.tags.push(vec![P.to_string(), pk]);
        }
    }
    event
}

fn build_pins_event(gid: &str, group: Option<&Group>, relay_pubkey: &str, now: u64) -> Event {
    let mut event = base_event(GROUP_PINS, gid, relay_pubkey, now);
    if let Some(group) = group {
        for (tag, value) in &group.pins {
            event.tags.push(vec![tag.clone(), value.clone()]);
        }
    }
    event
}

fn build_put_user(gid: &str, member: &str, roles: &[&str], relay_pubkey: &str, now: u64) -> Event {
    let mut event = base_event(9000, gid, relay_pubkey, now);
    event.tags[0] = vec![H.to_string(), gid.to_string()];
    let mut tag = vec![P.to_string(), member.to_string()];
    tag.extend(roles.iter().map(|r| r.to_string()));
    event.tags.push(tag);
    event
}

fn build_remove_user(gid: &str, member: &str, relay_pubkey: &str, now: u64) -> Event {
    let mut event = base_event(9001, gid, relay_pubkey, now);
    event.tags[0] = vec![H.to_string(), gid.to_string()];
    event.tags.push(vec![P.to_string(), member.to_string()]);
    event
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(kind: u64, pubkey: &str, h: Option<&str>, tags: Vec<Vec<String>>) -> Event {
        let mut tags = tags;
        if let Some(h) = h {
            tags.insert(0, vec![H.to_string(), h.to_string()]);
        }
        Event {
            id: String::new(),
            pubkey: pubkey.to_string(),
            created_at: 1_600_000_000,
            kind,
            tags,
            content: String::new(),
            sig: String::new(),
        }
    }

    const ADMIN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const USER: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const OTHER: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn seeded() -> GroupStore {
        let mut store = GroupStore::default();
        let create = event(CREATE_GROUP, ADMIN, Some("g1"), vec![]);
        store.apply(&create, "", 1, false);
        let put_user = event(9000, ADMIN, Some("g1"), vec![vec![P.into(), OTHER.into()]]);
        store.apply(&put_user, "", 1, false);
        store
    }

    #[test]
    fn create_and_admin() {
        let store = seeded();
        let g = store.group("g1").unwrap();
        assert!(g.is_admin(ADMIN));
        // put-user adds a member; without roles they are not an admin.
        assert!(g.is_member(OTHER));
        assert!(!g.is_admin(OTHER));
    }

    #[test]
    fn moderation_requires_admin() {
        let store = seeded();
        let bad = event(9001, OTHER, Some("g1"), vec![vec![P.into(), ADMIN.into()]]);
        assert!(store.validate_write(&bad).is_err());
        let good = event(9001, ADMIN, Some("g1"), vec![vec![P.into(), OTHER.into()]]);
        assert!(store.validate_write(&good).is_ok());
    }

    #[test]
    fn put_user_roles_from_p_tag_extras() {
        // NIP-29: a kind:9000 carries the roles as the elements after the
        // pubkey inside the `p` tag.
        let mut store = seeded();
        let put = event(
            9000,
            ADMIN,
            Some("g1"),
            vec![vec![
                P.into(),
                USER.into(),
                "ceo".into(),
                "secretary".into(),
            ]],
        );
        store.apply(&put, "", 1, false);
        let group = store.group("g1").unwrap();
        assert_eq!(
            group.members.get(USER).unwrap(),
            &["ceo".into(), "secretary".into()].into_iter().collect()
        );
        assert!(group.is_admin(USER));
    }

    #[test]
    fn restricted_groups() {
        let mut store = seeded();
        let edit = event(9002, ADMIN, Some("g1"), vec![vec!["restricted".into()]]);
        store.apply(&edit, "", 1, false);
        let msg_by_user = event(1, USER, Some("g1"), vec![]);
        assert!(store.validate_write(&msg_by_user).is_err());
        // Join requests are pending review; admins add users.
        let join = event(JOIN, USER, Some("g1"), vec![]);
        assert!(store.validate_write(&join).is_err());
        let add = event(9000, ADMIN, Some("g1"), vec![vec![P.into(), USER.into()]]);
        store.apply(&add, "", 1, false);
        assert!(store.validate_write(&msg_by_user).is_ok());
    }

    #[test]
    fn invite_code_admits() {
        let mut store = seeded();
        let invite = event(
            9009,
            ADMIN,
            Some("g1"),
            vec![vec![CODE.into(), "abc".into()]],
        );
        store.apply(&invite, "", 1, false);
        let join = event(
            JOIN,
            USER,
            Some("g1"),
            vec![vec![CODE.into(), "abc".into()]],
        );
        assert!(store.validate_write(&join).is_ok());
        store.apply(&join, "", 1, false);
        assert!(store.group("g1").unwrap().is_member(USER));
    }

    #[test]
    fn closed_group_rejects_joins() {
        let mut store = seeded();
        let edit = event(9002, ADMIN, Some("g1"), vec![vec!["closed".into()]]);
        store.apply(&edit, "", 1, false);
        let join = event(JOIN, USER, Some("g1"), vec![]);
        assert!(store.validate_write(&join).is_err());
    }

    #[test]
    fn subgroups() {
        let mut store = seeded();
        // Create a second group and move g1 under it.
        let create2 = event(CREATE_GROUP, ADMIN, Some("g2"), vec![]);
        store.apply(&create2, "", 1, false);
        let adopt = event(
            9002,
            ADMIN,
            Some("g1"),
            vec![vec!["parent".into(), "g2".into()]],
        );
        assert!(store.validate_write(&adopt).is_ok());
        store.apply(&adopt, "", 1, false);
        assert_eq!(store.group("g1").unwrap().parent.as_deref(), Some("g2"));
        assert_eq!(store.group("g2").unwrap().children, vec!["g1"]);

        // Self-parenting and cycles are rejected.
        let self_cycle = event(
            9002,
            ADMIN,
            Some("g2"),
            vec![vec!["parent".into(), "g2".into()]],
        );
        assert!(store.validate_write(&self_cycle).is_err());
        let cycle = event(
            9002,
            ADMIN,
            Some("g2"),
            vec![vec!["parent".into(), "g1".into()]],
        );
        assert!(store.validate_write(&cycle).is_err());
        // Unknown parent is rejected.
        let ghost = event(
            9002,
            ADMIN,
            Some("g1"),
            vec![vec!["parent".into(), "ghost".into()]],
        );
        assert!(store.validate_write(&ghost).is_err());

        // Deleting a child removes it from the parent's child list.
        let delete_child = event(DELETE_GROUP, ADMIN, Some("g1"), vec![]);
        store.apply(&delete_child, "", 1, false);
        assert!(store.group("g1").is_none());
        assert!(store.group("g2").unwrap().children.is_empty());
    }

    #[test]
    fn deleted_group_content_is_hidden() {
        let mut store = seeded();
        let edit = event(9002, ADMIN, Some("g1"), vec![vec!["private".into()]]);
        store.apply(&edit, "", 1, false);
        let msg = event(1, ADMIN, Some("g1"), vec![]);
        let meta = store.apply(&msg, "", 1, true);
        // Before deletion: hidden from outsiders, visible to members.
        assert!(!store.visible_to(&msg, None));
        assert!(store.visible_to(&msg, Some(ADMIN)));
        // After deletion: the history must not become public.
        let delete = event(DELETE_GROUP, ADMIN, Some("g1"), vec![]);
        store.apply(&delete, "", 1, false);
        assert!(!store.visible_to(&msg, None));
        assert!(!store.visible_to(&msg, Some(ADMIN)));
        for m in &meta {
            assert!(!store.visible_to(m, Some(ADMIN)));
        }
    }

    #[test]
    fn private_groups_hide_from_non_members() {
        let mut store = seeded();
        let edit = event(9002, ADMIN, Some("g1"), vec![vec!["private".into()]]);
        store.apply(&edit, "", 1, false);
        let msg = event(1, ADMIN, Some("g1"), vec![]);
        let outsider = "d".repeat(64);
        assert!(!store.visible_to(&msg, Some(&outsider)));
        assert!(store.visible_to(&msg, Some(ADMIN)));
        // OTHER is a member and may read private groups.
        assert!(store.visible_to(&msg, Some(OTHER)));
        let meta = store.apply(&msg, "", 1, true);
        for m in &meta {
            assert!(!store.visible_to(m, Some(&outsider)));
        }
    }
}
