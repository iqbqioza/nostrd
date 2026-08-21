//! NIP-29: Relay-based Groups.
//!
//! The group state machine (access control, moderation application and
//! read visibility) lives here; the relay-generated metadata events are
//! built by the [`events`] module.

pub(crate) mod events;
#[cfg(test)]
mod tests;

use events::{
    apply_settings, build_admins_event, build_members_event, build_meta_event, build_pins_event,
    build_put_user, build_remove_user,
};

/// Moderation policy implemented here: any user with at least one role (from
/// a `kind:9000` put-user event or a `kind:9007` group creation) is an admin
/// and may send moderation events; the relay's own key is always an admin.
use std::collections::{HashMap, HashSet};

use serde_json::json;

use crate::db::DbClient;
use crate::event::Event;
use crate::filter::Filter;
use crate::util::unix_now;

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

/// Whether the event is a group *action*: moderation events (9000-9020),
/// join requests (9021) and leave requests (9022). These MUST carry an `h`
/// tag naming the group they act on.
pub fn is_group_action(event: &Event) -> bool {
    (MOD_MIN..=MOD_MAX).contains(&event.kind) || event.kind == JOIN || event.kind == LEAVE
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

/// Group id of a stored event for visibility checks: the `h` tag for user
/// and moderation events, the `d` tag for relay-generated metadata events.
pub fn group_id_any(event: &Event) -> Option<&str> {
    match event.kind {
        GROUP_META..=GROUP_PINS => group_id_d(event),
        _ => group_id(event),
    }
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
    /// A member carrying at least one role is an admin. (The relay's own key
    /// is handled separately: its relay-generated events are stored directly
    /// and never go through this check.)
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
            if let Some(code) = event_code(event) {
                if !group.has_invite(code) {
                    return Err("restricted: invalid invite code".into());
                }
                return Ok(());
            }
            if group.settings.closed {
                // NIP-29: `closed` means join requests are ignored — the
                // request is rejected (final) and not stored. Admission to
                // a closed group happens via an invite code or a kind:9000
                // issued by an admin.
                return Err("restricted: this group is closed".into());
            }
            // NIP-29: omitting the `closed` tag means join requests are
            // honored; the relay admits the user right away.
            return Ok(());
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
            if event.kind == 9000 {
                // NIP-29: the roles of each `p`-tag subject are replaced; a
                // `p` tag without roles demotes the subject to a plain member.
                // Refuse to leave the group with no admin at all (the creator
                // or any admin could otherwise be silently demoted and the
                // group left unmanageable).
                let grants_roles = event.tags.iter().any(|t| t.len() > 2 && t[0] == P);
                if !grants_roles {
                    let demoted: HashSet<&str> = event
                        .tags
                        .iter()
                        .filter(|t| t.len() == 2 && t[0] == P)
                        .map(|t| t[1].as_str())
                        .collect();
                    // An admin keeps their roles unless named in a `p` tag.
                    let retains_admin = group
                        .members
                        .iter()
                        .any(|(pk, roles)| !roles.is_empty() && !demoted.contains(pk.as_str()));
                    if !retains_admin {
                        return Err("restricted: the group must retain at least one admin".into());
                    }
                }
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
                // Joined via a valid invite code, or honored on an open
                // group (not `closed`): admit the user with no privileges.
                // A closed group without a valid code leaves the request
                // pending for an admin to review.
                let admitted = if let Some(code) = event_code(event) {
                    self.groups.get(gid).is_some_and(|g| g.has_invite(code))
                } else {
                    self.groups.get(gid).is_some_and(|g| !g.settings.closed)
                };
                if admitted {
                    let member = event.pubkey.clone();
                    if let Some(group) = self.groups.get_mut(gid) {
                        // Membership is the entry in the member map; roles
                        // (granted only via `kind:9000`) decide privileges.
                        group.members.entry(member.clone()).or_default();
                    }
                    if emit {
                        out.push(build_put_user(gid, &member, &[], relay_pubkey, now));
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
                    // pubkey in each `p` tag (["p", <pubkey>, <role>...]).
                    // The listed roles replace the user's previous roles
                    // ("the user roles must just be updated"), and a `p` tag
                    // without roles leaves the user a plain member.
                    for tag in event.tags.iter().filter(|t| t.len() >= 2 && t[0] == P) {
                        let pk = tag[1].clone();
                        let roles: HashSet<String> = tag[2..].iter().cloned().collect();
                        // An empty role list leaves the user a plain member
                        // (replacing any previous roles).
                        group.members.insert(pk, roles);
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
        let Some(gid) = group_id_any(event) else {
            return true;
        };
        let is_meta = (GROUP_META..=GROUP_PINS).contains(&event.kind);
        self.visible_gid(gid, is_meta, authed)
    }

    /// Whether the content of a group may be served to `authed`. `is_meta`
    /// distinguishes relay-generated metadata events (kinds 39000-39005),
    /// which `hidden` groups additionally withhold from non-members.
    pub fn visible_gid(&self, gid: &str, is_meta: bool, authed: Option<&str>) -> bool {
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
        if group.settings.hidden && is_meta && !member {
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
        // 9021 JOIN is included so that honored joins survive a restart even
        // on relays without a private key (which never emit the relay-signed
        // 9000 put-user that would otherwise carry the membership).
        let kinds: Vec<u64> = (MOD_MIN..=MOD_MAX).chain([JOIN, LEAVE]).collect();
        // Walk every stored group event in pages (newest first) instead of
        // one giant query: a single query with a huge limit would be truncated
        // by the scan's collection cap / work budget and could exceed the
        // database request timeout, silently rebuilding an incomplete group
        // store (missing groups → private content world-readable, admin
        // writes rejected, deleted groups resurrected).
        const PAGE: usize = 50_000;
        let mut events: Vec<Event> = Vec::new();
        let mut until: Option<u64> = None;
        loop {
            let mut filter: Filter =
                serde_json::from_value(json!({ "kinds": kinds })).expect("static filter");
            filter.until = until;
            // `query_full` gives each page the full-scan work budget (not the
            // smaller per-query one), so a single second holding more events
            // than the small budget cannot be silently cut mid-boundary.
            let (page, more) = db.query_full(vec![filter], PAGE, unix_now()).await;
            if page.is_empty() {
                break;
            }
            let min_created = page.iter().map(|e| e.created_at).min().unwrap_or(0);
            let full = page.len() >= PAGE;
            if !full && more {
                log::warn!(
                    "group state rebuild ended early (scan budget exhausted with {} events in \
                     the page): the in-memory group store may be incomplete after this restart",
                    page.len()
                );
                events.extend(page);
                break;
            }
            events.extend(page);
            if !full {
                // Fewer than a page: every remaining event was collected.
                break;
            }
            if min_created == 0 {
                break;
            }
            // The scan collects every event at the boundary timestamp, so
            // stepping the cursor just below it cannot skip any event.
            until = Some(min_created - 1);
        }
        // Chronological order (the scan is per-kind, not globally ordered) so
        // that later events win. Within the same second the kind is used as a
        // tie-breaker: the group-establishing events apply first (9007 create,
        // 9008 delete), then the member/settings operations (9000-9006,
        // 9009-9010) which need the group to exist, and joins/leaves last.
        events.sort_by(|a, b| {
            (a.created_at, group_rank(a.kind), a.kind, &a.id).cmp(&(
                b.created_at,
                group_rank(b.kind),
                b.kind,
                &b.id,
            ))
        });
        for event in events {
            self.apply(&event, "", unix_now(), false);
        }
    }
}

/// Replay order of group events within the same second: the create/delete
/// establish the group before the member/settings operations, joins and
/// leaves come last.
fn group_rank(kind: u64) -> u8 {
    match kind {
        9007 | 9008 => 0,
        9021 | 9022 => 2,
        _ => 1,
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
