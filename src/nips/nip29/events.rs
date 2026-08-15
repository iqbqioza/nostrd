//! Relay-generated NIP-29 events: metadata (39000), admins (39001),
//! members (39002), pins (39005) and the put-user/remove-user moderation
//! events emitted by the group state machine.

use crate::event::Event;

use super::{D, GROUP_ADMINS, GROUP_MEMBERS, GROUP_META, GROUP_PINS, Group, GroupSettings, H, P};
pub(crate) fn apply_settings(group: &mut Group, event: &Event) {
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

pub(crate) fn base_event(kind: u64, gid: &str, relay_pubkey: &str, now: u64) -> Event {
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

pub(crate) fn build_meta_event(
    gid: &str,
    group: Option<&Group>,
    relay_pubkey: &str,
    now: u64,
) -> Event {
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

pub(crate) fn build_admins_event(
    gid: &str,
    group: Option<&Group>,
    relay_pubkey: &str,
    now: u64,
) -> Event {
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

pub(crate) fn build_members_event(
    gid: &str,
    group: Option<&Group>,
    relay_pubkey: &str,
    now: u64,
) -> Event {
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

pub(crate) fn build_pins_event(
    gid: &str,
    group: Option<&Group>,
    relay_pubkey: &str,
    now: u64,
) -> Event {
    let mut event = base_event(GROUP_PINS, gid, relay_pubkey, now);
    if let Some(group) = group {
        for (tag, value) in &group.pins {
            event.tags.push(vec![tag.clone(), value.clone()]);
        }
    }
    event
}

pub(crate) fn build_put_user(
    gid: &str,
    member: &str,
    roles: &[&str],
    relay_pubkey: &str,
    now: u64,
) -> Event {
    let mut event = base_event(9000, gid, relay_pubkey, now);
    event.tags[0] = vec![H.to_string(), gid.to_string()];
    let mut tag = vec![P.to_string(), member.to_string()];
    tag.extend(roles.iter().map(|r| r.to_string()));
    event.tags.push(tag);
    event
}

pub(crate) fn build_remove_user(gid: &str, member: &str, relay_pubkey: &str, now: u64) -> Event {
    let mut event = base_event(9001, gid, relay_pubkey, now);
    event.tags[0] = vec![H.to_string(), gid.to_string()];
    event.tags.push(vec![P.to_string(), member.to_string()]);
    event
}
