//! NIP-62: Request to Vanish.
//!
//! A kind-62 event requests the complete deletion of every event authored by
//! the event's pubkey. The relay must also make sure those events can never
//! be re-published afterwards.
//!
//! This module also hosts [`RelayIdentity`], the relay's own URL identity
//! used to validate `relay` and `u` tags (NIP-42/62/98).

use crate::event::Event;

/// The relay's own URL identity: the bound host:port plus the optional
/// public URL, which overrides them when set. Shared by the NIP-42/62/98
/// tag validations.
#[derive(Debug, Clone, Copy)]
pub struct RelayIdentity<'a> {
    host: &'a str,
    port: u16,
    public_url: &'a str,
}

impl<'a> RelayIdentity<'a> {
    pub fn new(host: &'a str, port: u16, public_url: &'a str) -> Self {
        RelayIdentity {
            host,
            port,
            public_url,
        }
    }
}

pub const VANISH_KIND: u64 = 62;
pub const RELAY_TAG: &str = "relay";
pub const ALL_RELAYS: &str = "ALL_RELAYS";
/// Kind of NIP-59 gift wraps (deleted as a courtesy when they p-tag the
/// vanished pubkey).
pub const GIFT_WRAP_KIND: u64 = 1059;

/// Returns `true` when the event is a request to vanish.
pub fn is_vanish(event: &Event) -> bool {
    event.kind == VANISH_KIND
        && event
            .tags
            .iter()
            .any(|t| t.first().map(String::as_str) == Some(RELAY_TAG))
}

/// Returns `true` when the request targets this relay, either because its
/// `relay` tag equals `ALL_RELAYS` or because it names our own URL.
pub fn targets_us(event: &Event, identity: &RelayIdentity<'_>) -> bool {
    event
        .tags
        .iter()
        .filter(|t| t.len() >= 2 && t[0] == RELAY_TAG)
        .any(|t| tag_matches(&t[1], identity))
}

/// Compares a relay URL tag value against this relay's host:port (or
/// `public_url` when set), tolerating different schemes and paths. Also used
/// by NIP-42 to validate the `relay` tag of auth events.
pub fn tag_matches(tag: &str, identity: &RelayIdentity<'_>) -> bool {
    if tag == ALL_RELAYS {
        return true;
    }
    // Compare host:port, tolerating different schemes, paths and the
    // hostname variants (localhost vs 127.0.0.1 are intentionally not
    // normalized further).
    let authority = tag
        .strip_prefix("wss://")
        .or_else(|| tag.strip_prefix("ws://"))
        .or_else(|| tag.strip_prefix("https://"))
        .or_else(|| tag.strip_prefix("http://"))
        .unwrap_or(tag);
    let authority = authority.split(['/', '?', '#']).next().unwrap_or(authority);
    let (tag_host, tag_port) = split_host_port(authority);
    let authority = authority_of(identity);
    let (our_host, our_port) = split_host_port(&authority);
    tag_host == our_host && (tag_port == our_port || tag_port.is_none())
}

pub(crate) fn authority_of(identity: &RelayIdentity<'_>) -> String {
    if let Some(rest) = identity
        .public_url
        .strip_prefix("wss://")
        .or_else(|| identity.public_url.strip_prefix("ws://"))
        .or_else(|| identity.public_url.strip_prefix("https://"))
        .or_else(|| identity.public_url.strip_prefix("http://"))
    {
        let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
        return authority.to_string();
    }
    format!("{}:{}", identity.host, identity.port)
}

pub(crate) fn split_host_port(authority: &str) -> (&str, Option<u16>) {
    if let Some((host, port)) = authority.rsplit_once(':')
        && let Ok(port) = port.parse::<u16>()
    {
        return (host, Some(port));
    }
    (authority, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(relay: &str) -> Event {
        Event {
            id: "a".repeat(64),
            pubkey: "b".repeat(64),
            created_at: 1,
            kind: VANISH_KIND,
            tags: vec![vec![RELAY_TAG.into(), relay.into()]],
            content: String::new(),
            sig: "c".repeat(128),
        }
    }

    #[test]
    fn detection() {
        assert!(is_vanish(&event("wss://relay.example.com")));
        let mut no_relay = event("x");
        no_relay.tags.clear();
        assert!(!is_vanish(&no_relay));
        let mut wrong_kind = event("x");
        wrong_kind.kind = 5;
        assert!(!is_vanish(&wrong_kind));
    }

    #[test]
    fn url_matching() {
        let identity = RelayIdentity::new("relay.example.com", 8080, "");
        assert!(targets_us(&event("ALL_RELAYS"), &identity));
        assert!(targets_us(&event("ws://relay.example.com:8080"), &identity));
        assert!(targets_us(
            &event("wss://relay.example.com:8080/some/path"),
            &identity
        ));
        assert!(!targets_us(
            &event("ws://other.example.com:8080"),
            &identity
        ));
        assert!(!targets_us(
            &event("ws://relay.example.com:9999"),
            &identity
        ));
        // public_url overrides the configured host/port.
        let public = RelayIdentity::new("127.0.0.1", 8080, "wss://public.example.net");
        assert!(targets_us(&event("wss://public.example.net"), &public));
    }
}
