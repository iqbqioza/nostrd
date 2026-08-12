//! NIP-62: Request to Vanish.
//!
//! A kind-62 event requests the complete deletion of every event authored by
//! the event's pubkey. The relay must also make sure those events can never
//! be re-published afterwards.

use crate::event::Event;

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
pub fn targets_us(event: &Event, host: &str, port: u16, public_url: &str) -> bool {
    event
        .tags
        .iter()
        .filter(|t| t.len() >= 2 && t[0] == RELAY_TAG)
        .any(|t| tag_matches(&t[1], host, port, public_url))
}

/// Compares a relay URL tag value against this relay's host:port (or
/// `public_url` when set), tolerating different schemes and paths. Also used
/// by NIP-42 to validate the `relay` tag of auth events.
pub fn tag_matches(tag: &str, host: &str, port: u16, public_url: &str) -> bool {
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
    let authority = authority_of(host, port, public_url);
    let (our_host, our_port) = split_host_port(&authority);
    tag_host == our_host && (tag_port == our_port || tag_port.is_none())
}

fn authority_of(host: &str, port: u16, public_url: &str) -> String {
    if let Some(rest) = public_url
        .strip_prefix("wss://")
        .or_else(|| public_url.strip_prefix("ws://"))
    {
        let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
        return authority.to_string();
    }
    format!("{host}:{port}")
}

fn split_host_port(authority: &str) -> (&str, Option<u16>) {
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
        let host = "relay.example.com";
        let port = 8080;
        assert!(targets_us(&event("ALL_RELAYS"), host, port, ""));
        assert!(targets_us(
            &event("ws://relay.example.com:8080"),
            host,
            port,
            ""
        ));
        assert!(targets_us(
            &event("wss://relay.example.com:8080/some/path"),
            host,
            port,
            ""
        ));
        assert!(!targets_us(
            &event("ws://other.example.com:8080"),
            host,
            port,
            ""
        ));
        assert!(!targets_us(
            &event("ws://relay.example.com:9999"),
            host,
            port,
            ""
        ));
        // public_url overrides the configured host/port.
        assert!(targets_us(
            &event("wss://public.example.net"),
            "127.0.0.1",
            8080,
            "wss://public.example.net"
        ));
    }
}
