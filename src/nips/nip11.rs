//! NIP-11: Relay Information Document.
//!
//! Served on `GET /` as `application/nostr+json`.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use serde_json::{Value, json};

use crate::config::Config;
use crate::relay::Relay;
use crate::stats::Stats;

pub fn relay_info(config: &Config, stats: &Stats, self_pubkey: Option<&str>) -> Value {
    let limits = &config.limits;
    // NIP-11: any field may be omitted. Empty string fields are omitted
    // too: some clients try to decode the pubkey/icon as data and fail on
    // an empty value.
    let mut info = json!({
        "name": config.relay.name,
        "description": config.relay.description,
        "pubkey": config.relay.pubkey,
        "contact": config.relay.contact,
        "icon": config.relay.icon,
        "supported_nips": config.supported_nips(),
        "software": env!("CARGO_PKG_REPOSITORY"),
        "version": env!("CARGO_PKG_VERSION"),
        "limitation": {
            "max_message_length": limits.max_ws_message_size,
            "max_subscriptions": limits.max_subscriptions,
            "max_filters": limits.max_filters,
            "max_limit": limits.max_limit,
            "max_subid_length": limits.max_sub_id_len,
            "max_event_tags": limits.max_tags,
            "max_content_length": limits.max_content_bytes,
            // Only advertise the PoW floor when NIP-13 is enabled and it is
            // actually enforced; otherwise reporting `require_pow` would
            // claim a difficulty the relay never checks.
            "min_pow_difficulty": if config.nip_enabled(13) { limits.require_pow } else { 0 },
            "auth_required": config.server.require_auth,
            "payment_required": false,
            "restricted_writes": false,
            "created_at_lower_limit": 0,
            // NIP-11: an absolute unix timestamp. The relay accepts events up
            // to `max_created_at_future` seconds into the future.
            "created_at_upper_limit": crate::util::unix_now() + limits.max_created_at_future,
            "default_limit": limits.max_limit,
        },
        // The relay never purges by age: events are kept indefinitely unless
        // a NIP-40 expiration elapses, a NIP-09 deletion/NIP-62 vanish/NIP-86
        // ban removes them, or the operator prunes the database. A `null`
        // time means indefinite retention.
        "retention": [{ "kinds": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 40, 41, 42, 43, 44, 10000, 10001, 10002, 30000, 30001, 30023, 30078], "time": null }],
        "relay_countries": [],
        "language_tags": [],
        "tags": [],
        "posting_policy": config.relay.post_policy,
        "payments_url": "",
        "fees": {
            "admission": [],
            "subscription": [],
            "periodic": []
        },
        "stats": stats.as_json(),
    });
    if let Some(self_pubkey) = self_pubkey {
        info["self"] = json!(self_pubkey);
    }
    for field in [
        "pubkey",
        "contact",
        "icon",
        "posting_policy",
        "payments_url",
    ] {
        if info.get(field).and_then(Value::as_str) == Some("") {
            info.as_object_mut()
                .expect("relay_info builds an object")
                .remove(field);
        }
    }
    if config.nip_enabled(29) {
        info["nip29"] = json!({ "subgroups": true });
    }
    info
}

pub async fn stats_handler(State(relay): State<Arc<Relay>>) -> Json<Value> {
    Json(relay.stats.as_json())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::util::unix_now;

    fn info() -> Value {
        let cfg = Config::default();
        let stats = Stats::new();
        relay_info(&cfg, &stats, None)
    }

    #[test]
    fn upper_limit_is_absolute() {
        let info = info();
        let upper = info["limitation"]["created_at_upper_limit"]
            .as_u64()
            .expect("upper limit is a number");
        let now = unix_now();
        let max_future = Config::default().limits.max_created_at_future;
        assert!(
            upper >= now + max_future.saturating_sub(1) && upper <= now + max_future + 1,
            "upper limit must be now + max_created_at_future, got {upper} vs now {now} + {max_future}"
        );
    }

    #[test]
    fn retention_is_indefinite() {
        let info = info();
        let retention = info["retention"].as_array().expect("retention is an array");
        assert_eq!(retention.len(), 1);
        let entry = &retention[0];
        assert!(
            entry["time"].is_null(),
            "no age-based purge means indefinite retention"
        );
        let kinds = entry["kinds"].as_array().expect("kinds is an array");
        assert!(!kinds.is_empty());
    }

    #[test]
    fn empty_fields_are_omitted() {
        let info = info();
        assert!(info.get("contact").is_none());
        assert!(info.get("icon").is_none());
        assert!(info.get("posting_policy").is_none());
        assert!(info.get("payments_url").is_none());
    }

    #[test]
    fn identity_fields_are_advertised_when_set() {
        let mut cfg = Config::default();
        cfg.relay.pubkey = "aa".repeat(32);
        cfg.relay.contact = "https://example.com/contact".to_string();
        cfg.relay.icon = "https://example.com/icon.png".to_string();
        let stats = Stats::new();
        let info = relay_info(&cfg, &stats, Some(&"bb".repeat(32)));
        assert_eq!(info["pubkey"], "aa".repeat(32));
        assert_eq!(info["contact"], "https://example.com/contact");
        assert_eq!(info["icon"], "https://example.com/icon.png");
        assert_eq!(info["self"], "bb".repeat(32));
    }

    #[test]
    fn advertises_relay_nips() {
        let info = info();
        let nips = info["supported_nips"]
            .as_array()
            .expect("supported_nips is an array");
        let nips: Vec<u16> = nips.iter().map(|n| n.as_u64().unwrap() as u16).collect();
        for expected in [1u16, 9, 11, 26, 29, 42, 45, 50, 62, 70, 77, 86, 98] {
            assert!(
                nips.contains(&expected),
                "NIP-{expected} must be advertised"
            );
        }
    }
}
