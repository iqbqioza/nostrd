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
    let mut info = json!({
        "name": config.relay.name,
        "description": config.relay.description,
        "pubkey": config.relay.pubkey,
        "contact": config.relay.contact,
        "supported_nips": config.supported_nips(),
        "software": config.relay.software,
        "version": config.relay.version,
        "icon": config.relay.icon,
        "limitation": {
            "max_message_length": limits.max_ws_message_size,
            "max_subscriptions": limits.max_subscriptions,
            "max_filters": limits.max_filters,
            "max_limit": limits.max_limit,
            "max_subid_length": limits.max_sub_id_len,
            "max_event_tags": limits.max_tags,
            "max_content_length": limits.max_content_bytes,
            "min_pow_difficulty": limits.require_pow,
            "auth_required": config.server.require_auth,
            "payment_required": false,
            "restricted_writes": false,
            "created_at_lower_limit": 0,
            "created_at_upper_limit": null,
            "default_limit": limits.max_limit,
        },
        "retention": [
            { "kinds": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 40, 41, 42, 43, 44, 30023, 30078], "time": 31536000 },
            { "kinds": [10000, 10001, 10002, 30000, 30001], "time": 31536000 },
            { "kinds": [20000, 20001, 30000], "time": null }
        ],
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
    if config.nip_enabled(29) {
        info["nip29"] = json!({ "subgroups": true });
    }
    info
}

pub async fn info_handler(State(relay): State<Arc<Relay>>) -> Json<Value> {
    let cfg = relay.config.read().await;
    Json(relay_info(
        &cfg,
        &relay.stats,
        relay.relay_pubkey().as_deref(),
    ))
}

pub async fn stats_handler(State(relay): State<Arc<Relay>>) -> Json<Value> {
    Json(relay.stats.as_json())
}
