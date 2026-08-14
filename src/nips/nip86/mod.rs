//! NIP-86: Relay Management API.
//!
//! The current NIP-86 revision defines a JSON-RPC style protocol served on
//! the same URI as the relay's websocket, with `Content-Type:
//! application/nostr+json+rpc` and NIP-98 authentication. For backwards
//! compatibility the older REST endpoints remain available on a separate
//! localhost management port.

mod legacy;

pub(crate) use legacy::router;

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use crate::nips::nip98;
use crate::relay::Relay;

const RPC_CONTENT_TYPE: &str = "application/nostr+json+rpc";

// ----- new-style JSON-RPC API (served on the relay's HTTP endpoint) -----

/// Methods implemented by this relay (a subset of the NIP-86 list).
const SUPPORTED_METHODS: &[&str] = &[
    "supportedmethods",
    "banpubkey",
    "unbanpubkey",
    "listbannedpubkeys",
    "allowpubkey",
    "unallowpubkey",
    "listallowedpubkeys",
    "allowkind",
    "disallowkind",
    "listallowedkinds",
    "changerelayname",
    "changerelaydescription",
    "changerelayicon",
    "createrole",
    "editrole",
    "deleterole",
    "assignrole",
    "unassignrole",
    "blockip",
    "unblockip",
    "listblockedips",
    "banevent",
    "allowevent",
    "listbannedevents",
    "listeventsneedingmoderation",
];

fn rpc_ok(result: Value) -> Response {
    (StatusCode::OK, Json(json!({ "result": result }))).into_response()
}

fn rpc_err(message: &str) -> Response {
    (StatusCode::OK, Json(json!({ "error": message }))).into_response()
}

/// NIP-86 JSON-RPC handler, mounted on `POST /` and `POST /ws`.
pub async fn rpc_handler(
    State(relay): State<Arc<Relay>>,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: String,
) -> Response {
    // The spec requires the JSON-RPC content type (parameters such as
    // `; charset=utf-8` are tolerated).
    let is_rpc = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|t| t.split(';').next().map(str::trim) == Some(RPC_CONTENT_TYPE))
        .unwrap_or(false);
    if !is_rpc {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid content type" })),
        )
            .into_response();
    }
    if !rpc_authenticated(&relay, &headers, &uri).await {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        )
            .into_response();
    }
    let request: Value = match serde_json::from_str(&body) {
        Ok(request) => request,
        Err(_) => return rpc_err("invalid request"),
    };
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        return rpc_err("missing method");
    };
    let params = request.get("params").and_then(Value::as_array).cloned();
    let params = params.as_deref().unwrap_or(&[]);

    match method {
        "supportedmethods" => rpc_ok(json!(SUPPORTED_METHODS)),
        "banpubkey" => {
            let Some(pubkey) = params.first().and_then(Value::as_str) else {
                return rpc_err("invalid params");
            };
            if !is_pubkey(pubkey) {
                return rpc_err("invalid pubkey");
            }
            let mut access = relay.access.write().await;
            if !access.blocked_pubkeys.iter().any(|p| p == pubkey) {
                access.blocked_pubkeys.push(pubkey.to_string());
            }
            rpc_ok(json!(true))
        }
        "unbanpubkey" => {
            let Some(pubkey) = params.first().and_then(Value::as_str) else {
                return rpc_err("invalid params");
            };
            relay
                .access
                .write()
                .await
                .blocked_pubkeys
                .retain(|p| p != pubkey);
            rpc_ok(json!(true))
        }
        "listbannedpubkeys" => {
            let access = relay.access.read().await;
            let list: Vec<Value> = access
                .blocked_pubkeys
                .iter()
                .map(|pubkey| json!({ "pubkey": pubkey, "reason": "" }))
                .collect();
            rpc_ok(json!(list))
        }
        "allowpubkey" => {
            let Some(pubkey) = params.first().and_then(Value::as_str) else {
                return rpc_err("invalid params");
            };
            if !is_pubkey(pubkey) {
                return rpc_err("invalid pubkey");
            }
            let mut access = relay.access.write().await;
            if !access.allowed_pubkeys.iter().any(|p| p == pubkey) {
                access.allowed_pubkeys.push(pubkey.to_string());
            }
            rpc_ok(json!(true))
        }
        "unallowpubkey" => {
            let Some(pubkey) = params.first().and_then(Value::as_str) else {
                return rpc_err("invalid params");
            };
            relay
                .access
                .write()
                .await
                .allowed_pubkeys
                .retain(|p| p != pubkey);
            rpc_ok(json!(true))
        }
        "listallowedpubkeys" => {
            let access = relay.access.read().await;
            let list: Vec<Value> = access
                .allowed_pubkeys
                .iter()
                .map(|pubkey| json!({ "pubkey": pubkey, "reason": "" }))
                .collect();
            rpc_ok(json!(list))
        }
        "allowkind" => {
            let Some(kind) = params.first().and_then(Value::as_u64) else {
                return rpc_err("invalid params");
            };
            let mut access = relay.access.write().await;
            if !access.allowed_kinds.contains(&kind) {
                access.allowed_kinds.push(kind);
            }
            rpc_ok(json!(true))
        }
        "disallowkind" => {
            let Some(kind) = params.first().and_then(Value::as_u64) else {
                return rpc_err("invalid params");
            };
            let mut access = relay.access.write().await;
            if !access.blocked_kinds.contains(&kind) {
                access.blocked_kinds.push(kind);
            }
            rpc_ok(json!(true))
        }
        "listallowedkinds" => {
            let access = relay.access.read().await;
            rpc_ok(json!(access.allowed_kinds))
        }
        "changerelayname" | "changerelaydescription" | "changerelayicon" => {
            let Some(value) = params.first().and_then(Value::as_str) else {
                return rpc_err("invalid params");
            };
            let mut cfg = relay.config.write().await;
            match method {
                "changerelayname" => cfg.relay.name = value.to_string(),
                "changerelaydescription" => cfg.relay.description = value.to_string(),
                _ => cfg.relay.icon = value.to_string(),
            }
            rpc_ok(json!(true))
        }
        // NIP-43 role management.
        "createrole" => {
            let Some(id) = params.first().and_then(Value::as_str) else {
                return rpc_err("invalid params");
            };
            let label = params.get(1).and_then(Value::as_str).unwrap_or("");
            let description = params.get(2).and_then(Value::as_str).unwrap_or("");
            let color = params.get(3).and_then(Value::as_str).unwrap_or("");
            let order = params.get(4).and_then(Value::as_i64);
            if relay
                .create_role(id, label, description, color, order)
                .await
            {
                rpc_ok(json!(true))
            } else {
                rpc_err("restricted: NIP-43 is disabled or the relay key is not configured")
            }
        }
        "editrole" => {
            let Some(id) = params.first().and_then(Value::as_str) else {
                return rpc_err("invalid params");
            };
            let label = params.get(1).and_then(Value::as_str).unwrap_or("");
            let description = params.get(2).and_then(Value::as_str).unwrap_or("");
            let color = params.get(3).and_then(Value::as_str).unwrap_or("");
            let order = params.get(4).and_then(Value::as_i64);
            if relay
                .create_role(id, label, description, color, order)
                .await
            {
                rpc_ok(json!(true))
            } else {
                rpc_err("restricted: NIP-43 is disabled or the relay key is not configured")
            }
        }
        "deleterole" => {
            let Some(id) = params.first().and_then(Value::as_str) else {
                return rpc_err("invalid params");
            };
            if relay.delete_role(id).await {
                rpc_ok(json!(true))
            } else {
                rpc_err("restricted: NIP-43 is disabled or the relay key is not configured")
            }
        }
        "assignrole" => {
            let (Some(pubkey), Some(role)) = (
                params.first().and_then(Value::as_str),
                params.get(1).and_then(Value::as_str),
            ) else {
                return rpc_err("invalid params");
            };
            if !is_pubkey(pubkey) {
                return rpc_err("invalid pubkey");
            }
            if relay.assign_role(pubkey, role).await {
                rpc_ok(json!(true))
            } else {
                rpc_err(
                    "restricted: NIP-43 is disabled, the relay key is missing or the role does not exist",
                )
            }
        }
        "unassignrole" => {
            let (Some(pubkey), Some(role)) = (
                params.first().and_then(Value::as_str),
                params.get(1).and_then(Value::as_str),
            ) else {
                return rpc_err("invalid params");
            };
            relay.unassign_role(pubkey, role).await;
            rpc_ok(json!(true))
        }
        "blockip" => {
            let Some(ip) = params.first().and_then(Value::as_str) else {
                return rpc_err("invalid params");
            };
            if ip.parse::<std::net::IpAddr>().is_err() {
                return rpc_err("invalid ip address");
            }
            let mut access = relay.access.write().await;
            if !access.blocked_ips.iter().any(|i| i == ip) {
                access.blocked_ips.push(ip.to_string());
            }
            rpc_ok(json!(true))
        }
        "unblockip" => {
            let Some(ip) = params.first().and_then(Value::as_str) else {
                return rpc_err("invalid params");
            };
            relay.access.write().await.blocked_ips.retain(|i| i != ip);
            rpc_ok(json!(true))
        }
        "listblockedips" => {
            let access = relay.access.read().await;
            let list: Vec<Value> = access
                .blocked_ips
                .iter()
                .map(|ip| json!({ "ip": ip, "reason": "" }))
                .collect();
            rpc_ok(json!(list))
        }
        "banevent" => {
            let (Some(id), reason) = (
                params.first().and_then(Value::as_str),
                params.get(1).and_then(Value::as_str).unwrap_or(""),
            ) else {
                return rpc_err("invalid params");
            };
            let Ok(id) = hex::decode(id) else {
                return rpc_err("invalid event id");
            };
            let Ok(id): Result<[u8; 32], _> = id.try_into() else {
                return rpc_err("invalid event id");
            };
            relay.db.ban_event(id, reason).await;
            rpc_ok(json!(true))
        }
        "allowevent" => {
            let Some(id) = params.first().and_then(Value::as_str) else {
                return rpc_err("invalid params");
            };
            let Ok(id) = hex::decode(id) else {
                return rpc_err("invalid event id");
            };
            let Ok(id): Result<[u8; 32], _> = id.try_into() else {
                return rpc_err("invalid event id");
            };
            relay.db.unban_event(id).await;
            rpc_ok(json!(true))
        }
        "listbannedevents" => {
            let list: Vec<Value> = relay
                .db
                .list_banned_events()
                .await
                .into_iter()
                .map(|(id, reason)| json!({ "id": id, "reason": reason }))
                .collect();
            rpc_ok(json!(list))
        }
        "listeventsneedingmoderation" => {
            // This relay has no moderation queue: no events await review.
            rpc_ok(json!([]))
        }
        _ => rpc_err("unsupported method"),
    }
}

fn is_pubkey(value: &str) -> bool {
    hex::decode(value).map(|b| b.len() == 32).unwrap_or(false)
}

/// Constant-time comparison for the management token: the token must not be
/// recoverable through response-timing differences of the comparison.
fn ct_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    let mut diff = (a.len() ^ b.len()) as u8;
    let n = a.len().max(b.len());
    for i in 0..n {
        diff |= a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0);
    }
    diff == 0
}

/// NIP-86 authentication: either the bearer `management_token` or a NIP-98
/// event by `admin_pubkey` whose `payload` tag is present and whose `u` tag
/// matches this relay's URL, including the request path and query
/// (NIP-98: "the `u` tag MUST be exactly the same as the absolute request
/// URL"; the scheme is normalized so TLS-terminating proxies keep working).
async fn rpc_authenticated(relay: &Relay, headers: &HeaderMap, uri: &axum::http::Uri) -> bool {
    let cfg = relay.config.read().await;
    if !cfg.server.management_token.is_empty()
        && let Some(token) = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
        && ct_eq(token, &cfg.server.management_token)
    {
        return true;
    }
    if !cfg.server.admin_pubkey.is_empty()
        && let Some(auth) = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Nostr "))
        && nip98::verify(
            auth,
            Some(&cfg.server.admin_pubkey),
            relay.secp(),
            true,
            "POST",
            |url| {
                nip98::matches_request_url(
                    url,
                    &cfg.server.host,
                    cfg.server.port,
                    &cfg.relay.public_url,
                    uri.path(),
                    uri.query(),
                )
            },
        )
        .await
        .is_some()
    {
        return true;
    }
    false
}
