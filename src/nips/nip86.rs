//! NIP-86: Relay Management API.
//!
//! The current NIP-86 revision defines a JSON-RPC style protocol served on
//! the same URI as the relay's websocket, with `Content-Type:
//! application/nostr+json+rpc` and NIP-98 authentication. For backwards
//! compatibility the older REST endpoints remain available on a separate
//! localhost management port.

use std::sync::Arc;

use axum::extract::{Path as AxPath, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::watch;

use crate::nips::nip11::relay_info;
use crate::nips::nip62;
use crate::nips::nip98;
use crate::relay::Relay;
use crate::stats::unix_now;

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
    if !rpc_authenticated(&relay, &headers).await {
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

/// NIP-86 authentication: either the bearer `management_token` or a NIP-98
/// event by `admin_pubkey` whose `payload` tag is present and whose `u` tag
/// matches this relay's URL.
async fn rpc_authenticated(relay: &Relay, headers: &HeaderMap) -> bool {
    let cfg = relay.config.read().await;
    if !cfg.server.management_token.is_empty()
        && let Some(token) = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
        && token == cfg.server.management_token
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
            |url| {
                nip62::tag_matches(
                    url,
                    &cfg.server.host,
                    cfg.server.port,
                    &cfg.relay.public_url,
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

// ----- legacy REST endpoints (localhost management port) -----

#[derive(Deserialize)]
struct PubkeyBody {
    pubkey: String,
}

#[derive(Deserialize)]
struct KindBody {
    kind: u64,
}

struct AdminState {
    relay: Arc<Relay>,
    shutdown: watch::Sender<bool>,
}

pub fn router(relay: Arc<Relay>, shutdown_tx: watch::Sender<bool>) -> Router {
    Router::new()
        .route("/admin/info", get(admin_info))
        .route("/admin/stats", get(admin_stats))
        .route("/admin/block_pubkey", post(block_pubkey))
        .route("/admin/allow_pubkey", post(allow_pubkey))
        .route("/admin/block_kind", post(block_kind))
        .route("/admin/allow_kind", post(allow_kind))
        .route("/admin/status/{id}", get(event_status))
        .route("/admin/shutdown", post(shutdown))
        .layer(axum::middleware::from_fn(crate::server::cors_middleware))
        .with_state(Arc::new(AdminState {
            relay,
            shutdown: shutdown_tx,
        }))
}

async fn check_auth(headers: &HeaderMap, state: &AdminState) -> std::result::Result<(), Response> {
    let relay = &state.relay;
    let cfg = relay.config.read().await;

    if !cfg.server.management_token.is_empty() {
        let token = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(|| unauthorized("missing bearer token"))?;
        if token == cfg.server.management_token {
            return Ok(());
        }
        return Err(unauthorized("invalid bearer token"));
    }

    if !cfg.server.admin_pubkey.is_empty() {
        let auth = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Nostr "))
            .ok_or_else(|| unauthorized("missing NIP-98 auth"))?;
        if nip98::verify(
            auth,
            Some(&cfg.server.admin_pubkey),
            relay.secp(),
            true,
            |_| true,
        )
        .await
        .is_some()
        {
            return Ok(());
        }
        return Err(unauthorized("invalid NIP-98 auth"));
    }

    Err(unauthorized(
        "management API disabled: set server.management_token or server.admin_pubkey",
    ))
}

fn unauthorized(msg: &str) -> Response {
    (StatusCode::UNAUTHORIZED, Json(json!({ "error": msg }))).into_response()
}

fn bad_request(msg: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response()
}

async fn admin_info(State(state): State<Arc<AdminState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = check_auth(&headers, &state).await {
        return resp;
    }
    let cfg = state.relay.config.read().await;
    Json(relay_info(
        &cfg,
        &state.relay.stats,
        state.relay.relay_pubkey().as_deref(),
    ))
    .into_response()
}

async fn admin_stats(State(state): State<Arc<AdminState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = check_auth(&headers, &state).await {
        return resp;
    }
    Json(state.relay.stats.as_json()).into_response()
}

async fn block_pubkey(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Json(body): Json<PubkeyBody>,
) -> Response {
    if let Err(resp) = check_auth(&headers, &state).await {
        return resp;
    }
    if hex::decode(&body.pubkey)
        .map(|b| b.len() != 32)
        .unwrap_or(true)
    {
        return bad_request("invalid pubkey");
    }
    let mut access = state.relay.access.write().await;
    if !access.blocked_pubkeys.iter().any(|p| p == &body.pubkey) {
        access.blocked_pubkeys.push(body.pubkey.clone());
    }
    Json(json!({ "ok": true, "blocked_pubkey": body.pubkey })).into_response()
}

async fn allow_pubkey(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Json(body): Json<PubkeyBody>,
) -> Response {
    if let Err(resp) = check_auth(&headers, &state).await {
        return resp;
    }
    let mut access = state.relay.access.write().await;
    access.blocked_pubkeys.retain(|p| p != &body.pubkey);
    Json(json!({ "ok": true, "allowed_pubkey": body.pubkey })).into_response()
}

async fn block_kind(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Json(body): Json<KindBody>,
) -> Response {
    if let Err(resp) = check_auth(&headers, &state).await {
        return resp;
    }
    let mut access = state.relay.access.write().await;
    if !access.blocked_kinds.contains(&body.kind) {
        access.blocked_kinds.push(body.kind);
    }
    Json(json!({ "ok": true, "blocked_kind": body.kind })).into_response()
}

async fn allow_kind(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Json(body): Json<KindBody>,
) -> Response {
    if let Err(resp) = check_auth(&headers, &state).await {
        return resp;
    }
    let mut access = state.relay.access.write().await;
    access.blocked_kinds.retain(|k| k != &body.kind);
    Json(json!({ "ok": true, "allowed_kind": body.kind })).into_response()
}

async fn event_status(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    AxPath(id): AxPath<String>,
) -> Response {
    if let Err(resp) = check_auth(&headers, &state).await {
        return resp;
    }
    let filter: Value = json!({ "ids": [id] });
    let (event, _) = state
        .relay
        .db
        .query(vec![serde_json::from_value(filter).unwrap()], 1, unix_now())
        .await;
    if event.is_empty() {
        return Json(json!({ "ok": false, "found": false })).into_response();
    }
    Json(json!({ "ok": true, "found": true, "event": event[0] })).into_response()
}

async fn shutdown(State(state): State<Arc<AdminState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = check_auth(&headers, &state).await {
        return resp;
    }
    let _ = state.shutdown.send(true);
    Json(json!({ "ok": true, "shutting_down": true })).into_response()
}
