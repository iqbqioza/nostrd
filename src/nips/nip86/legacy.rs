//! Legacy REST management endpoints, served on the separate localhost
//! management port. Kept for backwards compatibility alongside the
//! JSON-RPC API in `super`.

use std::sync::Arc;

use axum::extract::{OriginalUri, Path as AxPath, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::watch;

use crate::nips::nip11::relay_info;
use crate::nips::nip98;
use crate::relay::Relay;
use crate::util::unix_now;

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

pub(crate) fn router(relay: Arc<Relay>, shutdown_tx: watch::Sender<bool>) -> Router {
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

async fn check_auth(
    headers: &HeaderMap,
    state: &AdminState,
    method: &str,
    uri: &axum::http::Uri,
) -> std::result::Result<(), Response> {
    let relay = &state.relay;
    let cfg = relay.config.read().await;

    // Bearer token, when configured. A wrong token falls through to the
    // NIP-98 check (matching the JSON-RPC path) so both methods can be
    // configured at once instead of one silently disabling the other.
    let mut token_configured = false;
    if !cfg.server.management_token.is_empty() {
        token_configured = true;
        if let Some(token) = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            && super::ct_eq(token, &cfg.server.management_token)
        {
            return Ok(());
        }
    }

    if !cfg.server.admin_pubkey.is_empty() {
        let auth = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Nostr "))
            .ok_or_else(|| unauthorized("missing NIP-98 auth"))?;
        // NIP-98: the `u` tag must be the absolute request URL (host, path
        // and query all match), matching the JSON-RPC path. The legacy
        // management API is served on the *management* host:port, not the
        // relay's main endpoint, so the authority is the management
        // host:port (the relay `public_url` does not apply here).
        let mgmt_identity = crate::nips::nip62::RelayIdentity::new(
            &cfg.server.management_host,
            cfg.server.management_port,
            "",
        );
        let url_ok =
            |tag: &str| nip98::matches_request_url(tag, &mgmt_identity, uri.path(), uri.query());
        if nip98::verify(
            auth,
            Some(&cfg.server.admin_pubkey),
            relay.secp(),
            true,
            method,
            url_ok,
        )
        .await
        .is_some()
        {
            return Ok(());
        }
        return Err(unauthorized("invalid NIP-98 auth"));
    }

    Err(unauthorized(if token_configured {
        "invalid bearer token"
    } else {
        "management API disabled: set server.management_token or server.admin_pubkey"
    }))
}

fn unauthorized(msg: &str) -> Response {
    (StatusCode::UNAUTHORIZED, Json(json!({ "error": msg }))).into_response()
}

fn bad_request(msg: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response()
}

async fn admin_info(
    uri: OriginalUri,
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(resp) = check_auth(&headers, &state, "GET", &uri).await {
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

async fn admin_stats(
    uri: OriginalUri,
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(resp) = check_auth(&headers, &state, "GET", &uri).await {
        return resp;
    }
    Json(state.relay.stats.as_json()).into_response()
}

async fn block_pubkey(
    uri: OriginalUri,
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Json(body): Json<PubkeyBody>,
) -> Response {
    if let Err(resp) = check_auth(&headers, &state, "POST", &uri).await {
        return resp;
    }
    if hex::decode(&body.pubkey)
        .map(|b| b.len() != 32)
        .unwrap_or(true)
    {
        return bad_request("invalid pubkey");
    }
    let mut access = state.relay.access.write().await;
    if !access
        .blocked_pubkeys
        .iter()
        .any(|(p, _)| p == &body.pubkey)
    {
        access
            .blocked_pubkeys
            .push((body.pubkey.clone(), String::new()));
    }
    drop(access);
    state.relay.persist_access().await;
    Json(json!({ "ok": true, "blocked_pubkey": body.pubkey })).into_response()
}

async fn allow_pubkey(
    uri: OriginalUri,
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Json(body): Json<PubkeyBody>,
) -> Response {
    if let Err(resp) = check_auth(&headers, &state, "POST", &uri).await {
        return resp;
    }
    let mut access = state.relay.access.write().await;
    access.blocked_pubkeys.retain(|(p, _)| p != &body.pubkey);
    drop(access);
    state.relay.persist_access().await;
    Json(json!({ "ok": true, "allowed_pubkey": body.pubkey })).into_response()
}

async fn block_kind(
    uri: OriginalUri,
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Json(body): Json<KindBody>,
) -> Response {
    if let Err(resp) = check_auth(&headers, &state, "POST", &uri).await {
        return resp;
    }
    let mut access = state.relay.access.write().await;
    if !access.blocked_kinds.contains(&body.kind) {
        access.blocked_kinds.push(body.kind);
    }
    drop(access);
    state.relay.persist_access().await;
    Json(json!({ "ok": true, "blocked_kind": body.kind })).into_response()
}

async fn allow_kind(
    uri: OriginalUri,
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Json(body): Json<KindBody>,
) -> Response {
    if let Err(resp) = check_auth(&headers, &state, "POST", &uri).await {
        return resp;
    }
    let mut access = state.relay.access.write().await;
    access.blocked_kinds.retain(|k| k != &body.kind);
    drop(access);
    state.relay.persist_access().await;
    Json(json!({ "ok": true, "allowed_kind": body.kind })).into_response()
}

async fn event_status(
    uri: OriginalUri,
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    AxPath(id): AxPath<String>,
) -> Response {
    if let Err(resp) = check_auth(&headers, &state, "GET", &uri).await {
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

async fn shutdown(
    uri: OriginalUri,
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(resp) = check_auth(&headers, &state, "POST", &uri).await {
        return resp;
    }
    let _ = state.shutdown.send(true);
    Json(json!({ "ok": true, "shutting_down": true })).into_response()
}
