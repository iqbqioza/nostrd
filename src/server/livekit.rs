//! NIP-29 LiveKit integration: the well-known capability endpoint and the
//! per-group token endpoint authenticated with NIP-98 HTTP auth.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path as AxPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use serde_json::json;

use base64::Engine;

use crate::config::Config;
use crate::error::Result;
use crate::relay::Relay;
use crate::stats::unix_now;

// ----- NIP-29 LiveKit integration -----

/// `GET /.well-known/nip29/livekit` — 204 when LiveKit rooms are supported.
pub(crate) async fn livekit_supported(State(relay): State<Arc<Relay>>) -> impl IntoResponse {
    let cfg = relay.config.read().await;
    if cfg.nip_enabled(29) && !cfg.relay.livekit_url.is_empty() {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

/// `GET /.well-known/nip29/livekit/<group>` — issues a LiveKit JWT for a
/// group member, authenticated with a NIP-98 HTTP auth event.
pub(crate) async fn livekit_token(
    State(relay): State<Arc<Relay>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    AxPath(group): AxPath<String>,
) -> impl IntoResponse {
    let cfg = relay.config.read().await;
    if !cfg.nip_enabled(29)
        || cfg.relay.livekit_api_key.is_empty()
        || cfg.relay.livekit_api_secret.is_empty()
    {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "livekit not configured" })),
        );
    }
    let expected_path = format!("/.well-known/nip29/livekit/{group}");
    let encoded = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Nostr "))
        .map(str::to_string);
    let Some(encoded) = encoded else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        );
    };
    // NIP-29: the auth event's `u` tag must point at this group's livekit
    // token endpoint (exact path and query), and its `method` tag must
    // match the GET request.
    let authed = crate::nips::nip98::verify(&encoded, None, relay.secp(), false, "GET", |url| {
        crate::nips::nip98::matches_request_url(
            url,
            &cfg.server.host,
            cfg.server.port,
            &cfg.relay.public_url,
            &expected_path,
            uri.query(),
        )
    })
    .await;
    match authed {
        Some(pubkey) if group_allows(&relay, &group, &pubkey).await => {
            match issue_livekit_token(&cfg, &group, &pubkey) {
                Ok(token) => {
                    let url = cfg.relay.livekit_url.clone();
                    (StatusCode::OK, Json(json!({ "token": token, "url": url })))
                }
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": e.to_string() })),
                ),
            }
        }
        _ => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        ),
    }
}

async fn group_allows(relay: &Relay, group: &str, pubkey: &str) -> bool {
    let groups = relay.groups.read().await;
    match groups.group(group) {
        // Unknown groups are open.
        None => true,
        Some(g) => !g.settings.private && !g.settings.restricted || g.is_member(pubkey),
    }
}

fn issue_livekit_token(cfg: &Config, group: &str, pubkey: &str) -> Result<String> {
    let mut suffix = [0u8; 4];
    getrandom::getrandom(&mut suffix)
        .map_err(|e| crate::error::Error::Other(format!("rng failure: {e}")))?;
    let identity = format!("{pubkey}{}", hex::encode(suffix));
    let now = unix_now();
    let claims = json!({
        "iss": cfg.relay.livekit_api_key,
        "sub": identity,
        "iat": now,
        "nbf": now,
        "exp": now + 3600,
        "video": {
            "room": group,
            "identity": identity,
            "permissions": { "canPublish": true, "canSubscribe": true, "canPublishData": true }
        }
    });
    jwt_hs256(&cfg.relay.livekit_api_secret, &claims)
}

/// Minimal HS256 JWT implementation (base64url + HMAC-SHA256).
fn jwt_hs256(secret: &str, claims: &serde_json::Value) -> Result<String> {
    fn b64url(data: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
    }
    let header = b64url(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = b64url(serde_json::to_string(claims)?.as_bytes());
    let signing_input = format!("{header}.{payload}");
    let mac = hmac_sha256(secret.as_bytes(), signing_input.as_bytes());
    Ok(format!("{signing_input}.{}", b64url(&mac)))
}

/// HMAC-SHA256 (RFC 2104), implemented locally to avoid extra dependencies.
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    const BLOCK: usize = 64;
    let mut key = key.to_vec();
    if key.len() > BLOCK {
        key = Sha256::digest(&key).to_vec();
    }
    key.resize(BLOCK, 0);
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for (i, b) in key.iter().enumerate() {
        ipad[i] ^= b;
        opad[i] ^= b;
    }
    let inner = Sha256::digest([ipad.as_slice(), data].concat());
    let outer = Sha256::digest([opad.as_slice(), inner.as_slice()].concat());
    outer.into()
}
