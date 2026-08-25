//! Blossom file server (BUD-01 / BUD-02).
//!
//! Serves a media/blob store on a hostname dedicated like the REST API:
//! requests whose Host header matches `blossom.host` are served only the
//! Blossom routes. Files are stored as `bucket/{npub1xxx}/{sha256}` on
//! local disk or in an S3-compatible bucket, content-addressed by SHA-256.
//!
//! Endpoints:
//! - `GET /`            — server info
//! - `GET /<sha256>[.ext]` / `HEAD` — fetch / probe a blob
//! - `PUT /upload`      — upload (NIP-98 style auth, kind 24242, `t=upload`)
//! - `GET /list/<pubkey>` — blobs uploaded by a pubkey
//! - `DELETE /<sha256>[.ext]` — delete (auth, `t=delete`, `x=<sha256>`)

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path as AxPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use base64::Engine;
use serde_json::{Value, json};

use crate::config::Config;
use crate::relay::Relay;
use crate::util::unix_now;

use storage::BlobStore;

pub(crate) mod s3;
pub(crate) mod storage;

/// State shared by the Blossom handlers.
pub(crate) struct BlossomState {
    pub store: BlobStore,
    /// The configured blossom hostname (used for the `server` auth tag).
    pub host: String,
}

/// The routes, mounted by `build_router` only when `blossom.host` is set.
pub(crate) async fn routes(relay: &Arc<Relay>) -> axum::Router<Arc<Relay>> {
    let max_upload = relay.config.read().await.blossom.max_upload_bytes;
    // The root `/` route belongs to the relay: the WS handler answers it
    // with the Blossom server info when the Host names the Blossom host.
    axum::Router::new()
        .route(
            "/upload",
            put(upload).layer(DefaultBodyLimit::max(max_upload)),
        )
        .route("/list/{pubkey}", get(list))
        .route("/{blob}", get(get_blob).head(head_blob).delete(delete_blob))
        .with_state(relay.clone())
}

/// The configured Blossom state, when the feature is enabled and the
/// store initialized.
async fn state_of(relay: &Relay) -> Option<Arc<BlossomState>> {
    relay.blossom.read().await.clone()
}

/// Whether a request path belongs to the Blossom server (used by the
/// host-split middleware).
pub(crate) fn is_blossom_path(path: &str) -> bool {
    // The root `/` stays with the relay (WS + NIP-11): the WS handler
    // answers it with the Blossom server info when the Host names the
    // Blossom host.
    if path == "/upload" {
        return true;
    }
    if let Some(rest) = path.strip_prefix("/list/") {
        return is_pubkey(rest);
    }
    // `/<sha256>` or `/<sha256>.<ext>`
    let segment = path.trim_start_matches('/');
    if segment.is_empty() || segment.contains('/') {
        return false;
    }
    let hash = segment.split('.').next().unwrap_or(segment);
    hash.len() == 64 && hex::decode(hash).is_ok()
}

fn is_pubkey(value: &str) -> bool {
    value.len() == 64 && hex::decode(value).map(|b| b.len() == 32).unwrap_or(false)
}

/// The advisory file extension for a MIME type, appended to the
/// Blossom descriptor `url` (the spec's examples always include it;
/// the extension is a hint — the file is served by hash alone).
fn ext_of(mime: &str) -> &'static str {
    match mime {
        "image/jpeg" => ".jpg",
        "image/png" => ".png",
        "image/gif" => ".gif",
        "image/webp" => ".webp",
        "image/avif" => ".avif",
        "image/svg+xml" => ".svg",
        "image/bmp" => ".bmp",
        "image/tiff" => ".tiff",
        "video/mp4" => ".mp4",
        "video/webm" => ".webm",
        "video/quicktime" => ".mov",
        "audio/mpeg" => ".mp3",
        "audio/ogg" => ".ogg",
        "audio/wav" | "audio/wave" | "audio/x-wav" => ".wav",
        "text/plain" => ".txt",
        "text/html" => ".html",
        "text/markdown" => ".md",
        "application/pdf" => ".pdf",
        "application/json" => ".json",
        "application/zip" => ".zip",
        "application/gzip" => ".gz",
        _ => "",
    }
}

/// Splits `/<sha256>.<ext>` into the hash (normalized to lowercase, so
/// an uppercase request matches the stored index) and drops the advisory
/// extension.
fn split_blob(segment: &str) -> Option<String> {
    if segment.contains('/') {
        return None;
    }
    let hash = segment.split('.').next()?;
    if hash.len() == 64 && hex::decode(hash).is_ok() {
        Some(hash.to_ascii_lowercase())
    } else {
        None
    }
}

/// Whether `pubkey` (hex) may upload: unrestricted, or present in
/// `blossom.allow_pubkeys` (npub1... or hex). Read from the live config so
/// `nostrd blossom allow/deny` + a SIGHUP applies without a restart.
async fn upload_allowed(relay: &Relay, pubkey: &str) -> Result<(), ()> {
    let cfg = relay.config.read().await;
    if !cfg.blossom.restrict_uploads {
        return Ok(());
    }
    // The allowlist lives in the relay database (LMDB), loaded into
    // memory at startup and refreshed on SIGHUP (`nostrd blossom allow/deny`).
    let allowed = relay
        .blossom_allow
        .read()
        .await
        .iter()
        .any(|entry| entry == pubkey);
    if allowed { Ok(()) } else { Err(()) }
}

/// Normalizes the `server` tag of a Blossom auth event for comparison
/// with `blossom.host`: strips the scheme and any path, IPv6 literals keep
/// their bracket contents (colons are part of the host), and a DNS/IPv4
/// `:port` suffix is removed.
fn auth_server_host(server: &str) -> String {
    let host_part = server
        .strip_prefix("https://")
        .or_else(|| server.strip_prefix("http://"))
        .unwrap_or(server)
        .split('/')
        .next()
        .unwrap_or(server);
    let host = if let Some(rest) = host_part.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else {
        host_part.split(':').next().unwrap_or(host_part)
    };
    host.to_ascii_lowercase()
}

/// Validates and normalizes the client-sent Content-Type: only the media
/// type (the part before any `;` parameter) is kept, and it must be a
/// well-formed `type/subtype` token pair. Anything else falls back to
/// `application/octet-stream`, so a hostile header can never reach a
/// response header (which would make the response builder panic).
pub(crate) fn sanitize_mime(raw: &str) -> String {
    let media = raw
        .split(';')
        .next()
        .unwrap_or(raw)
        .trim()
        .to_ascii_lowercase();
    let valid = |t: &str| {
        !t.is_empty()
            && t.chars()
                .all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+.^_`|~-".contains(c))
    };
    match media.split_once('/') {
        Some((t, s)) if valid(t) && valid(s) && t.len() <= 32 && s.len() <= 64 => media,
        _ => "application/octet-stream".to_string(),
    }
}

/// Verifies a Blossom auth event (BUD-11): kind 24242 with `t` (verb),
/// optional `server` and `x` (sha256 scope) tags. Returns the pubkey.
async fn verify_auth(
    relay: &Relay,
    state: &BlossomState,
    headers: &HeaderMap,
    verb: &str,
    expected_sha: Option<&str>,
) -> Option<String> {
    let encoded = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Nostr "))?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let event: crate::event::Event = serde_json::from_slice(&raw).ok()?;
    if event.kind != 24242 {
        return None;
    }
    if crate::nips::nip01::verify(&event, relay.secp()).is_err() {
        return None;
    }
    let now = unix_now();
    if event.created_at.abs_diff(now) > 600 {
        return None;
    }
    fn tags<'a>(event: &'a crate::event::Event, name: &'a str) -> impl Iterator<Item = &'a str> {
        event
            .tags
            .iter()
            .filter(move |t| t.len() >= 2 && t[0] == name)
            .map(|t| t[1].as_str())
    }
    if !tags(&event, "t").any(|t| t == verb) {
        return None;
    }
    // The `expiration` tag (BUD-11): when present it must be a unix
    // timestamp in the future — an unparseable value is rejected too.
    if let Some(exp) = tags(&event, "expiration").next()
        && exp.parse::<u64>().map(|e| e <= now).unwrap_or(true)
    {
        return None;
    }
    // The `server` tag (when present) must name our host. The tag may
    // carry a scheme and a path; IPv6 hosts use brackets (`[::1]`), whose
    // colons must not be mistaken for a port separator.
    if let Some(server) = tags(&event, "server").next() {
        // The state keeps the configured host for URL building (IPv6 keeps
        // its brackets there); the comparison uses the normalized form.
        let host = state
            .host
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase();
        let tag_host = auth_server_host(server);
        if tag_host != host {
            return None;
        }
    }
    if let Some(sha) = expected_sha
        && !tags(&event, "x").any(|x| x == sha)
    {
        return None;
    }
    Some(event.pubkey)
}

fn error(status: StatusCode, reason: &str) -> Response {
    let reason = reason.to_string();
    (
        status,
        [
            (axum::http::header::CONTENT_TYPE, "text/plain".to_string()),
            (
                axum::http::header::HeaderName::from_static("x-reason"),
                reason.clone(),
            ),
        ],
        reason,
    )
        .into_response()
}

/// `GET /<sha256>` — serve the blob.
async fn get_blob(State(relay): State<Arc<Relay>>, AxPath(blob): AxPath<String>) -> Response {
    let Some(state) = state_of(&relay).await else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "blossom not initialized");
    };
    let Some(sha) = split_blob(&blob) else {
        return error(StatusCode::NOT_FOUND, "invalid blob hash");
    };
    let Some(desc) = state.store.find(&sha).await else {
        return error(StatusCode::NOT_FOUND, "blob not found");
    };
    match state.store.read(&desc.npub(), &sha).await {
        Ok(Some(bytes)) => (
            [
                (axum::http::header::CONTENT_TYPE, desc.mime),
                (axum::http::header::ETAG, format!("\"{sha}\"")),
                (
                    axum::http::header::CACHE_CONTROL,
                    "public, max-age=31536000, immutable".to_string(),
                ),
            ],
            bytes,
        )
            .into_response(),
        Ok(None) => error(StatusCode::NOT_FOUND, "blob not found"),
        Err(e) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("storage error: {e}"),
        ),
    }
}

/// `HEAD /<sha256>` — blob headers without the body.
async fn head_blob(State(relay): State<Arc<Relay>>, AxPath(blob): AxPath<String>) -> Response {
    let Some(state) = state_of(&relay).await else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "blossom not initialized");
    };
    let Some(sha) = split_blob(&blob) else {
        return error(StatusCode::NOT_FOUND, "invalid blob hash");
    };
    let Some(desc) = state.store.find(&sha).await else {
        return error(StatusCode::NOT_FOUND, "blob not found");
    };
    (
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, desc.mime),
            (axum::http::header::CONTENT_LENGTH, desc.size.to_string()),
            (axum::http::header::ETAG, format!("\"{sha}\"")),
        ],
    )
        .into_response()
}

/// `PUT /upload` — upload a blob. Returns 201 + the BlobDescriptor.
async fn upload(State(relay): State<Arc<Relay>>, headers: HeaderMap, body: Bytes) -> Response {
    let Some(state) = state_of(&relay).await else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "blossom not initialized");
    };
    let Some(pubkey) = verify_auth(&relay, &state, &headers, "upload", None).await else {
        return error(StatusCode::UNAUTHORIZED, "invalid or missing authorization");
    };
    // Upload allowlist: when restrict_uploads is on, only the listed
    // pubkeys (npub1... or hex) may upload.
    if upload_allowed(&relay, &pubkey).await.is_err() {
        return error(
            StatusCode::FORBIDDEN,
            "uploads are restricted to the configured allowlist",
        );
    }
    let mime = sanitize_mime(
        headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream"),
    );
    let sha = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(&body))
    };
    match state.store.put(&pubkey, &sha, &body, &mime).await {
        Ok(desc) => {
            let url = format!("https://{}/{sha}{}", state.host, ext_of(&desc.mime));
            (
                StatusCode::CREATED,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                serde_json::to_string(&json!({
                    "sha256": desc.sha256,
                    "size": desc.size,
                    "type": desc.mime,
                    "url": url,
                    "uploaded": desc.uploaded,
                }))
                .unwrap(),
            )
                .into_response()
        }
        Err(e) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("storage error: {e}"),
        ),
    }
}

/// `GET /list/<pubkey>` — blobs uploaded by a pubkey (hex).
async fn list(State(relay): State<Arc<Relay>>, AxPath(pubkey): AxPath<String>) -> Response {
    let Some(state) = state_of(&relay).await else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "blossom not initialized");
    };
    if !is_pubkey(&pubkey) {
        return error(StatusCode::BAD_REQUEST, "invalid pubkey");
    }
    let blobs = state.store.list(&pubkey).await;
    let items: Vec<Value> = blobs
        .into_iter()
        .map(|d| {
            json!({
                "sha256": d.sha256,
                "size": d.size,
                "type": d.mime,
                "url": format!(
                    "https://{}/{}{}",
                    state.host,
                    d.sha256,
                    ext_of(&d.mime)
                ),
                "uploaded": d.uploaded,
            })
        })
        .collect();
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&items).unwrap(),
    )
        .into_response()
}

/// `DELETE /<sha256>[.ext]` — delete the requester's own copy of a blob.
async fn delete_blob(
    State(relay): State<Arc<Relay>>,
    headers: HeaderMap,
    AxPath(blob): AxPath<String>,
) -> Response {
    let Some(state) = state_of(&relay).await else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "blossom not initialized");
    };
    let Some(sha) = split_blob(&blob) else {
        return error(StatusCode::NOT_FOUND, "invalid blob hash");
    };
    let Some(pubkey) = verify_auth(&relay, &state, &headers, "delete", Some(&sha)).await else {
        return error(StatusCode::UNAUTHORIZED, "invalid or missing authorization");
    };
    if state.store.find(&sha).await.is_none() {
        return error(StatusCode::NOT_FOUND, "blob not found");
    }
    // Only an uploader of these bytes may delete their own copy; other
    // uploaders of identical content keep theirs.
    if !state.store.has(&pubkey, &sha).await {
        return error(
            StatusCode::FORBIDDEN,
            "only the uploader may delete this blob",
        );
    }
    match state.store.delete(&pubkey, &sha).await {
        Ok(true) => StatusCode::OK.into_response(),
        Ok(false) => error(StatusCode::NOT_FOUND, "blob not found"),
        Err(e) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("storage error: {e}"),
        ),
    }
}

/// Builds the shared Blossom state from the config (or `None` when the
/// feature is disabled). Must be called before the router is built.
pub(crate) async fn build_state(cfg: &Config, _relay: &Relay) -> Option<Arc<BlossomState>> {
    if cfg.blossom.host.trim().is_empty() {
        return None;
    }
    let s3 = if cfg.blossom.storage == "s3" {
        Some(storage::S3Config {
            endpoint: cfg.blossom.s3_endpoint.clone(),
            region: cfg.blossom.s3_region.clone(),
            bucket: cfg.blossom.s3_bucket.clone(),
            access_key: cfg.blossom.s3_access_key.clone(),
            secret_key: cfg.blossom.s3_secret_key.clone(),
        })
    } else {
        None
    };
    match BlobStore::new(
        &cfg.blossom.storage,
        &cfg.blossom.local_path,
        s3,
        _relay.db.clone(),
    )
    .await
    {
        Ok(store) => {
            let state = Arc::new(BlossomState {
                store,
                host: cfg.blossom.host.clone(),
            });
            // One-time automatic migration of legacy blobs (storage files
            // that predate the LMDB mapping), in the background so the
            // relay starts instantly.
            let state_for_migration = Arc::clone(&state);
            tokio::spawn(async move {
                match state_for_migration.store.auto_migrate_legacy().await {
                    Ok(n) if n > 0 => {
                        log::info!("Blossom legacy migration: mapped {n} existing blob(s)")
                    }
                    Ok(_) => {}
                    Err(e) => log::warn!("Blossom legacy migration failed: {e}"),
                }
            });
            Some(state)
        }
        Err(e) => {
            log::error!("blossom storage failed to initialize: {e}");
            None
        }
    }
}

/// Whether the request Host names the Blossom host.
pub(crate) fn host_is_blossom(
    blossom_host: &str,
    request: &axum::http::Request<axum::body::Body>,
) -> bool {
    if blossom_host.trim().is_empty() {
        return false;
    }
    request
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|h| {
            let host = crate::server::host_header_host(h).to_ascii_lowercase();
            host == blossom_host
                .trim()
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_ascii_lowercase()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_server_host_normalization() {
        assert_eq!(auth_server_host("media.example.com"), "media.example.com");
        assert_eq!(
            auth_server_host("media.example.com:8080"),
            "media.example.com"
        );
        assert_eq!(
            auth_server_host("https://media.example.com"),
            "media.example.com"
        );
        assert_eq!(
            auth_server_host("https://media.example.com/path"),
            "media.example.com"
        );
        assert_eq!(auth_server_host("[::1]"), "::1");
        assert_eq!(auth_server_host("[::1]:8080"), "::1");
        assert_eq!(auth_server_host("http://[::1]/upload"), "::1");
        assert_eq!(auth_server_host("MEDIA.EXAMPLE.COM"), "media.example.com");
    }

    #[test]
    fn mime_sanitization() {
        assert_eq!(sanitize_mime("image/png"), "image/png");
        assert_eq!(sanitize_mime("image/png; charset=utf-8"), "image/png");
        assert_eq!(sanitize_mime("  IMAGE/JPEG  "), "image/jpeg");
        assert_eq!(sanitize_mime("image/png; filename=a.png"), "image/png");
        assert_eq!(
            sanitize_mime("image/png\r\nX-Evil: 1"),
            "application/octet-stream"
        );
        assert_eq!(sanitize_mime("image/"), "application/octet-stream");
        assert_eq!(sanitize_mime("/png"), "application/octet-stream");
        assert_eq!(sanitize_mime("not-a-mime"), "application/octet-stream");
        assert_eq!(
            sanitize_mime(&format!("image/{}", "x".repeat(65))),
            "application/octet-stream"
        );
    }

    #[test]
    fn mime_extension_mapping() {
        assert_eq!(ext_of("image/png"), ".png");
        assert_eq!(ext_of("image/jpeg"), ".jpg");
        assert_eq!(ext_of("image/svg+xml"), ".svg");
        assert_eq!(ext_of("text/plain"), ".txt");
        assert_eq!(ext_of("video/mp4"), ".mp4");
        assert_eq!(ext_of("application/octet-stream"), "");
        assert_eq!(ext_of("unknown/type"), "");
    }

    #[test]
    fn blossom_path_detection() {
        assert!(!is_blossom_path("/"));
        assert!(is_blossom_path("/upload"));
        assert!(is_blossom_path(&format!("/list/{}", "aa".repeat(32))));
        assert!(is_blossom_path(&format!("/{}.jpg", "a".repeat(64))));
        assert!(is_blossom_path(&format!("/{}", "a".repeat(64))));
        assert!(!is_blossom_path("/ws"));
        assert!(!is_blossom_path("/api/v1/npub1..."));
        assert!(!is_blossom_path(&format!("/{}", "a".repeat(63))));
        assert!(!is_blossom_path("/list/nothex"));
    }

    #[test]
    fn blob_segment_splits_extension() {
        assert_eq!(
            split_blob(&format!("{}.png", "a".repeat(64))),
            Some("a".repeat(64))
        );
        assert_eq!(split_blob(&"a".repeat(64)), Some("a".repeat(64)));
        assert_eq!(split_blob("short"), None);
        assert_eq!(split_blob(&format!("{}.png/x", "a".repeat(64))), None);
        assert_eq!(split_blob(&"A".repeat(64)), Some("a".repeat(64)));
    }
}
