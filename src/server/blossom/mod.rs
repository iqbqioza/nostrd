//! Blossom file server (BUD-01 / BUD-02).
//!
//! Serves a media/blob store on a hostname dedicated like the REST API:
//! requests whose Host header matches `blossom.host` are served only the
//! Blossom routes. Files are stored as `bucket/{npub1xxx}/{sha256}` on
//! local disk or in an S3-compatible bucket, content-addressed by SHA-256.
//!
//! Endpoints:
//! - `GET /`            — server info
//! - `GET /<sha256>[.ext]` / `HEAD` — fetch / probe a blob (with RFC 7233
//!   byte-range support on `GET`)
//! - `PUT /upload`      — upload (NIP-98 style auth, kind 24242, `t=upload`,
//!   mandatory `expiration` and `x` tags per BUD-11)
//! - `GET /list/<pubkey>` — blobs uploaded by a pubkey
//! - `DELETE /<sha256>[.ext]` — delete (auth, `t=delete`, `x=<sha256>`)

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path as AxPath, Query, State};
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

/// The `t`-tag values of `name` in a Blossom auth event.
fn event_tags<'a>(event: &'a crate::event::Event, name: &'a str) -> impl Iterator<Item = &'a str> {
    event
        .tags
        .iter()
        .filter(move |t| t.len() >= 2 && t[0] == name)
        .map(|t| t[1].as_str())
}

/// Validates a Blossom auth event (BUD-11): kind 24242 with a `t` verb, a
/// mandatory `expiration` tag set to a unix timestamp in the future, an
/// optional `server` tag naming our host and — when the endpoint implies a
/// blob hash — a mandatory matching `x` tag. Returns the pubkey.
fn validate_auth_event(
    secp: &secp256k1::Secp256k1<secp256k1::All>,
    event: &crate::event::Event,
    host: &str,
    verb: &str,
    expected_sha: Option<&str>,
    now: u64,
) -> Option<String> {
    if event.kind != 24242 {
        return None;
    }
    if crate::nips::nip01::verify(event, secp).is_err() {
        return None;
    }
    // BUD-11: `created_at` must be in the past. The relay additionally
    // enforces a freshness window: an intercepted token cannot be replayed
    // long after signing (the 10-minute slack tolerates client clock skew).
    if event.created_at.abs_diff(now) > 600 {
        return None;
    }
    if !event_tags(event, "t").any(|t| t == verb) {
        return None;
    }
    // BUD-11: the `expiration` tag is mandatory and must be a unix
    // timestamp in the future — a missing or unparseable value is rejected
    // too, so an intercepted token cannot outlive its scope.
    let exp = event_tags(event, "expiration").next()?;
    if exp.parse::<u64>().map(|e| e <= now).unwrap_or(true) {
        return None;
    }
    // The `server` tag (when present) must name our host. The tag may
    // carry a scheme and a path; IPv6 hosts use brackets (`[::1]`), whose
    // colons must not be mistaken for a port separator.
    if let Some(server) = event_tags(event, "server").next() {
        // The state keeps the configured host for URL building (IPv6 keeps
        // its brackets there); the comparison uses the normalized form.
        let host = host
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase();
        let tag_host = auth_server_host(server);
        if tag_host != host {
            return None;
        }
    }
    // BUD-11: when the endpoint implies a blob hash (upload/delete), at
    // least one `x` tag must match it.
    if let Some(sha) = expected_sha
        && !event_tags(event, "x").any(|x| x == sha)
    {
        return None;
    }
    Some(event.pubkey.clone())
}

/// Verifies a Blossom auth event (BUD-11): kind 24242 with `t` (verb),
/// mandatory future `expiration`, optional `server` and `x` (sha256 scope)
/// tags. Returns the pubkey.
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
    // BUD-11: the token is Base64url without padding. Accept both the
    // spec encoding and the padded standard variant for leniency.
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(encoded))
        .ok()?;
    let event: crate::event::Event = serde_json::from_slice(&raw).ok()?;
    validate_auth_event(
        relay.secp(),
        &event,
        &state.host,
        verb,
        expected_sha,
        unix_now(),
    )
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

/// Parses a single `Range: bytes=` request (RFC 7233) against `size`.
///
/// Returns `Ok(None)` when the range should be ignored (a multi-range
/// header, or a unit other than `bytes` — RFC 7233 allows the server to
/// ignore the header), `Ok(Some((start, end)))` for a satisfiable single
/// range (inclusive end, clamped to the blob size) and `Err(())` for an
/// unsatisfiable or malformed range (416 with `Content-Range: bytes */`).
fn parse_range(header: &str, size: usize) -> Result<Option<(usize, usize)>, ()> {
    let Some(spec) = header
        .trim()
        .strip_prefix("bytes=")
        .or_else(|| header.trim().strip_prefix("Bytes="))
    else {
        return Ok(None); // not a byte range: ignore
    };
    if spec.contains(',') {
        return Ok(None); // multi-range: serve the full blob instead
    }
    let (start, end) = match spec.split_once('-') {
        Some((start, end)) if !start.is_empty() => {
            // `bytes=start-end` / `bytes=start-`
            let start: usize = start.parse().map_err(|_| ())?;
            let end = if end.is_empty() {
                size.saturating_sub(1)
            } else {
                end.parse::<usize>()
                    .map_err(|_| ())?
                    .min(size.saturating_sub(1))
            };
            (start, end)
        }
        Some((_, suffix)) => {
            // `bytes=-suffix`: the last `suffix` bytes
            let suffix: usize = suffix.parse().map_err(|_| ())?;
            if suffix == 0 {
                return Err(());
            }
            (size.saturating_sub(suffix), size.saturating_sub(1))
        }
        None => return Err(()),
    };
    if start >= size || end < start {
        return Err(());
    }
    Ok(Some((start, end)))
}

/// `GET /<sha256>` — serve the blob (with RFC 7233 single-range support).
async fn get_blob(
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
    let Some(desc) = state.store.find(&sha).await else {
        return error(StatusCode::NOT_FOUND, "blob not found");
    };
    match state.store.read(&desc.npub(), &sha).await {
        Ok(Some(bytes)) => {
            let size = bytes.len();
            let base_headers = [
                (axum::http::header::CONTENT_TYPE, desc.mime),
                (axum::http::header::ETAG, format!("\"{sha}\"")),
                (
                    axum::http::header::CACHE_CONTROL,
                    "public, max-age=31536000, immutable".to_string(),
                ),
                (axum::http::header::ACCEPT_RANGES, "bytes".to_string()),
            ];
            // BUD-01: RFC 7233 range requests (video/audio streaming).
            let range = headers
                .get(axum::http::header::RANGE)
                .and_then(|v| v.to_str().ok())
                .map(|r| parse_range(r, size));
            match range {
                Some(Err(())) => {
                    // Unsatisfiable or malformed range: 416 with the
                    // required `Content-Range: bytes */<size>`.
                    let mut response = error(
                        StatusCode::RANGE_NOT_SATISFIABLE,
                        "requested byte range is not satisfiable",
                    );
                    response.headers_mut().insert(
                        axum::http::header::CONTENT_RANGE,
                        format!("bytes */{size}").parse().unwrap(),
                    );
                    response
                }
                Some(Ok(Some((start, end)))) => {
                    let mut response = (
                        StatusCode::PARTIAL_CONTENT,
                        base_headers,
                        bytes[start..=end].to_vec(),
                    )
                        .into_response();
                    response.headers_mut().insert(
                        axum::http::header::CONTENT_RANGE,
                        format!("bytes {start}-{end}/{size}").parse().unwrap(),
                    );
                    response
                }
                _ => (StatusCode::OK, base_headers, bytes).into_response(),
            }
        }
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
            (axum::http::header::ACCEPT_RANGES, "bytes".to_string()),
        ],
    )
        .into_response()
}

/// `PUT /upload` — upload a blob. Returns 201 + the BlobDescriptor.
async fn upload(State(relay): State<Arc<Relay>>, headers: HeaderMap, body: Bytes) -> Response {
    let Some(state) = state_of(&relay).await else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "blossom not initialized");
    };
    let sha = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(&body))
    };
    // BUD-02: the optional `X-SHA-256` header declares the expected hash of
    // the request body — a provided value that does not match the actual
    // bytes is a 409 Conflict, and a malformed value is a 400.
    if let Some(declared) = headers.get("x-sha-256").and_then(|v| v.to_str().ok()) {
        let declared = declared.trim().to_ascii_lowercase();
        if declared.len() != 64 || hex::decode(&declared).is_err() {
            return error(StatusCode::BAD_REQUEST, "malformed X-SHA-256 header");
        }
        if declared != sha {
            return error(
                StatusCode::CONFLICT,
                "the X-SHA-256 header does not match the request body",
            );
        }
    }
    // BUD-11: upload tokens MUST carry an `x` tag matching the blob hash
    // (the token is scoped to exactly the bytes being uploaded).
    let Some(pubkey) = verify_auth(&relay, &state, &headers, "upload", Some(&sha)).await else {
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
    // BUD-02: 201 for a newly stored blob, 200 when it already exists.
    let existed = state.store.find(&sha).await.is_some();
    match state.store.put(&pubkey, &sha, &body, &mime).await {
        Ok(desc) => {
            let url = format!("https://{}/{sha}{}", state.host, ext_of(&desc.mime));
            let status = if existed {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            };
            (
                status,
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

/// `GET /list/<pubkey>` — blobs uploaded by a pubkey (hex), sorted by
/// `uploaded` descending, with BUD-12 cursor-based pagination
/// (`cursor` = the sha256 of the last entry of the previous page,
/// `limit` = the maximum number of results).
async fn list(
    State(relay): State<Arc<Relay>>,
    AxPath(pubkey): AxPath<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let Some(state) = state_of(&relay).await else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "blossom not initialized");
    };
    if !is_pubkey(&pubkey) {
        return error(StatusCode::BAD_REQUEST, "invalid pubkey");
    }
    let cursor = params
        .get("cursor")
        .map(String::as_str)
        .filter(|c| is_pubkey(c));
    let limit = params.get("limit").and_then(|v| v.parse::<usize>().ok());
    let mut blobs = state.store.list(&pubkey).await;
    // BUD-12: sorted by `uploaded` descending; the page starts after the
    // cursor and never includes it.
    blobs.sort_by_key(|d| std::cmp::Reverse(d.uploaded));
    if let Some(cursor) = cursor
        && let Some(pos) = blobs.iter().position(|d| d.sha256 == cursor)
    {
        blobs.drain(..=pos);
    }
    if let Some(limit) = limit {
        blobs.truncate(limit);
    }
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

/// Whether the request Host header names the Blossom host. Takes the raw
/// header value (not the whole request) so callers can hold it across
/// awaits without borrowing the request.
pub(crate) fn host_is_blossom(blossom_host: &str, host_header: Option<&str>) -> bool {
    if blossom_host.trim().is_empty() {
        return false;
    }
    host_header.is_some_and(|h| {
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
    use crate::event::Event;
    use secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};

    fn auth_event(
        secp: &Secp256k1<secp256k1::All>,
        created: u64,
        verb: &str,
        expiration: Option<u64>,
        x: Option<&str>,
        server: Option<&str>,
    ) -> Event {
        let keypair = Keypair::from_seckey_slice(secp, &[9u8; 32]).unwrap();
        let pubkey = XOnlyPublicKey::from_keypair(&keypair).0.to_string();
        let mut tags: Vec<Vec<String>> = vec![vec!["t".into(), verb.into()]];
        if let Some(exp) = expiration {
            tags.push(vec!["expiration".into(), exp.to_string()]);
        }
        if let Some(x) = x {
            tags.push(vec!["x".into(), x.into()]);
        }
        if let Some(server) = server {
            tags.push(vec!["server".into(), server.into()]);
        }
        let mut ev = Event {
            id: String::new(),
            pubkey,
            created_at: created,
            kind: 24242,
            tags,
            content: String::new(),
            sig: String::new(),
        };
        ev.id = crate::nips::nip01::compute_id(&ev);
        let id = ev.id_bytes().unwrap();
        ev.sig = secp.sign_schnorr_no_aux_rand(&id, &keypair).to_string();
        ev
    }

    #[test]
    fn auth_event_validation_follows_bud11() {
        let secp = Secp256k1::new();
        let now = unix_now();
        let sha = "a".repeat(64);
        let host = "media.example.com";
        // A fully-specified upload token validates.
        let ev = auth_event(
            &secp,
            now,
            "upload",
            Some(now + 300),
            Some(&sha),
            Some(host),
        );
        assert_eq!(
            validate_auth_event(&secp, &ev, host, "upload", Some(&sha), now),
            Some(ev.pubkey.clone())
        );
        // BUD-11: the `expiration` tag is mandatory.
        let ev = auth_event(&secp, now, "upload", None, Some(&sha), Some(host));
        assert_eq!(
            validate_auth_event(&secp, &ev, host, "upload", Some(&sha), now),
            None,
            "a token without an expiration tag must be rejected"
        );
        // An expired or unparseable expiration is rejected.
        let ev = auth_event(&secp, now, "upload", Some(now - 1), Some(&sha), Some(host));
        assert_eq!(
            validate_auth_event(&secp, &ev, host, "upload", Some(&sha), now),
            None
        );
        let ev = auth_event(&secp, now, "upload", Some(0), Some(&sha), Some(host));
        assert_eq!(
            validate_auth_event(&secp, &ev, host, "upload", Some(&sha), now),
            None
        );
        // The `t` verb must match the endpoint.
        let ev = auth_event(
            &secp,
            now,
            "delete",
            Some(now + 300),
            Some(&sha),
            Some(host),
        );
        assert_eq!(
            validate_auth_event(&secp, &ev, host, "upload", Some(&sha), now),
            None
        );
        // A `server` tag naming another host is rejected.
        let ev = auth_event(
            &secp,
            now,
            "upload",
            Some(now + 300),
            Some(&sha),
            Some("evil.example.com"),
        );
        assert_eq!(
            validate_auth_event(&secp, &ev, host, "upload", Some(&sha), now),
            None
        );
        // BUD-11: an upload token must carry an `x` tag matching the blob.
        let ev = auth_event(&secp, now, "upload", Some(now + 300), None, Some(host));
        assert_eq!(
            validate_auth_event(&secp, &ev, host, "upload", Some(&sha), now),
            None,
            "an upload token without an x tag must be rejected"
        );
        let ev = auth_event(
            &secp,
            now,
            "upload",
            Some(now + 300),
            Some("b".repeat(64).as_str()),
            Some(host),
        );
        assert_eq!(
            validate_auth_event(&secp, &ev, host, "upload", Some(&sha), now),
            None,
            "an x tag for a different blob must be rejected"
        );
        // A token stamped too far in the past or the future is stale.
        let ev = auth_event(
            &secp,
            now - 601,
            "upload",
            Some(now + 300),
            Some(&sha),
            Some(host),
        );
        assert_eq!(
            validate_auth_event(&secp, &ev, host, "upload", Some(&sha), now),
            None
        );
        let ev = auth_event(
            &secp,
            now + 601,
            "upload",
            Some(now + 300),
            Some(&sha),
            Some(host),
        );
        assert_eq!(
            validate_auth_event(&secp, &ev, host, "upload", Some(&sha), now),
            None
        );
        // A wrong event kind is rejected.
        let mut ev = auth_event(
            &secp,
            now,
            "upload",
            Some(now + 300),
            Some(&sha),
            Some(host),
        );
        ev.kind = 22242;
        assert_eq!(
            validate_auth_event(&secp, &ev, host, "upload", Some(&sha), now),
            None
        );
        // A delete token without an `x` tag is rejected (implied hash).
        let ev = auth_event(&secp, now, "delete", Some(now + 300), None, Some(host));
        assert_eq!(
            validate_auth_event(&secp, &ev, host, "delete", Some(&sha), now),
            None
        );
        // An unsigned (invalid signature) token is rejected.
        let mut ev = auth_event(
            &secp,
            now,
            "upload",
            Some(now + 300),
            Some(&sha),
            Some(host),
        );
        ev.sig = "f".repeat(128);
        assert_eq!(
            validate_auth_event(&secp, &ev, host, "upload", Some(&sha), now),
            None
        );
    }

    #[test]
    fn byte_ranges_follow_rfc7233() {
        // Satisfiable ranges (end is inclusive and clamped).
        assert_eq!(parse_range("bytes=0-4", 10), Ok(Some((0, 4))));
        assert_eq!(parse_range("bytes=5-", 10), Ok(Some((5, 9))));
        assert_eq!(parse_range("bytes=-3", 10), Ok(Some((7, 9))));
        assert_eq!(parse_range("bytes=0-99", 10), Ok(Some((0, 9))));
        assert_eq!(parse_range("bytes=5-5", 10), Ok(Some((5, 5))));
        // Unsatisfiable or malformed ranges.
        assert_eq!(parse_range("bytes=10-", 10), Err(()));
        assert_eq!(parse_range("bytes=8-4", 10), Err(()));
        assert_eq!(parse_range("bytes=-0", 10), Err(()));
        assert_eq!(parse_range("bytes=abc", 10), Err(()));
        assert_eq!(parse_range("bytes=0-", 0), Err(()));
        // Multi-ranges and non-byte units are ignored (full response).
        assert_eq!(parse_range("bytes=0-4,6-8", 10), Ok(None));
        assert_eq!(parse_range("items=0-4", 10), Ok(None));
        assert_eq!(parse_range("", 10), Ok(None));
    }

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
