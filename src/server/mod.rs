//! HTTP server: the WebSocket/NIP-11/NIP-86 endpoint, CORS, the
//! daemon background tasks (stats, expiry purge, signals, config
//! reload) and the NIP-29 LiveKit integration in [`livekit`].

mod api;
pub(crate) mod blossom;
mod livekit;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::body::Body;
use axum::extract::FromRequestParts;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use log::{error, info, warn};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;
use tokio::time::{MissedTickBehavior, interval};

use crate::config::Config;
use crate::db::DbClient;
use crate::error::{Error, Result};
use crate::nips::nip11::{relay_info, stats_handler};
use crate::nips::nip86;
use crate::relay::Relay;
use crate::stats::Stats;
use crate::util::unix_now;
use crate::ws::handle_connection;
use api::{
    api_count_handler, api_daily_handler, api_follows_handler, api_handler, api_hourly_handler,
    api_id_handler, api_kind_handler, api_kinds_handler, api_monthly_handler, api_query_handler,
    api_related_handler, api_relay_kinds_handler, api_stats_handler,
};
use axum::serve::ListenerExt;
use livekit::{livekit_supported, livekit_token};

/// Sets an integer socket option on a TCP stream.
///
/// # Safety
/// `fd` must be a valid open socket descriptor.
unsafe fn set_sock_opt(stream: &tokio::net::TcpStream, opt: libc::c_int, value: i32) {
    use std::os::fd::AsRawFd;
    let value: libc::c_int = value;
    // SAFETY: `stream` holds a valid socket descriptor and the option value
    // is a valid pointer to a `libc::c_int`.
    let ret = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            opt,
            &value as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        log::warn!(
            "setsockopt({opt}) failed: {}",
            std::io::Error::last_os_error()
        );
    }
}

/// NIP-11: relays MUST accept CORS requests.
pub async fn cors_middleware(request: Request, next: Next) -> Response {
    if request.method() == Method::OPTIONS {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::NO_CONTENT;
        add_cors_headers(response.headers_mut());
        return response;
    }
    let mut response = next.run(request).await;
    add_cors_headers(response.headers_mut());
    response
}

fn add_cors_headers(headers: &mut HeaderMap) {
    headers.insert(
        axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        axum::http::header::ACCESS_CONTROL_ALLOW_METHODS,
        // PUT/DELETE are used by the Blossom file server (upload / delete).
        HeaderValue::from_static("GET, POST, PUT, DELETE, HEAD, OPTIONS"),
    );
    headers.insert(
        axum::http::header::ACCESS_CONTROL_ALLOW_HEADERS,
        // X-SHA-256 is the optional preflight hash header of BUD-02.
        HeaderValue::from_static("Authorization, Content-Type, Accept, X-SHA-256"),
    );
    headers.insert(
        axum::http::header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static("86400"),
    );
}

/// Binds a TCP listener on `addr` and logs the given label with the
/// address, turning a bind failure into a configuration error.
async fn bind_listener(addr: &(String, u16), label: &str) -> Result<TcpListener> {
    let listener = match TcpListener::bind(addr).await {
        Ok(listener) => listener,
        // Log through the logger too: in daemon mode the process stderr
        // goes to /dev/null, so a bind failure (e.g. the port is already
        // in use by another instance) would otherwise be invisible.
        Err(e) => {
            let msg = format!("cannot bind to {}:{}: {e}", addr.0, addr.1);
            log::error!("{msg}");
            return Err(Error::Config(msg));
        }
    };
    info!("{label}{}:{}", addr.0, addr.1);
    Ok(listener)
}

/// The relay's HTTP router: the WebSocket/NIP-11/NIP-86 endpoint, health
/// and stats routes, the NIP-29 LiveKit endpoints and the Blossom file
/// server when configured.
async fn build_router(
    relay: &Arc<Relay>,
    blossom_state: Option<Arc<blossom::BlossomState>>,
) -> Router {
    let api_routes = Router::new()
        .route("/query", get(api_query_handler))
        .route("/count", get(api_count_handler))
        .route("/relay/kinds", get(api_relay_kinds_handler))
        .route("/ids/{hex}", get(api_id_handler))
        .route("/ids/{hex}/related", get(api_related_handler))
        .route("/{identifier}", get(api_handler))
        .route("/{identifier}/{kind}", get(api_kind_handler))
        .route("/{identifier}/kinds", get(api_kinds_handler))
        .route("/{identifier}/stats", get(api_stats_handler))
        .route("/{identifier}/follows", get(api_follows_handler))
        .route("/{identifier}/{kind}/monthly", get(api_monthly_handler))
        .route("/{identifier}/{kind}/daily", get(api_daily_handler))
        .route("/{identifier}/{kind}/hourly", get(api_hourly_handler))
        .layer(axum::middleware::from_fn(reject_ws_upgrade));
    // `server.ws_paths` selects which paths serve the WebSocket/NIP-11/NIP-86
    // endpoint: the default root paths, the inbox/outbox paths only, or all
    // of them. The inbox and outbox paths give the relay distinct endpoints
    // for the inbox/outbox routing model.
    let ws_paths = relay.config.read().await.server.ws_paths.trim().to_string();
    let mut app = Router::new()
        .route("/health", get(health_handler))
        .route("/relay/stats", get(stats_handler))
        .nest("/api/v1", api_routes);
    // In `inbox-outbox` mode the root is not a WebSocket endpoint: it only
    // answers the Blossom server-info document on the Blossom host (every
    // other host gets a 404).
    if ws_paths == "inbox-outbox" {
        app = app.route("/", get(root_inbox_outbox));
    }
    for path in ws_paths_for(&ws_paths) {
        app = app.route(path, get(ws_handler).post(nip86::rpc_handler));
    }
    let cfg = relay.config.read().await;
    if cfg.server.metrics_enabled {
        app = app.route("/metrics", get(metrics_handler));
    }
    if cfg.nip_enabled(29) && !cfg.relay.livekit_url.is_empty() {
        app = app
            .route("/.well-known/nip29/livekit", get(livekit_supported))
            .route("/.well-known/nip29/livekit/{group}", get(livekit_token));
    }
    // The Blossom routes are reachable only on the Blossom host (the host
    // split middleware gates them; the root `/` route stays with the relay
    // and is answered with the Blossom server info by `ws_handler` when the
    // Host names the Blossom host).
    let (api_host, blossom_host) = {
        let cfg = relay.config.read().await;
        (
            normalize_host(&cfg.server.api_host),
            normalize_host(&cfg.blossom.host),
        )
    };
    if blossom_state.is_some() {
        app = app.merge(blossom::routes(relay).await);
    }
    drop(cfg);
    if !api_host.is_empty() || !blossom_host.is_empty() {
        let api_host = api_host.clone();
        let blossom_host = blossom_host.clone();
        app = app.layer(axum::middleware::from_fn(move |req, next| {
            let api_host = api_host.clone();
            let blossom_host = blossom_host.clone();
            async move { host_split(&api_host, &blossom_host, req, next).await }
        }));
    }
    app.layer(axum::middleware::from_fn(cors_middleware))
        .with_state(relay.clone())
}

/// The paths serving the WebSocket/NIP-11/NIP-86 endpoint for a
/// `server.ws_paths` value. Unknown values fall back to the default root
/// path (the config validation rejects them, but the router must stay
/// safe even on an unvalidated reload path).
fn ws_paths_for(mode: &str) -> &'static [&'static str] {
    match mode {
        "inbox-outbox" => &["/inbox", "/outbox"],
        "all" => &["/", "/inbox", "/outbox"],
        _ => &["/"],
    }
}

/// Normalizes a configured split hostname (api_host / blossom.host):
/// lowercase, with IPv6 brackets stripped so it compares equal to the
/// normalized request Host (`[::1]` -> `::1`).
fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase()
}

/// The host part of an HTTP Host header value: strips an IPv6 literal's
/// brackets (`[::1]:8080` -> `::1`) or splits a DNS/IPv4 host from its
/// optional `:port` suffix (`relay.example.com:8080` -> `relay.example.com`).
fn host_header_host(header: &str) -> &str {
    let h = header.trim();
    if let Some(rest) = h.strip_prefix('[') {
        // IPv6 literal: the host ends at the closing bracket.
        rest.split(']').next().unwrap_or(rest)
    } else {
        // DNS name or IPv4 address: everything before the first ':'.
        h.split(':').next().unwrap_or(h)
    }
}

async fn host_split(api_host: &str, blossom_host: &str, request: Request, next: Next) -> Response {
    let host = request
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(host_header_host)
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    if host_route_allowed(api_host, blossom_host, &host, request.uri().path()) {
        next.run(request).await
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

/// Decides whether a request (host + path) may reach the next handler:
/// the `api_host` serves only the API paths, the `blossom.host` serves only
/// the Blossom routes, and every other host serves only the relay endpoints.
/// API paths are relay-side when `api_host` is unset (so `restrict_uploads` /
/// blossom alone never hides `/health`, `/metrics` or `/api/v1`).
fn host_route_allowed(api_host: &str, blossom_host: &str, host: &str, path: &str) -> bool {
    let is_api = !api_host.is_empty() && host == api_host;
    let is_blossom = !blossom_host.is_empty() && host == blossom_host;
    let is_relay = !is_api && !is_blossom;
    let api_path = !api_host.is_empty()
        && (path.starts_with("/api/v1") || path == "/health" || path == "/metrics");
    // The root `/` is dispatched by the WS handler (relay info or Blossom
    // server info), so it must pass through on the Blossom host too.
    let blossom_path = blossom::is_blossom_path(path) || (is_blossom && path == "/");
    (is_api && api_path) || (is_blossom && blossom_path) || (is_relay && !api_path && !blossom_path)
}

pub async fn run_server(config_path: PathBuf, config: Config, db: DbClient) -> Result<()> {
    let private_key = config.relay.private_key.clone();
    let live = crate::relay::LiveBusConfig {
        buffer: config.limits.live_buffer,
        batch_interval_ms: config.limits.live_batch_interval_ms,
        batch_size: config.limits.live_batch_size,
    };
    let config = Arc::new(tokio::sync::RwLock::new(config));
    let stats = Stats::new();
    let mut relay = Arc::new(Relay::new(config, db, stats, &private_key, live).await);
    Arc::get_mut(&mut relay)
        .expect("relay not cloned yet")
        .start_live_bus();
    // Make the config file path known to the relay so NIP-86 runtime
    // changes (relay name/description/icon) can be persisted to disk.
    *relay.config_path.write().await = Some(config_path.clone());

    // Rebuild the NIP-29 group state from the stored moderation events.
    if relay.config.read().await.nip_enabled(29) {
        relay.groups.write().await.rebuild(&relay.db).await;
        if relay.has_relay_key() {
            info!(
                "NIP-29 groups enabled (relay key {})",
                relay.relay_pubkey().unwrap_or_default()
            );
        }
    }

    // Rebuild the NIP-43 role store from the stored role definitions and
    // membership lists.
    if relay.config.read().await.nip_enabled(43) {
        relay
            .roles
            .write()
            .await
            .rebuild(&relay.db, &relay.relay_pubkey().unwrap_or_default())
            .await;
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let blossom_state = blossom::build_state(&relay.config.read().await.clone(), &relay).await;
    *relay.blossom.write().await = blossom_state.clone();
    let app = build_router(&relay, blossom_state).await;

    let bind_addr = {
        let cfg = relay.config.read().await;
        (cfg.server.host.clone(), cfg.server.port)
    };
    let listener = bind_listener(&bind_addr, "relay listening on ws://").await?;

    let mut tasks = Vec::new();

    let mgmt = {
        let cfg = relay.config.read().await;
        if cfg.server.management_port > 0 {
            let mgmt_addr = (
                cfg.server.management_host.clone(),
                cfg.server.management_port,
            );
            let listener = bind_listener(&mgmt_addr, "management listening on http://").await?;
            Some((mgmt_addr, listener))
        } else {
            None
        }
    };

    if let Some((addr, listener)) = mgmt {
        let mgmt_app = nip86::router(relay.clone(), shutdown_tx.clone());
        let rx = shutdown_rx.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(e) = axum::serve(
                listener.tap_io(|stream| {
                    let _ = stream.set_nodelay(true);
                }),
                mgmt_app,
            )
            .with_graceful_shutdown(await_shutdown(rx))
            .await
            {
                error!("management server error: {e}");
            }
            info!("management server stopped ({addr:?})");
        }));
    }

    tasks.push(tokio::spawn(stats_writer(
        relay.clone(),
        shutdown_rx.clone(),
    )));
    tasks.push(tokio::spawn(purge_loop(relay.clone(), shutdown_rx.clone())));
    tasks.push(tokio::spawn(signal_handler(shutdown_tx.clone())));
    tasks.push(tokio::spawn(reload_handler(
        config_path,
        relay.clone(),
        relay.db.clone(),
        relay.api_limit.clone(),
        shutdown_rx.clone(),
    )));

    let main = axum::serve(
        listener.tap_io(|stream| {
            // Keep per-connection kernel buffers small so that hundreds of
            // thousands of idle connections do not pin gigabytes of kernel
            // memory (each buffer is a per-socket allocation); slow readers
            // are throttled per-connection instead.
            let _ = stream.set_nodelay(true);
            // SAFETY: `setsockopt` only touches the socket's own buffers.
            unsafe {
                set_sock_opt(stream, libc::SO_RCVBUF, 32 * 1024);
                set_sock_opt(stream, libc::SO_SNDBUF, 32 * 1024);
            }
        }),
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(await_shutdown(shutdown_rx))
    .await;
    if let Err(e) = main {
        error!("relay server error: {e}");
    }

    let _ = shutdown_tx.send(true);
    for task in tasks {
        task.await.ok();
    }
    relay.db.shutdown();
    info!("relay stopped");
    Ok(())
}

async fn await_shutdown(mut rx: watch::Receiver<bool>) {
    while !*rx.borrow() {
        if rx.changed().await.is_err() {
            break;
        }
    }
}

/// Returns `true` when the request is a valid WebSocket handshake: the
/// standard upgrade headers must be present (`Upgrade: websocket`,
/// `Connection: upgrade`, `Sec-WebSocket-Version: 13` and a non-empty
/// `Sec-WebSocket-Key`), and a proxy-provided `X-Forwarded-Proto` must be
/// `ws` or `wss`. Anything else is a plain HTTP request.
fn is_websocket_request(headers: &HeaderMap) -> bool {
    let upgrade = headers
        .get(axum::http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    let connection = headers
        .get(axum::http::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.to_ascii_lowercase()
                .split(',')
                .any(|t| t.trim() == "upgrade")
        })
        .unwrap_or(false);
    let version = headers
        .get(axum::http::header::SEC_WEBSOCKET_VERSION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v == "13")
        .unwrap_or(false);
    let key = headers
        .get(axum::http::header::SEC_WEBSOCKET_KEY)
        .and_then(|v| v.to_str().ok())
        .map(|v| !v.is_empty())
        .unwrap_or(false);
    if !(upgrade && connection && version && key) {
        return false;
    }
    // Behind a proxy the request scheme is announced with
    // X-Forwarded-Proto. The value is the scheme the client used to reach
    // the proxy: `wss`/`ws` for a direct WebSocket connection, or
    // `https`/`http` when the proxy terminates TLS (e.g. Cloudflare
    // Tunnel), in which case the WebSocket upgrade is decided by the
    // upgrade headers alone.
    match headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
    {
        Some(proto) => {
            let proto = proto.to_ascii_lowercase();
            matches!(proto.as_str(), "ws" | "wss" | "http" | "https")
        }
        None => true,
    }
}

/// Rejects WebSocket upgrade requests, returning 403 Forbidden.
/// Applied as a layer to `/api/v1` routes so that they are only
/// accessible over plain HTTP/HTTPS.
async fn reject_ws_upgrade(request: Request, next: Next) -> Response {
    if is_websocket_request(request.headers()) {
        return StatusCode::FORBIDDEN.into_response();
    }
    next.run(request).await
}

/// The Blossom server-info document (BUD-01) when the request Host names
/// the configured Blossom host; `None` otherwise. Used by the shared root
/// route and by the dedicated root route of the `inbox-outbox` mode, so
/// the info document stays available on the Blossom host whatever the
/// WebSocket path selection is. Takes the Host header value (not the whole
/// request) so the future never borrows the request across the await.
async fn blossom_root_info(
    relay: Arc<Relay>,
    host_header: Option<&str>,
    is_websocket: bool,
) -> Option<Response> {
    let cfg = relay.config.read().await;
    if cfg.blossom.host.trim().is_empty()
        || !blossom::host_is_blossom(&cfg.blossom.host, host_header)
    {
        return None;
    }
    // WebSocket upgrades are never accepted on the Blossom host's root.
    if is_websocket {
        return Some(StatusCode::NOT_FOUND.into_response());
    }
    let info = json!({
        "name": format!("nostrd Blossom ({})", cfg.blossom.host.trim()),
        "supported_nips": [],
        "supported_file_hashes": ["sha256"],
        "tos_url": null,
        "payment_required": false,
        "max_file_size": cfg.blossom.max_upload_bytes,
        "storage": cfg.blossom.storage,
    });
    let mut response = Json(info).into_response();
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    Some(response)
}

/// The NIP-11 relay information document, served with `application/nostr+json`
/// when the client asked for it.
async fn nip11_doc(relay: Arc<Relay>, wants_nostr_json: bool) -> Response {
    let cfg = relay.config.read().await;
    let body = Json(relay_info(
        &cfg,
        &relay.stats,
        relay.relay_pubkey().as_deref(),
    ));
    let mut response = body.into_response();
    if wants_nostr_json {
        response.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/nostr+json"),
        );
    }
    response
}

/// The root path in `ws_paths = "inbox-outbox"` mode: only the Blossom
/// server-info answer is served (on the Blossom host); every other request
/// gets a 404, keeping the relay's WebSocket endpoint and the NIP-11
/// document exclusive to `/inbox` and `/outbox`.
async fn root_inbox_outbox(State(relay): State<Arc<Relay>>, request: Request) -> Response {
    let host_header = request
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok());
    if is_websocket_request(request.headers()) {
        return StatusCode::NOT_FOUND.into_response();
    }
    match blossom_root_info(relay, host_header, false).await {
        Some(response) => response,
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Serves the WebSocket endpoint and the NIP-11 document on the same URI:
/// valid WebSocket handshakes are upgraded, plain HTTP requests (GET with
/// no upgrade headers) receive the relay information document, per NIP-11
/// ("on the same URI as the relay's websocket").
async fn ws_handler(State(relay): State<Arc<Relay>>, request: Request) -> Response {
    // NIP-86: blockip — refuse WebSocket connections from blocked peers.
    if let Some(ip) = request
        .extensions()
        .get::<axum::extract::connect_info::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0.ip())
        && relay
            .access
            .read()
            .await
            .blocked_ips
            .iter()
            .any(|(blocked, _)| blocked.parse::<std::net::IpAddr>().is_ok_and(|b| b == ip))
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    // The Blossom server shares the root `/` route with the relay: when
    // the request Host names the Blossom host, the root path is answered
    // with the Blossom server info instead of the NIP-11 document (and
    // WebSocket upgrades are refused there by the host split).
    let host_header = request
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok());
    if let Some(response) = blossom_root_info(
        relay.clone(),
        host_header,
        is_websocket_request(request.headers()),
    )
    .await
    {
        return response;
    }
    if !is_websocket_request(request.headers()) {
        // Not a WebSocket handshake: serve the NIP-11 info document.
        let wants_nostr_json = request
            .headers()
            .get(axum::http::header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|a| a.contains("application/nostr+json"));
        return nip11_doc(relay.clone(), wants_nostr_json).await;
    }
    let path = request.uri().path().to_string();
    let (mut parts, _) = request.into_parts();
    let peer_ip = parts
        .extensions
        .get::<axum::extract::connect_info::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0.ip());
    match WebSocketUpgrade::from_request_parts(&mut parts, &()).await {
        Ok(upgrade) => {
            // Start with small read/write buffers (they grow on demand) so
            // that hundreds of thousands of idle connections do not pin
            // megabytes each.
            let cfg = relay.config.read().await;
            let max_msg = cfg.limits.max_ws_message_size;
            // Initial read/write buffer size per connection (grows on
            // demand); bounded so that hundreds of thousands of idle
            // connections do not pin megabytes each.
            let buffer_size = cfg.limits.buffer_size;
            // The outgoing buffer must fit the largest relay-generated
            // message: a NIP-77 NEG-MSG response carries every id of a
            // queried range as hex (up to neg_max_items ids), plus the JSON
            // envelope. Per-id worst case: 32 bytes as 64 hex chars, with
            // range headers amortized over the emitted ranges.
            let neg_max = cfg.limits.neg_max_items;
            let max_write = max_msg.max(neg_max.saturating_mul(80).saturating_add(64 * 1024));
            drop(cfg);
            upgrade
                .read_buffer_size(buffer_size)
                .write_buffer_size(buffer_size)
                // Reject oversized frames at the protocol layer: without
                // this the WebSocket stack buffers frames of up to its own
                // 64 MiB default into memory before the application check
                // runs, letting a client pin large allocations per frame.
                .max_message_size(max_msg)
                .max_frame_size(max_msg)
                .max_write_buffer_size(max_write)
                .on_upgrade(move |socket| {
                    handle_connection(
                        socket,
                        relay,
                        peer_ip.unwrap_or_else(|| "0.0.0.0".parse().unwrap()),
                        path,
                    )
                })
                .into_response()
        }
        Err(rejection) => rejection.into_response(),
    }
}

async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({ "status": "ok" })))
}

/// Prometheus metrics endpoint: the counters in text exposition format.
async fn metrics_handler(State(relay): State<Arc<Relay>>) -> impl IntoResponse {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        relay.stats.as_prometheus(),
    )
}

async fn stats_writer(relay: Arc<Relay>, mut shutdown: watch::Receiver<bool>) {
    let secs = relay.config.read().await.daemon.stats_interval_secs.max(1);
    let mut ticker = interval(Duration::from_secs(secs));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let path = relay.config.read().await.daemon.stats_file.clone();
                relay
                    .stats
                    .db_size_bytes
                    .store(relay.db.size_on_disk().await, std::sync::atomic::Ordering::Relaxed);
                relay.stats.bump(&relay.stats.db_errors, relay.db.take_errors());
                if let Ok(json) = serde_json::to_string_pretty(&relay.stats.as_json()) {
                    write_atomic(&path, json.as_bytes());
                }
            }
            _ = shutdown.changed() => break,
        }
    }
}

/// Writes `data` to `path` atomically (temp file + rename) so a crash in
/// the middle of a write never leaves a truncated stats file behind.
fn write_atomic(path: &Path, data: &[u8]) {
    let tmp = path.with_extension("tmp");
    let result = std::fs::write(&tmp, data).and_then(|()| std::fs::rename(&tmp, path));
    if let Err(e) = result {
        error!("cannot write {}: {e}", path.display());
        let _ = std::fs::remove_file(&tmp);
    }
}

async fn purge_loop(relay: Arc<Relay>, mut shutdown: watch::Receiver<bool>) {
    let secs = relay
        .config
        .read()
        .await
        .database
        .purge_interval_secs
        .max(10);
    let mut ticker = interval(Duration::from_secs(secs));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let removed = relay.db.purge_expired(unix_now()).await;
                if removed > 0 {
                    info!("purged {removed} expired events");
                }
            }
            _ = shutdown.changed() => break,
        }
    }
}

async fn signal_handler(shutdown: watch::Sender<bool>) {
    let mut terminate = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            error!("cannot register SIGTERM handler: {e}");
            return;
        }
    };
    let mut interrupt = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(e) => {
            error!("cannot register SIGINT handler: {e}");
            return;
        }
    };
    tokio::select! {
        _ = terminate.recv() => {}
        _ = interrupt.recv() => {}
    }
    info!("shutdown signal received");
    let _ = shutdown.send(true);
}

async fn reload_handler(
    config_path: PathBuf,
    relay: Arc<Relay>,
    db: DbClient,
    api_limit: Arc<crate::relay::ApiLimiter>,
    mut shutdown: watch::Receiver<bool>,
) {
    let config = relay.config.clone();
    let mut hangup = match signal(SignalKind::hangup()) {
        Ok(s) => s,
        Err(e) => {
            error!("cannot register SIGHUP handler: {e}");
            return;
        }
    };
    loop {
        tokio::select! {
            _ = hangup.recv() => {
                match Config::load(&config_path) {
                    Ok(mut new_config) => {
                        new_config.absolutize_paths(&config_path);
                        // Validate before applying: a parseable-but-invalid
                        // file (zero limits, bad keys, map layout) must not
                        // silently disable the relay at runtime. The old
                        // configuration stays in force on failure.
                        if let Err(e) = new_config.validate() {
                            error!("config reload rejected: {e}");
                            continue;
                        }
                        db.set_expiry_enabled(new_config.nip_enabled(40));
                        api_limit.set_max(new_config.limits.api_max_concurrent);
                        // The relay's signing key is fixed at startup: a
                        // reloaded private_key is not applied (NIP-29/NIP-43
                        // keep signing and NIP-11 `self` keeps advertising
                        // the old key). Warn so the operator knows a restart
                        // is required for it to take effect.
                        let old = config.read().await;
                        if old.relay.private_key != new_config.relay.private_key {
                            warn!(
                                "relay.private_key changed in the reloaded config but is fixed \
                                 at startup; a restart is required to apply it"
                            );
                        }
                        // Settings that shape the HTTP router are also fixed
                        // at startup: a reload cannot rebuild the routes.
                        let static_routes = [
                            ("server.api_host", old.server.api_host != new_config.server.api_host),
                            (
                                "server.metrics_enabled",
                                old.server.metrics_enabled != new_config.server.metrics_enabled,
                            ),
                            (
                                "relay.livekit_url",
                                old.relay.livekit_url != new_config.relay.livekit_url,
                            ),
                            (
                                "relay.livekit_api_key",
                                old.relay.livekit_api_key != new_config.relay.livekit_api_key,
                            ),
                            (
                                "relay.livekit_api_secret",
                                old.relay.livekit_api_secret
                                    != new_config.relay.livekit_api_secret,
                            ),
                            ("relay.enabled_nips", old.relay.enabled_nips != new_config.relay.enabled_nips),
                            ("relay.disabled_nips", old.relay.disabled_nips != new_config.relay.disabled_nips),
                            (
                                "blossom.host",
                                old.blossom.host != new_config.blossom.host,
                            ),
                            (
                                "blossom.storage",
                                old.blossom.storage != new_config.blossom.storage,
                            ),
                            (
                                "blossom.local_path",
                                old.blossom.local_path != new_config.blossom.local_path,
                            ),
                            (
                                "blossom.max_upload_bytes",
                                old.blossom.max_upload_bytes
                                    != new_config.blossom.max_upload_bytes,
                            ),
                            (
                                "blossom.s3_*",
                                old.blossom.s3_endpoint != new_config.blossom.s3_endpoint
                                    || old.blossom.s3_region != new_config.blossom.s3_region
                                    || old.blossom.s3_bucket != new_config.blossom.s3_bucket
                                    || old.blossom.s3_access_key
                                        != new_config.blossom.s3_access_key
                                    || old.blossom.s3_secret_key
                                        != new_config.blossom.s3_secret_key,
                            ),
                        ];
                        for (name, changed) in static_routes {
                            if changed {
                                warn!(
                                    "{name} changed in the reloaded config but the routes are \
                                     fixed at startup; a restart is required to apply it"
                                );
                            }
                        }
                        drop(old);
                        *config.write().await = new_config;
                        info!("configuration reloaded from {}", config_path.display());
                    }
                    Err(e) => error!("config reload failed: {e}"),
                }
                // The Blossom upload allowlist lives in the database: the
                // CLI (`nostrd blossom allow/deny`) writes it there and signals
                // SIGHUP, so re-read it here independently of the config
                // file (which may be untouched).
                let list = relay.db.load_blossom_allow().await;
                *relay.blossom_allow.write().await = list;
                info!("Blossom upload allowlist reloaded from the database");
                // The relay pubkey allow/deny lists are also database state
                // (`nostrd relay allow/deny`): re-read them into the live
                // access control.
                let (deny, allow) = relay.db.load_relay_pubkeys().await;
                let mut access = relay.access.write().await;
                access.blocked_pubkeys = deny;
                access.allowed_pubkeys = allow;
                // `restrict_relay` is config-owned: apply the reloaded flag.
                access.restrict_relay = relay.config.read().await.access.restrict_relay;
                info!("relay pubkey access lists reloaded from the database");
            }
            _ = shutdown.changed() => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_paths_for_selects_endpoints() {
        assert_eq!(ws_paths_for("root"), &["/"]);
        assert_eq!(ws_paths_for("inbox-outbox"), &["/inbox", "/outbox"]);
        assert_eq!(
            ws_paths_for("all"),
            &["/", "/inbox", "/outbox"],
            "all serves the root and the inbox/outbox paths"
        );
        assert_eq!(
            ws_paths_for("anything-else"),
            &["/"],
            "unknown values fall back to the root path"
        );
    }

    #[test]
    fn host_split_matches_ports_case_and_ipv6() {
        // The middleware normalizes ports, case and IPv6 brackets through
        // host_header_host before comparing — mirror it here.
        let norm = |h: &str| host_header_host(h).to_ascii_lowercase();
        assert!(host_route_allowed(
            "api.example.com",
            "",
            &norm("api.example.com"),
            "/api/v1/x"
        ));
        assert!(host_route_allowed(
            "api.example.com",
            "",
            &norm("api.example.com:8080"),
            "/api/v1/x"
        ));
        assert!(host_route_allowed(
            "api.example.com",
            "",
            &norm("API.EXAMPLE.COM"),
            "/api/v1/x"
        ));
        assert!(!host_route_allowed(
            "api.example.com",
            "",
            &norm("notapi.example.com"),
            "/api/v1/x"
        ));
        // HTTP requires bracket form for IPv6 Host headers.
        assert!(host_route_allowed("", "::1", &norm("[::1]"), "/upload"));
        assert!(host_route_allowed(
            "",
            "::1",
            &norm("[::1]:8080"),
            "/upload"
        ));
    }

    #[test]
    fn host_route_allocation_matrix() {
        let sha = "ab".repeat(32);
        // blossom only (api_host unset): relay paths stay reachable.
        assert!(host_route_allowed(
            "",
            "media.test",
            "relay.example.com",
            "/health"
        ));
        assert!(host_route_allowed(
            "",
            "media.test",
            "relay.example.com",
            "/metrics"
        ));
        assert!(host_route_allowed(
            "",
            "media.test",
            "relay.example.com",
            "/api/v1/npub1x"
        ));
        assert!(host_route_allowed(
            "",
            "media.test",
            "relay.example.com",
            "/ws"
        ));
        assert!(host_route_allowed(
            "",
            "media.test",
            "media.test",
            &format!("/{sha}")
        ));
        assert!(host_route_allowed(
            "",
            "media.test",
            "media.test",
            "/upload"
        ));
        assert!(!host_route_allowed("", "media.test", "media.test", "/ws"));
        assert!(!host_route_allowed(
            "",
            "media.test",
            "relay.example.com",
            &format!("/{sha}")
        ));
        // api + blossom: each host serves only its own paths.
        assert!(host_route_allowed(
            "api.example.com",
            "media.test",
            "api.example.com",
            "/api/v1/npub1x"
        ));
        assert!(host_route_allowed(
            "api.example.com",
            "media.test",
            "api.example.com",
            "/health"
        ));
        assert!(!host_route_allowed(
            "api.example.com",
            "media.test",
            "api.example.com",
            "/ws"
        ));
        assert!(!host_route_allowed(
            "api.example.com",
            "media.test",
            "relay.example.com",
            "/health"
        ));
        assert!(host_route_allowed(
            "api.example.com",
            "media.test",
            "relay.example.com",
            "/ws"
        ));
        assert!(!host_route_allowed(
            "api.example.com",
            "media.test",
            "media.test",
            "/api/v1/npub1x"
        ));
        // neither split: everything is a relay path (a bare 64-hex path is
        // still a Blossom-shaped path and 404s — no Blossom routes are
        // mounted without `blossom.host`).
        assert!(host_route_allowed("", "", "relay.example.com", "/health"));
        assert!(!host_route_allowed(
            "",
            "",
            "relay.example.com",
            &format!("/{sha}")
        ));
        assert!(!host_route_allowed("", "", "relay.example.com", "/upload"));
    }

    #[test]
    fn host_header_host_extracts_host() {
        assert_eq!(host_header_host("api.example.com"), "api.example.com");
        assert_eq!(host_header_host("api.example.com:8080"), "api.example.com");
        assert_eq!(host_header_host("[::1]"), "::1");
        assert_eq!(host_header_host("[::1]:8080"), "::1");
        assert_eq!(host_header_host("192.0.2.1:80"), "192.0.2.1");
    }
}
