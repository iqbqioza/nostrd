//! HTTP server: the WebSocket/NIP-11/NIP-86 endpoint, CORS, the
//! daemon background tasks (stats, expiry purge, signals, config
//! reload) and the NIP-29 LiveKit integration in [`livekit`].

mod livekit;

use std::path::PathBuf;
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
use log::{error, info};
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
    unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            opt,
            &value as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
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
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    headers.insert(
        axum::http::header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("Authorization, Content-Type, Accept"),
    );
    headers.insert(
        axum::http::header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static("86400"),
    );
}

pub async fn run_server(config_path: PathBuf, config: Config, db: DbClient) -> Result<()> {
    let private_key = config.relay.private_key.clone();
    let live_buffer = config.limits.live_buffer;
    let live_batch_interval_ms = config.limits.live_batch_interval_ms;
    let live_batch_size = config.limits.live_batch_size;
    let config = Arc::new(tokio::sync::RwLock::new(config));
    let stats = Stats::new();
    let mut relay = Arc::new(
        Relay::new(
            config,
            db,
            stats,
            &private_key,
            live_buffer,
            live_batch_interval_ms,
            live_batch_size,
        )
        .await,
    );
    Arc::get_mut(&mut relay)
        .expect("relay not cloned yet")
        .start_live_bus();

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

    let mut app = Router::new()
        .route("/", get(ws_handler).post(nip86::rpc_handler))
        .route("/ws", get(ws_handler).post(nip86::rpc_handler))
        .route("/ws/", get(ws_handler))
        .route("/health", get(health_handler))
        .route("/relay/stats", get(stats_handler));
    {
        let cfg = relay.config.read().await;
        if cfg.nip_enabled(29) && !cfg.relay.livekit_url.is_empty() {
            app = app
                .route("/.well-known/nip29/livekit", get(livekit_supported))
                .route("/.well-known/nip29/livekit/{group}", get(livekit_token));
        }
    }
    let app = app
        .layer(axum::middleware::from_fn(cors_middleware))
        .with_state(relay.clone());

    let bind_addr = {
        let cfg = relay.config.read().await;
        (cfg.server.host.clone(), cfg.server.port)
    };
    let listener = TcpListener::bind(&bind_addr).await.map_err(|e| {
        Error::Config(format!(
            "cannot bind to {}:{}: {e}",
            bind_addr.0, bind_addr.1
        ))
    })?;
    info!("relay listening on ws://{}:{}", bind_addr.0, bind_addr.1);

    let mut tasks = Vec::new();

    let mgmt = {
        let cfg = relay.config.read().await;
        if cfg.server.management_port > 0 {
            let mgmt_addr = (
                cfg.server.management_host.clone(),
                cfg.server.management_port,
            );
            let listener = TcpListener::bind(&mgmt_addr).await.map_err(|e| {
                Error::Config(format!(
                    "cannot bind management on {}:{}: {e}",
                    mgmt_addr.0, mgmt_addr.1
                ))
            })?;
            info!(
                "management listening on http://{}:{}",
                mgmt_addr.0, mgmt_addr.1
            );
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
        relay.config.clone(),
        relay.db.clone(),
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
            .any(|blocked| blocked.parse::<std::net::IpAddr>().is_ok_and(|b| b == ip))
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    if !is_websocket_request(request.headers()) {
        // Not a WebSocket handshake: serve the NIP-11 info document.
        let cfg = relay.config.read().await;
        let body = Json(relay_info(
            &cfg,
            &relay.stats,
            relay.relay_pubkey().as_deref(),
        ));
        let mut response = body.into_response();
        // Serve with the NIP-11 media type when the client asked for it;
        // some clients only accept `application/nostr+json`.
        let wants_nostr_json = request
            .headers()
            .get(axum::http::header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|a| a.contains("application/nostr+json"));
        if wants_nostr_json {
            response.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("application/nostr+json"),
            );
        }
        return response;
    }
    let (mut parts, _) = request.into_parts();
    match WebSocketUpgrade::from_request_parts(&mut parts, &()).await {
        Ok(upgrade) => {
            // Start with small read/write buffers (they grow on demand) so
            // that hundreds of thousands of idle connections do not pin
            // megabytes each.
            let cfg = relay.config.read().await;
            let max_msg = cfg.limits.max_ws_message_size;
            // The outgoing buffer must fit the largest relay-generated
            // message: a NIP-77 NEG-MSG response carries every id of a
            // queried range as hex (up to neg_max_items ids), plus the JSON
            // envelope. Per-id worst case: 32 bytes as 64 hex chars, with
            // range headers amortized over the emitted ranges.
            let neg_max = cfg.limits.neg_max_items;
            let max_write = max_msg.max(neg_max.saturating_mul(80).saturating_add(64 * 1024));
            drop(cfg);
            upgrade
                .read_buffer_size(2 * 1024)
                .write_buffer_size(2 * 1024)
                // Reject oversized frames at the protocol layer: without
                // this the WebSocket stack buffers frames of up to its own
                // 64 MiB default into memory before the application check
                // runs, letting a client pin large allocations per frame.
                .max_message_size(max_msg)
                .max_frame_size(max_msg)
                .max_write_buffer_size(max_write)
                .on_upgrade(move |socket| handle_connection(socket, relay))
                .into_response()
        }
        Err(rejection) => rejection.into_response(),
    }
}

async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({ "status": "ok" })))
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
                if let Ok(json) = serde_json::to_string_pretty(&relay.stats.as_json())
                    && std::fs::write(&path, json).is_err()
                {
                    error!("cannot write stats file {}", path.display());
                }
            }
            _ = shutdown.changed() => break,
        }
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
    config: Arc<tokio::sync::RwLock<Config>>,
    db: DbClient,
    mut shutdown: watch::Receiver<bool>,
) {
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
                        db.set_expiry_enabled(new_config.nip_enabled(40));
                        *config.write().await = new_config;
                        info!("configuration reloaded from {}", config_path.display());
                    }
                    Err(e) => error!("config reload failed: {e}"),
                }
            }
            _ = shutdown.changed() => break,
        }
    }
}
