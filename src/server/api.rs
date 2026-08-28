//! HTTP REST API: `/api/v1/` endpoint.
//!
//! Provides a read-only JSON API for querying stored events by npub1,
//! nevent1, or naddr1 identifiers.  Only `GET` is supported.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::config::Config;
use crate::event::Event;
use crate::filter::Filter;
use crate::nips::nip19::{self, Nip19Entity};
use crate::nips::{nip29, nip62, nip70};
use crate::relay::Relay;
use crate::util::unix_now;

#[derive(Debug, Deserialize)]
pub struct ApiParams {
    pub limit: Option<usize>,
    pub since: Option<u64>,
    pub until: Option<u64>,
    pub search: Option<String>,
    pub e: Option<String>,
    pub p: Option<String>,
    pub t: Option<String>,
    pub d: Option<String>,
    pub sort: Option<String>,
    pub offset: Option<usize>,
    /// Exclude events carrying the tag (absence filter): `no_p=true` drops
    /// every event with a `p` tag (mentions, replies, DMs), `no_e` drops
    /// events with an `e` tag (replies), `no_t` and `no_d` likewise. The
    /// exclusion applies before pagination, like the visibility rules.
    pub no_p: Option<bool>,
    pub no_e: Option<bool>,
    pub no_t: Option<bool>,
    pub no_d: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct ApiResponse {
    pub events: Vec<Value>,
    pub count: usize,
    pub more: bool,
}

fn error_response(status: StatusCode, message: &str) -> (StatusCode, Json<Value>) {
    (status, Json(json!({ "error": message })))
}

/// Bounds the API query parameters so a single request cannot trigger an
/// arbitrarily large database scan: `limit` is capped, `offset` is capped,
/// and over-long `search` terms are rejected.
fn bound_params(params: &mut ApiParams, cfg: &Config) -> Result<(), (StatusCode, String)> {
    let limits = &cfg.limits;
    if limits.api_max_limit > 0
        && let Some(limit) = params.limit
        && limit > limits.api_max_limit
    {
        params.limit = Some(limits.api_max_limit);
    }
    if limits.api_max_offset > 0
        && let Some(offset) = params.offset
        && offset > limits.api_max_offset
    {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("offset exceeds the maximum of {}", limits.api_max_offset),
        ));
    }
    if limits.api_max_search_bytes > 0
        && let Some(ref search) = params.search
        && search.len() > limits.api_max_search_bytes
    {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "search exceeds the maximum of {} bytes",
                limits.api_max_search_bytes
            ),
        ));
    }
    Ok(())
}

/// The tag names excluded by the `no_p`/`no_e`/`no_t`/`no_d` parameters
/// (absence filters: events carrying the tag are dropped before
/// pagination).
fn excluded_tags(params: &ApiParams) -> Vec<&'static str> {
    let mut out = Vec::new();
    if params.no_p.unwrap_or(false) {
        out.push("p");
    }
    if params.no_e.unwrap_or(false) {
        out.push("e");
    }
    if params.no_t.unwrap_or(false) {
        out.push("t");
    }
    if params.no_d.unwrap_or(false) {
        out.push("d");
    }
    out
}

fn apply_params(mut filter: Filter, params: &ApiParams) -> Filter {
    if let Some(since) = params.since {
        filter.since = Some(since);
    }
    if let Some(until) = params.until {
        filter.until = Some(until);
    }
    if let Some(ref search) = params.search {
        filter.search = Some(search.clone());
    }
    if let Some(ref e) = params.e {
        filter.tags.insert("#e".to_string(), json!(e));
    }
    if let Some(ref p) = params.p {
        filter.tags.insert("#p".to_string(), json!(p));
    }
    if let Some(ref t) = params.t {
        filter.tags.insert("#t".to_string(), json!(t));
    }
    if let Some(ref d) = params.d {
        filter.tags.insert("#d".to_string(), json!(d));
    }
    filter
}

/// Maps the `sort` query parameter to a scan direction: `asc` (or `ascending`)
/// returns oldest events first, everything else returns newest first.
fn sort_ascending(sort: &Option<String>) -> bool {
    matches!(sort.as_deref(), Some("asc" | "ascending"))
}

/// `GET /api/v1/{identifier}`
///
/// Handles npub1 (with a kind sub-path) and nevent1 (no kind needed).
pub async fn api_handler(
    State(relay): State<Arc<Relay>>,
    Path(identifier): Path<String>,
    Query(mut params): Query<ApiParams>,
) -> (StatusCode, Json<Value>) {
    let cfg = relay.config.read().await;
    if let Err((status, msg)) = bound_params(&mut params, &cfg) {
        return error_response(status, &msg);
    }
    let entity = match nip19::parse_nip19(&identifier) {
        Ok(e) => e,
        Err(e) => {
            return error_response(StatusCode::BAD_REQUEST, &format!("invalid identifier: {e}"));
        }
    };

    match entity {
        Nip19Entity::Pubkey(_) => error_response(
            StatusCode::BAD_REQUEST,
            "npub1 requires a kind path: /api/v1/npub1.../{kind}",
        ),
        Nip19Entity::Note(id) => {
            let hex_id = hex::encode(id);
            let filter = apply_params(
                Filter {
                    ids: Some(vec![hex_id]),
                    ..Default::default()
                },
                &params,
            );
            let no_tags = excluded_tags(&params);
            query_and_respond(
                &relay,
                vec![filter],
                1,
                params.offset,
                sort_ascending(&params.sort),
                &no_tags,
            )
            .await
        }
        Nip19Entity::Event { id, .. } => {
            let hex_id = hex::encode(id);
            let filter = apply_params(
                Filter {
                    ids: Some(vec![hex_id]),
                    ..Default::default()
                },
                &params,
            );
            let no_tags = excluded_tags(&params);
            query_and_respond(
                &relay,
                vec![filter],
                1,
                params.offset,
                sort_ascending(&params.sort),
                &no_tags,
            )
            .await
        }
        Nip19Entity::Addr {
            kind,
            pubkey,
            d_tag,
            ..
        } => {
            let hex_pk = hex::encode(pubkey);
            // `bound_params` already capped `params.limit` at
            // `limits.api_max_limit` when one is configured; there is no
            // hardcoded ceiling here (a configured `api_max_limit: 0` means
            // "no bound").
            let limit = params.limit.unwrap_or(100);
            // No per-filter `limit`: see the Pubkey handler.
            let mut filter = Filter {
                authors: Some(vec![hex_pk]),
                kinds: Some(vec![kind]),
                ..Default::default()
            };
            // d_tag from naddr1 is primary; user ?d= overrides if present
            let d_value = params.d.as_deref().unwrap_or(&d_tag);
            filter.tags.insert("#d".to_string(), json!(d_value));
            filter = apply_params(filter, &params);
            let no_tags = excluded_tags(&params);
            query_and_respond(
                &relay,
                vec![filter],
                limit,
                params.offset,
                sort_ascending(&params.sort),
                &no_tags,
            )
            .await
        }
    }
}

/// `GET /api/v1/{identifier}/{kind}`
///
/// Handles npub1 with a mandatory kind parameter.
pub async fn api_kind_handler(
    State(relay): State<Arc<Relay>>,
    Path((identifier, kind)): Path<(String, u64)>,
    Query(mut params): Query<ApiParams>,
) -> (StatusCode, Json<Value>) {
    let cfg = relay.config.read().await;
    if let Err((status, msg)) = bound_params(&mut params, &cfg) {
        return error_response(status, &msg);
    }
    let entity = match nip19::parse_nip19(&identifier) {
        Ok(e) => e,
        Err(e) => {
            return error_response(StatusCode::BAD_REQUEST, &format!("invalid identifier: {e}"));
        }
    };

    match entity {
        Nip19Entity::Pubkey(pk) => {
            let hex_pk = hex::encode(pk);
            // `bound_params` already capped `params.limit` at
            // `limits.api_max_limit` when one is configured; there is no
            // hardcoded ceiling here (a configured `api_max_limit: 0` means
            // "no bound").
            let limit = params.limit.unwrap_or(100);
            // No per-filter `limit`: query_and_respond fetches `limit+offset+1`
            // pre-filter rows (via the max_limit parameter) so pagination over
            // the visible sequence works even when hidden events are present.
            let filter = apply_params(
                Filter {
                    authors: Some(vec![hex_pk]),
                    kinds: Some(vec![kind]),
                    ..Default::default()
                },
                &params,
            );
            let no_tags = excluded_tags(&params);
            query_and_respond(
                &relay,
                vec![filter],
                limit,
                params.offset,
                sort_ascending(&params.sort),
                &no_tags,
            )
            .await
        }
        _ => error_response(
            StatusCode::BAD_REQUEST,
            "kind path is only valid with npub1 identifiers",
        ),
    }
}

async fn query_and_respond(
    relay: &Arc<Relay>,
    filters: Vec<Filter>,
    max_limit: usize,
    offset: Option<usize>,
    ascending: bool,
    no_tags: &[&str],
) -> (StatusCode, Json<Value>) {
    // Concurrency limiter: at most `api_max_concurrent` `/api/v1` queries
    // run at once. When saturated, the request fails fast with 503 so a
    // flood of REST traffic cannot pile up behind the shared database. The
    // permit releases the slot on every exit path of this handler.
    let Some(_permit) = relay.api_limit.try_acquire() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "server is busy, try again shortly" })),
        );
    };
    let now = unix_now();
    // NIP-50: when the search capability is disabled, strip `search` from the
    // filters (like the WebSocket path) so the REST API cannot trigger a
    // full-range term scan that a WS client could never run.
    let mut filters = filters;
    if !relay.config.read().await.nip_enabled(50) {
        for f in &mut filters {
            f.search = None;
        }
    }
    // Pagination: fetch `limit + offset + 1` so `more` can be decided from
    // the *visible* sequence (events hidden between pages — protected, gift
    // wraps, private groups — must not make a client skip a page or stop
    // early, e.g. `[V1, H, V2]` with offset=0 must still deliver V1 and V2).
    let skip = offset.unwrap_or(0);
    let (events, db_more) = relay
        .db
        .api_query(
            filters,
            max_limit.saturating_add(skip).saturating_add(1),
            now,
            ascending,
        )
        .await;
    drop(_permit);

    // The REST API is unauthenticated, so it must apply the same
    // visibility rules as an anonymous WebSocket connection: NIP-70
    // protected events, NIP-59 gift wraps and NIP-29 private/hidden group
    // content are withheld. Only the group read lock is taken when a batch
    // actually contains group events (the common case has none).
    let has_group_events = events.iter().any(nip29::is_group_event);
    let groups = if has_group_events {
        Some(relay.groups.read().await)
    } else {
        None
    };
    let visible: Vec<Event> = events
        .into_iter()
        .filter(|e| {
            !nip70::is_protected(e)
                && (e.kind != nip62::GIFT_WRAP_KIND)
                && groups.as_deref().is_none_or(|g| g.visible_to(e, None))
                && !no_tags
                    .iter()
                    .any(|name| e.tags.iter().any(|t| t.len() >= 2 && t[0] == *name))
        })
        .collect();
    drop(groups);

    // `more` reflects the visible sequence: a further page exists when more
    // than `skip + limit` visible events were fetched, or when the database
    // hint says the pre-filter scan was cut short (best-effort, so a page
    // that is under-filled because of hidden rows still advertises more).
    let has_more = visible.len() > skip.saturating_add(max_limit) || db_more;
    let event_values: Vec<Value> = visible
        .into_iter()
        .skip(skip)
        .take(max_limit)
        .filter_map(|e| serde_json::to_value(e).ok())
        .collect();

    let count = event_values.len();

    (
        StatusCode::OK,
        Json(json!(ApiResponse {
            events: event_values,
            count,
            more: has_more,
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};
    use tokio::sync::RwLock;

    use crate::db::DbClient;
    use crate::nips::nip01::sign;
    use crate::relay::LiveBusConfig;
    use crate::stats::Stats;

    fn signed_note(
        secp: &Secp256k1<secp256k1::All>,
        content: &str,
        created: u64,
        tags: Vec<Vec<String>>,
    ) -> Event {
        let keypair = Keypair::from_seckey_slice(secp, &[1u8; 32]).unwrap();
        let pubkey = XOnlyPublicKey::from_keypair(&keypair).0.to_string();
        let mut ev = Event {
            id: String::new(),
            pubkey,
            created_at: created,
            kind: 1,
            tags,
            content: content.into(),
            sig: String::new(),
        };
        sign(&mut ev, &keypair, secp).unwrap();
        ev
    }

    async fn build_relay() -> Arc<Relay> {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join("nostrd-api-test")
            .join(format!("{:x}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        let mut cfg = Config::default();
        cfg.database.path = path;
        let db = DbClient::open(
            &cfg.database,
            true,
            Arc::new(Default::default()),
            0,
            128,
            4096,
            262144,
        )
        .unwrap();
        let config = Arc::new(RwLock::new(cfg));
        let stats = Stats::new();
        let mut relay = Relay::new(
            config,
            db,
            stats,
            "",
            LiveBusConfig {
                buffer: 1024,
                batch_interval_ms: 10,
                batch_size: 64,
            },
        )
        .await;
        relay.start_live_bus();
        Arc::new(relay)
    }

    #[test]
    fn pagination_skips_hidden_events_without_losing_pages() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay().await;
            let now = unix_now();
            let v1 = signed_note(relay.secp(), "v1", now, vec![]);
            let hidden = signed_note(relay.secp(), "hidden", now - 1, vec![vec!["-".into()]]);
            let v2 = signed_note(relay.secp(), "v2", now - 2, vec![]);
            let v3 = signed_note(relay.secp(), "v3", now - 3, vec![]);
            for e in [&v1, &hidden, &v2, &v3] {
                assert_eq!(
                    relay.db.put(e.clone(), now).await,
                    crate::db::PutOutcome::Stored
                );
            }
            let filters: Vec<Filter> =
                serde_json::from_value(serde_json::json!([{"kinds": [1]}])).unwrap();

            // Page 1: the hidden event must not consume a slot; V1 and V2 both
            // arrive, and more pages exist.
            let (code, Json(resp)) =
                query_and_respond(&relay, filters.clone(), 2, Some(0), false, &[]).await;
            assert_eq!(code, StatusCode::OK);
            let events = resp["events"].as_array().unwrap();
            assert_eq!(events.len(), 2, "hidden event must not consume the page");
            assert_eq!(events[0]["content"], "v1");
            assert_eq!(events[1]["content"], "v2");
            assert_eq!(resp["more"], true);

            // Page 2 (offset 2 over visible): V3, and no more pages.
            let (_, Json(resp)) = query_and_respond(&relay, filters, 2, Some(2), false, &[]).await;
            let events = resp["events"].as_array().unwrap();
            assert_eq!(events.len(), 1);
            assert_eq!(
                events[0]["content"], "v3",
                "V2 must not be lost or repeated"
            );
            assert_eq!(resp["more"], false);

            relay.db.shutdown();
        });
    }

    #[test]
    fn no_tag_filters_exclude_mention_events() {
        // `no_p=true` is the "top-level posts only" filter: events carrying
        // a `p` tag (mentions, replies, DMs) are dropped before pagination,
        // so excluded events do not consume limit slots or offset steps.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay().await;
            let now = unix_now();
            let plain = signed_note(relay.secp(), "top-level", now, vec![]);
            let mention = signed_note(
                relay.secp(),
                "mention",
                now - 1,
                vec![vec!["p".into(), "aa".repeat(32)]],
            );
            let reply = signed_note(
                relay.secp(),
                "reply",
                now - 2,
                vec![vec!["e".into(), "bb".repeat(32)]],
            );
            for e in [&plain, &mention, &reply] {
                assert_eq!(
                    relay.db.put(e.clone(), now).await,
                    crate::db::PutOutcome::Stored
                );
            }
            let filters: Vec<Filter> =
                serde_json::from_value(serde_json::json!([{"kinds": [1]}])).unwrap();

            // Without exclusion: all three events.
            let (code, Json(resp)) =
                query_and_respond(&relay, filters.clone(), 10, Some(0), false, &[]).await;
            assert_eq!(code, StatusCode::OK);
            assert_eq!(resp["events"].as_array().unwrap().len(), 3);

            // no_p: the mention is dropped, the reply stays.
            let (_, Json(resp)) =
                query_and_respond(&relay, filters.clone(), 10, Some(0), false, &["p"]).await;
            let contents: Vec<String> = resp["events"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e["content"].as_str().unwrap().to_string())
                .collect();
            assert_eq!(contents, vec!["top-level".to_string(), "reply".to_string()]);

            // no_e: the reply is dropped, the mention stays.
            let (_, Json(resp)) =
                query_and_respond(&relay, filters.clone(), 10, Some(0), false, &["e"]).await;
            let contents: Vec<String> = resp["events"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e["content"].as_str().unwrap().to_string())
                .collect();
            assert_eq!(
                contents,
                vec!["top-level".to_string(), "mention".to_string()]
            );

            // no_p + no_e: only the top-level post remains.
            let (_, Json(resp)) =
                query_and_respond(&relay, filters, 10, Some(0), false, &["p", "e"]).await;
            let contents: Vec<String> = resp["events"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e["content"].as_str().unwrap().to_string())
                .collect();
            assert_eq!(contents, vec!["top-level".to_string()]);

            relay.db.shutdown();
        });
    }
}
