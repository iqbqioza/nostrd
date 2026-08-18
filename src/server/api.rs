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
            query_and_respond(
                &relay,
                vec![filter],
                1,
                params.offset,
                sort_ascending(&params.sort),
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
            query_and_respond(
                &relay,
                vec![filter],
                1,
                params.offset,
                sort_ascending(&params.sort),
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
            let limit = params.limit.unwrap_or(100).min(500);
            let mut filter = Filter {
                authors: Some(vec![hex_pk]),
                kinds: Some(vec![kind]),
                limit: Some(limit),
                ..Default::default()
            };
            // d_tag from naddr1 is primary; user ?d= overrides if present
            let d_value = params.d.as_deref().unwrap_or(&d_tag);
            filter.tags.insert("#d".to_string(), json!(d_value));
            filter = apply_params(filter, &params);
            query_and_respond(
                &relay,
                vec![filter],
                limit,
                params.offset,
                sort_ascending(&params.sort),
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
            let limit = params.limit.unwrap_or(100).min(500);
            let filter = apply_params(
                Filter {
                    authors: Some(vec![hex_pk]),
                    kinds: Some(vec![kind]),
                    limit: Some(limit),
                    ..Default::default()
                },
                &params,
            );
            query_and_respond(
                &relay,
                vec![filter],
                limit,
                params.offset,
                sort_ascending(&params.sort),
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
) -> (StatusCode, Json<Value>) {
    // Concurrency limiter: at most `api_max_concurrent` `/api/v1` queries
    // run at once. When saturated, the request fails fast with 503 so a
    // flood of REST traffic cannot pile up behind the shared database.
    let Ok(permit) = relay.api_limit.clone().try_acquire_owned() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "server is busy, try again shortly" })),
        );
    };
    let now = unix_now();
    // Pagination: fetch `limit + offset` so skipping `offset` still leaves
    // `limit` events to return.
    let skip = offset.unwrap_or(0);
    let (events, more) = relay
        .db
        .api_query(filters, max_limit.saturating_add(skip), now, ascending)
        .await;
    drop(permit);

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
    let event_values: Vec<Value> = events
        .into_iter()
        .filter(|e| {
            !nip70::is_protected(e)
                && (e.kind != nip62::GIFT_WRAP_KIND)
                && groups.as_deref().is_none_or(|g| g.visible_to(e, None))
        })
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
            more,
        })),
    )
}
