# nostrd HTTP REST API Reference

nostrd provides a **read-only** HTTP REST API for querying stored events. It is served on `GET /api/v1/...`.

## Table of Contents

1. [Base URL and Host Routing](#1-base-url-and-host-routing)
2. [Endpoints](#2-endpoints)
3. [Query Parameters](#3-query-parameters)
4. [Response Format](#4-response-format)
5. [Pagination](#5-pagination)
6. [Visibility Rules](#6-visibility-rules)
7. [Error Responses](#7-error-responses)
8. [Status Codes](#8-status-codes)
9. [Examples](#9-examples)

---

## 1. Base URL and Host Routing

The API is served on the same port as the WebSocket relay, under the `/api/v1` prefix:

```
http://<host>:<port>/api/v1/{identifier}
http://<host>:<port>/api/v1/{identifier}/{kind}
```

### `server.api_host` (host-based routing)

When `server.api_host` is configured (e.g. `api.example.com`), the API and the WebSocket relay are split by the **Host header**:

| Host header | `/api/v1`, `/health`, `/metrics` | WebSocket relay & NIP-11 (`/`, `/ws`) |
| --- | --- | --- |
| `api.example.com` | served | `404` |
| any other host | `404` | served |

Without `api_host`, the API is served on every host, next to the WebSocket endpoint.

> **Note**: Only `GET` is supported. WebSocket upgrade requests to `/api/v1` are rejected with `403 Forbidden`.

---

## 2. Endpoints

### 2.1 `GET /api/v1/{identifier}`

`{identifier}` is a NIP-19 entity:

| Identifier | Returns | `limit` default |
| --- | --- | --- |
| `npub1...` | **error `400`** — an npub requires the kind path (see 2.2) | — |
| `note1...` | the single event with this id | `1` (fixed) |
| `nevent1...` | the single event with this id (relays/author/kind hints ignored) | `1` (fixed) |
| `naddr1...` | events of the address: kind + author + `d` tag from the address | `100` |

### 2.2 `GET /api/v1/{identifier}/{kind}`

Only valid for `npub1...`. Returns events by the pubkey, filtered by `kind` (a decimal number).

```
GET /api/v1/npub1.../1        # notes
GET /api/v1/npub1.../7        # reactions
GET /api/v1/npub1.../30023    # long-form articles
```

Any other identifier with a kind path returns `400`.

---

## 3. Query Parameters

All parameters are optional and passed as URL query strings.

| Parameter | Type | Description |
| --- | --- | --- |
| `limit` | integer | Max results (default `100` for npub queries; capped by `limits.api_max_limit`; `0` in the config means "no bound") |
| `offset` | integer | Number of visible results to skip (pagination; capped by `limits.api_max_offset` — exceeding it returns `400`) |
| `since` | integer | Only events with `created_at >= since` |
| `until` | integer | Only events with `created_at <= until` |
| `sort` | string | `asc` or `ascending` = oldest first; anything else (default) = newest first |
| `search` | string | NIP-50 full-text search on content (whole-word matching; length capped by `limits.api_max_search_bytes` — exceeding it returns `400`) |
| `e` | string | Require an `e` tag with this value |
| `p` | string | Require a `p` tag with this value |
| `t` | string | Require a `t` tag with this value |
| `d` | string | Require a `d` tag with this value. For `naddr1...` the address's own `d` is used unless `d` is given (which overrides it) |

> **Search note**: like the WebSocket path, search matches **whole words** — `search=ru` does not match the word "rust". When NIP-50 is disabled, `search` is silently ignored.

---

## 4. Response Format

Successful responses return `200 OK` with the following JSON body:

```json
{
  "events": [
    {
      "id": "32-byte hex event id",
      "pubkey": "32-byte hex pubkey",
      "created_at": 1700000000,
      "kind": 1,
      "tags": [["t", "example"]],
      "content": "hello",
      "sig": "64-byte hex signature"
    }
  ],
  "count": 1,
  "more": false
}
```

| Field | Description |
| --- | --- |
| `events` | The events of this page (newest first by default) |
| `count` | The number of events in this page |
| `more` | `true` when further pages exist (use `offset` to fetch them) |

---

## 5. Pagination

Pagination is done with `offset` and the `more` flag:

```
GET /api/v1/npub1.../1?limit=50&offset=0     # page 1
GET /api/v1/npub1.../1?limit=50&offset=50    # page 2 (when more was true)
```

Pagination is computed over the **visible** sequence (see [Visibility Rules](#6-visibility-rules)), so hidden events never skip or duplicate a page.

---

## 6. Visibility Rules

The API is unauthenticated, so it applies the same visibility rules as an **anonymous** WebSocket connection. The following events are withheld:

- **NIP-70 protected events** (carrying a `-` tag)
- **NIP-59 gift wraps** (kind 1059)
- **NIP-29 private/hidden group content** (visible only to members)

These events are excluded before pagination, so they do not consume `limit` slots or corrupt the `offset` sequence.

---

## 7. Error Responses

Errors return a JSON body with an `error` field:

```json
{"error": "invalid identifier: invalid bech32m checksum"}
```

| Error example | When |
| --- | --- |
| `invalid identifier: ...` | The NIP-19 identifier cannot be decoded (400) |
| `npub1 requires a kind path: /api/v1/npub1.../{kind}` | An npub without the kind path (400) |
| `kind path is only valid with npub1 identifiers` | A kind path with note/nevent/naddr (400) |
| `offset exceeds the maximum of 10000` | `offset` above `api_max_offset` (400) |
| `search exceeds the maximum of 1024 bytes` | `search` longer than `api_max_search_bytes` (400) |
| `server is busy, try again shortly` | Too many concurrent API requests (`api_max_concurrent` reached) (503) |
| `not found` | The path does not exist, or the Host header does not match `api_host` (404) |

---

## 8. Status Codes

| Code | Meaning |
| --- | --- |
| `200` | Success |
| `400` | Invalid identifier or query parameter |
| `403` | WebSocket upgrade attempt to `/api/v1` |
| `404` | Unknown path, or wrong Host for the API (`api_host` configured) |
| `503` | API concurrency limit reached — retry shortly |

---

## 9. Examples

### Fetch a user's notes (newest first)

```bash
curl "http://127.0.0.1:8080/api/v1/npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkws3w8ktc/1"
```

### Paginate

```bash
curl "http://127.0.0.1:8080/api/v1/npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkws3w8ktc/1?limit=10&offset=10&sort=asc"
```

### Fetch a single event by id

```bash
# note1 or nevent1 both work
curl "http://127.0.0.1:8080/api/v1/note1..."
curl "http://127.0.0.1:8080/api/v1/nevent1..."
```

### Fetch an addressable event (naddr)

```bash
curl "http://127.0.0.1:8080/api/v1/naddr1..."
# override the d tag from the address:
curl "http://127.0.0.1:8080/api/v1/naddr1...?d=another-d"
```

### Search

```bash
curl "http://127.0.0.1:8080/api/v1/npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkws3w8ktc/1?search=rust"
```

### Tag filters

```bash
curl "http://127.0.0.1:8080/api/v1/npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkws3w8ktc/7?e=<event-id>&limit=100"
```

---

## Related

- [Manual (MANUAL.md)](MANUAL.md) — configuration reference for the API limits (`api_max_concurrent`, `api_max_limit`, `api_max_offset`, `api_max_search_bytes`)
- [Troubleshooting (TROUBLESHOOTING.md)](TROUBLESHOOTING.md)