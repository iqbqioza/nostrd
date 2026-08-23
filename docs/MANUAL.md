# nostrd Manual

This manual explains every feature of **nostrd**, a Nostr relay server, step by step — from installation to everyday operation.

## Table of Contents

1. [What is nostrd](#1-what-is-nostrd)
2. [Installation](#2-installation)
3. [The Config File (nostrd.toml)](#3-the-config-file-nostrdtoml)
4. [Starting and Stopping](#4-starting-and-stopping)
5. [Command Reference](#5-command-reference)
6. [REST API](#6-rest-api)
7. [NIP-86 Management API](#7-nip-86-management-api)
8. [Supported NIPs](#8-supported-nips)
9. [NIP-29 Groups](#9-nip-29-groups)
10. [LiveKit (Audio/Video Rooms)](#10-livekit-audiovideo-rooms)
11. [Logs and Statistics](#11-logs-and-statistics)
12. [Reloading Configuration (SIGHUP)](#12-reloading-configuration-sighup)
13. [When You Are Stuck](#13-when-you-are-stuck)

---

## 1. What is nostrd

nostrd is a **relay server** for the [Nostr](https://nostr.com/) protocol. It stores events (posts, reactions, profiles, ...) sent by clients (nos2x, Amethyst, Damus, Iris, and others) and delivers them in response to subscription requests.

Key features:

- **Simple and stable**: written in Rust; a single binary does everything
- **Fast storage and search**: LMDB database with a full-text search index
- **Broad NIP support**: 19 NIPs implemented, including deletion, proof-of-work, delegation, groups, search, and a management API
- **Easy to operate**: daemon mode, log rotation, hot configuration reload, statistics output, a REST API, and Prometheus metrics

---

## 2. Installation

### Requirements

- A recent stable Rust toolchain
- A Linux machine (2 GB of RAM or more is recommended)

### Building

```bash
git clone https://github.com/iqbqioza/nostrd.git
cd nostrd
cargo build --release
```

When the build finishes, the binary is at `target/release/nostrd`.

```bash
./target/release/nostrd --version
```

### Running on port 80

Regular users cannot bind port 80. Either run with `sudo`, or use a higher port such as 8080.

```bash
# Example: run on port 8080 (works for regular users)
./target/release/nostrd --config nostrd.toml start
```

---

## 3. The Config File (nostrd.toml)

Configuration lives in a **TOML** file called `nostrd.toml`.

### Creating the initial config file

```bash
./target/release/nostrd --config nostrd.toml init
```

This generates `nostrd.toml`. Open it in a text editor and adjust it — every option is commented.

> For the complete option-by-option reference, see [Configuration Reference (CONFIGURATION.md)](CONFIGURATION.md).

### Validating the config

```bash
./target/release/nostrd --config nostrd.toml check
```

If anything is wrong, it tells you exactly what. It is strongly recommended to run this before starting.

### Configuration Options

#### `[relay]` — Basic relay information

| Option | Description | Default |
| --- | --- | --- |
| `name` | Relay name (shown to clients via NIP-11) | `nostrd` |
| `description` | Relay description | A fixed description |
| `pubkey` | Administrator public key (64 hex chars) | empty |
| `contact` | Administrator contact (URL or email) | empty |
| `icon` | Relay icon image URL | empty |
| `post_policy` | URL describing the posting policy | empty |
| `private_key` | The relay's own secret key. **Required for NIP-29 groups** | empty |
| `public_url` | The relay's public URL (e.g. `wss://relay.example.com`). **Set this for NIP-42 auth and friends to work correctly** | empty |
| `livekit_url` | LiveKit server URL (for audio/video rooms) | empty |
| `livekit_api_key` / `livekit_api_secret` | LiveKit API key and secret | empty |
| `enabled_nips` | Explicit allowlist of NIP numbers (empty = all enabled) | empty |
| `disabled_nips` | List of NIP numbers to disable | empty |

To generate a secret key, use the `nostrd genkey` command (see [5. Command Reference](#5-command-reference)).

#### `[server]` — Server settings

| Option | Description | Default |
| --- | --- | --- |
| `host` | Bind address (`0.0.0.0` for all interfaces) | `127.0.0.1` |
| `port` | Port number | `8080` |
| `api_host` | Hostname dedicated to the REST API. When set, only requests with this Host header can use the API (e.g. separate `api.example.com` and `relay.example.com` on the same port) | empty |
| `management_port` | Legacy management port (0 = disabled) | `0` |
| `management_host` | Bind address for the management port | `127.0.0.1` |
| `management_token` | Bearer token for the management API | empty |
| `admin_pubkey` | Administrator public key for NIP-98 auth | empty |
| `require_auth` | Require NIP-42 auth for everything (subscriptions and publishing) | `false` |
| `send_auth_challenge` | Send an AUTH challenge on connect | `true` |
| `metrics_enabled` | Serve `/metrics` (Prometheus format) | `true` |

> **Note**: `require_auth = true` combined with `send_auth_challenge = false` locks everyone out — nobody can authenticate. Avoid this combination.

#### `[limits]` — Limits

| Option | Description | Default |
| --- | --- | --- |
| `max_connections` | Maximum concurrent connections | `10000` |
| `max_connections_per_ip` | Max connections per source IP (0 = unlimited) | `0` |
| `max_ws_message_size` | Max bytes per WebSocket message/frame | `1048576` (1 MB) |
| `max_filters` | Max filters per REQ | `20` |
| `max_subscriptions` | Max subscriptions per connection | `20` |
| `max_limit` | Ceiling for the REQ `limit` | `500` |
| `count_limit` | Ceiling for COUNT aggregation | `2000` |
| `max_sub_id_len` | Max subscription id length | `64` |
| `max_content_bytes` | Max event content length in **characters** (not bytes — non-ASCII text is fine) | `65536` |
| `max_tags` | Max tags per event | `2000` |
| `max_tag_value_bytes` | Max bytes per tag value | `1024` |
| `max_created_at_future` | How many seconds of future timestamps are tolerated | `3600` |
| `require_pow` | Required proof-of-work difficulty in bits (0 = none) | `0` |
| `max_indexed_words` | Words indexed per event for search | `128` |
| `buffer_size` | Initial per-connection buffer size | `2048` |
| `neg_max_items` | Max records per NIP-77 negentropy sync | `100000` |
| `db_request_timeout_secs` | Database request timeout (0 = wait forever) | `30` |
| `new_pubkey_min_age_secs` | Reject posts from accounts younger than this (spam defense, 0 = off) | `0` |
| `max_out_queue_bytes` | Per-connection outgoing queue cap (bytes) | `262144` |
| `ws_idle_timeout_secs` | Close idle connections after this many seconds (0 = off) | `0` |
| `db_queue_msgs` / `db_queue_events` | Overload protection when the DB queue backs up | `4096` / `262144` |
| `max_sub_bytes` | Total subscription filter bytes per connection | `524288` |
| `group_late_publish_secs` | Reject NIP-29 group events older than this (0 = off) | `604800` (7 days) |
| `api_max_concurrent` | Max concurrent REST API requests | `32` |
| `api_max_limit` | Ceiling for the API `limit` parameter (0 = unlimited) | `500` |
| `api_max_offset` | Ceiling for the API `offset` parameter (0 = unlimited) | `10000` |
| `api_max_search_bytes` | Max `search` bytes for the API (0 = unlimited) | `1024` |
| `live_batch_interval_ms` / `live_batch_size` | Live fan-out batching (ms / events) | `10` / `64` |
| `live_buffer` | Live fan-out queue size | `65536` |

#### `[database]` — Database

| Option | Description | Default |
| --- | --- | --- |
| `path` | Database directory | `./data` |
| `max_dbs` / `max_readers` | Internal LMDB settings (usually leave as-is) | `32` / `128` |
| `map_size` | Minimum memory-map size (bytes) | 1 GB |
| `map_max_size` | Memory-map ceiling (bytes). **Raise this if you hit the "map is full" error** | 1 TB |
| `purge_interval_secs` | Interval for purging NIP-40 expired events | `300` |
| `search_index` | Enable the NIP-50 full-text index | `true` |

#### `[daemon]` — Daemon settings

| Option | Description | Default |
| --- | --- | --- |
| `pid_file` | PID file path | `./nostrd.pid` |
| `log_file` | Log file path | `./nostrd.log` |
| `stats_file` | Statistics file path | `./nostrd.stats.json` |
| `stats_interval_secs` | Statistics write interval | `5` |
| `log_max_size_bytes` | Log rotation size (0 = no rotation) | 50 MB |
| `log_max_files` | Number of rotated log files to keep | `5` |

#### `[access]` — Access control (also changeable at runtime via NIP-86)

| Option | Description |
| --- | --- |
| `blocked_pubkeys` | Public keys whose posts are rejected |
| `allowed_pubkeys` | **Allowlist**. When non-empty, only these pubkeys may post |
| `blocked_kinds` | Event kinds to reject |
| `allowed_kinds` | Kind allowlist. When non-empty, only these kinds are accepted |
| `blocked_ips` | IP addresses to refuse connections from |

> **Note**: Adding even one entry to `allowed_pubkeys` switches the relay into allowlist mode — everyone else is locked out. Be careful not to lock yourself out unintentionally.

---

## 4. Starting and Stopping

### Start (as a daemon)

```bash
./target/release/nostrd --config nostrd.toml start
# => nostrd started (pid 12345)
```

### Start (foreground, in the terminal)

```bash
./target/release/nostrd --config nostrd.toml start --foreground
```

### Stop

```bash
./target/release/nostrd --config nostrd.toml stop
# => stopping nostrd (pid 12345)
# => nostrd stopped
```

### Restart (re-reads the config)

```bash
./target/release/nostrd --config nostrd.toml restart
```

### Health check

```bash
curl http://127.0.0.1:8080/health
# => {"status":"ok"}
```

### NIP-11 information document

```bash
curl -H "Accept: application/nostr+json" http://127.0.0.1:8080/
```

Returns the relay name, supported NIPs, limits, and more as JSON.

### Reload the config without replacing the process

After editing the config file, a **SIGHUP** reloads it without a full restart:

```bash
# The PID is written to nostrd.pid
kill -HUP $(cat nostrd.pid)
```

> Some settings are fixed at startup and are **not** changed by a reload (`api_host`, `metrics_enabled`, LiveKit settings, `private_key`, ...). Use `restart` for those; the log warns you when this applies.

---

## 5. Command Reference

All commands accept `--config <path>` (default: `nostrd.toml`).

| Command | Description |
| --- | --- |
| `nostrd init` | Write a default config file (refuses to overwrite an existing one) |
| `nostrd genkey` | Generate a secret key for NIP-29 groups and write it into `relay.private_key`. Asks for confirmation (y/N) if a key already exists. Also prints the public key (the NIP-11 `self`) |
| `nostrd check` | Validate the config file (run before starting) |
| `nostrd start` | Start as a daemon (`--foreground` to run in the terminal) |
| `nostrd stop` | Stop the running daemon |
| `nostrd restart` | Stop and start again (re-reads the config) |
| `nostrd stats` | Show live statistics |

---

## 6. REST API

nostrd provides a read-only REST API at `GET /api/v1/...`.

> If `server.api_host` is set, only requests with that Host header can use the API (e.g. `curl -H "Host: api.example.com" ...`).

### Fetching events

| Path | Description |
| --- | --- |
| `/api/v1/{npub1}/{kind}` | Events of a pubkey, filtered by kind |
| `/api/v1/{note1}` | A single event |
| `/api/v1/{nevent1}` | A single event |
| `/api/v1/{naddr1}` | A specific addressable event |

Example:

```bash
curl "http://127.0.0.1:8080/api/v1/npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkws3w8ktc/1"
# => {"events":[...],"count":N,"more":false}
```

### Query parameters

| Parameter | Description |
| --- | --- |
| `limit` | Max results (default 100, capped by `api_max_limit`) |
| `offset` | Number of results to skip (pagination) |
| `since` / `until` | Unix timestamp range |
| `sort` | `asc` for oldest-first (default is newest-first) |
| `search` | NIP-50 full-text search |
| `e` / `p` / `t` / `d` | Filter by `#e` / `#p` / `#t` / `#d` tags |

`more: true` means there is more data; increase `offset` to continue.

> **Tip**: Pagination is computed over the *visible* sequence, so hidden events (protected events etc.) never skip or duplicate a page.

> For the full endpoint, parameter, pagination and error reference, see [HTTP REST API Reference (API.md)](API.md).

---

## 7. NIP-86 Management API

NIP-86 is a JSON-RPC API for managing the relay. **Authentication is required.**

### Authentication methods

1. **Bearer token**: set `server.management_token` and send `Authorization: Bearer <token>`
2. **NIP-98**: set `server.admin_pubkey` and send a NIP-98 auth event (kind 27235) signed by the admin key in `Authorization: Nostr <base64>` (a `payload` tag is required)

### Calling the API

`POST /` with `Content-Type: application/nostr+json+rpc`:

```bash
curl -X POST http://127.0.0.1:8080/ \
  -H "Content-Type: application/nostr+json+rpc" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"method":"supportedmethods","params":[]}'
```

### Methods

| Method | Params | Description |
| --- | --- | --- |
| `supportedmethods` | `[]` | List of supported methods |
| `banpubkey` | `["pubkey", "reason (optional)"]` | Ban a pubkey from posting |
| `unbanpubkey` | `["pubkey"]` | Unban a pubkey |
| `listbannedpubkeys` | `[]` | List banned pubkeys and reasons |
| `allowpubkey` | `["pubkey", "reason (optional)"]` | Add to the allowlist (also un-bans) |
| `unallowpubkey` | `["pubkey"]` | Remove from the allowlist |
| `listallowedpubkeys` | `[]` | List the allowlist |
| `allowkind` / `disallowkind` | `[kind]` | Allow / disallow a kind |
| `listallowedkinds` | `[]` | List allowed kinds |
| `changerelayname` / `changerelaydescription` / `changerelayicon` | `["new value"]` | Change the relay name / description / icon (**persisted to the config file**) |
| `createrole` / `editrole` / `deleterole` | `[id, label, description, color, order]` | NIP-43 role management |
| `assignrole` / `unassignrole` | `["pubkey", "role id"]` | Assign / unassign a role |
| `blockip` / `unblockip` | `["ip", "reason (optional)"]` | Block / unblock an IP (**blocking also drops existing connections**) |
| `listblockedips` | `[]` | List blocked IPs |
| `banevent` / `allowevent` | `["event id", "reason (optional)"]` | Ban / unban an event |
| `listbannedevents` | `[]` | List banned events |
| `listeventsneedingmoderation` | `[]` | Events awaiting moderation (always empty on this relay) |

### Legacy management port

If `server.management_port` is set, the legacy REST endpoints are available at `http://<management_host>:<port>/admin/...` (`/admin/info`, `/admin/stats`, `/admin/block_pubkey`, `/admin/allow_pubkey`, `/admin/block_kind`, `/admin/allow_kind`, `/admin/status/{id}`, `/admin/shutdown`). Same authentication.

---

## 8. Supported NIPs

| NIP | Description |
| --- | --- |
| 1 | Basic protocol (events, subscriptions) |
| 9 | Event deletion |
| 11 | Relay information document |
| 13 | Proof of work |
| 26 | Delegated event signing |
| 28 | Public chat |
| 29 | Relay-based groups |
| 33 | Parameterized replaceable events |
| 40 | Expiration timestamp |
| 42 | Client authentication |
| 43 | Relay access metadata (roles) |
| 45 | Counting results (COUNT / HyperLogLog) |
| 50 | Search capability (full-text, relevance-ordered) |
| 62 | Request to vanish |
| 67 | EOSE completeness hint |
| 70 | Protected events |
| 77 | Negentropy syncing |
| 86 | Relay management API |
| 98 | HTTP auth |

---

## 9. NIP-29 Groups

nostrd supports NIP-29 (relay-based groups): closed chat spaces where only members can write.

### Enabling groups

1. Run `nostrd genkey` to set `relay.private_key` (**required** — group metadata is not generated without it)
2. `restart` the relay

### How groups work (overview)

| Event | Description |
| --- | --- |
| `kind:9007` | Create group (the creator becomes the admin) |
| `kind:9000` / `9001` | Add member (with roles) / remove member |
| `kind:9002` | Edit metadata (name, description, public/private, ...) |
| `kind:9005` | Delete event (moderation) |
| `kind:9008` | Delete group |
| `kind:9009` | Create invite code |
| `kind:9010` | Update pin list |
| `kind:9021` / `9022` | Join request / leave request |

From these moderation events, the relay generates the following **relay-signed snapshots** (used by clients for display):

- `kind:39000` — group metadata (name, visibility settings, ...)
- `kind:39001` — admin list
- `kind:39002` — member list
- `kind:39005` — pinned events

### Group visibility settings

| Tag | Meaning |
| --- | --- |
| `private` | Only members can read messages |
| `restricted` | Only members can write |
| `hidden` | Metadata is hidden from non-members |
| `closed` | Join requests are not auto-approved (invite codes required) |
| `livekit` | The group has a LiveKit audio/video room |

### Subgroups

Groups can be hierarchical (`parent` / `child` tags). Cycles are rejected automatically.

---

## 10. LiveKit (Audio/Video Rooms)

With a LiveKit server configured, groups can have audio/video chat rooms.

1. Set `relay.livekit_url`, `relay.livekit_api_key`, and `relay.livekit_api_secret`
2. Add the `livekit` tag to the group's metadata (via an admin's 9002 edit)
3. Clients fetch a JWT from `/.well-known/nip29/livekit/<group-id>` with NIP-98 auth

```bash
# Support check (204 means enabled)
curl -i http://127.0.0.1:8080/.well-known/nip29/livekit
```

---

## 11. Logs and Statistics

### Logs

The daemon writes to `daemon.log_file`. When the file grows past `log_max_size_bytes`, it rotates automatically (`nostrd.log.1`, `nostrd.log.2`, ... up to `log_max_files` generations).

```bash
# Follow the log
tail -f nostrd.log
```

The log level is controlled by the `RUST_LOG` environment variable (e.g. `RUST_LOG=debug`).

### Statistics

```bash
./target/release/nostrd stats
```

Or over HTTP:

```bash
curl http://127.0.0.1:8080/relay/stats
```

Shows connections, events received/accepted/rejected, DB size, and more.

### Prometheus metrics

```bash
curl http://127.0.0.1:8080/metrics
```

Available when `metrics_enabled = true`.

---

## 12. Reloading Configuration (SIGHUP)

After editing the config file, reload it without a restart:

```bash
kill -HUP $(cat nostrd.pid)
```

Settings that take effect on reload: relay name/description, limits, NIP toggles (partially), NIP-40 on/off, API concurrency, ...

Settings that require a **restart**: `private_key`, `api_host`, `metrics_enabled`, LiveKit settings, `enabled_nips`/`disabled_nips`. The log warns when a change needs a restart.

---

## 13. When You Are Stuck

See [Troubleshooting (TROUBLESHOOTING.md)](TROUBLESHOOTING.md) for common errors and their fixes.