# nostrd

A minimal, stable and fast [Nostr](https://github.com/nostr-protocol/nostr) relay server written in Rust.

nostrd is designed around two goals:

- **Never go down.** Overload protection, a dedicated reader thread, panic containment and strict resource bounds keep the relay serving even under sustained abuse, a stalled disk or a memory-constrained host.
- **Spec-complete.** All relay-side NIPs are implemented and verified against the official specifications (file-storage NIPs excluded by design).

## Features

- **All relay-side NIPs implemented** — see the [NIP support](#nip-support) table.
- **LMDB persistence (via `heed`)** — durable, crash-safe storage that grows automatically (up to a configurable ceiling) and keeps serving no matter how large the database becomes.
- **Overload protection** — the database queue is bounded; when it fills up, new requests fail fast instead of accumulating in memory.
- **Reader/writer thread split** — reads are served by a dedicated thread that never takes the LMDB write lock, so a stalled writer (slow disk, external lock holder) cannot take the relay down for readers.
- **Panic-safe** — task panics are contained and logged, and connection accounting is released on every exit path.
- **Efficient hot paths** — single-pass event parsing, deduplicated live serialization, batched commits (one fsync per batch), merged multi-range scans and NIP-67 boundary handling.
- **Everything configurable** via `nostrd.toml` — no compile-time options.
- **Works behind TLS-terminating proxies** (nginx, Caddy, Cloudflare Tunnel): WebSocket upgrades are honored via `X-Forwarded-Proto`.

## Requirements

- Linux / macOS / other Unix-like OS (daemonization uses the `daemonize` crate)
- Rust 1.85+ (edition 2024)
- A 64-bit system is recommended (LMDB maps can be huge on 32-bit systems)

## Build

```sh
cargo build --release
# the binary is at target/release/nostrd
```

## Quick start

```sh
# write a default nostrd.toml and exit
nostrd init

# start the relay as a daemon (add --foreground to run in the shell)
nostrd start

# check it is up
nostrd stats
```

Point your Nostr client at `ws://<host>:8080` (or `wss://<domain>` behind a TLS proxy).

## Commands

| Command | Description |
| --- | --- |
| `nostrd init` | Write a default configuration file and exit |
| `nostrd start` | Start the relay as a daemon (`--foreground` to stay in the shell) |
| `nostrd stop` | Stop the running daemon |
| `nostrd restart` | Stop and start again (reloads `nostrd.toml`) |
| `nostrd stats` | Show live statistics of the running daemon |
| `nostrd check` | Validate `nostrd.toml` and exit |

All commands accept `--config <path>` (default `./nostrd.toml`).

Sending `SIGHUP` to the daemon reloads the configuration at runtime (limits and server settings apply immediately; the NIP-40 toggle is applied live too).

## Configuration

Every setting is optional — missing entries fall back to the defaults. `nostrd.toml.example` documents every option with comments. The main sections:

```toml
[relay]
name = "nostrd"                 # relay name (NIP-11)
description = "..."             # relay description (NIP-11)
private_key = ""                # hex secret key of the relay itself (required for
                                # NIP-29 group metadata and NIP-43 membership events;
                                # its pubkey is advertised as the NIP-11 "self")
public_url = ""                 # public URL as seen by clients (e.g. "wss://relay.example.com");
                                # set this behind a TLS-terminating proxy / Cloudflare Tunnel
enabled_nips = []               # explicit NIP allowlist (empty = all except disabled_nips)
disabled_nips = []              # NIPs to disable

[server]
host = "0.0.0.0"                # bind address; "127.0.0.1" = local only,
                                # "0.0.0.0" = all interfaces
port = 8080
management_token = ""           # bearer token for the NIP-86 management API
admin_pubkey = ""               # or authorize NIP-86 calls with a NIP-98 event

[limits]
max_connections = 10000
max_ws_message_size = 1048576
max_subscriptions = 20
max_limit = 500
count_limit = 2000              # NIP-45 COUNT cap (results beyond it are "approximate")
new_pubkey_min_age_secs = 0     # spam defense: reject events from accounts younger
                                # than this many seconds (0 = off)
db_queue_msgs = 4096            # overload protection: fail fast when the database
db_queue_events = 262144        # queue holds more than this much pending work
buffer_size = 2048              # initial WebSocket read/write buffer per connection
group_late_publish_secs = 604800  # NIP-29 late-publication window

[database]
path = "./data"
map_size = 1073741824           # initial LMDB memory map (virtual address space)
map_max_size = 1099511627776    # growth ceiling (sparse file: only written pages
                                # consume physical memory or disk)
search_index = true             # NIP-50 word index
purge_interval_secs = 300       # NIP-40 expired-event purge interval

[daemon]
pid_file = "./nostrd.pid"
log_file = "./nostrd.log"
stats_file = "./nostrd.stats.json"

[access]
blocked_pubkeys = []
allowed_pubkeys = []            # non-empty = allowlist
blocked_kinds = []
blocked_ips = []
```

## NIP support

All relay-side NIPs are implemented; client-side NIPs are stored and served as plain events but are deliberately **not** advertised in the NIP-11 document (per the spec). File-storage NIPs (34 git, 94 file metadata, 95/96 HTTP file storage) are excluded by design.

| NIP | Description |
| --- | --- |
| [01](https://github.com/nostr-protocol/nips/blob/master/01.md) | Basic protocol (EVENT/REQ/CLOSE, filters, replaceable/ephemeral/addressable events) |
| [09](https://github.com/nostr-protocol/nips/blob/master/09.md) | Event deletion |
| [11](https://github.com/nostr-protocol/nips/blob/master/11.md) | Relay information document |
| [13](https://github.com/nostr-protocol/nips/blob/master/13.md) | Proof of work |
| [26](https://github.com/nostr-protocol/nips/blob/master/26.md) | Delegated event signing |
| [29](https://github.com/nostr-protocol/nips/blob/master/29.md) | Relay-based groups (moderation events, relay-signed metadata, subgroups, invite codes, LiveKit rooms) |
| [33](https://github.com/nostr-protocol/nips/blob/master/33.md) | Parameterized replaceable events |
| [40](https://github.com/nostr-protocol/nips/blob/master/40.md) | Expiration timestamp |
| [42](https://github.com/nostr-protocol/nips/blob/master/42.md) | Client authentication (AUTH) |
| [43](https://github.com/nostr-protocol/nips/blob/master/43.md) | Relay access metadata and requests (roles, membership lists, join/leave) |
| [45](https://github.com/nostr-protocol/nips/blob/master/45.md) | Counting results (COUNT, with HyperLogLog registers) |
| [50](https://github.com/nostr-protocol/nips/blob/master/50.md) | Search capability (relevance-ordered) |
| [59](https://github.com/nostr-protocol/nips/blob/master/59.md) | Gift wrap (recipient-only serving, NIP-09/62 linked deletion) |
| [62](https://github.com/nostr-protocol/nips/blob/master/62.md) | Request to vanish |
| [67](https://github.com/nostr-protocol/nips/blob/master/67.md) | EOSE completeness hint (`finish`/`more`) |
| [70](https://github.com/nostr-protocol/nips/blob/master/70.md) | Protected events |
| [77](https://github.com/nostr-protocol/nips/blob/master/77.md) | Negentropy syncing (NEG-OPEN/MSG/CLOSE) |
| [86](https://github.com/nostr-protocol/nips/blob/master/86.md) | Relay management API (JSON-RPC) |
| [98](https://github.com/nostr-protocol/nips/blob/master/98.md) | HTTP auth (kind 27235) |

## Architecture notes

- **Single database thread for writes**, with puts merged into batches that share one write transaction (one fsync per batch). Replies are sent only after a successful commit, so an `OK` implies durability.
- **A dedicated reader thread** serves queries/counts/lookups without ever taking the write lock. If a commit is blocked (stalled disk, external lock holder), reads keep working.
- **Bounded queues everywhere** — the database request queue (fail-fast overload protection), the outgoing message queue (per-connection byte cap), the live fan-out channel and the negentropy item store are all capped.
- **Scan engine** — multi-range filters (`authors`, `kinds`, `#tag`) are walked with a merged newest-first iterator so a per-filter `limit` applies to the union of all ranges; NIP-67 boundary handling never splits a `created_at` tie across pages.
- **Panic containment** — the database thread, the reader thread and every connection task are isolated; a fault in any of them is logged and does not take the relay down.

## Performance

Measured on the release build (5 concurrent connections, fresh database, fsync per commit):

| Operation | Result |
| --- | --- |
| Event publish (signature verification + fsync commit) | ~1,100–1,400 events/s |
| Query (limit 100, tag filter) | 50 queries in ~1.4 s |
| Live notification delivery (publish → subscriber) | median ~6 ms, p95 ~12 ms |
| COUNT (NIP-45) | 50 counts in ~0.9 s |

Sustained-load stability test (10 connections × 30 s, ~20,000 published events):
zero database errors, zero panics, zero rejected events. The memory map is a
virtual address-space reservation: a freshly started relay uses only a few
tens of MB of physical memory regardless of `map_size`.

## Repository layout

```
src/
├── main.rs, cli.rs, config.rs   entry point, CLI, nostrd.toml
├── util.rs, error.rs, event.rs, filter.rs, stats.rs
├── db/                          LMDB storage
│   ├── mod.rs                   DbClient handle and request plumbing
│   ├── threads.rs               dedicated writer/reader threads
│   ├── store.rs                 write path and index maintenance
│   ├── removal.rs               deletions, bans, vanish, expiry purge
│   └── scan.rs                  query engine (filters, merged walks, collectors)
├── relay/                       event acceptance and NIP-29/43 state
│   ├── mod.rs                   accept paths, live fan-out
│   ├── validate.rs              pre-acceptance checks (shared by both paths)
│   └── roles.rs                 NIP-43 role administration
├── server/                      HTTP/WebSocket front end
│   ├── mod.rs                   router, CORS, background tasks
│   └── livekit.rs               NIP-29 LiveKit token endpoint
├── ws/                          connection handling
│   ├── mod.rs                   connection loop and live delivery
│   ├── handler.rs               protocol message handlers
│   └── negentropy.rs            NIP-77 NEG-OPEN/MSG/CLOSE
└── nips/                        per-NIP modules (some split further, e.g.
                                nip29/{mod,events,tests}, nip77/{mod,codec},
                                nip86/{mod,legacy})
```

## License

MIT
