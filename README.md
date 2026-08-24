# nostrd

[![CI](https://github.com/iqbqioza/nostrd/actions/workflows/ci.yml/badge.svg)](https://github.com/iqbqioza/nostrd/actions/workflows/ci.yml)
[![Release](https://github.com/iqbqioza/nostrd/actions/workflows/release.yml/badge.svg)](https://github.com/iqbqioza/nostrd/actions/workflows/release.yml)

> [!NOTE]
> This project is maintained by an individual who also operates the public relay at **wss://relay.damustr.com**. If nostrd has been useful to you, a small sponsorship or tip would be a wonderful encouragement and helps keep the project going. For larger sponsorships, please reach out through the contact details on the [@iqbqioza](https://github.com/iqbqioza) profile.

A minimal, stable and fast [Nostr](https://github.com/nostr-protocol/nostr) relay server written in Rust.

nostrd is designed around two goals:

- **Never go down.** Overload protection, a dedicated reader thread, panic containment and strict resource bounds keep the relay serving even under sustained abuse, a stalled disk or a memory-constrained host.
- **Spec-complete.** All relay-side NIPs are implemented and verified against the official specifications (file-storage NIPs excluded by design).

## Table of contents

- [Documentation](#documentation)
- [Features](#features)
- [Install (pre-built binary)](#install-pre-built-binary)
- [Deploying to Fly.io](#deploying-to-flyio)
- [Requirements](#requirements)
- [Build](#build)
- [Quick start](#quick-start)
- [REST API](#rest-api)
- [Commands](#commands)
- [Configuration](#configuration)
  - [Anti-abuse limits](#anti-abuse-limits)
- [NIP support](#nip-support)
- [Architecture notes](#architecture-notes)
- [Performance](#performance)
- [Repository layout](#repository-layout)
- [License](#license)

## Documentation

The detailed guides live in the [`docs/`](docs/) directory:

| Document | Contents |
| --- | --- |
| [Manual](docs/MANUAL.md) | Installation, configuration, operation, NIP support, NIP-29 groups, LiveKit, logs and statistics |
| [Configuration reference](docs/CONFIGURATION.md) | Every `nostrd.toml` option with its default and exact behavior, validation rules, SIGHUP reload, full example |
| [HTTP REST API reference](docs/API.md) | `/api/v1` endpoints, query parameters, pagination, errors, status codes |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Common errors and their step-by-step fixes |
| [Deploying to Fly.io](docs/DEPLOYMENT.md) | Deploy the pre-built release binary to Fly.io in four steps |

## Features

- **All relay-side NIPs implemented** — see the [NIP support](#nip-support) table.
- **REST API** — a read-only HTTP API at `/api/v1/...` for querying events by `npub1`, `nevent1` or `naddr1`, with its own dedicated database reader thread and concurrency limiter so REST traffic can never stall WebSocket subscribers.
- **LMDB persistence (via `heed`)** — durable, crash-safe storage; the memory map is a sparse virtual-address reservation opened at its configured ceiling, so it never needs a runtime resize (which would be unsafe with concurrent reader threads) and physical memory stays small.
- **Overload protection** — the database queue is bounded; when it fills up, new requests fail fast instead of accumulating in memory. Writes that reach the queue always wait for their true outcome, so a queued event can never silently commit after the relay reported a false failure (which would skip its side-effects).
- **Reader/writer thread split** — reads are served by dedicated threads that never take the LMDB write lock, so a stalled writer (slow disk, external lock holder) cannot take the relay down for readers. The REST API gets its own reader thread, isolated from WebSocket REQ/COUNT/NEG queries.
- **Per-IP connection cap** — a single host cannot consume the whole connection budget.
- **Optional WS idle timeout** — close connections that stay silent for a configured period (sending periodic PINGs so alive-but-idle subscribers keep their slot while dead peers are reaped), preventing a socket flood from exhausting the connection budget.
- **Panic-safe** — task panics are contained and logged, and connection accounting is released on every exit path.
- **Efficient hot paths** — single-pass event parsing, deduplicated live serialization, batched commits (one fsync per batch), merged multi-range scans with a per-scan work budget, and NIP-67 boundary handling.
- **Everything configurable** via `nostrd.toml` — no compile-time options.
- **Works behind TLS-terminating proxies** (nginx, Caddy, Cloudflare Tunnel): WebSocket upgrades are honored via `X-Forwarded-Proto`.

## Install (pre-built binary)

The GitHub Actions release workflow builds `nostrd` for **x86_64** and **aarch64** and attaches both binaries (plus checksums) to every release. The `install.sh` script downloads the right one, verifies its sha256 checksum and installs it into a directory on `PATH`.

The fastest way — **one-liner, no clone needed**:

```sh
curl -fsSL https://raw.githubusercontent.com/iqbqioza/nostrd/main/install.sh | sh
```

Or download and run it manually (useful to inspect the script first, or to pass options):

```sh
curl -fsSL -o install.sh https://raw.githubusercontent.com/iqbqioza/nostrd/main/install.sh
chmod +x install.sh
./install.sh                       # latest release, into ~/.local/bin (no sudo needed)

VERSION=v0.1.0-alpha-01 ./install.sh            # a specific release
INSTALL_DIR=/usr/local/bin sudo ./install.sh    # system-wide (requires sudo)
./install.sh --force                            # overwrite without asking
curl -fsSL https://raw.githubusercontent.com/iqbqioza/nostrd/main/install.sh | sh -s -- --force
```

The script picks the first of `~/.local/bin`, `~/bin` and `~/.cargo/bin` that is already on `PATH` (falling back to `~/.local/bin`, which it then tells you how to add to `PATH`). If `nostrd` already exists at the install location it asks for confirmation before overwriting. The install directory can be overridden with the `INSTALL_DIR` environment variable.

## Deploying to Fly.io

nostrd ships a ready-made [Fly.io](https://fly.io) template: the `Dockerfile` downloads the **pre-built release binary** from the GitHub release assets (no compilation on Fly), `fly.toml` wires up the HTTP service, health checks and a persistent volume, and `fly/nostrd.toml` is the baked-in configuration.

```sh
fly launch --no-deploy --name <app-name> --region <region>
fly volumes create data --size 1 --region <region>
fly deploy
```

Full guide: [Deploying to Fly.io](docs/DEPLOYMENT.md).

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

## REST API

nostrd exposes a **read-only HTTP API** on the same port under `/api/v1`, served by a dedicated database reader thread with its own concurrency limiter, so heavy REST traffic can never stall WebSocket subscribers.

| Endpoint | Description |
| --- | --- |
| `GET /api/v1/{npub1...}/{kind}` | Events by author pubkey and kind (the `{kind}` path is mandatory for `npub1`) |
| `GET /api/v1/{nevent1...}` / `GET /api/v1/{note1...}` | A single event by its NIP-19 id |
| `GET /api/v1/{naddr1...}` | Addressable/replaceable events by NIP-19 address |

Query parameters: `limit`, `offset`, `since`, `until`, `sort`, `search`, `e`, `p`, `t`, `d`. Responses are `{ "events": [...], "count": N, "more": bool }`; `offset` + `more` paginate over the *visible* sequence (NIP-70 protected, NIP-59 gift wraps and NIP-29 private/hidden group content are withheld).

By default the API is served on every host; set `server.api_host` (e.g. `api_host = "api.example.com"`) to serve it only on that hostname and hide `/api/v1` from every other host.

**Full reference — endpoints, parameters, pagination, errors, status codes: [HTTP REST API reference](docs/API.md).**

## Commands

| Command | Description |
| --- | --- |
| `nostrd init` | Write a default configuration file and exit |
| `nostrd genkey` | Generate a relay secret key (for NIP-29 group metadata and NIP-43 membership events) and write it into `relay.private_key` of the config file. Preserves the rest of the file; asks for confirmation (y/N) when a key is already set. Prints the relay pubkey (the NIP-11 `self`). |
| `nostrd start` | Start the relay as a daemon (`--foreground` to stay in the shell) |
| `nostrd stop` | Stop the running daemon |
| `nostrd restart` | Stop and start again (reloads `nostrd.toml`) |
| `nostrd stats` | Show live statistics of the running daemon |
| `nostrd check` | Validate `nostrd.toml` and exit |

All commands accept `--config <path>` (default `./nostrd.toml`).

Sending `SIGHUP` to the daemon reloads the configuration at runtime: most limits, server auth settings, the NIP toggles (including the NIP-40 toggle, applied live) and the REST API concurrency ceiling apply immediately. A few settings are captured at startup and require a full restart: `live_buffer`/`live_batch_size`/`live_batch_interval_ms`, `server.api_host`, `server.management_port`, `server.metrics_enabled`, `relay.private_key` (a reload warns that it is ignored), `relay.livekit_url`, `daemon.log_max_size_bytes`/`log_max_files`, the database request timeouts/queue caps, `purge_interval_secs`, `stats_interval_secs` and `max_indexed_words`. An invalid reloaded file is rejected (the old configuration stays in force). The access control lists are runtime-managed (NIP-86) and are **not** overwritten by a reload.

## Configuration

Every setting is optional — missing entries fall back to the defaults, and `nostrd.toml.example` documents every option with comments. The configuration has six sections:

| Section | Purpose |
| --- | --- |
| `[relay]` | Identity, URLs (incl. `public_url` for NIP-42/62/98), `private_key`, LiveKit, NIP toggles |
| `[server]` | Binding, `api_host` split, management API, authentication |
| `[limits]` | All limits and overload protections (connections, events, search, API bounds) |
| `[database]` | LMDB storage (paths, memory-map sizes, search index) |
| `[daemon]` | PID/log/stats files and log rotation |
| `[access]` | Initial access control lists (NIP-86 manages them at runtime) |

`nostrd check` (and startup) validate the file and warn about common misconfigurations — e.g. an empty `relay.public_url` with a wildcard/loopback bind (which would break NIP-42 AUTH, NIP-62 vanish and NIP-86 NIP-98 auth), a `require_pow` high enough to make mining infeasible, incomplete LiveKit settings, or the `require_auth` + `send_auth_challenge = false` lockout.

**Full reference — every key, its default and its exact behavior, validation rules, SIGHUP reload, full example: [Configuration reference](docs/CONFIGURATION.md).**

### Anti-abuse limits

In addition to the tunables above, a few hard bounds are fixed to keep the relay responsive under abuse:

- A single filter may carry at most **512 `ids` or `authors` entries**; larger filters are rejected (the per-candidate match is linear in these arrays, so unbounded arrays would allow quadratic work per REQ).
- Event ids in `ids` filters may be prefixes, but only full 32-byte ids and even-length prefixes are matched (odd-length/empty entries are ignored, consistently for historical and live delivery).
- Over-long index keys (a tag value, content word or `d` tag long enough to exceed LMDB's key-size limit) are skipped at indexing time rather than aborting the write batch; the event is still stored.

## NIP support

All relay-side NIPs are implemented; client-side NIPs are stored and served as plain events but are deliberately **not** advertised in the NIP-11 document (per the spec). File-storage NIPs (34 git, 94 file metadata, 95/96 HTTP file storage) are excluded by design.

| NIP | Description |
| --- | --- |
| [01](https://github.com/nostr-protocol/nips/blob/master/01.md) | Basic protocol (EVENT/REQ/CLOSE, filters, replaceable/ephemeral/addressable events) |
| [09](https://github.com/nostr-protocol/nips/blob/master/09.md) | Event deletion |
| [11](https://github.com/nostr-protocol/nips/blob/master/11.md) | Relay information document |
| [13](https://github.com/nostr-protocol/nips/blob/master/13.md) | Proof of work |
| [26](https://github.com/nostr-protocol/nips/blob/master/26.md) | Delegated event signing |
| [28](https://github.com/nostr-protocol/nips/blob/master/28.md) | Public chat (channel messages are served via the `#e` index) |
| [29](https://github.com/nostr-protocol/nips/blob/master/29.md) | Relay-based groups (moderation events, relay-signed metadata, subgroups, invite codes, LiveKit rooms) |
| [33](https://github.com/nostr-protocol/nips/blob/master/33.md) | Parameterized replaceable events |
| [40](https://github.com/nostr-protocol/nips/blob/master/40.md) | Expiration timestamp |
| [42](https://github.com/nostr-protocol/nips/blob/master/42.md) | Client authentication (AUTH) |
| [43](https://github.com/nostr-protocol/nips/blob/master/43.md) | Relay access metadata and requests (roles, membership lists, join/leave) |
| [45](https://github.com/nostr-protocol/nips/blob/master/45.md) | Counting results (COUNT, with HyperLogLog registers) |
| [50](https://github.com/nostr-protocol/nips/blob/master/50.md) | Search capability (whole-word terms, relevance-ordered by IDF weights) |
| [59](https://github.com/nostr-protocol/nips/blob/master/59.md) | Gift wrap (recipient-only serving, NIP-09/62 linked deletion) |
| [62](https://github.com/nostr-protocol/nips/blob/master/62.md) | Request to vanish |
| [67](https://github.com/nostr-protocol/nips/blob/master/67.md) | EOSE completeness hint (`finish`/`more`) |
| [70](https://github.com/nostr-protocol/nips/blob/master/70.md) | Protected events |
| [77](https://github.com/nostr-protocol/nips/blob/master/77.md) | Negentropy syncing (NEG-OPEN/MSG/CLOSE) |
| [86](https://github.com/nostr-protocol/nips/blob/master/86.md) | Relay management API (JSON-RPC) |
| [98](https://github.com/nostr-protocol/nips/blob/master/98.md) | HTTP auth (kind 27235) |

## Architecture notes

- **Single database thread for writes**, with puts merged into batches that share one write transaction (one fsync per batch). Replies are sent only after a successful commit, so an `OK` implies durability.
- **Dedicated reader threads** serve queries/counts/lookups without ever taking the write lock. If a commit is blocked (stalled disk, external lock holder), reads keep working. The REST API runs on its own reader thread with its own bounded queue, so an `/api/v1` flood can neither queue up behind nor delay WebSocket REQ/COUNT/NEG queries.
- **Bounded queues everywhere** — the database request queue (fail-fast overload protection), the outgoing message queue (per-connection byte cap), the live fan-out channel and the negentropy item store are all capped. The REST API has its own concurrency limiter (`api_max_concurrent`) that fails fast with `503` when saturated.
- **The LMDB map is opened at its configured ceiling** and never resized at runtime: resizing would require that no read transactions are active, which cannot be guaranteed with concurrent reader threads. The reservation is a sparse virtual-address mapping, so physical memory and disk grow only with the data actually written.
- **Scan engine** — multi-range filters (`authors`, `kinds`, `#tag`) are walked with a merged newest-first iterator so a per-filter `limit` applies to the union of all ranges; NIP-67 boundary handling never splits a `created_at` tie across pages. A per-scan work budget bounds the candidates examined so a filter matching nothing cannot walk an entire index range.
- **Panic containment** — the database thread, the reader threads and every connection task are isolated; a fault in any of them is logged and does not take the relay down.
- **Per-IP connection accounting** — the number of active WebSocket connections per source IP is tracked and capped, so a socket flood from one host cannot evict legitimate clients.

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
│   ├── threads.rs               dedicated writer/reader/API-reader threads
│   ├── store.rs                 write path and index maintenance
│   ├── removal.rs               deletions, bans, vanish, expiry purge
│   └── scan.rs                  query engine (filters, merged walks, collectors)
├── relay/                       event acceptance and NIP-29/43 state
│   ├── mod.rs                   accept paths, live fan-out
│   ├── validate.rs              pre-acceptance checks (shared by both paths)
│   └── roles.rs                 NIP-43 role administration
├── server/                      HTTP/WebSocket front end
│   ├── mod.rs                   router, CORS, background tasks
│   ├── api.rs                   read-only REST API (/api/v1)
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
