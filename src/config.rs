//! `nostrd.toml` configuration: relay identity, server binding,
//! limits, database, daemon paths and NIP toggles.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const DEFAULT_CONFIG: &str = "nostrd.toml";

/// NIPs with relay-side behaviour implemented by this relay, as advertised
/// in the NIP-11 document. NIPs whose behaviour is purely client-side are
/// deliberately not advertised (NIP-11: "Client-side NIPs SHOULD NOT be
/// advertised"): NIP-28 explicitly "imposes no additional requirements on
/// relays", so it is not listed. File-storage NIPs (34/94/95/96) are
/// excluded per the project rules (Blossom is provided separately by the
/// `[blossom]` file server). NIP-33 was merged into NIP-01 but remains
/// advertised for clients that check it.
pub const RELAY_NIPS: &[u16] = &[
    1, 9, 11, 13, 26, 29, 33, 40, 42, 43, 45, 50, 62, 67, 70, 77, 86, 98,
];

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub relay: RelayConfig,
    pub server: ServerConfig,
    pub limits: LimitsConfig,
    pub database: DatabaseConfig,
    pub daemon: DaemonConfig,
    /// Initial access control lists (NIP-86 bans/allowlists), seeded at
    /// startup so they survive restarts.
    pub access: AccessControl,
    /// Blossom file server (media hosting) settings.
    pub blossom: BlossomConfig,
}

/// Blossom (BUD-01/02) file server configuration.
///
/// The feature is active when `host` is non-empty: requests whose Host
/// header matches it are served only the Blossom routes (like
/// `server.api_host` for the REST API), so the media server and the relay
/// live on the same port behind one reverse proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BlossomConfig {
    /// Hostname dedicated to the Blossom server (e.g. `media.example.com`).
    /// Empty = the feature is disabled.
    pub host: String,
    /// Storage backend: `"local"` (files under `local_path`) or `"s3"`
    /// (any S3-compatible service, including Cloudflare R2).
    pub storage: String,
    /// Directory for local storage. Files are kept as
    /// `<local_path>/<npub1...>/<sha256>` (the `bucket/{npub1}/{file}`
    /// hierarchy on disk).
    pub local_path: PathBuf,
    /// Maximum accepted upload size in bytes (the HTTP body limit for
    /// `PUT /upload`).
    pub max_upload_bytes: usize,
    /// S3 endpoint (e.g. `https://<account>.r2.cloudflarestorage.com` for
    /// Cloudflare R2, `https://s3.amazonaws.com` for AWS).
    pub s3_endpoint: String,
    /// S3 region (Cloudflare R2 uses `"auto"`).
    pub s3_region: String,
    /// S3 bucket name — the `bucket` of the `bucket/{npub1}/{file}` layout.
    pub s3_bucket: String,
    pub s3_access_key: String,
    pub s3_secret_key: String,
    /// When true, only the pubkeys in the Blossom upload allowlist may
    /// upload blobs. The allowlist itself lives in the relay database
    /// (LMDB), managed with `nostrd blossom allow/deny`.
    pub restrict_uploads: bool,
}

impl Default for BlossomConfig {
    fn default() -> Self {
        BlossomConfig {
            host: String::new(),
            storage: "local".into(),
            local_path: PathBuf::from("./data/images"),
            max_upload_bytes: 20 * 1024 * 1024,
            s3_endpoint: String::new(),
            s3_region: String::new(),
            s3_bucket: String::new(),
            s3_access_key: String::new(),
            s3_secret_key: String::new(),
            restrict_uploads: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RelayConfig {
    pub name: String,
    pub description: String,
    pub pubkey: String,
    pub contact: String,
    pub icon: String,
    pub post_policy: String,
    /// Hex-encoded secret key of the relay itself. When set, the relay can
    /// sign and publish NIP-29 group metadata events.
    pub private_key: String,
    /// Public URL of this relay (e.g. "wss://relay.example.com"). Used for
    /// NIP-62 request-to-vanish matching; falls back to host:port when empty.
    pub public_url: String,
    /// Optional LiveKit server URL for NIP-29 live audio/video rooms.
    pub livekit_url: String,
    pub livekit_api_key: String,
    pub livekit_api_secret: String,
    /// Explicit allowlist of NIP numbers; empty means "all except disabled".
    pub enabled_nips: Vec<u16>,
    pub disabled_nips: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    /// Hostname (Host header) dedicated to the REST API. When set, requests
    /// whose Host header matches this value are served only the `/api/v1`
    /// routes, and requests for any other host never reach them: the API
    /// and the WebSocket relay are split by hostname on the same port
    /// (e.g. `api.example.com` vs `relay.example.com`). Empty = the API is
    /// served on every host, next to the WebSocket endpoint.
    pub api_host: String,
    /// Separate local management port for NIP-86; 0 disables it.
    pub management_port: u16,
    pub management_host: String,
    pub management_token: String,
    /// Admin pubkey for NIP-98 authenticated management calls.
    pub admin_pubkey: String,
    pub require_auth: bool,
    pub send_auth_challenge: bool,
    /// Expose Prometheus metrics on `GET /metrics` (text format). Served on
    /// the API host when one is configured; without `api_host` the metrics
    /// are public on every host.
    pub metrics_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LimitsConfig {
    pub max_connections: usize,
    /// Per-source-IP cap on WebSocket connections: a single host cannot
    /// consume the whole connection budget (a socket flood from one IP
    /// would otherwise evict legitimate clients). 0 = no per-IP cap.
    pub max_connections_per_ip: usize,
    pub max_ws_message_size: usize,
    pub max_filters: usize,
    pub max_subscriptions: usize,
    pub max_limit: usize,
    pub count_limit: usize,
    pub max_sub_id_len: usize,
    pub max_content_bytes: usize,
    pub max_tags: usize,
    pub max_tag_value_bytes: usize,
    /// Events whose created_at is more than this many seconds in the future
    /// are silently dropped (OK `mute:`) instead of rejected as invalid.
    pub max_created_at_future: u64,
    pub require_pow: u8,
    pub max_indexed_words: usize,
    pub buffer_size: usize,
    /// NIP-77: maximum number of records a single NEG-OPEN may process.
    pub neg_max_items: usize,
    /// Seconds a database request may wait before timing out (0 = wait
    /// forever). A timeout keeps the relay responsive even when the storage
    /// is stuck: the request fails with a clear error instead of hanging.
    pub db_request_timeout_secs: u64,
    /// Spam defense: a pubkey's first accepted event is recorded, and events
    /// from pubkeys first seen less than this many seconds ago are rejected
    /// with `restricted: your account is too new` (0 disables the check).
    pub new_pubkey_min_age_secs: u64,
    /// Maximum bytes of outgoing messages queued for a single connection
    /// before new ones are dropped (protects memory against slow readers).
    pub max_out_queue_bytes: usize,
    /// Seconds a connection may stay idle (no inbound frames) before it is
    /// closed. When non-zero the relay also sends periodic WebSocket PINGs so
    /// an alive-but-silent subscriber keeps its slot and dead peers are
    /// detected and reaped; 0 disables the idle timeout entirely.
    pub ws_idle_timeout_secs: u64,
    /// Overload protection: when the database thread's queue holds more than
    /// this many pending messages (or `db_queue_events` events), new
    /// database requests fail fast instead of accumulating in memory.
    pub db_queue_msgs: usize,
    pub db_queue_events: usize,
    /// Maximum total bytes of subscription filters held by a single
    /// connection.
    pub max_sub_bytes: usize,
    /// NIP-29: reject group events whose created_at is older than this many
    /// seconds (late publication prevention); 0 disables the check.
    pub group_late_publish_secs: u64,
    /// REST API: maximum number of concurrent `/api/v1` requests being
    /// served at once. Requests beyond this limit fail fast with `503`
    /// instead of queuing, so a flood of API traffic cannot stall the
    /// WebSocket subscribers (which share the same database).
    pub api_max_concurrent: usize,
    /// REST API: upper bound for the `limit` query parameter (0 = no bound).
    pub api_max_limit: usize,
    /// REST API: upper bound for the `offset` query parameter (0 = no bound).
    pub api_max_offset: usize,
    /// REST API: maximum length of the `search` query parameter in bytes
    /// (0 = no bound).
    pub api_max_search_bytes: usize,
    /// Live fan-out: events are accumulated and broadcast in batches of at
    /// most `live_batch_size` events every `live_batch_interval_ms`, so that
    /// idle connections wake up once per batch instead of once per event.
    pub live_batch_interval_ms: u64,
    pub live_batch_size: usize,
    /// Bounded queue for events waiting to be broadcast live; messages are
    /// dropped (never stored) when it overflows.
    pub live_buffer: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DatabaseConfig {
    pub path: PathBuf,
    pub max_dbs: u32,
    pub max_readers: u32,
    /// Memory map size in bytes. The map is opened at `map_max_size` (a
    /// sparse virtual-address reservation), so this value only acts as a
    /// floor: the actual map is never smaller than this or `map_max_size`.
    pub map_size: usize,
    /// Memory map ceiling in bytes. The map is opened at this size once and
    /// never resized at runtime: the reservation is virtual address space
    /// (sparse file), so physical memory and disk grow only with the data
    /// actually written.
    pub map_max_size: usize,
    pub purge_interval_secs: u64,
    /// Enable the NIP-50 full-text word index.
    pub search_index: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DaemonConfig {
    pub pid_file: PathBuf,
    pub log_file: PathBuf,
    pub stats_file: PathBuf,
    pub stats_interval_secs: u64,
    /// Rotate the log file when it grows past this many bytes (0 disables
    /// rotation). The old file is renamed to `.1` and older backups shift up
    /// to `log_max_files` backups.
    pub log_max_size_bytes: u64,
    /// Number of rotated log backups to keep (each is the previous generation
    /// of the log file).
    pub log_max_files: u32,
}

impl Default for RelayConfig {
    fn default() -> Self {
        RelayConfig {
            name: "nostrd".into(),
            description: "A minimal and stable Nostr relay".into(),
            pubkey: String::new(),
            contact: String::new(),
            icon: String::new(),
            post_policy: String::new(),
            private_key: String::new(),
            public_url: String::new(),
            livekit_url: String::new(),
            livekit_api_key: String::new(),
            livekit_api_secret: String::new(),
            enabled_nips: Vec::new(),
            disabled_nips: Vec::new(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            host: "127.0.0.1".into(),
            port: 8080,
            api_host: String::new(),
            management_port: 0,
            management_host: "127.0.0.1".into(),
            management_token: String::new(),
            admin_pubkey: String::new(),
            require_auth: false,
            send_auth_challenge: true,
            metrics_enabled: true,
        }
    }
}

impl Default for LimitsConfig {
    fn default() -> Self {
        LimitsConfig {
            max_connections: 10_000,
            max_connections_per_ip: 0,
            max_ws_message_size: 1 << 20,
            max_filters: 20,
            max_subscriptions: 20,
            max_limit: 500,
            count_limit: 2_000,
            max_sub_id_len: 64,
            max_content_bytes: 64 * 1024,
            max_tags: 2_000,
            max_tag_value_bytes: 1_024,
            max_created_at_future: 60 * 60,
            require_pow: 0,
            max_indexed_words: 128,
            buffer_size: 2_048,
            neg_max_items: 100_000,
            db_request_timeout_secs: 30,
            new_pubkey_min_age_secs: 0,
            max_out_queue_bytes: 256 * 1024,
            ws_idle_timeout_secs: 0,
            db_queue_msgs: 4_096,
            db_queue_events: 262_144,
            max_sub_bytes: 512 * 1024,
            live_batch_interval_ms: 10,
            live_batch_size: 64,
            live_buffer: 65_536,
            group_late_publish_secs: 7 * 24 * 60 * 60,
            api_max_concurrent: 32,
            api_max_limit: 500,
            api_max_offset: 10_000,
            api_max_search_bytes: 1_024,
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        DatabaseConfig {
            path: PathBuf::from("./data"),
            max_dbs: 32,
            max_readers: 128,
            map_size: 1024 * 1024 * 1024,
            // 1 TiB of virtual address space; the actual disk usage grows
            // only with the stored data (sparse file).
            map_max_size: 1024 * 1024 * 1024 * 1024,
            purge_interval_secs: 300,
            search_index: true,
        }
    }
}

impl Default for DaemonConfig {
    fn default() -> Self {
        DaemonConfig {
            pid_file: PathBuf::from("./nostrd.pid"),
            log_file: PathBuf::from("./nostrd.log"),
            stats_file: PathBuf::from("./nostrd.stats.json"),
            stats_interval_secs: 5,
            log_max_size_bytes: 50 * 1024 * 1024,
            log_max_files: 5,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("cannot read {}: {e}", path.display())))?;
        let cfg: Config = toml::from_str(&raw)
            .map_err(|e| Error::Config(format!("invalid {}: {e}", path.display())))?;
        warn_unknown_fields(&raw);
        Ok(cfg)
    }

    pub fn write_default(path: &Path) -> Result<()> {
        if path.exists() {
            return Err(Error::Config(format!(
                "{} already exists, refusing to overwrite",
                path.display()
            )));
        }
        let cfg = Config::default();
        let toml = toml::to_string_pretty(&cfg)
            .map_err(|e| Error::Config(format!("cannot serialize config: {e}")))?;
        std::fs::write(path, toml)?;
        Ok(())
    }

    /// Resolves every relative path against the config file directory so that
    /// paths stay valid after the daemon changes its working directory.
    pub fn absolutize_paths(&mut self, config_path: &Path) {
        let base = match config_path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => {
                std::fs::canonicalize(parent).unwrap_or_else(|_| PathBuf::from(parent))
            }
            _ => std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        };
        let abs = |p: PathBuf| -> PathBuf { if p.is_absolute() { p } else { base.join(p) } };
        self.database.path = abs(self.database.path.clone());
        self.daemon.pid_file = abs(self.daemon.pid_file.clone());
        self.daemon.log_file = abs(self.daemon.log_file.clone());
        self.daemon.stats_file = abs(self.daemon.stats_file.clone());
    }

    /// The set of NIPs this relay claims to support (NIP-11).
    ///
    /// Only NIPs with actual relay-side behaviour are advertised: the NIP-11
    /// spec says client-side NIPs SHOULD NOT be advertised, and advertising
    /// them misleads clients (e.g. into relying on NIP-02 or NIP-05 features
    /// this relay does not provide).
    pub fn supported_nips(&self) -> Vec<u16> {
        if !self.relay.enabled_nips.is_empty() {
            return self
                .relay
                .enabled_nips
                .iter()
                .copied()
                .filter(|num| RELAY_NIPS.contains(num))
                .collect();
        }
        RELAY_NIPS
            .iter()
            .copied()
            .filter(|num| !self.relay.disabled_nips.contains(num))
            .collect()
    }

    /// The relay's own URL identity (host:port plus the optional public
    /// URL), used by the NIP-42/62/98 tag validations.
    pub fn relay_identity(&self) -> crate::nips::nip62::RelayIdentity<'_> {
        crate::nips::nip62::RelayIdentity::new(
            &self.server.host,
            self.server.port,
            &self.relay.public_url,
        )
    }

    pub fn nip_enabled(&self, num: u16) -> bool {
        if !self.relay.enabled_nips.is_empty() {
            return self.relay.enabled_nips.contains(&num);
        }
        !self.relay.disabled_nips.contains(&num)
    }

    /// Validates the configuration values. Returns a clear error message for
    /// the first problem found, so `nostrd check` and startup fail fast
    /// instead of misbehaving at runtime with a typo'd key or an impossible
    /// database layout.
    pub fn validate(&self) -> Result<()> {
        // Hex key format checks.
        let hex32 = |value: &str, what: &str| -> Result<()> {
            if value.is_empty() {
                return Ok(());
            }
            match hex::decode(value) {
                Ok(b) if b.len() == 32 => Ok(()),
                _ => Err(Error::Config(format!(
                    "{what} must be 64 hex characters (32 bytes), got {value:?}"
                ))),
            }
        };
        hex32(&self.relay.pubkey, "relay.pubkey")?;
        hex32(&self.server.admin_pubkey, "server.admin_pubkey")?;

        // Secret key: must be a valid secp256k1 secret key when set.
        if !self.relay.private_key.is_empty() {
            let bytes = hex::decode(&self.relay.private_key)
                .map_err(|_| Error::Config("relay.private_key must be 64 hex characters".into()))?;
            if bytes.len() != 32 {
                return Err(Error::Config("relay.private_key must be 32 bytes".into()));
            }
            secp256k1::SecretKey::from_slice(&bytes).map_err(|_| {
                Error::Config("relay.private_key is not a valid secp256k1 secret key".into())
            })?;
        }

        // Ports.
        if self.server.port == 0 {
            return Err(Error::Config(
                "server.port must be between 1 and 65535".into(),
            ));
        }
        if self.server.management_port > 0 && self.server.management_port == self.server.port {
            return Err(Error::Config(
                "server.management_port must differ from server.port".into(),
            ));
        }

        // Blocked IPs must parse as IP addresses.
        for (ip, _) in &self.access.blocked_ips {
            ip.parse::<std::net::IpAddr>().map_err(|_| {
                Error::Config(format!(
                    "access.blocked_ips contains an invalid IP address: {ip:?}"
                ))
            })?;
        }

        // Database layout.
        if self.database.map_size > self.database.map_max_size {
            return Err(Error::Config(
                "database.map_size must not exceed database.map_max_size".into(),
            ));
        }

        // NIP toggles: `enabled_nips` wins silently; surface the ambiguity.
        if !self.relay.enabled_nips.is_empty() && !self.relay.disabled_nips.is_empty() {
            log::warn!(
                "relay.enabled_nips and relay.disabled_nips are both set; enabled_nips wins"
            );
        }

        // Limits must be usable (zero would disable core functionality or
        // make the queue fail fast on the first request).
        let l = &self.limits;
        let nonzero = [
            ("limits.max_connections", l.max_connections),
            ("limits.max_ws_message_size", l.max_ws_message_size),
            ("limits.max_filters", l.max_filters),
            ("limits.max_subscriptions", l.max_subscriptions),
            ("limits.max_limit", l.max_limit),
            ("limits.count_limit", l.count_limit),
            ("limits.neg_max_items", l.neg_max_items),
            ("limits.buffer_size", l.buffer_size),
            ("limits.max_sub_bytes", l.max_sub_bytes),
            ("limits.db_queue_msgs", l.db_queue_msgs),
            ("limits.db_queue_events", l.db_queue_events),
            ("limits.api_max_concurrent", l.api_max_concurrent),
            ("limits.live_buffer", l.live_buffer),
            ("limits.max_out_queue_bytes", l.max_out_queue_bytes),
            ("limits.max_indexed_words", l.max_indexed_words),
        ];
        for (name, value) in nonzero {
            if value == 0 {
                return Err(Error::Config(format!("{name} must be at least 1 (got 0)")));
            }
        }

        // NIP-42 AUTH relay-tag, NIP-62 vanish and NIP-86 NIP-98 admin auth
        // all compare client URLs against `relay_identity()`. With an empty
        // `public_url` that identity is `server.host:server.port`; a
        // wildcard or loopback bind (0.0.0.0, ::, 127.0.0.1) never matches a
        // client's real hostname, silently breaking all three. Warn loudly.
        if self.relay.public_url.trim().is_empty() {
            let host = self.server.host.trim();
            if matches!(host, "0.0.0.0" | "::" | "127.0.0.1" | "::1" | "localhost") {
                log::warn!(
                    "relay.public_url is empty and server.host is {host:?}: NIP-42 AUTH, \
                     NIP-62 vanish and NIP-86 NIP-98 auth will not match client URLs; \
                     set relay.public_url to the public wss:// address"
                );
            }
        } else if !self.relay.public_url.contains("://") {
            log::warn!(
                "relay.public_url {0:?} has no scheme (wss:///ws://); set it to the public \
                 wss:// address or NIP-42/62/98 URL matching may fail",
                self.relay.public_url
            );
        }

        // Paths must be non-empty: an empty database path would silently open
        // the LMDB environment inside the config file's directory.
        if self.database.path.as_os_str().is_empty() {
            return Err(Error::Config("database.path must not be empty".into()));
        }
        if self.daemon.pid_file.as_os_str().is_empty()
            || self.daemon.log_file.as_os_str().is_empty()
            || self.daemon.stats_file.as_os_str().is_empty()
        {
            return Err(Error::Config(
                "daemon.pid_file, daemon.log_file and daemon.stats_file must not be empty".into(),
            ));
        }

        // LiveKit configuration must be complete when enabled.
        if !self.relay.livekit_url.trim().is_empty()
            && (self.relay.livekit_api_key.trim().is_empty()
                || self.relay.livekit_api_secret.trim().is_empty())
        {
            log::warn!(
                "relay.livekit_url is set but livekit_api_key/livekit_api_secret are empty: \
                 tokens will be signed with an empty secret and rejected by LiveKit"
            );
        }

        // A very high PoW requirement makes every event infeasible to mine;
        // warn instead of silently disabling writes.
        if l.require_pow >= 64 {
            log::warn!(
                "limits.require_pow = {} is practically unmineable; new events will be \
                 rejected with 'pow: difficulty requirement not reached'",
                l.require_pow
            );
        }

        // `require_auth` with `send_auth_challenge = false` is a total
        // lockout: the challenge is only ever sent on connect, so nobody can
        // authenticate and every REQ/EVENT/COUNT is refused.
        if self.server.require_auth && !self.server.send_auth_challenge {
            log::warn!(
                "server.require_auth is true but server.send_auth_challenge is false: the \
                 AUTH challenge is never sent, so no client can authenticate and all \
                 REQ/EVENT/COUNT messages will be refused"
            );
        }

        // NIP-29: the group metadata/members/admins snapshots (39000-39005)
        // are relay-signed and are only generated when the relay has a key.
        // Without one, clients get no 39001/39002 at group creation.
        if self.nip_enabled(29) && self.relay.private_key.trim().is_empty() {
            log::warn!(
                "relay.private_key is empty while NIP-29 is enabled: the relay cannot sign \
                 group metadata (39000-39005), so 39001 (admins) / 39002 (members) snapshots \
                 are not generated at group creation; run 'nostrd genkey' to set a key"
            );
        }

        // Blossom file server: the storage backend must be known, and S3
        // storage needs its credentials. The feature is opt-in via `host`.
        let b = &self.blossom;
        if !b.host.trim().is_empty() {
            if b.max_upload_bytes == 0 {
                return Err(Error::Config(
                    "blossom.max_upload_bytes must be at least 1".into(),
                ));
            }
            match b.storage.as_str() {
                "local" => {
                    if b.local_path.as_os_str().is_empty() {
                        return Err(Error::Config("blossom.local_path must not be empty".into()));
                    }
                }
                "s3" => {
                    if b.s3_endpoint.trim().is_empty()
                        || b.s3_bucket.trim().is_empty()
                        || b.s3_access_key.trim().is_empty()
                        || b.s3_secret_key.trim().is_empty()
                    {
                        return Err(Error::Config(
                            "blossom.storage = \"s3\" requires s3_endpoint, s3_bucket, \
                             s3_access_key and s3_secret_key"
                                .into(),
                        ));
                    }
                }
                other => {
                    return Err(Error::Config(format!(
                        "blossom.storage must be \"local\" or \"s3\", got {other:?}"
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Whether a string is a 64-hex pubkey or a parseable `npub1...`.
/// Shared with the CLI (`nostrd blossom allow/deny`).
pub(crate) fn is_pubkey_or_npub(value: &str) -> bool {
    if value.len() == 64 && hex::decode(value).map(|b| b.len() == 32).unwrap_or(false) {
        return true;
    }
    if value.starts_with("npub1")
        && crate::nips::nip19::parse_nip19(value)
            .is_ok_and(|e| matches!(e, crate::nips::nip19::Nip19Entity::Pubkey(_)))
    {
        return true;
    }
    false
}

// The pubkey allow/deny lists are runtime state managed via
// `nostrd relay allow/deny` and NIP-86, persisted in the relay database
// (LMDB) — not in the config file (see `restrict_relay`). The fields stay
// in this struct for the in-memory checks but are excluded from both the
// TOML `[access]` section and the persisted JSON.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AccessControl {
    /// (pubkey, reason) pairs; the reason is reported by NIP-86
    /// `listbannedpubkeys`. Persisted in LMDB under `relay_pubkeys`.
    #[serde(skip)]
    pub blocked_pubkeys: Vec<(String, String)>,
    #[serde(skip)]
    pub allowed_pubkeys: Vec<(String, String)>,
    pub blocked_kinds: Vec<u64>,
    pub allowed_kinds: Vec<u64>,
    /// (ip, reason) pairs, reported by NIP-86 `listblockedips`.
    #[serde(deserialize_with = "de_access_entries")]
    pub blocked_ips: Vec<(String, String)>,
    /// When true, only the pubkeys on the allow list (`nostrd relay allow`)
    /// may publish. When false (default), everyone except the denied
    /// pubkeys may publish.
    pub restrict_relay: bool,
}

/// Deserializes an access list that accepts both the current format —
/// `[["pubkey", "reason"], ...]` — and the legacy format — `["pubkey", ...]`
/// (plain strings). The persisted JSON and the TOML `[access]` section both
/// go through this, so upgrading never fails to read the old data: the
/// legacy entries simply get an empty reason.
fn de_access_entries<'de, D>(de: D) -> std::result::Result<Vec<(String, String)>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let items: Vec<serde_json::Value> = serde::Deserialize::deserialize(de)?;
    items
        .into_iter()
        .map(|v| match v {
            serde_json::Value::String(s) => Ok((s, String::new())),
            serde_json::Value::Array(a) if a.len() >= 2 && a[0].is_string() && a[1].is_string() => {
                Ok((
                    a[0].as_str().unwrap().to_string(),
                    a[1].as_str().unwrap().to_string(),
                ))
            }
            other => Err(serde::de::Error::custom(format!(
                "invalid access list entry: {other}"
            ))),
        })
        .collect()
}

impl AccessControl {
    pub fn allows_pubkey(&self, pubkey: &str) -> bool {
        // A denied pubkey is always rejected — even when restrict_relay
        // is off (the default: everyone else may publish).
        if self.blocked_pubkeys.iter().any(|(p, _)| p == pubkey) {
            return false;
        }
        !self.restrict_relay || self.allowed_pubkeys.iter().any(|(p, _)| p == pubkey)
    }

    pub fn allows_kind(&self, kind: u64) -> bool {
        if self.blocked_kinds.contains(&kind) {
            return false;
        }
        self.allowed_kinds.is_empty() || self.allowed_kinds.contains(&kind)
    }
}

/// Escapes a string for a TOML basic string literal. The TOML spec requires
/// every control character (U+0000-U+0008, U+000A-U+001F, U+007F) to be
/// escaped; leaving one raw would make the written config file unparseable.
pub(crate) fn toml_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 8);
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Replaces (or inserts) a `field = "value"` line inside the `[relay]`
/// section of a config file's text, preserving every other line, comment
/// and section. Handles three cases: a matching line already present in the
/// `[relay]` section (replaced), no such line in `[relay]` (inserted right
/// after the header), and no `[relay]` section at all (appended).
/// Used by `nostrd genkey` (private_key) and the NIP-86 relay-name changes.
pub(crate) fn set_relay_field_in_text(text: &str, field: &str, value: &str) -> String {
    let line = format!("{field} = \"{}\"", toml_escape(value));

    // Locate a real `[relay]` section header: a line whose trimmed text
    // starts with `[relay]` followed by `]`. A `[relay]` inside a comment or
    // a string value is not a section header and must not match.
    let mut header_start = None;
    let mut offset = 0;
    for l in text.split_inclusive('\n') {
        let t = l.trim();
        // `[relay]` header line: exactly `[relay]`, or `[relay]` followed by
        // whitespace or a comment. A `[relay]` inside a comment or a string
        // value does not start with `[relay]` as a header.
        if t == "[relay]"
            || t.starts_with("[relay] ")
            || t.starts_with("[relay]\t")
            || t.starts_with("[relay]#")
        {
            header_start = Some(offset);
            break;
        }
        offset += l.len();
    }
    let Some(header_start) = header_start else {
        // No [relay] section: append one at the end.
        let mut s = text.to_string();
        if !s.ends_with('\n') {
            s.push('\n');
        }
        s.push_str(&format!("[relay]\n{line}\n"));
        return s;
    };

    // The header line ends at the first newline after its start (or EOF when
    // it is the last line without a trailing newline).
    let header_end = text[header_start..]
        .find('\n')
        .map(|i| header_start + i + 1)
        .unwrap_or(text.len());

    // Bound the section at the next `[section]` header line.
    let mut section_end = text.len();
    let mut cursor = header_end;
    for l in text[header_end..].split_inclusive('\n') {
        let t = l.trim();
        if t.starts_with('[') && t.ends_with(']') {
            section_end = cursor;
            break;
        }
        cursor += l.len();
    }
    let section = &text[header_end..section_end];

    // Case 1: a matching line already exists in the section — replace it.
    if let Some(offset) = section
        .lines()
        .position(|l| l.trim_start().starts_with(field))
    {
        let mut new_section = String::new();
        for (i, l) in section.lines().enumerate() {
            if i == offset {
                let indent: String = l.chars().take_while(|c| c.is_whitespace()).collect();
                new_section.push_str(&format!("{indent}{line}\n"));
            } else {
                new_section.push_str(l);
                new_section.push('\n');
            }
        }
        let mut s = text.to_string();
        s.replace_range(header_end..section_end, &new_section);
        return s;
    }

    // Case 2: no matching line — insert it right after the `[relay]`
    // header line, keeping the header on its own line even when the header
    // is the last line of the file without a trailing newline.
    let mut s = text.to_string();
    if header_end >= s.len() {
        // Header is the last line without a trailing newline.
        s.push('\n');
        s.push_str(&line);
        s.push('\n');
    } else {
        s.insert_str(header_end, &format!("{line}\n"));
    }
    s
}

/// Writes `text` to `path` atomically (temp file + rename) so a crash in
/// the middle of a write never leaves a truncated config file behind.
pub(crate) fn write_text_atomic(path: &Path, text: &str) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Warns about config keys the schema does not know (a typo like
/// `server.potr = 9000` would otherwise be silently ignored and the relay
/// start with the default value). Implemented as a warning rather than a
/// hard error because older config files legitimately carry keys the schema
/// dropped (e.g. `software`/`version`).
fn warn_unknown_fields(raw: &str) {
    let Ok(value) = raw.parse::<toml::Value>() else {
        return;
    };
    let known: &[(&str, &[&str])] = &[
        // `software`/`version` were part of the older config template and
        // are recognized (and ignored) so operators upgrading from it are
        // not warned about them on every start.
        (
            "relay",
            &[
                "name",
                "description",
                "pubkey",
                "contact",
                "icon",
                "post_policy",
                "private_key",
                "public_url",
                "livekit_url",
                "livekit_api_key",
                "livekit_api_secret",
                "enabled_nips",
                "disabled_nips",
                "software",
                "version",
            ],
        ),
        (
            "server",
            &[
                "host",
                "port",
                "api_host",
                "management_port",
                "management_host",
                "management_token",
                "admin_pubkey",
                "require_auth",
                "send_auth_challenge",
                "metrics_enabled",
            ],
        ),
        (
            "limits",
            &[
                "max_connections",
                "max_connections_per_ip",
                "max_ws_message_size",
                "max_filters",
                "max_subscriptions",
                "max_limit",
                "count_limit",
                "max_sub_id_len",
                "max_content_bytes",
                "max_tags",
                "max_tag_value_bytes",
                "max_created_at_future",
                "require_pow",
                "max_indexed_words",
                "buffer_size",
                "neg_max_items",
                "db_request_timeout_secs",
                "new_pubkey_min_age_secs",
                "max_out_queue_bytes",
                "ws_idle_timeout_secs",
                "db_queue_msgs",
                "db_queue_events",
                "max_sub_bytes",
                "group_late_publish_secs",
                "api_max_concurrent",
                "api_max_limit",
                "api_max_offset",
                "api_max_search_bytes",
                "live_batch_interval_ms",
                "live_batch_size",
                "live_buffer",
            ],
        ),
        (
            "database",
            &[
                "path",
                "max_dbs",
                "max_readers",
                "map_size",
                "map_max_size",
                "purge_interval_secs",
                "search_index",
            ],
        ),
        (
            "daemon",
            &[
                "pid_file",
                "log_file",
                "stats_file",
                "stats_interval_secs",
                "log_max_size_bytes",
                "log_max_files",
            ],
        ),
        (
            "access",
            &[
                "blocked_kinds",
                "allowed_kinds",
                "blocked_ips",
                "restrict_relay",
            ],
        ),
        (
            "blossom",
            &[
                "host",
                "storage",
                "local_path",
                "max_upload_bytes",
                "s3_endpoint",
                "s3_region",
                "s3_bucket",
                "s3_access_key",
                "s3_secret_key",
                "restrict_uploads",
            ],
        ),
    ];
    let Some(table) = value.as_table() else {
        return;
    };
    // Unknown top-level sections (e.g. a typo'd `[serve]` instead of
    // `[server]`) are silently ignored by serde; warn so the operator
    // notices the section never took effect.
    for (section, table) in table {
        let Some(keys) = known.iter().find(|(s, _)| s == section).map(|(_, k)| *k) else {
            log::warn!(
                "unknown config section [{section}] is ignored; check the spelling \
                 (the relay runs with the defaults for this section)"
            );
            continue;
        };
        let Some(table) = table.as_table() else {
            continue;
        };
        for (key, _) in table {
            if !keys.contains(&key.as_str()) {
                log::warn!(
                    "unknown config key [{section}].{key} is ignored; check the spelling \
                     (the relay runs with the default for this field)"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blossom_allowlist_pubkey_validation() {
        assert!(is_pubkey_or_npub(&"a".repeat(64)));
        assert!(is_pubkey_or_npub(
            "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6"
        ));
        assert!(!is_pubkey_or_npub("not-a-pubkey"));
        assert!(!is_pubkey_or_npub(&"a".repeat(63)));
    }

    #[test]
    fn default_config_roundtrip() {
        let dir = std::env::temp_dir().join("nostrd-config-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nostrd.toml");
        Config::write_default(&path).unwrap();
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.server.port, 8080);
        assert!(cfg.supported_nips().contains(&1));
        assert!(cfg.supported_nips().contains(&11));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_relay_nips_are_advertised() {
        let cfg = Config::default();
        let nips = cfg.supported_nips();
        // Relay-side NIPs are advertised.
        for n in [
            1, 9, 11, 13, 26, 29, 33, 40, 42, 43, 45, 50, 62, 67, 70, 77, 86, 98,
        ] {
            assert!(nips.contains(&n), "NIP-{n} must be advertised");
        }
        // Client-side NIPs must not be advertised (NIP-11). NIP-28
        // explicitly "imposes no additional requirements on relays".
        for n in [2, 3, 5, 17, 19, 28, 32, 51, 65, 68, 99] {
            assert!(
                !nips.contains(&n),
                "client-side NIP-{n} must not be advertised"
            );
        }
        // An explicit allowlist still only advertises relay-side NIPs.
        let mut cfg = Config::default();
        cfg.relay.enabled_nips = vec![1, 2, 50];
        assert_eq!(cfg.supported_nips(), vec![1, 50]);
    }

    #[test]
    fn disabled_nips_are_removed() {
        let mut cfg = Config::default();
        cfg.relay.disabled_nips = vec![11, 50];
        assert!(!cfg.supported_nips().contains(&11));
        assert!(!cfg.nip_enabled(50));
        assert!(cfg.nip_enabled(1));
    }

    #[test]
    fn access_control() {
        let mut ac = AccessControl::default();
        ac.blocked_pubkeys.push(("bad".into(), String::new()));
        assert!(!ac.allows_pubkey("bad"));
        assert!(ac.allows_pubkey("good"));
        ac.blocked_kinds.push(5);
        assert!(!ac.allows_kind(5));
        assert!(ac.allows_kind(1));
    }

    #[test]
    fn access_entries_accept_legacy_and_pairs() {
        // The persisted JSON and the TOML [access] section may carry the
        // legacy plain-string form; reading it must not fail (the entries
        // get an empty reason).
        let legacy = AccessControl {
            blocked_pubkeys: vec![("aa".repeat(32), String::new())],
            allowed_pubkeys: Vec::new(),
            blocked_kinds: vec![],
            allowed_kinds: vec![],
            blocked_ips: vec![("203.0.113.9".into(), String::new())],
            restrict_relay: false,
        };
        let json = serde_json::to_string(&legacy).unwrap();
        // Simulate the pre-reason persisted document.
        let old_json = r#"{"blocked_pubkeys":["REPL"],"allowed_pubkeys":[],"blocked_kinds":[],"allowed_kinds":[],"blocked_ips":["203.0.113.9"]}"#;
        let old_json = old_json.replace("REPL", &"aa".repeat(32));
        let parsed: AccessControl = serde_json::from_str(&old_json).expect("legacy JSON reads");
        // The pubkey lists are skipped from the config/blob and now live in
        // the database under their own key (migrated at startup); reading
        // the legacy document must still succeed, dropping the entries.
        assert!(
            parsed.blocked_pubkeys.is_empty(),
            "pubkey lists are not config state"
        );
        assert!(parsed.allowed_pubkeys.is_empty());
        assert_eq!(parsed.blocked_ips[0].0, "203.0.113.9");
        // The current format round-trips with its reasons.
        let with_reason = AccessControl {
            blocked_pubkeys: vec![("bb".repeat(32), "spam".to_string())],
            ..Default::default()
        };
        let raw = serde_json::to_string(&with_reason).unwrap();
        let parsed: AccessControl = serde_json::from_str(&raw).unwrap();
        // Serialization skips the pubkey lists: they live in LMDB.
        assert!(parsed.blocked_pubkeys.is_empty());
        assert!(parsed.allowed_pubkeys.is_empty());
        let _ = json;
    }

    #[test]
    fn allows_pubkey_respects_restrict_relay_and_deny() {
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        let mut access = AccessControl::default();
        // Default (restrict_relay = false): everyone may publish.
        assert!(access.allows_pubkey(&a));
        assert!(access.allows_pubkey(&b));
        // A denied pubkey is rejected even without restrict_relay.
        access.blocked_pubkeys.push((b.clone(), String::new()));
        assert!(access.allows_pubkey(&a));
        assert!(!access.allows_pubkey(&b));
        // restrict_relay = true: only the allow list may publish.
        access.restrict_relay = true;
        assert!(
            !access.allows_pubkey(&a),
            "empty allow list locks everyone out"
        );
        access.allowed_pubkeys.push((a.clone(), String::new()));
        assert!(access.allows_pubkey(&a));
        assert!(!access.allows_pubkey(&b), "denied wins even when allowed");
    }

    #[test]
    fn validation_accepts_defaults() {
        assert!(Config::default().validate().is_ok());
    }

    #[test]
    fn validation_rejects_bad_keys() {
        let mut cfg = Config::default();
        cfg.relay.pubkey = "zz".repeat(32);
        assert!(cfg.validate().is_err(), "pubkey must be hex");
        cfg.relay.pubkey = "aa".repeat(31); // 62 chars
        assert!(cfg.validate().is_err(), "pubkey must be 32 bytes");
        cfg.relay.private_key = "gg".repeat(32);
        assert!(cfg.validate().is_err(), "secret key must be valid hex");
        cfg.relay.private_key = "00".repeat(32); // 0 is not on the curve
        assert!(
            cfg.validate().is_err(),
            "secret key must be on the secp256k1 curve"
        );
    }

    #[test]
    fn validation_rejects_port_collision_and_map_layout() {
        let mut cfg = Config::default();
        cfg.server.port = 8080;
        cfg.server.management_port = 8080;
        assert!(
            cfg.validate().is_err(),
            "management_port must differ from port"
        );
        cfg.server.management_port = 0;

        cfg.database.map_size = 1024 * 1024;
        cfg.database.map_max_size = 512 * 1024;
        assert!(
            cfg.validate().is_err(),
            "map_size must not exceed map_max_size"
        );
    }

    #[test]
    fn validation_rejects_bad_access_entries() {
        let mut cfg = Config::default();
        cfg.access.blocked_ips = vec![("not-an-ip".into(), String::new())];
        assert!(cfg.validate().is_err(), "blocked IPs must parse");
    }

    #[test]
    fn validation_rejects_zero_limits() {
        let mut cfg = Config::default();
        cfg.limits.max_connections = 0;
        assert!(
            cfg.validate().is_err(),
            "max_connections must be at least 1"
        );
    }

    #[test]
    fn toml_escape_handles_all_control_chars() {
        // U+007F (DEL) and other control characters must be escaped: the
        // toml crate rejects them raw in basic strings.
        for ch in ['\u{0}', '\u{7f}', '\u{1f}'] {
            let escaped = toml_escape(&format!("a{ch}b"));
            assert!(
                !escaped.contains(ch),
                "control character must be escaped, got {escaped:?}"
            );
            assert!(
                toml::from_str::<toml::Value>(&format!("x = \"{escaped}\"")).is_ok(),
                "escaped output must parse as TOML"
            );
        }
        assert_eq!(toml_escape("quote\\backslash"), "quote\\\\backslash");
    }
}
