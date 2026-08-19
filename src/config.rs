//! `nostrd.toml` configuration: relay identity, server binding,
//! limits, database, daemon paths and NIP toggles.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const DEFAULT_CONFIG: &str = "nostrd.toml";

/// NIPs with relay-side behaviour implemented by this relay, as advertised
/// in the NIP-11 document. NIPs whose behaviour is purely client-side are
/// deliberately not advertised (NIP-11: "Client-side NIPs SHOULD NOT be
/// advertised"), and file-storage NIPs (34/94/95/96) are excluded per the
/// project rules. NIP-33 was merged into NIP-01 but remains advertised for
/// clients that check it.
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
    /// Initial memory map size in bytes. The map grows automatically (up to
    /// `map_max_size`) when the database outgrows it, so reads and writes
    /// keep working no matter how large the database becomes.
    pub map_size: usize,
    /// Upper bound for the automatic map growth. The reservation is virtual
    /// address space (sparse file): physical memory is only consumed by the
    /// pages actually touched.
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
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("cannot read {}: {e}", path.display())))?;
        let cfg: Config = toml::from_str(&raw)
            .map_err(|e| Error::Config(format!("invalid {}: {e}", path.display())))?;
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
}

// Blocked/allowed lists live in the runtime config that NIP-86 can mutate.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AccessControl {
    pub blocked_pubkeys: Vec<String>,
    pub allowed_pubkeys: Vec<String>,
    pub blocked_kinds: Vec<u64>,
    pub allowed_kinds: Vec<u64>,
    pub blocked_ips: Vec<String>,
}

impl AccessControl {
    pub fn allows_pubkey(&self, pubkey: &str) -> bool {
        if self.blocked_pubkeys.iter().any(|p| p == pubkey) {
            return false;
        }
        self.allowed_pubkeys.is_empty() || self.allowed_pubkeys.iter().any(|p| p == pubkey)
    }

    pub fn allows_kind(&self, kind: u64) -> bool {
        if self.blocked_kinds.contains(&kind) {
            return false;
        }
        self.allowed_kinds.is_empty() || self.allowed_kinds.contains(&kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // Client-side NIPs must not be advertised (NIP-11).
        for n in [2, 3, 5, 17, 19, 32, 51, 65, 68, 99] {
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
        ac.blocked_pubkeys.push("bad".into());
        assert!(!ac.allows_pubkey("bad"));
        assert!(ac.allows_pubkey("good"));
        ac.blocked_kinds.push(5);
        assert!(!ac.allows_kind(5));
        assert!(ac.allows_kind(1));
    }
}
