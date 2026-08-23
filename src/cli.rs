//! Command-line interface: configuration handling, daemon
//! management and the foreground server entry point.

use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Parser, Subcommand};
use daemonize::Daemonize;
use log::{error, info};

use crate::config::{Config, DEFAULT_CONFIG};
use crate::error::{Error, Result};
use crate::server::run_server;

#[derive(Debug, Parser)]
#[command(
    name = "nostrd",
    version,
    about = "A minimal and stable Nostr relay server"
)]
pub struct Cli {
    #[arg(long, default_value = DEFAULT_CONFIG, value_name = "PATH")]
    pub config: PathBuf,
    #[command(subcommand)]
    pub command: Command,
    /// Set when the process is the daemon child (after daemonization).
    #[arg(skip)]
    pub daemonized: bool,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Write a default nostrd.toml and exit.
    Init,
    /// Generate a relay secret key for NIP-29 and write it into nostrd.toml
    /// (asks for confirmation when relay.private_key is already set).
    #[command(name = "genkey")]
    GenKey,
    /// Start the relay as a daemon (or in the foreground with --foreground).
    Start {
        #[arg(long)]
        foreground: bool,
    },
    /// Stop the running daemon.
    Stop,
    /// Stop the daemon and start it again (reloads nostrd.toml).
    Restart,
    /// Show live statistics of the running daemon.
    Stats,
    /// Validate nostrd.toml and exit.
    Check,
}

impl Cli {
    /// Runs every synchronous step of the command. For `start`/`restart` in
    /// daemon mode the parent process terminates inside this call and only
    /// the daemon child continues; the caller then starts the async runtime
    /// and calls [`Cli::serve`].
    pub fn prepare(&mut self) -> Result<()> {
        match self.command {
            Command::Init => return init_config(&self.config),
            Command::GenKey => return self.genkey(),
            Command::Check => {
                let cfg = self.load_config()?;
                cfg.validate()?;
                print_line(&format!("configuration OK: {}", cfg.relay.name));
                return Ok(());
            }
            Command::Stop => return self.stop(),
            Command::Stats => return self.stats(),
            Command::Start { foreground: true } => return Ok(()),
            _ => {}
        }

        if matches!(self.command, Command::Restart) {
            let _ = self.stop();
        }

        self.config = absolutize(&self.config);
        let cfg = self.load_config()?;
        // Validate before daemonizing: an invalid config must fail loudly in
        // the foreground (the parent), not silently in the daemon child
        // whose stderr is already pointed at /dev/null.
        cfg.validate()?;
        if let Some(pid) = running_pid(&cfg.daemon.pid_file) {
            return Err(Error::Config(format!(
                "already running (pid {pid}); use 'nostrd stop' or 'nostrd restart'"
            )));
        }
        self.daemonize(&cfg)?;
        Ok(())
    }

    /// Runs the relay server. Only reached in foreground mode or in the
    /// daemon child process.
    pub async fn serve(&self) -> Result<()> {
        match self.command {
            Command::Start { .. } | Command::Restart => {
                if !self.config.exists() {
                    Config::write_default(&self.config)?;
                    info!("created default configuration at {}", self.config.display());
                }
                let cfg = self.load_config()?;
                cfg.validate()?;
                let db = open_db(&cfg)?;
                run_server(self.config.clone(), cfg, db).await
            }
            _ => Ok(()),
        }
    }

    fn load_config(&self) -> Result<Config> {
        let mut cfg = Config::load(&self.config)?;
        cfg.absolutize_paths(&self.config);
        Ok(cfg)
    }

    fn daemonize(&mut self, cfg: &Config) -> Result<()> {
        // All logging goes through the custom logger to the log file (with
        // rotation); the daemon's stdio is pointed at /dev/null so the
        // inherited descriptors do not keep the file open across rotations.
        if let Some(dir) = cfg.daemon.log_file.parent() {
            std::fs::create_dir_all(dir).map_err(|e| {
                Error::Config(format!(
                    "cannot create log directory {}: {e}",
                    dir.display()
                ))
            })?;
        }
        crate::logging::install_file_logger(
            cfg.daemon.log_file.clone(),
            cfg.daemon.log_max_size_bytes,
            cfg.daemon.log_max_files,
        )
        .map_err(|e| {
            Error::Config(format!(
                "cannot open {}: {e}",
                cfg.daemon.log_file.display()
            ))
        })?;
        let devnull = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .map_err(|e| Error::Config(format!("cannot open /dev/null: {e}")))?;

        let daemon = Daemonize::new()
            .pid_file(&cfg.daemon.pid_file)
            .working_directory("/")
            .stdout(devnull.try_clone()?)
            .stderr(devnull);

        match daemon.execute() {
            // Parent: the daemon has forked and the first child exited.
            // Report the pid (read from the pid file, which the daemon
            // writes just after the first child exits) and terminate, so the
            // foreground `nostrd start`/`restart` returns with a clear
            // message instead of silently.
            daemonize::Outcome::Parent(result) => {
                result.map_err(|e| Error::Config(format!("failed to daemonize: {e}")))?;
                match wait_for_pid_file(&cfg.daemon.pid_file) {
                    Some(pid) => print_line(&format!("nostrd started (pid {pid})")),
                    None => print_line("nostrd started"),
                }
                flush_stdout();
                std::process::exit(0);
            }
            // Only the daemon child reaches this point.
            daemonize::Outcome::Child(result) => {
                result.map_err(|e| Error::Config(format!("failed to daemonize: {e}")))?;
                self.daemonized = true;
                info!(
                    "daemon started (pid {}), log: {}",
                    std::process::id(),
                    cfg.daemon.log_file.display()
                );
                Ok(())
            }
        }
    }

    fn stop(&self) -> Result<()> {
        let pid = match running_pid(&self.load_config()?.daemon.pid_file) {
            Some(pid) => pid,
            None => {
                print_line("nostrd is not running");
                return Ok(());
            }
        };
        print_line(&format!("stopping nostrd (pid {pid})"));
        // SAFETY: `kill` only touches the targeted process id.
        let ret = unsafe { libc::kill(pid as i32, libc::SIGTERM) };
        if ret != 0 {
            return Err(Error::Other(format!(
                "cannot signal pid {pid}: {}",
                std::io::Error::last_os_error()
            )));
        }
        if !wait_for_stop(&self.load_config()?.daemon.pid_file) {
            return Err(Error::Other(format!(
                "daemon (pid {pid}) did not stop in time"
            )));
        }
        print_line("nostrd stopped");
        Ok(())
    }

    fn stats(&self) -> Result<()> {
        let cfg = self.load_config()?;
        if !cfg.daemon.stats_file.exists() {
            return Err(Error::Config(
                "nostrd is not running (no stats file)".into(),
            ));
        }
        let raw = std::fs::read_to_string(&cfg.daemon.stats_file)?;
        let value: serde_json::Value = serde_json::from_str(&raw)?;
        print_line(&serde_json::to_string_pretty(&value)?);
        Ok(())
    }

    /// `nostrd genkey`: generates a relay secret key (for NIP-29 group
    /// metadata and NIP-43 membership events) and writes it into
    /// `relay.private_key` of the config file, preserving the rest of the
    /// file. When `relay.private_key` is already set, the operator is asked
    /// to confirm the overwrite (y/N).
    fn genkey(&self) -> Result<()> {
        if !self.config.exists() {
            return Err(Error::Config(format!(
                "{} not found; run 'nostrd init' first",
                self.config.display()
            )));
        }
        let existing = Config::load(&self.config)?.relay.private_key.clone();
        let key = generate_secret_key_hex()?;

        if !existing.is_empty() {
            let prefix: String = existing.chars().take(8).collect();
            print_line(&format!(
                "relay.private_key is already set ({}...). Overwrite it? [y/N]",
                prefix
            ));
            let mut answer = String::new();
            std::io::stdin().read_line(&mut answer).map_err(Error::Io)?;
            if !answer.trim().eq_ignore_ascii_case("y") {
                print_line("aborted: relay.private_key unchanged");
                return Ok(());
            }
        }

        let text = std::fs::read_to_string(&self.config)?;
        std::fs::write(&self.config, set_private_key_in_text(&text, &key))?;

        // Print the relay's pubkey too: it is safe to share and useful for
        // advertising the relay's `self` identity (NIP-11).
        let pubkey = match secp256k1::SecretKey::from_slice(&hex::decode(&key).unwrap()) {
            Ok(secret) => {
                let secp = secp256k1::Secp256k1::new();
                let keypair = secp256k1::Keypair::from_seckey_slice(&secp, &secret.secret_bytes())
                    .map(|k| secp256k1::XOnlyPublicKey::from_keypair(&k).0.to_string());
                keypair.unwrap_or_default()
            }
            Err(_) => String::new(),
        };
        print_line(&format!(
            "wrote relay.private_key to {}",
            self.config.display()
        ));
        if !pubkey.is_empty() {
            print_line(&format!("relay pubkey (NIP-11 \"self\"): {pubkey}"));
        }
        Ok(())
    }
}

fn open_db(cfg: &Config) -> Result<crate::db::DbClient> {
    crate::db::DbClient::open(
        &cfg.database,
        cfg.nip_enabled(40),
        std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        cfg.limits.db_request_timeout_secs,
        cfg.limits.max_indexed_words,
        cfg.limits.db_queue_msgs,
        cfg.limits.db_queue_events,
    )
}

/// Prints a line to stdout, ignoring broken-pipe errors (e.g. `nostrd stats
/// | head`): a closed pipe must not panic the process like `println!` does.
fn print_line(text: &str) {
    use std::io::Write;
    let _ = writeln!(std::io::stdout(), "{text}");
}

/// Flushes stdout so a completion message survives a `process::exit` (which
/// runs no destructors and would otherwise drop a buffered write).
fn flush_stdout() {
    use std::io::Write;
    let _ = std::io::stdout().flush();
}

/// Waits up to one second for the daemon's pid file to appear (the daemon
/// writes it just after the first child exits, so the parent can read it a
/// moment early) and returns the pid when the daemon is alive.
fn wait_for_pid_file(path: &Path) -> Option<u32> {
    for _ in 0..100 {
        if let Some(pid) = running_pid(path) {
            return Some(pid);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    None
}

fn init_config(path: &Path) -> Result<()> {
    match Config::write_default(path) {
        Ok(()) => print_line(&format!("wrote {}", path.display())),
        Err(Error::Config(msg)) => {
            error!("{msg}");
            std::process::exit(1);
        }
        Err(e) => return Err(e),
    }
    Ok(())
}

/// Generates a random secp256k1 secret key as lowercase hex (64 chars),
/// retrying if the random bytes happen to be out of the valid range.
fn generate_secret_key_hex() -> Result<String> {
    for _ in 0..8 {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes)
            .map_err(|e| Error::Other(format!("cannot read random bytes: {e}")))?;
        if let Ok(secret) = secp256k1::SecretKey::from_slice(&bytes) {
            return Ok(hex::encode(secret.secret_bytes()));
        }
    }
    Err(Error::Other("failed to generate a valid secret key".into()))
}

/// Replaces (or inserts) the `relay.private_key` value in a config file's
/// text, preserving every other line, comment and section. Delegates to the
/// shared [`crate::config::set_relay_field_in_text`] helper.
fn set_private_key_in_text(text: &str, key: &str) -> String {
    crate::config::set_relay_field_in_text(text, "private_key", key)
}

/// Resolves a possibly relative path against the current directory so that it
/// stays valid after the daemon changes its working directory.
fn absolutize(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    }
}

fn running_pid(pid_file: &Path) -> Option<u32> {
    let pid = std::fs::read_to_string(pid_file)
        .ok()?
        .trim()
        .parse::<u32>()
        .ok()?;
    if pid == 0 {
        return None;
    }
    if process_alive(pid) { Some(pid) } else { None }
}

/// Checks whether a process is alive with `kill(pid, 0)`. On Linux the
/// process name is cross-checked against `/proc/<pid>/comm` so that a stale
/// pid file whose pid was reused by an unrelated process is not mistaken for
/// a running relay (which would make `start` refuse and `stop` signal an
/// innocent process).
fn process_alive(pid: u32) -> bool {
    // SAFETY: signal 0 only probes for the existence of the process.
    let alive = {
        let ret = unsafe { libc::kill(pid as i32, 0) };
        ret == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    };
    if !alive {
        return false;
    }
    // Best-effort name check (Linux only): a reused pid running a different
    // program is not our daemon.
    if let Ok(comm) = std::fs::read_to_string(format!("/proc/{pid}/comm")) {
        return comm.trim() == "nostrd";
    }
    true
}

/// Waits up to 10 seconds for the daemon to exit (the pid file to disappear).
/// Returns `true` when the daemon stopped, `false` when it is still running.
fn wait_for_stop(pid_file: &Path) -> bool {
    for _ in 0..100 {
        let gone = std::fs::read_to_string(pid_file)
            .ok()
            .and_then(|p| p.trim().parse::<u32>().ok())
            .map(|pid| !process_alive(pid))
            .unwrap_or(true);
        if gone {
            let _ = std::fs::remove_file(pid_file);
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    error!(
        "daemon did not stop in time; pid file {} still exists",
        pid_file.display()
    );
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    #[test]
    fn replaces_existing_private_key_preserving_comments() {
        let text = "# comment\n[relay]\nname = \"nostrd\"\n# my key\nprivate_key = \"\"\npublic_url = \"wss://x\"\n";
        let out = set_private_key_in_text(text, KEY);
        assert!(out.contains(&format!("private_key = \"{KEY}\"")));
        assert!(!out.contains("private_key = \"\""));
        // Comments and unrelated lines survive.
        assert!(out.contains("# comment"));
        assert!(out.contains("# my key"));
        assert!(out.contains("name = \"nostrd\""));
        assert!(out.contains("public_url = \"wss://x\""));
    }

    #[test]
    fn inserts_private_key_after_relay_header() {
        let text = "[relay]\nname = \"nostrd\"\n\n[server]\nport = 8080\n";
        let out = set_private_key_in_text(text, KEY);
        assert!(out.contains(&format!(
            "[relay]\nprivate_key = \"{KEY}\"\nname = \"nostrd\""
        )));
        assert!(out.contains("[server]\nport = 8080"));
    }

    #[test]
    fn appends_relay_section_when_missing() {
        let text = "[server]\nport = 8080\n";
        let out = set_private_key_in_text(text, KEY);
        assert!(out.ends_with(&format!("[relay]\nprivate_key = \"{KEY}\"\n")));
        assert!(out.starts_with("[server]\nport = 8080\n"));
    }

    #[test]
    fn relay_header_at_eof_without_newline_stays_valid_toml() {
        // [relay] as the last line with no trailing newline: the key must be
        // inserted on a new line, not glued to the header.
        let text = "[server]\nport = 8080\n[relay]";
        let out = set_private_key_in_text(text, KEY);
        assert!(out.contains(&format!("[relay]\nprivate_key = \"{KEY}\"\n")));
        // The result must parse as valid TOML.
        assert!(toml::from_str::<toml::Value>(&out).is_ok());
    }

    #[test]
    fn relay_in_comment_or_string_is_not_a_header() {
        // A `[relay]` mention inside a comment or a string value must not be
        // treated as the section header.
        let text =
            "# [relay] mentioned in a comment\nname = \"x [relay] y\"\n[server]\nport = 8080\n";
        let out = set_private_key_in_text(text, KEY);
        assert!(out.ends_with(&format!("[relay]\nprivate_key = \"{KEY}\"\n")));
        assert!(out.starts_with("# [relay] mentioned in a comment\n"));
        assert!(toml::from_str::<toml::Value>(&out).is_ok());
    }

    #[test]
    fn relay_header_with_inline_comment_is_recognized() {
        // `[relay]# a trailing comment` is a valid TOML header and must be
        // recognized as the `[relay]` section; before the fix the key was
        // appended as a *second* `[relay]` section, breaking the file with
        // a duplicate key.
        let text = "[relay]# my relay\nname = \"nostrd\"\n[server]\nport = 8080\n";
        let out = set_private_key_in_text(text, KEY);
        assert!(out.contains(&format!("[relay]# my relay\nprivate_key = \"{KEY}\"")));
        assert!(out.contains("[server]\nport = 8080"));
        assert!(toml::from_str::<toml::Value>(&out).is_ok());
    }

    #[test]
    fn generated_key_is_valid_hex() {
        let key = generate_secret_key_hex().unwrap();
        assert_eq!(key.len(), 64);
        assert!(hex::decode(&key).is_ok());
        assert!(secp256k1::SecretKey::from_slice(&hex::decode(&key).unwrap()).is_ok());
    }
}
