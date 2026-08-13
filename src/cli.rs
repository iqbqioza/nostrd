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
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Write a default nostrd.toml and exit.
    Init,
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
            Command::Check => {
                let cfg = self.load_config()?;
                println!("configuration OK: {}", cfg.relay.name);
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

    fn daemonize(&self, cfg: &Config) -> Result<()> {
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&cfg.daemon.log_file)
            .map_err(|e| {
                Error::Config(format!(
                    "cannot open {}: {e}",
                    cfg.daemon.log_file.display()
                ))
            })?;
        let err_file = log_file
            .try_clone()
            .map_err(|e| Error::Config(format!("cannot clone log file: {e}")))?;

        let daemon = Daemonize::new()
            .pid_file(&cfg.daemon.pid_file)
            .working_directory("/")
            .stdout(log_file)
            .stderr(err_file);

        daemon
            .start()
            .map_err(|e| Error::Config(format!("failed to daemonize: {e}")))?;

        // Only the daemon child reaches this point.
        info!(
            "daemon started (pid {}), log: {}",
            std::process::id(),
            cfg.daemon.log_file.display()
        );
        Ok(())
    }

    fn stop(&self) -> Result<()> {
        let pid = match running_pid(&self.load_config()?.daemon.pid_file) {
            Some(pid) => pid,
            None => {
                println!("nostrd is not running");
                return Ok(());
            }
        };
        info!("stopping nostrd (pid {pid})");
        // SAFETY: `kill` only touches the targeted process id.
        let ret = unsafe { libc::kill(pid as i32, libc::SIGTERM) };
        if ret != 0 {
            return Err(Error::Other(format!(
                "cannot signal pid {pid}: {}",
                std::io::Error::last_os_error()
            )));
        }
        wait_for_stop(&self.load_config()?.daemon.pid_file);
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
        println!("{}", serde_json::to_string_pretty(&value)?);
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
    )
}

fn init_config(path: &Path) -> Result<()> {
    match Config::write_default(path) {
        Ok(()) => println!("wrote {}", path.display()),
        Err(Error::Config(msg)) => {
            error!("{msg}");
            std::process::exit(1);
        }
        Err(e) => return Err(e),
    }
    Ok(())
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

/// Checks whether a process is alive with `kill(pid, 0)`.
fn process_alive(pid: u32) -> bool {
    // SAFETY: signal 0 only probes for the existence of the process.
    let ret = unsafe { libc::kill(pid as i32, 0) };
    ret == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn wait_for_stop(pid_file: &Path) {
    for _ in 0..100 {
        let gone = std::fs::read_to_string(pid_file)
            .ok()
            .and_then(|p| p.trim().parse::<u32>().ok())
            .map(|pid| !process_alive(pid))
            .unwrap_or(true);
        if gone {
            let _ = std::fs::remove_file(pid_file);
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    error!(
        "daemon did not stop in time; pid file {} still exists",
        pid_file.display()
    );
}
