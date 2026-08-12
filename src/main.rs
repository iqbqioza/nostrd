mod cli;
mod config;
mod db;
mod error;
mod event;
mod filter;
mod nips;
mod relay;
mod server;
mod stats;
mod ws;

use clap::Parser;

use crate::cli::Cli;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let mut cli = Cli::parse();
    if let Err(e) = cli.prepare() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }

    // Reached in foreground mode or in the daemon child process. The runtime
    // must be created after daemonization because the fork inherits the
    // runtime context of the parent thread.
    let rt = tokio::runtime::Runtime::new().expect("cannot create tokio runtime");
    if let Err(e) = rt.block_on(cli.serve()) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
