// MyMTA — A Mail Transfer Agent built from scratch in Rust.
//
// Phase 1: SMTP Ingestion
//   - RFC 5321 SMTP state machine (EHLO, MAIL FROM, RCPT TO, DATA, etc.)
//   - RFC 5322 message parsing & validation
//   - RFC 2920 PIPELINING support
//   - Disk-based message spooling with atomic writes

use std::path::PathBuf;
use std::sync::Arc;

use mymta::config::Config;
use mymta::http::api::{self, ApiState};
use mymta::smtp::server::SmtpServer;
use mymta::spool::disk::DiskSpool;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── parse CLI args ──────────────────────────────────────────────
    let config_path = parse_args();

    // ── load config (file + env vars + defaults) ────────────────────
    let config = Arc::new(Config::load(config_path.as_deref())?);

    // ── initialize structured logging with config-driven level ──────
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| {
                    tracing_subscriber::EnvFilter::new(&config.log_level)
                }),
        )
        .init();

    tracing::info!(?config, "starting MyMTA");

    // ── shared spool (used by both SMTP and HTTP servers) ───────────
    let spool = Arc::new(DiskSpool::new(&config.spool_dir).await?);

    // ── build servers ───────────────────────────────────────────────
    let smtp = SmtpServer::with_shared(config.clone(), spool.clone());
    let http_state = ApiState {
        config: config.clone(),
        spool,
    };
    let http_addr = config.http_listen_addr;

    // ── run SMTP + HTTP concurrently ────────────────────────────────
    tokio::try_join!(
        async { smtp.run().await },
        async { api::run_http_server(http_state, http_addr).await },
    )?;

    Ok(())
}

/// Minimal CLI: `mymta [--config <path>]`
fn parse_args() -> Option<PathBuf> {
    let args: Vec<String> = std::env::args().collect();
    #[allow(unused_mut)]
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-c" => {
                if i + 1 < args.len() {
                    return Some(PathBuf::from(&args[i + 1]));
                } else {
                    eprintln!("error: --config requires a file path");
                    std::process::exit(1);
                }
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => {
                eprintln!("error: unknown argument '{}'", other);
                print_usage();
                std::process::exit(1);
            }
        }
        // Every arm above returns or exits, so this is currently
        // unreachable.  Kept for future non-terminal flags.
        #[allow(unreachable_code)]
        {
            i += 1;
        }
    }
    None
}

fn print_usage() {
    eprintln!(
        "Usage: mymta [OPTIONS]\n\n\
         Options:\n\
         \x20 -c, --config <path>   Path to TOML configuration file\n\
         \x20 -h, --help            Show this help message\n\n\
         Environment variables (override config file):\n\
         \x20 MTA_LISTEN             Listen address  (default: 0.0.0.0:2525)\n\
         \x20 MTA_HOSTNAME           Server hostname (default: localhost)\n\
         \x20 MTA_MAX_MESSAGE_SIZE   Max message bytes (default: 10485760)\n\
         \x20 MTA_MAX_RECIPIENTS     Max recipients    (default: 100)\n\
         \x20 MTA_SPOOL_DIR          Spool directory   (default: spool)\n\
         \x20 MTA_LOG_LEVEL          Log level         (default: info)"
    );
}
