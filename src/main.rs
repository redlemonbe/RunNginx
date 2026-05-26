use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tracing::info;

mod config;
mod http;
mod router;
mod server;
mod simd;

#[cfg(feature = "jemalloc")]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Parser)]
#[command(name = "runnginx", version, about = "High-performance nginx-compatible HTTP server")]
struct Cli {
    /// Path to nginx.conf
    #[arg(short, long, default_value = "/etc/runnginx/nginx.conf")]
    config: PathBuf,

    /// Log level (trace/debug/info/warn/error)
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Test config and exit
    #[arg(short = 't', long)]
    test: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Init tracing.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| cli.log_level.parse().unwrap_or_default()),
        )
        .init();

    // Log SIMD dispatch level.
    info!("SIMD level: {:?}", simd::simd_level());

    // Load and validate config.
    let cfg = config::load(&cli.config)?;
    info!("config loaded: {} server block(s)", cfg.http.servers.len());

    if cli.test {
        info!("config test OK");
        return Ok(());
    }

    // Bind listeners.
    let http_block = cfg.http;
    let servers: Arc<Vec<Arc<config::types::ServerBlock>>> =
        Arc::new(http_block.servers.iter().map(|s| Arc::new(s.clone())).collect());

    let mut handles = Vec::new();

    for srv in http_block.servers.iter() {
        for listen in &srv.listen {
            let listener = server::listener::Listener {
                addr:    listen.addr,
                tls:     srv.tls.as_ref().map(|t| Arc::new(t.clone())),
                servers: Arc::clone(&servers),
            };
            handles.push(tokio::spawn(async move {
                if let Err(e) = listener.run().await {
                    tracing::error!("listener error: {}", e);
                }
            }));
        }
    }

    if handles.is_empty() {
        anyhow::bail!("no listen directives found in config");
    }

    // Wait for all listeners (run forever).
    for h in handles {
        let _ = h.await;
    }
    Ok(())
}
