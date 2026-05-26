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
    #[arg(short, long, default_value = "/etc/runnginx/nginx.conf")]
    config: PathBuf,

    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Test config and exit (nginx -t equivalent)
    #[arg(short = 't', long)]
    test: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| cli.log_level.parse().unwrap_or_default()),
        )
        .init();

    info!("RunNginx v{} — SIMD level: {:?}", env!("CARGO_PKG_VERSION"), simd::simd_level());

    let cfg = config::load(&cli.config)?;
    info!("config OK: {} server block(s)", cfg.http.servers.len());

    if cli.test {
        info!("config test OK");
        return Ok(());
    }

    let http = Arc::new(cfg.http);

    // Create access logger (uses http-level access_log directive).
    let logger = Arc::new(server::access_log::Logger::new(&http.access_log));

    // Bind one listener per (server × listen) directive.
    let mut handles = Vec::new();

    for srv in &http.servers {
        for listen in &srv.listen {
            let listener = server::listener::Listener {
                addr:    listen.addr,
                tls:     srv.tls.as_ref().map(|t| Arc::new(t.clone())),
                http:    Arc::clone(&http),
                logger:  Arc::clone(&logger),
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

    for h in handles {
        let _ = h.await;
    }
    Ok(())
}
