use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tracing::info;

mod api;
mod tls;
mod proxy;
mod config;
mod http;
mod router;
mod server;
mod simd;
mod stats;

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

    #[arg(short = 't', long)]
    test: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Install rustls ring crypto provider (must be done before any TLS operations).
    #[cfg(feature = "tls")]
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok(); // ok() — harmless if already installed

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

    let (reload_tx, _reload_rx) = tokio::sync::watch::channel(());

    let api_ctx = Arc::new(api::ApiContext {
        stats:       Arc::new(stats::Stats::new()),
        rate:        Arc::new(stats::RateLimiter::new(crate::http::limits::API_RATE_LIMIT_RPS as u32)),
        http:        Arc::clone(&http),
        config_path: cli.config.clone(),
        reload_tx,
    });

    let logger = Arc::new(server::access_log::Logger::new(&http.access_log));

    let handler_ctx = Arc::new(server::handler::HandlerContext {
        http:    Arc::clone(&http),
        logger:  Arc::clone(&logger),
        stats:   Arc::clone(&api_ctx.stats),
        api_ctx: Arc::clone(&api_ctx),
    });

    let mut handles = Vec::new();

    for srv in &http.servers {
        for listen in &srv.listen {
            let listener = server::listener::Listener {
                addr: listen.addr,
                tls:  srv.tls.as_ref().map(|t| Arc::new(t.clone())),
                ctx:  Arc::clone(&handler_ctx),
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

    for h in handles { let _ = h.await; }
    Ok(())
}
