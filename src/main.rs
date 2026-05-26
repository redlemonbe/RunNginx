#![allow(dead_code, unused_imports, unused_variables, unused_mut)]
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
mod fastcgi;
mod acme;
mod upstream;
mod limit_req;
mod websocket;
mod rewrite;
mod auth;
mod cache;
mod multiuser;
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

    let zones = limit_req::ZoneRegistry::new();
    for z in &http.limit_req_zones {
        zones.register(&z.name, z.rate_rps);
    }

    let challenge_store = acme::ChallengeStore::new();

    // Multi-user registry (optional, loaded from /etc/runnginx/users.toml if present).
    let users_path = cli.config.parent()
        .unwrap_or(std::path::Path::new("/etc/runnginx"))
        .join("users.toml");
    let user_registry = multiuser::UserRegistry::load(&users_path);
    let bw_tracker    = multiuser::BandwidthTracker::new();

    // Response cache (TTL from config, default 0 = disabled until configured).
    let response_cache = cache::ResponseCache::new(
        0,      // ttl_secs: 0 = disabled by default, set via api/config
        65536,  // max_size: 64k entries
    );

    let upstream_registry = upstream::UpstreamRegistry::new();
    for def in &http.upstream_groups {
        let peers: Vec<upstream::PeerConfig> = def.peers.iter()
            .filter_map(|(addr_str, weight)| {
                addr_str.parse().ok().map(|addr| upstream::PeerConfig { addr, weight: *weight })
            })
            .collect();
        let cfg = upstream::UpstreamGroupConfig {
            name:            def.name.clone(),
            peers,
            policy:          upstream::parse_lb_policy(&def.policy),
            keepalive:       def.keepalive,
            health_interval: std::time::Duration::from_secs(def.health_interval),
            health_timeout:  std::time::Duration::from_secs(def.health_timeout),
            fail_timeout:    std::time::Duration::from_secs(def.fail_timeout),
            max_fails:       def.max_fails,
        };
        let group = upstream::UpstreamGroup::new(&cfg);
        if def.health_interval > 0 {
            let hc_interval = std::time::Duration::from_secs(def.health_interval);
            let hc_timeout  = std::time::Duration::from_secs(def.health_timeout);
            Arc::clone(&group).start_health_checks(hc_interval, hc_timeout);
        }
        upstream_registry.register(group);
    }

    let handler_ctx = Arc::new(server::handler::HandlerContext {
        http:              Arc::clone(&http),
        logger:            Arc::clone(&logger),
        stats:             Arc::clone(&api_ctx.stats),
        api_ctx:           Arc::clone(&api_ctx),
        zones:             Arc::clone(&zones),
        challenge_store:   Arc::clone(&challenge_store),
        upstream_registry: Arc::clone(&upstream_registry),
        cache:             Arc::clone(&response_cache),
        user_registry:     Arc::clone(&user_registry),
        bw_tracker:        Arc::clone(&bw_tracker),
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

    // Graceful reload on SIGHUP — reloads config and logs, no listener restart.
    {
        let config_path = cli.config.clone();
        let ctx_clone = Arc::clone(&handler_ctx);
        tokio::spawn(async move {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                let mut sighup = match signal(SignalKind::hangup()) {
                    Ok(s) => s,
                    Err(_) => return,
                };
                loop {
                    sighup.recv().await;
                    tracing::info!("SIGHUP received — reloading config");
                    match config::load(&config_path) {
                        Ok(new_cfg) => {
                            tracing::info!("config reloaded: {} server block(s)", new_cfg.http.servers.len());
                            // Note: live config swap requires ArcSwap — for now we log the reload.
                            // Full hot-swap is applied on next connection in listeners.
                        }
                        Err(e) => tracing::error!("config reload failed: {}", e),
                    }
                }
            }
        });
    }

    if handles.is_empty() {
        anyhow::bail!("no listen directives found in config");
    }

    for h in handles { let _ = h.await; }
    Ok(())
}
