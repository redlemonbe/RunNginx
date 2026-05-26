// TCP accept loop for HTTP/1.1 connections.
// Spawns one tokio task per connection; each task drives keep-alive.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::config::types::{HttpBlock, TlsConfig};
use crate::http::limits::*;
use crate::server::access_log::Logger;
use crate::server::handler;

// ── Listener handle ───────────────────────────────────────────────────────────

pub struct Listener {
    pub addr:    SocketAddr,
    pub tls:     Option<Arc<TlsConfig>>,
    pub http:    Arc<HttpBlock>,
    pub logger:  Arc<Logger>,
}

impl Listener {
    pub async fn run(self) -> Result<()> {
        let tcp = TcpListener::bind(self.addr).await?;
        info!("listening on {}{}", self.addr, if self.tls.is_some() { " (TLS)" } else { "" });

        loop {
            match tcp.accept().await {
                Ok((stream, peer)) => {
                    let http   = Arc::clone(&self.http);
                    let logger = Arc::clone(&self.logger);
                    let tls    = self.tls.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, peer, http, logger, tls).await {
                            debug!("connection {} closed: {}", peer, e);
                        }
                    });
                }
                Err(e) => warn!("accept error: {}", e),
            }
        }
    }
}

// ── Connection handler ────────────────────────────────────────────────────────

async fn handle_connection(
    stream:  TcpStream,
    peer:    SocketAddr,
    http:    Arc<HttpBlock>,
    logger:  Arc<Logger>,
    tls_cfg: Option<Arc<TlsConfig>>,
) -> Result<()> {
    stream.set_nodelay(true)?;

    if tls_cfg.is_some() {
        return Err(anyhow::anyhow!("TLS not yet implemented (Phase 2)"));
    }

    handle_plain(stream, peer, http, logger).await
}

// ── Plain HTTP/1.1 keep-alive loop ────────────────────────────────────────────

async fn handle_plain(
    mut stream: TcpStream,
    peer:       SocketAddr,
    http:       Arc<HttpBlock>,
    logger:     Arc<Logger>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf       = vec![0u8; MAX_HEADER_BUFFER + DEFAULT_MAX_BODY_BYTES + 1];
    let mut requests  = 0u64;

    loop {
        if requests >= MAX_KEEPALIVE_REQUESTS {
            let _ = stream.write_all(b"HTTP/1.1 400 Too Many Requests\r\nConnection: close\r\n\r\n").await;
            break;
        }

        // Read with client header timeout.
        let n = match timeout(
            Duration::from_secs(DEFAULT_CLIENT_HEADER_TIMEOUT_S),
            stream.read(&mut buf),
        ).await {
            Err(_) => {
                let _ = stream.write_all(
                    b"HTTP/1.1 408 Request Timeout\r\nConnection: close\r\n\r\n"
                ).await;
                break;
            }
            Ok(Err(e)) => return Err(e.into()),
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
        };

        requests += 1;

        let result = handler::handle(&buf[..n], peer, Arc::clone(&http), Arc::clone(&logger)).await;
        let keep_alive = result.keep_alive;

        stream.write_all(&result.bytes).await?;
        stream.flush().await?;

        if !keep_alive { break; }

        // Keep-alive idle timeout between requests.
        // We reuse the header timeout here for simplicity.
        // A dedicated keepalive_timeout could be added later.
    }
    Ok(())
}
