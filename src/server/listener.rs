// TCP accept loop — HTTP/1.1 plain and TLS.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::config::types::TlsConfig;
use crate::http::limits::*;
use crate::server::handler::{HandlerContext, HandlerResult};

pub struct Listener {
    pub addr: SocketAddr,
    pub tls:  Option<Arc<TlsConfig>>,
    pub ctx:  Arc<HandlerContext>,
}

impl Listener {
    pub async fn run(self) -> Result<()> {
        // Load TLS config if needed.
        #[cfg(feature = "tls")]
        let tls_server_cfg = if let Some(ref tls) = self.tls {
            let server_names: Vec<String> = self.ctx.http.servers.iter()
                .flat_map(|s| s.server_names.iter().filter_map(|n| {
                    match n {
                        crate::config::types::ServerName::Exact(s) => Some(s.clone()),
                        _ => None,
                    }
                }))
                .collect();
            let domains = if server_names.is_empty() {
                vec!["localhost".to_owned()]
            } else {
                server_names
            };
            Some(crate::tls::load_server_config(&tls.cert_path, &tls.key_path, &domains)?)
        } else {
            None
        };

        #[cfg(not(feature = "tls"))]
        let tls_server_cfg: Option<()> = None;

        let tcp = TcpListener::bind(self.addr).await?;
        info!("listening on {}{}", self.addr,
            if self.tls.is_some() { " (TLS)" } else { "" });

        loop {
            match tcp.accept().await {
                Ok((stream, peer)) => {
                    let ctx = Arc::clone(&self.ctx);
                    #[cfg(feature = "tls")]
                    let tls_cfg = tls_server_cfg.clone();
                    #[cfg(not(feature = "tls"))]
                    let tls_cfg: Option<()> = None;

                    tokio::spawn(async move {
                        #[cfg(feature = "tls")]
                        {
                            if let Err(e) = handle_connection_tls(stream, peer, ctx, tls_cfg).await {
                                debug!("connection {} closed: {}", peer, e);
                            }
                        }
                        #[cfg(not(feature = "tls"))]
                        {
                            let _ = tls_cfg; // suppress warning
                            if let Err(e) = handle_plain(stream, peer, ctx).await {
                                debug!("connection {} closed: {}", peer, e);
                            }
                        }
                    });
                }
                Err(e) => warn!("accept error: {}", e),
            }
        }
    }
}

// ── TLS connection handler ────────────────────────────────────────────────────

#[cfg(feature = "tls")]
async fn handle_connection_tls(
    stream:  TcpStream,
    peer:    SocketAddr,
    ctx:     Arc<HandlerContext>,
    tls_cfg: Option<Arc<rustls::ServerConfig>>,
) -> Result<()> {
    stream.set_nodelay(true)?;
    if let Some(cfg) = tls_cfg {
        let tls_stream = crate::tls::accept_tls(stream, cfg).await?;
        handle_generic(tls_stream, peer, ctx).await
    } else {
        handle_plain(stream, peer, ctx).await
    }
}

// ── Plain HTTP handler ────────────────────────────────────────────────────────

async fn handle_plain(
    mut stream: TcpStream,
    peer:       SocketAddr,
    ctx:        Arc<HandlerContext>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf      = vec![0u8; MAX_HEADER_BUFFER + DEFAULT_MAX_BODY_BYTES + 1];
    let mut requests = 0u64;

    loop {
        if requests >= MAX_KEEPALIVE_REQUESTS {
            let _ = stream.write_all(b"HTTP/1.1 400 Too Many Requests\r\nConnection: close\r\n\r\n").await;
            break;
        }
        let n = match timeout(
            Duration::from_secs(DEFAULT_CLIENT_HEADER_TIMEOUT_S),
            stream.read(&mut buf),
        ).await {
            Err(_) => {
                let _ = stream.write_all(b"HTTP/1.1 408 Request Timeout\r\nConnection: close\r\n\r\n").await;
                break;
            }
            Ok(Err(e)) => return Err(e.into()),
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
        };
        requests += 1;
        let result = crate::server::handler::handle(&buf[..n], peer, Arc::clone(&ctx)).await;
        let keep_alive = result.keep_alive;
        stream.write_all(&result.bytes).await?;
        stream.flush().await?;
        if let Some(mut upstream) = result.tunnel {
            // WebSocket: splice until either side closes.
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
            break;
        }
        if !keep_alive { break; }
    }
    Ok(())
}

// ── Generic async read/write handler (for TLS streams) ───────────────────────

#[cfg(feature = "tls")]
async fn handle_generic<S>(
    mut stream: S,
    peer:       SocketAddr,
    ctx:        Arc<HandlerContext>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf      = vec![0u8; MAX_HEADER_BUFFER + DEFAULT_MAX_BODY_BYTES + 1];
    let mut requests = 0u64;

    loop {
        if requests >= MAX_KEEPALIVE_REQUESTS {
            let _ = stream.write_all(b"HTTP/1.1 400 Too Many Requests\r\nConnection: close\r\n\r\n").await;
            break;
        }
        let n = match timeout(
            Duration::from_secs(DEFAULT_CLIENT_HEADER_TIMEOUT_S),
            stream.read(&mut buf),
        ).await {
            Err(_) => {
                let _ = stream.write_all(b"HTTP/1.1 408 Request Timeout\r\nConnection: close\r\n\r\n").await;
                break;
            }
            Ok(Err(e)) => return Err(e.into()),
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
        };
        requests += 1;
        let result = crate::server::handler::handle(&buf[..n], peer, Arc::clone(&ctx)).await;
        let keep_alive = result.keep_alive;
        stream.write_all(&result.bytes).await?;
        stream.flush().await?;
        if let Some(mut upstream) = result.tunnel {
            // WebSocket: splice streams. For TLS client, use copy_bidirectional on the TLS stream.
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
            break;
        }
        if !keep_alive { break; }
    }
    Ok(())
}
