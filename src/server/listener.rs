// TCP accept loop for HTTP/1.1 connections.

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
        let tcp = TcpListener::bind(self.addr).await?;
        info!("listening on {}{}", self.addr, if self.tls.is_some() { " (TLS)" } else { "" });
        loop {
            match tcp.accept().await {
                Ok((stream, peer)) => {
                    let ctx = Arc::clone(&self.ctx);
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, peer, ctx).await {
                            debug!("connection {} closed: {}", peer, e);
                        }
                    });
                }
                Err(e) => warn!("accept error: {}", e),
            }
        }
    }
}

async fn handle_connection(
    stream: TcpStream,
    peer:   SocketAddr,
    ctx:    Arc<HandlerContext>,
) -> Result<()> {
    stream.set_nodelay(true)?;
    handle_plain(stream, peer, ctx).await
}

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
        let result = crate::server::handler::handle(&buf[..n], peer, Arc::clone(&ctx)).await;
        let keep_alive = result.keep_alive;
        stream.write_all(&result.bytes).await?;
        stream.flush().await?;
        if !keep_alive { break; }
    }
    Ok(())
}
