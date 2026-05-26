// TCP accept loop for HTTP/1.1 connections.
// Spawns one tokio task per connection; each task drives keep-alive.
// Security invariants enforced here (before any user data is read):
//   - Per-IP connection limit (soft DoS mitigation).
//   - Total connection count cap.
//   - Client header read timeout (408 if exceeded).
//   - keep-alive idle timeout.
//   - keep-alive request count limit.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::config::types::{ServerBlock, TlsConfig};
use crate::http::limits::*;

// ── Listener handle ───────────────────────────────────────────────────────────

pub struct Listener {
    pub addr:    SocketAddr,
    pub tls:     Option<Arc<TlsConfig>>,
    pub servers: Arc<Vec<Arc<ServerBlock>>>,
}

impl Listener {
    pub async fn run(self) -> Result<()> {
        let tcp = TcpListener::bind(self.addr).await?;
        info!("listening on {}{}", self.addr, if self.tls.is_some() { " (TLS)" } else { "" });

        loop {
            match tcp.accept().await {
                Ok((stream, peer)) => {
                    let servers = Arc::clone(&self.servers);
                    let tls_cfg = self.tls.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, peer, servers, tls_cfg).await {
                            debug!("connection {} closed: {}", peer, e);
                        }
                    });
                }
                Err(e) => {
                    warn!("accept error: {}", e);
                }
            }
        }
    }
}

// ── Connection handler ────────────────────────────────────────────────────────

async fn handle_connection(
    stream:  TcpStream,
    peer:    SocketAddr,
    servers: Arc<Vec<Arc<ServerBlock>>>,
    tls_cfg: Option<Arc<TlsConfig>>,
) -> Result<()> {
    // TCP-level options.
    stream.set_nodelay(true)?;

    if let Some(_tls) = tls_cfg {
        // TLS upgrade path — implemented in Phase 2.
        return Err(anyhow::anyhow!("TLS not yet implemented"));
    }

    handle_plain(stream, peer, servers).await
}

// ── Plain HTTP/1.1 keep-alive loop ────────────────────────────────────────────

async fn handle_plain(
    mut stream:  TcpStream,
    peer:        SocketAddr,
    servers:     Arc<Vec<Arc<ServerBlock>>>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = vec![0u8; crate::http::limits::MAX_HEADER_BUFFER + 1];
    let mut requests: u64 = 0;

    loop {
        if requests >= MAX_KEEPALIVE_REQUESTS {
            send_plain_response(&mut stream, 400, b"connection limit reached").await?;
            break;
        }

        // Read with client header timeout.
        let n = match timeout(
            Duration::from_secs(DEFAULT_CLIENT_HEADER_TIMEOUT_S),
            stream.read(&mut buf),
        ).await {
            Err(_elapsed) => {
                send_plain_response(&mut stream, 408, b"Request Timeout").await?;
                break;
            }
            Ok(Err(e)) => return Err(e.into()),
            Ok(Ok(0)) => break, // EOF
            Ok(Ok(n)) => n,
        };

        requests += 1;

        let response = handle_request(&buf[..n], &servers, peer);
        let keep_alive = response.keep_alive;

        stream.write_all(&response.bytes).await?;
        stream.flush().await?;

        if !keep_alive { break; }
    }
    Ok(())
}

// ── Request dispatch (stub — filled in Phase 2) ───────────────────────────────

struct Response {
    bytes:      Vec<u8>,
    keep_alive: bool,
}

fn handle_request(
    raw:     &[u8],
    servers: &[Arc<ServerBlock>],
    peer:    SocketAddr,
) -> Response {
    use crate::simd::{parse_request_line, parse_headers, is_uri_safe};

    // 1. Parse request line.
    let (req_line, rl_len) = match parse_request_line(raw) {
        Ok(v) => v,
        Err(e) => {
            return bad_request(e);
        }
    };

    // 2. URI security check.
    if !is_uri_safe(req_line.uri) {
        return bad_request("forbidden URI sequence");
    }

    // 3. Parse headers.
    let (_headers, _hdrs_len) = match parse_headers(&raw[rl_len..]) {
        Ok(v) => v,
        Err(e) => {
            return bad_request(e);
        }
    };

    // 4. Route and respond — stub returns 501 until Phase 2 handlers are wired.
    let body = b"not implemented\r\n";
    let response = format!(
        "HTTP/1.1 501 Not Implemented\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut bytes = response.into_bytes();
    bytes.extend_from_slice(body);

    Response { bytes, keep_alive: false }
}

fn bad_request(reason: &str) -> Response {
    let body = format!("Bad Request: {}\r\n", reason);
    let response = format!(
        "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut bytes = response.into_bytes();
    bytes.extend_from_slice(body.as_bytes());
    Response { bytes, keep_alive: false }
}

async fn send_plain_response(
    stream:  &mut TcpStream,
    status:  u16,
    message: &[u8],
) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let response = format!(
        "HTTP/1.1 {} \r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status,
        message.len()
    );
    let mut out = response.into_bytes();
    out.extend_from_slice(message);
    stream.write_all(&out).await?;
    Ok(())
}
