// WebSocket proxy — upgrades an HTTP connection to a WebSocket tunnel.
// Forwards the Upgrade handshake to upstream, then splices the TCP streams.

use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Forward the WebSocket upgrade request to `upstream_addr`, read the 101 response,
/// and return (101_response_bytes, upstream_stream) for the caller to splice.
pub async fn upgrade_to_websocket(
    upstream_addr:   &str,
    connect_timeout: Duration,
    read_timeout:    Duration,
    method:          &str,
    path:            &str,
    headers:         &[(String, String)],
) -> Result<(Vec<u8>, TcpStream)> {
    let mut stream = timeout(connect_timeout, TcpStream::connect(upstream_addr)).await
        .map_err(|_| anyhow::anyhow!("websocket upstream connect timeout"))??;
    stream.set_nodelay(true)?;

    // Build upgrade request — forward almost all headers including Upgrade/Connection/Sec-WebSocket-*.
    let hop_by_hop = ["transfer-encoding", "te", "trailers", "proxy-authenticate",
                      "proxy-authorization", "proxy-connection"];
    let mut req = format!("{} {} HTTP/1.1\r\n", method, path);
    for (k, v) in headers {
        if hop_by_hop.iter().any(|h| k.eq_ignore_ascii_case(h)) { continue; }
        req.push_str(&format!("{}: {}\r\n", k, v));
    }
    req.push_str("\r\n");

    timeout(connect_timeout, stream.write_all(req.as_bytes())).await
        .map_err(|_| anyhow::anyhow!("websocket upstream send timeout"))??;

    // Read until we get the full HTTP response headers (101 or error).
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 1024];
    let deadline = tokio::time::Instant::now() + read_timeout;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            anyhow::bail!("websocket upstream read timeout");
        }
        let n = timeout(remaining, stream.read(&mut tmp)).await
            .map_err(|_| anyhow::anyhow!("websocket upstream read timeout"))?
            .context("websocket upstream read")?;
        if n == 0 { anyhow::bail!("websocket upstream closed during handshake"); }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") { break; }
        if buf.len() > 16_384 { anyhow::bail!("websocket upstream response too large"); }
    }

    // Check status is 101.
    let header_str = std::str::from_utf8(&buf).unwrap_or("");
    let status_line = header_str.lines().next().unwrap_or("");
    let status: u16 = status_line.split_whitespace().nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    if status != 101 {
        anyhow::bail!("websocket upstream returned {} instead of 101", status);
    }

    Ok((buf, stream))
}
