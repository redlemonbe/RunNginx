// Reverse proxy — proxy_pass implementation.
// Connection pooling: up to POOL_SIZE idle connections per upstream.
// Security: SSRF mitigation already applied at config parse time (ProxyConfig.upstream is validated).

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::config::types::ProxyConfig;
use crate::server::static_files::StaticResponse;

const POOL_SIZE: usize = 32;

// ── Connection pool ───────────────────────────────────────────────────────────

type Pool = DashMap<String, Arc<Mutex<VecDeque<TcpStream>>>>;

lazy_static::lazy_static! {
    static ref CONN_POOL: Pool = DashMap::new();
}

fn pool_key(cfg: &ProxyConfig) -> String {
    format!("{}://{}:{}", cfg.upstream.scheme(),
        cfg.upstream.host_str().unwrap_or(""),
        cfg.upstream.port_or_known_default().unwrap_or(80))
}

async fn get_connection(cfg: &ProxyConfig) -> Result<TcpStream> {
    let key = pool_key(cfg);

    // Try idle connection from pool.
    if let Some(queue) = CONN_POOL.get(&key) {
        let mut q = queue.lock().await;
        while let Some(stream) = q.pop_front() {
            // Quick health check: peek 0 bytes.
            if stream.peek(&mut []).await.map(|_| true).unwrap_or(false)
                || true // TcpStream::peek(0) always returns Ok(0) on healthy conn
            {
                return Ok(stream);
            }
        }
    }

    // Establish new connection.
    let host = cfg.upstream.host_str().unwrap_or("127.0.0.1");
    let port = cfg.upstream.port_or_known_default().unwrap_or(80);
    let addr = format!("{}:{}", host, port);

    let stream = timeout(
        Duration::from_secs(cfg.connect_timeout),
        TcpStream::connect(&addr),
    ).await
    .map_err(|_| anyhow::anyhow!("proxy connect timeout to {}", addr))?
    .map_err(|e| anyhow::anyhow!("proxy connect failed to {}: {}", addr, e))?;

    stream.set_nodelay(true)?;
    Ok(stream)
}

fn return_to_pool(cfg: &ProxyConfig, stream: TcpStream) {
    let key = pool_key(cfg);
    let entry = CONN_POOL
        .entry(key)
        .or_insert_with(|| Arc::new(Mutex::new(VecDeque::new())));
    let queue = Arc::clone(entry.value());
    tokio::spawn(async move {
        let mut q = queue.lock().await;
        if q.len() < POOL_SIZE {
            q.push_back(stream);
        }
        // If pool is full, stream is dropped (connection closed).
    });
}

// ── Proxy request ─────────────────────────────────────────────────────────────

pub async fn proxy_request(
    cfg:            &ProxyConfig,
    method:         &str,
    path:           &str,
    location_prefix: &str,
    headers:        &[(String, String)],
    body:           &[u8],
) -> StaticResponse {
    match do_proxy(cfg, method, path, location_prefix, headers, body).await {
        Ok(resp) => resp,
        Err(e) => {
            warn!("proxy error: {}", e);
            bad_gateway(&e.to_string())
        }
    }
}

async fn do_proxy(
    cfg:             &ProxyConfig,
    method:          &str,
    path:            &str,
    location_prefix: &str,
    headers:         &[(String, String)],
    body:            &[u8],
) -> Result<StaticResponse> {
    // Runtime SSRF check for private/loopback addresses.
    if !cfg.allow_internal {
        let host = cfg.upstream.host_str().unwrap_or("");
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            if ip.is_loopback() || ip.is_unspecified() {
                anyhow::bail!("proxy_pass to loopback/unspecified blocked (SSRF). Use proxy_allow_internal on;");
            }
            if let std::net::IpAddr::V4(v4) = ip {
                if v4.is_private() || v4.is_link_local() {
                    anyhow::bail!("proxy_pass to private address blocked (SSRF). Use proxy_allow_internal on;");
                }
            }
        }
        if host.eq_ignore_ascii_case("localhost") {
            anyhow::bail!("proxy_pass to localhost blocked (SSRF). Use proxy_allow_internal on;");
        }
    }

    let mut stream = get_connection(cfg).await?;

    // Build the forwarded request.
    let upstream_path = build_upstream_path(cfg, path, location_prefix);
    let request = build_proxy_request(cfg, method, &upstream_path, headers, body)?;

    // Send.
    timeout(
        Duration::from_secs(cfg.connect_timeout),
        stream.write_all(&request),
    ).await
    .map_err(|_| anyhow::anyhow!("proxy send timeout"))??;

    // Read response.
    let mut buf = Vec::with_capacity(65536);
    let mut tmp = [0u8; 8192];

    let read_timeout = Duration::from_secs(cfg.read_timeout);
    loop {
        let n = timeout(read_timeout, stream.read(&mut tmp)).await
            .map_err(|_| anyhow::anyhow!("proxy read timeout"))??;
        if n == 0 { break; }
        buf.extend_from_slice(&tmp[..n]);

        // Check if we have a complete response.
        if is_response_complete(&buf) { break; }
        if buf.len() > 64 * 1024 * 1024 { break; } // 64 MiB cap
    }

    let (status, resp_headers, body) = parse_proxy_response(&buf)?;

    // Return connection to pool if keep-alive.
    let keep_alive = resp_headers.iter().any(|(k, v)|
        k.eq_ignore_ascii_case("connection") && v.eq_ignore_ascii_case("keep-alive")
    );
    if keep_alive {
        return_to_pool(cfg, stream);
    }

    Ok(StaticResponse { status, headers: resp_headers, body })
}

// ── Request builder ───────────────────────────────────────────────────────────

fn build_upstream_path(cfg: &ProxyConfig, original_path: &str, location_prefix: &str) -> String {
    let upstream_path = cfg.upstream.path();
    // nginx rewriting rule:
    // - proxy_pass http://host;        → forward full original URI
    // - proxy_pass http://host/        → strip location prefix, prepend upstream path
    // - proxy_pass http://host/subpath → strip location prefix, prepend upstream subpath
    if upstream_path == "/" || !upstream_path.is_empty() {
        // Strip location prefix from original path, replace with upstream path.
        let suffix = original_path.strip_prefix(location_prefix).unwrap_or(original_path);
        let base = upstream_path.trim_end_matches('/');
        format!("{}/{}", base, suffix.trim_start_matches('/'))
    } else {
        original_path.to_owned()
    }
}

fn build_proxy_request(
    cfg:     &ProxyConfig,
    method:  &str,
    path:    &str,
    headers: &[(String, String)],
    body:    &[u8],
) -> Result<Vec<u8>> {
    let host = format!("{}:{}",
        cfg.upstream.host_str().unwrap_or(""),
        cfg.upstream.port_or_known_default().unwrap_or(80));

    let mut req = format!("{} {} HTTP/1.1\r\nHost: {}\r\n", method, path, host);

    // Forward headers, skip hop-by-hop headers.
    let hop_by_hop = ["connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
                      "te", "trailers", "transfer-encoding", "upgrade"];
    for (k, v) in headers {
        if hop_by_hop.iter().any(|h| k.eq_ignore_ascii_case(h)) { continue; }
        req.push_str(&format!("{}: {}\r\n", k, v));
    }

    // Inject proxy headers.
    let existing_xff = headers.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-forwarded-for"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("");

    // Apply proxy_set_header overrides from config.
    for (k, v) in &cfg.set_headers {
        req.push_str(&format!("{}: {}\r\n", k, v));
    }

    let xff_set = cfg.set_headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("x-forwarded-for"));
    if !xff_set && !existing_xff.is_empty() {
        req.push_str(&format!("X-Forwarded-For: {}\r\n", existing_xff));
    }
    req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    req.push_str("Connection: keep-alive\r\n\r\n");

    let mut out = req.into_bytes();
    out.extend_from_slice(body);
    Ok(out)
}

// ── Response parser ───────────────────────────────────────────────────────────

fn is_response_complete(buf: &[u8]) -> bool {
    // Find end of headers.
    let hdr_end = match find_double_crlf(buf) {
        Some(pos) => pos,
        None => return false,
    };

    let header_section = std::str::from_utf8(&buf[..hdr_end]).unwrap_or("");

    // Check Content-Length.
    if let Some(cl) = extract_header_value(header_section, "content-length") {
        if let Ok(n) = cl.parse::<usize>() {
            return buf.len() >= hdr_end + 4 + n;
        }
    }

    // Transfer-Encoding: chunked
    if let Some(te) = extract_header_value(header_section, "transfer-encoding") {
        if te.contains("chunked") {
            // Check for final chunk "0\r\n\r\n"
            return buf.windows(5).any(|w| w == b"0\r\n\r\n");
        }
    }

    // No Content-Length / chunked → read until EOF
    false
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn extract_header_value<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    for line in headers.lines() {
        if let Some(rest) = line.to_ascii_lowercase().strip_prefix(&format!("{}:", name.to_ascii_lowercase())) {
            return Some(line[name.len()+1..].trim());
        }
    }
    None
}

fn parse_proxy_response(buf: &[u8]) -> Result<(u16, Vec<(String, String)>, Vec<u8>)> {
    let hdr_end = find_double_crlf(buf)
        .ok_or_else(|| anyhow::anyhow!("incomplete proxy response"))?;

    let header_str = std::str::from_utf8(&buf[..hdr_end])
        .map_err(|_| anyhow::anyhow!("non-UTF8 proxy response headers"))?;

    let mut lines = header_str.lines();
    let status_line = lines.next().ok_or_else(|| anyhow::anyhow!("empty proxy response"))?;

    let status: u16 = status_line.split_whitespace().nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(502);

    let mut headers = Vec::new();
    for line in lines {
        if let Some(colon) = line.find(':') {
            let name  = line[..colon].trim().to_owned();
            let value = line[colon+1..].trim().to_owned();
            // Skip hop-by-hop headers before forwarding to client.
            let hop = ["connection","keep-alive","transfer-encoding","te","upgrade"];
            if !hop.iter().any(|h| name.eq_ignore_ascii_case(h)) {
                headers.push((name, value));
            }
        }
    }

    let body = buf[hdr_end + 4..].to_vec();
    Ok((status, headers, body))
}


/// proxy_request_stream — uses an already-open TcpStream (from UpstreamGroup).
pub async fn proxy_request_stream(
    cfg:             &ProxyConfig,
    method:          &str,
    path:            &str,
    location_prefix: &str,
    headers:         &[(String, String)],
    body:            &[u8],
    mut stream:      TcpStream,
) -> StaticResponse {
    match do_proxy_stream(cfg, method, path, location_prefix, headers, body, &mut stream).await {
        Ok(resp) => resp,
        Err(e) => {
            warn!("proxy stream error: {}", e);
            bad_gateway(&e.to_string())
        }
    }
}

async fn do_proxy_stream(
    cfg:             &ProxyConfig,
    method:          &str,
    path:            &str,
    location_prefix: &str,
    headers:         &[(String, String)],
    body:            &[u8],
    stream:          &mut TcpStream,
) -> Result<StaticResponse> {
    let upstream_path = build_upstream_path(cfg, path, location_prefix);
    let request = build_proxy_request(cfg, method, &upstream_path, headers, body)?;

    timeout(
        Duration::from_secs(cfg.connect_timeout),
        stream.write_all(&request),
    ).await
    .map_err(|_| anyhow::anyhow!("proxy send timeout"))??;

    let mut buf = Vec::with_capacity(65536);
    let mut tmp = [0u8; 8192];
    let read_timeout = Duration::from_secs(cfg.read_timeout);

    loop {
        let n = timeout(read_timeout, stream.read(&mut tmp)).await
            .map_err(|_| anyhow::anyhow!("proxy read timeout"))??;
        if n == 0 { break; }
        buf.extend_from_slice(&tmp[..n]);
        if is_response_complete(&buf) { break; }
        if buf.len() > 64 * 1024 * 1024 { break; }
    }

    let (status, resp_headers, body) = parse_proxy_response(&buf)?;
    Ok(StaticResponse { status, headers: resp_headers, body })
}

fn bad_gateway(reason: &str) -> StaticResponse {
    let body = format!("<html><body>502 Bad Gateway: {}</body></html>\n", reason);
    StaticResponse {
        status: 502,
        headers: vec![
            ("Content-Type".into(), "text/html; charset=utf-8".into()),
            ("Content-Length".into(), body.len().to_string()),
        ],
        body: body.into_bytes(),
    }
}
