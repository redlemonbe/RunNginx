// Request dispatcher: parses the request, routes it, produces a response.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use crate::api::{self, ApiContext};
use crate::http::gzip::{GzipConfig, maybe_compress};
use crate::config::types::{HttpBlock, LocationHandler, ReturnBody, ReturnDirective, ServerBlock};
use crate::router;
use crate::server::access_log::{LogEntry, Logger};
use crate::server::static_files::{self, find_error_page_uri};
use crate::simd::{parse_headers, parse_request_line, is_uri_safe, Header};
use crate::stats::Stats;

// ── Parsed request ─────────────────────────────────────────────────────────────

struct ParsedRequest {
    method:      String,
    path:        String,
    _query:      String,
    version_1_0: bool,
    headers:     Vec<(String, String)>,
    host:        String,
    content_len: usize,
}

// ── Public handler ────────────────────────────────────────────────────────────

pub struct HandlerContext {
    pub http:    Arc<HttpBlock>,
    pub logger:  Arc<Logger>,
    pub stats:   Arc<Stats>,
    pub api_ctx: Arc<ApiContext>,
}

pub async fn handle(
    raw:  &[u8],
    peer: SocketAddr,
    ctx:  Arc<HandlerContext>,
) -> HandlerResult {
    let t0 = Instant::now();
    ctx.stats.active.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let result = dispatch(raw, peer, &ctx).await;

    ctx.stats.active.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    ctx.stats.record_request(
        result.status,
        result.bytes.len() as u64,
        raw.len() as u64,
        t0.elapsed(),
    );

    result
}

async fn dispatch(
    raw:  &[u8],
    peer: SocketAddr,
    ctx:  &Arc<HandlerContext>,
) -> HandlerResult {
    // Parse request line.
    let (rl, rl_len) = match parse_request_line(raw) {
        Ok(v) => v,
        Err(e) => return HandlerResult::bad_request(e, false),
    };

    if !is_uri_safe(rl.uri) {
        return HandlerResult::bad_request("forbidden URI sequence", false);
    }

    let method      = String::from_utf8_lossy(rl.method).into_owned();
    let version_1_0 = rl.version == b"HTTP/1.0";

    let full_uri = String::from_utf8_lossy(rl.uri).into_owned();
    let (path, query) = if let Some(q) = full_uri.find('?') {
        (full_uri[..q].to_owned(), full_uri[q+1..].to_owned())
    } else {
        (full_uri, String::new())
    };

    let (raw_headers, headers_len) = match parse_headers(&raw[rl_len..]) {
        Ok(v) => v,
        Err(e) => return HandlerResult::bad_request(e, false),
    };

    let headers: Vec<(String, String)> = raw_headers.iter().map(|h: &Header| {
        (
            String::from_utf8_lossy(h.name).into_owned(),
            String::from_utf8_lossy(h.value).into_owned(),
        )
    }).collect();

    let host        = get_header(&headers, "host").unwrap_or("").to_owned();
    let content_len = get_header(&headers, "content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let keep_alive = !version_1_0
        && get_header(&headers, "connection")
            .map(|v| !v.eq_ignore_ascii_case("close"))
            .unwrap_or(true);

    // Extract body bytes (everything after the header section).
    let body_offset = rl_len + headers_len;
    let body_raw: &[u8] = if body_offset < raw.len() {
        let remaining = &raw[body_offset..];
        &remaining[..remaining.len().min(content_len)]
    } else {
        &[]
    };

    // Check if this is an API request before routing to server blocks.
    if let Some(api_bytes) = api::handle_api(&path, &method, &headers, peer.ip(), &ctx.api_ctx) {
        // API endpoints always close the connection.
        ctx.logger.log(LogEntry {
            remote_addr:  peer,
            request_line: format!("{} {} HTTP/1.{}", method, path, if version_1_0 { "0" } else { "1" }),
            status:       extract_status_from_response(&api_bytes),
            body_bytes:   api_bytes.len(),
            referer:      get_header(&headers, "referer").unwrap_or("-").to_owned(),
            user_agent:   get_header(&headers, "user-agent").unwrap_or("-").to_owned(),
        });
        return HandlerResult { bytes: api_bytes, keep_alive: false, status: 200 };
    }

    let req = ParsedRequest {
        method, path, _query: query, version_1_0, headers, host, content_len,
    };

    // Route to server block.
    let servers_arc: Vec<Arc<ServerBlock>> = ctx.http.servers.iter()
        .map(|s| Arc::new(s.clone()))
        .collect();
    let server   = router::select_server(&servers_arc, &req.host);
    let location = router::select_location(server, &req.path);

    // Enforce client_max_body_size.
    let max_body = location
        .and_then(|l| l.client_max_body_size)
        .or(server.client_max_body_size)
        .unwrap_or(ctx.http.client_max_body_size);
    if req.content_len > max_body {
        let r = HandlerResult {
            bytes: format_response(413, &[
                ("Content-Type".to_owned(), "text/plain".to_owned()),
                ("Content-Length".to_owned(), "22".to_owned()),
            ], keep_alive, b"413 Content Too Large"),
            keep_alive: false,
            status: 413,
        };
        log_request(&req, &r, peer, &ctx.logger);
        return r;
    }

    // Apply return directive.
    let return_dir = location
        .and_then(|l| l.return_directive.as_ref())
        .or(server.return_directive.as_ref());
    if let Some(rd) = return_dir {
        let r = handle_return(rd, keep_alive);
        log_request(&req, &r, peer, &ctx.logger);
        return r;
    }

    // Dispatch to handler.
    let response = match location.map(|l| &l.handler) {
        Some(LocationHandler::Return(rd)) => {
            let r = handle_return(rd, keep_alive);
            log_request(&req, &r, peer, &ctx.logger);
            return r;
        }
        Some(LocationHandler::Static) | None => {
            let mut resp = static_files::serve_static(server, location, &req.path, &req.method, &req.headers).await;
            // Apply custom error page if configured.
            if resp.status >= 400 {
                if let Some(ep_uri) = find_error_page_uri(server, resp.status) {
                    let ep_path = ep_uri.to_owned();
                    let ep_resp = static_files::serve_static(server, None, &ep_path, "GET", &[]).await;
                    if ep_resp.status == 200 {
                        // Serve the error page with the original error status.
                        resp.body    = ep_resp.body;
                        resp.headers = ep_resp.headers;
                    }
                }
            }
            resp
        }
        Some(LocationHandler::Proxy(pc)) => {
            let prefix = match location.map(|l| &l.pattern) {
                Some(crate::config::types::LocationPattern::Prefix(p)) => p.as_str(),
                Some(crate::config::types::LocationPattern::PrefixNoRegex(p)) => p.as_str(),
                _ => "",
            };
            crate::proxy::proxy_request(
                pc,
                &req.method,
                &req.path,
                prefix,
                &req.headers,
                &[],
            ).await
        }
        Some(LocationHandler::FastCgi(fc)) => {
            let root = location
                .and_then(|l| l.root.as_deref())
                .or(server.root.as_deref());
            let root_str = root
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|| "/var/www/html".to_owned());
            let script_rel = req.path.trim_start_matches('/');
            let mut script_path = format!("{}/{}", root_str.trim_end_matches('/'), script_rel);
            let index = fc.index.as_deref().unwrap_or("index.php");
            if req.path.ends_with('/') || !std::path::Path::new(&script_path).extension().is_some() {
                script_path = format!("{}/{}", script_path.trim_end_matches('/'), index);
            }
            crate::fastcgi::fastcgi_request(fc, &req.method, &req.path, &script_path, &req.headers, body_raw).await
        }
    };

    let status   = response.status;

    // Apply gzip if configured and applicable.
    let gzip_enabled = location.and_then(|l| l.gzip).unwrap_or(ctx.http.gzip);
    let accept_enc = get_header(&req.headers, "accept-encoding");
    let content_type = response.headers.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("application/octet-stream");
    let gz_cfg = GzipConfig {
        enabled:    gzip_enabled,
        min_length: ctx.http.gzip_min_length,
        types:      ctx.http.gzip_types.clone(),
    };
    let (body, gzipped) = maybe_compress(response.body, content_type, accept_enc, &gz_cfg);

    let mut hdrs = response.headers;
    if gzipped {
        hdrs.push(("Content-Encoding".to_owned(), "gzip".to_owned()));
        // Update Content-Length to compressed size.
        if let Some(pos) = hdrs.iter().position(|(k, _)| k.eq_ignore_ascii_case("content-length")) {
            hdrs[pos] = ("Content-Length".to_owned(), body.len().to_string());
        }
    }

    let body_len = body.len();
    ctx.logger.log(LogEntry {
        remote_addr:  peer,
        request_line: format!("{} {} HTTP/1.{}", req.method, req.path, if req.version_1_0 { "0" } else { "1" }),
        status,
        body_bytes:   body_len,
        referer:      get_header(&req.headers, "referer").unwrap_or("-").to_owned(),
        user_agent:   get_header(&req.headers, "user-agent").unwrap_or("-").to_owned(),
    });

    let bytes = format_response(status, &hdrs, keep_alive, &body);
    HandlerResult { bytes, keep_alive, status }
}

// ── Return directive ──────────────────────────────────────────────────────────

fn handle_return(rd: &ReturnDirective, keep_alive: bool) -> HandlerResult {
    let (body_str, location_hdr) = match &rd.body {
        ReturnBody::Empty  => (String::new(), None),
        ReturnBody::Text(t) => (t.clone(), None),
        ReturnBody::Url(u)  => (String::new(), Some(u.clone())),
    };
    let body = body_str.as_bytes().to_vec();
    let mut hdrs = vec![("Content-Length".to_owned(), body.len().to_string())];
    if let Some(loc) = location_hdr { hdrs.push(("Location".to_owned(), loc)); }
    if !body.is_empty() { hdrs.push(("Content-Type".to_owned(), "text/plain".to_owned())); }
    let bytes = format_response(rd.status, &hdrs, keep_alive, &body);
    HandlerResult { bytes, keep_alive, status: rd.status }
}

// ── Response serialization ────────────────────────────────────────────────────

pub fn format_response(
    status:     u16,
    headers:    &[(String, String)],
    keep_alive: bool,
    body:       &[u8],
) -> Vec<u8> {
    let reason = status_reason(status);
    let mut out = format!("HTTP/1.1 {} {}\r\nServer: RunNginx/{}\r\n",
        status, reason, env!("CARGO_PKG_VERSION"));
    for (k, v) in headers { out.push_str(&format!("{}: {}\r\n", k, v)); }
    out.push_str(if keep_alive { "Connection: keep-alive\r\n" } else { "Connection: close\r\n" });
    out.push_str("\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn status_reason(code: u16) -> &'static str {
    match code {
        200 => "OK", 206 => "Partial Content", 301 => "Moved Permanently",
        302 => "Found", 304 => "Not Modified", 307 => "Temporary Redirect",
        308 => "Permanent Redirect", 400 => "Bad Request", 401 => "Unauthorized",
        403 => "Forbidden", 404 => "Not Found", 405 => "Method Not Allowed",
        408 => "Request Timeout", 413 => "Content Too Large",
        429 => "Too Many Requests", 500 => "Internal Server Error",
        501 => "Not Implemented", 502 => "Bad Gateway", 503 => "Service Unavailable",
        _ => "Unknown",
    }
}

// ── Public result type ────────────────────────────────────────────────────────

pub struct HandlerResult {
    pub bytes:      Vec<u8>,
    pub keep_alive: bool,
    pub status:     u16,
}

impl HandlerResult {
    pub fn bad_request(reason: &str, keep_alive: bool) -> Self {
        let body = format!("Bad Request: {}\r\n", reason);
        let hdrs = vec![
            ("Content-Type".to_owned(), "text/plain".to_owned()),
            ("Content-Length".to_owned(), body.len().to_string()),
        ];
        Self {
            bytes: format_response(400, &hdrs, keep_alive, body.as_bytes()),
            keep_alive,
            status: 400,
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn get_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn log_request(req: &ParsedRequest, result: &HandlerResult, peer: SocketAddr, logger: &Logger) {
    logger.log(LogEntry {
        remote_addr:  peer,
        request_line: format!("{} {} HTTP/1.{}", req.method, req.path, if req.version_1_0 { "0" } else { "1" }),
        status:       result.status,
        body_bytes:   result.bytes.len(),
        referer:      get_header(&req.headers, "referer").unwrap_or("-").to_owned(),
        user_agent:   get_header(&req.headers, "user-agent").unwrap_or("-").to_owned(),
    });
}

fn extract_status_from_response(bytes: &[u8]) -> u16 {
    // "HTTP/1.1 NNN ..." — extract the 3-digit status
    let s = std::str::from_utf8(bytes).unwrap_or("");
    s.split_whitespace().nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(200)
}
