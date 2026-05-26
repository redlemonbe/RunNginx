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
use subtle::ConstantTimeEq;

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
    pub zones:          Arc<crate::limit_req::ZoneRegistry>,
    pub challenge_store:    Arc<crate::acme::ChallengeStore>,
    pub upstream_registry: Arc<crate::upstream::UpstreamRegistry>,
    pub cache:             Arc<crate::cache::ResponseCache>,
    pub user_registry:     Arc<crate::multiuser::UserRegistry>,
    pub bw_tracker:        Arc<crate::multiuser::BandwidthTracker>,
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
        (full_uri.clone(), String::new())
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

    // Serve ACME HTTP-01 challenge tokens.
    // Cache lookup (GET/HEAD only, respects Cache-Control).
    if matches!(method.as_str(), "GET" | "HEAD") {
        let skip = crate::cache::request_bypasses_cache(&headers);
        if !skip {
            let key = crate::cache::ResponseCache::cache_key(&host, &method, &full_uri);
            if let Some(bytes) = ctx.cache.get(&key) {
                ctx.stats.record_request(200, bytes.len() as u64, raw.len() as u64, std::time::Duration::ZERO);
                return HandlerResult {
                    bytes: bytes.as_ref().clone(),
                    keep_alive: true,
                    status: 200,
                    tunnel: None,
                };
            }
        }
    }

    if let Some(stripped) = path.strip_prefix("/.well-known/acme-challenge/") {
        if let Some(key_auth) = ctx.challenge_store.get_key_auth(stripped) {
            let body = key_auth.into_bytes();
            let hdrs = [
                ("Content-Type".to_owned(), "application/octet-stream".to_owned()),
                ("Content-Length".to_owned(), body.len().to_string()),
            ];
            return HandlerResult {
                bytes: format_response(200, &hdrs, false, &body),
                keep_alive: false,
                status: 200,
                tunnel: None,
            };
        }
    }

    // Multi-user API (POST /api/users, GET /api/users/me, etc.)
    let auth_header_val = get_header(&headers, "authorization")
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(|k| k.trim().to_owned())
        .unwrap_or_default();
    let is_admin = !ctx.http.api_key.is_empty() && bool::from(auth_header_val.as_bytes().ct_eq(ctx.http.api_key.as_bytes()));
    if let Some(bytes) = crate::multiuser::handle_user_api(&path, &method, body_raw, &auth_header_val, &ctx.user_registry, is_admin) {
        let status = extract_status_from_response(&bytes);
        ctx.logger.log(LogEntry {
            remote_addr: peer, request_line: format!("{} {} HTTP/1.1", method, path),
            status, body_bytes: bytes.len(),
            referer: get_header(&headers, "referer").unwrap_or("-").to_owned(),
            user_agent: get_header(&headers, "user-agent").unwrap_or("-").to_owned(),
        });
        return HandlerResult { bytes, keep_alive: false, status, tunnel: None };
    }

    // Check if this is an API request before routing to server blocks.
    if let Some(api_bytes) = api::handle_api(&path, &query, &method, &headers, peer.ip(), &ctx.api_ctx) {
        // API endpoints always close the connection.
        ctx.logger.log(LogEntry {
            remote_addr:  peer,
            request_line: format!("{} {} HTTP/1.{}", method, path, if version_1_0 { "0" } else { "1" }),
            status:       extract_status_from_response(&api_bytes),
            body_bytes:   api_bytes.len(),
            referer:      get_header(&headers, "referer").unwrap_or("-").to_owned(),
            user_agent:   get_header(&headers, "user-agent").unwrap_or("-").to_owned(),
        });
        let api_status = extract_status_from_response(&api_bytes);
        return HandlerResult { bytes: api_bytes, keep_alive: false, status: api_status, tunnel: None };
    }

    let mut req = ParsedRequest {
        method, path, _query: query, version_1_0, headers, host, content_len,
    };

    // Route to server block.
    let servers_arc: Vec<Arc<ServerBlock>> = ctx.http.servers.iter()
        .map(|s| Arc::new(s.clone()))
        .collect();
    let server   = router::select_server(&servers_arc, &req.host);

    // Apply server-level rewrite rules.
    let srv_rewrites = &server.rewrites;
    if !srv_rewrites.is_empty() {
        match crate::rewrite::apply_rewrites(srv_rewrites, &req.path) {
            crate::rewrite::RewriteOutcome::Redirect { uri, status } => {
                let r = HandlerResult {
                    bytes: format_response(status, &[
                        ("Location".to_owned(), uri),
                        ("Content-Length".to_owned(), "0".to_owned()),
                    ], keep_alive, &[]),
                    keep_alive, status, tunnel: None,
                };
                log_request(&req, &r, peer, &ctx.logger);
                return r;
            }
            crate::rewrite::RewriteOutcome::Rewritten { uri, .. } => {
                req.path = uri;
            }
            crate::rewrite::RewriteOutcome::NoMatch => {}
        }
    }

    let location = router::select_location(server, &req.path);

    // Apply location-level rewrite rules.
    if let Some(loc) = location {
        if !loc.rewrites.is_empty() {
            match crate::rewrite::apply_rewrites(&loc.rewrites, &req.path) {
                crate::rewrite::RewriteOutcome::Redirect { uri, status } => {
                    let r = HandlerResult {
                        bytes: format_response(status, &[
                            ("Location".to_owned(), uri),
                            ("Content-Length".to_owned(), "0".to_owned()),
                        ], keep_alive, &[]),
                        keep_alive, status, tunnel: None,
                    };
                    log_request(&req, &r, peer, &ctx.logger);
                    return r;
                }
                crate::rewrite::RewriteOutcome::Rewritten { uri, .. } => {
                    req.path = uri;
                }
                crate::rewrite::RewriteOutcome::NoMatch => {}
            }
        }
    }

    // Auth basic — location takes priority over server.
    let auth_cfg = location.and_then(|l| l.auth_basic.as_ref())
        .or(server.auth_basic.as_ref());
    if let Some(ab) = auth_cfg {
        let auth_header = get_header(&req.headers, "authorization");
        let authorized = auth_header
            .map(|h| crate::auth::check_basic_auth(&ab.user_file, h))
            .unwrap_or(false);
        if !authorized {
            let bytes = crate::auth::unauthorized_response(&ab.realm);
            let status = 401u16;
            ctx.logger.log(LogEntry {
                remote_addr: peer,
                request_line: format!("{} {} HTTP/1.1", req.method, req.path),
                status, body_bytes: bytes.len(),
                referer: get_header(&req.headers, "referer").unwrap_or("-").to_owned(),
                user_agent: get_header(&req.headers, "user-agent").unwrap_or("-").to_owned(),
            });
            return HandlerResult { bytes, keep_alive, status, tunnel: None };
        }
    }

    // Per-location rate limit (limit_req).
    let limit_ref = location
        .and_then(|l| l.limit_req.as_ref())
        .or(server.limit_req.as_ref());
    if let Some(lr) = limit_ref {
        if let Some(zone) = ctx.zones.get(&lr.zone) {
            if !zone.allow(peer.ip(), lr.burst) {
                let r = HandlerResult {
                    bytes: format_response(429, &[
                        ("Content-Type".to_owned(), "text/plain".to_owned()),
                        ("Content-Length".to_owned(), "19".to_owned()),
                        ("Retry-After".to_owned(), "1".to_owned()),
                    ], false, b"429 Too Many Requests"),
                    keep_alive: false,
                    status: 429,
                    tunnel: None,
                };
                log_request(&req, &r, peer, &ctx.logger);
                return r;
            }
        }
    }

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
            tunnel: None,
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
            // WebSocket upgrade — splice TCP streams instead of buffered proxy.
            let is_ws_upgrade = req.headers.iter().any(|(k, v)|
                k.eq_ignore_ascii_case("upgrade") && v.eq_ignore_ascii_case("websocket")
            );
            if is_ws_upgrade {
                let host = pc.upstream.host_str().unwrap_or("127.0.0.1");
                let port = pc.upstream.port_or_known_default().unwrap_or(80);
                let addr = format!("{}:{}", host, port);
                let ct = std::time::Duration::from_secs(pc.connect_timeout);
                let rt = std::time::Duration::from_secs(pc.read_timeout);
                match crate::websocket::upgrade_to_websocket(&addr, ct, rt, &req.method, &req.path, &req.headers).await {
                    Ok((resp_bytes, upstream)) => {
                        let status = 101u16;
                        ctx.logger.log(crate::server::access_log::LogEntry {
                            remote_addr: peer,
                            request_line: format!("{} {} HTTP/1.1", req.method, req.path),
                            status,
                            body_bytes: 0,
                            referer: get_header(&req.headers, "referer").unwrap_or("-").to_owned(),
                            user_agent: get_header(&req.headers, "user-agent").unwrap_or("-").to_owned(),
                        });
                        return HandlerResult { bytes: resp_bytes, keep_alive: false, status, tunnel: Some(upstream) };
                    }
                    Err(e) => {
                        tracing::warn!("websocket upgrade failed: {}", e);
                        return HandlerResult {
                            bytes: format_response(502, &[("Content-Length".to_owned(),"0".to_owned())], false, &[]),
                            keep_alive: false,
                            status: 502,
                            tunnel: None,
                        };
                    }
                }
            }
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
        Some(LocationHandler::UpstreamGroup(group_name)) => {
            match ctx.upstream_registry.get(group_name) {
                Some(group) => {
                    let connect_to = std::time::Duration::from_secs(10);
                    match group.connect(connect_to, Some(peer.ip())).await {
                        Ok((stream, peer_addr)) => {
                            let prefix = match location.map(|l| &l.pattern) {
                                Some(crate::config::types::LocationPattern::Prefix(p)) => p.as_str(),
                                Some(crate::config::types::LocationPattern::PrefixNoRegex(p)) => p.as_str(),
                                _ => "",
                            };
                            let pc = crate::config::types::ProxyConfig {
                                upstream: url::Url::parse(&format!("http://{}", peer_addr)).unwrap(),
                                set_headers: Vec::new(),
                                read_timeout: 60,
                                connect_timeout: 10,
                                buffering: true,
                                http2: false,
                                allow_internal: true,
                            };
                            let resp = crate::proxy::proxy_request_stream(
                                &pc, &req.method, &req.path, prefix, &req.headers, body_raw, stream
                            ).await;
                            group.release(peer_addr);
                            resp
                        }
                        Err(e) => {
                            tracing::warn!("upstream {}: {}", group_name, e);
                            crate::server::static_files::not_implemented("502 upstream unavailable")
                        }
                    }
                }
                None => crate::server::static_files::not_implemented("upstream group not found"),
            }
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

    // Apply brotli if gzip was not applied (prefer br over gzip when client accepts both).
    let br_cfg = crate::http::brotli::BrotliConfig {
        enabled:    ctx.http.brotli,
        min_length: ctx.http.brotli_min_length,
        types:      ctx.http.brotli_types.clone(),
    };
    let (body, brotli_used) = if !gzipped {
        crate::http::brotli::maybe_brotli(body, content_type, accept_enc, &br_cfg)
    } else {
        (body, false)
    };

    let mut hdrs = response.headers;
    if gzipped {
        hdrs.push(("Content-Encoding".to_owned(), "gzip".to_owned()));
        if let Some(pos) = hdrs.iter().position(|(k, _)| k.eq_ignore_ascii_case("content-length")) {
            hdrs[pos] = ("Content-Length".to_owned(), body.len().to_string());
        }
    } else if brotli_used {
        hdrs.push(("Content-Encoding".to_owned(), "br".to_owned()));
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

    // Store cacheable responses.
    if crate::cache::is_cacheable(&req.method, status, &hdrs) {
        if !crate::cache::request_bypasses_cache(&req.headers) {
            let key = crate::cache::ResponseCache::cache_key(&req.host, &req.method, &req.path);
            ctx.cache.put(key, bytes.clone(), status);
        }
    }

    HandlerResult { bytes, keep_alive, status, tunnel: None }
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
    HandlerResult { bytes, keep_alive, status: rd.status, tunnel: None }
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
    /// WebSocket tunnel: if Some, listener should splice streams after writing bytes.
    pub tunnel:     Option<tokio::net::TcpStream>,
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
            tunnel: None,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_response_200() {
        let hdrs = vec![
            ("Content-Type".to_owned(), "text/plain".to_owned()),
            ("Content-Length".to_owned(), "5".to_owned()),
        ];
        let bytes = format_response(200, &hdrs, false, b"hello");
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("Content-Type: text/plain\r\n"));
        assert!(s.contains("Connection: close\r\n"));
        assert!(s.ends_with("hello"));
    }

    #[test]
    fn format_response_keepalive() {
        let bytes = format_response(204, &[], true, b"");
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains("Connection: keep-alive\r\n"));
    }

    #[test]
    fn format_response_404() {
        let bytes = format_response(404, &[], false, b"");
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.starts_with("HTTP/1.1 404 Not Found\r\n"));
    }

    #[test]
    fn bad_request_is_400() {
        let r = HandlerResult::bad_request("test", false);
        assert_eq!(r.status, 400);
        let s = std::str::from_utf8(&r.bytes).unwrap();
        assert!(s.contains("400 Bad Request"));
        assert!(s.contains("test"));
    }

    #[test]
    fn extract_status_200() {
        assert_eq!(extract_status_from_response(b"HTTP/1.1 200 OK\r\n\r\n"), 200);
    }

    #[test]
    fn extract_status_404() {
        assert_eq!(extract_status_from_response(b"HTTP/1.1 404 Not Found\r\n\r\n"), 404);
    }

    #[test]
    fn extract_status_empty_defaults_200() {
        assert_eq!(extract_status_from_response(b""), 200);
    }
}

