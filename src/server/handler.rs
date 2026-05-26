// Request dispatcher: parses the request, routes it, produces a response.
// Called from listener.rs once a complete HTTP/1.1 request has been buffered.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::types::{HttpBlock, LocationHandler, ReturnBody, ReturnDirective, ServerBlock};
use crate::router;
use crate::server::access_log::{LogEntry, Logger};
use crate::server::static_files;
use crate::simd::{parse_headers, parse_request_line, is_uri_safe, Header};

// ── Parsed request ─────────────────────────────────────────────────────────────

struct ParsedRequest {
    method:       String,
    path:         String,    // decoded URI path (query string stripped)
    query:        String,
    version_1_0:  bool,
    headers:      Vec<(String, String)>,
    host:         String,
    content_len:  usize,
}

// ── Public handler ────────────────────────────────────────────────────────────

pub async fn handle(
    raw:    &[u8],
    peer:   SocketAddr,
    http:   Arc<HttpBlock>,
    logger: Arc<Logger>,
) -> HandlerResult {
    // Parse request line.
    let (rl, rl_len) = match parse_request_line(raw) {
        Ok(v) => v,
        Err(e) => return HandlerResult::bad_request(e, false),
    };

    // URI security check before any parsing.
    if !is_uri_safe(rl.uri) {
        return HandlerResult::bad_request("forbidden URI sequence", false);
    }

    let method  = String::from_utf8_lossy(rl.method).into_owned();
    let version_1_0 = rl.version == b"HTTP/1.0";

    // Split path and query.
    let full_uri = String::from_utf8_lossy(rl.uri).into_owned();
    let (path, query) = if let Some(q) = full_uri.find('?') {
        (full_uri[..q].to_owned(), full_uri[q+1..].to_owned())
    } else {
        (full_uri, String::new())
    };

    // Parse headers.
    let (raw_headers, _) = match parse_headers(&raw[rl_len..]) {
        Ok(v) => v,
        Err(e) => return HandlerResult::bad_request(e, false),
    };

    let headers: Vec<(String, String)> = raw_headers.iter().map(|h: &Header| {
        (
            String::from_utf8_lossy(h.name).into_owned(),
            String::from_utf8_lossy(h.value).into_owned(),
        )
    }).collect();

    let host = get_header(&headers, "host").unwrap_or("").to_owned();
    let content_len = get_header(&headers, "content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let keep_alive = !version_1_0
        && get_header(&headers, "connection")
            .map(|v| !v.eq_ignore_ascii_case("close"))
            .unwrap_or(true);

    let req = ParsedRequest { method, path, query, version_1_0, headers, host, content_len };

    // Route to server block.
    // select_server borrows from the slice so bind it first.
    let servers_arc: Vec<Arc<ServerBlock>> = http.servers.iter().map(|s| Arc::new(s.clone())).collect();
    let server = router::select_server(&servers_arc, &req.host);
    let location = router::select_location(server, &req.path);

    // Apply return directive if present.
    let return_dir = location
        .and_then(|l| l.return_directive.as_ref())
        .or(server.return_directive.as_ref());
    if let Some(rd) = return_dir {
        return handle_return(rd, keep_alive);
    }

    // Dispatch to handler.
    let response = match location.map(|l| &l.handler) {
        Some(LocationHandler::Return(rd)) => {
            return handle_return(rd, keep_alive);
        }
        Some(LocationHandler::Static) | None => {
            let resp = static_files::serve_static(
                server,
                location,
                &req.path,
                &req.method,
                &req.headers,
            ).await;
            resp
        }
        Some(LocationHandler::Proxy(_pc)) => {
            // Phase 3.
            static_files::not_implemented("proxy_pass not yet implemented")
        }
        Some(LocationHandler::FastCgi(_fc)) => {
            // Phase 3.
            static_files::not_implemented("fastcgi_pass not yet implemented")
        }
    };

    // Collect response headers.
    let status = response.status;
    let body_len = response.body.len();

    // Access log.
    logger.log(LogEntry {
        remote_addr:  peer,
        request_line: format!("{} {} HTTP/1.{}", req.method, req.path, if req.version_1_0 { "0" } else { "1" }),
        status,
        body_bytes:   body_len,
        referer:      get_header(&req.headers, "referer").unwrap_or("-").to_owned(),
        user_agent:   get_header(&req.headers, "user-agent").unwrap_or("-").to_owned(),
    });

    // Serialize response.
    let mut out = format_response(
        status,
        &response.headers,
        keep_alive,
        &response.body,
    );

    HandlerResult {
        bytes:      out,
        keep_alive,
    }
}

// ── Return directive ──────────────────────────────────────────────────────────

fn handle_return(rd: &ReturnDirective, keep_alive: bool) -> HandlerResult {
    let (body_str, location_hdr) = match &rd.body {
        ReturnBody::Empty => (String::new(), None),
        ReturnBody::Text(t) => (t.clone(), None),
        ReturnBody::Url(u) => (String::new(), Some(u.clone())),
    };

    let body = body_str.as_bytes().to_vec();
    let mut headers = vec![
        ("Content-Length".to_owned(), body.len().to_string()),
    ];
    if let Some(loc) = location_hdr {
        headers.push(("Location".to_owned(), loc));
    }
    if !body.is_empty() {
        headers.push(("Content-Type".to_owned(), "text/plain".to_owned()));
    }

    HandlerResult {
        bytes: format_response(rd.status, &headers, keep_alive, &body),
        keep_alive,
    }
}

// ── Response serialization ────────────────────────────────────────────────────

fn format_response(
    status:     u16,
    headers:    &[(String, String)],
    keep_alive: bool,
    body:       &[u8],
) -> Vec<u8> {
    let reason = status_reason(status);
    let mut out = format!("HTTP/1.1 {} {}\r\n", status, reason);
    out.push_str("Server: RunNginx/0.1.0\r\n");
    for (k, v) in headers {
        out.push_str(&format!("{}: {}\r\n", k, v));
    }
    out.push_str(if keep_alive { "Connection: keep-alive\r\n" } else { "Connection: close\r\n" });
    out.push_str("\r\n");

    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn status_reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Content Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _   => "Unknown",
    }
}

// ── Public result type ────────────────────────────────────────────────────────

pub struct HandlerResult {
    pub bytes:      Vec<u8>,
    pub keep_alive: bool,
}

impl HandlerResult {
    pub fn bad_request(reason: &str, keep_alive: bool) -> Self {
        let body = format!("Bad Request: {}\r\n", reason);
        let headers = vec![
            ("Content-Type".to_owned(), "text/plain".to_owned()),
            ("Content-Length".to_owned(), body.len().to_string()),
        ];
        Self {
            bytes: format_response(400, &headers, keep_alive, body.as_bytes()),
            keep_alive,
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn get_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}
