// Management REST API.
// Routes: GET /health (no auth), GET /api/stats, GET /api/system, POST /api/reload
// Auth: Bearer token (constant-time comparison via subtle crate)
// Rate limit: 30 RPS/IP (applied to authenticated endpoints only)

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use subtle::ConstantTimeEq;
use tracing::warn;

use crate::config::types::HttpBlock;
use crate::stats::{RateLimiter, Stats};

// ── API context (shared across connections) ───────────────────────────────────

pub struct ApiContext {
    pub stats:      Arc<Stats>,
    pub rate:       Arc<RateLimiter>,
    pub http:       Arc<HttpBlock>,
    pub config_path: PathBuf,
    pub reload_tx:  tokio::sync::watch::Sender<()>,
}

// ── Route dispatcher ──────────────────────────────────────────────────────────

/// Returns Some(response_bytes) if the path is an API route, None otherwise.
/// If Some, the caller should not route to static/proxy handlers.
pub fn handle_api(
    path:    &str,
    method:  &str,
    headers: &[(String, String)],
    peer_ip: IpAddr,
    ctx:     &Arc<ApiContext>,
) -> Option<Vec<u8>> {
    match path {
        "/health" => Some(health_response()),
        p if p.starts_with("/api/") => Some(handle_api_authenticated(p, method, headers, peer_ip, ctx)),
        _ => None,
    }
}

fn handle_api_authenticated(
    path:    &str,
    method:  &str,
    headers: &[(String, String)],
    peer_ip: IpAddr,
    ctx:     &Arc<ApiContext>,
) -> Vec<u8> {
    // Rate check first.
    if !ctx.rate.allow(peer_ip) {
        return json_response(429, r#"{"error":"rate limit exceeded"}"#);
    }

    // Auth check.
    if !is_authorized(headers, &ctx.http.api_key) {
        return json_response(401, r#"{"error":"unauthorized"}"#);
    }

    match (method, path) {
        ("GET",  "/api/stats")  => api_stats(ctx),
        ("GET",  "/api/system") => api_system(ctx),
        ("POST", "/api/reload") => api_reload(ctx),
        _                       => json_response(404, r#"{"error":"not found"}"#),
    }
}

// ── Auth ──────────────────────────────────────────────────────────────────────

fn is_authorized(headers: &[(String, String)], api_key: &str) -> bool {
    if api_key.is_empty() { return false; }
    let auth = headers.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    let token = auth.strip_prefix("Bearer ").unwrap_or("").trim();
    // Constant-time comparison to prevent timing attacks.
    token.as_bytes().ct_eq(api_key.as_bytes()).into()
}

// ── Endpoints ─────────────────────────────────────────────────────────────────

fn health_response() -> Vec<u8> {
    let body = r#"{"status":"ok"}"#;
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(), body
    ).into_bytes()
}

fn api_stats(ctx: &Arc<ApiContext>) -> Vec<u8> {
    let s = &ctx.stats;
    let reqs  = s.requests_total.load(std::sync::atomic::Ordering::Relaxed);
    let sent  = s.bytes_sent.load(std::sync::atomic::Ordering::Relaxed);
    let recv  = s.bytes_received.load(std::sync::atomic::Ordering::Relaxed);
    let active = s.active.load(std::sync::atomic::Ordering::Relaxed);
    let s2xx  = s.status_2xx.load(std::sync::atomic::Ordering::Relaxed);
    let s3xx  = s.status_3xx.load(std::sync::atomic::Ordering::Relaxed);
    let s4xx  = s.status_4xx.load(std::sync::atomic::Ordering::Relaxed);
    let s5xx  = s.status_5xx.load(std::sync::atomic::Ordering::Relaxed);
    let (p50, p90, p99, p999) = s.latency_percentiles();

    let body = format!(
        r#"{{"requests_total":{reqs},"bytes_sent":{sent},"bytes_received":{recv},"active_connections":{active},"status":{{"2xx":{s2xx},"3xx":{s3xx},"4xx":{s4xx},"5xx":{s5xx}}},"latency_us":{{"p50":{p50},"p90":{p90},"p99":{p99},"p99.9":{p999}}}}}"#
    );
    json_response(200, &body)
}

fn api_system(ctx: &Arc<ApiContext>) -> Vec<u8> {
    let uptime_s = ctx.stats.start.elapsed().as_secs();
    let config_path = ctx.config_path.display().to_string();
    let servers = ctx.http.servers.len();
    let version = env!("CARGO_PKG_VERSION");

    let body = format!(
        r#"{{"version":"{version}","uptime_s":{uptime_s},"config":"{config_path}","server_blocks":{servers},"simd":"{simd:?}"}}"#,
        simd = crate::simd::simd_level()
    );
    json_response(200, &body)
}

fn api_reload(ctx: &Arc<ApiContext>) -> Vec<u8> {
    let _ = ctx.reload_tx.send(());
    json_response(202, r#"{"status":"reloading"}"#)
}

// ── Serialization helper ──────────────────────────────────────────────────────

fn json_response(status: u16, body: &str) -> Vec<u8> {
    let reason = match status {
        200 => "OK", 202 => "Accepted", 401 => "Unauthorized",
        404 => "Not Found", 429 => "Too Many Requests", _ => "Error",
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nServer: RunNginx/{}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        env!("CARGO_PKG_VERSION"),
        body
    ).into_bytes()
}
