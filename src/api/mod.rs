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
    pub log_ring:   crate::server::access_log::LogRing,
}

// ── Route dispatcher ──────────────────────────────────────────────────────────

/// Returns Some(response_bytes) if the path is an API route, None otherwise.
/// If Some, the caller should not route to static/proxy handlers.
const WEBUI_HTML: &str = include_str!("webui.html");

fn serve_webui() -> Vec<u8> {
    let body = WEBUI_HTML.as_bytes();
    let mut r = format!(
        "HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: {}
Cache-Control: no-cache
Connection: keep-alive

",
        body.len()
    ).into_bytes();
    r.extend_from_slice(body);
    r
}

pub fn handle_api(
    path:    &str,
    query:   &str,
    method:  &str,
    headers: &[(String, String)],
    body:    &[u8],
    peer_ip: IpAddr,
    ctx:     &Arc<ApiContext>,
) -> Option<Vec<u8>> {
    match path {
        "/health"  => Some(health_response()),
        "/metrics" => Some(prometheus_metrics(ctx)),
        "/ui" | "/ui/" => Some(serve_webui()),
        p if p.starts_with("/api/") => Some(handle_api_authenticated(p, query, method, headers, body, peer_ip, ctx)),
        _ => None,
    }
}

fn handle_api_authenticated(
    path:    &str,
    query:   &str,
    method:  &str,
    headers: &[(String, String)],
    body:    &[u8],
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

    let body_str = String::from_utf8_lossy(body);
    match (method, path) {
        ("GET",  "/api/stats")  => api_stats(ctx),
        ("GET",  "/api/system") => api_system(ctx),
        ("POST", "/api/reload") => api_reload(ctx),
        ("GET",  "/api/logs")   => api_logs(query, ctx),
        ("POST", "/api/backup") => api_backup(ctx, &body_str),
        ("GET",  "/api/backups") => api_list_backups(ctx),
        ("POST", "/api/restore") => api_restore(ctx, &body_str),
        (_, p) if method == "DELETE" && p.starts_with("/api/backups/") => {
            api_delete_backup(ctx, &p["/api/backups/".len()..])
        }
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

fn api_logs(query: &str, ctx: &Arc<ApiContext>) -> Vec<u8> {
    let n: usize = query.split('&')
        .find_map(|kv| {
            let mut p = kv.splitn(2, '=');
            if p.next()? == "n" { p.next()?.parse().ok() } else { None }
        })
        .unwrap_or(100)
        .min(500);

    let lines = {
        let ring = ctx.log_ring.lock().unwrap();
        let skip = ring.len().saturating_sub(n);
        ring.iter().skip(skip).cloned().collect::<Vec<_>>()
    };

    let body = serde_json::json!({"lines": lines, "total": lines.len()});
    let body_bytes = body.to_string();
    let mut r = format!(
        "HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: {}
Connection: close

",
        body_bytes.len()
    );
    r.push_str(&body_bytes);
    r.into_bytes()
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

    let uptime = s.start.elapsed().as_secs();
    let p50_s = p50 as f64 / 1_000_000.0;
    let p99_s = p99 as f64 / 1_000_000.0;
    let version = env!("CARGO_PKG_VERSION");
    let body = format!(
        r#"{{"version":"{version}","requests_total":{reqs},"bytes_sent":{sent},"bytes_received":{recv},"active_connections":{active},"status_2xx":{s2xx},"status_3xx":{s3xx},"status_4xx":{s4xx},"status_5xx":{s5xx},"latency_us":{{"p50":{p50},"p90":{p90},"p99":{p99},"p99.9":{p999}}},"p50_s":{p50_s:.6},"p99_s":{p99_s:.6},"uptime_seconds":{uptime}}}"#
    );
    json_response(200, &body)
}

fn api_system(ctx: &Arc<ApiContext>) -> Vec<u8> {
    let uptime_s = ctx.stats.start.elapsed().as_secs();
    let config_path = ctx.config_path.display().to_string();
    let servers = ctx.http.servers.len();
    let version = env!("CARGO_PKG_VERSION");
    let simd = crate::simd::simd_level();

    // Build upstream groups list.
    let upstream_groups: Vec<String> = ctx.http.upstream_groups.iter().map(|g| {
        let peers: Vec<String> = g.peers.iter().map(|(a, _)| {
            let mut s = String::new(); s.push('"'); s.push_str(a); s.push('"'); s
        }).collect();
        format!(r#"{{"name":"{}","policy":"{}","peers":[{}],"health_interval":{}}}"#,
            g.name, g.policy, peers.join(","), g.health_interval)
    }).collect();

    let body = format!(
        r#"{{"version":"{version}","uptime_s":{uptime_s},"uptime_seconds":{uptime_s},"config":"{config_path}","servers":{servers},"server_blocks":{servers},"simd":"{simd:?}","upstream_groups":[{ug}]}}"#,
        ug = upstream_groups.join(",")
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
        200 => "OK", 202 => "Accepted", 400 => "Bad Request",
        401 => "Unauthorized", 404 => "Not Found",
        429 => "Too Many Requests", 500 => "Internal Server Error", _ => "Error",
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nServer: RunNginx/{}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        env!("CARGO_PKG_VERSION"),
        body
    ).into_bytes()
}


// ── Backup / Restore ─────────────────────────────────────────────────────────

fn backup_dir(ctx: &Arc<ApiContext>) -> std::path::PathBuf {
    ctx.config_path.parent()
        .unwrap_or_else(|| std::path::Path::new("/etc/runnginx"))
        .join("backups")
}

fn api_backup(ctx: &Arc<ApiContext>, body: &str) -> Vec<u8> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let label = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v["label"].as_str().map(|s| s.to_owned()))
        .filter(|s| !s.is_empty() && s.len() <= 32
            && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
        .unwrap_or_default();

    let dir_name = if label.is_empty() {
        format!("backup_{ts}")
    } else {
        format!("backup_{ts}_{label}")
    };

    let bdir = backup_dir(ctx).join(&dir_name);
    if let Err(e) = std::fs::create_dir_all(&bdir) {
        return json_response(500, &format!(r#"{{"error":"cannot create backup dir: {e}"}}"#));
    }

    // Copy config file
    if let Err(e) = std::fs::copy(&ctx.config_path, bdir.join("runnginx.conf")) {
        return json_response(500, &format!(r#"{{"error":"config copy failed: {e}"}}"#));
    }

    // Copy users.toml if present
    let users_path = ctx.config_path.parent()
        .unwrap_or_else(|| std::path::Path::new("/etc/runnginx"))
        .join("users.toml");
    if users_path.exists() {
        let _ = std::fs::copy(&users_path, bdir.join("users.toml"));
    }

    json_response(200, &format!(r#"{{"id":"{dir_name}","ts":{ts}}}"#))
}

fn api_list_backups(ctx: &Arc<ApiContext>) -> Vec<u8> {
    let bdir = backup_dir(ctx);
    let entries = match std::fs::read_dir(&bdir) {
        Ok(e) => e,
        Err(_) => return json_response(200, "[]"),
    };

    let mut items: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.metadata().map(|m| m.is_dir()).unwrap_or(false))
        .filter(|e| e.file_name().to_string_lossy().starts_with("backup_"))
        .map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            let ts = e.metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let has_users = e.path().join("users.toml").exists();
            format!(r#"{{"id":"{name}","ts":{ts},"has_users":{has_users}}}"#)
        })
        .collect();

    items.sort();
    json_response(200, &format!("[{}]", items.join(",")))
}

fn api_restore(ctx: &Arc<ApiContext>, body: &str) -> Vec<u8> {
    let parsed: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return json_response(400, r#"{"error":"Invalid JSON"}"#),
    };

    let id = match parsed["id"].as_str() {
        Some(s) => s.to_owned(),
        None => return json_response(400, r#"{"error":"Missing id field"}"#),
    };

    if id.contains('/') || id.contains("..") || !id.starts_with("backup_") {
        return json_response(400, r#"{"error":"Invalid backup id"}"#);
    }

    let bdir = backup_dir(ctx).join(&id);
    if !bdir.exists() {
        return json_response(404, r#"{"error":"Backup not found"}"#);
    }

    // Restore config file
    if let Err(e) = std::fs::copy(bdir.join("runnginx.conf"), &ctx.config_path) {
        return json_response(500, &format!(r#"{{"error":"config restore failed: {e}"}}"#));
    }

    // Restore users.toml if present in backup
    let backup_users = bdir.join("users.toml");
    if backup_users.exists() {
        let users_path = ctx.config_path.parent()
            .unwrap_or_else(|| std::path::Path::new("/etc/runnginx"))
            .join("users.toml");
        let _ = std::fs::copy(&backup_users, &users_path);
    }

    // Trigger reload
    let _ = ctx.reload_tx.send(());

    json_response(200, &format!(r#"{{"ok":true,"restored":"{id}"}}"#))
}

fn api_delete_backup(ctx: &Arc<ApiContext>, id: &str) -> Vec<u8> {
    if id.contains('/') || id.contains("..") || !id.starts_with("backup_") {
        return json_response(400, r#"{"error":"Invalid backup id"}"#);
    }
    let bdir = backup_dir(ctx).join(id);
    match std::fs::remove_dir_all(&bdir) {
        Ok(_) => json_response(200, &format!(r#"{{"ok":true,"deleted":"{id}"}}"#)),
        Err(_) => json_response(404, r#"{"error":"Backup not found"}"#),
    }
}

// ── Prometheus metrics ────────────────────────────────────────────────────────

fn prometheus_metrics(ctx: &Arc<ApiContext>) -> Vec<u8> {
    use std::sync::atomic::Ordering::Relaxed;
    let s = &ctx.stats;
    let uptime = s.start.elapsed().as_secs();
    let (p50, p90, p99, _) = s.latency_percentiles();
    let total = s.requests_total.load(Relaxed);

    let mut body = String::with_capacity(4096);

    body.push_str("# HELP runnginx_requests_total Total HTTP requests\n");
    body.push_str("# TYPE runnginx_requests_total counter\n");
    body.push_str(&format!("runnginx_requests_total {}\n", total));

    body.push_str("# HELP runnginx_active_connections Active connections\n");
    body.push_str("# TYPE runnginx_active_connections gauge\n");
    body.push_str(&format!("runnginx_active_connections {}\n", s.active.load(Relaxed)));

    body.push_str("# HELP runnginx_bytes_sent_total Bytes sent\n");
    body.push_str("# TYPE runnginx_bytes_sent_total counter\n");
    body.push_str(&format!("runnginx_bytes_sent_total {}\n", s.bytes_sent.load(Relaxed)));

    body.push_str("# HELP runnginx_bytes_received_total Bytes received\n");
    body.push_str("# TYPE runnginx_bytes_received_total counter\n");
    body.push_str(&format!("runnginx_bytes_received_total {}\n", s.bytes_received.load(Relaxed)));

    body.push_str("# HELP runnginx_status_total Requests by HTTP status class\n");
    body.push_str("# TYPE runnginx_status_total counter\n");
    body.push_str(&format!("runnginx_status_total{{class=\"2xx\"}} {}\n", s.status_2xx.load(Relaxed)));
    body.push_str(&format!("runnginx_status_total{{class=\"3xx\"}} {}\n", s.status_3xx.load(Relaxed)));
    body.push_str(&format!("runnginx_status_total{{class=\"4xx\"}} {}\n", s.status_4xx.load(Relaxed)));
    body.push_str(&format!("runnginx_status_total{{class=\"5xx\"}} {}\n", s.status_5xx.load(Relaxed)));

    body.push_str("# HELP runnginx_uptime_seconds Process uptime\n");
    body.push_str("# TYPE runnginx_uptime_seconds gauge\n");
    body.push_str(&format!("runnginx_uptime_seconds {}\n", uptime));

    // Latency histogram.
    body.push_str("# HELP runnginx_request_duration_seconds Request latency\n");
    body.push_str("# TYPE runnginx_request_duration_seconds histogram\n");
    let mut cumulative = 0u64;
    for (i, count) in s.latency_buckets.iter().enumerate() {
        cumulative += count.load(Relaxed);
        let bound_s = if i == 0 { 0.000001f64 } else { (1u64 << i) as f64 / 1_000_000.0 };
        body.push_str(&format!("runnginx_request_duration_seconds_bucket{{le=\"{:.6}\"}} {}\n", bound_s, cumulative));
    }
    body.push_str(&format!("runnginx_request_duration_seconds_bucket{{le=\"+Inf\"}} {}\n", total));
    body.push_str(&format!("runnginx_request_duration_seconds_sum {:.6}\n", p90 as f64 / 1_000_000.0 * total as f64));
    body.push_str(&format!("runnginx_request_duration_seconds_count {}\n", total));

    body.push_str("# HELP runnginx_p50_seconds p50 latency\n");
    body.push_str("# TYPE runnginx_p50_seconds gauge\n");
    body.push_str(&format!("runnginx_p50_seconds {:.6}\n", p50 as f64 / 1_000_000.0));
    body.push_str("# HELP runnginx_p99_seconds p99 latency\n");
    body.push_str("# TYPE runnginx_p99_seconds gauge\n");
    body.push_str(&format!("runnginx_p99_seconds {:.6}\n", p99 as f64 / 1_000_000.0));

    let body_bytes = body.as_bytes();
    let mut r = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        body_bytes.len()
    ).into_bytes();
    r.extend_from_slice(body_bytes);
    r
}

