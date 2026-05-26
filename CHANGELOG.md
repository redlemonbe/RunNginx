# Changelog — RunNginx

## [0.4.0] — 2026-05-26

### Added

- **ICMP flood protection** (on by default): rate-limits ICMP echo-request to 5/s burst 10 via iptables/nftables. IPv4 + IPv6. Config: `icmp_protection on|off`. Mirrors Runbound's network-level protection.
- **Inter-process coordination**: lock file `/var/run/icmp_guard.pid` ensures only one program (RunNginx, RunAlexDB, or Runbound) sets up ICMP rules at a time. Second instance detects live lock owner and skips setup automatically. On clean exit, owner releases lock and removes rules.
- **HTTP scan/probe detection** (on by default): per-IP scoring across a 60s sliding window. Score based on request volume, 4xx error rate, and known probe paths (`.env`, `wp-login.php`, `/etc/passwd`, 30+ patterns). Score ≥ 60 → 429 block for 1h.
- **AbuseIPDB integration** (optional): `abuseipdb_key "your-key"; abuseipdb_report on;` reports detected scanners with confidence score to AbuseIPDB v2 API (categories 14+21).
- Config directives: `scan_window`, `scan_threshold`, `scan_error_rate`, `scan_block`, `abuseipdb_key`, `abuseipdb_report`.

Closes #33

---

## [0.3.0] — 2026-05-26

### Added

- **ssl_redirect**: Per-server directive; when set to , plain HTTP requests receive a 301 redirect to HTTPS. Passes  flag through the request pipeline.
- **HSTS**:  injects  on all TLS responses.  and  allow fine-grained control.
- **add_headers now active**: Server-level and location-level  directives were parsed but never applied to responses — now correctly injected before .

Closes #32

---

## [0.4.0] — 2026-05-26

### Added

- **ICMP flood protection** (on by default): rate-limits ICMP echo-request to 5/s burst 10 via iptables/nftables. IPv4 + IPv6. Config: `icmp_protection on|off`. Mirrors Runbound's network-level protection.
- **Inter-process coordination**: lock file `/var/run/icmp_guard.pid` ensures only one program (RunNginx, RunAlexDB, or Runbound) sets up ICMP rules at a time. Second instance detects live lock owner and skips setup automatically. On clean exit, owner releases lock and removes rules.
- **HTTP scan/probe detection** (on by default): per-IP scoring across a 60s sliding window. Score based on request volume, 4xx error rate, and known probe paths (`.env`, `wp-login.php`, `/etc/passwd`, 30+ patterns). Score ≥ 60 → 429 block for 1h.
- **AbuseIPDB integration** (optional): `abuseipdb_key "your-key"; abuseipdb_report on;` reports detected scanners with confidence score to AbuseIPDB v2 API (categories 14+21).
- Config directives: `scan_window`, `scan_threshold`, `scan_error_rate`, `scan_block`, `abuseipdb_key`, `abuseipdb_report`.

Closes #33

---

## [0.3.0] — 2026-05-26

### Added

- **ssl_redirect**: Per-server directive; when set to `on`, plain HTTP requests receive a 301 redirect to HTTPS. The `is_tls` flag is threaded through the request pipeline via the new `dispatch()` parameter.
- **HSTS**: `hsts on` injects `Strict-Transport-Security: max-age=31536000; includeSubDomains` on all TLS responses. `hsts_max_age` and `hsts_include_subdomains` allow fine-grained control per server block.
- **add_headers now active**: Server-level and location-level `add_header` directives were parsed but never applied to responses — now correctly injected before `format_response()`.

Closes #32

---

## [0.2.0] — 2026-05-26

### Added

- **Hot backup**: `POST /api/backup` — snapshots `runnginx.conf` + `users.toml` to `config_dir/backups/backup_<ts>[_label]/`. Optional `label` field for named snapshots.
- **Backup listing**: `GET /api/backups` — returns JSON list with id, timestamp, and `has_users` flag.
- **Hot restore**: `POST /api/restore` with `{"id": "backup_<ts>"}` — copies config and users back from snapshot, then triggers a live reload.
- **Backup deletion**: `DELETE /api/backups/<id>` — removes a named backup directory.

Closes #31

---

## [0.1.9] — 2026-05-26

### Security

- **B-001 fixed**: `generate_id()` now uses `/dev/urandom` (16 random bytes) instead of nanosecond timestamp — closes #28.
- **B-002 fixed**: Username validated in `POST /api/users` — only alphanumeric, `-`, `_`, max 32 chars. Rejects path traversal attempts — closes #29.
- **A-006 fixed**: bcrypt errors logged with `tracing::warn` before returning false — closes #30.

---

## [0.1.8] — 2026-05-26

### Added

- **Firewall auto-management**: RunNginx opens its configured listen ports at startup and closes them on SIGINT/SIGTERM. Detects and uses ufw, nftables, or iptables automatically. Rules are tagged (`# runnginx` or configurable via `firewall_tag`). Config directives: `firewall_manage`, `firewall_backend`, `firewall_tag`.

### Fixed

- **QUERY_STRING not forwarded to FastCGI** (security: closes #28): The `query` field in `Request` was declared `_query` and never read. FastCGI received only the path component of the URI — all `$_GET` parameters were empty in PHP. Fixed by constructing `full_uri = path + "?" + query` before calling `fastcgi_request()`.
- **Constant-time API key comparison** (security RNN-2026-A-001: closes #25): API key comparison in the request handler now uses `subtle::ConstantTimeEq` to prevent timing side-channel.
- **HTTP 401 instead of 200 on auth failure** (security RNN-2026-A-003: closes #26): Authentication failures now return `401 Unauthorized` instead of `200 OK` with a plain-text body.

---

## [0.1.7] — 2026-05-26

### Added

- **CloudPanel-style Web UI dashboard**: full management interface with sidebar navigation — Dashboard, Virtual Hosts, Users, SSH & Access, Live Metrics, Logs.

---

## [0.1.6] — 2026-05-26

### Changed

- **Web UI login modal**: replaced browser `prompt()` with a styled API key input modal.

---

## [0.1.5] — 2026-05-26

### Added

- **Live access log API**: `GET /api/logs?n=N` returns the last N access log lines. Web UI polls and displays a live log tail.

---

## [0.1.4] -- 2026-05-26

### Added

- **io_uring file-read service** (optional feature `io_uring`): thread pool backed by
  `io_uring::IoUring` rings, replaces tokio::fs::read for static file GET responses.
  - N worker threads (N = min(CPU count, 4)), each owning a 64-entry IoUring ring.
  - Requests bridged from tokio via std::sync::mpsc try_send (non-blocking) and
    tokio::sync::oneshot for results; no conflict with the main tokio runtime.
  - Files > 4 MB fall back to tokio::fs::read automatically.
  - If the pool queue is full, graceful fallback to tokio::fs::read.
  - Feature disabled by default; build with --features io_uring to enable.

---

## [0.1.3] -- 2026-05-26

### Added

- **SIMD enhancements**: two new public utilities in `src/simd/mod.rs`.
  - `percent_decode(input: &[u8]) -> Vec<u8>`: decode %XX sequences with passthrough
    of incomplete/invalid sequences; null bytes pass through and are caught by
    `is_uri_safe` downstream.
  - `normalize_header_name(name: &[u8]) -> Vec<u8>`: lowercase ASCII in one pass;
    callers can use == instead of eq_ignore_ascii_case for header lookups.
- 6 new unit tests (total: 53).

---

## [0.1.2] — 2026-05-26

### Added

- **HTTP/2 support**: ALPN negotiation on TLS connections (`h2` + `http/1.1` advertised). When a client negotiates `h2`, the connection is handed to an h2 server that multiplexes streams and bridges each request through the existing handler pipeline. Requires the `tls` feature (default).

---

## [0.1.1] — 2026-05-26

### Added

- **README**: complete documentation — feature table, quick start, all config examples (proxy, load balancing, TLS/ACME, rate limiting, FastCGI, auth, compression, rewrite), management API, multi-user mode, security notes.
- **Test suite**: 47 unit tests across `simd`, `limit_req`, and `server::handler` modules.

### Changed

- Suppressed v0.1.x development warnings (`dead_code`, `unused_*`) via `#![allow(...)]` in `main.rs`.

---

## [0.1.0] — 2026-05-26

### Initial release

- Static file serving (sendfile, directory index, custom error pages)
- Reverse proxy (`proxy_pass`, `proxy_set_header`, configurable timeouts)
- Load balancing: round-robin, least-connections, IP-hash
- TLS via rustls — self-signed auto-generation; ACME/Let's Encrypt (DNS-01)
- FastCGI / PHP-FPM client (Unix socket + TCP upstreams)
- WebSocket proxy (transparent TCP splice on `Upgrade: websocket`)
- Rewrite rules (regex, redirect/last/break/permanent)
- Auth Basic (htpasswd-format)
- Rate limiting: `limit_req_zone` / `limit_req` token-bucket per-IP
- In-memory LRU response cache (Cache-Control aware)
- Brotli + Gzip compression per location
- Prometheus metrics at `/metrics`
- SIGHUP zero-downtime config reload
- Multi-user mode: per-user API keys, bandwidth quotas, isolated vhosts
- Embedded Web UI (management dashboard)
- SIMD HTTP parser: AVX2 / SSE2 / scalar dispatch chosen at startup
- Access log (combined format)
