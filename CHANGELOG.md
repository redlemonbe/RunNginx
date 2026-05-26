# Changelog — RunNginx

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
