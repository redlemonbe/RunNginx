# Changelog — RunNginx

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
