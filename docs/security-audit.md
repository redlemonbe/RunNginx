# RunNginx Security Audit

**Version audited:** v0.1.5  
**Audit date:** 2026-05-26  
**Status:** Cycle A — [AI-INTERNAL]

---

## Executive Summary

This is a first-cycle, AI-internal code review of RunNginx v0.1.5. The audit covered the HTTP handler, authentication, URI validation, rate limiting, API endpoints, and proxy logic. No external human pentester or automated scanning tool was used in this cycle.

The codebase demonstrates deliberate security design in several areas: constant-time API key comparison (subtle crate), bcrypt-only htpasswd (SHA1/MD5 rejected at parse time), documented URI blocklist with path-traversal and null-byte coverage, and per-IP rate limiting on API endpoints. The findings below document the gaps that remain as of this version.

This summary does not imply production-readiness. RunNginx has not undergone [HUMAN-EXTERNAL] audit. The "Status: Experimental" notice in the README is accurate and should be maintained until at least one such cycle is completed.

---

## Methodology

### Scope

| Module | Files reviewed |
|--------|---------------|
| HTTP handler | `src/server/handler.rs` (full) |
| Auth | `src/auth/mod.rs` (full) |
| API | `src/api/mod.rs` (partial — first 130 lines) |
| URI validation | `src/simd/mod.rs` (is_uri_safe + tests) |
| Multi-user | `src/multiuser/mod.rs` (not reviewed — not in scope this cycle) |
| TLS | `src/tls/mod.rs` (not reviewed) |
| XDP/eBPF | not yet implemented |

### Not in scope this cycle

- FastCGI parameter injection (reviewed in future cycle)
- TLS implementation
- Websocket splice correctness
- io_uring safety
- Config parser / directory traversal via nginx.conf directives
- Supply chain / dependency audit

### Threat models considered

- Unauthenticated remote attacker with network access
- Authenticated attacker (valid API key)
- Malicious nginx.conf (self-hosted config injection)
- Header injection via upstream responses

### AI model used

Claude Sonnet 4.6 (2026-05-26). This audit has not been re-reviewed by a different model or human reviewer.

---

## Findings

### RNN-2026-A-001 — API key comparison non-constant-time in multi-user handler

| Field | Value |
|-------|-------|
| **ID** | RNN-2026-A-001 |
| **Severity** | MEDIUM |
| **Source** | [AI-INTERNAL] |
| **File** | `src/server/handler.rs:165` |
| **Discovered** | 2026-05-26 |
| **Status** | ✅ Fixed — v0.1.5+, commit b31d622 — closes #25 |

**Threat model:** Remote attacker with many requests, local or low-latency network.

**Description:** The main API (`/api/*`) correctly uses `subtle::ConstantTimeEq` for Bearer token comparison (see `src/api/mod.rs`). However, the multi-user handler path uses a regular `==` comparison on the same API key:

```rust
let is_admin = !ctx.http.api_key.is_empty() && auth_header_val == ctx.http.api_key;
```

This creates a timing oracle: an attacker who can measure response time with sufficient precision can brute-force the API key one character at a time by observing where the comparison terminates early.

**Exploit path:** Requires ~O(key_len × charset_size) requests with measurable timing. Practical on a local network or co-located attacker. Less practical over the internet due to timing jitter. Not exploitable in a single request.

**Fix:** Replace with `auth_header_val.as_bytes().ct_eq(ctx.http.api_key.as_bytes()).into()` using the `subtle` crate (already a dependency).

**Residual risk after fix:** None — the key is sufficiently long (random 256-bit) to resist brute force even with oracle.

**Verification:** No automated test. Manual review required post-fix.

---

### RNN-2026-A-002 — /ui and /health served without authentication

| Field | Value |
|-------|-------|
| **ID** | RNN-2026-A-002 |
| **Severity** | LOW |
| **Source** | [AI-INTERNAL] |
| **File** | `src/api/mod.rs:71` |
| **Discovered** | 2026-05-26 |
| **Status** | ⚠️ Accepted risk |

**Threat model:** Unauthenticated internet-accessible instance.

**Description:** `/health` and `/ui` (web dashboard) are served to any caller without authentication. The dashboard HTML itself requires an API key to load any data, but the HTML is publicly accessible. `/health` returns `{"status":"ok"}` publicly.

**Exploit path:** `/health` reveals liveness to scanners. `/ui` reveals the management dashboard exists and its version.

**Fix:** Allow configuring auth for `/ui` (optional `api_required: true` in config). `/health` should remain public as it is standard practice for load balancers.

**Residual risk:** Information disclosure — attacker knows the server is RunNginx. Acceptable given the README warning.

**Verification:** Behavioral — `curl http://server/ui` without auth returns 200.

---

### RNN-2026-A-003 — API response status always logged as 200

| Field | Value |
|-------|-------|
| **ID** | RNN-2026-A-003 |
| **Severity** | LOW |
| **Source** | [AI-INTERNAL] |
| **File** | `src/server/handler.rs:152-164` |
| **Discovered** | 2026-05-26 |
| **Status** | ✅ Fixed — v0.1.5+, commit b31d622 — closes #26 |

**Threat model:** Operations / incident response.

**Description:** The API dispatch block returns `status: 200` unconditionally regardless of the actual response status:

```rust
return HandlerResult { bytes: api_bytes, keep_alive: false, status: 200, tunnel: None };
```

This means 401 Unauthorized and 404 Not Found responses from API endpoints are logged as 200 OK. An attacker probing the API leaves no authentication failure trace in access logs.

**Exploit path:** Not directly exploitable. Obscures attack patterns in access logs.

**Fix:** Extract the actual status from `api_bytes` using the existing `extract_status_from_response()` helper.

**Residual risk after fix:** None.

**Verification:** Test: probe `/api/stats` without auth, verify access log shows 401 not 200.

---

### RNN-2026-A-004 — path traversal blocklist based on string matching, not canonical path

| Field | Value |
|-------|-------|
| **ID** | RNN-2026-A-004 |
| **Severity** | LOW |
| **Source** | [AI-INTERNAL] |
| **File** | `src/simd/mod.rs:271` |
| **Discovered** | 2026-05-26 |
| **Status** | ⚠️ Accepted risk |

**Threat model:** Attacker crafting unusual URI encodings.

**Description:** `is_uri_safe()` blocks known dangerous patterns (`/../`, `%2F`, `%5C`, `%00`, `//`, invalid UTF-8). The implementation is a blocklist, not a canonical-path check. Novel encodings not in the blocklist (e.g., `%2e%2e/`, Unicode normalization edge cases) could potentially bypass it.

**Exploit path:** Requires a URI encoding not in the current blocklist. Static file serving passes the URI to the file system — any bypass could allow reading files outside the configured root. Path is mitigated by the OS filesystem boundary and the server running as a non-root user in typical deployments.

**Fix:** After applying `is_uri_safe()`, canonicalize the path (Rust `std::path::Path::canonicalize`) and verify it is under the configured root before file read. Defense-in-depth against unknown encoding bypasses.

**Residual risk:** Reduced but not eliminated without the canonicalization check.

**Verification:** Test: attempt `GET /%2e%2e/etc/passwd`, verify 400 or 404.

---

### RNN-2026-A-005 — No TLS termination at HTTP listener level

| Field | Value |
|-------|-------|
| **ID** | RNN-2026-A-005 |
| **Severity** | INFO |
| **Source** | [AI-INTERNAL] |
| **File** | `src/tls/mod.rs` (not reviewed) |
| **Discovered** | 2026-05-26 |
| **Status** | ⚠️ Accepted risk — TLS module exists but not audited |

**Description:** `src/tls/mod.rs` exists but was not reviewed in this cycle. It is unknown whether TLS is correctly wired into the listener or only partially implemented. API keys and HTTP Basic auth credentials transit in cleartext over plain HTTP connections.

**Accepted risk:** TLS module present; full review deferred to Cycle B.

---

### RNN-2026-A-006 — bcrypt `unwrap_or(false)` silently fails on hash error

| Field | Value |
|-------|-------|
| **ID** | RNN-2026-A-006 |
| **Severity** | LOW |
| **Source** | [AI-INTERNAL] |
| **File** | `src/auth/mod.rs:36` |
| **Discovered** | 2026-05-26 |
| **Status** | ✅ Fixed — v0.1.9, closes #30 — errors now logged with tracing::warn |

**Description:** `bcrypt::verify(password, &normalized).unwrap_or(false)` swallows errors. If the bcrypt crate returns an error for a malformed hash string (e.g., corrupted htpasswd entry), the result is `false` (denied) — this is the safe direction. However, it also silently hides corruption. A corrupted htpasswd could deny legitimate users without any log entry or error indication.

**Exploit path:** Not a direct authentication bypass. Availability impact only.

**Fix:** Log the error before returning false: `bcrypt::verify(...).unwrap_or_else(|e| { tracing::warn!("bcrypt verify error: {e}"); false })`.

**Residual risk after fix:** None — still denies access, now with a trace.

**Verification:** Test with a deliberately malformed bcrypt hash in htpasswd.

---

## Known Limitations and Accepted Risks

Per R8, the following risks are accepted for this version:

1. **No [HUMAN-EXTERNAL] audit has been performed.** All findings are AI-internal. The presence of this audit document does not constitute security certification.

2. **Multi-user module not audited.** `src/multiuser/mod.rs` handles per-user isolation, quotas, and API key management. This is a high-value target and must be audited before any multi-user deployment.

3. **TLS implementation not audited.** The TLS module was not reviewed. HTTPS deployments should be tested with tooling (e.g., testssl.sh, sslyze) before exposure.

4. **FastCGI parameter injection not reviewed.** FastCGI SCRIPT_FILENAME, PATH_INFO, and DOCUMENT_ROOT handling must be reviewed before PHP-FPM deployments.

5. **No supply chain audit.** Dependencies have not been audited. Notable: the `bcrypt` crate is a third-party implementation. Its correctness is assumed but not verified.

6. **Rate limiting is per-IP only.** There is no global rate limit or per-user-account rate limit. A botnet with many IPs bypasses the per-IP limit. Accepted at experimental status.

7. **io_uring zero-copy not audited.** Kernel-level operations require separate review.

---

## Audit trail

| Cycle | Date | Source | Model | Scope |
|-------|------|--------|-------|-------|
| A | 2026-05-26 | [AI-INTERNAL] | Claude Sonnet 4.6 | handler, auth, API, URI validation |

---

## Cycle B — 2026-05-26 [AI-INTERNAL]

**Scope:** `src/multiuser/mod.rs`, `src/tls/mod.rs`, `src/auth/mod.rs` (full), `src/server/handler.rs` (re-review), `src/api/mod.rs`, `src/proxy/mod.rs`, `src/fastcgi/mod.rs`
**Model:** Claude Sonnet 4.6
**Note:** Cycle B includes a full review of `src/tls/mod.rs` (deferred in Cycle A under A-005) and the multi-user module (`src/multiuser/mod.rs`) flagged in Cycle A Known Limitations.

### Status update — RNN-2026-A-005 (TLS not audited)

Full review completed in this cycle. rustls with `ServerConfig::builder().with_no_client_auth()` — safe default, no client cert required. ALPN correctly negotiated (`h2`, `http/1.1`). Self-signed cert auto-generated via rcgen. Sub-finding documented as RNN-2026-B-003.

**Updated status:** Partially addressed — TLS reviewed, sub-finding documented as B-003.

---

### RNN-2026-B-001 — `generate_id()` uses nanosecond timestamp as user ID

| Field | Value |
|-------|-------|
| **ID** | RNN-2026-B-001 |
| **Severity** | LOW |
| **Source** | [AI-INTERNAL] |
| **File** | `src/multiuser/mod.rs:196-199` |
| **Discovered** | 2026-05-26 |
| **Status** | ✅ Fixed — v0.1.9, closes #28 — using /dev/urandom (16 random bytes) |

**Threat model:** Attacker with admin API access enumerating user IDs.

**Description:** User IDs are generated as `format!("{:x}", SystemTime::now().as_nanos())` — a hex-encoded nanosecond timestamp. IDs are monotonically increasing and predictable: any user ID can be approximated by sampling the epoch at account creation time.

Practical impact is limited: all ID-based operations (`GET /api/users/{id}`, `DELETE /api/users/{id}`) require admin authentication. Without admin auth, guessing an ID grants nothing. A same-nanosecond collision creates a duplicate-ID bug, not a security bypass.

**Exploit path:** Admin-authenticated attacker enumerates user IDs by brute-force timestamp guessing. Prerequisite: admin API key compromise.

**Fix:** Use `/dev/urandom` entropy, same approach as `generate_api_key()`: read 16 random bytes, hex-encode them.

**Residual risk after fix:** None.

**Verification:** Generate two users rapidly; verify IDs are not adjacent hex timestamps.

---

### RNN-2026-B-002 — Username not validated before constructing `/home/<username>`

| Field | Value |
|-------|-------|
| **ID** | RNN-2026-B-002 |
| **Severity** | MEDIUM |
| **Source** | [AI-INTERNAL] |
| **File** | `src/multiuser/mod.rs:245` |
| **Discovered** | 2026-05-26 |
| **Status** | ✅ Fixed — v0.1.9, closes #29 — username validated: alphanumeric + - + _ only, max 32 chars |

**Threat model:** Admin creating an account with a crafted username to pre-position a path traversal.

**Description:** `home_dir` is constructed as `PathBuf::from(format!("/home/{}", username))` with no validation. A username such as `../../etc` yields `home_dir = PathBuf("/etc")`, which is persisted to `users.toml`. The value is not currently used to enforce filesystem isolation — that layer is not yet implemented. However, when vhost isolation (roadmap) uses `home_dir` as a boundary, any stored traversal bypasses all isolation without a second input validation step.

**Exploit path:** Requires admin API key. Admin POSTs `{"username":"../../etc","domains":[]}`. When file isolation is added without re-validating the stored `home_dir`, the account has read/write access to `/etc`.

**Fix:** Validate username at the API handler before calling `create_user()`: reject any value that is empty, contains `/`, `\`, `.`, or non-alphanumeric characters beyond `-` and `_`. Apply canonical Linux username rules.

**Residual risk after fix:** None — traversal prevented at ingress.

**Verification:** POST `{"username":"../../etc"}` → expect 400. POST `{"username":"alice"}` → expect 200.

---

### RNN-2026-B-003 — Self-signed cert has hard-coded validity dates, no rotation

| Field | Value |
|-------|-------|
| **ID** | RNN-2026-B-003 |
| **Severity** | INFO |
| **Source** | [AI-INTERNAL] |
| **File** | `src/tls/mod.rs:72-73` |
| **Discovered** | 2026-05-26 |
| **Status** | ⏳ Open |

**Threat model:** Certificate expires in production with no automated renewal path.

**Description:** Auto-generated self-signed certificates use `not_before = 2024-01-01` and `not_after = 2030-01-01`. The cert is generated once on first startup and never rotated. No ACME or expiry-check mechanism exists.

**Impact:** Informational for experimental use. Cert expires 2030-01-01. Production deployments behind a TLS-terminating proxy are unaffected.

**Fix:** At startup, if cert file exists, parse `not_after` and regenerate if within 30 days of expiry. ACME integration (rustls-acme crate) is the production-grade solution.

**Verification:** `openssl x509 -text -noout -in /etc/runnginx/tls/cert.pem | grep "Not After"`.

---

### RNN-2026-B-004 — QUERY_STRING not forwarded to FastCGI (Fixed)

| Field | Value |
|-------|-------|
| **ID** | RNN-2026-B-004 |
| **Severity** | MEDIUM |
| **Source** | [AI-INTERNAL] |
| **File** | `src/server/handler.rs` |
| **Discovered** | 2026-05-26 |
| **Status** | ✅ Fixed — v0.1.8, commit 883d760 — closes #28 |

**Description:** `query` field in `Request` was declared `_query: String` (unused). FastCGI received only the path — query string dropped silently. PHP `$_GET` parameters were always empty.

**Fix applied:** Renamed to `query`, constructed `full_uri = format!("{}?{}", req.path, req.query)` before calling `fastcgi_request()`.

**Verification:** `curl 'http://host/index.php?action=orders'` — PHP `$_GET['action']` receives `orders`.

---


---

## Cycle C — [AI-INTERNAL] — 2026-05-26 — v0.4.0 (ICMP guard + scan detector)

**Scope:** ICMP guard (icmp_guard/mod.rs), scan detector (scan_detector/mod.rs), AbuseIPDB reporter, command injection audit, config parser (new ICMP/scan directives), is_tls threading.

### C-001 — INFO — ICMP guard nft rule fails on VMs without inet filter table

| Field | Value |
|-------|-------|
| **Severity** | INFO |
| **Discovered** | 2026-05-26 |
| **Status** | Accepted |

Description: On VMs where nft has no `inet filter` table, the icmp_guard rule fails with "No such file or directory". Logs WARN and continues without ICMP protection. Graceful degradation — no crash.

Accepted: lab/prod use ufw/iptables which succeeds. ICMP protection is hardening, not a security boundary.

---

### C-002 — INFO — AbuseIPDB curl: no command injection vector confirmed

| Field | Value |
|-------|-------|
| **Severity** | INFO |
| **Discovered** | 2026-05-26 |
| **Status** | No finding |

Description: Command::new("curl").args([...]) — no shell involved. ip is Rust IpAddr (always safe). comment is urlencodecomment()-encoded (percent-encodes all non-alphanumeric). No injection path.

---

### C-003 — LOW — Scan detector: first probe path request returns 404 not 429

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Discovered** | 2026-05-26 |
| **Status** | Open |

Description: Single probe path hit = 10 pts (threshold 60). First request to /.env gets 404 before score accumulates. Subsequent requests trigger 429 block.

Impact: Low — attacker sees one 404, then gets blocked. No sensitive data leaked.

---

## Updated Known Limitations and Accepted Risks (post Cycle C)

| # | Risk | Cycle | Status |
|---|------|-------|--------|
| 1 | No HUMAN-EXTERNAL audit performed | A | Open |
| 2 | Username path traversal in home_dir | B | Open (B-002) |
| 3 | TLS: self-signed cert, no auto-renewal | B | Open (B-003) |
| 4 | bcrypt error silently swallowed | A | Open (A-006) |
| 5 | User IDs are nanosecond timestamps | B | Open (B-001) |
| 6 | No supply chain audit | A | Open |
| 7 | Rate limiting is per-IP only | A | Accepted |
| 8 | io_uring zero-copy not audited | A | Open |
| 9 | ICMP guard degrades on VMs without inet filter | C | Accepted (C-001) |
| 10 | Scan detector first probe response is 404 | C | Open (C-003) |

## Audit trail (updated)

| Cycle | Date | Source | Model | Scope |
|-------|------|--------|-------|-------|
| A | 2026-05-26 | AI-INTERNAL | Claude Sonnet 4.6 | handler, auth, API, URI validation |
| B | 2026-05-26 | AI-INTERNAL | Claude Sonnet 4.6 | multiuser, TLS, auth (full), proxy, fastcgi |
| C | 2026-05-26 | AI-INTERNAL | Claude Sonnet 4.6 | ICMP guard, scan detector, AbuseIPDB, command injection, is_tls |


---

## Cycle D — [AI-INTERNAL] — 2026-05-26 — v0.4.0 (HTTP/2, WebSocket, Cache, ACME)

**Scope:** `src/http2/mod.rs`, `src/websocket/mod.rs`, `src/cache/mod.rs`, `src/acme/mod.rs`
**Model:** Claude Sonnet 4.6
**Note:** v0.4.0 added HTTP/2 bridging (ALPN h2), WebSocket proxy, response cache, and ACME Let's Encrypt integration. This cycle reviews these new modules exclusively.

---

### RNN-2026-D-001 — MEDIUM — HTTP/2 per-stream task spawn is unbounded

| Field | Value |
|-------|-------|
| **ID** | RNN-2026-D-001 |
| **Severity** | MEDIUM |
| **CWE** | CWE-400 (Uncontrolled Resource Consumption) |
| **Source** | [AI-INTERNAL] |
| **File** | `src/http2/mod.rs:31` |
| **Discovered** | 2026-05-26 |
| **Status** | ✅ Fixed — v0.4.2 |

**Threat model:** An HTTP/2 client that floods the server with concurrent streams.

**Description:** `h2::server::serve()` spawns a new `tokio::task` for each accepted h2 stream via `tokio::spawn(handle_stream(...))` with no concurrency bound. HTTP/2 allows multiplexing hundreds of streams per connection (default `SETTINGS_MAX_CONCURRENT_STREAMS` is implementation-defined, but clients can negotiate values up to `2^31-1`). A single authenticated HTTP/2 connection can create thousands of streams simultaneously, spawning thousands of tasks. Each task allocates a body buffer and a synthetic HTTP/1.1 request. Under load, this exhausts memory or scheduler capacity.

**Fix:** Use `tokio::sync::Semaphore` to cap concurrent in-flight h2 stream tasks (e.g., `max_concurrent_streams = 256`). Additionally, advertise a conservative `SETTINGS_MAX_CONCURRENT_STREAMS` value to the client to let the h2 crate enforce it at the protocol level:
```
conn.set_max_concurrent_streams(Some(256));
```

---

### RNN-2026-D-002 — MEDIUM — WebSocket header passthrough without CRLF sanitization (header injection)

| Field | Value |
|-------|-------|
| **ID** | RNN-2026-D-002 |
| **Severity** | MEDIUM |
| **CWE** | CWE-113 (HTTP Response/Request Splitting) |
| **Source** | [AI-INTERNAL] |
| **File** | `src/websocket/mod.rs:36` |
| **Discovered** | 2026-05-26 |
| **Status** | ✅ Fixed — v0.4.2 |

**Threat model:** Attacker who controls HTTP header values in a WebSocket upgrade request (e.g., a malicious `Sec-WebSocket-Protocol` header containing CRLF).

**Description:** `upgrade_to_websocket()` builds the HTTP/1.1 upstream request by appending header values directly:
```
req.push_str(&format!("{}: {}\r\n", k, v));
```

If a header value contains `\r\n`, the injected CRLF would split the request line and insert arbitrary headers or a second request into the upstream connection. This is a header injection / HTTP request-splitting vulnerability.

Example: A client sends `Sec-WebSocket-Protocol: chat\r\nX-Injected: evil`. The upstream receives an extra `X-Injected: evil` header.

**Mitigations already present:** Most HTTP/1.1 request parsers reject bare CRLF in header values. However, if the upstream is a custom server or a misconfigured proxy, injection may succeed.

**Fix:** Strip `\r` and `\n` characters from header values before inclusion:
```
let v_safe = v.replace('\r', "").replace('\n', "");
req.push_str(&format!("{}: {}\r\n", k, v_safe));
```

---

### RNN-2026-D-003 — INFO — ACME renewal check uses file mtime, not certificate expiry

| Field | Value |
|-------|-------|
| **ID** | RNN-2026-D-003 |
| **Severity** | INFO |
| **Source** | [AI-INTERNAL] |
| **File** | `src/acme/mod.rs` — `needs_renewal()` |
| **Discovered** | 2026-05-26 |
| **Status** | ⏳ Open |

**Description:** `needs_renewal()` reads `meta.modified()` (file modification timestamp) to decide if a certificate needs renewal. If the cert file is copied, replaced, or touched, the mtime is reset and renewal is deferred for another 60 days — regardless of the certificate's actual expiry. This could leave a shorter-lived or already-expired certificate in place beyond the intended renewal window.

Additionally, Let's Encrypt certificates are valid for 90 days. The `RENEW_AFTER_DAYS = 60` constant is correct in intent, but using mtime means the renewal trigger fires 60 days after the file was *last written*, not 60 days before the cert expires.

**Fix:** Parse the X.509 certificate with `rustls-pemfile` + `x509-parser` and read the `notAfter` field. Renew when `notAfter - now < 30 days`.

---

### RNN-2026-D-004 — INFO — Response cache caches 404 responses (potential cache poisoning)

| Field | Value |
|-------|-------|
| **ID** | RNN-2026-D-004 |
| **Severity** | INFO |
| **Source** | [AI-INTERNAL] |
| **File** | `src/cache/mod.rs` — `is_cacheable()` |
| **Discovered** | 2026-05-26 |
| **Status** | ⚠️ Accepted risk for current use case |

**Description:** `is_cacheable()` returns `true` for HTTP 404 responses. A 404 for a path that later becomes valid (e.g., content is published after a first request) will be served stale from cache until the TTL expires. Cache poisoning requires the attacker to be the first requester of a not-yet-published URL; the impact is limited to the TTL window.

For most deployments this is a non-issue and caching 404s reduces upstream load. Accepted.

**Mitigation if needed:** Exclude 404 from the cacheable status set. Or expose a `cache_bypass_on_404: true` config option.

---

### RNN-2026-D-005 — INFO — Cache eviction: full cache silently drops new entries

| Field | Value |
|-------|-------|
| **ID** | RNN-2026-D-005 |
| **Severity** | INFO |
| **Source** | [AI-INTERNAL] |
| **File** | `src/cache/mod.rs` — `ResponseCache::put()` |
| **Discovered** | 2026-05-26 |
| **Status** | ⚠️ Accepted risk |

**Description:** When the cache is at `max_size` and no expired entries exist, `put()` silently skips the insertion. An attacker who fills the cache with requests to unique URLs (cache flood) can prevent legitimate responses from ever being cached, degrading the server to no-cache performance permanently until the cache expires naturally.

This is a low-impact DoS that degrades performance but does not expose data or allow code execution.

**Mitigation:** Implement LRU eviction (evict the least-recently-accessed entry instead of skipping). This would require an ordered data structure (e.g., `linked-hash-map` crate). Accepted for alpha; LRU is a v1.0 quality-of-life item.

---

## Updated Known Limitations and Accepted Risks (post Cycle D)

| # | Risk | Cycle | Status |
|---|------|-------|--------|
| 1 | No HUMAN-EXTERNAL audit | A | Open |
| 2 | Username path traversal in home_dir | B | Open (B-002) |
| 3 | TLS: self-signed cert, no auto-renewal | B | Mitigated: ACME added in v0.4.0 |
| 4 | bcrypt error silently swallowed | A | Open (A-006) |
| 5 | User IDs are nanosecond timestamps | B | Open (B-001) |
| 6 | No supply chain audit | A | Open |
| 7 | Rate limiting is per-IP only | A | Accepted |
| 8 | io_uring zero-copy not audited | A | Open |
| 9 | ICMP guard degrades on VMs without inet filter | C | Accepted (C-001) |
| 10 | Scan detector first probe response is 404 | C | Open (C-003) |
| 11 | HTTP/2 per-stream task spawn unbounded | D | Fixed v0.4.2 (D-001) |
| 12 | WebSocket header CRLF injection | D | Fixed v0.4.2 (D-002) |
| 13 | ACME renewal uses mtime not cert expiry | D | Open (D-003) |
| 14 | Cache caches 404 responses | D | Accepted (D-004) |
| 15 | Cache eviction silently drops when full | D | Accepted (D-005) |

## Audit trail (updated)

| Cycle | Date | Source | Model | Scope |
|-------|------|--------|-------|-------|
| A | 2026-05-26 | AI-INTERNAL | Claude Sonnet 4.6 | handler, auth, API, URI validation |
| B | 2026-05-26 | AI-INTERNAL | Claude Sonnet 4.6 | multiuser, TLS, auth (full), proxy, fastcgi |
| C | 2026-05-26 | AI-INTERNAL | Claude Sonnet 4.6 | ICMP guard, scan detector, AbuseIPDB, command injection, is_tls |
| D | 2026-05-26 | AI-INTERNAL | Claude Sonnet 4.6 | http2, websocket, cache, acme |


---

## Security Audit Cycle E — Sites Manager + Session Auth (v0.5.0)

**Date:** 2026-05-27
**Source:** [AI-INTERNAL] — Gemini 2.5 Pro (VM2) + Claude Sonnet 4.6 (review)
**Scope:** `src/api/sites.rs`, `src/api/mod.rs` (session auth), `src/config/types.rs`, `src/config/parser.rs`

---

### RNN-2026-E-001 — CRITICAL — PHP injection via wp-config.php string replacement

| Field | Value |
|-------|-------|
| **ID** | RNN-2026-E-001 |
| **Severity** | CRITICAL |
| **Source** | [AI-INTERNAL] |
| **File** | `src/api/sites.rs:371` — `setup_wordpress()` |
| **Discovered** | 2026-05-27 |
| **Status** | ✅ Fixed v0.5.1 |

**Description:** The `db_pass` field was inserted into `wp-config.php` via `.replace("password_here", db_pass)` without any PHP string escaping. A user-supplied password containing `'); ?>` would inject arbitrary PHP code executed at WordPress bootstrap.

**Fix:** Added `php_escape()` closure that replaces `\` with `\\` and `'` with `\'` before substitution.

---

### RNN-2026-E-002 — CRITICAL — Nginx config injection via php_version and upstream_url

| Field | Value |
|-------|-------|
| **ID** | RNN-2026-E-002 |
| **Severity** | CRITICAL |
| **Source** | [AI-INTERNAL] |
| **File** | `src/api/sites.rs:94, 399` — `create_site()`, `generate_config()` |
| **Discovered** | 2026-05-27 |
| **Status** | ✅ Fixed v0.5.1 |

**Description:** `php_version` and `upstream_url` were interpolated directly into the nginx config template without validation. A value like `8.2;\n} server { listen 80; location / { return 200 "pwned"; }` would inject arbitrary nginx directives.

**Fix:** `php_version` validated as `[0-9.]{1-8}` only. `upstream_url` must start with `http://` or `https://`, max 512 chars, no `\n`, `\r`, `;`, `{`, `}`, `#`.

---

### RNN-2026-E-003 — HIGH — SQL injection in WordPress DB provisioning

| Field | Value |
|-------|-------|
| **ID** | RNN-2026-E-003 |
| **Severity** | HIGH |
| **Source** | [AI-INTERNAL] |
| **File** | `src/api/sites.rs:318` — `setup_wordpress()` |
| **Discovered** | 2026-05-27 |
| **Status** | ✅ Fixed v0.5.1 |

**Description:** `db_name` and `db_user` were injected into the `mysql -e` SQL string without sanitisation. Backticks or semicolons could inject additional SQL commands. `db_pass` was also vulnerable in the `IDENTIFIED BY` clause.

**Fix:** Strict allowlist validation on `db_name` and `db_user` (alphanumeric + `_` + `-`, max 64 chars). Single-quote escaping (`'` → `''`) applied to `db_pass` in the SQL string.

---

### RNN-2026-E-004 — HIGH — wp-config.php world-readable after chmod -R 755

| Field | Value |
|-------|-------|
| **ID** | RNN-2026-E-004 |
| **Severity** | HIGH |
| **Source** | [AI-INTERNAL] |
| **File** | `src/api/sites.rs:376` — `setup_wordpress()` |
| **Discovered** | 2026-05-27 |
| **Status** | ✅ Fixed v0.5.1 |

**Description:** After recursive `chmod 755 webroot/`, the `wp-config.php` containing database credentials was world-readable by any local user.

**Fix:** After the recursive chmod, a dedicated `chmod 640 wp-config.php` restricts the file to owner+group only.

---

### RNN-2026-E-005 — MEDIUM — No rate limiting on POST /login

| Field | Value |
|-------|-------|
| **ID** | RNN-2026-E-005 |
| **Severity** | MEDIUM |
| **Source** | [AI-INTERNAL] |
| **File** | `src/api/mod.rs:160` — `handle_api()` routing |
| **Discovered** | 2026-05-27 |
| **Status** | ✅ Fixed v0.5.1 |

**Description:** The `/login` POST handler had a 300ms brute-force delay but bypassed the `ctx.rate.allow(peer_ip)` check applied to all other endpoints.

**Fix:** Rate limiter check added before dispatching to `handle_login_post`.

---

### RNN-2026-E-006 — MEDIUM — WordPress security keys generated with non-random subsec_nanos

| Field | Value |
|-------|-------|
| **ID** | RNN-2026-E-006 |
| **Severity** | MEDIUM |
| **Source** | [AI-INTERNAL] |
| **File** | `src/api/sites.rs:561` — `rand_hex()` |
| **Discovered** | 2026-05-27 |
| **Status** | ✅ Fixed v0.5.1 |

**Description:** `rand_hex()` used `subsec_nanos() as u8` in a tight loop, generating nearly constant output. The 8 WordPress security keys were thus predictable, weakening session and cookie security.

**Fix:** Reads from `/dev/urandom` for cryptographically secure output.

---

### RNN-2026-E-007 — LOW — Secure flag missing on session cookie

| Field | Value |
|-------|-------|
| **ID** | RNN-2026-E-007 |
| **Severity** | LOW |
| **Source** | [AI-INTERNAL] |
| **File** | `src/api/mod.rs:132` — `handle_login_post()` |
| **Discovered** | 2026-05-27 |
| **Status** | ✅ Fixed v0.5.1 |

**Description:** The `session` cookie lacked the `Secure` flag, risking token leak on HTTP connections. `HttpOnly` and `SameSite=Strict` were present.

**Fix:** `Secure` flag added when `X-Forwarded-Proto: https` header is present.

---

### RNN-2026-E-008 — LOW — Length leakage in constant-time comparison

| Field | Value |
|-------|-------|
| **ID** | RNN-2026-E-008 |
| **Severity** | LOW |
| **Source** | [AI-INTERNAL] |
| **File** | `src/api/mod.rs:104, 211` — `verify_login_credentials()` |
| **Discovered** | 2026-05-27 |
| **Status** | ⚠️ Open |

**Description:** `subtle::ConstantTimeEq` is used but compares slices of potentially different lengths. A mismatch in length returns immediately, leaking the expected length. This slightly aids brute-force by revealing password length.

**Mitigation:** Compare fixed-length hashes (e.g. SHA-256) of credentials instead of raw strings. Low priority for local webui.

---

## Updated Known Limitations and Accepted Risks (post Cycle E)

| # | Risk | Cycle | Status |
|---|------|-------|--------|
| 1 | No HUMAN-EXTERNAL audit | A | Open |
| 2 | Username path traversal in home_dir | B | Open (B-002) |
| 3 | TLS: self-signed cert, no auto-renewal | B | Mitigated: ACME added in v0.4.0 |
| 4 | bcrypt error silently swallowed | A | Open (A-006) |
| 5 | User IDs are nanosecond timestamps | B | Open (B-001) |
| 6 | No supply chain audit | A | Open |
| 7 | Rate limiting is per-IP only | A | Accepted |
| 8 | io_uring zero-copy not audited | A | Open |
| 9 | ICMP guard degrades on VMs without inet filter | C | Accepted (C-001) |
| 10 | Scan detector first probe response is 404 | C | Open (C-003) |
| 11 | HTTP/2 per-stream task spawn unbounded | D | Fixed v0.4.2 (D-001) |
| 12 | WebSocket header CRLF injection | D | Fixed v0.4.2 (D-002) |
| 13 | ACME renewal uses mtime not cert expiry | D | Open (D-003) |
| 14 | Cache caches 404 responses | D | Accepted (D-004) |
| 15 | Cache eviction silently drops when full | D | Accepted (D-005) |
| 16 | PHP injection in wp-config.php | E | Fixed v0.5.1 (E-001) |
| 17 | Nginx config injection via php_version/upstream | E | Fixed v0.5.1 (E-002) |
| 18 | SQL injection in WordPress DB provisioning | E | Fixed v0.5.1 (E-003) |
| 19 | wp-config.php world-readable | E | Fixed v0.5.1 (E-004) |
| 20 | No rate limiting on /login | E | Fixed v0.5.1 (E-005) |
| 21 | WordPress keys non-random | E | Fixed v0.5.1 (E-006) |
| 22 | Secure cookie flag missing | E | Fixed v0.5.1 (E-007) |
| 23 | Length leakage in CT comparison | E | Open (E-008) |

## Audit trail (updated)

| Cycle | Date | Source | Model | Scope |
|-------|------|--------|-------|-------|
| A | 2026-05-26 | AI-INTERNAL | Claude Sonnet 4.6 | handler, auth, API, URI validation |
| B | 2026-05-26 | AI-INTERNAL | Claude Sonnet 4.6 | multiuser, TLS, auth (full), proxy, fastcgi |
| C | 2026-05-26 | AI-INTERNAL | Claude Sonnet 4.6 | ICMP guard, scan detector, AbuseIPDB, command injection, is_tls |
| D | 2026-05-26 | AI-INTERNAL | Claude Sonnet 4.6 | http2, websocket, cache, acme |
| E | 2026-05-27 | AI-INTERNAL | Gemini 2.5 Pro + Claude Sonnet 4.6 | sites manager, session auth, wp provisioning |
