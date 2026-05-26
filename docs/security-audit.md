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
