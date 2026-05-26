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
| **Status** | ⏳ Open |

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
