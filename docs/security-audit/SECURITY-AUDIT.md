# RunNginx — Security Audit Log

## Cycle F — Phase 1 Foundations [AI-INTERNAL]

**Date:** 2026-05-26
**Scope:** src/http/limits.rs, src/config/types.rs, src/config/parser.rs, src/simd/mod.rs, src/server/listener.rs
**Auditor:** Claude Sonnet 4.6 (self-audit, adversarial mode)
**Label:** [AI-INTERNAL] — same model that wrote the code; independent external audit required before v1.0

---

### SEC-F1 — SSRF: IPv6 private ranges not blocked in proxy_pass [FIXED]

**Severity:** HIGH
**File:** src/config/parser.rs, `parse_proxy_pass()`
**Finding:** IPv4 private (RFC-1918) and link-local were blocked, but IPv6 equivalents were not:
- fe80::/10 (link-local) — could reach internal services on dual-stack hosts
- fc00::/7 (ULA — unique local addresses) — private IPv6 range
- ::ffff:0:0/96 (IPv4-mapped IPv6) — allowed reaching IPv4 10.x/172.16.x/192.168.x via IPv6 notation
- fd00:ec2::254 — AWS IMDSv2 metadata endpoint IPv6 address

**Fix:** Added explicit IPv6 segment checks for all three ranges plus cloud metadata hostname. Commit 403df2e.

---

### SEC-F2 — Implicit invariant: .unwrap() calls in parser loops [FIXED]

**Severity:** LOW
**File:** src/config/parser.rs, lines 248/375/582
**Finding:** Three `.unwrap()` calls on `peek_word()` were safe (Word token confirmed by preceding match arm) but silent about the invariant. A future refactor removing the match guard could introduce a panic.
**Fix:** Changed to `.expect("unreachable: Word token confirmed above")`. Commit 403df2e.

---

### ACC-F1 — No symlink resolution on root paths [ACCEPTED]

**Severity:** MEDIUM (theoretical)
**File:** src/config/parser.rs, `canonicalize_root()`
**Finding:** Root paths with `..` components are rejected. Symlinks pointing outside the web root are not resolved at parse time.
**Rationale for acceptance:** Paths may not exist at parse time (containers, hot-reload before mount). Runtime path resolution (when serving files) must re-validate the canonical path — this is a responsibility of the static file handler (Phase 2). Documented in code.
**Mitigation:** The `--test` flag validates config at startup; operators must ensure root paths are not symlinks to sensitive directories.

---

### ACC-F2 — Config file trust boundary [ACCEPTED]

**Severity:** INFO
**Finding:** The parser trusts the config file to be root-owned and unmodified. An attacker who can write `/etc/runnginx/nginx.conf` already has filesystem access beyond what this tool can prevent.
**Rationale:** Same trust model as nginx, Apache, Caddy. Config file protection is an OS-level concern.

---

### ACC-F3 — Glob include patterns [ACCEPTED]

**Severity:** LOW
**File:** src/config/parser.rs, `handle_include()`
**Finding:** Include directives accept glob patterns. A malicious config could include system files, but non-config content would produce parse errors with no data exfiltration (parser returns an error, data stays in the process and is discarded).
**Rationale:** nginx itself supports include glob. Anyone who controls config file content can already use absolute paths. No additional risk beyond ACC-F2.

---

### INFO-F1 — SIMD unsafe blocks [ACCEPTED]

**Severity:** INFO
**File:** src/simd/mod.rs
**Finding:** Two unsafe functions (`find_crlf_sse2`, `find_crlf_avx2`) use x86 intrinsics with `_mm_loadu_si128` / `_mm256_loadu_si256` (unaligned loads — correct).
**Assessment:** Buffer bounds are checked before SIMD loops. Scalar fallback handles the tail. Runtime feature detection via `is_x86_feature_detected!()` guards dispatch. No memory safety issues identified.

---

### INFO-F2 — Rate limiting constants defined, not implemented [ACCEPTED]

**Severity:** INFO
**File:** src/http/limits.rs
**Finding:** `API_RATE_LIMIT_RPS` and `API_RATE_BURST` are defined but no rate limiter is implemented in Phase 1. TCP-level connection flooding is not throttled.
**Rationale:** Rate limiting is Phase 3. For Phase 1, operators are expected to front the server with a firewall. Tracked as issue #9.

---

## Summary

| ID | Severity | Status | Description |
|----|----------|--------|-------------|
| SEC-F1 | HIGH | Fixed | IPv6 SSRF gaps in proxy_pass |
| SEC-F2 | LOW | Fixed | Silent .unwrap() invariants |
| ACC-F1 | MEDIUM | Accepted | Symlink resolution deferred to file handler (Phase 2) |
| ACC-F2 | INFO | Accepted | Config file trust boundary |
| ACC-F3 | LOW | Accepted | Include glob patterns |
| INFO-F1 | INFO | Accepted | SIMD unsafe blocks — assessed clean |
| INFO-F2 | INFO | Accepted | Rate limiting not implemented in Phase 1 |

**Next audit:** Cycle G — after Phase 2 (HTTP routing, static file handler, proxy forwarding, TLS)
