// Security limits — all HTTP input validation constants live here.
// Every limit has a comment explaining the attack it prevents.
// Changing these requires a security review — do not adjust for convenience.

// ── Request line ──────────────────────────────────────────────────────────────

/// Max HTTP method length. "DELETE" = 6; 16 gives room for custom methods.
/// Prevents method buffer over-read and slow-loris variants.
pub const MAX_METHOD_LEN: usize = 16;

/// Max URI length. nginx default is 8192. Prevents memory exhaustion from
/// crafted long URIs and path-traversal payloads that rely on very long paths.
pub const MAX_URI_LEN: usize = 8192;

/// Max HTTP version string length. "HTTP/1.1" = 8. 16 is generous.
pub const MAX_VERSION_LEN: usize = 16;

/// Max total request line length (method + SP + uri + SP + version + CRLF).
pub const MAX_REQUEST_LINE: usize = MAX_METHOD_LEN + 1 + MAX_URI_LEN + 1 + MAX_VERSION_LEN + 2;

// ── Headers ───────────────────────────────────────────────────────────────────

/// Max number of request headers. nginx default: 100.
/// Prevents header-count amplification (slowloris, OOM via many small headers).
pub const MAX_HEADER_COUNT: usize = 100;

/// Max length of a single header name. RFC 7230 has no limit; 256 is generous.
pub const MAX_HEADER_NAME_LEN: usize = 256;

/// Max length of a single header value. Cookie headers can be large.
/// 8192 matches nginx's large_client_header_buffers default.
pub const MAX_HEADER_VALUE_LEN: usize = 8_192;

/// Max total bytes consumed by all headers (name + ": " + value + CRLF each).
/// Prevents OOM from crafted requests with many medium-size headers.
pub const MAX_HEADERS_TOTAL_BYTES: usize = 65_536;

/// Max bytes to buffer before the request headers are fully parsed.
/// If we haven't seen \r\n\r\n within this window, the connection is dropped.
pub const MAX_HEADER_BUFFER: usize = MAX_HEADERS_TOTAL_BYTES + MAX_REQUEST_LINE;

// ── Body ──────────────────────────────────────────────────────────────────────

/// Default max request body size (overridden by client_max_body_size directive).
/// 1 MiB — conservative default, operators can raise it.
pub const DEFAULT_MAX_BODY_BYTES: usize = 1_048_576;

/// Hard ceiling regardless of client_max_body_size config.
/// Prevents operators from accidentally exposing the server to OOM via config.
pub const ABSOLUTE_MAX_BODY_BYTES: usize = 2_147_483_648; // 2 GiB

// ── Connections ───────────────────────────────────────────────────────────────

/// Default keep-alive idle timeout (seconds). nginx default: 75.
pub const DEFAULT_KEEPALIVE_TIMEOUT_S: u64 = 75;

/// Max keep-alive requests per connection. Prevents one client from
/// monopolizing a worker indefinitely via persistent connection abuse.
pub const MAX_KEEPALIVE_REQUESTS: u64 = 1_000;

/// Default read timeout for receiving the first byte of a request (seconds).
/// After this, the connection is closed with 408 Request Timeout.
pub const DEFAULT_CLIENT_HEADER_TIMEOUT_S: u64 = 60;

/// Default send timeout — if client doesn't read response for this long, drop.
pub const DEFAULT_SEND_TIMEOUT_S: u64 = 60;

// ── Config parsing ────────────────────────────────────────────────────────────

/// Max depth for include file recursion. Prevents include loops.
pub const MAX_INCLUDE_DEPTH: usize = 10;

/// Max number of server blocks in a single config.
pub const MAX_SERVER_BLOCKS: usize = 256;

/// Max number of location blocks per server.
pub const MAX_LOCATION_BLOCKS: usize = 1_024;

// ── Rate limiting ─────────────────────────────────────────────────────────────

/// Default API management rate limit (requests per second per IP).
pub const API_RATE_LIMIT_RPS: u64 = 30;
pub const API_RATE_BURST: u64 = 60;

// ── Path security ─────────────────────────────────────────────────────────────

/// Reject URI paths containing null bytes, encoded null (%00), or encoded
/// path separators (%2F, %5C) that could escape the document root jail.
/// This list is checked before any path resolution.
pub const FORBIDDEN_URI_SEQUENCES: &[&str] = &[
    "\x00", "%00",      // null byte injection
    "%2F", "%5C",       // encoded / and \ — path separator injection
    "//",               // double slash — some servers treat as root
];
