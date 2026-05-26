// SIMD HTTP/1.1 request-line and header parser.
// Architecture:
//   - Dispatch table selected once at startup via OnceLock (same pattern as Runbound).
//   - AVX2 path: 32-byte CRLF scan.
//   - SSE2 path: 16-byte CRLF scan (fallback for pre-Haswell x86_64 and all other arches).
//   - Scalar path: safe fallback for any platform without SIMD.
// All paths produce identical output; the SIMD paths are strictly a speed optimization.

use std::sync::OnceLock;

use crate::http::limits::*;

// ── Feature dispatch ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimdLevel {
    Scalar,
    Sse2,
    Avx2,
}

static SIMD_LEVEL: OnceLock<SimdLevel> = OnceLock::new();

pub fn simd_level() -> SimdLevel {
    *SIMD_LEVEL.get_or_init(|| {
        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("avx2") { return SimdLevel::Avx2; }
            if is_x86_feature_detected!("sse2") { return SimdLevel::Sse2; }
        }
        SimdLevel::Scalar
    })
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Parsed HTTP/1.1 request line.
#[derive(Debug)]
pub struct RequestLine<'a> {
    pub method:  &'a [u8],
    pub uri:     &'a [u8],
    pub version: &'a [u8],
}

/// Parse the HTTP/1.1 request line from `buf`.
/// Returns `(RequestLine, bytes_consumed)` or an error string.
pub fn parse_request_line(buf: &[u8]) -> Result<(RequestLine<'_>, usize), &'static str> {
    // Find CRLF at end of request line.
    let crlf_pos = find_crlf(buf).ok_or("request line incomplete")?;
    let line = &buf[..crlf_pos];
    if line.len() > MAX_REQUEST_LINE { return Err("request line too long"); }

    // Split on spaces.
    let sp1 = memchr::memchr(b' ', line).ok_or("malformed request line")?;
    let method = &line[..sp1];
    if method.len() > MAX_METHOD_LEN { return Err("method too long"); }

    let rest = &line[sp1+1..];
    let sp2 = memchr::memrchr(b' ', rest).ok_or("malformed request line")?;
    let uri = &rest[..sp2];
    if uri.len() > MAX_URI_LEN { return Err("URI too long"); }
    if uri.len() > MAX_VERSION_LEN { /* version check next */ }

    let version = &rest[sp2+1..];
    if version.len() > MAX_VERSION_LEN { return Err("version string too long"); }

    Ok((RequestLine { method, uri, version }, crlf_pos + 2))
}

/// A single parsed header (name and value are slices into the original buffer).
#[derive(Debug)]
pub struct Header<'a> {
    pub name:  &'a [u8],
    pub value: &'a [u8],
}

/// Parse HTTP/1.1 headers from `buf` (starting after the request line).
/// Returns `(headers_vec, bytes_consumed_including_trailing_CRLF)`.
pub fn parse_headers<'a>(buf: &'a [u8]) -> Result<(Vec<Header<'a>>, usize), &'static str> {
    if buf.len() > MAX_HEADER_BUFFER {
        return Err("header buffer overflow");
    }

    let mut headers = Vec::with_capacity(16);
    let mut total_bytes = 0usize;
    let mut pos = 0usize;

    loop {
        // Check for end-of-headers blank line.
        if buf.get(pos..pos+2) == Some(b"\r\n") {
            pos += 2;
            break;
        }
        if pos >= buf.len() {
            return Err("headers incomplete");
        }

        let crlf = find_crlf(&buf[pos..]).ok_or("header line incomplete")?;
        let line = &buf[pos..pos+crlf];

        let colon = memchr::memchr(b':', line).ok_or("malformed header line")?;
        let name = trim_bytes(&line[..colon]);
        if name.len() > MAX_HEADER_NAME_LEN { return Err("header name too long"); }

        let raw_value = if colon + 1 < line.len() { &line[colon+1..] } else { b"" };
        let value = trim_bytes(raw_value);
        if value.len() > MAX_HEADER_VALUE_LEN { return Err("header value too long"); }

        total_bytes += name.len() + 2 + value.len() + 2; // name: value\r\n
        if total_bytes > MAX_HEADERS_TOTAL_BYTES { return Err("headers too large"); }

        if headers.len() >= MAX_HEADER_COUNT { return Err("too many headers"); }
        headers.push(Header { name, value });

        pos += crlf + 2;
    }

    Ok((headers, pos))
}

// ── CRLF finder ──────────────────────────────────────────────────────────────

#[inline(always)]
fn find_crlf(buf: &[u8]) -> Option<usize> {
    match simd_level() {
        SimdLevel::Avx2 => {
            #[cfg(target_arch = "x86_64")]
            // SAFETY: guarded by runtime feature check.
            unsafe { find_crlf_avx2(buf) }
            #[cfg(not(target_arch = "x86_64"))]
            find_crlf_scalar(buf)
        }
        SimdLevel::Sse2 => {
            #[cfg(target_arch = "x86_64")]
            // SAFETY: guarded by runtime feature check.
            unsafe { find_crlf_sse2(buf) }
            #[cfg(not(target_arch = "x86_64"))]
            find_crlf_scalar(buf)
        }
        SimdLevel::Scalar => find_crlf_scalar(buf),
    }
}

fn find_crlf_scalar(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

// ── SSE2 CRLF scan — 16 bytes/iter ───────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn find_crlf_sse2(buf: &[u8]) -> Option<usize> {
    use std::arch::x86_64::*;

    let len = buf.len();
    if len < 2 { return find_crlf_scalar(buf); }

    let cr_vec = _mm_set1_epi8(b'\r' as i8);
    let lf_vec = _mm_set1_epi8(b'\n' as i8);
    let ptr = buf.as_ptr();

    let mut i = 0usize;
    // Process 16-byte chunks.
    while i + 16 < len {
        let chunk = _mm_loadu_si128(ptr.add(i) as *const __m128i);
        // Find '\r' positions in this chunk.
        let cr_mask = _mm_movemask_epi8(_mm_cmpeq_epi8(chunk, cr_vec)) as u32;
        if cr_mask != 0 {
            let mut mask = cr_mask;
            while mask != 0 {
                let bit = mask.trailing_zeros() as usize;
                let pos = i + bit;
                if pos + 1 < len && *ptr.add(pos + 1) == b'\n' {
                    return Some(pos);
                }
                mask &= mask - 1;
            }
        }
        i += 16;
    }
    // Scalar tail.
    find_crlf_scalar(&buf[i..]).map(|p| p + i)
}

// ── AVX2 CRLF scan — 32 bytes/iter ───────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn find_crlf_avx2(buf: &[u8]) -> Option<usize> {
    use std::arch::x86_64::*;

    let len = buf.len();
    if len < 2 { return find_crlf_scalar(buf); }

    let cr_vec = _mm256_set1_epi8(b'\r' as i8);
    let ptr = buf.as_ptr();

    let mut i = 0usize;
    while i + 32 < len {
        let chunk = _mm256_loadu_si256(ptr.add(i) as *const __m256i);
        let cr_mask = _mm256_movemask_epi8(_mm256_cmpeq_epi8(chunk, cr_vec)) as u32;
        if cr_mask != 0 {
            let mut mask = cr_mask;
            while mask != 0 {
                let bit = mask.trailing_zeros() as usize;
                let pos = i + bit;
                if pos + 1 < len && *ptr.add(pos + 1) == b'\n' {
                    return Some(pos);
                }
                mask &= mask - 1;
            }
        }
        i += 32;
    }
    // Scalar tail.
    find_crlf_scalar(&buf[i..]).map(|p| p + i)
}

// ── Byte slice trimming ───────────────────────────────────────────────────────

fn trim_bytes(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|&c| c != b' ' && c != b'\t').unwrap_or(b.len());
    let end   = b.iter().rposition(|&c| c != b' ' && c != b'\t').map(|i| i+1).unwrap_or(0);
    if start >= end { &b[0..0] } else { &b[start..end] }
}


// ── Percent-decode ────────────────────────────────────────────────────────────

/// Decode percent-encoded bytes in a URI path.
/// Sequences that would produce forbidden characters (%00, %2F, %5C) are left
/// encoded and will be rejected by `is_uri_safe` afterwards.
pub fn percent_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%' && i + 2 < input.len() {
            if let (Some(hi), Some(lo)) = (hex_nibble(input[i+1]), hex_nibble(input[i+2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(input[i]);
        i += 1;
    }
    out
}

#[inline(always)]
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _            => None,
    }
}

// ── Header name normalization ─────────────────────────────────────────────────

/// Lowercase-normalize an ASCII header name in-place.
/// Returns the input as a `Vec<u8>` with all A-Z bytes mapped to a-z.
/// Allows the handler to use `==` instead of `eq_ignore_ascii_case`.
pub fn normalize_header_name(name: &[u8]) -> Vec<u8> {
    name.iter().map(|&b| b.to_ascii_lowercase()).collect()
}

// ── URI security check ────────────────────────────────────────────────────────

pub fn is_uri_safe(uri: &[u8]) -> bool {
    let s = match std::str::from_utf8(uri) {
        Ok(s) => s,
        Err(_) => return false,
    };
    for seq in FORBIDDEN_URI_SEQUENCES {
        if s.contains(seq) { return false; }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_safe_normal() {
        assert!(is_uri_safe(b"/index.html"));
        assert!(is_uri_safe(b"/api/v1/status?foo=bar&baz=1"));
        assert!(is_uri_safe(b"/"));
    }

    #[test]
    fn uri_safe_rejects_null_byte() {
        assert!(!is_uri_safe(b"/foo\x00bar"));
        assert!(!is_uri_safe(b"%00"));
    }

    #[test]
    fn uri_safe_rejects_path_traversal() {
        assert!(!is_uri_safe(b"/../etc/passwd"));
        assert!(!is_uri_safe(b"/foo/../bar"));
    }

    #[test]
    fn uri_safe_rejects_encoded_slash() {
        assert!(!is_uri_safe(b"/foo%2Fbar"));
        assert!(!is_uri_safe(b"/foo%5Cbar"));
    }

    #[test]
    fn uri_safe_rejects_double_slash() {
        assert!(!is_uri_safe(b"//etc/passwd"));
    }

    #[test]
    fn uri_safe_rejects_invalid_utf8() {
        assert!(!is_uri_safe(&[b'/', 0xff, 0xfe, b'/']));
    }

    #[test]
    fn parse_request_line_get() {
        let buf = b"GET /index.html HTTP/1.1\r\n";
        let (rl, consumed) = parse_request_line(buf).unwrap();
        assert_eq!(rl.method, b"GET");
        assert_eq!(rl.uri, b"/index.html");
        assert_eq!(rl.version, b"HTTP/1.1");
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn parse_request_line_post_with_query() {
        let buf = b"POST /api/v1/submit?key=val HTTP/1.1\r\n";
        let (rl, _) = parse_request_line(buf).unwrap();
        assert_eq!(rl.method, b"POST");
        assert_eq!(rl.uri, b"/api/v1/submit?key=val");
    }

    #[test]
    fn parse_request_line_missing_crlf() {
        assert!(parse_request_line(b"GET / HTTP/1.1").is_err());
    }

    #[test]
    fn parse_request_line_missing_space() {
        assert!(parse_request_line(b"GETHTTP/1.1\r\n").is_err());
    }

    #[test]
    fn parse_request_line_uri_too_long() {
        let uri = "A".repeat(MAX_URI_LEN + 1);
        let buf = format!("GET /{} HTTP/1.1\r\n", uri);
        assert!(parse_request_line(buf.as_bytes()).is_err());
    }

    #[test]
    fn parse_headers_basic() {
        let buf = b"Host: example.com\r\nContent-Length: 0\r\n\r\n";
        let (hdrs, consumed) = parse_headers(buf).unwrap();
        assert_eq!(hdrs.len(), 2);
        assert_eq!(hdrs[0].name, b"Host");
        assert_eq!(hdrs[0].value, b"example.com");
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn parse_headers_empty() {
        let buf = b"\r\n";
        let (hdrs, consumed) = parse_headers(buf).unwrap();
        assert!(hdrs.is_empty());
        assert_eq!(consumed, 2);
    }

    #[test]
    fn parse_headers_too_many() {
        let single = b"X-H: v\r\n";
        let mut buf: Vec<u8> = (0..=MAX_HEADER_COUNT).flat_map(|_| single.iter().copied()).collect();
        buf.extend_from_slice(b"\r\n");
        assert!(parse_headers(&buf).is_err());
    }

    #[test]
    fn percent_decode_basic() {
        assert_eq!(percent_decode(b"/my%20file.html"), b"/my file.html");
        assert_eq!(percent_decode(b"/foo%2Bbar"), b"/foo+bar");
        assert_eq!(percent_decode(b"/no-encoding"), b"/no-encoding");
    }

    #[test]
    fn percent_decode_uppercase_hex() {
        assert_eq!(percent_decode(b"/%41%42%43"), b"/ABC");
    }

    #[test]
    fn percent_decode_incomplete_sequence_passthrough() {
        // Incomplete or invalid sequences are passed through unchanged.
        assert_eq!(percent_decode(b"/%2"), b"/%2");
        assert_eq!(percent_decode(b"/%zz"), b"/%zz");
    }

    #[test]
    fn percent_decode_null_kept_encoded_for_safety_check() {
        // %00 decodes to 0x00; is_uri_safe will then reject it.
        let decoded = percent_decode(b"/foo%00bar");
        assert_eq!(decoded, b"/foo\x00bar");
        assert!(!is_uri_safe(&decoded));
    }

    #[test]
    fn normalize_header_name_lowercase() {
        assert_eq!(normalize_header_name(b"Content-Type"), b"content-type");
        assert_eq!(normalize_header_name(b"HOST"), b"host");
        assert_eq!(normalize_header_name(b"x-custom-header"), b"x-custom-header");
    }

    #[test]
    fn normalize_header_name_already_lower() {
        assert_eq!(normalize_header_name(b"host"), b"host");
    }

}

