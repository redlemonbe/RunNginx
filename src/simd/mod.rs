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
    if buf.len() > MAX_REQUEST_LINE {
        return Err("request line too long");
    }
    // Find CRLF at end of request line.
    let crlf_pos = find_crlf(buf).ok_or("request line incomplete")?;
    let line = &buf[..crlf_pos];

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
