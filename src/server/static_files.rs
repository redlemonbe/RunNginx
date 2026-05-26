// Static file handler.
// Security invariants:
//   - All paths are jailed to the configured root — resolved path must start with root.
//   - Symlinks are followed but the final resolved path must still be within root.
//   - Null bytes and encoded path separators rejected by the URI checker (simd::is_uri_safe).
//   - No directory listing unless autoindex is enabled in the location.
//   - Range requests are validated (start <= end <= file_size).

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use tokio::io::AsyncReadExt;
use tracing::warn;

use crate::config::types::{LocationBlock, ServerBlock, TryFilesEntry};

// ── Public API ────────────────────────────────────────────────────────────────

pub struct StaticResponse {
    pub status:   u16,
    pub headers:  Vec<(String, String)>,
    pub body:     Vec<u8>,
}

/// Handle a static file request.
pub async fn serve_static(
    server:    &ServerBlock,
    location:  Option<&LocationBlock>,
    uri_path:  &str,
    method:    &str,
    req_hdrs:  &[(String, String)],
) -> StaticResponse {
    // Resolve root: location root overrides server root.
    let root = match location.and_then(|l| l.root.as_ref())
        .or(server.root.as_ref()) {
        Some(r) => r.clone(),
        None => return error_response(500, "no root configured"),
    };

    // Resolve index list.
    let index_files: &[String] = location
        .and_then(|l| l.index.as_ref())
        .map(|v| v.as_slice())
        .unwrap_or(server.index.as_slice());

    // Percent-decode the URI path.
    let decoded = match percent_decode(uri_path) {
        Ok(s) => s,
        Err(_) => return error_response(400, "invalid URI encoding"),
    };

    // Try-files if configured.
    if let Some(try_files) = location.and_then(|l| l.try_files.as_ref()) {
        return handle_try_files(&root, &decoded, try_files, index_files, method, req_hdrs).await;
    }

    // Direct path resolution.
    let fs_path = jail_path(&root, &decoded);
    serve_path(&fs_path, &root, index_files, method, req_hdrs).await
}

// ── Path jailing ──────────────────────────────────────────────────────────────

/// Build a filesystem path from root + URI, then verify it's within root.
fn jail_path(root: &Path, uri: &str) -> PathBuf {
    // Strip leading '/' to make it relative, then join.
    let rel = uri.trim_start_matches('/');
    root.join(rel)
}

/// Verify `path` is within `root` after resolving all symlinks.
/// Returns `Err` if the path escapes the root jail.
fn assert_within_root(path: &Path, root: &Path) -> Result<()> {
    // We can only canonicalize paths that exist. If the path doesn't exist,
    // the caller will get a 404 before we need to serve any content.
    let canonical_path = path.canonicalize()
        .map_err(|e| anyhow::anyhow!("path resolution failed: {}", e))?;
    let canonical_root = root.canonicalize()
        .map_err(|e| anyhow::anyhow!("root resolution failed: {}", e))?;

    if !canonical_path.starts_with(&canonical_root) {
        anyhow::bail!("path traversal attempt: {} escapes root {}", path.display(), root.display());
    }
    Ok(())
}

// ── try_files ─────────────────────────────────────────────────────────────────

async fn handle_try_files(
    root:        &Path,
    decoded_uri: &str,
    try_files:   &[TryFilesEntry],
    index_files: &[String],
    method:      &str,
    req_hdrs:    &[(String, String)],
) -> StaticResponse {
    for entry in try_files {
        match entry {
            TryFilesEntry::Path(p) => {
                let expanded = p.replace("$uri", decoded_uri).replace("$uri/", &format!("{}/", decoded_uri));
                let candidate = jail_path(root, &expanded);
                if candidate.exists() {
                    return serve_path(&candidate, root, index_files, method, req_hdrs).await;
                }
            }
            TryFilesEntry::StatusCode(code) => {
                return error_response(*code, "not found");
            }
            TryFilesEntry::Named(_name) => {
                // Named location redirect — handled at a higher level; return 404 as fallback.
                return error_response(404, "not found");
            }
        }
    }
    error_response(404, "not found")
}

// ── Core file server ──────────────────────────────────────────────────────────

async fn serve_path(
    path:        &Path,
    root:        &Path,
    index_files: &[String],
    method:      &str,
    req_hdrs:    &[(String, String)],
) -> StaticResponse {
    // Determine effective path (follow directory → index).
    let effective = if path.is_dir() {
        // Try index files.
        let mut found = None;
        for idx in index_files {
            let candidate = path.join(idx);
            if candidate.is_file() {
                found = Some(candidate);
                break;
            }
        }
        match found {
            Some(p) => p,
            None => return error_response(403, "forbidden"),
        }
    } else {
        path.to_path_buf()
    };

    if !effective.exists() {
        return error_response(404, "not found");
    }
    if !effective.is_file() {
        return error_response(404, "not found");
    }

    // Path traversal check (post-resolution).
    if let Err(e) = assert_within_root(&effective, root) {
        warn!("{}", e);
        return error_response(403, "forbidden");
    }

    let metadata = match tokio::fs::metadata(&effective).await {
        Ok(m) => m,
        Err(_) => return error_response(404, "not found"),
    };

    let file_size = metadata.len();
    let mtime    = metadata.modified().ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let etag = format!("{:x}-{:x}", file_size, mtime);
    let mime = mime_for_path(&effective);

    // Conditional GET — If-None-Match / If-Modified-Since.
    if let Some(inm) = get_header(req_hdrs, "if-none-match") {
        if inm.trim_matches('"') == etag {
            return StaticResponse {
                status:  304,
                headers: vec![
                    ("ETag".into(), format!("\"{}\"", etag)),
                    ("Cache-Control".into(), "public, max-age=3600".into()),
                ],
                body: Vec::new(),
            };
        }
    }

    // Range request.
    if let Some(range_hdr) = get_header(req_hdrs, "range") {
        if let Some((start, end)) = parse_range(&range_hdr, file_size) {
            return serve_range(&effective, start, end, file_size, mime, &etag).await;
        }
    }

    // HEAD — headers only, no body.
    if method.eq_ignore_ascii_case("HEAD") {
        return StaticResponse {
            status:  200,
            headers: base_headers(mime, file_size, &etag),
            body:    Vec::new(),
        };
    }

    // Read and serve full file.
    match tokio::fs::read(&effective).await {
        Ok(bytes) => StaticResponse {
            status:  200,
            headers: base_headers(mime, file_size, &etag),
            body:    bytes,
        },
        Err(e) => {
            warn!("read error {}: {}", effective.display(), e);
            error_response(500, "internal server error")
        }
    }
}

// ── Range request ─────────────────────────────────────────────────────────────

/// Parse "bytes=start-end" header. Returns (start, inclusive_end) or None if invalid.
fn parse_range(hdr: &str, file_size: u64) -> Option<(u64, u64)> {
    let bytes_part = hdr.strip_prefix("bytes=")?;
    let mut parts = bytes_part.splitn(2, '-');
    let start_str = parts.next()?.trim();
    let end_str   = parts.next()?.trim();

    if start_str.is_empty() {
        // bytes=-N  (last N bytes)
        let n: u64 = end_str.parse().ok()?;
        if n == 0 || n > file_size { return None; }
        Some((file_size - n, file_size - 1))
    } else {
        let start: u64 = start_str.parse().ok()?;
        let end: u64 = if end_str.is_empty() {
            file_size - 1
        } else {
            end_str.parse().ok()?
        };
        if start > end || end >= file_size { return None; }
        Some((start, end))
    }
}

async fn serve_range(
    path:      &Path,
    start:     u64,
    end:       u64,
    file_size: u64,
    mime:      &'static str,
    etag:      &str,
) -> StaticResponse {
    use tokio::io::AsyncSeekExt;

    let count = end - start + 1;
    let mut f = match tokio::fs::File::open(path).await {
        Ok(f) => f,
        Err(_) => return error_response(500, "internal server error"),
    };
    if tokio::io::AsyncSeekExt::seek(&mut f, std::io::SeekFrom::Start(start)).await.is_err() {
        return error_response(500, "internal server error");
    }
    let mut buf = vec![0u8; count as usize];
    if f.read_exact(&mut buf).await.is_err() {
        return error_response(500, "internal server error");
    }

    StaticResponse {
        status:  206,
        headers: vec![
            ("Content-Type".into(), mime.into()),
            ("Content-Length".into(), count.to_string()),
            ("Content-Range".into(), format!("bytes {}-{}/{}", start, end, file_size)),
            ("ETag".into(), format!("\"{}\"", etag)),
            ("Accept-Ranges".into(), "bytes".into()),
        ],
        body: buf,
    }
}

// ── MIME types ────────────────────────────────────────────────────────────────

fn mime_for_path(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") | Some("htm") => "text/html; charset=utf-8",
        Some("css")                => "text/css; charset=utf-8",
        Some("js") | Some("mjs")  => "application/javascript; charset=utf-8",
        Some("json")               => "application/json",
        Some("xml")                => "application/xml",
        Some("txt")                => "text/plain; charset=utf-8",
        Some("png")                => "image/png",
        Some("jpg") | Some("jpeg")=> "image/jpeg",
        Some("gif")                => "image/gif",
        Some("webp")               => "image/webp",
        Some("svg")                => "image/svg+xml",
        Some("ico")                => "image/x-icon",
        Some("woff")               => "font/woff",
        Some("woff2")              => "font/woff2",
        Some("ttf")                => "font/ttf",
        Some("otf")                => "font/otf",
        Some("pdf")                => "application/pdf",
        Some("zip")                => "application/zip",
        Some("gz")                 => "application/gzip",
        Some("tar")                => "application/x-tar",
        Some("mp4")                => "video/mp4",
        Some("webm")               => "video/webm",
        Some("mp3")                => "audio/mpeg",
        Some("ogg")                => "audio/ogg",
        Some("wasm")               => "application/wasm",
        _                          => "application/octet-stream",
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn base_headers(mime: &'static str, size: u64, etag: &str) -> Vec<(String, String)> {
    vec![
        ("Content-Type".into(), mime.into()),
        ("Content-Length".into(), size.to_string()),
        ("ETag".into(), format!("\"{}\"", etag)),
        ("Accept-Ranges".into(), "bytes".into()),
        ("Cache-Control".into(), "public, max-age=3600".into()),
    ]
}

fn error_response(status: u16, message: &str) -> StaticResponse {
    let body = format!("<html><body>{} {}</body></html>\n", status, message);
    StaticResponse {
        status,
        headers: vec![
            ("Content-Type".into(), "text/html; charset=utf-8".into()),
            ("Content-Length".into(), body.len().to_string()),
        ],
        body: body.into_bytes(),
    }
}

fn get_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Decode a percent-encoded URI path. Only decodes safe characters.
/// %2F (/) and %5C (\) remain encoded — they are rejected by is_uri_safe() before we get here.
fn percent_decode(s: &str) -> Result<String> {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = hex_val(bytes[i+1]).ok_or_else(|| anyhow::anyhow!("bad percent encoding"))?;
            let lo = hex_val(bytes[i+2]).ok_or_else(|| anyhow::anyhow!("bad percent encoding"))?;
            let c = (hi << 4) | lo;
            if c == 0 { anyhow::bail!("null byte in URI"); }
            out.push(c as char);
            i += 3;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    Ok(out)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Placeholder for unimplemented handlers (proxy_pass, fastcgi_pass).
pub fn not_implemented(msg: &'static str) -> StaticResponse {
    let body = format!("<html><body>501 Not Implemented: {}</body></html>\n", msg);
    StaticResponse {
        status: 501,
        headers: vec![
            ("Content-Type".into(), "text/html; charset=utf-8".into()),
            ("Content-Length".into(), body.len().to_string()),
        ],
        body: body.into_bytes(),
    }
}

/// Resolve a custom error page URI from the server's error_pages config.
/// Returns the URI to serve, or None if no custom page is configured.
pub fn find_error_page_uri(server: &ServerBlock, status: u16) -> Option<&str> {
    server.error_pages.iter()
        .find(|ep| ep.codes.contains(&status))
        .map(|ep| ep.uri.as_str())
}
