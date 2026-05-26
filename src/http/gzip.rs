// Gzip response compression.
// Applied when:
//   1. gzip is enabled in the matching location (or server/http block)
//   2. The request has Accept-Encoding: gzip
//   3. The response Content-Type is in gzip_types
//   4. The response body is >= gzip_min_length bytes

use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::Write;

pub struct GzipConfig {
    pub enabled:    bool,
    pub min_length: usize,
    pub types:      Vec<String>,
}

/// Try to gzip compress a response body.
/// Returns (compressed_body, "gzip") if compression applies, (original, "") otherwise.
pub fn maybe_compress(
    body:        Vec<u8>,
    content_type: &str,
    accept_enc:  Option<&str>,
    cfg:         &GzipConfig,
) -> (Vec<u8>, bool) {
    if !cfg.enabled { return (body, false); }
    if body.len() < cfg.min_length { return (body, false); }

    // Check Accept-Encoding.
    let accepts_gzip = accept_enc
        .map(|v| v.contains("gzip"))
        .unwrap_or(false);
    if !accepts_gzip { return (body, false); }

    // Check MIME type.
    let base_type = content_type.split(';').next().unwrap_or("").trim();
    let type_ok = cfg.types.iter().any(|t| t.as_str() == base_type);
    if !type_ok { return (body, false); }

    match compress_gzip(&body) {
        Ok(compressed) if compressed.len() < body.len() => (compressed, true),
        _ => (body, false),
    }
}

fn compress_gzip(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut enc = GzEncoder::new(Vec::with_capacity(data.len() / 2), Compression::default());
    enc.write_all(data)?;
    enc.finish()
}
