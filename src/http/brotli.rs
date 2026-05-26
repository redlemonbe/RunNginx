// Brotli compression helper — mirrors gzip::maybe_compress interface.

pub struct BrotliConfig {
    pub enabled:    bool,
    pub min_length: usize,
    pub types:      Vec<String>,
}

pub fn maybe_brotli(
    body:         Vec<u8>,
    content_type: &str,
    accept_enc:   Option<&str>,
    cfg:          &BrotliConfig,
) -> (Vec<u8>, bool) {
    if !cfg.enabled { return (body, false); }
    if body.len() < cfg.min_length { return (body, false); }

    let accepts_br = accept_enc
        .map(|enc| enc.split(',').any(|t| t.trim() == "br"))
        .unwrap_or(false);
    if !accepts_br { return (body, false); }

    let ct = content_type.split(';').next().unwrap_or("").trim();
    let type_match = cfg.types.iter().any(|t| t == ct);
    if !type_match { return (body, false); }

    #[cfg(feature = "brotli")]
    {
        let mut compressed = Vec::new();
        let quality = 6u32; // balance speed/ratio
        let lgwin = 22u32;
        let result = brotli::BrotliCompress(
            &mut std::io::Cursor::new(&body),
            &mut compressed,
            &brotli::enc::BrotliEncoderParams {
                quality: quality as i32,
                lgwin: lgwin as i32,
                ..Default::default()
            },
        );
        match result {
            Ok(_) if compressed.len() < body.len() => (compressed, true),
            _ => (body, false),
        }
    }

    #[cfg(not(feature = "brotli"))]
    { (body, false) }
}
