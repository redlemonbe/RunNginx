// HTTP Basic Authentication — htpasswd file verification.
// Supports bcrypt ($2y$/$2b$/$2a$) and plaintext.
// {SHA} entries are rejected (deprecated, insecure).

use std::path::Path;

pub fn check_basic_auth(user_file: &Path, authorization: &str) -> bool {
    let encoded = match authorization.strip_prefix("Basic ") {
        Some(s) => s.trim(),
        None => return false,
    };

    let decoded = match base64_decode(encoded) {
        Some(d) => d,
        None => return false,
    };

    let colon = match decoded.find(':') {
        Some(i) => i,
        None => return false,
    };
    let username = &decoded[..colon];
    let password = &decoded[colon+1..];

    let Ok(contents) = std::fs::read_to_string(user_file) else { return false };

    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        let Some(col) = line.find(':') else { continue };
        if &line[..col] != username { continue; }
        let hash = &line[col+1..];
        return verify_password(password, hash);
    }
    false
}

fn verify_password(password: &str, hash: &str) -> bool {
    if hash.starts_with("$2y$") || hash.starts_with("$2b$") || hash.starts_with("$2a$") {
        let normalized = if hash.starts_with("$2y$") {
            format!("$2b${}", &hash[4..])
        } else {
            hash.to_owned()
        };
        bcrypt::verify(password, &normalized).unwrap_or_else(|e| { tracing::warn!("bcrypt verify error: {e}"); false })
    } else if hash.starts_with("{SHA}") || hash.starts_with("$apr1$") || hash.starts_with("$1$") {
        false  // MD5/SHA1 deprecated — denied
    } else {
        hash == password  // plaintext (legacy test use only)
    }
}

fn base64_decode(s: &str) -> Option<String> {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let indices: Vec<u8> = s.bytes()
        .filter(|&b| b != b'=')
        .filter_map(|b| TABLE.iter().position(|&t| t == b).map(|p| p as u8))
        .collect();

    let mut out = Vec::new();
    for chunk in indices.chunks(4) {
        let a = chunk[0];
        let b = *chunk.get(1).unwrap_or(&0);
        let c = *chunk.get(2).unwrap_or(&0);
        let d = *chunk.get(3).unwrap_or(&0);
        let n = ((a as u32) << 18) | ((b as u32) << 12) | ((c as u32) << 6) | (d as u32);
        out.push((n >> 16) as u8);
        if chunk.len() >= 3 { out.push((n >> 8) as u8); }
        if chunk.len() >= 4 { out.push(n as u8); }
    }
    String::from_utf8(out).ok()
}

pub fn unauthorized_response(realm: &str) -> Vec<u8> {
    let challenge = format!("Basic realm=\"{}\"", realm.replace('"', "\\\""));
    let body = b"401 Unauthorized";
    let mut r = format!(
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: {}\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: keep-alive\r\n\r\n",
        challenge, body.len()
    ).into_bytes();
    r.extend_from_slice(body);
    r
}
