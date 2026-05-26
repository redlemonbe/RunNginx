// FastCGI client — implements enough of the FastCGI protocol to talk to PHP-FPM.
// Reference: https://fastcgi-fr.net/dev/docs/FastCGI_Specification.md
// We implement: BEGIN_REQUEST, PARAMS, STDIN, STDOUT, END_REQUEST record types.

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use tokio::time::timeout;

use crate::config::types::{FastCgiConfig, FastCgiUpstream};
use crate::server::static_files::StaticResponse;

// ── FastCGI record constants ──────────────────────────────────────────────────

const FCGI_VERSION: u8 = 1;
const FCGI_BEGIN_REQUEST: u8 = 1;
const FCGI_ABORT_REQUEST: u8 = 2;
const FCGI_END_REQUEST:   u8 = 3;
const FCGI_PARAMS:        u8 = 4;
const FCGI_STDIN:         u8 = 5;
const FCGI_STDOUT:        u8 = 6;
const FCGI_STDERR:        u8 = 7;
const FCGI_RESPONDER:     u16 = 1;

const REQUEST_ID: u16 = 1;

// ── Public API ────────────────────────────────────────────────────────────────

pub async fn fastcgi_request(
    cfg:         &FastCgiConfig,
    method:      &str,
    uri:         &str,
    script_path: &str,    // SCRIPT_FILENAME — absolute path on disk
    headers:     &[(String, String)],
    body:        &[u8],
) -> StaticResponse {
    match do_fastcgi(cfg, method, uri, script_path, headers, body).await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::warn!("fastcgi error: {}", e);
            fcgi_error(502, &e.to_string())
        }
    }
}

// ── Protocol implementation ───────────────────────────────────────────────────

async fn do_fastcgi(
    cfg:         &FastCgiConfig,
    method:      &str,
    uri:         &str,
    script_path: &str,
    headers:     &[(String, String)],
    body:        &[u8],
) -> Result<StaticResponse> {
    // Build params map.
    let mut params = build_params(method, uri, script_path, headers, body.len(), cfg);

    // Connect to upstream.
    let connect_timeout = Duration::from_secs(cfg.connect_timeout);
    let read_timeout    = Duration::from_secs(cfg.read_timeout);

    match &cfg.upstream {
        FastCgiUpstream::UnixSocket(path) => {
            let stream = timeout(connect_timeout, UnixStream::connect(path)).await
                .map_err(|_| anyhow::anyhow!("fastcgi connect timeout"))??;
            run_fastcgi(stream, params, body, read_timeout).await
        }
        FastCgiUpstream::Tcp(addr) => {
            let stream = timeout(connect_timeout, TcpStream::connect(addr)).await
                .map_err(|_| anyhow::anyhow!("fastcgi connect timeout"))??;
            run_fastcgi(stream, params, body, read_timeout).await
        }
    }
}

async fn run_fastcgi<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    mut stream:      S,
    params:          HashMap<String, String>,
    body:            &[u8],
    read_timeout:    Duration,
) -> Result<StaticResponse> {
    // 1. BEGIN_REQUEST record.
    stream.write_all(&begin_request_record(REQUEST_ID)).await?;

    // 2. PARAMS records.
    let encoded_params = encode_params(&params);
    for chunk in encoded_params.chunks(65000) {
        stream.write_all(&make_record(FCGI_PARAMS, REQUEST_ID, chunk)).await?;
    }
    // Empty PARAMS to signal end of params.
    stream.write_all(&make_record(FCGI_PARAMS, REQUEST_ID, &[])).await?;

    // 3. STDIN records (request body).
    for chunk in body.chunks(65000) {
        stream.write_all(&make_record(FCGI_STDIN, REQUEST_ID, chunk)).await?;
    }
    // Empty STDIN to signal end of body.
    stream.write_all(&make_record(FCGI_STDIN, REQUEST_ID, &[])).await?;

    // 4. Read STDOUT records until END_REQUEST.
    let mut stdout_buf = Vec::new();

    loop {
        let header = read_record_header(&mut stream, read_timeout).await?;
        let (record_type, content_len, padding_len) = header;

        let mut content = vec![0u8; content_len as usize];
        timeout(read_timeout, stream.read_exact(&mut content)).await
            .map_err(|_| anyhow::anyhow!("fastcgi read timeout"))?
            .context("reading fastcgi record content")?;

        // Skip padding.
        if padding_len > 0 {
            let mut pad = vec![0u8; padding_len as usize];
            let _ = timeout(read_timeout, stream.read_exact(&mut pad)).await;
        }

        match record_type {
            FCGI_STDOUT => stdout_buf.extend_from_slice(&content),
            FCGI_STDERR => {
                let msg = String::from_utf8_lossy(&content);
                if !msg.trim().is_empty() {
                    tracing::warn!("fastcgi stderr: {}", msg.trim());
                }
            }
            FCGI_END_REQUEST => break,
            _ => {} // ignore unknown record types
        }
    }

    parse_cgi_response(&stdout_buf)
}

// ── Record builders ───────────────────────────────────────────────────────────

fn begin_request_record(id: u16) -> Vec<u8> {
    let mut body = vec![0u8; 8];
    // role = RESPONDER (1)
    body[0] = (FCGI_RESPONDER >> 8) as u8;
    body[1] = (FCGI_RESPONDER & 0xff) as u8;
    // flags = 0 (don't keep connection)
    make_record(FCGI_BEGIN_REQUEST, id, &body)
}

fn make_record(record_type: u8, id: u16, content: &[u8]) -> Vec<u8> {
    let len = content.len() as u16;
    let mut rec = Vec::with_capacity(8 + content.len());
    rec.push(FCGI_VERSION);
    rec.push(record_type);
    rec.push((id >> 8) as u8);
    rec.push((id & 0xff) as u8);
    rec.push((len >> 8) as u8);
    rec.push((len & 0xff) as u8);
    rec.push(0); // padding length
    rec.push(0); // reserved
    rec.extend_from_slice(content);
    rec
}

async fn read_record_header<S: AsyncReadExt + Unpin>(
    stream: &mut S,
    timeout_dur: Duration,
) -> Result<(u8, u16, u8)> {
    let mut hdr = [0u8; 8];
    timeout(timeout_dur, stream.read_exact(&mut hdr)).await
        .map_err(|_| anyhow::anyhow!("fastcgi read timeout"))?
        .context("reading fastcgi record header")?;

    let record_type = hdr[1];
    let content_len = ((hdr[4] as u16) << 8) | (hdr[5] as u16);
    let padding_len = hdr[6];
    Ok((record_type, content_len, padding_len))
}

// ── Params encoding ───────────────────────────────────────────────────────────

fn encode_params(params: &HashMap<String, String>) -> Vec<u8> {
    let mut out = Vec::new();
    for (k, v) in params {
        encode_length(&mut out, k.len());
        encode_length(&mut out, v.len());
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(v.as_bytes());
    }
    out
}

fn encode_length(buf: &mut Vec<u8>, len: usize) {
    if len < 128 {
        buf.push(len as u8);
    } else {
        buf.push(((len >> 24) as u8) | 0x80);
        buf.push((len >> 16) as u8);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

fn build_params(
    method:      &str,
    uri:         &str,
    script_path: &str,
    headers:     &[(String, String)],
    body_len:    usize,
    cfg:         &FastCgiConfig,
) -> HashMap<String, String> {
    let (path, query) = if let Some(q) = uri.find('?') {
        (&uri[..q], &uri[q+1..])
    } else {
        (uri, "")
    };

    let mut p = HashMap::new();
    p.insert("SCRIPT_FILENAME".into(), script_path.to_owned());
    p.insert("SCRIPT_NAME".into(),    path.to_owned());
    p.insert("REQUEST_URI".into(),    uri.to_owned());
    p.insert("QUERY_STRING".into(),   query.to_owned());
    p.insert("REQUEST_METHOD".into(), method.to_ascii_uppercase());
    p.insert("CONTENT_LENGTH".into(), body_len.to_string());
    p.insert("SERVER_SOFTWARE".into(), format!("RunNginx/{}", env!("CARGO_PKG_VERSION")));
    p.insert("GATEWAY_INTERFACE".into(), "CGI/1.1".into());
    p.insert("SERVER_PROTOCOL".into(), "HTTP/1.1".into());
    p.insert("REDIRECT_STATUS".into(), "200".into()); // required for PHP-FPM

    // FastCGI index (default: index.php)
    let index = cfg.index.as_deref().unwrap_or("index.php");
    p.insert("FCGI_SCRIPT_NAME".into(), index.to_owned());

    // Convert HTTP headers to CGI env vars.
    let content_type = headers.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    p.insert("CONTENT_TYPE".into(), content_type.to_owned());

    for (k, v) in headers {
        if k.eq_ignore_ascii_case("content-type")
            || k.eq_ignore_ascii_case("content-length")
            || k.eq_ignore_ascii_case("proxy")  // httpoxy mitigation
        {
            continue;
        }
        let env_key = format!("HTTP_{}", k.replace('-', "_").to_ascii_uppercase());
        p.insert(env_key, v.clone());
    }

    // Apply fastcgi_param overrides from config.
    for (k, v) in &cfg.params {
        p.insert(k.clone(), v.clone());
    }

    p
}

// ── CGI response parser ───────────────────────────────────────────────────────

fn parse_cgi_response(data: &[u8]) -> Result<StaticResponse> {
    let crlf_crlf = data.windows(4).position(|w| w == b"\r\n\r\n");
    let lf_lf     = data.windows(2).position(|w| w == b"\n\n");

    let (hdr_end, body_start) = match (crlf_crlf, lf_lf) {
        (Some(a), Some(b)) if a <= b => (a, a + 4),
        (Some(a), _) => (a, a + 4),
        (_, Some(b)) => (b, b + 2),
        (None, None) => anyhow::bail!("no header terminator in FastCGI response"),
    };

    let header_str = std::str::from_utf8(&data[..hdr_end])?;
    let body = data[body_start..].to_vec();

    let mut status: u16 = 200;
    let mut resp_headers: Vec<(String, String)> = Vec::new();

    for line in header_str.lines() {
        if line.is_empty() { continue; }
        if let Some(rest) = line.strip_prefix("Status:") {
            status = rest.trim().split_whitespace().next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(200);
        } else if let Some(colon) = line.find(':') {
            resp_headers.push((
                line[..colon].trim().to_owned(),
                line[colon+1..].trim().to_owned(),
            ));
        }
    }

    // Ensure Content-Length is set.
    if !resp_headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-length")) {
        resp_headers.push(("Content-Length".into(), body.len().to_string()));
    }

    Ok(StaticResponse { status, headers: resp_headers, body })
}

fn fcgi_error(status: u16, msg: &str) -> StaticResponse {
    let body = format!("<html><body>{} FastCGI Error: {}</body></html>\n", status, msg);
    StaticResponse {
        status,
        headers: vec![
            ("Content-Type".into(), "text/html; charset=utf-8".into()),
            ("Content-Length".into(), body.len().to_string()),
        ],
        body: body.into_bytes(),
    }
}
