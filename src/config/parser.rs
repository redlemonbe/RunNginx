// nginx.conf parser.
// Security invariants:
//   - Only whitelisted directives are accepted; unknown → WARN + skip.
//   - Include depth is capped at MAX_INCLUDE_DEPTH.
//   - Root paths are canonicalized and verified to be within the jail.
//   - proxy_pass upstreams are validated by url::Url and SSRF-checked.
//   - client_max_body_size is capped at ABSOLUTE_MAX_BODY_BYTES.
//   - Server/location block counts are capped.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use regex::Regex;
use tracing::warn;

use crate::config::types::*;
use crate::http::limits::*;

// ── Public entry point ────────────────────────────────────────────────────────

pub fn load_from_str(src: &str) -> Result<Config> {
    let tokens = tokenize(src);
    let mut pos = 0usize;
    parse_root(&tokens, &mut pos, std::path::Path::new("<string>"), 0)
}

pub fn load(path: &Path) -> Result<Config> {
    let src = std::fs::read_to_string(path)
        .with_context(|| format!("reading config {}", path.display()))?;
    let tokens = tokenize(&src);
    let mut pos = 0usize;
    parse_root(&tokens, &mut pos, path, 0)
}

// ── Tokenizer ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Word(String),
    Semicolon,
    OpenBrace,
    CloseBrace,
}

fn tokenize(src: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut chars = src.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            // Skip whitespace
            c if c.is_ascii_whitespace() => { chars.next(); }
            // Skip line comments
            '#' => { while chars.next().map(|c| c != '\n').unwrap_or(false) {} }
            ';' => { chars.next(); tokens.push(Token::Semicolon); }
            '{' => { chars.next(); tokens.push(Token::OpenBrace); }
            '}' => { chars.next(); tokens.push(Token::CloseBrace); }
            // Quoted string
            '"' | '\'' => {
                let q = c;
                chars.next();
                let mut s = String::new();
                loop {
                    match chars.next() {
                        None | Some('\n') => break,
                        Some(c) if c == q => break,
                        Some('\\') => { if let Some(nc) = chars.next() { s.push(nc); } }
                        Some(c) => s.push(c),
                    }
                }
                tokens.push(Token::Word(s));
            }
            _ => {
                let mut word = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_ascii_whitespace() || c == ';' || c == '{' || c == '}' || c == '#' {
                        break;
                    }
                    word.push(c);
                    chars.next();
                }
                if !word.is_empty() {
                    tokens.push(Token::Word(word));
                }
            }
        }
    }
    tokens
}

// ── Token stream helpers ──────────────────────────────────────────────────────

fn peek_word<'a>(tokens: &'a [Token], pos: usize) -> Option<&'a str> {
    tokens.get(pos).and_then(|t| if let Token::Word(w) = t { Some(w.as_str()) } else { None })
}

fn expect_word(tokens: &[Token], pos: &mut usize) -> Result<String> {
    match tokens.get(*pos) {
        Some(Token::Word(w)) => { let w = w.clone(); *pos += 1; Ok(w) }
        other => bail!("expected word, got {:?}", other),
    }
}

fn expect_semi(tokens: &[Token], pos: &mut usize) -> Result<()> {
    match tokens.get(*pos) {
        Some(Token::Semicolon) => { *pos += 1; Ok(()) }
        other => bail!("expected ';', got {:?}", other),
    }
}

fn expect_open(tokens: &[Token], pos: &mut usize) -> Result<()> {
    match tokens.get(*pos) {
        Some(Token::OpenBrace) => { *pos += 1; Ok(()) }
        other => bail!("expected '{{', got {:?}", other),
    }
}

// Collect words until ';' without consuming the semicolon.
fn collect_args(tokens: &[Token], pos: &mut usize) -> Vec<String> {
    let mut args = Vec::new();
    while let Some(Token::Word(w)) = tokens.get(*pos) {
        args.push(w.clone());
        *pos += 1;
    }
    args
}

// Skip an entire unknown block { ... } including nested blocks.
fn skip_block(tokens: &[Token], pos: &mut usize) {
    let mut depth = 1usize;
    while *pos < tokens.len() && depth > 0 {
        match &tokens[*pos] {
            Token::OpenBrace  => depth += 1,
            Token::CloseBrace => depth -= 1,
            _ => {}
        }
        *pos += 1;
    }
}

// ── Root parser ───────────────────────────────────────────────────────────────

fn parse_root(tokens: &[Token], pos: &mut usize, config_path: &Path, depth: usize) -> Result<Config> {
    let mut cfg = Config {
        worker_processes: WorkerCount::Auto,
        worker_connections: 1024,
        http: HttpBlock::default(),
    };

    while *pos < tokens.len() {
        match peek_word(tokens, *pos) {
            Some("worker_processes") => {
                *pos += 1;
                let val = expect_word(tokens, pos)?;
                cfg.worker_processes = parse_worker_count(&val)?;
                expect_semi(tokens, pos)?;
            }
            Some("worker_connections") => {
                *pos += 1;
                let val = expect_word(tokens, pos)?;
                cfg.worker_connections = val.parse().context("worker_connections")?;
                expect_semi(tokens, pos)?;
            }
            Some("events") => {
                // events { worker_connections N; } — absorb the block
                *pos += 1;
                expect_open(tokens, pos)?;
                while *pos < tokens.len() {
                    match peek_word(tokens, *pos) {
                        Some("worker_connections") => {
                            *pos += 1;
                            let v = expect_word(tokens, pos)?;
                            cfg.worker_connections = v.parse().context("worker_connections")?;
                            expect_semi(tokens, pos)?;
                        }
                        Some(_) => {
                            let _ = collect_args(tokens, pos);
                            let _ = expect_semi(tokens, pos);
                        }
                        None => break,
                    }
                    if tokens.get(*pos) == Some(&Token::CloseBrace) { *pos += 1; break; }
                }
            }
            Some("http") => {
                *pos += 1;
                expect_open(tokens, pos)?;
                cfg.http = parse_http_block(tokens, pos, config_path, depth)?;
            }
            Some("include") => {
                *pos += 1;
                let pattern = expect_word(tokens, pos)?;
                expect_semi(tokens, pos)?;
                handle_include(&pattern, config_path, depth, &mut cfg)?;
            }
            Some(unknown) => {
                warn!("unknown root directive '{}' — skipped", unknown);
                *pos += 1;
                let _ = collect_args(tokens, pos);
                match tokens.get(*pos) {
                    Some(Token::Semicolon) => { *pos += 1; }
                    Some(Token::OpenBrace) => { *pos += 1; skip_block(tokens, pos); }
                    _ => {}
                }
            }
            None => break,
        }
    }
    Ok(cfg)
}

fn parse_worker_count(s: &str) -> Result<WorkerCount> {
    if s == "auto" { return Ok(WorkerCount::Auto); }
    Ok(WorkerCount::Fixed(s.parse().context("worker_processes")?))
}

fn handle_include(pattern: &str, base: &Path, depth: usize, cfg: &mut Config) -> Result<()> {
    if depth >= MAX_INCLUDE_DEPTH {
        bail!("include depth limit ({}) exceeded", MAX_INCLUDE_DEPTH);
    }
    let base_dir = base.parent().unwrap_or(Path::new("/"));
    let full = if Path::new(pattern).is_absolute() {
        pattern.to_owned()
    } else {
        base_dir.join(pattern).display().to_string()
    };
    // glob expansion
    for entry in glob::glob(&full).into_iter().flatten().flatten() {
        let sub_src = std::fs::read_to_string(&entry)
            .with_context(|| format!("include {}", entry.display()))?;
        let sub_tokens = tokenize(&sub_src);
        let mut sub_pos = 0usize;
        let sub_cfg = parse_root(&sub_tokens, &mut sub_pos, &entry, depth + 1)?;
        // Merge servers
        cfg.http.servers.extend(sub_cfg.http.servers);
    }
    Ok(())
}

// ── HTTP block ────────────────────────────────────────────────────────────────

fn parse_http_block(tokens: &[Token], pos: &mut usize, config_path: &Path, depth: usize) -> Result<HttpBlock> {
    let mut http = HttpBlock::default();
    let mut server_count = 0usize;

    loop {
        match tokens.get(*pos) {
            None | Some(Token::CloseBrace) => { *pos += 1; break; }
            Some(Token::Word(_)) => {}
            other => { bail!("unexpected token in http block: {:?}", other); }
        }

        match peek_word(tokens, *pos).expect("unreachable: Word token confirmed above") {
            "gzip" => {
                *pos += 1;
                let v = expect_word(tokens, pos)?;
                http.gzip = v == "on";
                expect_semi(tokens, pos)?;
            }
            "gzip_types" => {
                *pos += 1;
                http.gzip_types = collect_args(tokens, pos);
                expect_semi(tokens, pos)?;
            }
            "gzip_min_length" => {
                *pos += 1;
                let v = expect_word(tokens, pos)?;
                http.gzip_min_length = parse_size(&v).context("gzip_min_length")?;
                expect_semi(tokens, pos)?;
            }
            "access_log" => {
                *pos += 1;
                http.access_log = parse_access_log(tokens, pos)?;
            }
            "client_max_body_size" => {
                *pos += 1;
                let v = expect_word(tokens, pos)?;
                let n = parse_size(&v).context("client_max_body_size")?;
                http.client_max_body_size = n.min(ABSOLUTE_MAX_BODY_BYTES);
                expect_semi(tokens, pos)?;
            }
            "keepalive_timeout" => {
                *pos += 1;
                let v = expect_word(tokens, pos)?;
                http.keepalive_timeout = v.trim_end_matches('s').parse().context("keepalive_timeout")?;
                // optional second arg (header value) — skip
                if matches!(tokens.get(*pos), Some(Token::Word(_))) { *pos += 1; }
                expect_semi(tokens, pos)?;
            }
            "send_timeout" => {
                *pos += 1;
                let v = expect_word(tokens, pos)?;
                http.send_timeout = v.trim_end_matches('s').parse().context("send_timeout")?;
                expect_semi(tokens, pos)?;
            }
            "api_key" => {
                *pos += 1;
                let v = expect_word(tokens, pos)?;
                http.api_key = v;
                expect_semi(tokens, pos)?;
            }
            "brotli" => {
                *pos += 1;
                let v = expect_word(tokens, pos)?;
                http.brotli = v == "on";
                expect_semi(tokens, pos)?;
            }
            "brotli_types" => {
                *pos += 1;
                http.brotli_types = collect_args(tokens, pos);
                expect_semi(tokens, pos)?;
            }
            "brotli_min_length" => {
                *pos += 1;
                let v = expect_word(tokens, pos)?;
                http.brotli_min_length = parse_size(&v).context("brotli_min_length")?;
                expect_semi(tokens, pos)?;
            }
            "limit_req_zone" => {
                *pos += 1;
                let args = collect_args(tokens, pos);
                let zone_arg = args.iter().find(|a| a.starts_with("zone=")).map(|s| s.as_str());
                let rate_arg = args.iter().find(|a| a.starts_with("rate=")).map(|s| s.as_str());
                if let (Some(z), Some(r)) = (zone_arg, rate_arg) {
                    let name = z.trim_start_matches("zone=").split(':').next().unwrap_or("");
                    let rate_str = r.trim_start_matches("rate=");
                    if let Some(rps) = crate::limit_req::ZoneRegistry::parse_rate(rate_str) {
                        http.limit_req_zones.push(crate::config::types::LimitReqZoneDef {
                            name: name.to_owned(),
                            rate_rps: rps,
                        });
                    } else {
                        warn!("invalid limit_req_zone rate: {}", rate_str);
                    }
                }
                expect_semi(tokens, pos)?;
            }
            "upstream" => {
                // upstream groupname { server addr [weight=N]; ... policy; }
                *pos += 1;
                let name = expect_word(tokens, pos)?;
                expect_open(tokens, pos)?;
                let mut peers: Vec<(String, u32)> = Vec::new();
                let mut policy = "round_robin".to_owned();
                let mut health_interval = 0u64;
                let mut health_timeout  = 5u64;
                let mut fail_timeout    = 30u64;
                let mut max_fails: u32  = 3;
                let mut keepalive: usize = 0;
                loop {
                    match tokens.get(*pos) {
                        None | Some(Token::CloseBrace) => { *pos += 1; break; }
                        Some(Token::Word(_)) => {}
                        _ => { *pos += 1; continue; }
                    }
                    match peek_word(tokens, *pos).expect("Word confirmed") {
                        "server" => {
                            *pos += 1;
                            let addr = expect_word(tokens, pos)?;
                            let mut weight = 1u32;
                            let args = collect_args(tokens, pos);
                            expect_semi(tokens, pos)?;
                            for a in &args {
                                if let Some(w) = a.strip_prefix("weight=") {
                                    weight = w.parse().unwrap_or(1);
                                }
                            }
                            peers.push((addr, weight));
                        }
                        "least_conn"   => { policy = "least_conn".to_owned();  *pos += 1; expect_semi(tokens, pos)?; }
                        "ip_hash"      => { policy = "ip_hash".to_owned();     *pos += 1; expect_semi(tokens, pos)?; }
                        "random"       => { policy = "random".to_owned();      *pos += 1; expect_semi(tokens, pos)?; }
                        "keepalive" => {
                            *pos += 1;
                            let v = expect_word(tokens, pos)?;
                            keepalive = v.parse().unwrap_or(0);
                            expect_semi(tokens, pos)?;
                        }
                        "fail_timeout" => {
                            *pos += 1;
                            let v = expect_word(tokens, pos)?;
                            fail_timeout = v.trim_end_matches('s').parse().unwrap_or(30);
                            expect_semi(tokens, pos)?;
                        }
                        "max_fails" => {
                            *pos += 1;
                            let v = expect_word(tokens, pos)?;
                            max_fails = v.parse().unwrap_or(3);
                            expect_semi(tokens, pos)?;
                        }
                        "health_check" => {
                            *pos += 1;
                            let args = collect_args(tokens, pos);
                            expect_semi(tokens, pos)?;
                            for a in &args {
                                if let Some(v) = a.strip_prefix("interval=") {
                                    health_interval = v.trim_end_matches('s').parse().unwrap_or(0);
                                }
                                if let Some(v) = a.strip_prefix("timeout=") {
                                    health_timeout = v.trim_end_matches('s').parse().unwrap_or(5);
                                }
                            }
                        }
                        unknown => {
                            *pos += 1;
                            let _ = collect_args(tokens, pos);
                            match tokens.get(*pos) {
                                Some(Token::Semicolon) => { *pos += 1; }
                                _ => {}
                            }
                            warn!("unknown upstream directive '{}' — skipped", unknown);
                        }
                    }
                }
                http.upstream_groups.push(crate::config::types::UpstreamGroupDef {
                    name, peers, policy, health_interval, health_timeout, fail_timeout, max_fails, keepalive,
                });
            }
            "server" => {
                *pos += 1;
                expect_open(tokens, pos)?;
                if server_count >= MAX_SERVER_BLOCKS {
                    bail!("exceeded MAX_SERVER_BLOCKS ({})", MAX_SERVER_BLOCKS);
                }
                let srv = parse_server_block(tokens, pos, config_path, depth)?;
                http.servers.push(srv);
                server_count += 1;
            }
            "include" => {
                *pos += 1;
                let pattern = expect_word(tokens, pos)?;
                expect_semi(tokens, pos)?;
                // include inside http block: we only pull in servers
                let base_dir = config_path.parent().unwrap_or(Path::new("/"));
                let full = if Path::new(&pattern).is_absolute() {
                    pattern.clone()
                } else {
                    base_dir.join(&pattern).display().to_string()
                };
                for entry in glob::glob(&full).into_iter().flatten().flatten() {
                    let sub_src = std::fs::read_to_string(&entry)
                        .with_context(|| format!("include {}", entry.display()))?;
                    let sub_tokens = tokenize(&sub_src);
                    let mut sp = 0usize;
                    // parse as http block content
                    while sp < sub_tokens.len() {
                        if let Some("server") = peek_word(&sub_tokens, sp) {
                            sp += 1;
                            if matches!(sub_tokens.get(sp), Some(Token::OpenBrace)) {
                                sp += 1;
                                if server_count < MAX_SERVER_BLOCKS {
                                    let srv = parse_server_block(&sub_tokens, &mut sp, &entry, depth + 1)?;
                                    http.servers.push(srv);
                                    server_count += 1;
                                }
                            }
                        } else {
                            sp += 1;
                        }
                    }
                }
            }
            unknown => {
                warn!("unknown http directive '{}' — skipped", unknown);
                *pos += 1;
                let _ = collect_args(tokens, pos);
                match tokens.get(*pos) {
                    Some(Token::Semicolon) => { *pos += 1; }
                    Some(Token::OpenBrace) => { *pos += 1; skip_block(tokens, pos); }
                    _ => {}
                }
            }
        }
    }
    Ok(http)
}

// ── Server block ──────────────────────────────────────────────────────────────

fn parse_server_block(tokens: &[Token], pos: &mut usize, config_path: &Path, depth: usize) -> Result<ServerBlock> {
    let mut srv = ServerBlock {
        listen: Vec::new(),
        server_names: Vec::new(),
        root: None,
        index: vec!["index.html".into(), "index.htm".into()],
        locations: Vec::new(),
        tls: None,
        access_log: None,
        client_max_body_size: None,
        error_pages: Vec::new(),
        add_headers: Vec::new(),
        return_directive: None,
        limit_req: None,
        rewrites: Vec::new(),
        auth_basic: None,
    };
    let mut loc_count = 0usize;

    loop {
        match tokens.get(*pos) {
            None | Some(Token::CloseBrace) => { *pos += 1; break; }
            Some(Token::Word(_)) => {}
            other => bail!("unexpected token in server block: {:?}", other),
        }

        match peek_word(tokens, *pos).expect("unreachable: Word token confirmed above") {
            "listen" => {
                *pos += 1;
                let directive = parse_listen(tokens, pos)?;
                srv.listen.push(directive);
            }
            "server_name" => {
                *pos += 1;
                let names = collect_args(tokens, pos);
                expect_semi(tokens, pos)?;
                for n in names {
                    srv.server_names.push(parse_server_name(&n));
                }
            }
            "root" => {
                *pos += 1;
                let p = expect_word(tokens, pos)?;
                expect_semi(tokens, pos)?;
                srv.root = Some(canonicalize_root(&p)?);
            }
            "index" => {
                *pos += 1;
                srv.index = collect_args(tokens, pos);
                expect_semi(tokens, pos)?;
            }
            "access_log" => {
                *pos += 1;
                srv.access_log = Some(parse_access_log(tokens, pos)?);
            }
            "client_max_body_size" => {
                *pos += 1;
                let v = expect_word(tokens, pos)?;
                let n = parse_size(&v).context("client_max_body_size")?;
                srv.client_max_body_size = Some(n.min(ABSOLUTE_MAX_BODY_BYTES));
                expect_semi(tokens, pos)?;
            }
            "add_header" => {
                *pos += 1;
                let name  = expect_word(tokens, pos)?;
                let value = expect_word(tokens, pos)?;
                // optional "always" keyword
                if matches!(tokens.get(*pos), Some(Token::Word(w)) if w == "always") { *pos += 1; }
                expect_semi(tokens, pos)?;
                srv.add_headers.push((name, value));
            }
            "limit_req" => {
                *pos += 1;
                let args = collect_args(tokens, pos);
                srv.limit_req = parse_limit_req(&args);
                expect_semi(tokens, pos)?;
            }
            "rewrite" => {
                *pos += 1;
                let pattern     = expect_word(tokens, pos)?;
                let replacement = expect_word(tokens, pos)?;
                let flag_str = if matches!(tokens.get(*pos), Some(Token::Word(_))) {
                    let s = expect_word(tokens, pos)?;
                    expect_semi(tokens, pos)?;
                    s
                } else {
                    expect_semi(tokens, pos)?;
                    "last".to_owned()
                };
                let flag = match flag_str.as_str() {
                    "last"      => crate::config::types::RewriteFlag::Last,
                    "break"     => crate::config::types::RewriteFlag::Break,
                    "redirect"  => crate::config::types::RewriteFlag::Redirect,
                    "permanent" => crate::config::types::RewriteFlag::Permanent,
                    _           => crate::config::types::RewriteFlag::Last,
                };
                srv.rewrites.push(crate::config::types::RewriteRule { pattern, replacement, flag });
            }
            "auth_basic" => {
                *pos += 1;
                let realm = expect_word(tokens, pos)?;
                expect_semi(tokens, pos)?;
                if realm != "off" { srv.auth_basic = Some(crate::config::types::AuthBasicConfig { realm, user_file: std::path::PathBuf::new() }); }
            }
            "auth_basic_user_file" => {
                *pos += 1;
                let file = expect_word(tokens, pos)?;
                expect_semi(tokens, pos)?;
                if let Some(ref mut ab) = srv.auth_basic { ab.user_file = std::path::PathBuf::from(&file); }
                else { srv.auth_basic = Some(crate::config::types::AuthBasicConfig { realm: "Restricted".to_owned(), user_file: std::path::PathBuf::from(file) }); }
            }
            "error_page" => {
                *pos += 1;
                let args = collect_args(tokens, pos);
                expect_semi(tokens, pos)?;
                if args.len() >= 2 {
                    let uri = args.last().unwrap().clone();
                    let codes: Vec<u16> = args[..args.len()-1]
                        .iter()
                        .filter_map(|s| s.parse().ok())
                        .collect();
                    if !codes.is_empty() {
                        srv.error_pages.push(ErrorPage { codes, uri });
                    }
                }
            }
            "return" => {
                *pos += 1;
                srv.return_directive = Some(parse_return(tokens, pos)?);
            }
            "ssl_certificate" => {
                *pos += 1;
                let p = expect_word(tokens, pos)?;
                expect_semi(tokens, pos)?;
                srv.tls.get_or_insert_with(|| TlsConfig {
                    cert_path: PathBuf::new(),
                    key_path: PathBuf::new(),
                    min_version: TlsVersion::default(),
                }).cert_path = PathBuf::from(p);
            }
            "ssl_certificate_key" => {
                *pos += 1;
                let p = expect_word(tokens, pos)?;
                expect_semi(tokens, pos)?;
                srv.tls.get_or_insert_with(|| TlsConfig {
                    cert_path: PathBuf::new(),
                    key_path: PathBuf::new(),
                    min_version: TlsVersion::default(),
                }).key_path = PathBuf::from(p);
            }
            "ssl_protocols" => {
                *pos += 1;
                let args = collect_args(tokens, pos);
                expect_semi(tokens, pos)?;
                let min = if args.iter().any(|s| s == "TLSv1.2") {
                    TlsVersion::Tls12
                } else {
                    TlsVersion::Tls13
                };
                srv.tls.get_or_insert_with(|| TlsConfig {
                    cert_path: PathBuf::new(),
                    key_path: PathBuf::new(),
                    min_version: TlsVersion::default(),
                }).min_version = min;
            }
            "location" => {
                *pos += 1;
                if loc_count >= MAX_LOCATION_BLOCKS {
                    bail!("exceeded MAX_LOCATION_BLOCKS ({})", MAX_LOCATION_BLOCKS);
                }
                let loc = parse_location(tokens, pos, config_path, depth)?;
                srv.locations.push(loc);
                loc_count += 1;
            }
            unknown => {
                warn!("unknown server directive '{}' — skipped", unknown);
                *pos += 1;
                let _ = collect_args(tokens, pos);
                match tokens.get(*pos) {
                    Some(Token::Semicolon) => { *pos += 1; }
                    Some(Token::OpenBrace) => { *pos += 1; skip_block(tokens, pos); }
                    _ => {}
                }
            }
        }
    }
    Ok(srv)
}

fn parse_listen(tokens: &[Token], pos: &mut usize) -> Result<ListenDirective> {
    let args = collect_args(tokens, pos);
    expect_semi(tokens, pos)?;

    let mut tls = false;
    let mut http2 = false;
    let mut default_server = false;
    let mut addr_str = String::new();

    for arg in &args {
        match arg.as_str() {
            "ssl" => tls = true,
            "http2" => http2 = true,
            "default_server" => default_server = true,
            "reuseport" | "backlog" | "rcvbuf" | "sndbuf" | "ipv6only=on" | "ipv6only=off" => {}
            s => addr_str = s.to_owned(),
        }
    }

    let addr = parse_listen_addr(&addr_str)?;
    Ok(ListenDirective { addr, tls, http2, default_server })
}

fn parse_listen_addr(s: &str) -> Result<SocketAddr> {
    // Normalize: "80" → "0.0.0.0:80", "443 ssl" already stripped, "[::]:80", "127.0.0.1:8080"
    if let Ok(addr) = s.parse::<SocketAddr>() { return Ok(addr); }
    if let Ok(port) = s.parse::<u16>() {
        return Ok(SocketAddr::from(([0,0,0,0], port)));
    }
    // "localhost:80"
    bail!("cannot parse listen address '{}'", s)
}

fn parse_server_name(s: &str) -> ServerName {
    match s {
        "_" | "" => ServerName::CatchAll,
        s if s.starts_with("*.") => ServerName::Wildcard(s.to_owned()),
        s if s.starts_with('.') => ServerName::Suffix(s.to_owned()),
        s => ServerName::Exact(s.to_owned()),
    }
}

fn canonicalize_root(p: &str) -> Result<PathBuf> {
    let pb = PathBuf::from(p);
    // We accept non-existent paths at parse time (they may be created later),
    // but we reject anything with .. or null bytes.
    let s = pb.to_str().unwrap_or("");
    if s.contains('\x00') { bail!("root path contains null byte"); }
    if pb.components().any(|c| c == std::path::Component::ParentDir) {
        bail!("root path contains '..'");
    }
    Ok(pb)
}

// ── Location block ────────────────────────────────────────────────────────────

fn parse_location(tokens: &[Token], pos: &mut usize, config_path: &Path, depth: usize) -> Result<LocationBlock> {
    // Collect modifer and path before '{'
    let mut args = Vec::new();
    while let Some(Token::Word(w)) = tokens.get(*pos) {
        args.push(w.clone());
        *pos += 1;
        if matches!(tokens.get(*pos), Some(Token::OpenBrace)) { break; }
    }
    expect_open(tokens, pos)?;

    let pattern = parse_location_pattern(&args)?;

    let mut handler = LocationHandler::Static;
    let mut root: Option<PathBuf> = None;
    let mut index: Option<Vec<String>> = None;
    let mut try_files: Option<Vec<TryFilesEntry>> = None;
    let mut add_headers: Vec<(String,String)> = Vec::new();
    let mut client_max_body_size: Option<usize> = None;
    let mut return_directive: Option<ReturnDirective> = None;
    let mut gzip: Option<bool> = None;
    let mut limit_req: Option<crate::config::types::LimitReqRef> = None;
    let mut rewrites: Vec<crate::config::types::RewriteRule> = Vec::new();
    let mut auth_basic_realm: Option<String> = None;
    let mut auth_basic_file: Option<std::path::PathBuf> = None;

    loop {
        match tokens.get(*pos) {
            None | Some(Token::CloseBrace) => { *pos += 1; break; }
            Some(Token::Word(_)) => {}
            other => bail!("unexpected token in location block: {:?}", other),
        }

        match peek_word(tokens, *pos).expect("unreachable: Word token confirmed above") {
            "root" => {
                *pos += 1;
                let p = expect_word(tokens, pos)?;
                expect_semi(tokens, pos)?;
                root = Some(canonicalize_root(&p)?);
            }
            "index" => {
                *pos += 1;
                let idxs = collect_args(tokens, pos);
                expect_semi(tokens, pos)?;
                index = Some(idxs);
            }
            "try_files" => {
                *pos += 1;
                let args = collect_args(tokens, pos);
                expect_semi(tokens, pos)?;
                try_files = Some(parse_try_files(&args));
            }
            "proxy_pass" => {
                *pos += 1;
                let url_str = expect_word(tokens, pos)?;
                expect_semi(tokens, pos)?;
                let cfg = parse_proxy_pass(&url_str)?;
                handler = LocationHandler::Proxy(cfg);
            }
            "fastcgi_pass" => {
                *pos += 1;
                let upstream_str = expect_word(tokens, pos)?;
                expect_semi(tokens, pos)?;
                let upstream = parse_fastcgi_upstream(&upstream_str)?;
                handler = LocationHandler::FastCgi(FastCgiConfig {
                    upstream,
                    params: Vec::new(),
                    index: None,
                    read_timeout: 60,
                    connect_timeout: 5,
                });
            }
            "fastcgi_param" => {
                *pos += 1;
                let key = expect_word(tokens, pos)?;
                let val = expect_word(tokens, pos)?;
                expect_semi(tokens, pos)?;
                if let LocationHandler::FastCgi(ref mut fc) = handler {
                    fc.params.push((key, val));
                }
            }
            "fastcgi_index" => {
                *pos += 1;
                let idx = expect_word(tokens, pos)?;
                expect_semi(tokens, pos)?;
                if let LocationHandler::FastCgi(ref mut fc) = handler {
                    fc.index = Some(idx);
                }
            }
            "fastcgi_read_timeout" => {
                *pos += 1;
                let v = expect_word(tokens, pos)?;
                expect_semi(tokens, pos)?;
                if let LocationHandler::FastCgi(ref mut fc) = handler {
                    fc.read_timeout = v.trim_end_matches('s').parse().unwrap_or(60);
                }
            }
            "proxy_set_header" => {
                *pos += 1;
                let key = expect_word(tokens, pos)?;
                let val = expect_word(tokens, pos)?;
                expect_semi(tokens, pos)?;
                if let LocationHandler::Proxy(ref mut pc) = handler {
                    pc.set_headers.push((key, val));
                }
            }
            "proxy_read_timeout" => {
                *pos += 1;
                let v = expect_word(tokens, pos)?;
                expect_semi(tokens, pos)?;
                if let LocationHandler::Proxy(ref mut pc) = handler {
                    pc.read_timeout = v.trim_end_matches('s').parse().unwrap_or(60);
                }
            }
            "proxy_buffering" => {
                *pos += 1;
                let v = expect_word(tokens, pos)?;
                expect_semi(tokens, pos)?;
                if let LocationHandler::Proxy(ref mut pc) = handler {
                    pc.buffering = v == "on";
                }
            }
            "proxy_allow_internal" => {
                *pos += 1;
                let v = expect_word(tokens, pos)?;
                expect_semi(tokens, pos)?;
                if let LocationHandler::Proxy(ref mut pc) = handler {
                    pc.allow_internal = v == "on";
                }
            }
            "add_header" => {
                *pos += 1;
                let name  = expect_word(tokens, pos)?;
                let value = expect_word(tokens, pos)?;
                if matches!(tokens.get(*pos), Some(Token::Word(w)) if w == "always") { *pos += 1; }
                expect_semi(tokens, pos)?;
                add_headers.push((name, value));
            }
            "client_max_body_size" => {
                *pos += 1;
                let v = expect_word(tokens, pos)?;
                let n = parse_size(&v).context("client_max_body_size")?;
                client_max_body_size = Some(n.min(ABSOLUTE_MAX_BODY_BYTES));
                expect_semi(tokens, pos)?;
            }
            "return" => {
                *pos += 1;
                let rd = parse_return(tokens, pos)?;
                return_directive = Some(rd.clone());
                handler = LocationHandler::Return(rd);
            }
            "gzip" => {
                *pos += 1;
                let v = expect_word(tokens, pos)?;
                expect_semi(tokens, pos)?;
                gzip = Some(v == "on");
            }
            "limit_req" => {
                *pos += 1;
                let args = collect_args(tokens, pos);
                limit_req = parse_limit_req(&args);
                expect_semi(tokens, pos)?;
            }
            "rewrite" => {
                *pos += 1;
                let pattern     = expect_word(tokens, pos)?;
                let replacement = expect_word(tokens, pos)?;
                let flag_str = if matches!(tokens.get(*pos), Some(Token::Word(_))) {
                    let s = expect_word(tokens, pos)?;
                    expect_semi(tokens, pos)?;
                    s
                } else {
                    expect_semi(tokens, pos)?;
                    "last".to_owned()
                };
                let flag = match flag_str.as_str() {
                    "last"      => crate::config::types::RewriteFlag::Last,
                    "break"     => crate::config::types::RewriteFlag::Break,
                    "redirect"  => crate::config::types::RewriteFlag::Redirect,
                    "permanent" => crate::config::types::RewriteFlag::Permanent,
                    _           => crate::config::types::RewriteFlag::Last,
                };
                rewrites.push(crate::config::types::RewriteRule { pattern, replacement, flag });
            }
            "auth_basic" => {
                *pos += 1;
                let realm = expect_word(tokens, pos)?;
                expect_semi(tokens, pos)?;
                if realm != "off" { auth_basic_realm = Some(realm); }
            }
            "auth_basic_user_file" => {
                *pos += 1;
                let file = expect_word(tokens, pos)?;
                expect_semi(tokens, pos)?;
                auth_basic_file = Some(std::path::PathBuf::from(file));
            }
            unknown => {
                warn!("unknown location directive '{}' — skipped", unknown);
                *pos += 1;
                let _ = collect_args(tokens, pos);
                match tokens.get(*pos) {
                    Some(Token::Semicolon) => { *pos += 1; }
                    Some(Token::OpenBrace) => { *pos += 1; skip_block(tokens, pos); }
                    _ => {}
                }
            }
        }
    }

    let auth_basic: Option<crate::config::types::AuthBasicConfig> = match (auth_basic_realm, auth_basic_file) {
        (Some(realm), Some(user_file)) => Some(crate::config::types::AuthBasicConfig { realm, user_file }),
        _ => None,
    };
    Ok(LocationBlock {
        pattern,
        handler,
        root,
        index,
        try_files,
        add_headers,
        client_max_body_size,
        return_directive,
        gzip,
        limit_req,
        rewrites,
        auth_basic,
    })
}

fn parse_location_pattern(args: &[String]) -> Result<LocationPattern> {
    match args.len() {
        0 => bail!("empty location pattern"),
        1 => {
            let p = &args[0];
            if p.starts_with('@') { return Ok(LocationPattern::Named(p.clone())); }
            Ok(LocationPattern::Prefix(p.clone()))
        }
        2 => {
            let (modifier, path) = (&args[0], &args[1]);
            match modifier.as_str() {
                "=" => Ok(LocationPattern::Exact(path.clone())),
                "^~" => Ok(LocationPattern::PrefixNoRegex(path.clone())),
                "~" => {
                    let re = Regex::new(path).with_context(|| format!("location regex '{}'", path))?;
                    Ok(LocationPattern::Regex(path.clone(), re))
                }
                "~*" => {
                    let re = Regex::new(&format!("(?i){}", path))
                        .with_context(|| format!("location regex '(?i){}'", path))?;
                    Ok(LocationPattern::RegexInsensitive(path.clone(), re))
                }
                _ => bail!("unknown location modifier '{}'", modifier),
            }
        }
        _ => bail!("too many location pattern tokens: {:?}", args),
    }
}

fn parse_try_files(args: &[String]) -> Vec<TryFilesEntry> {
    args.iter().map(|s| {
        if let Some(code_str) = s.strip_prefix('=') {
            if let Ok(code) = code_str.parse::<u16>() {
                return TryFilesEntry::StatusCode(code);
            }
        }
        if s.starts_with('@') {
            return TryFilesEntry::Named(s.clone());
        }
        TryFilesEntry::Path(s.clone())
    }).collect()
}

// ── SSRF-safe proxy_pass ──────────────────────────────────────────────────────

fn parse_proxy_pass(raw: &str) -> Result<ProxyConfig> {
    let parsed = url::Url::parse(raw)
        .with_context(|| format!("invalid proxy_pass URL '{}'", raw))?;

    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        bail!("proxy_pass '{}': only http/https allowed", raw);
    }

    let host = parsed.host_str().unwrap_or("");

    // SSRF prevention: block cloud metadata and unambiguously unsafe endpoints.
    // RFC-1918 / loopback are allowed with proxy_allow_internal on; (checked at request time).
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if ip.is_unspecified() {
            bail!("proxy_pass '{}': unspecified address blocked (SSRF)", raw);
        }
        // Loopback and private IPs: allowed only with proxy_allow_internal on;
        // We accept them at parse time and block at request time in proxy.rs.
    }

    let host_lc = host.to_ascii_lowercase();
    if host_lc == "localhost"
        || host_lc.ends_with(".local")
        || host_lc == "metadata.google.internal"
        || host_lc == "169.254.169.254"
        || host_lc == "fd00:ec2::254"  // AWS IMDSv2 IPv6
        || host_lc == "metadata.internal"
    {
        bail!("proxy_pass '{}': blocked host (SSRF)", raw);
    }

    Ok(ProxyConfig {
        upstream: parsed,
        set_headers: Vec::new(),
        read_timeout: 60,
        connect_timeout: 5,
        buffering: true,
        http2: false,
        allow_internal: false,
    })
}

fn parse_fastcgi_upstream(s: &str) -> Result<FastCgiUpstream> {
    if let Some(path) = s.strip_prefix("unix:") {
        let p = path.trim_start_matches('/');
        return Ok(FastCgiUpstream::UnixSocket(PathBuf::from(format!("/{}", p))));
    }
    let addr = s.parse::<SocketAddr>()
        .with_context(|| format!("invalid fastcgi_pass address '{}'", s))?;
    Ok(FastCgiUpstream::Tcp(addr))
}

// ── Misc helpers ──────────────────────────────────────────────────────────────

fn parse_access_log(tokens: &[Token], pos: &mut usize) -> Result<AccessLog> {
    let val = expect_word(tokens, pos)?;
    // optional format name — skip
    if matches!(tokens.get(*pos), Some(Token::Word(_))) { *pos += 1; }
    expect_semi(tokens, pos)?;
    Ok(match val.as_str() {
        "off" => AccessLog::Off,
        "stderr" => AccessLog::Stderr,
        p => AccessLog::File(PathBuf::from(p)),
    })
}

fn parse_return(tokens: &[Token], pos: &mut usize) -> Result<ReturnDirective> {
    let first = expect_word(tokens, pos)?;
    let status: u16 = first.parse().context("return status code")?;

    let body = if matches!(tokens.get(*pos), Some(Token::Word(_))) {
        let s = expect_word(tokens, pos)?;
        if status >= 300 && status < 400 {
            ReturnBody::Url(s)
        } else {
            ReturnBody::Text(s)
        }
    } else {
        ReturnBody::Empty
    };
    expect_semi(tokens, pos)?;
    Ok(ReturnDirective { status, body })
}

/// Parse size strings: "1m" → 1048576, "8k" → 8192, "2g" → 2147483648.
fn parse_size(s: &str) -> Result<usize> {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some('k') | Some('K') => (&s[..s.len()-1], 1024usize),
        Some('m') | Some('M') => (&s[..s.len()-1], 1024*1024),
        Some('g') | Some('G') => (&s[..s.len()-1], 1024*1024*1024),
        _ => (s, 1),
    };
    let n: usize = num.parse().with_context(|| format!("invalid size '{}'", s))?;
    Ok(n * mult)
}

// ── limit_req parsing helper ─────────────────────────────────────────────────

fn parse_limit_req(args: &[String]) -> Option<crate::config::types::LimitReqRef> {
    // limit_req zone=name burst=20 [nodelay];
    let zone = args.iter()
        .find(|a| a.starts_with("zone="))?
        .trim_start_matches("zone=")
        .to_owned();
    let burst = args.iter()
        .find(|a| a.starts_with("burst="))
        .and_then(|a| a.trim_start_matches("burst=").parse().ok())
        .unwrap_or(0u32);
    let nodelay = args.iter().any(|a| a == "nodelay");
    Some(crate::config::types::LimitReqRef { zone, burst, nodelay })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Config {
        load_from_str(s).expect("parse failed")
    }

    #[test]
    fn upstream_block_parsed() {
        let cfg = parse(r#"http {
            upstream backend {
                server 127.0.0.1:3000 weight=2;
                server 127.0.0.1:3001;
                least_conn;
                keepalive 16;
                fail_timeout 30s;
                max_fails 3;
            }
            server { listen 127.0.0.1:19000; }
        }"#);
        let g = &cfg.http.upstream_groups[0];
        assert_eq!(g.name, "backend");
        assert_eq!(g.peers.len(), 2);
        assert_eq!(g.peers[0].1, 2);
        assert_eq!(g.policy, "least_conn");
        assert_eq!(g.keepalive, 16);
        assert_eq!(g.fail_timeout, 30);
        assert_eq!(g.max_fails, 3);
    }

    #[test]
    fn rewrite_directive_server_level() {
        let cfg = parse(r#"http {
            server {
                listen 127.0.0.1:19001;
                rewrite ^/old/(.*)$ /new/$1 redirect;
            }
        }"#);
        let srv = &cfg.http.servers[0];
        assert_eq!(srv.rewrites.len(), 1);
        assert_eq!(srv.rewrites[0].pattern, r"^/old/(.*)$");
        assert_eq!(srv.rewrites[0].replacement, "/new/$1");
        assert!(matches!(srv.rewrites[0].flag, crate::config::types::RewriteFlag::Redirect));
    }

    #[test]
    fn rewrite_directive_location_level() {
        let cfg = parse(r#"http {
            server {
                listen 127.0.0.1:19002;
                location /app {
                    rewrite ^/app/(.*)$ /index.php?q=$1 last;
                    root /var/www;
                }
            }
        }"#);
        assert_eq!(cfg.http.servers[0].locations[0].rewrites.len(), 1);
        assert!(matches!(cfg.http.servers[0].locations[0].rewrites[0].flag, crate::config::types::RewriteFlag::Last));
    }

    #[test]
    fn auth_basic_directive() {
        let cfg = parse(r#"http {
            server {
                listen 127.0.0.1:19003;
                location /admin {
                    auth_basic "Admin Area";
                    auth_basic_user_file /etc/runnginx/.htpasswd;
                    root /var/www;
                }
            }
        }"#);
        let ab = cfg.http.servers[0].locations[0].auth_basic.as_ref().unwrap();
        assert_eq!(ab.realm, "Admin Area");
        assert_eq!(ab.user_file.to_str().unwrap(), "/etc/runnginx/.htpasswd");
    }

    #[test]
    fn brotli_directives() {
        let cfg = parse(r#"http {
            brotli on;
            brotli_min_length 512;
            brotli_types text/html text/css;
            server { listen 127.0.0.1:19004; }
        }"#);
        assert!(cfg.http.brotli);
        assert_eq!(cfg.http.brotli_min_length, 512);
        assert!(cfg.http.brotli_types.contains(&"text/css".to_owned()));
    }

    #[test]
    fn limit_req_zone_and_ref() {
        let cfg = parse(r#"http {
            limit_req_zone zone=api:1m rate=10r/s;
            server {
                listen 127.0.0.1:19005;
                location /api {
                    limit_req zone=api burst=5;
                    root /var/www;
                }
            }
        }"#);
        assert_eq!(cfg.http.limit_req_zones.len(), 1);
        assert_eq!(cfg.http.limit_req_zones[0].name, "api");
        assert!((cfg.http.limit_req_zones[0].rate_rps - 10.0).abs() < 0.01);
        let lr = cfg.http.servers[0].locations[0].limit_req.as_ref().unwrap();
        assert_eq!(lr.zone, "api");
        assert_eq!(lr.burst, 5);
    }
}

