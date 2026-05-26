// Config type definitions — mirrors nginx.conf structure.
// All fields are validated at parse time; no runtime panics on bad config.

use std::net::SocketAddr;
use std::path::PathBuf;

use crate::http::limits::{DEFAULT_KEEPALIVE_TIMEOUT_S, DEFAULT_MAX_BODY_BYTES};

// ── Top-level config ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Config {
    pub worker_processes: WorkerCount,
    pub worker_connections: usize,
    pub http: HttpBlock,
}

#[derive(Debug, Clone)]
pub enum WorkerCount {
    Auto,          // physical cores, HT excluded
    Fixed(usize),
}

// ── HTTP block ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct HttpBlock {
    pub servers: Vec<ServerBlock>,
    pub gzip: bool,
    pub gzip_types: Vec<String>,
    pub gzip_min_length: usize,
    pub access_log: AccessLog,
    pub client_max_body_size: usize,
    pub keepalive_timeout: u64,
    pub send_timeout: u64,
    pub api_key: String,
}

impl Default for HttpBlock {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            gzip: false,
            gzip_types: vec!["text/html".into(), "text/css".into(),
                             "application/javascript".into(), "application/json".into()],
            gzip_min_length: 1024,
            access_log: AccessLog::File(PathBuf::from("/var/log/runnginx/access.log")),
            client_max_body_size: DEFAULT_MAX_BODY_BYTES,
            keepalive_timeout: DEFAULT_KEEPALIVE_TIMEOUT_S,
            send_timeout: 60,
            api_key: String::new(),
        }
    }
}

// ── Server block ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ServerBlock {
    pub listen: Vec<ListenDirective>,
    pub server_names: Vec<ServerName>,
    pub root: Option<PathBuf>,          // canonicalized and jailed at parse time
    pub index: Vec<String>,
    pub locations: Vec<LocationBlock>,
    pub tls: Option<TlsConfig>,
    pub access_log: Option<AccessLog>,  // overrides http-level if set
    pub client_max_body_size: Option<usize>,
    pub error_pages: Vec<ErrorPage>,
    pub add_headers: Vec<(String, String)>,
    pub return_directive: Option<ReturnDirective>,
}

#[derive(Debug, Clone)]
pub struct ListenDirective {
    pub addr: SocketAddr,
    pub tls: bool,
    pub http2: bool,
    pub default_server: bool,
}

#[derive(Debug, Clone)]
pub enum ServerName {
    Exact(String),          // server_name example.com
    Wildcard(String),       // server_name *.example.com
    Suffix(String),         // server_name .example.com (matches sub and bare)
    CatchAll,               // server_name _ (default)
}

impl ServerName {
    pub fn matches(&self, host: &str) -> bool {
        match self {
            Self::Exact(n)    => n.eq_ignore_ascii_case(host),
            Self::CatchAll    => true,
            Self::Suffix(s)   => {
                let s = s.trim_start_matches('.');
                host.eq_ignore_ascii_case(s)
                    || host.to_ascii_lowercase().ends_with(&format!(".{}", s.to_ascii_lowercase()))
            }
            Self::Wildcard(w) => {
                let suffix = w.trim_start_matches('*');
                host.to_ascii_lowercase().ends_with(&suffix.to_ascii_lowercase())
            }
        }
    }
}

// ── Location block ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LocationBlock {
    pub pattern: LocationPattern,
    pub handler: LocationHandler,
    pub root: Option<PathBuf>,
    pub index: Option<Vec<String>>,
    pub try_files: Option<Vec<TryFilesEntry>>,
    pub add_headers: Vec<(String, String)>,
    pub client_max_body_size: Option<usize>,
    pub return_directive: Option<ReturnDirective>,
    pub gzip: Option<bool>,
}

#[derive(Debug, Clone)]
pub enum LocationPattern {
    /// `location = /exact`     — highest priority
    Exact(String),
    /// `location ^~ /prefix`   — prefix, no regex after match
    PrefixNoRegex(String),
    /// `location /prefix`      — longest prefix wins
    Prefix(String),
    /// `location ~ regex`      — case-sensitive regex
    Regex(String, regex::Regex),
    /// `location ~* regex`     — case-insensitive regex
    RegexInsensitive(String, regex::Regex),
    /// `location @name`        — named, internal only
    Named(String),
}

impl LocationPattern {
    /// nginx priority: Exact > PrefixNoRegex > Regex/RegexInsensitive > Prefix
    pub fn priority(&self) -> u8 {
        match self {
            Self::Exact(_)           => 4,
            Self::PrefixNoRegex(_)   => 3,
            Self::Regex(..)          => 2,
            Self::RegexInsensitive(..)=>2,
            Self::Prefix(_)          => 1,
            Self::Named(_)           => 0,
        }
    }

    pub fn matches(&self, path: &str) -> bool {
        match self {
            Self::Exact(p)             => p == path,
            Self::Prefix(p) |
            Self::PrefixNoRegex(p)     => path.starts_with(p.as_str()),
            Self::Regex(_, re)         => re.is_match(path),
            Self::RegexInsensitive(_, re) => re.is_match(path),
            Self::Named(_)             => false, // matched by name, not URI
        }
    }
}

#[derive(Debug, Clone)]
pub enum LocationHandler {
    Static,                             // serve from root
    FastCgi(FastCgiConfig),             // fastcgi_pass
    Proxy(ProxyConfig),                 // proxy_pass
    Return(ReturnDirective),            // return 301 https://...
}

// ── FastCGI (PHP-FPM) ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FastCgiConfig {
    /// unix:///run/php/php8.2-fpm.sock  or  127.0.0.1:9000
    pub upstream: FastCgiUpstream,
    pub params: Vec<(String, String)>,  // fastcgi_param overrides
    pub index: Option<String>,          // fastcgi_index (default: index.php)
    pub read_timeout: u64,              // seconds
    pub connect_timeout: u64,
}

#[derive(Debug, Clone)]
pub enum FastCgiUpstream {
    UnixSocket(PathBuf),
    Tcp(SocketAddr),
}

// ── Reverse proxy ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Validated at parse time: must be http:// or https://, no private IPs
    /// unless proxy_allow_internal is set explicitly.
    pub upstream: url::Url,
    pub set_headers: Vec<(String, String)>,
    pub read_timeout: u64,
    pub connect_timeout: u64,
    pub buffering: bool,
    pub http2: bool,
    pub allow_internal: bool,
}

// ── TLS ───────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub min_version: TlsVersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

impl Default for TlsVersion {
    fn default() -> Self { Self::Tls12 }
}

// ── Access log ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum AccessLog {
    Off,
    File(PathBuf),
    Stderr,
}

// ── try_files ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum TryFilesEntry {
    Path(String),       // $uri, $uri/, /fallback.html
    StatusCode(u16),    // =404
    Named(String),      // @fallback
}

// ── return / redirect ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ReturnDirective {
    pub status: u16,
    pub body: ReturnBody,
}

#[derive(Debug, Clone)]
pub enum ReturnBody {
    Empty,
    Text(String),
    Url(String),        // for 3xx redirects
}

// ── Error pages ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ErrorPage {
    pub codes: Vec<u16>,
    pub uri: String,
}
