// HTTP scan / probe detection with AbuseIPDB reporting.
//
// Scores each IP across a sliding window. Score ≥ threshold triggers a block
// and optionally sends a report to AbuseIPDB v2.
//
// Scoring (max 100):
//   - Request volume  : up to 30 pts  (req_count / window_threshold)
//   - 4xx error rate  : up to 40 pts  (error_4xx / req_count)
//   - Known probe paths: 10 pts each  (max 30 pts)
//
// Config directives (all optional, shown with defaults):
//   scan_detection              on;
//   scan_detection_window       60;      # seconds
//   scan_detection_threshold    100;     # requests in window before scoring
//   scan_detection_error_rate   0.6;     # 4xx ratio trigger
//   scan_detection_block        3600;    # block duration in seconds (0 = no block)
//   scan_detection_abuseipdb_key "xxx";  # omit to disable reporting
//   scan_detection_abuseipdb_report on;
//   scan_detection_whitelist    127.0.0.1 10.0.0.0/8;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use tracing::{info, warn};

const SCORE_TRIGGER: u32 = 60;

// Known probe/scanner paths — hitting multiple of these heavily weighs the score.
static PROBE_PATHS: &[&str] = &[
    "/.env", "/.git", "/.gitignore", "/.htaccess", "/.htpasswd",
    "/wp-login.php", "/wp-admin", "/xmlrpc.php", "/wp-config.php",
    "/admin", "/administrator", "/phpmyadmin", "/phpMyAdmin",
    "/setup.php", "/config.php", "/install.php", "/upgrade.php",
    "/cgi-bin/", "/shell.php", "/webshell.php", "/c99.php", "/r57.php",
    "/proc/self/environ", "/etc/passwd", "/etc/shadow",
    "/.DS_Store", "/thumbs.db",
    "/actuator", "/actuator/health", "/actuator/env",  // Spring Boot
    "/console", "/manager/html",                        // Tomcat
    "/.aws/credentials", "/.ssh/id_rsa",
    "/api/swagger", "/swagger-ui.html", "/openapi.json",
    "/vendor/phpunit", "/vendor/autoload.php",
    "/backup.sql", "/backup.zip", "/database.sql",
];

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub enabled: bool,
    pub window_secs: u64,
    pub req_threshold: u64,
    pub error_rate_threshold: f32,
    pub block_secs: u64,
    pub abuseipdb_key: Option<String>,
    pub abuseipdb_report: bool,
    pub whitelist: Vec<std::net::IpAddr>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            window_secs: 60,
            req_threshold: 100,
            error_rate_threshold: 0.60,
            block_secs: 3600,
            abuseipdb_key: None,
            abuseipdb_report: false,
            whitelist: vec![],
        }
    }
}

struct IpRecord {
    window_start: Instant,
    req_count: u64,
    error_4xx: u64,
    probe_paths: HashSet<String>,
    blocked_until: Option<Instant>,
    last_reported: Option<Instant>,
}

impl IpRecord {
    fn new() -> Self {
        Self {
            window_start: Instant::now(),
            req_count: 0,
            error_4xx: 0,
            probe_paths: HashSet::new(),
            blocked_until: None,
            last_reported: None,
        }
    }

    fn reset_window(&mut self) {
        self.window_start = Instant::now();
        self.req_count = 0;
        self.error_4xx = 0;
        self.probe_paths.clear();
    }

    fn score(&self, cfg: &ScanConfig) -> u32 {
        if self.req_count == 0 { return 0; }
        // Volume score: 0..30
        let vol = ((self.req_count as f32 / cfg.req_threshold as f32) * 30.0).min(30.0) as u32;
        // Error rate score: 0..40
        let err_rate = self.error_4xx as f32 / self.req_count as f32;
        let err = if err_rate >= cfg.error_rate_threshold {
            ((err_rate / cfg.error_rate_threshold) * 30.0).min(40.0) as u32
        } else {
            0
        };
        // Probe paths: 10 pts each, max 30
        let probe = (self.probe_paths.len() as u32 * 10).min(30);
        vol + err + probe
    }
}

pub struct ScanDetector {
    config: ScanConfig,
    tracker: RwLock<HashMap<IpAddr, IpRecord>>,
}

impl ScanDetector {
    pub fn new(config: ScanConfig) -> Arc<Self> {
        let det = Arc::new(Self {
            config,
            tracker: RwLock::new(HashMap::new()),
        });
        // Periodic GC — evict stale records every 5 minutes
        let det2 = Arc::clone(&det);
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(Duration::from_secs(300));
                det2.gc();
            }
        });
        det
    }

    /// Call after each request. Returns true if the IP should be blocked (403).
    pub fn record(&self, ip: IpAddr, path: &str, status: u16) -> bool {
        if !self.config.enabled { return false; }
        if self.config.whitelist.contains(&ip) { return false; }

        let window = Duration::from_secs(self.config.window_secs);
        let now = Instant::now();

        let mut map = self.tracker.write().unwrap_or_else(|e| e.into_inner());
        let rec = map.entry(ip).or_insert_with(IpRecord::new);

        // Already blocked?
        if let Some(exp) = rec.blocked_until {
            if now < exp { return true; }
            rec.blocked_until = None;
        }

        // New window?
        if now.duration_since(rec.window_start) > window {
            rec.reset_window();
        }

        rec.req_count += 1;
        if status >= 400 && status < 500 { rec.error_4xx += 1; }

        // Check probe paths
        let path_lower = path.to_ascii_lowercase();
        for &probe in PROBE_PATHS {
            if path_lower.starts_with(probe) || path_lower.contains(probe) {
                rec.probe_paths.insert(probe.to_owned());
            }
        }

        let score = rec.score(&self.config);
        if score >= SCORE_TRIGGER {
            let block_exp = if self.config.block_secs > 0 {
                Some(now + Duration::from_secs(self.config.block_secs))
            } else {
                None
            };
            rec.blocked_until = block_exp;

            let already_reported = rec.last_reported
                .map(|t| now.duration_since(t) < Duration::from_secs(86400))
                .unwrap_or(false);

            if !already_reported && self.config.abuseipdb_report {
                if let Some(ref key) = self.config.abuseipdb_key {
                    let key = key.clone();
                    let ip_str = ip.to_string();
                    let score_copy = score;
                    std::thread::spawn(move || {
                        report_to_abuseipdb(&ip_str, &key, score_copy);
                    });
                    rec.last_reported = Some(now);
                }
            }

            info!(ip = %ip, score = score, "scan_detector: IP blocked (score={score})");
            return true;
        }
        false
    }

    /// Check if an IP is currently blocked (without recording a request).
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        if !self.config.enabled { return false; }
        let map = self.tracker.read().unwrap_or_else(|e| e.into_inner());
        map.get(&ip)
            .and_then(|r| r.blocked_until)
            .map(|exp| Instant::now() < exp)
            .unwrap_or(false)
    }

    fn gc(&self) {
        let cutoff = Duration::from_secs(self.config.window_secs * 3);
        let mut map = self.tracker.write().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        map.retain(|_, rec| {
            let active_block = rec.blocked_until.map(|e| now < e).unwrap_or(false);
            active_block || now.duration_since(rec.window_start) < cutoff
        });
    }
}

fn report_to_abuseipdb(ip: &str, api_key: &str, score: u32) {
    let confidence = score.min(100);
    let comment = format!(
        "Automated HTTP scan/probe detection by RunNginx (score={confidence}/100). \
         Multiple known vulnerability probe paths, high 4xx rate, or excessive request volume."
    );

    let body = format!(
        "ip={ip}&categories=14,21&comment={}&confidence={}",
        urlencodecomment(&comment),
        confidence,
    );

    let result = std::process::Command::new("curl")
        .args([
            "-s", "-X", "POST",
            "https://api.abuseipdb.com/api/v2/report",
            "-H", &format!("Key: {api_key}"),
            "-H", "Accept: application/json",
            "-H", "Content-Type: application/x-www-form-urlencoded",
            "-d", &body,
        ])
        .output();

    match result {
        Ok(out) if out.status.success() => {
            let resp = String::from_utf8_lossy(&out.stdout);
            if resp.contains("\"abuseConfidenceScore\"") {
                info!(ip = %ip, "scan_detector: AbuseIPDB report sent OK");
            } else {
                warn!(ip = %ip, "scan_detector: AbuseIPDB response: {}", resp.trim());
            }
        }
        Ok(out) => warn!(ip = %ip, "scan_detector: AbuseIPDB curl error: {}", String::from_utf8_lossy(&out.stderr)),
        Err(e) => warn!(ip = %ip, "scan_detector: AbuseIPDB curl spawn failed: {e}"),
    }
}

fn urlencodecomment(s: &str) -> String {
    s.chars().map(|c| match c {
        ' ' => '+'.to_string(),
        c if c.is_alphanumeric() || "._-~".contains(c) => c.to_string(),
        c => format!("%{:02X}", c as u8),
    }).collect()
}
