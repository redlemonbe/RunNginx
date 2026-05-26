// Per-IP rate limiting — nginx limit_req_zone / limit_req semantics.
// Uses a token bucket per IP per zone. No external dependencies.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use dashmap::DashMap;

// ── Zone ─────────────────────────────────────────────────────────────────────

pub struct LimitReqZone {
    pub name:  String,
    rate:      f64,   // tokens per second (from "10r/s" or "100r/m")
    buckets:   DashMap<IpAddr, Mutex<Bucket>>,
}

struct Bucket {
    tokens:     f64,
    last_check: Instant,
}

impl LimitReqZone {
    pub fn new(name: impl Into<String>, rate: f64) -> Arc<Self> {
        Arc::new(Self {
            name: name.into(),
            rate,
            buckets: DashMap::new(),
        })
    }

    /// Try to consume one token. Returns true if allowed.
    /// `burst` is the max burst capacity (tokens that can accumulate).
    pub fn allow(&self, ip: IpAddr, burst: u32) -> bool {
        let now = Instant::now();
        let burst_f = burst as f64;

        let entry = self.buckets
            .entry(ip)
            .or_insert_with(|| Mutex::new(Bucket { tokens: burst_f, last_check: now }));

        let mut b = entry.lock().unwrap();
        let elapsed = now.duration_since(b.last_check).as_secs_f64();
        b.tokens = (b.tokens + elapsed * self.rate).min(burst_f);
        b.last_check = now;

        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Periodically evict idle IPs (tokens == burst = fully refilled = idle).
    /// Call from a background task every few minutes.
    pub fn evict_idle(&self, burst: u32) {
        let burst_f = burst as f64;
        self.buckets.retain(|_, v| {
            let b = v.lock().unwrap();
            b.tokens < burst_f * 0.99  // keep if not fully refilled
        });
    }
}

// ── Zone registry ─────────────────────────────────────────────────────────────

pub struct ZoneRegistry {
    zones: DashMap<String, Arc<LimitReqZone>>,
}

impl ZoneRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { zones: DashMap::new() })
    }

    pub fn register(&self, name: &str, rate_rps: f64) {
        self.zones.insert(name.to_owned(), LimitReqZone::new(name, rate_rps));
    }

    pub fn get(&self, name: &str) -> Option<Arc<LimitReqZone>> {
        self.zones.get(name).map(|r| Arc::clone(&*r))
    }

    /// Parse "10r/s" or "100r/m" into requests per second.
    pub fn parse_rate(s: &str) -> Option<f64> {
        if let Some(n) = s.strip_suffix("r/s") {
            n.trim().parse::<f64>().ok()
        } else if let Some(n) = s.strip_suffix("r/m") {
            n.trim().parse::<f64>().ok().map(|v| v / 60.0)
        } else {
            None
        }
    }
}
