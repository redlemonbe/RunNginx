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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(n: u8) -> IpAddr { IpAddr::V4(Ipv4Addr::new(127, 0, 0, n)) }

    #[test]
    fn allow_within_burst() {
        let zone = LimitReqZone::new("test", 1.0);
        for _ in 0..5 {
            assert!(zone.allow(ip(1), 5));
        }
    }

    #[test]
    fn deny_when_burst_exhausted() {
        let zone = LimitReqZone::new("test", 0.001); // very slow refill
        let burst = 3u32;
        for _ in 0..burst { zone.allow(ip(2), burst); }
        assert!(!zone.allow(ip(2), burst));
    }

    #[test]
    fn different_ips_independent() {
        let zone = LimitReqZone::new("test", 0.001);
        let burst = 2u32;
        for _ in 0..burst { zone.allow(ip(3), burst); }
        assert!(!zone.allow(ip(3), burst));
        assert!(zone.allow(ip(4), burst));
    }

    #[test]
    fn parse_rate_per_second() {
        assert_eq!(ZoneRegistry::parse_rate("10r/s"), Some(10.0));
    }

    #[test]
    fn parse_rate_per_minute() {
        let r = ZoneRegistry::parse_rate("60r/m").unwrap();
        assert!((r - 1.0).abs() < 1e-9);
    }

    #[test]
    fn parse_rate_invalid() {
        assert_eq!(ZoneRegistry::parse_rate("10rps"), None);
        assert_eq!(ZoneRegistry::parse_rate(""), None);
    }
}

