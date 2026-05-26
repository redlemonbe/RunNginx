// Atomic stats counters — updated on every request, read by GET /api/stats.
// All fields use relaxed atomics since we only care about eventual consistency.

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};

use dashmap::DashMap;

// ── Request stats ─────────────────────────────────────────────────────────────

pub struct Stats {
    pub requests_total:  AtomicU64,
    pub bytes_sent:      AtomicU64,
    pub bytes_received:  AtomicU64,
    pub active:          AtomicU64,  // current open connections

    // Status code buckets.
    pub status_2xx: AtomicU64,
    pub status_3xx: AtomicU64,
    pub status_4xx: AtomicU64,
    pub status_5xx: AtomicU64,

    // Latency tracking — microsecond-resolution histogram (32 buckets, powers of 2 from 1µs to 2^31µs).
    pub latency_buckets: [AtomicU64; 32],

    // Start time for uptime calculation.
    pub start: Instant,
}

impl Stats {
    pub fn new() -> Self {
        Self {
            requests_total:  AtomicU64::new(0),
            bytes_sent:      AtomicU64::new(0),
            bytes_received:  AtomicU64::new(0),
            active:          AtomicU64::new(0),
            status_2xx:      AtomicU64::new(0),
            status_3xx:      AtomicU64::new(0),
            status_4xx:      AtomicU64::new(0),
            status_5xx:      AtomicU64::new(0),
            latency_buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            start:           Instant::now(),
        }
    }

    pub fn record_request(&self, status: u16, bytes_out: u64, bytes_in: u64, elapsed: Duration) {
        self.requests_total.fetch_add(1, Relaxed);
        self.bytes_sent.fetch_add(bytes_out, Relaxed);
        self.bytes_received.fetch_add(bytes_in, Relaxed);

        match status / 100 {
            2 => self.status_2xx.fetch_add(1, Relaxed),
            3 => self.status_3xx.fetch_add(1, Relaxed),
            4 => self.status_4xx.fetch_add(1, Relaxed),
            5 => self.status_5xx.fetch_add(1, Relaxed),
            _ => 0,
        };

        let us = elapsed.as_micros() as u64;
        let bucket = latency_bucket(us);
        self.latency_buckets[bucket].fetch_add(1, Relaxed);
    }

    /// Compute approximate percentiles from the histogram.
    /// Returns (p50, p90, p99, p999) in microseconds.
    pub fn latency_percentiles(&self) -> (u64, u64, u64, u64) {
        let total = self.requests_total.load(Relaxed);
        if total == 0 { return (0, 0, 0, 0); }

        let buckets: Vec<u64> = self.latency_buckets.iter().map(|b| b.load(Relaxed)).collect();
        let p50  = percentile_us(&buckets, total, 50);
        let p90  = percentile_us(&buckets, total, 90);
        let p99  = percentile_us(&buckets, total, 99);
        let p999 = percentile_us(&buckets, total, 999); // per-mille

        (p50, p90, p99, p999)
    }
}

fn latency_bucket(us: u64) -> usize {
    if us == 0 { return 0; }
    let bit = 63 - us.leading_zeros() as usize;
    bit.min(31)
}

fn percentile_us(buckets: &[u64], total: u64, per_mille_x10: u64) -> u64 {
    let target = (total * per_mille_x10) / 1000;
    let mut cumulative = 0u64;
    for (i, &count) in buckets.iter().enumerate() {
        cumulative += count;
        if cumulative >= target {
            // Bucket i covers [2^(i-1), 2^i) µs; return midpoint.
            return if i == 0 { 0 } else { 1u64 << (i - 1) };
        }
    }
    1u64 << 31 // overflow bucket
}

// ── Per-IP rate limiter ───────────────────────────────────────────────────────

pub struct RateLimiter {
    /// (last_second_unix, count_in_that_second)
    windows: DashMap<std::net::IpAddr, (u64, u32)>,
    pub rps_limit: u32,
}

impl RateLimiter {
    pub fn new(rps: u32) -> Self {
        Self { windows: DashMap::new(), rps_limit: rps }
    }

    /// Returns true if the request is allowed, false if rate-limited.
    pub fn allow(&self, ip: std::net::IpAddr) -> bool {
        let now_sec = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut entry = self.windows.entry(ip).or_insert((now_sec, 0));
        if entry.0 != now_sec {
            *entry = (now_sec, 1);
            true
        } else {
            entry.1 += 1;
            entry.1 <= self.rps_limit
        }
    }
}
