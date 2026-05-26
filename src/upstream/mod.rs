// Upstream group — load balancing for proxy_pass.
// Supports: round-robin (default), least-conn, ip-hash.
// Health checks: active TCP probe at configurable interval.
// Connection tracking: atomic counter per peer for least-conn.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{info, warn};

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LbPolicy {
    RoundRobin,
    LeastConn,
    IpHash,
    Random,
}

#[derive(Debug, Clone)]
pub struct PeerConfig {
    pub addr:   SocketAddr,
    pub weight: u32,
}

#[derive(Debug, Clone)]
pub struct UpstreamGroupConfig {
    pub name:             String,
    pub peers:            Vec<PeerConfig>,
    pub policy:           LbPolicy,
    pub keepalive:        usize,           // max idle conns per peer
    pub health_interval:  Duration,        // 0 = disabled
    pub health_timeout:   Duration,
    pub fail_timeout:     Duration,        // how long to mark a peer down
    pub max_fails:        u32,
}

// ── Runtime state ─────────────────────────────────────────────────────────────

struct PeerState {
    addr:         SocketAddr,
    weight:       u32,
    active_conns: AtomicU32,
    fails:        AtomicU32,
    down_until:   std::sync::atomic::AtomicU64,  // unix seconds
}

pub struct UpstreamGroup {
    pub name:   String,
    peers:      Vec<Arc<PeerState>>,
    policy:     LbPolicy,
    rr_counter: AtomicU64,
    fail_timeout_secs: u64,
    max_fails:  u32,
}

impl UpstreamGroup {
    pub fn new(cfg: &UpstreamGroupConfig) -> Arc<Self> {
        let peers = cfg.peers.iter().map(|p| Arc::new(PeerState {
            addr:         p.addr,
            weight:       p.weight,
            active_conns: AtomicU32::new(0),
            fails:        AtomicU32::new(0),
            down_until:   AtomicU64::new(0),
        })).collect();

        Arc::new(Self {
            name: cfg.name.clone(),
            peers,
            policy: cfg.policy,
            rr_counter: AtomicU64::new(0),
            fail_timeout_secs: cfg.fail_timeout.as_secs(),
            max_fails: cfg.max_fails,
        })
    }

    /// Pick a peer and open a connection. Returns (TcpStream, peer_addr).
    pub async fn connect(&self, connect_timeout: Duration, client_ip: Option<std::net::IpAddr>)
        -> anyhow::Result<(TcpStream, SocketAddr)>
    {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Filter available peers.
        let available: Vec<&Arc<PeerState>> = self.peers.iter()
            .filter(|p| p.down_until.load(Ordering::Relaxed) <= now_secs)
            .collect();

        if available.is_empty() {
            // All down — try all peers anyway (fail-open).
            anyhow::bail!("upstream {}: all peers are down", self.name);
        }

        let peer = match self.policy {
            LbPolicy::RoundRobin => {
                let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
                // Weighted round-robin via repeated peer slots.
                let total_weight: u32 = available.iter().map(|p| p.weight).sum();
                let slot = (idx as u32) % total_weight.max(1);
                let mut cum = 0u32;
                let mut selected = available[0];
                for p in &available {
                    cum += p.weight;
                    if slot < cum { selected = p; break; }
                }
                selected
            }
            LbPolicy::LeastConn => {
                available.iter()
                    .min_by_key(|p| p.active_conns.load(Ordering::Relaxed))
                    .unwrap()
            }
            LbPolicy::IpHash => {
                let hash = if let Some(ip) = client_ip {
                    ip_hash(ip)
                } else {
                    0
                };
                &available[hash as usize % available.len()]
            }
            LbPolicy::Random => {
                let idx = (now_secs ^ (now_secs >> 17)) as usize % available.len();
                &available[idx]
            }
        };

        peer.active_conns.fetch_add(1, Ordering::Relaxed);
        let addr = peer.addr;

        match timeout(connect_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                stream.set_nodelay(true)?;
                peer.fails.store(0, Ordering::Relaxed);
                Ok((stream, addr))
            }
            Ok(Err(_)) | Err(_) => {
                peer.active_conns.fetch_sub(1, Ordering::Relaxed);
                self.mark_fail(peer, now_secs);
                anyhow::bail!("upstream {}: connect to {} failed", self.name, addr)
            }
        }
    }

    pub fn release(&self, addr: SocketAddr) {
        if let Some(p) = self.peers.iter().find(|p| p.addr == addr) {
            p.active_conns.fetch_sub(1, Ordering::Relaxed);
        }
    }

    fn mark_fail(&self, peer: &PeerState, now_secs: u64) {
        let fails = peer.fails.fetch_add(1, Ordering::Relaxed) + 1;
        if fails >= self.max_fails && self.fail_timeout_secs > 0 {
            peer.down_until.store(now_secs + self.fail_timeout_secs, Ordering::Relaxed);
            warn!("upstream {}: peer {} marked down for {}s (fails={})",
                self.name, peer.addr, self.fail_timeout_secs, fails);
        }
    }

    /// Start active health check loop.
    pub fn start_health_checks(self: Arc<Self>, interval: Duration, hc_timeout: Duration) {
        if interval.is_zero() { return; }
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                for peer in &self.peers {
                    let ok = timeout(hc_timeout, TcpStream::connect(peer.addr)).await
                        .map(|r| r.is_ok())
                        .unwrap_or(false);

                    if ok && peer.down_until.load(Ordering::Relaxed) > now {
                        peer.down_until.store(0, Ordering::Relaxed);
                        peer.fails.store(0, Ordering::Relaxed);
                        info!("upstream {}: peer {} recovered", self.name, peer.addr);
                    } else if !ok {
                        self.mark_fail(peer, now);
                    }
                }
            }
        });
    }
}

// ── Group registry ────────────────────────────────────────────────────────────

pub struct UpstreamRegistry {
    groups: DashMap<String, Arc<UpstreamGroup>>,
}

impl UpstreamRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { groups: DashMap::new() })
    }

    pub fn register(&self, group: Arc<UpstreamGroup>) {
        self.groups.insert(group.name.clone(), group);
    }

    pub fn get(&self, name: &str) -> Option<Arc<UpstreamGroup>> {
        self.groups.get(name).map(|g| Arc::clone(&*g))
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn ip_hash(ip: std::net::IpAddr) -> u64 {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            let n = u32::from(v4) as u64;
            n ^ (n >> 16)
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            let mut h: u64 = 0;
            for s in &segments { h = h.wrapping_mul(31).wrapping_add(*s as u64); }
            h
        }
    }
}

/// Parse "round_robin" | "least_conn" | "ip_hash" | "random"
pub fn parse_lb_policy(s: &str) -> LbPolicy {
    match s {
        "least_conn"  => LbPolicy::LeastConn,
        "ip_hash"     => LbPolicy::IpHash,
        "random"      => LbPolicy::Random,
        _             => LbPolicy::RoundRobin,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lb_policy_parsing() {
        assert!(matches!(parse_lb_policy("round_robin"), LbPolicy::RoundRobin));
        assert!(matches!(parse_lb_policy("least_conn"),  LbPolicy::LeastConn));
        assert!(matches!(parse_lb_policy("ip_hash"),     LbPolicy::IpHash));
        assert!(matches!(parse_lb_policy("random"),      LbPolicy::Random));
        assert!(matches!(parse_lb_policy("bogus"),       LbPolicy::RoundRobin));
    }

    #[test]
    fn registry_register_and_get() {
        let cfg = UpstreamGroupConfig {
            name:            "test_group".to_owned(),
            peers:           vec![PeerConfig { addr: "127.0.0.1:9999".parse().unwrap(), weight: 1 }],
            policy:          LbPolicy::RoundRobin,
            keepalive:       0,
            health_interval: Duration::from_secs(0),
            health_timeout:  Duration::from_secs(5),
            fail_timeout:    Duration::from_secs(30),
            max_fails:       3,
        };
        let group = UpstreamGroup::new(&cfg);
        let reg = UpstreamRegistry::new();
        reg.register(group);
        assert!(reg.get("test_group").is_some());
        assert!(reg.get("nonexistent").is_none());
    }
}

