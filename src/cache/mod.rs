// Response cache — stores serialized HTTP responses keyed by (host, method, uri).
// TTL-based expiry with optional cache size cap. Only caches GET/HEAD 200/301/302.
// Respects Cache-Control: no-store, no-cache, private.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;

pub struct CacheEntry {
    /// Serialized HTTP response bytes ready to write to the client.
    pub bytes:      Arc<Vec<u8>>,
    pub status:     u16,
    pub expires_at: Instant,
}

pub struct ResponseCache {
    entries:       DashMap<String, CacheEntry>,
    pub ttl:       Duration,
    pub max_size:  usize,    // max number of entries
    pub enabled:   bool,
}

impl ResponseCache {
    pub fn new(ttl_secs: u64, max_size: usize) -> Arc<Self> {
        Arc::new(Self {
            entries:  DashMap::new(),
            ttl:      Duration::from_secs(ttl_secs),
            max_size,
            enabled:  ttl_secs > 0 && max_size > 0,
        })
    }

    pub fn cache_key(host: &str, method: &str, uri: &str) -> String {
        format!("{}|{}|{}", host, method, uri)
    }

    pub fn get(&self, key: &str) -> Option<Arc<Vec<u8>>> {
        if !self.enabled { return None; }
        let entry = self.entries.get(key)?;
        if entry.expires_at < Instant::now() {
            drop(entry);
            self.entries.remove(key);
            return None;
        }
        Some(Arc::clone(&entry.bytes))
    }

    pub fn put(&self, key: String, bytes: Vec<u8>, status: u16) {
        if !self.enabled { return; }
        if self.entries.len() >= self.max_size {
            // Simple eviction: remove the first expired entry, or skip if full.
            let now = Instant::now();
            let expired: Option<String> = self.entries.iter()
                .find(|e| e.expires_at < now)
                .map(|e| e.key().clone());
            if let Some(k) = expired { self.entries.remove(&k); }
            else { return; } // cache full, skip
        }
        self.entries.insert(key, CacheEntry {
            bytes:      Arc::new(bytes),
            status,
            expires_at: Instant::now() + self.ttl,
        });
    }

    pub fn invalidate_all(&self) {
        self.entries.clear();
    }
}

/// Returns true if this response should be cached.
pub fn is_cacheable(method: &str, status: u16, response_headers: &[(String, String)]) -> bool {
    if !matches!(method, "GET" | "HEAD") { return false; }
    if !matches!(status, 200 | 301 | 302 | 304 | 404) { return false; }

    // Check Cache-Control response header.
    for (k, v) in response_headers {
        if k.eq_ignore_ascii_case("cache-control") {
            let v = v.to_ascii_lowercase();
            if v.contains("no-store") || v.contains("no-cache") || v.contains("private") {
                return false;
            }
        }
        if k.eq_ignore_ascii_case("set-cookie") { return false; }
    }
    true
}

/// Returns true if the request should bypass cache (Cache-Control: no-cache in request).
pub fn request_bypasses_cache(request_headers: &[(String, String)]) -> bool {
    for (k, v) in request_headers {
        if k.eq_ignore_ascii_case("cache-control") {
            let v = v.to_ascii_lowercase();
            if v.contains("no-cache") || v.contains("no-store") { return true; }
        }
        if k.eq_ignore_ascii_case("pragma") && v.eq_ignore_ascii_case("no-cache") {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_and_retrieve() {
        let cache = ResponseCache::new(60, 100);
        let key = ResponseCache::cache_key("h", "GET", "/page");
        let body = b"HTTP/1.1 200 OK

hello".to_vec();
        cache.put(key.clone(), body.clone(), 200);
        assert_eq!(cache.get(&key).unwrap().as_ref(), &body);
    }
    #[test]
    fn ttl_zero_disabled() {
        let cache = ResponseCache::new(0, 100);
        let key = ResponseCache::cache_key("h", "GET", "/x");
        cache.put(key.clone(), b"data".to_vec(), 200);
        assert!(cache.get(&key).is_none(), "disabled cache should return None");
    }
    #[test]
    fn is_cacheable_rules() {
        assert!(is_cacheable("GET", 200, &[]));
        assert!(is_cacheable("HEAD", 200, &[]));
        assert!(!is_cacheable("POST", 200, &[]));
        assert!(!is_cacheable("GET", 500, &[]));
        assert!(!is_cacheable("GET", 200, &[("Cache-Control".into(), "no-store".into())]));
        assert!(!is_cacheable("GET", 200, &[("Cache-Control".into(), "private".into())]));
        assert!(!is_cacheable("GET", 200, &[("Set-Cookie".into(), "sess=1".into())]));
    }
    #[test]
    fn request_bypass() {
        assert!(!request_bypasses_cache(&[]));
        assert!(request_bypasses_cache(&[("Cache-Control".into(), "no-cache".into())]));
        assert!(request_bypasses_cache(&[("Pragma".into(), "no-cache".into())]));
    }
}

