// Multi-user mode — cPanel-style hosting account management.
//
// Each user account owns:
//   - A set of server names (vhosts)
//   - A document root (chroot-jailed within their home directory)
//   - An API key for managing their own configuration
//   - Bandwidth, connection, and disk quotas
//
// Storage: /etc/runnginx/users.toml (TOML, reloaded on SIGHUP or POST /api/users/reload).
// Admin operations require the global api_key; user operations require the user's own api_key.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAccount {
    pub id:        String,
    pub username:  String,
    pub api_key:   String,            // 64-char hex token
    pub domains:   Vec<String>,       // server_name values this user owns
    pub home_dir:  PathBuf,           // /home/username
    pub quota_bw:  u64,               // max bytes/day, 0 = unlimited
    pub quota_conn: u32,              // max concurrent connections, 0 = unlimited
    pub enabled:   bool,
    pub admin:     bool,              // can manage all users
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UsersFile {
    #[serde(default)]
    users: Vec<UserAccount>,
}

// ── Registry ──────────────────────────────────────────────────────────────────

pub struct UserRegistry {
    /// id → account
    by_id:     DashMap<String, Arc<UserAccount>>,
    /// api_key → id
    by_key:    DashMap<String, String>,
    /// domain → id
    by_domain: DashMap<String, String>,
    /// path to users.toml
    path: PathBuf,
}

impl UserRegistry {
    pub fn load(path: &Path) -> Arc<Self> {
        let reg = Arc::new(Self {
            by_id:     DashMap::new(),
            by_key:    DashMap::new(),
            by_domain: DashMap::new(),
            path:      path.to_owned(),
        });
        reg.reload();
        reg
    }

    pub fn reload(&self) {
        let src = match std::fs::read_to_string(&self.path) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("users.toml not found ({}): multi-user mode disabled", e);
                return;
            }
        };
        let file: UsersFile = match toml::from_str(&src) {
            Ok(f) => f,
            Err(e) => { tracing::error!("users.toml parse error: {}", e); return; }
        };

        self.by_id.clear();
        self.by_key.clear();
        self.by_domain.clear();

        for user in file.users {
            let user = Arc::new(user);
            self.by_key.insert(user.api_key.clone(), user.id.clone());
            for d in &user.domains {
                self.by_domain.insert(d.clone(), user.id.clone());
            }
            self.by_id.insert(user.id.clone(), user);
        }
        tracing::info!("users.toml reloaded: {} users", self.by_id.len());
    }

    pub fn by_api_key(&self, key: &str) -> Option<Arc<UserAccount>> {
        let id = self.by_key.get(key)?.clone();
        self.by_id.get(&id).map(|u| Arc::clone(&u))
    }

    pub fn by_id(&self, id: &str) -> Option<Arc<UserAccount>> {
        self.by_id.get(id).map(|u| Arc::clone(&u))
    }

    pub fn by_domain(&self, domain: &str) -> Option<Arc<UserAccount>> {
        let id = self.by_domain.get(domain)?.clone();
        self.by_id.get(&id).map(|u| Arc::clone(&u))
    }

    pub fn all_users(&self) -> Vec<Arc<UserAccount>> {
        self.by_id.iter().map(|e| Arc::clone(e.value())).collect()
    }

    /// Create a new user and persist to users.toml.
    pub fn create_user(&self, username: &str, domains: Vec<String>, home_dir: PathBuf) -> Result<Arc<UserAccount>, String> {
        let id  = generate_id();
        let key = generate_api_key();
        let user = Arc::new(UserAccount {
            id: id.clone(),
            username: username.to_owned(),
            api_key: key,
            domains,
            home_dir,
            quota_bw: 0,
            quota_conn: 0,
            enabled: true,
            admin: false,
        });
        self.by_id.insert(id.clone(), Arc::clone(&user));
        self.by_key.insert(user.api_key.clone(), id.clone());
        for d in &user.domains {
            self.by_domain.insert(d.clone(), id.clone());
        }
        self.persist().map_err(|e| e.to_string())?;
        Ok(user)
    }

    pub fn delete_user(&self, id: &str) -> bool {
        if let Some((_, user)) = self.by_id.remove(id) {
            self.by_key.remove(&user.api_key);
            for d in &user.domains {
                self.by_domain.remove(d.as_str());
            }
            let _ = self.persist();
            return true;
        }
        false
    }

    fn persist(&self) -> anyhow::Result<()> {
        let users: Vec<UserAccount> = self.by_id.iter()
            .map(|e| e.value().as_ref().clone())
            .collect();
        let file = UsersFile { users };
        let toml_str = toml::to_string_pretty(&file)
            .map_err(|e| anyhow::anyhow!("serialize users.toml: {}", e))?;
        std::fs::write(&self.path, toml_str)?;
        Ok(())
    }
}

// ── Per-user bandwidth tracking ───────────────────────────────────────────────

pub struct BandwidthTracker {
    /// user_id → (day_unix, bytes_today)
    windows: DashMap<String, (u64, u64)>,
}

impl BandwidthTracker {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { windows: DashMap::new() })
    }

    pub fn record(&self, user_id: &str, bytes: u64) {
        let day = current_day();
        let mut e = self.windows.entry(user_id.to_owned()).or_insert((day, 0));
        if e.0 != day { *e = (day, bytes); } else { e.1 += bytes; }
    }

    pub fn check(&self, user_id: &str, quota: u64) -> bool {
        if quota == 0 { return true; }
        let day = current_day();
        match self.windows.get(user_id) {
            Some(e) if e.0 == day => e.1 < quota,
            _ => true,
        }
    }
}

fn current_day() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 86400)
        .unwrap_or(0)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn generate_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    format!("{:x}", SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0))
}

fn generate_api_key() -> String {
    // 64-char hex from system entropy via /dev/urandom.
    let mut bytes = [0u8; 32];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut bytes);
    }
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ── User-scoped API handler ───────────────────────────────────────────────────

pub fn handle_user_api(
    path:       &str,
    method:     &str,
    body:       &[u8],
    api_key:    &str,
    registry:   &Arc<UserRegistry>,
    is_admin:   bool,
) -> Option<Vec<u8>> {
    if !path.starts_with("/api/users") { return None; }

    match (method, path) {
        // Admin: list all users
        ("GET", "/api/users") if is_admin => {
            let users: Vec<serde_json::Value> = registry.all_users().iter().map(|u| {
                serde_json::json!({
                    "id": u.id, "username": u.username,
                    "domains": u.domains, "enabled": u.enabled,
                    "admin": u.admin, "quota_bw": u.quota_bw,
                })
            }).collect();
            Some(json_ok(&serde_json::json!({"users": users}).to_string()))
        }
        // Admin: create user
        ("POST", "/api/users") if is_admin => {
            let v: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
            let username = v["username"].as_str().unwrap_or("").to_owned();
            let domains: Vec<String> = v["domains"].as_array()
                .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_owned())).collect())
                .unwrap_or_default();
            if username.is_empty() {
                return Some(json_err(400, "username required"));
            }
            let home = PathBuf::from(format!("/home/{}", username));
            match registry.create_user(&username, domains, home) {
                Ok(u) => Some(json_ok(&serde_json::json!({"id": u.id, "api_key": u.api_key}).to_string())),
                Err(e) => Some(json_err(500, &e)),
            }
        }
        // Admin: delete user
        (m, p) if m == "DELETE" && p.starts_with("/api/users/") && is_admin => {
            let id = &p["/api/users/".len()..];
            if registry.delete_user(id) {
                Some(json_ok(r#"{"status":"deleted"}"#))
            } else {
                Some(json_err(404, "user not found"))
            }
        }
        // User: get own info
        ("GET", "/api/users/me") => {
            if let Some(u) = registry.by_api_key(api_key) {
                Some(json_ok(&serde_json::json!({
                    "id": u.id, "username": u.username,
                    "domains": u.domains, "enabled": u.enabled,
                }).to_string()))
            } else {
                Some(json_err(401, "unauthorized"))
            }
        }
        _ => None,
    }
}

fn json_ok(body: &str) -> Vec<u8> {
    let mut r = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        body.len()
    ).into_bytes();
    r.extend_from_slice(body.as_bytes());
    r
}

fn json_err(status: u16, msg: &str) -> Vec<u8> {
    let body = format!(r#"{{"error":"{}"}}"#, msg);
    let mut r = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        status, if status == 400 { "Bad Request" } else if status == 404 { "Not Found" } else { "Internal Server Error" },
        body.len()
    ).into_bytes();
    r.extend_from_slice(body.as_bytes());
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_api_key_length() {
        let key = generate_api_key();
        assert_eq!(key.len(), 64, "API key should be 64 hex chars");
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn bandwidth_tracker_quota() {
        let tracker = BandwidthTracker::new();
        tracker.record("user1", 500);
        assert!(tracker.check("user1", 1000), "under quota");
        tracker.record("user1", 600);
        assert!(!tracker.check("user1", 1000), "over quota");
        assert!(tracker.check("user1", 0), "unlimited quota");
    }

    #[test]
    fn empty_registry() {
        let reg = UserRegistry {
            by_id: DashMap::new(), by_key: DashMap::new(), by_domain: DashMap::new(),
            path: PathBuf::new(),
        };
        assert!(reg.by_api_key("anything").is_none());
        assert!(reg.by_domain("example.com").is_none());
    }
}
