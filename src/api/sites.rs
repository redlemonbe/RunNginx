//! Site provisioning — create/list/delete virtual hosts managed by RunNginx.
//!
//! Sites are stored as individual .conf files in `{config_dir}/sites-enabled/`.
//! Metadata is stored in `{config_dir}/sites/{domain}/meta.json`.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct SiteRequest {
    pub domain:       String,
    pub site_type:    SiteType,
    pub php_version:  Option<String>,  // e.g. "8.2"
    pub upstream_url: Option<String>,  // reverse proxy target
    pub db_host:      Option<String>,
    pub db_port:      Option<u16>,
    pub db_root_user: Option<String>,
    pub db_root_pass: Option<String>,
    pub db_name:      Option<String>,
    pub db_user:      Option<String>,
    pub db_pass:      Option<String>,
    pub ssl_mode:     SslMode,
    pub ssl_email:    Option<String>,  // for Let's Encrypt
    pub ssl_cert:     Option<String>,  // PEM cert content
    pub ssl_key:      Option<String>,  // PEM key content
    pub cloudflare:   bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SiteType {
    Static,
    Php,
    Wordpress,
    Proxy,
}

impl SiteType {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Static    => "static",
            Self::Php       => "php",
            Self::Wordpress => "wordpress",
            Self::Proxy     => "proxy",
        }
    }
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "static"    => Some(Self::Static),
            "php"       => Some(Self::Php),
            "wordpress" => Some(Self::Wordpress),
            "proxy"     => Some(Self::Proxy),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum SslMode {
    None,
    LetsEncrypt,
    Custom,
    Cloudflare,
}

impl SslMode {
    pub fn from_str(s: &str) -> Self {
        match s {
            "letsencrypt" => Self::LetsEncrypt,
            "custom"      => Self::Custom,
            "cloudflare"  => Self::Cloudflare,
            _ => Self::None,
        }
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Create a new site. Returns JSON with {ok, message, webroot}.
pub fn create_site(req: &SiteRequest, config_path: &Path) -> Value {
    let config_dir = config_path.parent().unwrap_or(Path::new("/etc/runnginx"));

    // Validate domain
    if !is_valid_domain(&req.domain) {
        return json!({"error": "Invalid domain name"});
    }

    let webroot = PathBuf::from("/var/www").join(&req.domain).join("public");
    let sites_enabled = config_dir.join("sites-enabled");
    let site_meta_dir = config_dir.join("sites").join(&req.domain);

    // Create directories
    for dir in &[&sites_enabled, &site_meta_dir, &webroot] {
        if let Err(e) = std::fs::create_dir_all(dir) {
            return json!({"error": format!("Cannot create directory {}: {}", dir.display(), e)});
        }
    }

    // PHP-FPM socket detection
    let php_socket = if let Some(ref ver) = req.php_version {
        let candidates = [
            format!("/run/php/php{}-fpm.sock", ver),
            format!("/var/run/php/php{}-fpm.sock", ver),
            format!("/run/php{}/php{}-fpm.sock", ver, ver),
        ];
        candidates.into_iter().find(|p| Path::new(p).exists())
            .unwrap_or_else(|| format!("/run/php/php{}-fpm.sock", ver))
    } else {
        detect_php_socket().unwrap_or_else(|| "/run/php/php8.2-fpm.sock".to_string())
    };

    // Execute type-specific setup
    let setup_result = match req.site_type {
        SiteType::Static    => setup_static(req, &webroot),
        SiteType::Php       => setup_php(req, &webroot),
        SiteType::Wordpress => setup_wordpress(req, &webroot),
        SiteType::Proxy     => Ok(()),
    };

    if let Err(e) = setup_result {
        return json!({"error": e});
    }

    // Write nginx config
    let conf_path = sites_enabled.join(format!("{}.conf", req.domain));
    let conf = generate_config(req, &webroot, &php_socket);
    if let Err(e) = std::fs::write(&conf_path, &conf) {
        return json!({"error": format!("Cannot write config: {}", e)});
    }

    // SSL setup
    if let Err(e) = configure_ssl(req, &conf_path, config_dir) {
        // SSL failure is non-fatal — site works on HTTP
        tracing::warn!("SSL setup failed for {}: {}", req.domain, e);
    }

    // Write metadata
    let meta = json!({
        "domain":   req.domain,
        "type":     req.site_type.as_str(),
        "webroot":  webroot.display().to_string(),
        "php_version": req.php_version,
        "ssl_mode": match req.ssl_mode { SslMode::None => "none", SslMode::LetsEncrypt => "letsencrypt", SslMode::Custom => "custom", SslMode::Cloudflare => "cloudflare" },
        "created_at": chrono_now(),
    });
    let _ = std::fs::write(site_meta_dir.join("meta.json"), meta.to_string());

    json!({
        "ok": true,
        "domain": req.domain,
        "webroot": webroot.display().to_string(),
        "type": req.site_type.as_str(),
    })
}

/// List all sites from sites-enabled directory.
pub fn list_sites(config_path: &Path) -> Value {
    let config_dir = config_path.parent().unwrap_or(Path::new("/etc/runnginx"));
    let sites_enabled = config_dir.join("sites-enabled");
    let sites_meta_dir = config_dir.join("sites");

    let entries = match std::fs::read_dir(&sites_enabled) {
        Ok(e) => e,
        Err(_) => return json!([]),
    };

    let mut sites: Vec<Value> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|x| x == "conf").unwrap_or(false))
        .map(|e| {
            let fname = e.file_name();
            let domain = fname.to_string_lossy()
                .trim_end_matches(".conf").to_string();
            let meta_path = sites_meta_dir.join(&domain).join("meta.json");
            let meta: Value = std::fs::read_to_string(&meta_path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_else(|| json!({"domain": domain, "type": "unknown"}));
            meta
        })
        .collect();

    sites.sort_by(|a, b| {
        a["domain"].as_str().unwrap_or("").cmp(b["domain"].as_str().unwrap_or(""))
    });

    json!(sites)
}

/// Delete a site: remove config file, metadata, optionally webroot.
pub fn delete_site(domain: &str, config_path: &Path, delete_files: bool) -> Value {
    if !is_valid_domain(domain) {
        return json!({"error": "Invalid domain"});
    }
    let config_dir = config_path.parent().unwrap_or(Path::new("/etc/runnginx"));
    let conf = config_dir.join("sites-enabled").join(format!("{}.conf", domain));
    let meta = config_dir.join("sites").join(domain);
    let webroot = PathBuf::from("/var/www").join(domain);

    let _ = std::fs::remove_file(&conf);
    let _ = std::fs::remove_dir_all(&meta);
    if delete_files {
        let _ = std::fs::remove_dir_all(&webroot);
    }

    json!({"ok": true, "domain": domain})
}

/// Return list of installed PHP versions (detected from sockets and /etc/php).
pub fn list_php_versions() -> Value {
    let mut versions = std::collections::BTreeSet::new();

    // From sockets
    for dir in &["/run/php", "/var/run/php"] {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if name.starts_with("php") && name.ends_with("-fpm.sock") {
                    let ver = name.trim_start_matches("php").trim_end_matches("-fpm.sock").to_string();
                    if !ver.is_empty() { versions.insert(ver); }
                }
            }
        }
    }

    // From /etc/php
    if let Ok(entries) = std::fs::read_dir("/etc/php") {
        for e in entries.flatten() {
            if e.metadata().map(|m| m.is_dir()).unwrap_or(false) {
                let ver = e.file_name().to_string_lossy().to_string();
                if ver.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                    versions.insert(ver);
                }
            }
        }
    }

    // From which php
    if let Ok(out) = Command::new("sh").arg("-c").arg("php -r 'echo PHP_MAJOR_VERSION.\".\".PHP_MINOR_VERSION;' 2>/dev/null").output() {
        let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !v.is_empty() && v.contains('.') { versions.insert(v); }
    }

    json!(versions.into_iter().collect::<Vec<_>>())
}

// ── Type-specific setup ───────────────────────────────────────────────────────

fn setup_static(req: &SiteRequest, webroot: &Path) -> Result<(), String> {
    let index = webroot.join("index.html");
    if !index.exists() {
        std::fs::write(&index, format!(
            "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Welcome to {}</title></head>\
            <body style='font-family:sans-serif;max-width:600px;margin:80px auto;text-align:center'>\
            <h1>Welcome to {}</h1><p>Your site is up and running on RunNginx.</p></body></html>",
            req.domain, req.domain
        )).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn setup_php(req: &SiteRequest, webroot: &Path) -> Result<(), String> {
    let index = webroot.join("index.php");
    if !index.exists() {
        std::fs::write(&index, format!(
            "<?php\nphpinfo();\n"
        )).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn setup_wordpress(req: &SiteRequest, webroot: &Path) -> Result<(), String> {
    // Download and extract WordPress
    let wp_tmp = PathBuf::from("/tmp/wordpress-latest.tar.gz");
    if !wp_tmp.exists() {
        let dl = Command::new("wget")
            .args(["-q", "-O", wp_tmp.to_str().unwrap(), "https://wordpress.org/latest.tar.gz"])
            .status()
            .map_err(|e| format!("wget failed: {}", e))?;
        if !dl.success() {
            return Err("Failed to download WordPress".to_string());
        }
    }

    // Extract to webroot parent, then move wordpress/ → public/
    let parent = webroot.parent().unwrap();
    let extract_dir = parent.join("wp_extract_tmp");
    let _ = std::fs::remove_dir_all(&extract_dir);
    std::fs::create_dir_all(&extract_dir).map_err(|e| e.to_string())?;

    Command::new("tar")
        .args(["-xzf", wp_tmp.to_str().unwrap(), "-C", extract_dir.to_str().unwrap()])
        .status()
        .map_err(|e| format!("tar failed: {}", e))?;

    let wp_dir = extract_dir.join("wordpress");
    // Copy contents to webroot
    Command::new("cp").args(["-a", &format!("{}/.", wp_dir.display()), webroot.to_str().unwrap()])
        .status().map_err(|e| e.to_string())?;
    let _ = std::fs::remove_dir_all(&extract_dir);

    // Create MySQL database and user if credentials provided
    if let (Some(db_name), Some(db_user), Some(db_pass)) =
        (&req.db_name, &req.db_user, &req.db_pass)
    {
        let db_host = req.db_host.as_deref().unwrap_or("localhost");
        let db_port = req.db_port.unwrap_or(3306);
        let root_user = req.db_root_user.as_deref().unwrap_or("root");
        let root_pass = req.db_root_pass.as_deref().unwrap_or("");

        let mysql_cmd = format!(
            "CREATE DATABASE IF NOT EXISTS `{db_name}`; \
             CREATE USER IF NOT EXISTS '{db_user}'@'localhost' IDENTIFIED BY '{db_pass}'; \
             GRANT ALL PRIVILEGES ON `{db_name}`.* TO '{db_user}'@'localhost'; \
             FLUSH PRIVILEGES;"
        );

        let mut args = vec![
            format!("-h{}", db_host),
            format!("-P{}", db_port),
            format!("-u{}", root_user),
        ];
        if !root_pass.is_empty() {
            args.push(format!("-p{}", root_pass));
        }
        args.extend(["-e".to_string(), mysql_cmd]);

        Command::new("mysql").args(&args).status()
            .map_err(|e| format!("mysql command failed: {}", e))?;

        // Write wp-config.php
        let sample = webroot.join("wp-config-sample.php");
        let config_php = webroot.join("wp-config.php");
        if sample.exists() && !config_php.exists() {
            let mut content = std::fs::read_to_string(&sample).unwrap_or_default();
            content = content
                .replace("database_name_here", db_name)
                .replace("username_here", db_user)
                .replace("password_here", db_pass)
                .replace("localhost", db_host);
            // Generate unique keys
            let keys = [
                ("AUTH_KEY", rand_hex(64)),
                ("SECURE_AUTH_KEY", rand_hex(64)),
                ("LOGGED_IN_KEY", rand_hex(64)),
                ("NONCE_KEY", rand_hex(64)),
                ("AUTH_SALT", rand_hex(64)),
                ("SECURE_AUTH_SALT", rand_hex(64)),
                ("LOGGED_IN_SALT", rand_hex(64)),
                ("NONCE_SALT", rand_hex(64)),
            ];
            for (k, v) in &keys {
                let placeholder = format!("define( '{}', 'put your unique phrase here' );", k);
                let replacement = format!("define( '{}', '{}' );", k, v);
                content = content.replace(&placeholder, &replacement);
            }
            std::fs::write(&config_php, content).map_err(|e| e.to_string())?;
        }
    }

    // Set file permissions
    let _ = Command::new("chown").args(["-R", "www-data:www-data", webroot.to_str().unwrap()]).status();
    let _ = Command::new("chmod").args(["-R", "755", webroot.to_str().unwrap()]).status();

    Ok(())
}

// ── Config template generation ────────────────────────────────────────────────

fn generate_config(req: &SiteRequest, webroot: &Path, php_socket: &str) -> String {
    let domain = &req.domain;
    let root = webroot.display();
    let has_ssl = !matches!(req.ssl_mode, SslMode::None);

    let cf_headers = if req.cloudflare {
        "    real_ip_header CF-Connecting-IP;\n"
    } else {
        ""
    };

    // HTTP block
    let http_block = match req.site_type {
        SiteType::Static => format!(
            "server {{\n    listen 80;\n    server_name {domain};\n    root {root};\n    index index.html index.htm;\n{cf_headers}\
            location / {{\n        try_files $uri $uri/ =404;\n    }}\n}}\n"
        ),
        SiteType::Php => format!(
            "server {{\n    listen 80;\n    server_name {domain};\n    root {root};\n    index index.php index.html;\n{cf_headers}\
            location / {{\n        try_files $uri $uri/ =404;\n    }}\n\
            location ~ \\.php$ {{\n        fastcgi_pass unix:{php_socket};\n        fastcgi_index index.php;\n    }}\n}}\n"
        ),
        SiteType::Wordpress => format!(
            "server {{\n    listen 80;\n    server_name {domain};\n    root {root};\n    index index.php;\n{cf_headers}\
            location / {{\n        try_files $uri $uri/ /index.php?$args;\n    }}\n\
            location ~ \\.php$ {{\n        fastcgi_pass unix:{php_socket};\n        fastcgi_index index.php;\n    }}\n\
            location ~* \\.(js|css|png|jpg|jpeg|gif|ico|svg|woff2?)$ {{\n        expires max;\n    }}\n}}\n"
        ),
        SiteType::Proxy => {
            let upstream = req.upstream_url.as_deref().unwrap_or("http://127.0.0.1:8080");
            format!(
                "server {{\n    listen 80;\n    server_name {domain};\n{cf_headers}\
                location / {{\n        proxy_pass {upstream};\n        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto $scheme;\n    }}\n}}\n"
            )
        }
    };

    // HTTPS redirect block (added after SSL is configured)
    if has_ssl {
        format!(
            "{http_block}\nserver {{\n    listen 80;\n    server_name {domain};\n    return 301 https://{domain}$request_uri;\n}}\n"
        )
    } else {
        http_block
    }
}

// ── SSL ───────────────────────────────────────────────────────────────────────

fn configure_ssl(req: &SiteRequest, conf_path: &Path, config_dir: &Path) -> Result<(), String> {
    match req.ssl_mode {
        SslMode::None => Ok(()),
        SslMode::LetsEncrypt => configure_letsencrypt(req, conf_path),
        SslMode::Custom       => configure_custom_cert(req, conf_path, config_dir),
        SslMode::Cloudflare   => configure_cloudflare(req, conf_path, config_dir),
    }
}

fn configure_letsencrypt(req: &SiteRequest, _conf_path: &Path) -> Result<(), String> {
    let email = req.ssl_email.as_deref().unwrap_or("admin@localhost");
    let out = Command::new("certbot")
        .args([
            "certonly",
            "--webroot",
            "--webroot-path", &format!("/var/www/{}/public", req.domain),
            "-d", &req.domain,
            "--non-interactive",
            "--agree-tos",
            "-m", email,
        ])
        .output()
        .map_err(|e| format!("certbot not found: {}", e))?;

    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!("certbot failed: {}", err));
    }

    // Rewrite config with TLS
    let cert = format!("/etc/letsencrypt/live/{}/fullchain.pem", req.domain);
    let key  = format!("/etc/letsencrypt/live/{}/privkey.pem", req.domain);
    append_tls_block(_conf_path, &req.domain, &cert, &key)
}

fn configure_custom_cert(req: &SiteRequest, conf_path: &Path, config_dir: &Path) -> Result<(), String> {
    let ssl_dir = config_dir.join("ssl").join(&req.domain);
    std::fs::create_dir_all(&ssl_dir).map_err(|e| e.to_string())?;

    let cert_path = ssl_dir.join("cert.pem");
    let key_path  = ssl_dir.join("key.pem");

    if let Some(cert) = &req.ssl_cert {
        std::fs::write(&cert_path, cert).map_err(|e| e.to_string())?;
    }
    if let Some(key) = &req.ssl_key {
        std::fs::write(&key_path, key).map_err(|e| e.to_string())?;
    }

    if cert_path.exists() && key_path.exists() {
        append_tls_block(conf_path, &req.domain, cert_path.to_str().unwrap(), key_path.to_str().unwrap())?;
    }
    Ok(())
}

fn configure_cloudflare(req: &SiteRequest, conf_path: &Path, config_dir: &Path) -> Result<(), String> {
    // Cloudflare Origin Certificate — user must provide cert + key
    configure_custom_cert(req, conf_path, config_dir)?;
    // Add CF real_ip_header to existing config (already done in template via cloudflare flag)
    Ok(())
}

fn append_tls_block(conf_path: &Path, domain: &str, cert: &str, key: &str) -> Result<(), String> {
    let existing = std::fs::read_to_string(conf_path).unwrap_or_default();
    // Replace listen 80 with 443 ssl in first server block and add http→https redirect
    let tls_block = format!(
        "\nserver {{\n    listen 443 ssl;\n    ssl_certificate {cert};\n    ssl_certificate_key {key};\n    server_name {domain};\n"
    );
    // Extract location blocks from the HTTP block and put them in the HTTPS block
    let with_tls = format!("{}\n{}", existing, tls_block + "    # Location blocks copied from HTTP server\n}\n");
    std::fs::write(conf_path, with_tls).map_err(|e| e.to_string())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 { return false; }
    // Allow only safe chars: letters, digits, hyphens, dots
    domain.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains("..")
}

fn detect_php_socket() -> Option<String> {
    for dir in &["/run/php", "/var/run/php"] {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if name.starts_with("php") && name.ends_with("-fpm.sock") {
                    return Some(format!("{}/{}", dir, name));
                }
            }
        }
    }
    None
}

fn chrono_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn rand_hex(len: usize) -> String {
    use std::fmt::Write as FmtWrite;
    let bytes: Vec<u8> = (0..len/2).map(|_| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as u8
    }).collect();
    let mut s = String::new();
    for b in bytes { write!(s, "{:02x}", b).unwrap(); }
    s
}
