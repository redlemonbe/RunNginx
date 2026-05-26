# Configuration Reference

RunNginx uses an nginx-compatible configuration syntax. The default config path is
`/etc/runnginx/nginx.conf` (override with `-c <path>`).

---

## Top level

```nginx
worker_processes  auto;       # auto = physical cores (HT excluded) | N
worker_connections 1024;      # max concurrent connections per worker
```

---

## `http {}` block

```nginx
http {
    api_key          <64-char-hex>;      # management API + WebUI auth key
    access_log       /var/log/runnginx/access.log;  # or "off"
    client_max_body_size 10m;            # default: 1m
    keepalive_timeout    65;             # seconds, default: 65
    send_timeout         60;             # seconds, default: 60

    gzip             on;                 # default: off
    gzip_min_length  1024;
    gzip_types       text/html text/css application/javascript application/json;

    brotli           on;                 # default: off
    brotli_min_length 1024;
    brotli_types     text/html text/css application/javascript application/json;

    # Rate limiting zone
    limit_req_zone zone=api:1m rate=30r/s;

    # Upstream group
    upstream backend {
        server 127.0.0.1:3000;
        server 127.0.0.1:3001;
        policy round-robin;             # round-robin | least-conn | ip-hash
        health_check interval=10;
    }

    server { ... }
}
```

---

## `server {}` block

```nginx
server {
    listen 80;                       # port
    listen 443 ssl http2;            # TLS + HTTP/2
    server_name example.com www.example.com;

    root  /var/www/html;
    index index.html index.htm;

    access_log /var/log/runnginx/example.log;
    client_max_body_size 50m;

    # TLS
    ssl_certificate     /etc/runnginx/tls/cert.pem;
    ssl_certificate_key /etc/runnginx/tls/key.pem;

    # HTTP Basic Auth (server-wide)
    auth_basic "Restricted";
    auth_basic_user_file /etc/runnginx/.htpasswd;

    # Rate limit (server-wide)
    limit_req zone=api burst=10;

    # Rewrite
    rewrite ^/old/(.*) /new/$1 permanent;

    # Custom error pages
    error_page 404 /404.html;
    error_page 500 502 503 /50x.html;

    # Add response headers
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-Content-Type-Options nosniff;

    # Return directive
    return 301 https://www.example.com$request_uri;

    location / { ... }
}
```

---

## `location {}` block

```nginx
# Prefix match (longest match wins)
location /api/ {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_read_timeout 60;
    proxy_connect_timeout 5;
}

# Exact match
location = /health {
    return 200 "ok";
}

# Regex match
location ~ \.php$ {
    fastcgi_pass 127.0.0.1:9000;
    fastcgi_index index.php;
}

# Disable regex (prefix only, no regex)
location ^~ /static/ {
    root /var/www;
    gzip on;
}

# Upstream group
location /app/ {
    proxy_pass @backend;
}

# Static files
location / {
    root /var/www/html;
    index index.html;
    gzip on;
    client_max_body_size 100m;
    limit_req zone=api burst=5;
    auth_basic "Restricted";
    auth_basic_user_file /etc/runnginx/.htpasswd;
}
```

---

## TLS

### Self-signed (auto-generated)

RunNginx generates a self-signed certificate on first start if the files don't exist.

```nginx
server {
    listen 443 ssl;
    ssl_certificate     /etc/runnginx/tls/cert.pem;
    ssl_certificate_key /etc/runnginx/tls/key.pem;
}
```

### ACME / Let's Encrypt

```nginx
server {
    listen 443 ssl;
    server_name example.com;
    acme email=admin@example.com;
    acme provider=letsencrypt;
}
```

Certificates are stored in `/etc/runnginx/acme/` and renewed automatically.

---

## Upstream load balancing

```nginx
upstream backend {
    server 127.0.0.1:3000 weight=2;
    server 127.0.0.1:3001 weight=1;
    policy least-conn;             # round-robin | least-conn | ip-hash
    health_check interval=10;      # seconds
}
```

Reference with `proxy_pass @backend;` in a location block.

---

## Rate limiting

```nginx
# Define zone in http {} block
limit_req_zone zone=login:1m rate=5r/s;

# Apply in server or location
server {
    location /login {
        limit_req zone=login burst=3;
    }
}
```

---

## FastCGI / PHP-FPM

```nginx
location ~ \.php$ {
    fastcgi_pass  127.0.0.1:9000;    # or unix:/run/php/php8.2-fpm.sock
    fastcgi_index index.php;
}
```

---

## Multi-user mode

Create `/etc/runnginx/users.toml` — RunNginx loads it automatically. Managed via the
Web UI (Users tab) or directly:

```toml
[[users]]
id         = "17e3a4f2b9cd0a1f"
username   = "alice"
api_key    = "a1b2c3...64-hex..."
domains    = ["alice.example.com", "www.alice.example.com"]
home_dir   = "/home/alice"
quota_bw   = 10737418240   # 10 GB/day (0 = unlimited)
quota_conn = 50            # max concurrent connections (0 = unlimited)
enabled    = true
admin      = false
```

---

## SIGHUP reload

```bash
# Zero-downtime config reload (no connection drops)
kill -HUP $(pidof runnginx)

# Or via API
curl -X POST http://localhost/api/reload \
  -H "Authorization: Bearer $RUNNGINX_API_KEY"
```
