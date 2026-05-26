# RunNginx

A high-performance HTTP/1.1 server written in Rust, compatible with nginx-style configuration syntax. Designed for self-hosted infrastructure with a focus on security, low resource usage, and zero runtime dependencies.

> **Status**: v0.1.x — actively developed. API and config format may change between minor versions.

---

## Features

| Feature | Details |
|---------|---------|
| **Static file serving** | Efficient sendfile-based serving, directory index, custom error pages |
| **Reverse proxy** | HTTP upstream forwarding, `proxy_pass`, `proxy_set_header`, configurable timeouts |
| **Load balancing** | Round-robin, least-connections, and IP-hash policies across upstream groups |
| **TLS / HTTP/2** | rustls-powered HTTPS, self-signed certificate auto-generation; HTTP/2 via ALPN ( negotiated automatically over TLS) |
| **ACME / Let's Encrypt** | In-process certificate issuance and renewal — no certbot required |
| **FastCGI / PHP-FPM** | Full FastCGI client, supports Unix socket and TCP upstreams |
| **WebSocket proxy** | Transparent TCP splice on `Upgrade: websocket` |
| **Rewrite rules** | `rewrite` directive with regex capture groups, redirect/last/break/permanent flags |
| **Auth Basic** | HTTP Basic authentication from htpasswd-format user files |
| **Rate limiting** | `limit_req_zone` / `limit_req` token-bucket rate limiter, per-IP, per-location |
| **Response cache** | In-memory LRU cache for GET/HEAD responses, `Cache-Control` aware |
| **Brotli compression** | Native Rust brotli encoder, per-location toggle, MIME-type filter |
| **Gzip compression** | Gzip with configurable minimum length and MIME-type filter |
| **Prometheus metrics** | `GET /metrics` — requests/s, active connections, bytes in/out, latency histogram |
| **SIGHUP reload** | Zero-downtime configuration reload without dropping connections |
| **Multi-user mode** | Per-user API keys, bandwidth quotas, isolated vhosts, management REST API |
| **Embedded Web UI** | Built-in management dashboard served at configurable port |
| **SIMD HTTP parser** | AVX2 (32-byte) / SSE2 (16-byte) / scalar CRLF scan — dispatch chosen at startup |
| **Access log** | Combined log format, configurable path |

---

## Quick start

### Download a binary

From the [releases page](https://github.com/redlemonbe/RunNginx/releases):

```bash
# x86_64 static binary (no glibc dependency)
curl -LO https://github.com/redlemonbe/RunNginx/releases/latest/download/runnginx-x86_64-linux-musl
chmod +x runnginx-x86_64-linux-musl
./runnginx-x86_64-linux-musl --help
```

### Install with the provided script

```bash
curl -fsSL https://raw.githubusercontent.com/redlemonbe/RunNginx/main/install.sh | bash
```

This installs the binary to `/usr/local/bin/runnginx`, creates the systemd unit, and writes a minimal config to `/etc/runnginx/runnginx.conf`.

### Build from source

```bash
git clone https://github.com/redlemonbe/RunNginx
cd RunNginx
cargo build --release
```

Rust 1.75+ required.

---

## Configuration

RunNginx uses nginx-compatible configuration syntax.

### Minimal configuration

```nginx
http {
    api-key  secret-key-here;
    api-port 8081;

    server {
        listen 80;
        server_name example.com;
        root /var/www/html;

        location / {
            # serve static files
        }
    }
}
```

### Reverse proxy

```nginx
server {
    listen 80;
    server_name api.example.com;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 60;
        proxy_connect_timeout 10;
    }
}
```

### Load balancing

```nginx
upstream backend {
    policy round_robin;
    server 192.168.1.10:8080;
    server 192.168.1.11:8080;
    server 192.168.1.12:8080;
}

server {
    listen 80;

    location / {
        proxy_pass upstream://backend;
    }
}
```

### TLS with Let's Encrypt

```nginx
http {
    server {
        listen 443 ssl;
        server_name example.com;

        tls {
            acme yes;
            email  admin@example.com;
        }

        root /var/www/html;
    }
}
```

### Rate limiting

```nginx
http {
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;

    server {
        listen 80;

        location /api/ {
            limit_req zone=api burst=20;
            proxy_pass http://127.0.0.1:3000;
        }
    }
}
```

### FastCGI / PHP-FPM

```nginx
server {
    listen 80;
    server_name php.example.com;
    root /var/www/php;

    location ~ \.php$ {
        fastcgi_pass unix:/run/php/php8.2-fpm.sock;
        fastcgi_index index.php;
    }
}
```

### Auth Basic

```nginx
server {
    listen 80;

    location /admin {
        auth_basic "Admin area";
        auth_basic_user_file /etc/runnginx/.htpasswd;
    }
}
```

### Compression

```nginx
http {
    gzip on;
    gzip_min_length 1024;
    brotli on;
    brotli_min_length 512;
}
```

### Rewrite rules

```nginx
server {
    rewrite ^/old/(.*)$ /new/$1 permanent;

    location /api/ {
        rewrite ^/api/v1/(.*)$ /api/v2/$1 last;
    }
}
```

---

## Management API

When an `api-key` is set, RunNginx exposes a management API at `api-port` (default: 8081).

```bash
AUTH="Authorization: Bearer your-api-key"

# Server stats
curl -H "$AUTH" http://127.0.0.1:8081/api/stats

# Prometheus metrics (no auth required)
curl http://127.0.0.1:8081/metrics

# Reload config (equivalent to SIGHUP)
curl -X POST -H "$AUTH" http://127.0.0.1:8081/api/reload
```

---

## Multi-user mode

Create a `users.json` file in the config directory to enable multi-user mode.

```bash
# Create first user via API
curl -X POST -H "$AUTH" -H "Content-Type: application/json" \
  http://127.0.0.1:8081/api/users \
  -d '{"username":"alice","vhosts":["alice.example.com"],"bandwidth_mb":1024}'
```

User management endpoints:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/users` | List all users (admin) |
| `POST` | `/api/users` | Create user (admin) |
| `DELETE` | `/api/users/:id` | Delete user (admin) |
| `GET` | `/api/users/me` | Current user profile |
| `POST` | `/api/users/:id/rotate-key` | Rotate API key |

---

## Security

- All request limits are enforced before any I/O: method, URI, header count, header size, body size
- Path traversal sequences (`../`, `%2F`, `%5C`, null bytes) are rejected at the URI parsing stage
- TLS is provided by [rustls](https://github.com/rustls/rustls) — no OpenSSL dependency
- ACME certificate storage uses 0600 permissions
- Auth Basic uses constant-time comparison to prevent timing attacks

See [docs/security-audit/](docs/security-audit/) for the security audit history.

---

## License

[AGPL-3.0](LICENSE)
