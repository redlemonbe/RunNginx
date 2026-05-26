# REST API Reference

The management API listens on the same port as the web server (default: 80 or 443).
All `/api/*` endpoints require a Bearer token. `/health` and `/metrics` are unauthenticated.

---

## Authentication

```bash
export RUNNGINX_API_KEY="your-64-char-hex-key"
curl -H "Authorization: Bearer $RUNNGINX_API_KEY" http://localhost/api/stats
```

The key is set in `nginx.conf` as `api_key <key>;` inside the `http {}` block.

---

## Endpoints

### `GET /health`

Liveness probe — no auth required.

```json
{"status":"ok"}
```

---

### `GET /metrics`

Prometheus metrics — no auth required.

```
runnginx_requests_total 42190
runnginx_active_connections 7
runnginx_bytes_sent_total 98123456
runnginx_bytes_received_total 4521000
runnginx_status_total{class="2xx"} 41987
runnginx_p50_seconds 0.016230
runnginx_p99_seconds 0.048720
runnginx_uptime_seconds 3604
```

---

### `GET /api/stats`

Current server statistics.

```json
{
  "version": "0.1.7",
  "requests_total": 42190,
  "bytes_sent": 98123456,
  "bytes_received": 4521000,
  "active_connections": 7,
  "status_2xx": 41987,
  "status_3xx": 98,
  "status_4xx": 105,
  "status_5xx": 0,
  "latency_us": {
    "p50": 16230,
    "p90": 24110,
    "p99": 48720,
    "p99.9": 89150
  },
  "uptime_seconds": 3604
}
```

---

### `GET /api/system`

Server configuration summary.

```json
{
  "version": "0.1.7",
  "uptime_s": 3604,
  "config": "/etc/runnginx/nginx.conf",
  "servers": 2,
  "simd": "Avx2",
  "upstream_groups": [
    {
      "name": "backend",
      "policy": "round-robin",
      "peers": ["127.0.0.1:3000", "127.0.0.1:3001"],
      "health_interval": 10
    }
  ]
}
```

---

### `POST /api/reload`

Reload configuration without dropping connections (SIGHUP equivalent).

```bash
curl -X POST http://localhost/api/reload \
  -H "Authorization: Bearer $RUNNGINX_API_KEY"
```

```json
{"status":"reloading"}
```

---

### `GET /api/logs?n=<N>`

Return the last N access log lines (default: 100, max: 500).

```json
{
  "lines": [
    "192.168.1.1 - - [26/May/2026:14:00:01 +0000] \"GET / HTTP/1.1\" 200 1234 \"-\" \"curl/8.0\"",
    "..."
  ],
  "total": 100
}
```

---

## Multi-user API

When `users.toml` exists, additional endpoints are available.

### `GET /api/users`  *(admin only)*

List all hosting users.

```json
{
  "users": [
    {
      "id": "17e3a4f2",
      "username": "alice",
      "domains": ["alice.example.com"],
      "enabled": true,
      "admin": false,
      "quota_bw": 0
    }
  ]
}
```

---

### `POST /api/users`  *(admin only)*

Create a hosting user.

```bash
curl -X POST http://localhost/api/users \
  -H "Authorization: Bearer $RUNNGINX_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","domains":["alice.example.com"]}'
```

Response (API key shown **once only**):

```json
{"id":"17e3a4f2","api_key":"a1b2c3d4...64-char-hex..."}
```

---

### `DELETE /api/users/:id`  *(admin only)*

Delete a hosting user.

```bash
curl -X DELETE http://localhost/api/users/17e3a4f2 \
  -H "Authorization: Bearer $RUNNGINX_API_KEY"
```

```json
{"status":"deleted"}
```

---

### `GET /api/users/me`  *(any authenticated user)*

Return the current user's own account info.

---

## Web UI

`GET /ui` — serves the management dashboard (HTML, no auth gate on the endpoint itself — auth is handled in the JS with the stored API key).
