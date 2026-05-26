# RunNginx

## The World's First ASM-Accelerated HTTP Server

**nginx-compatible HTTP server — SIMD parser, XDP kernel-bypass, no restart ever.**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE) [![Commercial License](https://img.shields.io/badge/license-commercial-green.svg)](COMMERCIAL_LICENSE.md)
[![Release](https://img.shields.io/github/v/release/redlemonbe/RunNginx)](https://github.com/redlemonbe/RunNginx/releases/latest)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/redlemonbe?style=flat&logo=github&label=Sponsor)](https://github.com/sponsors/redlemonbe)

> ⚠️ **Status: Experimental** — RunNginx is under active development and has not yet undergone external human security audit. Not yet recommended for production deployments handling sensitive traffic.

Most existing `nginx.conf` files work as-is. Non-standard directives are ignored gracefully. RunNginx adds XDP kernel-bypass, SIMD HTTP parsing, and a browser dashboard on top of an nginx-compatible core.

---

## What you get

| | nginx | Caddy | RunNginx |
|---|:---:|:---:|:---:|
| nginx.conf compatible | ✅ | ❌ | ✅ |
| HTTP/1.1 + HTTP/2 | ✅ | ✅ | ✅ |
| TLS / ACME (Let's Encrypt) | ⚠️ certbot | ✅ built-in | ✅ built-in |
| FastCGI / PHP-FPM | ✅ | ⚠️ | ✅ |
| Reverse proxy + load balancing | ✅ | ✅ | ✅ |
| Live config reload (no restart) | ✅ SIGHUP | ✅ | ✅ SIGHUP |
| Built-in admin dashboard | ❌ | ✅ | ✅ |
| Multi-user mode (cPanel-style) | ❌ | ❌ | ✅ |
| SIMD HTTP parser (AVX2/SSE2) | ❌ | ❌ | ✅ |
| AF/XDP kernel-bypass | ❌ | ❌ | ✅ |
| io_uring zero-copy file serving | ❌ | ❌ | ✅ |
| Built-in SSH/SFTP engine (planned) | ❌ | ❌ | ✅ |
| Static binary, no dependencies | ❌ | ✅ | ✅ musl |

---

## Install

### One-line install

```bash
curl -fsSL https://raw.githubusercontent.com/redlemonbe/RunNginx/main/install.sh | sudo bash
```

The script installs the binary to `/usr/local/bin/runnginx`, writes a default config to `/etc/runnginx/nginx.conf`, and starts the systemd service.

At the end you'll see:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Version:  runnginx v0.1.8
 API key:  a1b2c3d4...   ← save this
 Config:   /etc/runnginx/nginx.conf
 Web UI:   http://YOUR_SERVER/ui
 Logs:     journalctl -u runnginx -f
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### Manual install

```bash
# x86_64 glibc (recommended for servers)
curl -Lo runnginx https://github.com/redlemonbe/RunNginx/releases/latest/download/runnginx-x86_64-linux-gnu
chmod +x runnginx && sudo mv runnginx /usr/local/bin/

# x86_64 static (musl — no glibc required)
curl -Lo runnginx https://github.com/redlemonbe/RunNginx/releases/latest/download/runnginx-x86_64-linux-musl
chmod +x runnginx && sudo mv runnginx /usr/local/bin/

# aarch64 (Graviton, Raspberry Pi 4/5)
curl -Lo runnginx https://github.com/redlemonbe/RunNginx/releases/latest/download/runnginx-aarch64-linux-gnu
chmod +x runnginx && sudo mv runnginx /usr/local/bin/
```

---

## Dashboard (Web UI)

RunNginx embeds the dashboard — no nginx needed. Open `http://YOUR_SERVER/ui`.

Enter your API key (from `/etc/runnginx/nginx.conf`) and click **Sign in**.

Features:
- **Dashboard** — request rate, active connections, bandwidth, virtual host list
- **Virtual Hosts** — create, edit, delete server blocks live
- **Users** — per-user API keys, bandwidth quotas, isolated vhosts
- **SSH & Access** — per-user SSH key management, SFTP chroot config
- **Live Metrics** — real-time stats and Prometheus endpoint
- **Logs** — live access log tail with filter

---

## Minimal config

```nginx
# /etc/runnginx/nginx.conf
http {
    api_key your-secret-key;

    server {
        listen 0.0.0.0:80;
        server_name example.com;

        location / {
            root /var/www/html;
        }
    }
}
```

Full reference: [docs/configuration.md](docs/configuration.md)

---


## Firewall management

RunNginx can open and close its own firewall rules automatically. Supported backends: ufw, nftables, iptables. The backend is auto-detected.

```nginx
# /etc/runnginx/nginx.conf
http {
    firewall_manage  on;          # default: on
    firewall_backend auto;        # auto | ufw | nftables | iptables
    firewall_tag     runnginx;    # tag for created rules (default: runnginx)

    server {
        listen 0.0.0.0:80;
        # ...
    }
}
```

On startup RunNginx opens the configured listen ports. On SIGINT/SIGTERM it closes them. Rules are tagged (`# runnginx`) so they can be audited and removed independently.

Set `firewall_manage off` to manage firewall rules manually.

---

## Performance

| Hardware | Mode | Throughput |
|----------|------|------------|
| Any CPU | SIMD HTTP parser (AVX2) | 2–4× vs scalar parser |
| Linux ≥ 5.14 | io_uring zero-copy | ~30% lower CPU at high file RPS |
| Intel/Mellanox NIC | AF/XDP kernel-bypass | Near line-rate at driver level |

SIMD dispatch is auto-detected at startup (AVX2 → SSE2 → scalar).

---

## Documentation

Full index: [docs/index.md](docs/index.md)

Quick links: [Quick Start](docs/quick-start.md) · [API Reference](docs/api.md) · [Configuration](docs/configuration.md) · [Web UI](docs/web-ui.md)

---

## Contributing

```bash
cargo clippy --all-targets   # zero warnings
cargo test                   # all tests must pass
```

Pull requests welcome.

---

## Support the project

[![GitHub Sponsors](https://img.shields.io/github/sponsors/redlemonbe?style=flat&logo=github&label=Sponsor%20on%20GitHub)](https://github.com/sponsors/redlemonbe)

**Bitcoin** — `3FP8hkkiu4kwCD1PDFgAv2oq1ZTyXwy3yy`  
**Ethereum** — `0xB5eEAf89edA4204Aa9305B068b37A93439cBb680`

Security issues: redlemonbe@codix.be (private disclosure before opening a public issue)

---

## License

AGPL-3.0-only — see [LICENSE](LICENSE). Commercial license available for organizations that need to deploy without AGPL obligations: [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md).

---

*Part of the [RunSoftware](https://github.com/redlemonbe) stack — [Runbound](https://github.com/redlemonbe/Runbound) · [RunAlexDB](https://github.com/redlemonbe/RunAlexDB) · [dnsmark](https://github.com/redlemonbe/dnsmark) · [httpmark](https://github.com/redlemonbe/httpmark)*  
Copyright (C) 2026 RedLemonBe


## Hot backup / restore

Snapshot and restore server configuration and user accounts without downtime.

| Endpoint | Description |
|----------|-------------|
| `POST /api/backup` | Snapshot `runnginx.conf` + `users.toml` to `config_dir/backups/backup_<ts>[_label]/` |
| `GET /api/backups` | List snapshots (id, timestamp, has_users) |
| `POST /api/restore` | Restore a snapshot by id — copies config+users back and triggers a live reload |
| `DELETE /api/backups/<id>` | Remove a snapshot |

Optional `label` field for named snapshots:
```bash
curl -X POST http://localhost:8090/api/backup \
  -H "Authorization: Bearer $KEY" \
  -d '{"label":"before-upgrade"}'
```

## Firewall auto-management