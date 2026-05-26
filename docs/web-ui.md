# Web Management Console

RunNginx embeds a single-file HTML/JS dashboard served at `/ui` — no nginx,
no external CDN, no build step. The UI is compiled into the binary at build time.

---

## Enable

The UI is always available at `/ui`. Set an `api_key` in your config to enable auth:

```nginx
http {
    api_key  <64-char-hex-key>;
    ...
}
```

Access: `http://<host>/ui` (or `https://<host>/ui` if TLS is configured).

---

## Login

The dashboard opens a login screen on first visit. Enter your `api_key`.

- **Remember** checkbox: stores the key in `localStorage` (browser only, never sent to a third party)
- **Sign out**: clears the stored key

---

## Dashboard

Real-time stats updated every 2 seconds:

| Card | Description |
|------|-------------|
| Total Requests | Cumulative request count |
| Active Connections | Current open connections |
| Data Transferred | Cumulative bytes sent |
| p99 Latency | 99th percentile response time |
| 2xx / 4xx / 5xx | Status code counters with progress bars |
| Uptime | Server uptime |

**Sparkline chart** — req/s for the last 60 seconds (canvas, no dependencies).  
**Status distribution** — 2xx/3xx/4xx/5xx as percentage progress bars.

---

## Virtual Hosts

Shows upstream groups from the loaded config. Raw JSON from `/api/system` is displayed for full detail.

---

## Users

Manage hosting accounts (requires `users.toml` — see [Multi-user mode](#multi-user-mode)).

- **List** all users with their domains, quota, status and role
- **Create** new user — generates an API key (shown once)
- **Delete** user

---

## SSH & Access

Per-user SSH public key management:

1. Select a user from the dropdown
2. Add an `ssh-ed25519` or `ssh-rsa` public key with a label
3. Keys are stored in the browser's `localStorage` per user ID
4. Copy the generated `authorized_keys` block and deploy to the user's `~/.ssh/`

**SFTP**: users are chrooted to `/home/<username>`. Configure `sshd_config`:

```
Match Group sftp-users
    ChrootDirectory /home/%u
    ForceCommand internal-sftp
    AllowTcpForwarding no
```

---

## Upstreams

Lists all upstream groups: name, policy (round-robin / least-conn / ip-hash), peer addresses, health check interval.

---

## Access Logs

Live tail of the last 500 access log lines, polled every 3 seconds.

- **Filter** input: substring match across all lines
- **Follow** toggle: auto-scrolls to new entries
- Color coding: green (2xx), blue (3xx), yellow (4xx), red (5xx)

---

## Settings

- **System info**: version, uptime, config path, server blocks, SIMD level
- **API key**: display (masked), copy to clipboard, update (stored locally)
- **Reload Config**: calls `POST /api/reload` (zero-downtime)

---

## Multi-user mode

Create `/etc/runnginx/users.toml`:

```toml
[[users]]
id        = "auto-generated"
username  = "alice"
api_key   = "auto-generated-64-hex"
domains   = ["alice.example.com"]
home_dir  = "/home/alice"
quota_bw  = 0
quota_conn = 0
enabled   = true
admin     = false
```

Or use the Web UI (Users tab → Add User) — the file is created/updated automatically.
