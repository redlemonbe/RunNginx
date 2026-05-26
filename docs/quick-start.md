# Quick Start

Up and running in 3 minutes.

---

## 1. Download

```bash
# x86_64 (glibc — most Linux servers)
curl -Lo runnginx https://github.com/redlemonbe/RunNginx/releases/latest/download/runnginx-x86_64-linux-gnu
chmod +x runnginx && sudo mv runnginx /usr/local/bin/
```

---

## 2. Minimal configuration

```bash
sudo mkdir -p /etc/runnginx /var/log/runnginx /var/www/html
sudo tee /etc/runnginx/nginx.conf << 'EOF'
worker_processes auto;
worker_connections 1024;

http {
    api_key  change-me-to-a-random-64-char-hex;
    access_log /var/log/runnginx/access.log;

    server {
        listen 80;
        server_name _;
        root /var/www/html;
        index index.html;
    }
}
EOF
```

---

## 3. Start

```bash
runnginx -c /etc/runnginx/nginx.conf
```

Or with systemd (see [install.sh](https://github.com/redlemonbe/RunNginx/releases/latest/download/install.sh)):

```bash
sudo systemctl start runnginx
sudo systemctl enable runnginx
```

---

## 4. Test

```bash
curl http://127.0.0.1/
curl http://127.0.0.1/health        # built-in health check (no auth)
curl http://127.0.0.1/metrics       # Prometheus metrics (no auth)
```

---

## 5. Open the Web UI

Add to your `http {}` block:

```
api_key  <64-char-hex-key>;
```

The management dashboard is available at `http://<host>/ui` — enter your API key to log in.

---

## 6. Reverse proxy example

```nginx
server {
    listen 80;
    server_name app.example.com;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## 7. HTTPS with auto-generated certificate

```nginx
server {
    listen 443 ssl;
    server_name app.example.com;

    ssl_certificate     /etc/runnginx/tls/cert.pem;
    ssl_certificate_key /etc/runnginx/tls/key.pem;

    # RunNginx generates a self-signed cert automatically on first start
    # if the files don't exist.
}
```

---

## Next steps

- [Configuration reference](configuration.md)
- [API reference](api.md)
- [Web UI guide](web-ui.md)
