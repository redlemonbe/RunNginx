#!/usr/bin/env bash
# RunNginx install script — installs binary, config, systemd unit.
# Usage: curl -fsSL https://raw.githubusercontent.com/redlemonbe/RunNginx/main/install.sh | bash
# Or:    bash install.sh [--prefix /usr/local] [--config /etc/runnginx]

set -euo pipefail

BLUE='\033[0;34m'; GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${BLUE}[RunNginx]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

PREFIX="${PREFIX:-/usr/local}"
CONFIG_DIR="${CONFIG_DIR:-/etc/runnginx}"
LOG_DIR="${LOG_DIR:-/var/log/runnginx}"
DATA_DIR="${DATA_DIR:-/var/lib/runnginx}"
SERVICE_USER="${SERVICE_USER:-www-data}"
VERSION="${VERSION:-latest}"

REPO="https://github.com/redlemonbe/RunNginx"
ARCH=$(uname -m)
OS=$(uname -s | tr '[:upper:]' '[:lower:]')

[[ "$OS" != "linux" ]] && err "Only Linux is supported."
[[ $(id -u) -ne 0 ]] && err "Must be run as root."

# Detect architecture and libc
case "$ARCH" in
    x86_64)  ARCH_ID="x86_64"  ;;
    aarch64) ARCH_ID="aarch64" ;;
    arm64)   ARCH_ID="aarch64" ;;
    *)       err "Unsupported architecture: $ARCH" ;;
esac

# Detect libc (musl vs glibc)
if ldd --version 2>&1 | grep -qi musl; then
    LIBC="musl"
elif command -v ldd >/dev/null && ldd --version 2>&1 | grep -qi GLIBC; then
    LIBC="gnu"
else
    LIBC="gnu"  # default
fi

info "Installing RunNginx $VERSION ($ARCH_ID-$LIBC)"

# Download binary
if [[ "$VERSION" == "latest" ]]; then
    BINARY_URL="$REPO/releases/latest/download/runnginx-${ARCH_ID}-linux-${LIBC}"
else
    BINARY_URL="$REPO/releases/download/$VERSION/runnginx-${ARCH_ID}-linux-${LIBC}"
fi

info "Downloading from $BINARY_URL"
TMP=$(mktemp)
if command -v curl >/dev/null; then
    curl -fsSL --progress-bar -o "$TMP" "$BINARY_URL"
elif command -v wget >/dev/null; then
    wget -q --show-progress -O "$TMP" "$BINARY_URL"
else
    err "curl or wget required"
fi

chmod +x "$TMP"
install -Dm755 "$TMP" "$PREFIX/bin/runnginx"
rm -f "$TMP"
ok "Binary installed to $PREFIX/bin/runnginx"

# Create directories
mkdir -p "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR"
chown -R "$SERVICE_USER:$SERVICE_USER" "$LOG_DIR" "$DATA_DIR" 2>/dev/null || true

# Write default config if not present
if [[ ! -f "$CONFIG_DIR/nginx.conf" ]]; then
    API_KEY=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
    cat > "$CONFIG_DIR/nginx.conf" << CONF
# RunNginx configuration
# Documentation: https://github.com/redlemonbe/RunNginx/wiki

http {
    # API key for the management API and Web UI.
    # Visit http://YOUR_SERVER/ui to access the dashboard.
    api_key $API_KEY;

    access_log /var/log/runnginx/access.log combined;

    gzip on;
    client_max_body_size 100m;

    server {
        listen 0.0.0.0:80;
        server_name _;

        location / {
            root /var/www/html;
            index index.html index.htm;
        }
    }
}
CONF
    ok "Default config written to $CONFIG_DIR/nginx.conf"
    info "Your API key: $API_KEY"
    info "Keep it safe — it's in $CONFIG_DIR/nginx.conf"
else
    info "Config already exists at $CONFIG_DIR/nginx.conf — skipping."
fi

# Write default web root index
if [[ ! -f /var/www/html/index.html ]]; then
    mkdir -p /var/www/html
    cat > /var/www/html/index.html << 'HTML'
<!DOCTYPE html>
<html><head><title>RunNginx</title></head>
<body><h1>RunNginx is running!</h1>
<p><a href="/ui">Management UI</a></p>
</body></html>
HTML
fi

# Write systemd unit
cat > /etc/systemd/system/runnginx.service << UNIT
[Unit]
Description=RunNginx — High-performance HTTP server
Documentation=https://github.com/redlemonbe/RunNginx
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
ExecStart=$PREFIX/bin/runnginx -c $CONFIG_DIR/nginx.conf
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
LimitNPROC=65536
LimitMEMLOCK=infinity
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=$LOG_DIR $DATA_DIR $CONFIG_DIR
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable runnginx
ok "systemd unit installed and enabled"

# Try to start
if systemctl start runnginx; then
    ok "RunNginx started successfully"
    echo
    echo -e "${GREEN}Installation complete!${NC}"
    echo -e "  Status:  systemctl status runnginx"
    echo -e "  Logs:    journalctl -u runnginx -f"
    echo -e "  Web UI:  http://YOUR_SERVER/ui"
    echo -e "  Config:  $CONFIG_DIR/nginx.conf"
else
    warn "Service failed to start. Check: journalctl -u runnginx"
    echo -e "  Config test: runnginx -c $CONFIG_DIR/nginx.conf -t"
fi
