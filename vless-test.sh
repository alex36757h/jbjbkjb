#!/bin/bash
set -euo pipefail
PORT="${PORT:-8080}"
UUID="${UUID:-$(cat /proc/sys/kernel/random/uuid)}"
XRAY_VERSION="${XRAY_VERSION:-v26.2.6}"
XRAY_DIR="/opt/xray"
mkdir -p "$XRAY_DIR"
ARCH="$(uname -m)"
case "$ARCH" in x86_64|amd64) XRAY_ARCH="64" ;; aarch64|arm64) XRAY_ARCH="arm64-v8a" ;; *) echo "Unsupported CPU architecture: $ARCH"; exit 1 ;; esac
ZIP="/tmp/xray.zip"
URL="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-${XRAY_ARCH}.zip"
echo "Downloading Xray: $URL"
curl -fL --retry 3 "$URL" -o "$ZIP"
unzip -o "$ZIP" -d "$XRAY_DIR" >/dev/null
chmod +x "$XRAY_DIR/xray"
cat > "$XRAY_DIR/config.json" <<EOF2
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "listen": "0.0.0.0",
    "port": ${PORT},
    "protocol": "vless",
    "settings": {"clients": [{"id": "${UUID}", "email": "vibenest-test"}], "decryption": "none"},
    "streamSettings": {"network": "ws", "wsSettings": {"path": "/vless"}}
  }],
  "outbounds": [{"protocol": "freedom", "tag": "direct"}]
}
EOF2
echo "V2rayShadow VLESS test server"
echo "Port: $PORT"
echo "UUID: $UUID"
echo "WebSocket path: /vless"
exec "$XRAY_DIR/xray" run -config "$XRAY_DIR/config.json"
