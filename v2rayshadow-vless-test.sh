#!/usr/bin/env bash
set -euo pipefail

# V2rayShadowbot - one-node VLESS/WS test server for container hosts.
# Requirements: Linux container, bash, curl, unzip, Node.js 18+.
# The public platform terminates HTTPS; Xray itself listens internally without TLS.

XRAY_VERSION="${XRAY_VERSION:-26.9.9}"
XRAY_DIR="${XRAY_DIR:-$PWD/.xray-test}"
XRAY_PORT="${XRAY_PORT:-10085}"
PUBLIC_PORT="${PORT:-3000}"
VLESS_PATH="${VLESS_PATH:-/vless}"
UUID_FILE="$XRAY_DIR/uuid"
CONFIG_FILE="$XRAY_DIR/config.json"
XRAY_BIN="$XRAY_DIR/xray"

mkdir -p "$XRAY_DIR"

case "$(uname -m)" in
  x86_64|amd64) XRAY_MACHINE="64" ;;
  aarch64|arm64) XRAY_MACHINE="arm64-v8a" ;;
  armv7l|armv7) XRAY_MACHINE="arm32-v7a" ;;
  *) echo "Unsupported CPU: $(uname -m)" >&2; exit 1 ;;
esac

if [[ ! -x "$XRAY_BIN" ]]; then
  ZIP="$XRAY_DIR/xray.zip"
  URL="https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-${XRAY_MACHINE}.zip"
  echo "Downloading Xray ${XRAY_VERSION} (${XRAY_MACHINE})..."
  curl -fL --retry 3 --connect-timeout 15 -o "$ZIP" "$URL"
  rm -rf "$XRAY_DIR/extract"
  mkdir -p "$XRAY_DIR/extract"
  unzip -oq "$ZIP" -d "$XRAY_DIR/extract"
  cp "$XRAY_DIR/extract/xray" "$XRAY_BIN"
  chmod +x "$XRAY_BIN"
  rm -rf "$XRAY_DIR/extract" "$ZIP"
fi

if [[ ! -s "$UUID_FILE" ]]; then
  "$XRAY_BIN" uuid > "$UUID_FILE"
fi
UUID="$(tr -d '\r\n' < "$UUID_FILE")"

cat > "$CONFIG_FILE" <<JSON
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": ${XRAY_PORT},
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${UUID}",
            "email": "v2rayshadow-test"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "path": "${VLESS_PATH}",
          "headers": {
            "Host": "localhost"
          }
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    }
  ]
}
JSON

"$XRAY_BIN" run -test -config "$CONFIG_FILE" >/dev/null

export XRAY_PORT PUBLIC_PORT VLESS_PATH UUID CONFIG_FILE XRAY_BIN

cat > "$XRAY_DIR/proxy.js" <<'NODE'
const http = require('http');
const net = require('net');
const { spawn } = require('child_process');
const fs = require('fs');

const XRAY_PORT = Number(process.env.XRAY_PORT || 10085);
const PUBLIC_PORT = Number(process.env.PUBLIC_PORT || 3000);
const VLESS_PATH = process.env.VLESS_PATH || '/vless';
const UUID = fs.readFileSync(process.env.UUID_FILE || process.env.UUID_PATH || './.xray-test/uuid', 'utf8').trim();
const XRAY_BIN = process.env.XRAY_BIN;
const CONFIG_FILE = process.env.CONFIG_FILE;

const xray = spawn(XRAY_BIN, ['run', '-config', CONFIG_FILE], { stdio: ['ignore', 'inherit', 'inherit'] });
xray.on('exit', (code, signal) => {
  console.error(`Xray stopped: code=${code} signal=${signal || ''}`);
  process.exit(code === 0 ? 1 : code || 1);
});

function publicHost(req) {
  const forwarded = String(req.headers['x-forwarded-host'] || '').split(',')[0].trim();
  return forwarded || String(req.headers.host || 'localhost');
}

function page(req) {
  const host = publicHost(req);
  const url = `vless://${UUID}@${host}:443?encryption=none&security=tls&type=ws&host=${encodeURIComponent(host.split(':')[0])}&path=${encodeURIComponent(VLESS_PATH)}&sni=${encodeURIComponent(host.split(':')[0])}#V2rayShadow-Test`;
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>V2rayShadowbot VLESS Test</title><style>body{font-family:system-ui;background:#0b0d10;color:#eee;max-width:900px;margin:40px auto;padding:20px}pre{white-space:pre-wrap;word-break:break-all;background:#151922;padding:16px;border-radius:12px}h1{font-size:24px}code{color:#8be9fd}.ok{color:#7ee787}</style></head><body><h1>V2rayShadowbot VLESS Test</h1><p class="ok">✓ Xray is running</p><p>WebSocket path: <code>${VLESS_PATH}</code></p><p>Copy this VLESS URI into V2RayNG/V2RayN/Hiddify:</p><pre>${url}</pre></body></html>`;
}

const server = http.createServer((req, res) => {
  if (req.url === '/healthz' || req.url === '/') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
    res.end(page(req));
    return;
  }
  res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
  res.end('Not found');
});

server.on('upgrade', (req, client, head) => {
  if (req.url !== VLESS_PATH) {
    client.write('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n');
    client.destroy();
    return;
  }

  const upstream = net.connect(XRAY_PORT, '127.0.0.1', () => {
    const lines = [`${req.method} ${req.url} HTTP/${req.httpVersion}`];
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      lines.push(`${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}`);
    }
    lines.push('', '');
    upstream.write(lines.join('\r\n'));
    if (head && head.length) upstream.write(head);
    client.pipe(upstream).pipe(client);
  });

  upstream.on('error', () => client.destroy());
  client.on('error', () => upstream.destroy());
});

server.listen(PUBLIC_PORT, '0.0.0.0', () => {
  console.log(`V2rayShadow VLESS test server listening on 0.0.0.0:${PUBLIC_PORT}`);
  console.log(`VLESS path: ${VLESS_PATH}`);
  console.log(`Internal Xray port: ${XRAY_PORT}`);
});
NODE

# Give the embedded Node helper access to the UUID path explicitly.
export UUID_PATH="$UUID_FILE"
node "$XRAY_DIR/proxy.js"
