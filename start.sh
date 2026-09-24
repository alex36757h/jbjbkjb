#!/bin/sh
set -eu

mkdir -p /data /etc/xray

# Keep the Xray UUID and the panel UUID in the same persistent state file.
# This prevents a mismatch when the container is restarted/redeployed.
if [ -f /data/state.json ]; then
  VLESS_UUID="$(python - <<'PY2'
import json
from pathlib import Path
p=Path("/data/state.json")
try:
    s=json.loads(p.read_text())
    u=s.get("uuid")
    if u:
        print(u)
except Exception:
    pass
PY2
)"
fi
if [ -z "${VLESS_UUID:-}" ]; then
  VLESS_UUID="$(python -c 'import uuid; print(uuid.uuid4())')"
  python - <<PY2
import json
from pathlib import Path
p=Path("/data/state.json")
state={"password_hash":None,"salt":None,"uuid":"${VLESS_UUID}"}
p.write_text(json.dumps(state))
PY2
fi
export VLESS_UUID

cat > /etc/xray/config.json <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": ${XRAY_PORT:-10000},
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${VLESS_UUID}"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/vless"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": ["geoip:private"],
        "outboundTag": "blocked"
      }
    ]
  }
}
EOF

python -m uvicorn main:app --host 127.0.0.1 --port 8000 >/tmp/panel.log 2>&1 &
PANEL_PID=$!

/usr/local/bin/xray run -c /etc/xray/config.json >/tmp/xray.log 2>&1 &
XRAY_PID=$!

cleanup() {
  kill "$PANEL_PID" "$XRAY_PID" 2>/dev/null || true
}
trap cleanup INT TERM EXIT

sleep 1
exec caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
