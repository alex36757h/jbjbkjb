import base64
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import time
import uuid
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

APP_NAME = "SpiderPanel"
PANEL_PORT = int(os.getenv("PANEL_PORT", "8000"))
PUBLIC_PORT = int(os.getenv("PORT", "8080"))
XRAY_PORT = int(os.getenv("XRAY_PORT", "10000"))
VLESS_PATH = "/vless"
SESSION_COOKIE = "spider_session"
SESSION_TTL = 7 * 24 * 60 * 60
DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
STATE_FILE = DATA_DIR / "state.json"

app = FastAPI(title=APP_NAME)


def load_state():
    if not STATE_FILE.exists():
        return {"password_hash": None, "salt": None, "uuid": str(uuid.uuid4())}
    try:
        state = json.loads(STATE_FILE.read_text("utf-8"))
        state.setdefault("password_hash", None)
        state.setdefault("salt", None)
        state.setdefault("uuid", str(uuid.uuid4()))
        return state
    except Exception:
        return {"password_hash": None, "salt": None, "uuid": str(uuid.uuid4())}


STATE = load_state()
STATE_FILE.write_text(json.dumps(STATE), encoding="utf-8")


def save_state():
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(STATE), encoding="utf-8")
    tmp.replace(STATE_FILE)


def hash_password(password: str, salt: bytes) -> str:
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32).hex()


def set_password(password: str):
    salt = secrets.token_bytes(16)
    STATE["salt"] = base64.urlsafe_b64encode(salt).decode()
    STATE["password_hash"] = hash_password(password, salt)
    save_state()


def verify_password(password: str) -> bool:
    try:
        salt = base64.urlsafe_b64decode(STATE["salt"].encode())
        candidate = hash_password(password, salt)
        return hmac.compare_digest(candidate, STATE["password_hash"])
    except Exception:
        return False


def session_value() -> str:
    issued = str(int(time.time()))
    sig = hmac.new((STATE.get("password_hash") or "").encode(), issued.encode(), hashlib.sha256).hexdigest()
    return f"{issued}.{sig}"


def valid_session(value: str | None) -> bool:
    if not value or not STATE.get("password_hash"):
        return False
    try:
        issued_s, sig = value.split(".", 1)
        issued = int(issued_s)
        now = time.time()
        if now - issued > SESSION_TTL or issued > now + 30:
            return False
        expected = hmac.new(STATE["password_hash"].encode(), issued_s.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, expected)
    except Exception:
        return False


def current_host(request: Request) -> str:
    raw = request.headers.get("x-forwarded-host") or request.headers.get("host") or "127.0.0.1"
    if raw.startswith("[") and "]" in raw:
        raw = raw.split("]", 1)[0] + "]"
    elif raw.count(":") == 1:
        raw = raw.rsplit(":", 1)[0]
    return raw


def xray_alive() -> bool:
    try:
        result = subprocess.run(
            ["/bin/sh", "-lc", f"nc -z 127.0.0.1 {XRAY_PORT}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
        )
        return result.returncode == 0
    except Exception:
        return False


def vless_uri(host: str) -> str:
    return (
        f"vless://{STATE['uuid']}@{host}:443"
        f"?encryption=none&security=tls&type=ws"
        f"&host={quote(host)}&sni={quote(host)}&path={quote(VLESS_PATH)}#SpiderPanel-VLESS"
    )


@app.get("/healthz")
async def healthz():
    alive = xray_alive()
    return JSONResponse({"ok": True, "panel": APP_NAME, "status": "online", "vless": "active" if alive else "down", "xray": alive, "path": VLESS_PATH})


@app.get("/api/status")
async def api_status(request: Request):
    alive = xray_alive()
    return JSONResponse({
        "ok": alive,
        "panel": APP_NAME,
        "status": "online",
        "vless": "active" if alive else "down",
        "transport": "WebSocket",
        "tls": "terminated by VibeNest ingress",
        "publicPort": 443,
        "path": VLESS_PATH,
        "server": current_host(request),
        "xray": alive,
    }, status_code=200 if alive else 503)


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    if not STATE.get("password_hash"):
        return HTMLResponse(SETUP_PAGE)
    if not valid_session(request.cookies.get(SESSION_COOKIE)):
        return HTMLResponse(LOGIN_PAGE)
    host = current_host(request)
    uri = vless_uri(host)
    alive = xray_alive()
    page = PANEL_PAGE.replace("__VLESS_URI__", uri).replace("__HOST__", host)
    page = page.replace("__STATUS__", "Active" if alive else "Down")
    page = page.replace("__STATUS_CLASS__", "online" if alive else "offline")
    return HTMLResponse(page)


@app.post("/setup")
async def setup(request: Request):
    if STATE.get("password_hash"):
        return JSONResponse({"ok": False, "error": "Password already configured"}, status_code=409)
    form = await request.form()
    password = str(form.get("password", ""))
    confirm = str(form.get("confirm", ""))
    if len(password) < 6:
        return JSONResponse({"ok": False, "error": "Password must be at least 6 characters."}, status_code=400)
    if password != confirm:
        return JSONResponse({"ok": False, "error": "Passwords do not match."}, status_code=400)
    set_password(password)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(SESSION_COOKIE, session_value(), httponly=True, secure=True, samesite="lax", max_age=SESSION_TTL)
    return response


@app.post("/login")
async def login(request: Request):
    form = await request.form()
    password = str(form.get("password", ""))
    if not verify_password(password):
        return HTMLResponse(LOGIN_PAGE.replace("__ERROR__", "Incorrect password."), status_code=401)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(SESSION_COOKIE, session_value(), httponly=True, secure=True, samesite="lax", max_age=SESSION_TTL)
    return response


@app.get("/logout")
async def logout():
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie(SESSION_COOKIE)
    return response


SETUP_PAGE = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SpiderPanel Setup</title><style>
body{margin:0;background:#080c12;color:#edf3fb;font-family:Arial,sans-serif;min-height:100vh;display:grid;place-items:center}.card{width:min(430px,calc(100% - 40px));background:#111925;border:1px solid #273449;border-radius:20px;padding:28px;box-sizing:border-box;box-shadow:0 22px 70px #0008}h1{margin:0 0 8px;font-size:30px}.muted{color:#95a4b8;margin:0 0 24px}label{display:block;margin:14px 0 7px;color:#b8c5d6}input{width:100%;box-sizing:border-box;padding:13px 14px;border-radius:11px;border:1px solid #344359;background:#0a1018;color:#fff;font-size:16px}button{width:100%;margin-top:20px;padding:13px;border:0;border-radius:11px;background:#dfe9f7;color:#0a1018;font-weight:700;font-size:16px;cursor:pointer}</style></head><body><div class="card"><h1>SpiderPanel</h1><p class="muted">Create a new panel password</p><form method="post" action="/setup"><label>New password</label><input name="password" type="password" minlength="6" required autofocus autocomplete="new-password"><label>Confirm password</label><input name="confirm" type="password" minlength="6" required autocomplete="new-password"><button type="submit">Create password</button></form></div></body></html>'''

LOGIN_PAGE = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SpiderPanel Login</title><style>
body{margin:0;background:#080c12;color:#edf3fb;font-family:Arial,sans-serif;min-height:100vh;display:grid;place-items:center}.card{width:min(430px,calc(100% - 40px));background:#111925;border:1px solid #273449;border-radius:20px;padding:28px;box-sizing:border-box;box-shadow:0 22px 70px #0008}h1{margin:0 0 8px;font-size:30px}.muted{color:#95a4b8;margin:0 0 24px}input{width:100%;box-sizing:border-box;padding:13px 14px;border-radius:11px;border:1px solid #344359;background:#0a1018;color:#fff;font-size:16px}button{width:100%;margin-top:20px;padding:13px;border:0;border-radius:11px;background:#dfe9f7;color:#0a1018;font-weight:700;font-size:16px;cursor:pointer}.err{color:#ff7f7f;margin-top:12px}</style></head><body><div class="card"><h1>SpiderPanel</h1><p class="muted">Enter your panel password</p><form method="post" action="/login"><input name="password" type="password" required autofocus autocomplete="current-password"><button type="submit">Open panel</button></form><div class="err">__ERROR__</div></div></body></html>'''

PANEL_PAGE = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SpiderPanel · VLESS</title><style>
body{margin:0;background:#080c12;color:#edf3fb;font-family:Arial,sans-serif;min-height:100vh}main{max-width:760px;margin:45px auto;padding:20px}.card{background:#111925;border:1px solid #273449;border-radius:20px;padding:24px;box-shadow:0 22px 70px #0005}h1{margin:0;font-size:32px}.muted{color:#95a4b8}.online,.offline{display:inline-flex;gap:8px;align-items:center;font-weight:700}.online{color:#57d98a}.offline{color:#ff7575}.dot{width:10px;height:10px;border-radius:50%;background:currentColor;box-shadow:0 0 14px currentColor}.server{margin-top:20px;padding:18px;border-radius:15px;background:#0b111a;border:1px solid #273449}.label{color:#8191a7;font-size:13px;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px}.value{word-break:break-all}textarea{width:100%;box-sizing:border-box;background:#070b10;color:#dce7f4;border:1px solid #29374a;border-radius:11px;padding:13px;min-height:115px;resize:vertical;font:14px/1.5 monospace}.row{display:flex;gap:10px;flex-wrap:wrap;margin-top:16px}button,a{background:#1d2a3b;border:1px solid #33435a;color:#fff;border-radius:10px;padding:10px 14px;text-decoration:none;cursor:pointer}.primary{background:#dfe9f7;color:#08101a;border-color:#dfe9f7;font-weight:700}.meta{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-top:15px}.box{background:#0d141e;border-radius:12px;padding:13px}.box b{display:block;margin-top:4px}@media(max-width:650px){main{margin:20px auto}.meta{grid-template-columns:repeat(2,1fr)}}
</style></head><body><main><div class="card"><div style="display:flex;justify-content:space-between;gap:12px;align-items:center"><div><h1>SpiderPanel</h1><p class="muted">VLESS server panel</p></div><a href="/logout">Logout</a></div><p class="__STATUS_CLASS__"><span class="dot"></span> VLESS server __STATUS__</p><div class="server"><div class="label">Server</div><div class="value">__HOST__</div><div class="meta"><div class="box"><span class="label">Protocol</span><b>VLESS</b></div><div class="box"><span class="label">Transport</span><b>WS + TLS</b></div><div class="box"><span class="label">Port</span><b>443</b></div><div class="box"><span class="label">Path</span><b>/vless</b></div></div></div><div style="margin-top:18px"><div class="label">VLESS link</div><textarea id="uri" readonly>__VLESS_URI__</textarea></div><div class="row"><button class="primary" onclick="copyLink()">Copy VLESS link</button><button onclick="testVless()">Real VLESS test</button><button onclick="refreshStatus()">Refresh status</button></div><div id="test" class="muted" style="font-size:13px;margin-top:16px">The Real VLESS test opens WebSocket /vless and sends an actual VLESS handshake through the public route.</div></div></main><script>
function copyLink(){navigator.clipboard.writeText(document.getElementById('uri').value).then(()=>alert('Copied'))}
function hexBytes(s){return new Uint8Array((s.match(/.{2}/g)||[]).map(x=>parseInt(x,16)))}
function uuidBytes(u){return hexBytes(u.replaceAll('-',''))}
async function testVless(){const out=document.getElementById('test');out.textContent='Testing public WebSocket + Xray VLESS...';const uri=document.getElementById('uri').value;const m=uri.match(/^vless:\/\/([^@]+)@([^:]+):/);if(!m){out.textContent='Invalid VLESS link';return}const host=location.host;const ws=new WebSocket((location.protocol==='https:'?'wss://':'ws://')+host+'/vless');ws.binaryType='arraybuffer';let ok=false;const timer=setTimeout(()=>{if(!ok){out.textContent='✕ Timeout: no VLESS response from Xray.';try{ws.close()}catch(e){}}},10000);ws.onopen=()=>{const id=uuidBytes(m[1]);const domain=new TextEncoder().encode('example.com');const b=new Uint8Array(18+1+2+1+1+domain.length);let p=0;b[p++]=1;b.set(id,p);p+=16;b[p++]=0;b[p++]=1;b[p++]=0;b[p++]=80;b[p++]=2;b[p++]=domain.length;b.set(domain,p);ws.send(b)};ws.onmessage=e=>{const a=new Uint8Array(e.data);if(a.length>=2&&a[0]===1&&a[1]===0){ok=true;clearTimeout(timer);out.textContent='✓ Real VLESS handshake succeeded through /vless → Xray.';try{ws.close()}catch(e){}}};ws.onerror=()=>{clearTimeout(timer);if(!ok)out.textContent='✕ Public WebSocket connection failed.'};ws.onclose=()=>{clearTimeout(timer);if(!ok&& !out.textContent.startsWith('✕'))out.textContent='✕ Connection closed before VLESS response.'}}
async function refreshStatus(){const out=document.getElementById('test');try{const r=await fetch('/api/status',{cache:'no-store'});const d=await r.json();out.textContent=d.xray?'✓ Xray is listening and public panel route is online.':'✕ Xray process is not listening.'}catch(e){out.textContent='✕ Status request failed.'}}
</script></body></html>'''
