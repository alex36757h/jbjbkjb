import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

APP_NAME = "SpiderPanel"
PORT = int(os.environ.get("PORT", "8080"))
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
STATE_FILE = DATA_DIR / "state.json"
VLESS_PATH = "/vless"
SESSION_COOKIE = "spider_session"
SESSION_TTL = 7 * 24 * 60 * 60

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


def save_state(state):
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state), encoding="utf-8")
    tmp.replace(STATE_FILE)


STATE = load_state()
save_state(STATE)


def hash_password(password: str, salt: bytes) -> str:
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=32,
    ).hex()


def set_password(password: str):
    salt = secrets.token_bytes(16)
    STATE["salt"] = base64.urlsafe_b64encode(salt).decode()
    STATE["password_hash"] = hash_password(password, salt)
    save_state(STATE)


def verify_password(password: str) -> bool:
    try:
        salt = base64.urlsafe_b64decode(STATE["salt"].encode())
        candidate = hash_password(password, salt)
        return hmac.compare_digest(candidate, STATE["password_hash"])
    except Exception:
        return False


def session_value() -> str:
    issued = str(int(time.time()))
    secret = (STATE.get("password_hash") or "").encode()
    sig = hmac.new(secret, issued.encode(), hashlib.sha256).hexdigest()
    return issued + "." + sig


def valid_session(value: str | None) -> bool:
    if not value or not STATE.get("password_hash"):
        return False
    try:
        issued_s, sig = value.split(".", 1)
        issued = int(issued_s)
        if time.time() - issued > SESSION_TTL or issued > time.time() + 30:
            return False
        secret = STATE["password_hash"].encode()
        expected = hmac.new(secret, issued_s.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, expected)
    except Exception:
        return False


def current_host(request: Request | None = None, websocket: WebSocket | None = None) -> str:
    raw = ""
    headers = request.headers if request is not None else (websocket.headers if websocket is not None else {})
    # Coolify/VibeNest normally preserves Host, but forwarded host is a useful fallback.
    raw = headers.get("x-forwarded-host", "") or headers.get("host", "")
    if not raw:
        return "127.0.0.1"
    if raw.startswith("[") and "]" in raw:
        return raw.split("]", 1)[0] + "]"
    return raw.rsplit(":", 1)[0] if raw.count(":") == 1 else raw


def vless_uri(host: str) -> str:
    client_uuid = STATE["uuid"]
    return (
        f"vless://{client_uuid}@{host}:443"
        f"?encryption=none&security=tls&type=ws"
        f"&host={host}&sni={host}&path=%2Fvless#SpiderPanel-VLESS"
    )


async def send_page(websocket: WebSocket, status_code: int = 1000, reason: str = ""):
    try:
        await websocket.close(code=status_code, reason=reason)
    except Exception:
        pass


def parse_vless_request(data: bytes):
    if len(data) < 24:
        raise ValueError("VLESS header too short")
    version = data[0]
    client_uuid = str(uuid.UUID(bytes=data[1:17]))
    addons_len = data[17]
    pos = 18 + addons_len
    if pos + 4 > len(data):
        raise ValueError("Invalid VLESS header")

    command = data[pos]
    pos += 1
    port = int.from_bytes(data[pos:pos + 2], "big")
    pos += 2
    addr_type = data[pos]
    pos += 1

    if addr_type == 1:  # IPv4
        if pos + 4 > len(data):
            raise ValueError("Invalid IPv4 address")
        host = ".".join(str(x) for x in data[pos:pos + 4])
        pos += 4
    elif addr_type == 2:  # Domain
        if pos >= len(data):
            raise ValueError("Missing domain length")
        length = data[pos]
        pos += 1
        if pos + length > len(data):
            raise ValueError("Invalid domain")
        host = data[pos:pos + length].decode("idna")
        pos += length
    elif addr_type == 3:  # IPv6
        if pos + 16 > len(data):
            raise ValueError("Invalid IPv6 address")
        import ipaddress
        host = str(ipaddress.IPv6Address(data[pos:pos + 16]))
        pos += 16
    else:
        raise ValueError("Unsupported address type")

    return {
        "version": version,
        "uuid": client_uuid,
        "command": command,
        "port": port,
        "host": host,
        "payload": data[pos:],
    }


async def relay_websocket_to_tcp(websocket: WebSocket, writer: asyncio.StreamWriter):
    while True:
        message = await websocket.receive()
        msg_type = message.get("type")
        if msg_type == "websocket.disconnect":
            return
        if msg_type != "websocket.receive":
            continue
        chunk = message.get("bytes")
        if chunk is None:
            # We don't accept text frames for VLESS data.
            continue
        if chunk:
            writer.write(chunk)
            await writer.drain()


async def relay_tcp_to_websocket(reader: asyncio.StreamReader, websocket: WebSocket):
    while True:
        chunk = await reader.read(64 * 1024)
        if not chunk:
            return
        await websocket.send_bytes(chunk)


@app.get("/healthz")
async def healthz():
    return JSONResponse({"ok": True, "panel": APP_NAME, "status": "online", "vless": "online", "path": VLESS_PATH})


@app.get("/api/status")
async def api_status(request: Request):
    return JSONResponse({
        "ok": True,
        "panel": APP_NAME,
        "status": "online",
        "vless": "online",
        "transport": "WebSocket",
        "tls": "terminated by VibeNest ingress",
        "path": VLESS_PATH,
        "server": current_host(request),
    })


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    configured = bool(STATE.get("password_hash"))
    authed = valid_session(request.cookies.get(SESSION_COOKIE))
    if not configured:
        return HTMLResponse(SETUP_PAGE)
    if not authed:
        return HTMLResponse(LOGIN_PAGE)

    host = current_host(request)
    uri = vless_uri(host)
    escaped_uri = uri.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    page = PANEL_PAGE.replace("__VLESS_URI__", escaped_uri).replace("__HOST__", host)
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


@app.websocket(VLESS_PATH)
async def vless_ws(websocket: WebSocket):
    # TLS is terminated by the VibeNest/Coolify HTTPS proxy. The container
    # therefore receives plain WebSocket traffic on PORT (normally 8080).
    await websocket.accept()
    writer = None
    try:
        # Do not assume the complete VLESS header arrives in one WebSocket
        # frame. Some clients/proxies can fragment it. Buffer until the
        # header is parseable, while keeping the buffer bounded.
        buffer = bytearray()
        request = None
        while request is None:
            message = await websocket.receive()
            if message.get("type") == "websocket.disconnect":
                return
            chunk = message.get("bytes")
            if not chunk:
                continue
            buffer.extend(chunk)
            if len(buffer) > 64 * 1024:
                await send_page(websocket, 1009, "VLESS header too large")
                return
            try:
                request = parse_vless_request(bytes(buffer))
            except ValueError:
                # Header may simply be incomplete. Keep receiving frames.
                continue

        if request["uuid"] != STATE["uuid"]:
            await send_page(websocket, 1008, "Unauthorized")
            return
        if request["command"] != 1:
            await send_page(websocket, 1003, "TCP only")
            return

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(request["host"], request["port"]),
            timeout=15,
        )

        # VLESS response header: version 1 + zero response addons.
        await websocket.send_bytes(bytes((1, 0)))
        if request["payload"]:
            writer.write(request["payload"])
            await writer.drain()

        t1 = asyncio.create_task(relay_websocket_to_tcp(websocket, writer))
        t2 = asyncio.create_task(relay_tcp_to_websocket(reader, websocket))
        done, pending = await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
    except (WebSocketDisconnect, asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError, asyncio.TimeoutError):
        pass
    except Exception:
        try:
            await websocket.close(code=1011)
        except Exception:
            pass
    finally:
        if writer is not None:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


SETUP_PAGE = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SpiderPanel · Setup</title>
<style>
body{margin:0;background:#080c12;color:#edf3fb;font-family:Arial,sans-serif;min-height:100vh;display:grid;place-items:center}
.card{width:min(430px,calc(100% - 40px));background:#111925;border:1px solid #273449;border-radius:20px;padding:28px;box-sizing:border-box;box-shadow:0 22px 70px #0008}
h1{margin:0 0 8px;font-size:30px}.muted{color:#95a4b8;margin:0 0 24px}
label{display:block;margin:14px 0 7px;color:#b8c5d6}input{width:100%;box-sizing:border-box;padding:13px 14px;border-radius:11px;border:1px solid #344359;background:#0a1018;color:#fff;font-size:16px;outline:none}
button{width:100%;margin-top:20px;padding:13px;border:0;border-radius:11px;background:#dfe9f7;color:#0a1018;font-weight:700;font-size:16px;cursor:pointer}
small{display:block;margin-top:12px;color:#738399;line-height:1.5}
</style></head><body><div class="card">
<h1>SpiderPanel</h1><p class="muted">Create a new panel password</p>
<form method="post" action="/setup"><label>New password</label><input name="password" type="password" minlength="6" required autofocus autocomplete="new-password"><label>Confirm password</label><input name="confirm" type="password" minlength="6" required autocomplete="new-password"><button type="submit">Create password</button></form>
<small>After setup, the panel shows one active VLESS server.</small></div></body></html>'''


LOGIN_PAGE = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SpiderPanel · Login</title>
<style>
body{margin:0;background:#080c12;color:#edf3fb;font-family:Arial,sans-serif;min-height:100vh;display:grid;place-items:center}
.card{width:min(430px,calc(100% - 40px));background:#111925;border:1px solid #273449;border-radius:20px;padding:28px;box-sizing:border-box;box-shadow:0 22px 70px #0008}
h1{margin:0 0 8px;font-size:30px}.muted{color:#95a4b8;margin:0 0 24px}
input{width:100%;box-sizing:border-box;padding:13px 14px;border-radius:11px;border:1px solid #344359;background:#0a1018;color:#fff;font-size:16px;outline:none}
button{width:100%;margin-top:20px;padding:13px;border:0;border-radius:11px;background:#dfe9f7;color:#0a1018;font-weight:700;font-size:16px;cursor:pointer}.err{color:#ff7f7f;margin-top:12px}
</style></head><body><div class="card"><h1>SpiderPanel</h1><p class="muted">Enter your panel password</p>
<form method="post" action="/login"><input name="password" type="password" required autofocus autocomplete="current-password"><button type="submit">Open panel</button></form><div class="err">__ERROR__</div></div></body></html>'''.replace("__ERROR__", "")


PANEL_PAGE = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SpiderPanel · VLESS</title>
<style>
body{margin:0;background:#080c12;color:#edf3fb;font-family:Arial,sans-serif;min-height:100vh}
main{max-width:760px;margin:45px auto;padding:20px}.card{background:#111925;border:1px solid #273449;border-radius:20px;padding:24px;box-shadow:0 22px 70px #0005}
h1{margin:0;font-size:32px}.muted{color:#95a4b8}.online{display:inline-flex;gap:8px;align-items:center;color:#57d98a;font-weight:700}.dot{width:10px;height:10px;border-radius:50%;background:#57d98a;box-shadow:0 0 14px #57d98a}
.server{margin-top:20px;padding:18px;border-radius:15px;background:#0b111a;border:1px solid #273449} .label{color:#8191a7;font-size:13px;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px}.value{word-break:break-all}
textarea{width:100%;box-sizing:border-box;background:#070b10;color:#dce7f4;border:1px solid #29374a;border-radius:11px;padding:13px;min-height:110px;resize:vertical;font:14px/1.5 monospace}
.row{display:flex;gap:10px;flex-wrap:wrap;margin-top:16px}a,button{background:#1d2a3b;border:1px solid #33435a;color:#fff;border-radius:10px;padding:10px 14px;text-decoration:none;cursor:pointer}.primary{background:#dfe9f7;color:#08101a;border-color:#dfe9f7;font-weight:700}
.meta{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin-top:15px}.box{background:#0d141e;border-radius:12px;padding:13px}.box b{display:block;margin-top:4px}
@media(max-width:560px){main{margin:20px auto}.meta{grid-template-columns:1fr}}
</style></head><body><main><div class="card">
<div style="display:flex;justify-content:space-between;gap:12px;align-items:center"><div><h1>SpiderPanel</h1><p class="muted">VLESS server panel</p></div><a href="/logout">Logout</a></div>
<p class="online"><span class="dot"></span> VLESS server active</p>
<div class="server"><div class="label">Server</div><div class="value">__HOST__</div><div class="meta"><div class="box"><span class="label">Protocol</span><b>VLESS</b></div><div class="box"><span class="label">Transport</span><b>WebSocket + TLS</b></div><div class="box"><span class="label">Port</span><b>443</b></div><div class="box"><span class="label">Path</span><b>/vless</b></div></div></div>
<div style="margin-top:18px"><div class="label">VLESS link</div><textarea id="uri" readonly>__VLESS_URI__</textarea></div>
<div class="row"><button class="primary" onclick="copyLink()">Copy VLESS link</button><button onclick="testVless()">Test connection</button><button onclick="location.href='/api/status'">Check status</button></div>
<div id="test" class="muted" style="font-size:13px;margin-top:16px"></div>
<p class="muted" style="font-size:13px;margin-top:16px">VLESS uses WebSocket + TLS through the VibeNest public HTTPS domain.</p>
</div></main><script>
function copyLink(){navigator.clipboard.writeText(document.getElementById('uri').value).then(()=>alert('Copied'))}
function uuidBytes(u){return new Uint8Array(u.replaceAll('-','').match(/.{2}/g).map(x=>parseInt(x,16)))}
function testVless(){
 const out=document.getElementById('test'); out.textContent='Testing VLESS WebSocket...';
 const uri=document.getElementById('uri').value; const m=uri.match(/^vless:\/\/([^@]+)@([^:]+):\d+/);
 if(!m){out.textContent='Invalid VLESS link';return}
 const host=location.host; const ws=new WebSocket('wss://'+host+'/vless'); ws.binaryType='arraybuffer';
 ws.onopen=()=>{
   const id=uuidBytes(m[1]); const domain=new TextEncoder().encode('example.com');
   const b=new Uint8Array(18+1+2+1+1+domain.length); let p=0; b[p++]=1; b.set(id,p); p+=16; b[p++]=0; b[p++]=1; b[p++]=0; b[p++]=80; b[p++]=2; b[p++]=domain.length; b.set(domain,p);
   ws.send(b);
 };
 ws.onmessage=(e)=>{ const a=new Uint8Array(e.data); if(a.length>=2&&a[0]===1){out.textContent='✓ VLESS WebSocket connected and outbound TCP test succeeded.';ws.close();} };
 ws.onerror=()=>{out.textContent='✕ WebSocket/VLESS connection failed. Check the VibeNest domain WebSocket route.'};
 ws.onclose=()=>{if(!out.textContent.startsWith('✓')) out.textContent='✕ VLESS connection closed before a valid response.'};
}
</script></body></html>'''
