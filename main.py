import os
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI(title="SpiderPanel")

PORT = int(os.environ.get("PORT", "8080"))

PAGE = '''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SpiderPanel</title>
<style>
body{margin:0;background:#0b0f14;color:#e8eef5;font-family:Arial,sans-serif}
main{max-width:760px;margin:70px auto;padding:24px}
.card{background:#121923;border:1px solid #263242;border-radius:16px;padding:24px}
h1{margin-top:0}.muted{color:#91a0b3}.ok{color:#55d187;font-weight:700}
button{background:#1e2938;color:#fff;border:1px solid #344256;border-radius:10px;padding:10px 14px;cursor:pointer}
pre{white-space:pre-wrap;background:#080c11;padding:14px;border-radius:10px}
</style>
</head>
<body><main><div class="card">
<h1>SpiderPanel</h1>
<p class="muted">Simple deployment test panel</p>
<p class="ok">● Online</p>
<p>Port: <b id="port">-</b></p>
<button onclick="check()">Refresh status</button>
<pre id="status">Loading...</pre>
</div></main>
<script>
async function check(){
 const r=await fetch('/api/status');
 document.getElementById('status').textContent=JSON.stringify(await r.json(),null,2);
}
check();
</script></body></html>'''

@app.get("/", response_class=HTMLResponse)
async def home():
    return PAGE

@app.get("/api/status")
async def status():
    return JSONResponse({"ok": True, "panel": "SpiderPanel", "status": "online", "port": PORT})
