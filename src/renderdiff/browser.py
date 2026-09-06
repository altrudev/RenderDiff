from __future__ import annotations
import base64, html, re, shutil, subprocess, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_MARKER=re.compile(r'<meta[^>]*id="renderdiff-observer"[^>]*data-text="([^"]*)"', re.I)

def find_chromium() -> str | None:
    for name in ('chromium','chromium-browser','google-chrome','google-chrome-stable'):
        path=shutil.which(name)
        if path: return path
    return None

def chromium_observe_html(source: str, *, executable: str | None=None, timeout: float=8.0) -> dict:
    """Observe Chromium body.innerText using an ephemeral loopback-only transport.

    External hostname resolution is denied. This adapter still executes active HTML;
    high-assurance deployments should additionally place Chromium in an OS/container sandbox.
    """
    exe=executable or find_chromium()
    if not exe:
        return {'available':False,'observer':'chromium','reason':'chromium-not-found'}
    probe='''<script>(function(){function emit(){try{var t=(document.body&&document.body.innerText)||"";var b=btoa(unescape(encodeURIComponent(t)));var m=document.createElement("meta");m.id="renderdiff-observer";m.setAttribute("data-text",b);(document.head||document.documentElement).appendChild(m)}catch(e){}};if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",emit,{once:true});else emit()})();</script>'''
    payload=(source+probe).encode('utf-8')
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200); self.send_header('Content-Type','text/html; charset=utf-8'); self.send_header('Content-Length',str(len(payload))); self.end_headers(); self.wfile.write(payload)
        def log_message(self,*args): pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    url=f'http://127.0.0.1:{server.server_port}/evidence'
    cmd=[exe,'--headless','--disable-gpu','--no-sandbox','--disable-extensions','--disable-sync',
         '--disable-background-networking','--disable-component-update','--disable-default-apps','--no-first-run',
         '--host-resolver-rules=MAP * 0.0.0.0, EXCLUDE localhost','--virtual-time-budget=1200','--dump-dom',url]
    try:
        cp=subprocess.run(cmd,capture_output=True,text=True,timeout=timeout)
    except (subprocess.TimeoutExpired,OSError) as e:
        return {'available':False,'observer':'chromium','reason':type(e).__name__}
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=1)
    m=_MARKER.search(cp.stdout)
    if not m:
        return {'available':False,'observer':'chromium','reason':'probe-not-observed','exit_code':cp.returncode}
    try:
        text=base64.b64decode(html.unescape(m.group(1))).decode('utf-8')
    except Exception:
        return {'available':False,'observer':'chromium','reason':'probe-decode-failed'}
    return {'available':True,'observer':'chromium','text':text,'exit_code':cp.returncode,'transport':'loopback-http'}
