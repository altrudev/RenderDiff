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
    from .safe_browser import observe_html
    from .safe_browser import bubblewrap_chromium
    return observe_html(source,runner=bubblewrap_chromium,timeout=timeout)


def chromium_observe_full_html(source: str, *, timeout: float=20):
    from .playwright_browser import observe_html
    return observe_html(source,timeout=timeout)
