"""Compatibility entrypoints for the isolated browser observer."""
from __future__ import annotations
import shutil

def find_chromium():
    return next((p for name in ('chromium','chromium-browser','google-chrome','google-chrome-stable') if (p:=shutil.which(name))),None)

def chromium_observe_html(source: str, *, executable=None, timeout: float=12.0) -> dict:
    from .playwright_browser import observe_html
    result=observe_html(source,executable=executable,timeout=timeout)
    if result.get('available'):
        return {**result,'observer':'playwright-isolated-chromium'}
    return result

def chromium_observe_full_html(source: str, *, timeout: float=20):
    from .playwright_browser import observe_html
    return observe_html(source,timeout=timeout)
