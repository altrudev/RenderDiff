from __future__ import annotations
from .engine import analyze

def analyze_request(payload: dict) -> dict:
    """Stable public assurance boundary suitable for ddcal.ca adapters.

    Request: {"text": str, "content_type": str?, "provenance": object?}
    No proprietary DDC internals are exposed or required.
    """
    if not isinstance(payload, dict):
        raise TypeError("payload must be an object")
    if "text" not in payload or not isinstance(payload["text"], str):
        raise ValueError("payload.text must be a string")
    return analyze(payload["text"], content_type=payload.get("content_type","text/plain"), provenance=payload.get("provenance"))
