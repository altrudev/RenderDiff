from __future__ import annotations
import json
from .engine import analyze

from .limits import MAX_ANALYSIS_CHARS, MAX_ANALYSIS_BYTES
MAX_TEXT_CHARS = MAX_ANALYSIS_CHARS
MAX_TEXT_BYTES = MAX_ANALYSIS_BYTES
MAX_PROVENANCE_BYTES = 64_000


def _json_size(value: object) -> int:
    try:
        encoded=json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",",":"))
    except (TypeError, ValueError) as exc:
        raise ValueError("payload.provenance must be deterministic JSON data") from exc
    return len(encoded.encode("utf-8"))


def analyze_request(payload: dict, *, browser_observer=None, tokenizer=None, tokenizer_name: str="custom") -> dict:
    """Stable public assurance boundary suitable for ddcal.ca adapters.

    Request: {"text": str, "content_type": str?, "provenance": object?}
    The boundary is deliberately bounded because exact byte/codepoint evidence can
    expand output substantially. No proprietary DDC internals are exposed or required.
    """
    if not isinstance(payload, dict):
        raise TypeError("payload must be an object")
    if "text" not in payload or not isinstance(payload["text"], str):
        raise ValueError("payload.text must be a string")

    text=payload["text"]
    byte_length=len(text.encode("utf-8"))
    if len(text) > MAX_TEXT_CHARS or byte_length > MAX_TEXT_BYTES:
        raise ValueError(
            f"payload.text exceeds assurance boundary limit ({MAX_TEXT_CHARS} chars / {MAX_TEXT_BYTES} UTF-8 bytes)"
        )

    content_type=payload.get("content_type", "text/plain")
    if not isinstance(content_type, str) or len(content_type) > 200:
        raise ValueError("payload.content_type must be a short string")

    provenance=payload.get("provenance")
    if provenance is not None:
        if not isinstance(provenance, dict):
            raise ValueError("payload.provenance must be an object")
        if _json_size(provenance) > MAX_PROVENANCE_BYTES:
            raise ValueError(f"payload.provenance exceeds {MAX_PROVENANCE_BYTES} UTF-8 bytes")

    browser_requested=payload.get("browser", False)
    if not isinstance(browser_requested, bool):
        raise ValueError("payload.browser must be boolean")
    if browser_requested and browser_observer is None:
        raise ValueError("browser observation requested but no browser observer is configured")
    if browser_requested and not content_type.lower().startswith(("text/html","application/xhtml+xml")):
        raise ValueError("browser observation requires HTML content_type")
    return analyze(
        text, content_type=content_type, provenance=provenance,
        browser_observer=browser_observer if browser_requested else None,
        tokenizer=tokenizer, tokenizer_name=tokenizer_name,
    )
