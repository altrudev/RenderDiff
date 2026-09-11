"""Shared, explicit resource boundaries for full-evidence reports."""
from __future__ import annotations
import json

MAX_ANALYSIS_CHARS = 64_000
MAX_ANALYSIS_BYTES = 256_000
MAX_FINDINGS = 10_000
MAX_REPORT_BYTES = 8_000_000

class EvidenceLimitError(ValueError):
    """Evidence was not completely analyzed within the configured budget."""

def check_text_budget(text: str) -> None:
    if len(text) > MAX_ANALYSIS_CHARS or len(text.encode('utf-8')) > MAX_ANALYSIS_BYTES:
        raise EvidenceLimitError('full-evidence analysis limit exceeded; no clean verdict issued')

def bounded_canonical(value, *, limit=MAX_REPORT_BYTES) -> bytes:
    """Serialize deterministically without allowing an oversized JSON allocation."""
    encoder = json.JSONEncoder(ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)
    out = bytearray()
    for fragment in encoder.iterencode(value):
        encoded = fragment.encode('utf-8')
        if len(out) + len(encoded) > limit:
            raise EvidenceLimitError('report amplification limit exceeded; no clean verdict issued')
        out.extend(encoded)
    return bytes(out)
