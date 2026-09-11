"""Bounded streaming intake with explicit incomplete-analysis semantics."""
from __future__ import annotations
import hashlib
from .engine import analyze_bytes
from .assurance import attach

def analyze_stream(chunks, *, max_bytes=4_000_000, content_type='text/plain'):
    digest=hashlib.sha256(); data=bytearray()
    for chunk in chunks:
        if not isinstance(chunk,bytes):raise TypeError('stream chunks must be bytes')
        digest.update(chunk)
        if len(data)+len(chunk)>max_bytes:raise ValueError('stream exceeds analysis limit; no clean verdict issued')
        data.extend(chunk)
    report=attach(analyze_bytes(bytes(data),content_type=content_type))
    report['views']['stream']={'source_sha256':digest.hexdigest(),'byte_length':len(data),'complete':True}
    from .assurance import digest as seal_hash
    report['receipt']={'canonical_json_sha256':seal_hash({k:v for k,v in report.items() if k!='receipt'})}
    return report
