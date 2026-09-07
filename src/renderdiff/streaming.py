"""Bounded streaming intake with explicit incomplete-analysis semantics."""
from __future__ import annotations
import hashlib
from .engine import analyze_bytes
from .assurance import attach
from .limits import bounded_canonical, MAX_ANALYSIS_BYTES, EvidenceLimitError

def analyze_stream(chunks, *, max_bytes=4_000_000, content_type='text/plain'):
    if max_bytes>MAX_ANALYSIS_BYTES: max_bytes=MAX_ANALYSIS_BYTES
    digest=hashlib.sha256(); data=bytearray()
    for chunk in chunks:
        if not isinstance(chunk,bytes):raise TypeError('stream chunks must be bytes')
        digest.update(chunk)
        if len(data)+len(chunk)>max_bytes:raise EvidenceLimitError('stream exceeds analysis limit; no clean verdict issued')
        data.extend(chunk)
    report=attach(analyze_bytes(bytes(data),content_type=content_type))
    report['views']['stream']={'source_sha256':digest.hexdigest(),'byte_length':len(data),'complete':True}
    from .assurance import digest as seal_hash
    report['receipt']={'canonical_json_sha256':hashlib.sha256(bounded_canonical({k:v for k,v in report.items() if k!='receipt'})).hexdigest()}
    return report
