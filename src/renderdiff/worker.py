"""Isolated extraction entrypoint; launched only by the sandbox adapter."""
from __future__ import annotations
import json
import sys
from pathlib import Path
from .ingest import acquire_bytes, MAX_BYTES
from .limits import EvidenceLimitError, bounded_canonical

def main():
    data=Path('/work/input').read_bytes()
    if len(data)>MAX_BYTES:
        raise EvidenceLimitError('original evidence exceeds input limit')
    report=acquire_bytes(data,filename=sys.argv[1])
    Path('/work/report.json').write_bytes(bounded_canonical(report))

if __name__=='__main__':
    try:
        main()
    except EvidenceLimitError as exc:
        Path('/work/error.json').write_text(json.dumps({'code':'resource-limit','detail':str(exc)}))
        raise SystemExit(2)
    except ValueError:
        Path('/work/error.json').write_text(json.dumps({'code':'invalid-evidence'}))
        raise SystemExit(3)
