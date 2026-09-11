"""Isolated extraction entrypoint; launched only by the sandbox adapter."""
from __future__ import annotations
import json, sys
from pathlib import Path
from .ingest import acquire_bytes

def main():
    data=Path('/work/input').read_bytes()
    if len(data)>4_000_000: raise ValueError('input too large')
    report=acquire_bytes(data,filename=sys.argv[1])
    Path('/work/report.json').write_text(json.dumps(report,ensure_ascii=False,allow_nan=False,separators=(',',':')),encoding='utf-8')
if __name__=='__main__': main()
