from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from .engine import analyze_bytes
from .report import human_report

def main(argv=None):
    p=argparse.ArgumentParser(prog="renderdiff", description="Compare human-visible and machine-facing representations of text.")
    sources=p.add_mutually_exclusive_group()
    sources.add_argument("--file", help="Read evidence from a file")
    sources.add_argument("--text", help="Analyze literal text; otherwise stdin is read")
    p.add_argument("--html", action="store_true", help="Treat input as HTML")
    p.add_argument("--json", action="store_true", help="Emit deterministic JSON")
    p.add_argument("--fail-on-material", action="store_true", help="Exit 2 when material divergence is found")
    args=p.parse_args(argv)
    if args.file:
        data=Path(args.file).read_bytes()
    elif args.text is not None:
        data=args.text.encode("utf-8")
    else:
        data=sys.stdin.buffer.read()
    result=analyze_bytes(data, content_type="text/html" if args.html else "text/plain")
    if args.json:
        sys.stdout.write(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2)+"\n")
    else:
        sys.stdout.write(human_report(result))
    return 2 if args.fail_on_material and result["summary"].get("material_divergence") else 0

if __name__ == "__main__":
    raise SystemExit(main())
