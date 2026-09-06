#!/usr/bin/env python3
from __future__ import annotations
from pathlib import Path
import argparse
import urllib.request
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from renderdiff.uts39 import UTS39_CONFUSABLES_URL, verify_pinned_confusables


def main() -> int:
    p=argparse.ArgumentParser(description="Fetch and verify RenderDiff's pinned Unicode confusables data")
    p.add_argument("--output", default="data/confusables-17.0.0.txt")
    args=p.parse_args()
    with urllib.request.urlopen(UTS39_CONFUSABLES_URL, timeout=30) as response:
        data=response.read()
    verify_pinned_confusables(data)
    out=Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(data)
    print(f"verified {len(data)} bytes -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
