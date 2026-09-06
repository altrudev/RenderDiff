from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from .engine import analyze_bytes
from .report import human_report
from .browser import chromium_observe_html
from .tokenizers import tiktoken_adapter, sentencepiece_adapter

def main(argv=None):
    p=argparse.ArgumentParser(prog="renderdiff", description="Compare human-visible and machine-facing representations of text.")
    sources=p.add_mutually_exclusive_group()
    sources.add_argument("--file", help="Read evidence from a file")
    sources.add_argument("--text", help="Analyze literal text; otherwise stdin is read")
    p.add_argument("--html", action="store_true", help="Treat input as HTML")
    p.add_argument("--json", action="store_true", help="Emit deterministic JSON")
    p.add_argument("--browser", action="store_true", help="For HTML, observe Chromium innerText when Chromium is installed")
    p.add_argument("--tiktoken", metavar="ENCODING", help="Observe tokens with an installed tiktoken encoding")
    p.add_argument("--sentencepiece", metavar="MODEL", help="Observe tokens with an installed SentencePiece model")
    p.add_argument("--fail-on-material", action="store_true", help="Exit 2 when material divergence is found")
    args=p.parse_args(argv)
    if args.file:
        data=Path(args.file).read_bytes()
    elif args.text is not None:
        data=args.text.encode("utf-8")
    else:
        data=sys.stdin.buffer.read()
    tokenizer=None; tokenizer_name="custom"
    if args.tiktoken:
        tokenizer,tokenizer_name=tiktoken_adapter(args.tiktoken)
    elif args.sentencepiece:
        tokenizer,tokenizer_name=sentencepiece_adapter(args.sentencepiece)
    result=analyze_bytes(
        data, content_type="text/html" if args.html else "text/plain",
        tokenizer=tokenizer, tokenizer_name=tokenizer_name,
        browser_observer=chromium_observe_html if args.browser and args.html else None,
    )
    if args.json:
        sys.stdout.write(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2)+"\n")
    else:
        sys.stdout.write(human_report(result))
    return 2 if args.fail_on_material and result["summary"].get("material_divergence") else 0

if __name__ == "__main__":
    raise SystemExit(main())
