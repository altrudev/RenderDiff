from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from .engine import analyze_bytes
from .assurance import attach
from .ingest import acquire_file, acquire_url
from .exports import html_report, sarif_report
from .receipt import verify
from .report import human_report
from .browser import chromium_observe_html
from .tokenizers import tiktoken_adapter, sentencepiece_adapter

def main(argv=None):
    p=argparse.ArgumentParser(prog="renderdiff", description="Compare human-visible and machine-facing representations of text.")
    sources=p.add_mutually_exclusive_group()
    sources.add_argument("--file", help="Read evidence from a file")
    sources.add_argument("--url", help="Fetch a public URL with explicit network permission")
    sources.add_argument("--text", help="Analyze literal text; otherwise stdin is read")
    p.add_argument("--allow-network", action="store_true", help="Permit the bounded public URL fetcher")
    p.add_argument("--html", action="store_true", help="Treat input as HTML")
    p.add_argument("--format", choices=["text","json","html","sarif","pdf"], default="text")
    p.add_argument("--output", help="Write report to a file")
    p.add_argument("--verify", help="Verify a saved JSON report")
    p.add_argument("--json", action="store_true", help="Emit deterministic JSON")
    p.add_argument("--browser", action="store_true", help="For HTML, observe Chromium innerText when Chromium is installed")
    p.add_argument("--tiktoken", metavar="ENCODING", help="Observe tokens with an installed tiktoken encoding")
    p.add_argument("--sentencepiece", metavar="MODEL", help="Observe tokens with an installed SentencePiece model")
    p.add_argument("--fail-on-material", action="store_true", help="Exit 2 when material divergence is found")
    args=p.parse_args(argv)
    if args.verify:
        try:
            valid=verify(json.loads(Path(args.verify).read_text(encoding="utf-8")))
        except (OSError,ValueError,TypeError): valid=False
        print("VALID" if valid else "INVALID")
        return 0 if valid else 2
    if args.url:
        if not args.allow_network: p.error("--url requires --allow-network")
        from .urlfetch import pinned_public_fetch
        result=acquire_url(args.url,fetcher=pinned_public_fetch)
        data=None
    elif args.file:
        data=Path(args.file).read_bytes()
    elif args.text is not None:
        data=args.text.encode("utf-8")
    elif not args.url:
        data=sys.stdin.buffer.read()
    tokenizer=None; tokenizer_name="custom"
    if args.tiktoken:
        tokenizer,tokenizer_name=tiktoken_adapter(args.tiktoken)
    elif args.sentencepiece:
        tokenizer,tokenizer_name=sentencepiece_adapter(args.sentencepiece)
    if args.url:
        pass
    elif args.file and not args.html and Path(args.file).suffix.lower() in {".pdf",".docx",".xlsx",".pptx"}:
        result=acquire_file(args.file)
    else:
        result=attach(analyze_bytes(
        data, content_type="text/html" if args.html else "text/plain",
        tokenizer=tokenizer, tokenizer_name=tokenizer_name,
        browser_observer=chromium_observe_html if args.browser and args.html else None,
    ), tokenizer=tokenizer, tokenizer_name=tokenizer_name)
    fmt="json" if args.json else args.format
    if fmt=="pdf":
        from .pdf_report import pdf_report
        output=pdf_report(result)
        if args.output: Path(args.output).write_bytes(output)
        else: sys.stdout.buffer.write(output)
        return 2 if args.fail_on_material and result["summary"].get("material_divergence") else 0
    if fmt=="json": output=json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2)+"\n"
    elif fmt=="html": output=html_report(result)
    elif fmt=="sarif": output=json.dumps(sarif_report(result),ensure_ascii=False,sort_keys=True,indent=2)+"\n"
    else: output=human_report(result)
    if args.output: Path(args.output).write_text(output,encoding="utf-8")
    else: sys.stdout.write(output)
    return 2 if args.fail_on_material and result["summary"].get("material_divergence") else 0

if __name__ == "__main__":
    raise SystemExit(main())
