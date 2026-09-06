from __future__ import annotations
import hashlib, json, re, unicodedata
from typing import Callable
from .model import Finding
from .unicode_rules import (
    BIDI_CLASSES, CONFUSABLES, confusable_skeleton, cp_name, is_invisible, is_tag, is_variation
)
from .htmlview import inspect_html

ENGINE_VERSION = "0.1.0"
SCHEMA_VERSION = "renderdiff.assurance.v1"
TOKEN_RE = re.compile(r"\w+|[^\w\s]", re.UNICODE)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _decode_tags(text: str) -> tuple[str, list[dict]]:
    out=[]; runs=[]; buf=[]; start=None
    for i,ch in enumerate(text):
        cp=ord(ch)
        if is_tag(cp):
            if start is None: start=i
            if 0xE0020 <= cp <= 0xE007E:
                buf.append(chr(cp - 0xE0000))
            elif cp == 0xE007F:
                if buf:
                    runs.append({"start":start,"end":i+1,"decoded":"".join(buf)})
                buf=[]; start=None
            continue
        if buf:
            runs.append({"start":start,"end":i,"decoded":"".join(buf)})
            buf=[]; start=None
        out.append(ch)
    if buf: runs.append({"start":start,"end":len(text),"decoded":"".join(buf)})
    return "".join(out), runs


def _visible_projection(text: str) -> str:
    return "".join(ch for ch in text if not is_invisible(ch))


def _severity(findings: list[Finding]) -> str:
    levels={"info":0,"low":1,"medium":2,"high":3,"critical":4}
    return max((f.severity for f in findings), key=lambda x: levels[x], default="info")


def _is_emoji_context(text: str, i: int) -> bool:
    # Practical suppression for ZWJ/variation selectors used in emoji sequences.
    neighbors = text[max(0,i-2):i] + text[i+1:i+3]
    return any(unicodedata.category(ch) == "So" or ord(ch) >= 0x1F000 for ch in neighbors)

def _is_subdivision_flag_run(text: str, start: int, end: int) -> bool:
    # Unicode subdivision flags are BLACK FLAG + tag letters/digits + CANCEL TAG.
    return start > 0 and ord(text[start-1]) == 0x1F3F4 and end <= len(text) and ord(text[end-1]) == 0xE007F

def analyze(text: str, *, content_type: str = "text/plain", tokenizer: Callable[[str], list[int] | list[str]] | None = None,
            provenance: dict | None = None, extra_confusables: dict[str,str] | None = None) -> dict:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    raw=text.encode("utf-8")
    findings: list[Finding]=[]

    codepoints=[]
    for i,ch in enumerate(text):
        cp=ord(ch); bidi=unicodedata.bidirectional(ch); cat=unicodedata.category(ch)
        rec={"index":i,"char":ch,"codepoint":f"U+{cp:04X}","name":cp_name(ch),"category":cat,"bidi":bidi}
        codepoints.append(rec)
        if is_invisible(ch):
            emoji_context = _is_emoji_context(text, i)
            if is_variation(cp) or (cp in {0x200C,0x200D} and emoji_context):
                sev, mat = "info", "context-dependent"
            elif is_tag(cp):
                sev, mat = "medium", "context-dependent"  # run-level decoder decides smuggling materiality
            elif bidi in BIDI_CLASSES:
                sev, mat = "high", "material"
            else:
                sev, mat = "medium", "potentially-material"
            findings.append(Finding(
                id=f"unicode-invisible:{i}", category="invisible-unicode", severity=sev,
                materiality=mat, start=i,end=i+1,
                evidence={**rec, "emoji_context": emoji_context}, explanation="Character may be invisible or non-printing in normal human rendering."
            ))
        if bidi in BIDI_CLASSES:
            findings.append(Finding(
                id=f"bidi-control:{i}", category="bidi-reordering", severity="high", materiality="material",
                start=i,end=i+1,evidence=rec,
                explanation="Explicit bidirectional control can reorder displayed text relative to logical storage order."
            ))

    tag_stripped, tag_runs = _decode_tags(text)
    for n,run in enumerate(tag_runs):
        legitimate_flag = _is_subdivision_flag_run(text, run["start"], run["end"])
        findings.append(Finding(
            id=f"unicode-tags:{n}", category="unicode-tag-sequence" if legitimate_flag else "ascii-smuggling",
            severity="info" if legitimate_flag else "high", materiality="context-dependent" if legitimate_flag else "material",
            start=run["start"], end=run["end"], evidence={**run, "subdivision_flag_context": legitimate_flag},
            explanation=("Unicode Tag sequence appears attached to a subdivision-flag emoji; preserve as legitimate unless policy says otherwise."
                         if legitimate_flag else "Unicode tag characters encode an ASCII-like hidden payload not normally visible to a reader.")
        ))

    nfc=unicodedata.normalize("NFC", text)
    nfkc=unicodedata.normalize("NFKC", text)
    if nfc != text or nfkc != text:
        evidence={
            "nfc_changed": nfc != text, "nfkc_changed": nfkc != text,
            "input_sha256": _sha256(raw), "nfc_sha256": _sha256(nfc.encode()), "nfkc_sha256": _sha256(nfkc.encode()),
            "nfc": nfc, "nfkc": nfkc
        }
        mat = "material" if nfkc != text and _visible_projection(nfkc) != _visible_projection(text) else "context-dependent"
        findings.append(Finding(
            id="normalization-delta", category="normalization", severity="medium", materiality=mat,
            start=None,end=None,evidence=evidence,
            explanation="Unicode normalization changes the stored representation; compatibility normalization may collapse distinctions."
        ))

    skeleton=confusable_skeleton(text, extra_confusables)
    confusable_positions=[]
    mapping = CONFUSABLES if not extra_confusables else {**CONFUSABLES, **extra_confusables}
    for i,ch in enumerate(text):
        if ch in mapping and mapping[ch] != ch:
            confusable_positions.append({"index":i,"char":ch,"codepoint":f"U+{ord(ch):04X}","maps_to":mapping[ch],"name":cp_name(ch)})
    if confusable_positions:
        # Avoid overclaiming: presence alone is not always malicious.
        mixed = len({unicodedata.name(ch, "").split(" ",1)[0] for ch in text if ch.isalpha() and unicodedata.name(ch, "")}) > 1
        findings.append(Finding(
            id="confusable-skeleton", category="confusable-homoglyph", severity="high" if mixed else "low",
            materiality="potentially-material" if mixed else "context-dependent", start=None,end=None,
            evidence={"skeleton":skeleton,"positions":confusable_positions,"mixed_script_heuristic":mixed},
            explanation="Characters have visually confusable alternatives; mixed scripts increase spoofing relevance."
        ))

    html_view=None
    if content_type.lower().split(";",1)[0].strip() in {"text/html","application/xhtml+xml"}:
        html_view=inspect_html(text)
        if html_view["hidden_fragments"] or html_view.get("hidden_attributes"):
            findings.append(Finding(
                id="html-hidden-content", category="hidden-html-css", severity="high", materiality="material",
                start=None,end=None,evidence={"fragments":html_view["hidden_fragments"], "hidden_attributes": html_view.get("hidden_attributes", [])},
                explanation="HTML contains text suppressed by markup or inline CSS while remaining present in the source representation."
            ))
        if html_view["comments"]:
            findings.append(Finding(
                id="html-comments", category="non-rendered-html", severity="low", materiality="context-dependent",
                start=None,end=None,evidence={"comments":html_view["comments"]},
                explanation="HTML comments are not normally rendered but are part of the supplied source."
            ))

    visible = html_view["visible_text"] if html_view else _visible_projection(text)
    hidden_projection = {
        "unicode_tag_payloads": [x["decoded"] for x in tag_runs],
        "invisible_characters": [r for r in codepoints if is_invisible(r["char"])],
        "html_hidden_fragments": html_view["hidden_fragments"] if html_view else [],
        "html_hidden_attributes": html_view.get("hidden_attributes", []) if html_view else [],
        "html_comments": html_view["comments"] if html_view else [],
    }

    model_view={
        "exact_text_sha256": _sha256(raw),
        "lexical_units": TOKEN_RE.findall(text),
        "tokenizer": None,
    }
    if tokenizer is not None:
        toks=tokenizer(text)
        model_view["tokenizer"]={"token_count":len(toks),"tokens":toks}

    material = [f for f in findings if f.materiality in {"material","potentially-material"}]
    semantic={
        "human_visible_text": visible,
        "machine_received_text": text,
        "decoded_hidden_text": [x["decoded"] for x in tag_runs] + ([x["text"] for x in html_view["hidden_fragments"]] + [x["text"] for x in html_view.get("hidden_attributes", [])] if html_view else []),
        "material_divergence": bool(material),
        "basis": sorted({f.category for f in material}),
    }

    result={
        "schema":SCHEMA_VERSION,"engine_version":ENGINE_VERSION,
        "input":{"content_type":content_type,"byte_length":len(raw),"char_length":len(text),"sha256":_sha256(raw)},
        "views":{
            "raw_bytes":{"encoding":"utf-8","hex":raw.hex()},
            "unicode":{"codepoints":codepoints},
            "human_visible":{"text":visible,"sha256":_sha256(visible.encode())},
            "normalized":{"nfc":nfc,"nfkc":nfkc,"nfc_sha256":_sha256(nfc.encode()),"nfkc_sha256":_sha256(nfkc.encode())},
            "model_facing":model_view,
            "semantic":semantic,
            "hidden":hidden_projection,
            "lineage":provenance or {},
            "tag_stripped":{"text":tag_stripped,"sha256":_sha256(tag_stripped.encode())},
            "confusable":{"skeleton":skeleton,"sha256":_sha256(skeleton.encode())},
        },
        "summary":{
            "finding_count":len(findings),"severity":_severity(findings),
            "material_divergence":bool(material),"categories":sorted({f.category for f in findings})
        },
        "findings":[f.to_dict() for f in sorted(findings, key=lambda x:x.id)],
    }
    canonical=json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",",":"))
    result["receipt"]={"canonical_json_sha256":_sha256(canonical.encode("utf-8"))}
    return result


def analyze_bytes(data: bytes, **kwargs) -> dict:
    try:
        text=data.decode("utf-8")
    except UnicodeDecodeError as e:
        return {
            "schema":SCHEMA_VERSION,"engine_version":ENGINE_VERSION,
            "input":{"byte_length":len(data),"sha256":_sha256(data)},
            "summary":{"finding_count":1,"severity":"high","material_divergence":True,"categories":["invalid-utf8"]},
            "findings":[Finding("invalid-utf8","invalid-utf8","high","material",e.start,e.end,
                {"reason":str(e),"offending_hex":data[e.start:e.end].hex()},
                "Input bytes are not valid UTF-8 and therefore can be interpreted differently across consumers.").to_dict()],
        }
    return analyze(text, **kwargs)
