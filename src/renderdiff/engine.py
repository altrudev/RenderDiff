from __future__ import annotations
import hashlib, json, re, unicodedata
from typing import Callable
from .model import Finding
from .unicode_rules import (
    BIDI_CLASSES, BIDI_DIRECTION_MARKS, BIDI_STRONG_CONTROLS, CONFUSABLES,
    STANDARD_SUBDIVISION_TAGS, bidi_control_strength, confusable_skeleton,
    cp_name, is_bidi_control, is_invisible, is_tag, is_variation, script_families,
)
from .htmlview import inspect_html
from .uts39 import default_confusables, uts39_skeleton, UTS39_VERSION, UTS39_CONFUSABLES_SHA256
from .divergence import compare_text_views
from .materiality import assess_representation_divergence
from .tokenizers import observe_tokenizer

ENGINE_VERSION = "0.4.0"
SCHEMA_VERSION = "renderdiff.assurance.v1"
TOKEN_RE = re.compile(r"\w+|[^\w\s]", re.UNICODE)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_hash(obj: dict) -> str:
    canonical = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",",":"))
    return _sha256(canonical.encode("utf-8"))


def _decode_tags(text: str) -> tuple[str, list[dict]]:
    out=[]; runs=[]; buf=[]; start=None
    for i,ch in enumerate(text):
        cp=ord(ch)
        if is_tag(cp):
            if start is None:
                start=i
            if 0xE0020 <= cp <= 0xE007E:
                buf.append(chr(cp - 0xE0000))
            elif cp == 0xE007F:
                runs.append({"start":start,"end":i+1,"decoded":"".join(buf),"terminated":True})
                buf=[]; start=None
            continue
        if start is not None:
            runs.append({"start":start,"end":i,"decoded":"".join(buf),"terminated":False})
            buf=[]; start=None
        out.append(ch)
    if start is not None:
        runs.append({"start":start,"end":len(text),"decoded":"".join(buf),"terminated":False})
    return "".join(out), runs


def _visible_projection(text: str) -> str:
    return "".join(ch for ch in text if not is_invisible(ch))


def _severity(findings: list[Finding]) -> str:
    levels={"info":0,"low":1,"medium":2,"high":3,"critical":4}
    return max((f.severity for f in findings), key=lambda x: levels[x], default="info")


def _is_emoji_like(ch: str) -> bool:
    cp=ord(ch)
    return unicodedata.category(ch) == "So" or 0x1F000 <= cp <= 0x1FAFF


def _is_emoji_zwj_context(text: str, i: int) -> bool:
    # Suppress only when ZWJ has emoji-like context on both sides (ignoring VS selectors).
    left=i-1
    while left >= 0 and is_variation(ord(text[left])):
        left -= 1
    right=i+1
    while right < len(text) and is_variation(ord(text[right])):
        right += 1
    return left >= 0 and right < len(text) and _is_emoji_like(text[left]) and _is_emoji_like(text[right])


def _is_standard_subdivision_flag_run(text: str, run: dict) -> bool:
    start=run["start"]; end=run["end"]
    return (
        start > 0
        and ord(text[start-1]) == 0x1F3F4
        and bool(run.get("terminated"))
        and end <= len(text)
        and ord(text[end-1]) == 0xE007F
        and run.get("decoded", "") in STANDARD_SUBDIVISION_TAGS
    )


def _hidden_carrier_finding(text: str, codepoints: list[dict]) -> Finding | None:
    carriers=[]
    for rec in codepoints:
        cp=int(rec["codepoint"][2:],16)
        if cp in {0x200B,0x200C,0x200D,0x2060,0xFEFF,0x034F} or is_variation(cp):
            carriers.append({
                "index":rec["index"], "codepoint":rec["codepoint"],
                "name":rec["name"], "category":rec["category"],
            })
    if len(carriers) < 4:
        return None
    density = len(carriers) / max(1, len(text))
    repeated = len({x["codepoint"] for x in carriers}) <= max(2, len(carriers)//2)
    if density < 0.05 and not repeated:
        return None
    return Finding(
        id="hidden-carrier-pattern", category="watermark-like-hidden-text", severity="low",
        materiality="context-dependent", start=None, end=None,
        evidence={"carrier_count":len(carriers),"char_length":len(text),"density":round(density,6),"carriers":carriers},
        explanation=(
            "Multiple non-rendering carrier characters form a hidden representation pattern. "
            "This can be used by watermarking, steganography, formatting, or adversarial payloads; origin is not inferred."
        ),
    )


def analyze(text: str, *, content_type: str = "text/plain", tokenizer: Callable[[str], list[int] | list[str]] | None = None,
            tokenizer_name: str = "custom", provenance: dict | None = None, extra_confusables: dict[str,str] | None = None,
            browser_observer: Callable[[str], dict] | None = None) -> dict:
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
            emoji_context = cp == 0x200D and _is_emoji_zwj_context(text, i)
            if is_variation(cp) or emoji_context:
                sev, mat = "info", "context-dependent"
            elif is_tag(cp):
                sev, mat = "medium", "context-dependent"  # run-level decoder decides materiality
            elif cp in BIDI_STRONG_CONTROLS:
                sev, mat = "high", "material"
            elif cp in BIDI_DIRECTION_MARKS:
                sev, mat = "medium", "potentially-material"
            else:
                sev, mat = "medium", "potentially-material"
            findings.append(Finding(
                id=f"unicode-invisible:{i}", category="invisible-unicode", severity=sev,
                materiality=mat, start=i,end=i+1,
                evidence={**rec, "emoji_context": emoji_context},
                explanation="Character may be invisible or non-printing in normal human rendering."
            ))
        if is_bidi_control(ch):
            strength=bidi_control_strength(ch)
            findings.append(Finding(
                id=f"bidi-control:{i}", category="bidi-reordering",
                severity="high" if strength == "strong" else "medium",
                materiality="material" if strength == "strong" else "potentially-material",
                start=i,end=i+1,evidence={**rec,"control_strength":strength},
                explanation=(
                    "Explicit bidirectional control can reorder displayed text relative to logical storage order."
                    if strength == "strong" else
                    "Bidirectional direction mark can change surrounding display direction without visible glyph evidence."
                )
            ))

    carrier_finding=_hidden_carrier_finding(text, codepoints)
    if carrier_finding:
        findings.append(carrier_finding)

    tag_stripped, tag_runs = _decode_tags(text)
    for n,run in enumerate(tag_runs):
        legitimate_flag = _is_standard_subdivision_flag_run(text, run)
        findings.append(Finding(
            id=f"unicode-tags:{n}", category="unicode-tag-sequence" if legitimate_flag else "ascii-smuggling",
            severity="info" if legitimate_flag else "high",
            materiality="context-dependent" if legitimate_flag else "material",
            start=run["start"], end=run["end"],
            evidence={**run, "standard_subdivision_flag": legitimate_flag},
            explanation=(
                "Unicode Tag sequence exactly matches a standardized subdivision-flag sequence."
                if legitimate_flag else
                "Unicode tag characters encode a hidden ASCII-like payload or malformed tag run not normally visible to a reader."
            )
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

    mapping=default_confusables().copy()
    if extra_confusables:
        mapping.update(extra_confusables)
    skeleton=uts39_skeleton(text, mapping)
    confusable_positions=[]
    for i,ch in enumerate(text):
        mapped=mapping.get(ch,ch)
        # Full UTS #39 maps many ordinary ASCII characters. Presence alone is not
        # evidence of spoofing, so exact-position findings focus on non-ASCII substitutions.
        if ord(ch) > 127 and mapped != ch:
            confusable_positions.append({"index":i,"char":ch,"codepoint":f"U+{ord(ch):04X}","maps_to":mapped,"name":cp_name(ch)})
    scripts=script_families(text)
    spoof_scripts=sorted(set(scripts) & {"Latin","Cyrillic","Greek"})
    mixed_spoof_scripts=len(spoof_scripts) > 1
    if confusable_positions:
        findings.append(Finding(
            id="confusable-skeleton", category="confusable-homoglyph",
            severity="high" if mixed_spoof_scripts else "low",
            materiality="potentially-material" if mixed_spoof_scripts else "context-dependent", start=None,end=None,
            evidence={
                "skeleton":skeleton,"positions":confusable_positions,
                "script_families":scripts,"spoof_script_families":spoof_scripts,
                "mixed_spoof_scripts":mixed_spoof_scripts,
                "mapping_scope":"full-pinned-uts39-plus-caller-overrides",
                "uts39_version":UTS39_VERSION,"uts39_confusables_sha256":UTS39_CONFUSABLES_SHA256,
            },
            explanation=(
                "Visually confusable mappings occur across spoof-relevant script families."
                if mixed_spoof_scripts else
                "Characters have visually confusable alternatives; context is required before treating this as spoofing."
            )
        ))

    html_view=None
    browser_view={"available":False,"observer":None,"reason":"not-requested"}
    if content_type.lower().split(";",1)[0].strip() in {"text/html","application/xhtml+xml"}:
        html_view=inspect_html(text)
        if browser_observer is not None:
            browser_view=browser_observer(text)
            if not isinstance(browser_view,dict):
                raise TypeError("browser_observer must return a dict")
            if browser_view.get("available") and isinstance(browser_view.get("text"),str):
                browser_view={**browser_view,"char_length":len(browser_view["text"]),"sha256":_sha256(browser_view["text"].encode())}
                if browser_view["text"] != html_view["visible_text"]:
                    findings.append(Finding(
                        id="render-observer-divergence", category="render-observer-divergence", severity="medium",
                        materiality="potentially-material", start=None,end=None,
                        evidence={"html_projection":html_view["visible_text"],"html_projection_sha256":_sha256(html_view["visible_text"].encode()),
                                  "browser_inner_text":browser_view["text"],"browser_inner_text_sha256":browser_view["sha256"],
                                  "observer":browser_view.get("observer")},
                        explanation="Deterministic HTML visibility analysis and actual browser-rendered innerText disagree."
                    ))
        if html_view["hidden_fragments"] or html_view.get("hidden_attributes"):
            findings.append(Finding(
                id="html-hidden-content", category="hidden-html-css", severity="high", materiality="material",
                start=None,end=None,evidence={"fragments":html_view["hidden_fragments"], "hidden_attributes": html_view.get("hidden_attributes", [])},
                explanation="HTML contains text suppressed by markup or CSS while remaining present in the source representation."
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
        "tokenizer": {"available":False,"name":None,"reason":"not-supplied"},
    }
    if tokenizer is not None:
        model_view["tokenizer"]=observe_tokenizer(text,tokenizer,name=tokenizer_name)

    material = [f for f in findings if f.materiality in {"material","potentially-material"}]
    semantic={
        "human_visible_text": visible,
        "machine_received_text": text,
        "decoded_hidden_text": [x["decoded"] for x in tag_runs] + (
            [x["text"] for x in html_view["hidden_fragments"]] + [x["text"] for x in html_view.get("hidden_attributes", [])]
            if html_view else []
        ),
        "material_divergence": bool(material),
        "basis": sorted({f.category for f in material}),
    }


    observer_texts={
        "machine":text,
        "human_projection":visible,
        "nfc":nfc,
        "nfkc":nfkc,
        "tag_stripped":tag_stripped,
        "confusable_skeleton":skeleton,
    }
    if browser_view.get("available") and isinstance(browser_view.get("text"),str):
        observer_texts["browser_inner_text"]=browser_view["text"]
    pairwise=compare_text_views(observer_texts)
    finding_dicts=[f.to_dict() for f in sorted(findings, key=lambda x:x.id)]
    radial_assessment=assess_representation_divergence(pairwise, finding_dicts)

    result={
        "schema":SCHEMA_VERSION,"engine_version":ENGINE_VERSION,
        "input":{"content_type":content_type,"byte_length":len(raw),"char_length":len(text),"sha256":_sha256(raw)},
        "views":{
            "raw_bytes":{"encoding":"utf-8","hex":raw.hex()},
            "unicode":{"codepoints":codepoints},
            "human_visible":{"text":visible,"sha256":_sha256(visible.encode())},
            "normalized":{"nfc":nfc,"nfkc":nfkc,"nfc_sha256":_sha256(nfc.encode()),"nfkc_sha256":_sha256(nfkc.encode())},
            "model_facing":model_view,
            "browser_render":browser_view,
            "pairwise_divergence":{"comparisons":pairwise},
            "radial_assessment":radial_assessment,
            "semantic":semantic,
            "hidden":hidden_projection,
            "lineage":provenance or {},
            "tag_stripped":{"text":tag_stripped,"sha256":_sha256(tag_stripped.encode())},
            "confusable":{"skeleton":skeleton,"sha256":_sha256(skeleton.encode()),"script_families":scripts,
                          "mapping_scope":"full-pinned-uts39","uts39_version":UTS39_VERSION,
                          "uts39_confusables_sha256":UTS39_CONFUSABLES_SHA256},
        },
        "summary":{
            "finding_count":len(findings),"severity":_severity(findings),
            "material_divergence":bool(material),"categories":sorted({f.category for f in findings}),
            "radial_disposition":radial_assessment["disposition"],
            "radial_material_divergence":radial_assessment["material_divergence"],
            "radial_boundaries":radial_assessment["boundaries"],
        },
        "findings":finding_dicts,
    }
    result["receipt"]={"canonical_json_sha256":_canonical_hash(result)}
    return result


def analyze_bytes(data: bytes, **kwargs) -> dict:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")
    data=bytes(data)
    try:
        text=data.decode("utf-8")
    except UnicodeDecodeError as e:
        finding=Finding(
            "invalid-utf8","invalid-utf8","high","material",e.start,e.end,
            {"reason":str(e),"offending_hex":data[e.start:e.end].hex()},
            "Input bytes are not valid UTF-8 and therefore can be interpreted differently across consumers."
        ).to_dict()
        result={
            "schema":SCHEMA_VERSION,"engine_version":ENGINE_VERSION,
            "input":{"content_type":kwargs.get("content_type","application/octet-stream"),"byte_length":len(data),"sha256":_sha256(data)},
            "views":{"raw_bytes":{"encoding":"unknown/invalid-utf8","hex":data.hex()}},
            "summary":{"finding_count":1,"severity":"high","material_divergence":True,"categories":["invalid-utf8"]},
            "findings":[finding],
        }
        result["receipt"]={"canonical_json_sha256":_canonical_hash(result)}
        return result
    return analyze(text, **kwargs)
