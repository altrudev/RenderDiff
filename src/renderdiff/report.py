from __future__ import annotations

def human_report(result: dict) -> str:
    s=result["summary"]
    lines=[
        "RenderDiff Assurance Report",
        f"Schema: {result.get('schema')}",
        f"Engine: {result.get('engine_version')}",
        f"Severity: {s['severity'].upper()}",
        f"Material divergence: {'YES' if s['material_divergence'] else 'NO'}",
        f"Assurance disposition: {s.get('assurance_disposition', 'not-evaluated')}",
        "A clean result applies only to performed observers; unavailable checks are not safety evidence.",
        f"Findings: {s['finding_count']}",
        "",
        "Human-visible representation:",
        result.get("views",{}).get("human_visible",{}).get("text", "<unavailable>"),
        "",
        "Findings:"
    ]
    if not result.get("findings"):
        lines.append("- None")
    for f in result.get("findings",[]):
        loc="" if f.get("start") is None else f" at [{f['start']}:{f['end']}]"
        lines.append(f"- [{f['severity'].upper()}] {f['category']}{loc}: {f['explanation']}")
        ev=f.get("evidence",{})
        if "codepoint" in ev:
            lines.append(f"  Evidence: {ev['codepoint']} {ev.get('name','')}")
        if "decoded" in ev:
            lines.append(f"  Decoded hidden payload: {ev['decoded']!r}")
        if "fragments" in ev:
            for frag in ev["fragments"]:
                lines.append(f"  Hidden HTML: {frag.get('text')!r} ({frag.get('reason')})")
    receipt=result.get("receipt",{}).get("canonical_json_sha256")
    if receipt:
        lines += ["", f"Canonical report SHA-256: {receipt}"]
    return "\n".join(lines)+"\n"
