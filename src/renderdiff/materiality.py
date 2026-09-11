from __future__ import annotations

from typing import Iterable


_LEVEL = {
    "none": 0,
    "context-dependent": 1,
    "potentially-material": 2,
    "material": 3,
}

# Public assurance policy only: these are representation-boundary semantics,
# not proprietary DDC scoring/routing internals.
_BOUNDARIES = {
    frozenset(("machine", "human_projection")): (
        "visibility",
        {"invisible-unicode", "bidi-reordering", "ascii-smuggling", "hidden-html-css"},
    ),
    frozenset(("human_projection", "browser_inner_text")): (
        "rendering",
        {"render-observer-divergence", "hidden-html-css"},
    ),
    frozenset(("machine", "tag_stripped")): (
        "hidden-tag",
        {"ascii-smuggling", "unicode-tag-sequence"},
    ),
    frozenset(("machine", "nfkc")): (
        "normalization",
        {"normalization"},
    ),
    frozenset(("machine", "confusable_skeleton")): (
        "identity",
        {"confusable-homoglyph"},
    ),
}


def _finding_index(findings: Iterable[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for finding in findings:
        category = finding.get("category")
        if isinstance(category, str):
            out.setdefault(category, []).append(finding)
    return out


def _max_materiality(findings: Iterable[dict]) -> str:
    best = "none"
    for finding in findings:
        value = finding.get("materiality", "none")
        if value in _LEVEL and _LEVEL[value] > _LEVEL[best]:
            best = value
    return best


def assess_representation_divergence(pairwise: list[dict], findings: list[dict]) -> dict:
    """Classify evidence-bearing observer edges by representation boundary.

    Pairwise mismatch alone is not materiality. This function only promotes a
    divergence when it crosses a defined human/machine representation boundary
    and is supported by detector evidence relevant to that boundary.
    """
    by_category = _finding_index(findings)
    assessed: list[dict] = []

    for comparison in pairwise:
        key = frozenset((comparison.get("left"), comparison.get("right")))
        rule = _BOUNDARIES.get(key)
        if rule is None:
            continue

        boundary, categories = rule
        equal = bool(comparison.get("equal"))
        evidence_findings = [
            finding
            for category in sorted(categories)
            for finding in by_category.get(category, [])
        ]
        # A detector elsewhere in the source must not promote this edge.
        # The bounded changed-middle interval is conservative: it can contain
        # unchanged material when there are multiple disjoint edits. Findings
        # without source coordinates are retained as global evidence, not
        # incorrectly assigned a fabricated location.
        delta = comparison.get("delta") or {}
        source_side = "left" if comparison.get("left") == "machine" else (
            "right" if comparison.get("right") == "machine" else None
        )
        source_range = delta.get(source_side + "_range") if source_side else None
        if not equal and isinstance(source_range, dict):
            start, end = source_range.get("start"), source_range.get("end")
            if type(start) is int and type(end) is int and start <= end:
                evidence_findings = [
                    finding for finding in evidence_findings
                    if not (type(finding.get("start")) is int and type(finding.get("end")) is int)
                    or (finding["start"] < end and finding["end"] > start)
                ]
        equal = bool(comparison.get("equal"))
        detector_materiality = _max_materiality(evidence_findings)

        # An observer agreement cannot itself be a divergent edge. A mismatch
        # with no relevant detector evidence remains observable but unpromoted.
        if equal:
            disposition = "none"
        elif detector_materiality != "none":
            disposition = detector_materiality
        else:
            disposition = "context-dependent"

        assessed.append({
            "left": comparison.get("left"),
            "right": comparison.get("right"),
            "boundary": boundary,
            "relation": "agreement" if equal else "divergence",
            "materiality": disposition,
            "evidence_categories": sorted({
                finding.get("category") for finding in evidence_findings
                if isinstance(finding.get("category"), str)
            }),
            "finding_ids": sorted({
                finding.get("id") for finding in evidence_findings
                if isinstance(finding.get("id"), str)
            }),
            "first_difference_index": comparison.get("first_difference_index"),
            "delta": comparison.get("delta") if not equal else None,
        })

    divergent = [edge for edge in assessed if edge["relation"] == "divergence"]
    strongest = "none"
    for edge in divergent:
        value = edge["materiality"]
        if _LEVEL[value] > _LEVEL[strongest]:
            strongest = value

    material_edges = [
        edge for edge in divergent
        if edge["materiality"] in {"material", "potentially-material"}
    ]
    return {
        "disposition": strongest,
        "material_divergence": bool(material_edges),
        "assessed_edge_count": len(assessed),
        "divergent_edge_count": len(divergent),
        "material_edge_count": len(material_edges),
        "boundaries": sorted({edge["boundary"] for edge in divergent}),
        "edges": assessed,
    }
