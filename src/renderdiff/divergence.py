from __future__ import annotations
import hashlib


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _common_prefix(a: str, b: str) -> int:
    limit=min(len(a),len(b))
    i=0
    while i < limit and a[i] == b[i]:
        i += 1
    return i


def _common_suffix(a: str, b: str, prefix: int) -> int:
    # Never allow prefix/suffix accounting to overlap.
    max_suffix=min(len(a)-prefix,len(b)-prefix)
    i=0
    while i < max_suffix and a[len(a)-1-i] == b[len(b)-1-i]:
        i += 1
    return i


def _bounded_fragment(text: str, start: int, end: int, *, limit: int = 96) -> dict:
    length=end-start
    if length <= limit:
        fragment=text[start:end]
        return {"text":fragment,"truncated":False,"char_length":len(fragment)}
    head=limit//2
    tail=limit-head
    return {
        "text":text[start:start+head] + "…" + text[end-tail:end],
        "truncated":True,
        "char_length":length,
    }


def compare_text_views(views: dict[str, str | None]) -> list[dict]:
    """Deterministic pairwise comparison with bounded local divergence evidence.

    The comparison intentionally avoids edit-distance algorithms whose runtime can grow
    quadratically on large evidence. Instead it records exact hashes/lengths plus the
    longest common prefix and suffix, which localizes the changed middle region in O(n).
    """
    names=sorted(k for k,v in views.items() if isinstance(v,str))
    out=[]
    for i,left in enumerate(names):
        for right in names[i+1:]:
            a=views[left]
            b=views[right]
            equal=a==b
            prefix=_common_prefix(a,b)
            suffix=_common_suffix(a,b,prefix)
            left_end=len(a)-suffix if suffix else len(a)
            right_end=len(b)-suffix if suffix else len(b)
            record={
                "left":left,
                "right":right,
                "equal":equal,
                "relation":"agreement" if equal else "divergence",
                "left_sha256":_sha(a),
                "right_sha256":_sha(b),
                "left_length":len(a),
                "right_length":len(b),
                "length_delta":len(b)-len(a),
                "common_prefix_chars":prefix,
                "common_suffix_chars":suffix,
                "first_difference_index":None if equal else prefix,
            }
            if not equal:
                record["delta"]={
                    "left_range":{"start":prefix,"end":left_end},
                    "right_range":{"start":prefix,"end":right_end},
                    "left_fragment":_bounded_fragment(a,prefix,left_end),
                    "right_fragment":_bounded_fragment(b,prefix,right_end),
                }
            out.append(record)
    return out
