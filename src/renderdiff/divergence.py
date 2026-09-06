from __future__ import annotations
import hashlib

def _sha(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def compare_text_views(views: dict[str, str | None]) -> list[dict]:
    """Deterministic pairwise comparison of observer text views."""
    names=sorted(k for k,v in views.items() if isinstance(v,str))
    out=[]
    for i,left in enumerate(names):
        for right in names[i+1:]:
            a=views[left]; b=views[right]
            out.append({
                'left':left,'right':right,'equal':a==b,
                'left_sha256':_sha(a),'right_sha256':_sha(b),
                'left_length':len(a),'right_length':len(b),
            })
    return out
