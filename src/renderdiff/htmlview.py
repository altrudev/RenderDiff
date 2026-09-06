from __future__ import annotations
from html.parser import HTMLParser
from dataclasses import dataclass
import re

HIDDEN_DECL = re.compile(r"(?:^|;)\s*(?:display\s*:\s*none\b|visibility\s*:\s*hidden\b|opacity\s*:\s*0(?:\.0+)?\b|font-size\s*:\s*0(?:px|em|rem|%)?\b|color\s*:\s*transparent\b|text-indent\s*:\s*-\d|(?:left|top)\s*:\s*-\d{3,})", re.I)
RULE_RE = re.compile(r"([^{}]+)\{([^{}]+)\}", re.S)

@dataclass
class HiddenFragment:
    text: str
    reason: str
    tag: str


def _hidden_selectors(css: str) -> set[str]:
    out=set()
    for selectors, decl in RULE_RE.findall(css):
        if not HIDDEN_DECL.search(";"+decl):
            continue
        for sel in selectors.split(','):
            sel=sel.strip()
            # MVP supports simple .class and #id selectors only; complex browser CSS stays out of scope.
            if re.fullmatch(r"[.#][A-Za-z_][\w-]*", sel): out.add(sel)
    return out

class StyleCollector(HTMLParser):
    def __init__(self): super().__init__(convert_charrefs=True); self.in_style=False; self.css=[]
    def handle_starttag(self,tag,attrs):
        if tag.lower()=="style": self.in_style=True
    def handle_endtag(self,tag):
        if tag.lower()=="style": self.in_style=False
    def handle_data(self,data):
        if self.in_style: self.css.append(data)

class VisibilityParser(HTMLParser):
    def __init__(self, hidden_selectors: set[str]):
        super().__init__(convert_charrefs=True)
        self.hidden_selectors=hidden_selectors
        self.stack: list[tuple[str,bool,str]]=[]
        self.visible=[]; self.hidden=[]; self.comments=[]; self.hidden_attributes=[]

    def handle_starttag(self, tag, attrs):
        d={k.lower():(v or "") for k,v in attrs}
        reasons=[]; style=d.get("style","")
        if "hidden" in d: reasons.append("hidden-attribute")
        if d.get("aria-hidden","").lower()=="true": reasons.append("aria-hidden")
        if tag.lower() in {"script","style","template","noscript"}: reasons.append(f"non-visible-{tag.lower()}")
        if HIDDEN_DECL.search(";"+style): reasons.append("css-hidden-inline")
        if d.get("id") and ("#"+d["id"]) in self.hidden_selectors: reasons.append("css-hidden-style-id")
        classes=d.get("class","").split()
        if any(("."+c) in self.hidden_selectors for c in classes): reasons.append("css-hidden-style-class")
        if tag.lower()=="input" and d.get("type","").lower()=="hidden" and "value" in d:
            self.hidden_attributes.append({"tag":"input","attribute":"value","text":d["value"],"reason":"hidden-input"})
        parent_hidden=self.stack[-1][1] if self.stack else False
        is_hidden=parent_hidden or bool(reasons)
        reason=",".join(reasons) if reasons else (self.stack[-1][2] if parent_hidden and self.stack else "")
        self.stack.append((tag.lower(),is_hidden,reason))

    def handle_startendtag(self, tag, attrs): self.handle_starttag(tag,attrs); self.handle_endtag(tag)
    def handle_endtag(self, tag):
        if self.stack: self.stack.pop()
    def handle_data(self,data):
        if not data: return
        if self.stack and self.stack[-1][1]: self.hidden.append(HiddenFragment(data,self.stack[-1][2] or "hidden-ancestor",self.stack[-1][0]))
        else: self.visible.append(data)
    def handle_comment(self,data): self.comments.append(data)


def inspect_html(html: str) -> dict:
    c=StyleCollector(); c.feed(html); selectors=_hidden_selectors("".join(c.css))
    p=VisibilityParser(selectors); p.feed(html)
    return {
        "visible_text":"".join(p.visible),
        "hidden_fragments":[f.__dict__ for f in p.hidden if f.text.strip()],
        "hidden_attributes":p.hidden_attributes,
        "comments":p.comments,
        "hidden_css_selectors":sorted(selectors),
    }
