from __future__ import annotations
from pathlib import Path
import hashlib
import unicodedata

# Stable security data baseline as verified on 2026-09-06.
# Unicode 18.0 security data was still served from /Public/draft at validation time.
UTS39_VERSION = "17.0.0"
UTS39_CONFUSABLES_URL = "https://www.unicode.org/Public/17.0.0/security/confusables.txt"
UTS39_CONFUSABLES_SHA256 = "091c7f82fc39ef208faf8f94d29c244de99254675e09de163160c810d13ef22a"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_pinned_confusables(data: bytes) -> None:
    actual=sha256_bytes(data)
    if actual != UTS39_CONFUSABLES_SHA256:
        raise ValueError(
            f"UTS39 confusables checksum mismatch: expected {UTS39_CONFUSABLES_SHA256}, got {actual}"
        )


def parse_confusables(data: bytes, *, expected_sha256: str | None = None) -> dict[str,str]:
    """Parse Unicode confusables.txt into source-character -> prototype mappings.

    RenderDiff deliberately rejects multi-codepoint source entries rather than silently
    implementing a different matching algorithm. Current UTS data is expected to use
    single-codepoint sources for this mapping form.
    """
    if expected_sha256 is not None:
        actual=sha256_bytes(data)
        if actual != expected_sha256:
            raise ValueError(f"confusables checksum mismatch: expected {expected_sha256}, got {actual}")

    mapping: dict[str,str]={}
    text=data.decode("utf-8")
    for lineno,line in enumerate(text.splitlines(),1):
        body=line.split("#",1)[0].strip()
        if not body:
            continue
        parts=[p.strip() for p in body.split(";")]
        if len(parts) < 2:
            raise ValueError(f"invalid confusables line {lineno}")
        source_cps=[int(x,16) for x in parts[0].split()]
        target_cps=[int(x,16) for x in parts[1].split()]
        if len(source_cps) != 1:
            raise ValueError(f"unsupported multi-codepoint confusable source at line {lineno}")
        mapping[chr(source_cps[0])]="".join(chr(cp) for cp in target_cps)
    return mapping


def load_pinned_confusables(path: str | Path) -> dict[str,str]:
    data=Path(path).read_bytes()
    verify_pinned_confusables(data)
    return parse_confusables(data)


def uts39_skeleton(text: str, mapping: dict[str,str]) -> str:
    """UTS #39-style skeleton core: NFD -> confusable mapping -> NFD.

    Restriction-level and Script_Extensions policy are separate concerns and are not
    claimed by this helper.
    """
    nfd=unicodedata.normalize("NFD", text)
    mapped="".join(mapping.get(ch,ch) for ch in nfd)
    return unicodedata.normalize("NFD", mapped)
