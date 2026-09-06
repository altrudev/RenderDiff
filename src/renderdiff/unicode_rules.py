from __future__ import annotations
import unicodedata

# Compact high-risk confusable subset for MVP. Full UTS #39 mappings can be injected by caller.
CONFUSABLES = {
    # Cyrillic -> Latin
    "а":"a","А":"A","е":"e","Е":"E","о":"o","О":"O","р":"p","Р":"P",
    "с":"c","С":"C","у":"y","У":"Y","х":"x","Х":"X","і":"i","І":"I",
    "ј":"j","Ј":"J","ѕ":"s","Ѕ":"S","ԁ":"d","Ԍ":"G",
    # Greek -> Latin
    "Α":"A","Β":"B","Ε":"E","Ζ":"Z","Η":"H","Ι":"I","Κ":"K","Μ":"M",
    "Ν":"N","Ο":"O","Ρ":"P","Τ":"T","Υ":"Y","Χ":"X",
    "α":"a","β":"b","ι":"i","κ":"k","ο":"o","ρ":"p","τ":"t","υ":"u","χ":"x",
    # common compatibility/fullwidth forms
    "０":"0","１":"1","２":"2","３":"3","４":"4","５":"5","６":"6","７":"7","８":"8","９":"9",
    "Ａ":"A","Ｂ":"B","Ｃ":"C","Ｄ":"D","Ｅ":"E","Ｆ":"F","Ｇ":"G","Ｈ":"H","Ｉ":"I","Ｊ":"J",
    "Ｋ":"K","Ｌ":"L","Ｍ":"M","Ｎ":"N","Ｏ":"O","Ｐ":"P","Ｑ":"Q","Ｒ":"R","Ｓ":"S","Ｔ":"T",
    "Ｕ":"U","Ｖ":"V","Ｗ":"W","Ｘ":"X","Ｙ":"Y","Ｚ":"Z",
    "ａ":"a","ｂ":"b","ｃ":"c","ｄ":"d","ｅ":"e","ｆ":"f","ｇ":"g","ｈ":"h","ｉ":"i","ｊ":"j",
    "ｋ":"k","ｌ":"l","ｍ":"m","ｎ":"n","ｏ":"o","ｐ":"p","ｑ":"q","ｒ":"r","ｓ":"s","ｔ":"t",
    "ｕ":"u","ｖ":"v","ｗ":"w","ｘ":"x","ｙ":"y","ｚ":"z",
}

# Explicit controls/marks that can change bidi presentation or direction context.
BIDI_STRONG_CONTROLS = {
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,  # embeddings/overrides/PDF
    0x2066, 0x2067, 0x2068, 0x2069,          # isolates/PDI
}
BIDI_DIRECTION_MARKS = {0x061C, 0x200E, 0x200F}  # ALM, LRM, RLM
BIDI_CLASSES = {"RLO","LRO","RLE","LRE","PDF","RLI","LRI","FSI","PDI"}

ZERO_WIDTH = {0x200B,0x200C,0x200D,0x2060,0xFEFF}
SPECIAL_INVISIBLES = {0x00AD,0x034F,0x061C,0x180E,0x200E,0x200F}
TAG_START, TAG_END = 0xE0000, 0xE007F
VARIATION_RANGES = [(0xFE00,0xFE0F),(0xE0100,0xE01EF)]
STANDARD_SUBDIVISION_TAGS = {"gbeng", "gbsct", "gbwls"}


def cp_name(ch: str) -> str:
    return unicodedata.name(ch, "UNNAMED")


def is_tag(cp: int) -> bool:
    return TAG_START <= cp <= TAG_END


def is_variation(cp: int) -> bool:
    return any(a <= cp <= b for a,b in VARIATION_RANGES)


def is_invisible(ch: str) -> bool:
    cp = ord(ch)
    cat = unicodedata.category(ch)
    return (
        cp in ZERO_WIDTH or cp in SPECIAL_INVISIBLES or is_tag(cp) or is_variation(cp)
        or cat == "Cf" or (cat == "Cc" and cp not in {0x09, 0x0A, 0x0D})
    )


def is_bidi_control(ch: str) -> bool:
    cp = ord(ch)
    return cp in BIDI_STRONG_CONTROLS or cp in BIDI_DIRECTION_MARKS


def bidi_control_strength(ch: str) -> str:
    return "strong" if ord(ch) in BIDI_STRONG_CONTROLS else "mark"


def script_family(ch: str) -> str | None:
    """Small deterministic script classifier for spoof materiality.

    Common/Inherited characters deliberately return None so punctuation, digits,
    combining marks and emoji do not manufacture a mixed-script finding.
    This is not a replacement for UCD Script_Extensions.
    """
    if not ch.isalpha():
        return None
    name = unicodedata.name(ch, "")
    if name.startswith("LATIN "):
        return "Latin"
    if name.startswith("CYRILLIC "):
        return "Cyrillic"
    if name.startswith("GREEK "):
        return "Greek"
    if name.startswith(("HIRAGANA ", "KATAKANA ")):
        return "Japanese"
    if name.startswith("HANGUL "):
        return "Korean"
    if name.startswith("CJK ") or "IDEOGRAPH" in name:
        return "Han"
    if name.startswith("HEBREW "):
        return "Hebrew"
    if name.startswith("ARABIC "):
        return "Arabic"
    if name.startswith("DEVANAGARI "):
        return "Devanagari"
    return "Other"


def script_families(text: str) -> list[str]:
    return sorted({s for ch in text if (s := script_family(ch)) is not None})


def confusable_skeleton(text: str, extra: dict[str,str] | None = None) -> str:
    mapping = CONFUSABLES if not extra else {**CONFUSABLES, **extra}
    return "".join(mapping.get(ch, ch) for ch in text)
