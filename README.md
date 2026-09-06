# RenderDiff

**Representation-divergence assurance for text and HTML.**

RenderDiff asks a simple question that ordinary Unicode scanners do not:

> **What does the human think this says, what does the machine actually receive, and is the difference material?**

The same evidence can have materially different representations across bytes, Unicode code points, rendering, normalization, model-facing text, hidden content, and provenance. RenderDiff compares those representations and emits deterministic evidence explaining the divergence.

## Status

RenderDiff v0.1.0 is an MVP. It is suitable for experimentation, CI checks, assurance workflows, and integration testing. It is **not** a complete implementation of Unicode TR39 and should not be represented as one.

## What it detects

- zero-width and invisible Unicode
- Unicode tag characters and tag-encoded ASCII-smuggling patterns
- suspicious homoglyph/confusable substitutions
- bidirectional controls and reordering hazards
- normalization-sensitive representation changes
- hidden HTML/CSS text when HTML is supplied
- watermark-like hidden text patterns without assuming a particular vendor
- representation divergence with exact evidence rather than only a score

RenderDiff deliberately suppresses or contextualizes known benign constructs such as emoji ZWJ sequences and legitimate Unicode subdivision-flag tag sequences.

## Assurance views

The MVP reasons across these public views:

1. raw bytes
2. Unicode/codepoint representation
3. human-visible representation
4. normalized text
5. model-facing representation where practical
6. semantic/materiality interpretation
7. hidden/invisible-content representation
8. lineage/provenance supplied by the caller

This is the public assurance boundary. Proprietary DDC radial-frequency internals are not included or required.

## Install

```bash
python -m pip install -e .
```

Requires Python 3.10+.

## CLI

Analyze text:

```bash
renderdiff "pay example.com"
```

JSON output:

```bash
renderdiff --json "pay example.com"
```

Analyze a file:

```bash
renderdiff --file suspicious.txt --json
```

Analyze HTML:

```bash
renderdiff --html --file page.html
```

## Library

```python
from renderdiff import analyze

receipt = analyze("safe\u200btext")
print(receipt["disposition"])
print(receipt["findings"])
```

## DDCAL integration

`renderdiff.api.assure()` provides a deliberately small public API boundary suitable for `ddcal.ca`.

RenderDiff can appear in:

- **Services → Representation Divergence Assurance**
- **Try DDC → RenderDiff**

Recommended result presentation:

- Human View
- Machine View
- Divergence Evidence
- Materiality
- Exact codepoints / byte positions
- Deterministic receipt hash

See [`docs/DDCAL-INTEGRATION.md`](docs/DDCAL-INTEGRATION.md).

## Philosophy

RenderDiff is not intended to label every unusual character malicious. A zero-width joiner can be essential to an emoji. Unicode tag characters have legitimate standardized uses. Internationalized text naturally contains scripts that resemble Latin characters.

The engine therefore separates:

**observation → divergence → context → materiality**

That ordering is important for reducing false positives and for producing evidence that another system can independently inspect.

## Unicode confusables

The MVP includes a compact deterministic mapping for high-risk confusable examples used by its assurance rules and tests. Full Unicode confusable coverage should use a pinned copy of the official Unicode `confusables.txt` dataset, with Unicode version and SHA-256 recorded as provenance.

Until that dataset is vendored and verified, RenderDiff must not claim full TR39 confusable coverage.

## Testing

```bash
python -m unittest discover -s tests -v
```

The MVP test corpus includes benign and adversarial cases covering invisible characters, tag smuggling, bidi controls, confusables, normalization, hidden HTML/CSS, emoji ZWJ sequences, legitimate tag-based flags, deterministic output, and the DDCAL API boundary.

## Security model

RenderDiff is an **assurance engine**, not a sanitizer. It reports what it observes and why representations diverge. Applications should make their own policy decision from the evidence.

Do not silently rewrite hostile input and then treat the rewritten version as the original evidence.

## License

Apache-2.0.

---

RenderDiff is part of the DDC / DDC Assurance Lab ecosystem: <https://ddcal.ca>.
