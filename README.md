# RenderDiff

**Representation-divergence assurance for text and HTML.**

RenderDiff asks one question:

> What does the human think this says, what does the machine actually receive, and is the difference material?

It is not a Unicode blacklist. It builds multiple deterministic views of the same evidence and reports exact divergences.

## MVP capabilities

- raw UTF-8 byte view + SHA-256
- Unicode/codepoint inventory
- human-visible projection
- NFC/NFKC normalization comparison
- model-facing exact-text hash + lexical units + optional tokenizer adapter
- hidden/invisible character evidence
- Unicode Tag decoding / ASCII-smuggling evidence
- bidi-control detection
- compact high-risk homoglyph/confusable skeleton
- HTML hidden-content detection for `hidden`, `aria-hidden`, common inline CSS hiding, and non-visible elements
- provenance passthrough
- deterministic JSON receipt hash
- human-readable report
- CLI and Python API

## Install locally

```bash
python -m pip install -e .
```

## CLI

```bash
printf 'pay\u200bment' | renderdiff
printf 'pay\u200bment' | renderdiff --json
renderdiff --file sample.html --html --fail-on-material
```

`--fail-on-material` exits with status 2 when a material or potentially-material divergence is present.

## Library

```python
from renderdiff import analyze
report = analyze("microsоft.com")  # Cyrillic 'о'
```

## DDCAL public boundary

```python
from renderdiff import analyze_request
report = analyze_request({
  "text": "...",
  "content_type": "text/plain",
  "provenance": {"source_url": "https://example.test"}
})
```

The public package contains assurance outputs only. It does not expose proprietary DDC scoring, routing, radial-frequency internals, or policy logic.

## What is novel

RenderDiff does **not** claim invention of Unicode confusable detection, zero-width detection, bidi detection, or ASCII-smuggling detection. Those primitives already exist in Unicode TR39 and multiple open-source scanners.

The proposed contribution is the assurance composition:

1. represent the same evidence through multiple observer views;
2. compare those views rather than simply enumerate suspicious characters;
3. separate *presence* from *material divergence*;
4. preserve exact evidence and hashes;
5. expose a deterministic receipt suitable for CI, APIs, and assurance workflows.

## Current MVP limits

- The bundled homoglyph mapping is intentionally compact, not full Unicode TR39. A production release should vendor/pin the Unicode `confusables.txt` dataset and record its version/hash.
- HTML visibility analysis handles markup and inline CSS heuristics; it does not execute browser layout, linked stylesheets, JavaScript, shadow DOM, or canvas rendering.
- The default model-facing view is tokenizer-independent. Callers can supply a tokenizer adapter for exact model tokens.
- Semantic interpretation is deterministic and evidence-based; it is not an LLM judgment.
- "AI watermark" is not asserted from hidden Unicode alone. RenderDiff reports hidden patterns and evidence without claiming vendor or authorship.

## License

Apache-2.0.
