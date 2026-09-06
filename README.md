# RenderDiff

**Representation-divergence assurance for text and HTML.**

RenderDiff asks one question:

> What does the human think this says, what does the machine actually receive, and is the difference material?

It is not a Unicode blacklist. It builds multiple deterministic views of the same evidence and reports exact divergences.

## v0.2 capabilities

- raw UTF-8 byte view + SHA-256
- Unicode/codepoint inventory
- human-visible projection
- NFC/NFKC normalization comparison
- model-facing exact-text hash + lexical units + optional tokenizer adapter
- hidden/invisible character evidence
- Unicode Tag decoding / ASCII-smuggling evidence
- exact validation of the standardized England/Scotland/Wales subdivision-tag sequences
- bidi-control and direction-mark evidence
- full pinned UTS #39 homoglyph/confusable skeleton
- optional UTS #39 confusables loader with a cryptographically pinned stable Unicode data baseline
- vendor-neutral watermark/steganographic hidden-carrier pattern evidence
- HTML hidden-content detection for `hidden`, `aria-hidden`, common CSS hiding, classes/IDs, and hidden input values
- separation of ordinary non-rendered HTML source from presentation-hidden user content
- bounded DDCAL-facing request API
- provenance passthrough with deterministic JSON validation
- deterministic receipts for valid UTF-8 and invalid-byte evidence
- human-readable report
- CLI and Python API

## v0.3 observer expansion

RenderDiff v0.3.0 adds:

- full pinned Unicode UTS #39 17.0.0 confusables data as the default skeleton source
- SHA-256 provenance for the Unicode confusables dataset
- deterministic pairwise comparison across machine, human projection, normalized, tag-stripped, confusable-skeleton, and browser views
- optional real Chromium `body.innerText` observation for HTML
- explicit render-observer divergence findings when heuristic and browser views disagree
- tokenizer observer metadata plus optional tiktoken and SentencePiece adapters
- a DDCAL API boundary where browser execution must be explicitly configured and requested

The browser observer is intentionally not automatic. Active HTML is executed only when the host enables that observer, and high-assurance deployments should run Chromium inside their own OS/container sandbox.

## v0.4 radial materiality

RenderDiff v0.4 adds an evidence-backed representation-boundary layer above raw observer mismatch. Pairwise differences are now localized and then classified by the boundary they cross:

- `visibility`: machine source versus human-visible projection
- `rendering`: deterministic HTML projection versus browser `innerText`
- `hidden-tag`: machine source versus Unicode-Tag-stripped text
- `normalization`: machine source versus NFKC-normalized text
- `identity`: machine source versus UTS #39 confusable skeleton

A mismatch is **not** promoted merely because two strings differ. The radial assessment links a divergent observer edge to detector findings relevant to that boundary and reports one of `none`, `context-dependent`, `potentially-material`, or `material`. The report includes the exact supporting finding IDs and localized delta evidence.

This is a public, deterministic assurance layer. It does not expose proprietary DDC scoring, routing, policy, or radial-frequency internals.

## Install locally

```bash
python -m pip install -e .
```

Requires Python 3.10+.

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

The public API bounds text and provenance sizes because exact byte/codepoint evidence can amplify output. The public package contains assurance outputs only. It does not expose proprietary DDC scoring, routing, radial-frequency internals, or policy logic.

## Unicode security data

RenderDiff v0.2 pins its reproducible UTS #39 baseline to the stable Unicode 17.0.0 `confusables.txt` data:

- source: `https://www.unicode.org/Public/17.0.0/security/confusables.txt`
- SHA-256: `091c7f82fc39ef208faf8f94d29c244de99254675e09de163160c810d13ef22a`

Fetch and verify it with:

```bash
PYTHONPATH=src python tools/fetch_uts39.py
```

The loader fails closed if the downloaded bytes do not match the pinned digest. RenderDiff does not silently follow a moving `latest` URL. At the v0.2 validation date (2026-09-06), Unicode 18.0 security data was still served from the Unicode draft directory, so RenderDiff stayed on the stable 17.0 data baseline.

The default engine still uses a compact built-in mapping unless a caller loads and supplies the full mapping. This distinction is intentional: RenderDiff must not claim full UTS #39 coverage when the full dataset is not actually in use.

## What is novel

RenderDiff does **not** claim invention of Unicode confusable detection, zero-width detection, bidi detection, or ASCII-smuggling detection. Those primitives already exist in Unicode UTS #39 and multiple open-source scanners.

The contribution is the assurance composition:

1. represent the same evidence through multiple observer views;
2. compare those views rather than simply enumerate suspicious characters;
3. separate *presence* from *material divergence*;
4. preserve exact evidence and hashes;
5. expose a deterministic receipt suitable for CI, APIs, and assurance workflows.

## DDC hardening snapshot

The v0.2 branch was adversarially exercised on 2026-09-06 with:

- 24 targeted unit/regression tests;
- 3,000 randomized Unicode/control-character mutation cases;
- 1,000 randomized byte-input cases;
- repeated byte-for-byte determinism checks;
- live retrieval and SHA-256 verification of the pinned Unicode 17.0 confusables file.

The DDC pass closed concrete defects including a BLACK FLAG prefix bypass for arbitrary Unicode Tag payloads, HTML void-element visibility-state leakage, ordinary `<style>` source being confused with deliberately hidden text, incomplete bidi-mark evidence, missing dedicated watermark-like carrier evidence, and unbounded/non-serializable public API inputs.

## Current limits

- Full UTS #39 mappings are supported through the pinned loader but are not bundled into the default in-memory mapping yet.
- HTML visibility analysis is a deterministic source-level model; it does not execute browser layout, linked stylesheets, JavaScript, shadow DOM, canvas, or accessibility-tree computation.
- The default model-facing view is tokenizer-independent. Callers can supply a tokenizer adapter for exact model tokens.
- Semantic interpretation is deterministic and evidence-based; it is not an LLM judgment.
- "AI watermark" is not asserted from hidden Unicode alone. RenderDiff reports hidden carrier patterns and evidence without claiming vendor, authorship, or malicious intent.

## License

Apache-2.0.
