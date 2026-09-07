# RenderDiff

**Representation-divergence assurance for text, documents and HTML.**

> What does the human think this says, what does the machine actually receive, and is the difference material?

RenderDiff is an open-source, evidence-first tool in the DDC/DDCAL ecosystem. It is not a Unicode blacklist, a malware scanner, an AI-watermark attribution service, or an accredited laboratory certificate. It compares representations, preserves exact evidence, and separates observable differences from claims about meaning, intent or authority.

## Status

The v0.6.0 beta candidate adds document ingestion, isolated browser observation, model/semantic observer interfaces, a local web service, portable evidence bundles, signed receipt support, report exports and CI integration. It is undergoing review and is **not a production-certified v1.0 release**. The existing v0.4 engine and public API remain available. No proprietary DDC scoring, policy, authority routing or radial-frequency internals are published.

### What is implemented

- Original UTF-8 bytes, codepoint inventory, hashes, visible projection, NFC/NFKC normalization and exact divergence edges.
- Pinned Unicode 17.0 UTS #39 confusables data, Unicode Tag decoding, ASCII-smuggling evidence, bidi controls, hidden carriers and HTML visibility analysis.
- Evidence-linked radial boundaries for visibility, rendering, normalization, hidden tags and confusable identity, with explicit materiality dispositions.
- Optional real tokenizer comparisons and exact model-input observation; paired model-response probes and evidence-span-validated advisory semantic observers.
- Static HTML inspection plus opt-in networkless Chromium and Playwright observers for DOM, computed styles, accessibility, open shadow roots and canvas metadata.
- Bounded text, PDF and selected DOCX/XLSX/PPTX extraction with original-source lineage. Production document extraction uses an isolated Linux worker.
- Opt-in public HTTPS/HTTP acquisition with DNS pinning, redirect checks, no proxy use and public-address restrictions. The public service does not enable arbitrary URL fetching.
- Deterministic JSON receipts, original-byte evidence bundles, optional detached Ed25519 signatures, and HTML, SARIF and PDF report exports.
- Local web UI/API, CLI, packaged repository scanner, pre-commit integration and an opt-in reusable GitHub composite action.

## Install

Python 3.10–3.14 are supported by the current local release matrix. The full 69-test suite has passed on each interpreter after correcting the isolated-runtime mapping. See `docs/RELEASE_GATES.md` for the exact scope and remaining production gates.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
# Optional capabilities:
python -m pip install -e '.[api,documents,models,crypto,browser,pdf]'
```

## Use from the command line

```bash
printf 'pay\u200bment' | renderdiff
printf 'pay\u200bment' | renderdiff --json
renderdiff --file sample.html --html --fail-on-material
renderdiff --file document.pdf --format json --output report.json
renderdiff --text 'microsоft.com' --format pdf --output report.pdf
renderdiff --file sample.txt --format sarif --output report.sarif
renderdiff --verify report.json
renderdiff --url https://example.com/ --allow-network --json
renderdiff --file sample.html --html --browser --json
renderdiff --text 'pay\u200bment' --tiktoken cl100k_base --json
```

`--fail-on-material` exits 2 when the legacy material/potentially-material gate is triggered. It does not mean that exit 0 certifies complete safety. The CLI's active browser path requires the Linux namespace sandbox. URL acquisition requires explicit network permission and a production egress boundary before use with untrusted users.

## Python API

```python
from renderdiff import analyze, analyze_request, acquire_file
from renderdiff.assurance import attach
from renderdiff.receipt import verify

report = attach(analyze('microsоft.com'))
assert verify(report)
report = analyze_request({'text': 'payment', 'content_type': 'text/plain'})
report = acquire_file('sample.txt')
```

The v0.6 assurance layer is additive. The original `renderdiff.assurance.v1` report shape remains available; `views.assurance` records observer coverage, materiality and unavailable channels. It does not silently convert unavailable observations into clean verdicts.

### Model-facing channels

```python
from renderdiff.modelview import compare_model_views
from renderdiff.tokenizers import tiktoken_adapter

encode, name = tiktoken_adapter('cl100k_base')
comparison = compare_model_views('pay\u200bment', 'payment', encode, name=name)
```

An exact token difference is not proof of semantic or behavioral divergence. Optional model probes require an explicitly authorized endpoint and model identity. The implementation does not discover API keys, download models, execute model-requested tools or automatically transmit evidence. See `docs/MODEL_OBSERVERS.md`.

## Local web interface

```bash
python -m pip install -e '.[api,documents,pdf]'
python -m uvicorn renderdiff.service:app --host 127.0.0.1 --port 8765
```

Configure `RENDERDIFF_API_TOKEN` first and open `http://127.0.0.1:8765/` on the same machine. Enter the credential in the session-only access field. See `docs/DEPLOYMENT.md` for the local startup and production requirements. The interface supports paste/upload, side-by-side views, findings and JSON/HTML/SARIF/PDF exports. The service is a local integration candidate, **not a claim that ddcal.ca has been deployed or updated**. Public deployment requires authentication, rate limits, TLS, privacy/retention controls, isolated workers, egress restrictions and a separate security review.

## Evidence integrity

```python
from renderdiff.bundle import create_bundle, verify_bundle
from renderdiff.receipt import seal, verify_seal

# Use the original bytes, not reconstructed extracted text.
source = b'pay\xe2\x80\x8bment'
report = attach(analyze(source.decode()))
bundle = create_bundle(report, source)
assert verify_bundle(bundle)
```

A SHA-256 receipt detects alteration relative to a trusted digest; it does not prove authorship. Detached Ed25519 signatures require separately managed trusted keys. The PDF is a readable derivative, not the canonical evidence. Source acquisition, extraction and normalization are recorded as distinct transformations.

## CI and validation

```bash
renderdiff-scan --fail-on-material --format sarif --output renderdiff.sarif sample.txt
python -m unittest discover -s tests -q
python tools/qualify_v05.py /tmp/renderdiff-qualification.json
```

The pre-commit configuration and `action.yml` are opt-in. No GitHub Actions workflow is enabled. The v0.5 candidate qualification on 2026-09-06 passed 60 integration/regression tests and 2,012 deterministic cases repeated twice. It is a public DDC-aligned qualification, not a private DDC certification. The production-release gate is pending. See `docs/V05.md` and `docs/CI.md`.

## Limits and security boundaries

Human-visible plain-text projection is heuristic; it cannot reproduce every font, rendering engine or accessibility configuration. Browser `innerText`, DOM, computed styles and accessibility observations are distinct from pixel-perfect visual perception. Canvas text, images and scanned PDFs require separately configured visual/OCR observers. Linked resources are blocked in the default browser sandbox. Office extraction covers selected text-bearing XML, not complete formatting, formulas, macros, embedded objects or layout. PDF extraction does not prove OCR coverage.

A generic tokenizer is not a model. Model behavior is not deterministic in all deployments, and an LLM judgment cannot establish authorization or prove the absence of prompt injection. Hidden Unicode alone cannot establish an AI watermark's origin. No general-purpose detector can guarantee that every semantic, visual or adversarial representation is understood.

The library has bounded input interfaces; the public service applies tighter limits and output-amplification checks. Streaming intake hashes incrementally but refuses evidence beyond its configured analysis limit rather than returning a partial clean verdict. Production URL and document processing require independent network/resource isolation. See `docs/V05.md` for coverage and pending release gates.

## License

Apache-2.0. RenderDiff is a public assurance component; private DDC implementation details and authority policies remain outside this repository.

## Release security and deployment

See `docs/SECURITY.md`, `docs/DEPLOYMENT.md`, and `docs/RELEASE_GATES.md`. The v0.6 beta includes authenticated local API access, bounded concurrency and hardened extraction/runtime isolation. Production multi-user identity, distributed quotas, external security review, configured model-provider validation and complete visual/OCR coverage remain explicit gates rather than implied guarantees.
