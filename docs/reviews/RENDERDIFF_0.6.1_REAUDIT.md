# RenderDiff v0.6.1 independent re-audit

This is a development assurance record, not a claim of perfect software, private DDC-kernel certification, independent security certification, or production authorization.

## Defects corrected

The audit corrected a document CLI isolation bypass, ignored observer options, inconsistent materiality exit policy, stale engine version, spoofable browser DOM marker, misleading model-input scope, token/report amplification limits, an unrelated-finding materiality promotion, malformed UTF-8 assessment failure, unsafe file/symlink handling, SARIF source positions, worker cancellation capacity, and a ZIP/Office magic-byte regression exposed only by clean-wheel testing. The full-evidence engine now has explicit resource ceilings and fails closed instead of issuing partial clean results.

## Verified development scope

The rebuilt wheel is tested in isolated installations on CPython 3.10–3.14. The test suite contains 86 tests, including real Chromium, PDF/OOXML extraction, namespace confinement, receipts, exports, CLI/API, tokenizer, materiality, malformed evidence, and resource-boundary regressions. Package distributions and the installed-wheel matrix are validated locally without GitHub Actions. The source-bound qualification record contains the exact revision, manifest, wheel hash, dependency audit, static findings and repeated adversarial cases.

## Limitations and pending gates

The human-visible view is a projection, not guaranteed visual perception. OCR is not configured; PDF and Office extraction is text-only. Semantic and model-behavior observations are advisory; provider-internal preprocessing cannot be inferred from submitted requests. The full-evidence engine is bounded to 64,000 characters / 256,000 bytes, 10,000 findings, and an 8 MB report. Larger evidence requires separate coverage-aware streaming. The local API is not a production multi-user identity, quota, or worker-isolation service. Independent security review, production cgroups/egress, TLS/privacy/retention and shared quotas, configured model-provider validation, DDCAL deployment and owner approval remain pending.

The audit makes no claim that RenderDiff detects all attacks, all watermark types, or proves malicious intent or authorship. A clean result applies only to performed observers. No proprietary DDC scoring or authority routing is included.
