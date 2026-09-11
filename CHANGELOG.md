# Changelog

## v0.6.1 beta — 2026-09-10

Current public beta on `main`.

### What changed
- Consolidated the representation-divergence engine, radial materiality layer, document/HTML acquisition, browser observers, model/tokenizer interfaces, receipts, evidence bundles, exports, CLI, CI scanner, local API and web UI.
- Re-audited the public interfaces and corrected defects missed by the earlier beta suite, including document-isolation bypasses, browser-observation spoofing, version/report inconsistencies, materiality evidence locality, unsupported observer combinations, malformed UTF-8 handling, file-intake boundaries, SARIF locations and worker-capacity accounting.
- Corrected a ZIP/Office regression found only when testing freshly installed wheels across multiple Python versions.
- Replaced ambiguous provider-internal "model input" claims with explicit submitted-request/observed-response semantics.

### Verification
- 86/86 tests passed on CPython 3.10, 3.11, 3.12, 3.13 and 3.14 using freshly installed wheels.
- Real isolated browser, document and namespace tests passed.
- 2,012 deterministic benign/adversarial cases were repeated twice with receipt and radial invariants checked.
- Wheel and source distribution passed package checks.
- Resolved dependency audit reported no known vulnerabilities at validation time.
- Ruff critical-code checks passed.
- Bandit reported no HIGH findings; retained MEDIUM temporary-path heuristics are documented and backed by direct namespace tests.
- DDC-aligned development qualification: **PASS-CANDIDATE**.

### Explicitly not complete
This beta is not a production-certified v1.0 release. Independent security review, production multi-user identity/quotas/TLS/retention, worker cgroup and egress controls, configured model-provider validation, actual OCR/visual coverage, DDCAL production deployment/rollback and final production owner approval remain separate gates.

A clean RenderDiff result means no material representation divergence was observed by the checks that actually ran. It does not certify safety, authenticity, authorship or universal semantic equivalence.
