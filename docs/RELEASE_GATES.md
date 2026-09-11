# RenderDiff release assurance

This document defines evidence-based release gates. DDC-aligned qualification is not certification by the private DDC kernel, an independent security assessor, or an accredited laboratory.

## Scope

The v0.6 beta provides deterministic text/Unicode assurance, bounded document extraction, evidence-linked representation comparisons, optional model and browser observers, receipts, reports, and a private local API. A clean result means no material divergence was observed within the performed checks, not that the evidence is safe, authentic, or semantically equivalent.

## Required gates

- Authority: no evidence or model output grants tool execution or changes operator permissions. Public writes require a configured credential; production identity and per-user quotas remain separate.
- Provenance: bind original bytes, extraction lineage, versioned observer identities and report hashes. A bare hash is not a signature.
- State: record source revision, dependency versions, report schema, observer availability and actual execution state.
- Resource: enforce input/output limits, concurrency, timeouts and worker resource ceilings.
- Physical: run active HTML and document parsing in networkless, filesystem-confined workers. Production needs separate cgroup memory/PID limits and tested egress policy.
- Verification: run unit/integration/security tests, actual browser/document fixtures, dependency audit and the supported-Python matrix.
- Frequency: repeat deterministic adversarial cases and verify receipt identity and invariants.
- Lineage: preserve original source hashes and immutable evidence references. Do not promote advisory semantic claims into facts or authority.

## Production release remains blocked until

An independent security review is completed; a real DDCAL deployment has authenticated users, shared rate limits, TLS, retention and deletion controls, isolated worker resource limits, egress restrictions, monitoring without evidence leakage, rollback and operational ownership; and the public capabilities and observer limitations are accurately disclosed. A configured external model requires explicit provider consent and separate behavioral validation. OCR and visual coverage require an installed, isolated observer and real fixtures. No universal semantic or visual completeness is claimed.

## Validation records

`artifacts/release-matrix.json` records the five-interpreter test matrix. `artifacts/dependency-audit.json` records the pinned dependency audit. `artifacts/bandit.json` retains static findings, including any documented false positives. The release qualification must bind these records to a source manifest and must not turn a pending production gate into PASS.

## Static-analysis disposition

The security audit uses Bandit and Ruff syntax/undefined-code checks. Bandit B108 warnings on `/tmp` are retained as documented false positives for isolated, private tmpfs paths; the direct namespace test verifies the actual boundary. The broader formatting lint is not yet clean and is not represented as a passed gate. The dependency audit uses a fully resolved pinned requirements file and records any known vulnerability as a release blocker.

## Release authority

The local qualification can establish `PASS-CANDIDATE` for the tested source snapshot only. It does not approve publication, merge, production deployment, or independent certification. Production approval requires the owner to review the final deployment configuration and the independent review evidence.

The current reproducible commands are `python tools/release_matrix.py` and `python tools/qualify_release.py`. Qualification requires a clean source tree, a matching installed package version, and the current matrix/audit evidence. It retains a PENDING production gate even when all development gates pass.
