# Architecture

## Public assurance boundary

Input -> immutable evidence views -> divergence detectors -> materiality classifier -> deterministic report/receipt.

### Views
1. Raw bytes
2. Unicode/codepoints
3. Human-visible projection
4. NFC/NFKC normalization
5. Model-facing exact input / optional tokenizer adapter
6. Deterministic semantic summary
7. Hidden/invisible representation
8. Provenance/lineage supplied by caller

### Materiality
RenderDiff distinguishes:
- `material`: representation changes can directly alter interpretation/order/hidden content
- `potentially-material`: suspicious divergence whose impact depends on context
- `context-dependent`: real transformation that can be benign

This is deliberately not a proprietary DDC internal score. DDCAL can consume RenderDiff's public evidence and apply private assurance policy separately.
