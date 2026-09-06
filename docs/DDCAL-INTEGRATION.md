# DDCAL integration

## Services
Add **Representation Divergence Assurance (RenderDiff)** under Services.

Accepted evidence in v0.3:
- pasted text
- `.txt`, `.md`, `.json`, `.csv`, source snippets
- HTML source
- URL-fetched content only after DDCAL's existing fetch/sandbox boundary retrieves it

## Try DDC
Add a `RenderDiff` mode with three panels:
1. Human view
2. Machine/source view
3. Divergence evidence

Show exact positions, codepoints, decoded Tag payloads, normalization delta, hidden HTML fragments, browser-render text when enabled, tokenizer metadata, pairwise observer comparisons, hashes, and materiality.

## API shape
`POST /api/v1/renderdiff/analyze`

Request:
```json
{"text":"...","content_type":"text/html","browser":true,"provenance":{}}
```

Response: the deterministic RenderDiff assurance object.

DDCAL may append private DDC policy decisions outside the RenderDiff namespace; never put proprietary methodology into the open-source engine.

Browser observation must be explicitly configured by the DDCAL host and explicitly requested with `browser:true`; HTML alone never triggers browser execution. Tokenizers are likewise host-configured capabilities.
