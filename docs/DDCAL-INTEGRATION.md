# DDCAL integration

## Services
Add **Representation Divergence Assurance (RenderDiff)** under Services.

Accepted evidence in v0.1:
- pasted text
- `.txt`, `.md`, `.json`, `.csv`, source snippets
- HTML source
- URL-fetched content only after DDCAL's existing fetch/sandbox boundary retrieves it

## Try DDC
Add a `RenderDiff` mode with three panels:
1. Human view
2. Machine/source view
3. Divergence evidence

Show exact positions, codepoints, decoded Tag payloads, normalization delta, hidden HTML fragments, hashes, and materiality.

## API shape
`POST /api/v1/renderdiff/analyze`

Request:
```json
{"text":"...","content_type":"text/plain","provenance":{}}
```

Response: the deterministic RenderDiff assurance object.

DDCAL may append private DDC policy decisions outside the RenderDiff namespace; never put proprietary methodology into the open-source engine.
