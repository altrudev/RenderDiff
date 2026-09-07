# Security and privacy

RenderDiff treats submitted evidence as untrusted data. It does not execute model-requested tools, discover credentials, or transmit evidence to a model provider automatically. Active rendering and external acquisition require explicit configuration. The public service does not expose URL fetching or active browser execution by default.

The local API requires a 32-character-or-longer bearer secret through `RENDERDIFF_API_TOKEN`. It is an operator credential, not a multi-user identity system. Set `RENDERDIFF_RATE_LIMIT` to a positive per-minute value. The browser interface keeps the credential in page memory only. Never embed it in a public page, URL, repository, or client application distributed to other users. Use HTTPS and a trusted reverse proxy for remote access.

The service has bounded request bodies, reports and concurrent jobs. Rate limits are in-process and must not be treated as distributed quotas. A public deployment needs a trusted authentication gateway, per-user quotas, shared enforcement, isolated workers and explicit data-retention policy. Do not expose the development server directly to the Internet.

Document and browser workers use Linux namespaces, read-only runtime mounts and network isolation. The host must provide bubblewrap and unprivileged namespace support. The service should run under a dedicated unprivileged account with systemd/container cgroup limits, no host secrets or privileged sockets, and no writable application source. A worker unavailable because isolation is missing must fail closed.

The application has no application telemetry or automatic evidence upload. Reports can contain the full supplied evidence, including secrets; downloads and evidence bundles must be handled accordingly. The application does not promise anonymity or deletion of copies retained by an operator. Configure request-log redaction, retention and deletion at the deployment boundary.

A receipt hash detects modification of the supplied report but does not establish authorship. Detached Ed25519 signatures require independently trusted keys. A semantic model's claims are advisory and must not be used to authorize consequential actions.

Report vulnerabilities privately to the repository maintainer using GitHub's private vulnerability reporting when enabled. Do not include sensitive exploitation data in public issues.

### Supported environments

The current integration matrix covers CPython 3.10–3.14 on Linux. Active browser and document isolation requires Linux namespace support. Other operating systems may use the deterministic text library but must not claim the same isolated-observer coverage. Browser memory/PID ceilings must be enforced by the production service manager or container runtime; Python address-space limits are not a substitute for Chromium cgroups.

### Re-audit resource and evidence semantics

Full-evidence analysis is bounded to 64,000 characters / 256,000 UTF-8 bytes, 10,000 findings and an 8 MB report. Original document intake is capped at 4 MB. An exceeded limit is a failed analysis, not a partial clean verdict. The local API retains capacity while a cancelled worker finishes; a request timeout does not terminate a running Python thread. Production cgroup ceilings and worker-process termination are therefore still required before public multi-user deployment.

The legacy browser DOM-marker observer has been replaced by the isolated Playwright observer. Model-provider responses cannot establish the provider's internal input representation. A self-computed report hash establishes consistency, not authorship; imported reports must not be treated as trusted attestations without an independently verified signature and trusted key.
