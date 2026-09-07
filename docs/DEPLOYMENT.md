# Deployment contract

This is a private, local-service deployment candidate. It is not an instruction to expose the API publicly without the production controls in `RELEASE_GATES.md`.

Install a pinned, reviewed wheel into a dedicated virtual environment. Configure a high-entropy `RENDERDIFF_API_TOKEN` through a protected secret file or service credential, never a command-line argument or public HTML. Bind Uvicorn to `127.0.0.1` and use one worker until distributed authentication/rate limiting is configured. Set `RENDERDIFF_RATE_LIMIT` explicitly.

Example local start after installing the package and optional API/document/PDF dependencies:

```bash
RENDERDIFF_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export RENDERDIFF_API_TOKEN
python -m uvicorn renderdiff.service:app --host 127.0.0.1 --port 8765 --workers 1 --no-access-log
```

This command creates an ephemeral credential; a real deployment must store it securely and rotate it without logging or exposing it. Open the local interface and enter the credential in its access field. Do not use this example to create a public shared-token service.

Before DDCAL deployment, verify the actual hosting architecture, authentication/authorization provider, shared quotas, TLS and CSRF strategy, request-log redaction, data retention/deletion, worker cgroups, egress policy, release artifact hashes, rollback and monitoring. Obtain explicit owner approval for the final production configuration. No hosting credentials, DNS records or existing production services should be changed by a repository build.
