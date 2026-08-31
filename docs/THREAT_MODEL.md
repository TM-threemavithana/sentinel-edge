# Threat model

## Assets

- Upstream provider credentials and API availability
- Gateway API keys and dashboard sessions
- Tenant policies, audit events, request metadata, and report artifacts
- Model system prompts and request content

## Trust boundaries

The public internet, browser console, gateway Worker, Cloudflare bindings,
Workers AI, and each registered upstream are distinct trust zones. Request body
content is always untrusted—even when it appears inside a classification prompt.

## Primary threats and controls

| Threat | Control |
| --- | --- |
| Stolen API key | One-time reveal, SHA-256 storage, scopes, expiry, instant revocation |
| Password disclosure | PBKDF2-SHA-256 at the Workers-enforced 100,000-iteration ceiling with per-user salt; HttpOnly opaque sessions; OIDC recommended for real organizations |
| Cross-site request forgery | SameSite=Lax cookies, CSRF tokens, and mandatory Origin validation on mutations |
| Broken object authorization | Workspace ownership predicates on every management query |
| SSRF | Admin-created public HTTPS upstream allowlist; private-address rejection |
| Credential forwarding | Client auth, cookies, host, and Cloudflare headers stripped |
| Prompt injection | Deterministic patterns plus isolated Workers AI classification |
| SQL injection | Prepared D1 statements and Zod validation |
| Sensitive log leakage | Header/body redaction, bounded samples, R2 retention metadata |
| Abuse and denial of service | Body ceiling and Durable Object tenant/IP/key limits |
| Regex denial of service | Policy regex length cap and invalid-expression rejection |
| Queue poison message | Bounded schema, retries, dead-letter queue, idempotent result upsert |
| Audit tampering | Append-only API surface and checksum-tagged R2 reports |

## Assumptions

- Cloudflare account RBAC and API tokens are managed outside this repository.
- TLS terminates on Cloudflare and all production upstreams use HTTPS.
- `SESSION_SECRET` and `UPSTREAM_ENCRYPTION_KEY` are created with a cryptographic
  generator and stored as Worker secrets.
- D1 and R2 retention/deletion policies are aligned with customer contracts.

## Required work before a real launch

Add secret rotation, provider-specific response inspection, alert delivery,
malware scanning for file uploads, tenant provisioning, legal retention review,
load testing, and an independent security assessment. Built-in TOTP MFA removes
password-only production access; larger organizations should still connect OIDC
or Cloudflare Access for centralized identity lifecycle management.
