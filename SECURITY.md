# Security policy

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Send a private
report to the repository maintainers with reproduction steps, affected routes,
and impact. Do not include production credentials or unredacted customer data.

## Supported versions

Security fixes are applied to the latest release. Rotate `SESSION_SECRET`, API
keys, and upstream credentials after any suspected disclosure.

## Security boundaries

- The dashboard authenticates through an opaque, HttpOnly session cookie.
- API keys are shown once and stored only as SHA-256 digests.
- Gateway destinations are selected from administrator-created upstreams; user
  input never becomes an arbitrary fetch URL.
- Request samples and reports are redacted before they reach D1, R2, or Queues.
- Authorization is enforced at every API route, not only in the interface.
- Durable Objects coordinate tenant rate limits; they are not the audit system
  of record.

This example is intentionally deployable, but a real launch should add an
external identity provider, Cloudflare Access, managed secret rotation, alert
delivery, and an independent penetration test.
