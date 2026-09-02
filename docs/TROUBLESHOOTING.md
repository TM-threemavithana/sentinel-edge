# Troubleshooting

## The console says Cloudflare Access is required

`ACCESS_REQUIRED=true` was enabled, but the request did not contain a valid
Access identity. Confirm the Access application hostname, team domain, audience,
and identity policy. For local development, keep `ACCESS_REQUIRED=false`.

## Sign-in returns 401

Confirm the administrator email, password, and environment. After MFA enrollment,
use the current authenticator code. Rotate a lost local credential with the
audited administrator command in the runbook; do not edit D1 manually.

## MFA confirmation fails

Check that the computer and phone clocks are synchronized. A TOTP code is
time-sensitive and cannot be replayed. Use one unused recovery code if the
authenticator is unavailable.

## Upstream creation returns `unsafe_upstream`

Sentinel Edge accepts only public HTTPS services. Localhost, private IP ranges,
credentials in URLs, query strings, fragments, and DNS names resolving to private
addresses are rejected. Use a public test service or tunnel during development.

## Gateway says the upstream does not exist

Use the upstream ID, not its display name. Copy it from console Settings and make
sure the API key and upstream belong to the same workspace.

## A request is blocked unexpectedly

Open Request explorer, locate the request ID returned to the caller, and inspect
its threat signals and matched decision. Review policy priority: the first
matching enabled rule wins.

## The protected demo is unavailable

The web Worker needs `DEMO_SENTINEL_API_KEY` as a secret plus `DEMO_UPSTREAM_ID`
and `DEMO_MODEL` as variables. The key must be active, belong to the same
workspace as the upstream, and have `gateway:invoke` scope.

## Local development cannot reach Workers AI

Free-tier mode intentionally skips asynchronous AI inference and R2 writes while
keeping deterministic inspection active. Remote AI use also requires Wrangler
authentication. This does not affect allow/block policy testing.

## A Cloudflare allowance is exhausted

The project is configured to fail rather than purchase paid capacity. Wait for
the free allowance to reset, reduce test traffic, or disable optional features.
Check current platform limits before public promotion.
