# Architecture

Sentinel Edge separates the control plane from the request data plane. The
Next.js application is an operator console. The gateway Worker remains small,
stateless between requests, and independently deployable.

```text
Operator browser
      |
      v
Next.js console Worker (vinext)
      |  same-site BFF proxy
      v
Gateway Worker ---------------------------------------------------+
      |                                                           |
      +--> D1: users, sessions, keys, policies, events, audit      |
      +--> KV: short-lived compiled policy cache                   |
      +--> Durable Object: limits, live counters, presence         |
      +--> Queue: redacted async threat analysis                   |
      +--> Workers AI: structured threat classification           |
      +--> R2: redacted request samples and analysis reports       |
      |                                                           |
      +---------------- allowed request -------------------------->+ Upstream API
```

## Request lifecycle

1. A client presents an `sg_live_…` key in `x-sentinel-key`.
2. The Worker hashes the presented value and resolves its active D1 record.
3. The upstream ID is resolved from a workspace-owned allowlist. Arbitrary
   destination URLs are never accepted from the caller.
4. The request is bounded, normalized, and inspected for deterministic signals.
5. Ordered policy rules are loaded from KV or D1 and evaluated.
6. A Durable Object coordinates any matching tenant rate limit.
7. Block, challenge, and limit decisions end at the edge. Allowed requests are
   forwarded with hop-by-hop, client credential, cookie, and Cloudflare headers
   removed.
8. A request event is written to D1. Redacted analysis work is sent to a Queue.
9. The Queue consumer calls Workers AI, stores a structured result in D1, and
   writes the checksum-tagged report to R2.

## Failure behavior

- Deterministic inspection and policy enforcement do not depend on AI.
- The default asynchronous AI mode never adds model latency to upstream calls.
- Queue failures retry three times, then move to a dead-letter queue.
- An unavailable policy cache falls back to D1.
- An invalid or expired session/API key is denied.
- Oversized bodies fail closed.
- Inline AI mode is optional and fails open to deterministic enforcement; its
  failure is logged with the request ID.

## Data ownership

Every mutable or sensitive record includes a workspace key. Management queries
bind the authenticated workspace ID server-side. R2 object names are prefixed
with the workspace ID, and artifact downloads re-check D1 ownership.

## Scaling notes

D1 holds the auditable source of truth. KV absorbs repeated policy reads. One
Durable Object per workspace coordinates limits without globally serializing
unrelated tenants. Queue consumers allow analysis throughput to scale
independently from gateway latency.
