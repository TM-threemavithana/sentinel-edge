# Integration examples

These examples show how an application backend calls Sentinel Edge instead of
calling its upstream provider directly. Keep the Sentinel key on the server and
load it from an environment variable.

Required values:

- `SENTINEL_GATEWAY_URL` — for example `https://sentinel-edge-gateway-production.example.workers.dev`
- `SENTINEL_UPSTREAM_ID` — the upstream ID shown in console Settings
- `SENTINEL_API_KEY` — a dedicated key with only `gateway:invoke`

Choose [TypeScript](typescript/chat.mjs), [Python](python/chat.py), or
[curl](curl/README.md). All three send the same OpenAI-compatible request through
the `/v1/gateway/{upstreamId}/chat/completions` route.

The machine-readable [OpenAPI document](../docs/openapi.json) describes the
public health and data-plane routes.
