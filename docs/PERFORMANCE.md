# Performance checks

The repository includes a dependency-free load smoke test. It is intentionally
manual so contributors do not generate public traffic or consume free-plan
allowances on every pull request.

Test a local health endpoint:

```bash
pnpm test:load
```

Test a deployed endpoint with a bounded run:

```bash
LOAD_URL=https://your-gateway.example.workers.dev/health \
LOAD_REQUESTS=100 LOAD_CONCURRENCY=10 pnpm test:load
```

For an authenticated gateway route, set `SENTINEL_API_KEY` in the shell. The
runner never prints it. Use a disposable, least-privilege key and revoke it after
testing.

Record the date, Cloudflare location, endpoint, request count, concurrency,
success rate, p50, p95, and maximum latency with any published benchmark. A
health-endpoint result measures Worker reachability and overhead, not provider
latency or full inspection throughput.

## Recorded smoke result

On 2026-09-02, the production `/health` endpoint completed 30 of 30 requests
successfully at concurrency 5. The observed throughput was 9.31 requests/second,
with p50 389.4 ms, p95 933.5 ms, and maximum 964.9 ms. This is a small client-side
reachability sample, not a capacity claim; provider, inspection, and sustained
load benchmarks remain separate release evidence.
