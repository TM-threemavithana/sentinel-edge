# Operations runbook

## Triage a spike in blocked traffic

1. Check the live request rate and top threat categories.
2. Filter Request Explorer by `block` and confirm whether one API key, route, or
   region dominates.
3. Inspect the matching policy and a redacted analysis artifact.
4. Revoke the affected key if behavior is unauthorized.
5. If a policy is a false positive, disable it temporarily and record the change
   in the incident timeline; do not delete the audit event.

## Queue backlog

Check the `sentinel-edge-analysis` and dead-letter queue in Cloudflare. Fix the
root cause before replay. Result writes are idempotent by `request_event_id`, but
R2 may contain more than one report object if custom replay tooling changes IDs.

## Suspected credential disclosure

1. Revoke the affected Sentinel API key.
2. Rotate the upstream provider credential.
3. Update the upstream through an authenticated administrative flow.
4. Rotate `UPSTREAM_ENCRYPTION_KEY` only with a migration plan; existing encrypted
   credentials cannot be decrypted with the new key.
5. Export audit events and preserve relevant request IDs.

## D1 recovery

Use Cloudflare D1 Time Travel according to your account retention. Restore into a
new database first, validate row counts and recent events, then update the Worker
binding during a controlled deployment.

## Safe rollback

Use Worker Versions/Deployments to roll back code. D1 migrations in this sample
are additive. Never roll back a destructive schema change without a forward
repair migration and verified backup.
