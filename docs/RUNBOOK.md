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

Check `sentinel-edge-analysis-staging` or `sentinel-edge-analysis` and its matching
dead-letter queue in Cloudflare. Fix the root cause before replay. Result writes
are idempotent by `request_event_id`, but R2 may contain more than one report
object if custom replay tooling changes IDs. Invalid queue payloads are
acknowledged and logged instead of retried; valid processing failures retry three
times before reaching the dead-letter queue.

## Free-tier exhaustion

Check Workers, D1, KV, Queue, Durable Object, and Workers AI usage in the
Cloudflare dashboard. In `FREE_TIER_MODE`, AI inference and R2 writes are disabled.
If a daily free allowance is exhausted, keep the deployment fail-closed and wait
for the UTC reset or explicitly approve a paid-plan migration; do not silently
enable billable capacity.

## Suspected credential disclosure

1. Revoke the affected Sentinel API key.
2. Rotate the upstream provider credential.
3. Update the upstream through an authenticated administrative flow.
4. Rotate `UPSTREAM_ENCRYPTION_KEY` only with a migration plan; existing encrypted
   credentials cannot be decrypted with the new key.
5. Export audit events and preserve relevant request IDs.

For a disclosed dashboard password, use one of these controlled responses:

- If Cloudflare Access is already available, set `ACCESS_REQUIRED=true`,
  provision the administrator with `SENTINEL_ADMIN_PROVIDER=access`, verify the
  Access login, and remove the local password hash.
- Without an external identity service, set `MFA_REQUIRED=true`, apply the MFA
  migration, and deploy. The first password sign-in receives only a restricted
  enrollment session. Immediately scan the QR code, verify the authenticator,
  choose a new 16+ character password, and save the recovery codes. Confirmation
  revokes every other session and the disclosed password.

If the authenticator and all recovery codes are lost, use the audited remote
administrator command with `SENTINEL_RESET_MFA=true` and a new unique 20+
character password. This revokes every session and requires fresh MFA enrollment
at the next sign-in. Never use this flag as a routine login bypass.

## D1 recovery

Use Cloudflare D1 Time Travel according to your account retention. Restore into a
new database first, validate row counts and recent events, then update the Worker
binding during a controlled deployment.

## Safe rollback

Use Worker Versions/Deployments to roll back code. D1 migrations in this sample
are additive. Never roll back a destructive schema change without a forward
repair migration and verified backup.
