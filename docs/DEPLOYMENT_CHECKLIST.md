# Deployment checklist

Use this checklist for staging first, then repeat it for production.

- [ ] `pnpm install --frozen-lockfile`
- [ ] `pnpm validate:config`
- [ ] `pnpm typecheck`
- [ ] `pnpm test`
- [ ] `pnpm test:coverage`
- [ ] `pnpm build`
- [ ] `pnpm test:e2e`
- [ ] D1 and KV IDs point to the intended environment
- [ ] `SESSION_SECRET` and `UPSTREAM_ENCRYPTION_KEY` are independent Worker secrets
- [ ] `DEMO_SENTINEL_API_KEY` is dedicated, least privilege, and server-side
- [ ] Production MFA is required; Cloudflare Access is enabled when organizational identity is needed
- [ ] Database migrations were applied before the Workers were deployed
- [ ] Gateway `/health` returns 200 after deployment
- [ ] Normal and intentionally blocked requests produce expected decisions
- [ ] Request and audit records appear without raw secrets or bodies
- [ ] A rollback version is identified in Cloudflare
- [ ] Secret scanning, Semgrep CE, CI, and the last DAST workflow are green
- [ ] Free-plan usage and notification limits are understood before public traffic
