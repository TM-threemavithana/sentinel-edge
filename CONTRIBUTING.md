# Contributing to Sentinel Edge

Thank you for improving Sentinel Edge. Security changes deserve careful,
reproducible review, so keep pull requests focused and include evidence.

## Start locally

1. Install Node.js 22 and pnpm 11.
2. Run `pnpm install --frozen-lockfile`.
3. Run `pnpm setup:local`.
4. Follow [docs/QUICKSTART.md](docs/QUICKSTART.md) to prepare D1 and create a local administrator.

## Before opening a pull request

Run:

```bash
pnpm validate:config
pnpm typecheck
pnpm test
pnpm test:coverage
pnpm build
pnpm test:e2e
```

Add or update tests whenever behavior changes. Include screenshots for visible UI
changes and document security assumptions for new trust boundaries. Never commit
credentials, `.dev.vars`, `.env.local`, raw request bodies, or customer data.

## Pull requests

- Explain the user problem and the selected solution.
- Keep unrelated refactors separate.
- Call out migrations, new Cloudflare bindings, and deployment ordering.
- Describe failure behavior and rollback steps for security-sensitive changes.
- Update `CHANGELOG.md` under **Unreleased** for user-visible changes.

## Security reports

Do not report vulnerabilities in a public issue. Follow [SECURITY.md](SECURITY.md)
to submit a private GitHub security advisory.
