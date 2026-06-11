# OAuth Redirect

Turborepo for the Ensombl OAuth redirect Worker, a local OAuth test server, and a small local OAuth test client.

## Workspace

- `apps/oauth-redirect-worker`: Cloudflare Worker that validates OAuth callback redirect targets and forwards allowed OAuth parameters.
- `apps/test-server`: local OAuth provider used by the demo.
- `apps/test-client`: local Node test client configured for the local OAuth provider.
- `packages/auth-config`: shared config schema, redirect host matching, and Wrangler config generation.
- `config/auth.config.jsonc`: source of truth for Worker routing, redirect allowlist, callback params, and provider metadata.

## Worker

The Worker expects OAuth providers to call it with a JSON `state` parameter containing `redirect_uri`:

```txt
https://oauth-redirect.dev.ensombl.io/callback/test?state={"redirect_uri":"https://app.certless.io/auth/callback"}&code=...
```

It validates the target from `state.redirect_uri`, strips redirect-like target params, forwards configured OAuth callback params, and redirects with `303`.

Configured target hosts:

- localhost, `*.localhost`, and loopback IPv4 for local development
- `*.plansombl.com`
- `*.ensombl.io`
- `*.certless.io`

Wrangler config is generated from `config/auth.config.jsonc` into `apps/oauth-redirect-worker/.generated/wrangler.jsonc`. There is one Worker target: `ensombl-oauth-redirect-worker` on the custom domain `oauth-redirect.dev.ensombl.io`. The `dev` label is part of the workflow hostname, not a separate Worker environment.

The Cloudflare account id is pinned in `config/auth.config.jsonc` so `pnpm deploy` can run non-interactively against the `ensombl` account.

Worker package scripts run Wrangler with `CI=1` scoped to the Wrangler process. Wrangler `4.99.0` prompts interactive terminals to install Cloudflare agent skills before starting `wrangler dev`, and it does not expose a no-install flag; the scoped CI env keeps local and Turbo startup non-blocking while still using the latest Wrangler.

`pnpm dev` also generates local Wrangler config with `AUTH_REDIRECT_ALLOW_INSECURE_CALLBACKS=true` so `http://localhost:8787` callbacks work. `pnpm build` and `pnpm --filter @ensombl/oauth-redirect-worker deploy` regenerate config without that var, so production still requires HTTPS callback traffic.

## Local Test

Create `.env` from the root example:

```sh
cp .env.example .env
```

The defaults are enough for the local demo:

```sh
PORT=3000
TEST_SERVER_PORT=4000
TEST_CLIENT_BASE_URL=http://localhost:3000
AUTH_WORKER_BASE_URL=http://localhost:8787
TEST_REDIRECT_URIS=http://localhost:8787/callback/test
```

Then run:

```sh
pnpm install
pnpm dev:demo
```

Demo URLs:

- Test client: `http://localhost:3000`
- OAuth test server: `http://localhost:4000`
- Redirect Worker: `http://localhost:8787`

Open `http://localhost:3000` and sign in with the local OAuth test server.

The test client can point at another OAuth provider from `.env` without changing `config/auth.config.jsonc`. For Google, register `http://localhost:8787/callback/google` as an authorized redirect URI, then set:

```sh
OAUTH_PROVIDER_ID=google
OAUTH_CLIENT_ID=your-google-client-id
OAUTH_CLIENT_SECRET=your-google-client-secret
OAUTH_SCOPES=openid,email,profile
```

For another provider, also set `OAUTH_PROVIDER_NAME`, `OAUTH_AUTHORIZATION_ENDPOINT`, `OAUTH_TOKEN_ENDPOINT`, and optionally `OAUTH_USERINFO_ENDPOINT`.

To test post-login navigation, start at a relative `return_to` path:

```txt
http://localhost:3000/auth/test?return_to=/dashboard?tab=home
```

The test client stores that value inside OAuth state, validates that it is a relative path, and redirects there after the callback with a local `login` handle. The Worker still strips redirect-like params from the callback URL itself.

## Commands

```sh
pnpm typecheck
pnpm test
pnpm build
pnpm dev:worker
pnpm dev:test-server
pnpm dev:test-client
pnpm dev:demo
pnpm deploy
pnpm cf-typegen
```

`pnpm deploy` generates Wrangler config first, then deploys the single Worker target.
