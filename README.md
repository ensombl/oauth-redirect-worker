# External Auth Worker

A Cloudflare Worker that provides secure OAuth redirect handling for Coda applications.

## Overview

This worker acts as a secure OAuth redirect endpoint that validates and forwards authentication responses to authorized domains. It's designed to protect against open redirect vulnerabilities by maintaining an allowlist of trusted redirect targets.

## Functionality

- **Secure Redirects**: Validates redirect URIs against an allowlist of trusted domains
- **Parameter Forwarding**: Preserves all query parameters when redirecting to the target URL
- **State Parameter Parsing**: Extracts redirect URI from the `state` parameter (expected as JSON)

## Allowed Redirect Domains

The worker only allows redirects to the following domains:

- `localhost` (any port)
- `127.*` (local IP addresses)
- `app.staging.coda.to`
- `preview.app.coda.to`
- `*.vercel.app`

## Usage

### URL Format

```
https://oauth-redirect.dev.coda.to/?state={"redirect_uri":"<encoded_target_url>"}&<other_oauth_params>
```

### Example

```
https://oauth-redirect.dev.coda.to/?state={"redirect_uri":"https%3A//app.staging.coda.to/callback"}&code=abc123&scope=read
```

## Deployment

### Prerequisites

- Node.js 18+
- Wrangler CLI

### Commands

```bash
# Development
pnpm run dev

# Deploy to production
pnpm run deploy

# Run tests
pnpm run test
```

## Configuration

The worker is configured via `wrangler.jsonc`:

- **Route**: `oauth-redirect.dev.coda.to/*`
- **Name**: `oauth-redirect-dev`
- **Compatibility Date**: `2025-06-07`

## Security Features

- **Allowlist Validation**: Only permits redirects to pre-approved domains
- **Parameter Validation**: Validates the structure of the `state` parameter
- **Error Handling**: Returns appropriate HTTP status codes for invalid requests

## Error Responses

- `400 Bad Request`: Invalid or missing `state` parameter
- `403 Forbidden`: Redirect target not in allowlist

## Development

The worker is built with TypeScript and uses Vitest for testing. The main logic is contained in `src/index.ts`.
