# Test Deploy

This repo has a small deployment and seed flow for checking a public Worker with
PDSls.

## Prerequisites

- Cloudflare auth configured for `wrangler`.
- A public route for the Worker. `wrangler.toml` currently has
  `workers_dev = false`, so either attach a route/custom domain or temporarily
  enable `workers_dev` for a throwaway test.
- A private admin token. Generate one with:

```bash
export PDS_ADMIN_TOKEN="$(openssl rand -hex 32)"
```

## Deploy

```bash
npm run deploy:test
```

The script stores `PDS_ADMIN_TOKEN` as a Worker secret, runs `wrangler deploy`,
and prints the seed command to run next.

## Seed And Check

```bash
export PDS_BASE_URL="https://<your-worker-host>"
export PDS_ADMIN_TOKEN="<same-token-used-for-deploy>"
npm run seed:test-repo
```

The seed script initializes a host-level `did:web:<host>` repo, writes one
`app.gsv.record` record, verifies both well-known identity endpoints, reads it
back through XRPC, downloads `com.atproto.sync.getRepo`, and prints PDSls links
like:

```text
https://pdsls.dev/at://did:web:<your-worker-host>
https://pdsls.dev/at://did:web:<your-worker-host>/app.gsv.record/seed
```

By default, the script generates a new P-256 signing key and prints it as
`signingKeyP256Hex`. Keep that value only for disposable test repos, or pass
`PDS_SIGNING_KEY_P256_HEX` explicitly when you need deterministic re-seeding.

Useful optional variables:

- `PDS_HANDLE`: handle to publish in the DID document, defaults to the base URL
  hostname.
- `PDS_DID`: repo DID, defaults to `did:web:<PDS_HANDLE>`.
- `PDS_REPO`: Durable Object name, defaults to the DID's local identifier.
- `PDS_RESET=false`: keep an existing initialized repo instead of resetting it.
- `PDS_RECORD_PATH`: record path, defaults to `app.gsv.record/seed`.
- `PDS_RECORD_JSON`: JSON object to store instead of the default seed record.

## Local Smoke

```bash
npm run dev -- --port 8788
```

In another shell:

```bash
PDS_BASE_URL=http://localhost:8788 \
PDS_ADMIN_TOKEN=dev-admin-token \
PDS_SIGNING_KEY_P256_HEX=0000000000000000000000000000000000000000000000000000000000000001 \
npm run seed:test-repo
```

The local smoke expects `.dev.vars` to contain:

```text
PDS_ADMIN_TOKEN=dev-admin-token
```
