#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -z "${PDS_ADMIN_TOKEN:-}" ]]; then
  echo "PDS_ADMIN_TOKEN is required. Generate one with: openssl rand -hex 32" >&2
  exit 2
fi

if grep -Eq '^[[:space:]]*workers_dev[[:space:]]*=[[:space:]]*false' wrangler.toml; then
  cat >&2 <<'MSG'
wrangler.toml currently has workers_dev = false.
That is fine if you configured a route/custom domain, but for a quick workers.dev test
set workers_dev = true or pass a config that enables a public route.

MSG
fi

printf '%s' "$PDS_ADMIN_TOKEN" | npx wrangler secret put PDS_ADMIN_TOKEN
npx wrangler deploy "$@"

cat <<'MSG'

Deployment finished.

Seed the public test repo with:
  PDS_BASE_URL=https://<your-worker-host> \
  PDS_ADMIN_TOKEN=<same-token> \
  npm run seed:test-repo

MSG
