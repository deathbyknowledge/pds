#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -f .dev.vars ]]; then
  set -a
  # shellcheck disable=SC1091
  . ./.dev.vars
  set +a
fi

if [[ -z "${PDS_ADMIN_TOKEN:-}" ]]; then
  echo "PDS_ADMIN_TOKEN is required. Set it in the environment or .dev.vars." >&2
  exit 2
fi

required_wrangler_vars=(PDS_LEXICON_AUTHORITY_DIDS)
missing_wrangler_vars=()
for name in "${required_wrangler_vars[@]}"; do
  if ! grep -Eq "^[[:space:]]*${name}[[:space:]]*=" wrangler.toml; then
    missing_wrangler_vars+=("$name")
  fi
done

if ((${#missing_wrangler_vars[@]})); then
  printf 'wrangler.toml is missing required non-secret [vars]: %s\n' \
    "${missing_wrangler_vars[*]}" >&2
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

if [[ -n "${PDS_BASE_URL:-}" ]]; then
  npm run seed:test-repo
  npm run smoke:account
  npm run smoke:public
  npm run smoke:lexicon
  exit 0
fi

cat <<'MSG'

Deployment finished.

Run remote smokes with:
  PDS_BASE_URL=https://<your-worker-host> \
  PDS_ADMIN_TOKEN=<same-token> \
  npm run seed:test-repo && \
  npm run smoke:account && \
  npm run smoke:public && \
  npm run smoke:lexicon

MSG
