#!/usr/bin/env node

const config = {
  baseUrl: requiredEnv("PDS_BASE_URL").replace(/\/+$/, ""),
  adminToken: requiredEnv("PDS_ADMIN_TOKEN"),
  handle: optionalEnv("PDS_ACCOUNT_HANDLE"),
  password: optionalEnv("PDS_ACCOUNT_PASSWORD", "dev-account-password"),
};

const base = new URL(config.baseUrl);
const baseOrigin = base.origin;
const handle = config.handle ?? base.hostname;
const collection = "app.gsv.accountSmoke";
const rkey = `session-${Date.now().toString(36)}`;

await expectOAuthDiscovery();
await expectOAuthScaffoldEndpoints();

const created = await maybeCreateAccount();
const session = await expectJson("create session", "POST", "/xrpc/com.atproto.server.createSession", {
  identifier: handle,
  password: config.password,
});

if (session.did !== `did:web:${handle}` || session.handle !== handle || !session.accessJwt || !session.refreshJwt) {
  throw new Error(`unexpected createSession response ${JSON.stringify(session)}`);
}

await expectJson(
  "get session",
  "GET",
  "/xrpc/com.atproto.server.getSession",
  null,
  (body) => {
    if (body.did !== session.did || body.handle !== handle || body.accessJwt || body.refreshJwt) {
      throw new Error(`unexpected getSession response ${JSON.stringify(body)}`);
    }
  },
  { authorization: `Bearer ${session.accessJwt}` },
);

const createRecord = await expectJson(
  "account createRecord",
  "POST",
  "/xrpc/com.atproto.repo.createRecord",
  {
    repo: session.did,
    collection,
    rkey,
    record: {
      $type: collection,
      text: "created through account auth",
      createdAt: new Date().toISOString(),
    },
  },
  (body) => {
    if (body.uri !== `at://${session.did}/${collection}/${rkey}` || !body.cid || !body.commit?.cid) {
      throw new Error(`unexpected createRecord response ${JSON.stringify(body)}`);
    }
  },
  { authorization: `Bearer ${session.accessJwt}` },
);

const refreshed = await expectJson(
  "refresh session",
  "POST",
  "/xrpc/com.atproto.server.refreshSession",
  null,
  (body) => {
    if (body.did !== session.did || !body.accessJwt || !body.refreshJwt) {
      throw new Error(`unexpected refreshSession response ${JSON.stringify(body)}`);
    }
  },
  { authorization: `Bearer ${session.refreshJwt}` },
);

await expectStatus(
  "delete session",
  "POST",
  "/xrpc/com.atproto.server.deleteSession",
  null,
  200,
  { authorization: `Bearer ${refreshed.refreshJwt}` },
);

await expectStatus(
  "deleted refresh token",
  "POST",
  "/xrpc/com.atproto.server.refreshSession",
  null,
  401,
  { authorization: `Bearer ${refreshed.refreshJwt}` },
);

console.log(
  JSON.stringify(
    {
      ok: true,
      created,
      baseUrl: config.baseUrl,
      handle,
      did: session.did,
      createdRecord: createRecord.uri,
      latestCommit: createRecord.commit.cid,
      pdslsRepoUrl: `https://pdsls.dev/at://${session.did}`,
    },
    null,
    2,
  ),
);

async function maybeCreateAccount() {
  const response = await request(
    "POST",
    "/xrpc/com.atproto.server.createAccount",
    {
      handle,
      password: config.password,
    },
    { authorization: `Bearer ${config.adminToken}` },
  );
  const text = await response.text();
  let body = {};
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    throw new Error(`createAccount returned non-JSON status=${response.status}: ${text}`);
  }
  if (response.ok) {
    return true;
  }
  if (response.status === 400 && String(body.error ?? "").includes("HandleNotAvailable")) {
    return false;
  }
  throw new Error(`createAccount failed status=${response.status}: ${JSON.stringify(body)}`);
}

async function expectOAuthDiscovery() {
  await expectJson(
    "OAuth protected resource metadata",
    "GET",
    "/.well-known/oauth-protected-resource",
    null,
    (body) => {
      if (body.resource !== baseOrigin || body.authorization_servers?.[0] !== baseOrigin) {
        throw new Error(`unexpected protected resource metadata ${JSON.stringify(body)}`);
      }
      if (!body.scopes_supported?.includes("atproto")) {
        throw new Error(`protected resource metadata did not advertise atproto scope ${JSON.stringify(body)}`);
      }
    },
  );

  await expectJson(
    "OAuth authorization server metadata",
    "GET",
    "/.well-known/oauth-authorization-server",
    null,
    (body) => {
      if (body.issuer !== baseOrigin) {
        throw new Error(`unexpected OAuth issuer ${JSON.stringify(body)}`);
      }
      if (body.authorization_endpoint !== `${baseOrigin}/oauth/authorize`) {
        throw new Error(`unexpected authorization endpoint ${JSON.stringify(body)}`);
      }
      if (body.token_endpoint !== `${baseOrigin}/oauth/token`) {
        throw new Error(`unexpected token endpoint ${JSON.stringify(body)}`);
      }
      if (body.pushed_authorization_request_endpoint !== `${baseOrigin}/oauth/par`) {
        throw new Error(`unexpected PAR endpoint ${JSON.stringify(body)}`);
      }
      if (
        body.require_pushed_authorization_requests !== true ||
        body.client_id_metadata_document_supported !== true ||
        !body.dpop_signing_alg_values_supported?.includes("ES256")
      ) {
        throw new Error(`OAuth metadata is missing required atproto capabilities ${JSON.stringify(body)}`);
      }
    },
  );
}

async function expectOAuthScaffoldEndpoints() {
  await expectStatus("OAuth PAR preflight", "OPTIONS", "/oauth/par", null, 204);
  await expectOAuthStub(
    "OAuth PAR scaffold",
    "POST",
    "/oauth/par",
    "client_id=http%3A%2F%2Flocalhost&response_type=code",
    { "content-type": "application/x-www-form-urlencoded" },
  );
  await expectOAuthStub("OAuth authorize scaffold", "GET", "/oauth/authorize?client_id=http%3A%2F%2Flocalhost");
  await expectOAuthStub(
    "OAuth token scaffold",
    "POST",
    "/oauth/token",
    "grant_type=authorization_code&code=stub",
    { "content-type": "application/x-www-form-urlencoded" },
  );
}

async function expectOAuthStub(label, method, path, body = null, extraHeaders = {}) {
  const response = await request(method, path, body, extraHeaders);
  const text = await response.text();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw new Error(`${label} returned non-JSON status=${response.status}: ${text}`, {
      cause: error,
    });
  }
  if (response.status !== 501 || parsed.error !== "temporarily_unavailable") {
    throw new Error(`${label} returned unexpected response status=${response.status}: ${JSON.stringify(parsed)}`);
  }
  if (parsed.error === "MethodNotFound") {
    throw new Error(`${label} still returned MethodNotFound`);
  }
}

async function expectJson(label, method, path, body, validate = undefined, extraHeaders = {}) {
  const response = await request(method, path, body, extraHeaders);
  const text = await response.text();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw new Error(`${label} returned non-JSON status=${response.status}: ${text}`, {
      cause: error,
    });
  }
  if (!response.ok) {
    throw new Error(`${label} failed status=${response.status}: ${JSON.stringify(parsed)}`);
  }
  validate?.(parsed);
  return parsed;
}

async function expectStatus(label, method, path, body, status, extraHeaders = {}) {
  const response = await request(method, path, body, extraHeaders);
  const text = await response.text();
  if (response.status !== status) {
    throw new Error(`${label} expected status=${status}, got ${response.status}: ${text}`);
  }
}

async function request(method, path, body = null, extraHeaders = {}) {
  const headers = {
    ...extraHeaders,
  };
  let requestBody = body;
  if (typeof body === "string") {
    requestBody = body;
  } else if (body && !(body instanceof Uint8Array)) {
    headers["content-type"] = headers["content-type"] ?? "application/json";
    requestBody = JSON.stringify(body);
  }
  return fetch(`${config.baseUrl}${path}`, {
    method,
    headers,
    body: requestBody,
  });
}

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}

function optionalEnv(name, fallback = undefined) {
  const value = process.env[name];
  return value && value.length > 0 ? value : fallback;
}
