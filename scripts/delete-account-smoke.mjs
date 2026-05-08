#!/usr/bin/env node

const config = {
  baseUrl: requiredEnv("PDS_BASE_URL").replace(/\/+$/, ""),
  adminToken: requiredEnv("PDS_ADMIN_TOKEN"),
  handleSuffix: optionalEnv("PDS_DELETE_ACCOUNT_HANDLE_SUFFIX", "gsv.dev"),
};

const stamp = Date.now().toString(36);
const id = `delete-${stamp}`;
const handle = `${id}.${config.handleSuffix.replace(/^\.+/, "")}`.toLowerCase();
const did = `did:gsv:${id}`;
const password = `delete-account-password-${stamp}`;

const created = await expectJson(
  "create disposable account",
  "POST",
  "/xrpc/com.atproto.server.createAccount",
  {
    handle,
    did,
    password,
    email: `delete-${stamp}@example.com`,
  },
  (body) => {
    if (body.did !== did || body.handle !== handle || !body.accessJwt || !body.refreshJwt) {
      throw new Error(`unexpected createAccount response ${JSON.stringify(body)}`);
    }
  },
  { authorization: `Bearer ${config.adminToken}` },
);

await expectJson(
  "resolve disposable handle",
  "GET",
  `/xrpc/com.atproto.identity.resolveIdentity?identifier=${encodeQuery(handle)}`,
  null,
  (body) => {
    if (body.did !== did || body.handle !== handle || body.didDoc?.id !== did) {
      throw new Error(`unexpected resolveIdentity response ${JSON.stringify(body)}`);
    }
  },
);

await expectJson(
  "disposable repo active",
  "GET",
  `/xrpc/com.atproto.sync.getRepoStatus?did=${encodeQuery(did)}`,
  null,
  (body) => {
    if (body.did !== did || body.active !== true || !body.rev) {
      throw new Error(`unexpected active repo status ${JSON.stringify(body)}`);
    }
  },
);

const session = await expectJson(
  "create disposable session",
  "POST",
  "/xrpc/com.atproto.server.createSession",
  {
    identifier: did,
    password,
  },
  (body) => {
    if (body.did !== did || body.handle !== handle || !body.accessJwt || !body.refreshJwt) {
      throw new Error(`unexpected createSession response ${JSON.stringify(body)}`);
    }
  },
);

const deletion = await expectJson(
  "request disposable account delete",
  "POST",
  "/xrpc/com.atproto.server.requestAccountDelete",
  null,
  (body) => {
    if (typeof body.token !== "string" || body.token.length < 16) {
      throw new Error(`unexpected requestAccountDelete response ${JSON.stringify(body)}`);
    }
  },
  {
    authorization: `Bearer ${session.accessJwt}`,
    "x-pds-admin-token": config.adminToken,
  },
);

await expectStatus(
  "delete disposable account rejects wrong token",
  "POST",
  "/xrpc/com.atproto.server.deleteAccount",
  {
    did,
    password,
    token: "wrong-token",
  },
  400,
  { authorization: `Bearer ${session.accessJwt}` },
);

await expectStatus(
  "delete disposable account",
  "POST",
  "/xrpc/com.atproto.server.deleteAccount",
  {
    did,
    password,
    token: deletion.token,
  },
  200,
  { authorization: `Bearer ${session.accessJwt}` },
);

await expectStatus(
  "deleted disposable account rejects login",
  "POST",
  "/xrpc/com.atproto.server.createSession",
  {
    identifier: did,
    password,
  },
  403,
);

await expectStatus(
  "deleted disposable account rejects getSession",
  "GET",
  "/xrpc/com.atproto.server.getSession",
  null,
  403,
  { authorization: `Bearer ${session.accessJwt}` },
);

await expectStatus(
  "deleted disposable account rejects refresh",
  "POST",
  "/xrpc/com.atproto.server.refreshSession",
  null,
  401,
  { authorization: `Bearer ${session.refreshJwt}` },
);

await expectStatus(
  "deleted disposable account rejects reactivation",
  "POST",
  "/xrpc/com.atproto.server.activateAccount",
  null,
  403,
  { authorization: `Bearer ${created.accessJwt}` },
);

await expectJson(
  "disposable repo deleted status",
  "GET",
  `/xrpc/com.atproto.sync.getRepoStatus?did=${encodeQuery(did)}`,
  null,
  (body) => {
    if (body.did !== did || body.active !== false || body.status !== "deleted" || body.rev) {
      throw new Error(`unexpected deleted repo status ${JSON.stringify(body)}`);
    }
  },
);

await expectStatus(
  "deleted disposable identity not resolvable",
  "GET",
  `/xrpc/com.atproto.identity.resolveIdentity?identifier=${encodeQuery(handle)}`,
  null,
  404,
);

console.log(
  JSON.stringify(
    {
      ok: true,
      baseUrl: config.baseUrl,
      handle,
      did,
    },
    null,
    2,
  ),
);

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
  validate?.(parsed, response);
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
  if (body && typeof body !== "string") {
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

function encodeQuery(value) {
  return encodeURIComponent(value);
}
