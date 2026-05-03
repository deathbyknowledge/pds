#!/usr/bin/env node
import { createHash } from "node:crypto";

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
const oauthPar = await expectOAuthParEndpoint();

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

await expectOAuthAuthorize(oauthPar, session.accessJwt);
const oauthToken = await expectOAuthTokenExchange(oauthPar);
await expectJson(
  "OAuth access token getSession",
  "GET",
  "/xrpc/com.atproto.server.getSession",
  null,
  (body) => {
    if (body.did !== session.did || body.handle !== handle) {
      throw new Error(`unexpected OAuth getSession response ${JSON.stringify(body)}`);
    }
  },
  { authorization: `DPoP ${oauthToken.access_token}` },
);
await expectOAuthRefresh(oauthPar.clientId, oauthToken.refresh_token);

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

async function expectOAuthParEndpoint() {
  await expectStatus("OAuth PAR preflight", "OPTIONS", "/oauth/par", null, 204);
  const state = `state-${Date.now().toString(36)}`;
  const clientId = "http://localhost";
  const redirectUri = "http://127.0.0.1/callback";
  const codeVerifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
  const parBody = new URLSearchParams({
    client_id: clientId,
    response_type: "code",
    code_challenge: pkceS256Challenge(codeVerifier),
    code_challenge_method: "S256",
    state,
    redirect_uri: redirectUri,
    scope: "atproto transition:generic",
    login_hint: handle,
  }).toString();
  const par = await expectJson(
    "OAuth PAR",
    "POST",
    "/oauth/par",
    parBody,
    (body, response) => {
      if (
        typeof body.request_uri !== "string" ||
        !body.request_uri.startsWith("urn:ietf:params:oauth:request_uri:") ||
        body.expires_in !== 300
      ) {
        throw new Error(`unexpected OAuth PAR response ${JSON.stringify(body)}`);
      }
      if (!response.headers.get("dpop-nonce")) {
        throw new Error(`OAuth PAR response did not include DPoP-Nonce header`);
      }
    },
    { "content-type": "application/x-www-form-urlencoded" },
  );
  await expectStatus(
    "OAuth duplicate PAR state",
    "POST",
    "/oauth/par",
    parBody,
    400,
    { "content-type": "application/x-www-form-urlencoded" },
  );
  if (!par.request_uri) {
    throw new Error(`OAuth PAR response did not include request_uri`);
  }
  await expectStatus(
    "OAuth authorize requires account session",
    "GET",
    `/oauth/authorize?client_id=${encodeQuery(clientId)}&request_uri=${encodeQuery(par.request_uri)}`,
    null,
    401,
  );
  return {
    clientId,
    redirectUri,
    requestUri: par.request_uri,
    state,
    codeVerifier,
  };
}

async function expectOAuthAuthorize(par, accessJwt) {
  const response = await fetch(
    `${config.baseUrl}/oauth/authorize?client_id=${encodeQuery(par.clientId)}&request_uri=${encodeQuery(par.requestUri)}`,
    {
      method: "GET",
      headers: { authorization: `Bearer ${accessJwt}` },
      redirect: "manual",
    },
  );
  const text = await response.text();
  if (response.status !== 302) {
    throw new Error(`OAuth authorize expected redirect, got status=${response.status}: ${text}`);
  }
  const location = response.headers.get("location");
  if (!location) {
    throw new Error(`OAuth authorize redirect did not include Location header`);
  }
  const expectedRedirect = new URL(par.redirectUri);
  const actualRedirect = new URL(location);
  if (actualRedirect.origin !== expectedRedirect.origin || actualRedirect.pathname !== expectedRedirect.pathname) {
    throw new Error(`OAuth authorize redirected to unexpected URI ${location}`);
  }
  if (
    !actualRedirect.searchParams.get("code") ||
    actualRedirect.searchParams.get("state") !== par.state ||
    actualRedirect.searchParams.get("iss") !== baseOrigin
  ) {
    throw new Error(`OAuth authorize redirect had unexpected query ${location}`);
  }
  par.code = actualRedirect.searchParams.get("code");
}

async function expectOAuthTokenExchange(par) {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: par.clientId,
    code: par.code,
    redirect_uri: par.redirectUri,
    code_verifier: par.codeVerifier,
  }).toString();
  const token = await expectJson(
    "OAuth token exchange",
    "POST",
    "/oauth/token",
    body,
    (body, response) => {
      if (
        !body.access_token ||
        !body.refresh_token ||
        body.token_type !== "DPoP" ||
        body.expires_in !== 900 ||
        body.sub !== `did:web:${handle}` ||
        !String(body.scope ?? "").split(/\s+/).includes("atproto")
      ) {
        throw new Error(`unexpected OAuth token response ${JSON.stringify(body)}`);
      }
      if (!response.headers.get("dpop-nonce")) {
        throw new Error(`OAuth token response did not include DPoP-Nonce header`);
      }
    },
    { "content-type": "application/x-www-form-urlencoded" },
  );
  await expectStatus(
    "OAuth authorization code replay",
    "POST",
    "/oauth/token",
    body,
    400,
    { "content-type": "application/x-www-form-urlencoded" },
  );
  return token;
}

async function expectOAuthRefresh(clientId, refreshToken) {
  const refreshed = await expectJson(
    "OAuth refresh token",
    "POST",
    "/oauth/token",
    new URLSearchParams({
      grant_type: "refresh_token",
      client_id: clientId,
      refresh_token: refreshToken,
    }).toString(),
    (body, response) => {
      if (!body.access_token || !body.refresh_token || body.token_type !== "DPoP" || body.sub !== `did:web:${handle}`) {
        throw new Error(`unexpected OAuth refresh response ${JSON.stringify(body)}`);
      }
      if (!response.headers.get("dpop-nonce")) {
        throw new Error(`OAuth refresh response did not include DPoP-Nonce header`);
      }
    },
    { "content-type": "application/x-www-form-urlencoded" },
  );
  await expectStatus(
    "OAuth refresh token replay",
    "POST",
    "/oauth/token",
    new URLSearchParams({
      grant_type: "refresh_token",
      client_id: clientId,
      refresh_token: refreshToken,
    }).toString(),
    400,
    { "content-type": "application/x-www-form-urlencoded" },
  );
  return refreshed;
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

function encodeQuery(value) {
  return encodeURIComponent(value);
}

function pkceS256Challenge(verifier) {
  return base64Url(createHash("sha256").update(verifier).digest());
}

function base64Url(bytes) {
  return Buffer.from(bytes).toString("base64").replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}
