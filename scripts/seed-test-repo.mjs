#!/usr/bin/env node
import { webcrypto } from "node:crypto";

const crypto = globalThis.crypto ?? webcrypto;

const config = {
  baseUrl: requiredEnv("PDS_BASE_URL").replace(/\/+$/, ""),
  adminToken: requiredEnv("PDS_ADMIN_TOKEN"),
  handle: optionalEnv("PDS_HANDLE"),
  did: optionalEnv("PDS_DID"),
  repo: optionalEnv("PDS_REPO"),
  signingKeyHex: optionalEnv("PDS_SIGNING_KEY_P256_HEX"),
  reset: optionalEnv("PDS_RESET", "true") !== "false",
  initRev: optionalEnv("PDS_INIT_REV", "2222222222222"),
  recordRev: optionalEnv("PDS_RECORD_REV", "2222222222223"),
  recordPath: optionalEnv("PDS_RECORD_PATH", "app.gsv.record/seed"),
  recordJson: optionalEnv("PDS_RECORD_JSON"),
};

const base = new URL(config.baseUrl);
const host = config.handle ?? base.hostname;
const did = config.did ?? `did:web:${host}`;
const repo = config.repo ?? repoNameFromDidOrHandle(did, host);
const signingKeyHex = config.signingKeyHex ?? (await generateP256PrivateKeyHex());
const [collection, rkey] = parseRecordPath(config.recordPath);
const record = config.recordJson
  ? JSON.parse(config.recordJson)
  : {
      $type: collection,
      text: "Hello from a seeded GSV PDS test repo",
      createdAt: new Date().toISOString(),
    };
const baseOrigin = base.origin;

assertP256Hex(signingKeyHex);

await expectJson("health", "GET", "/xrpc/_health", null, (body) => {
  if (body.status !== "ok") {
    throw new Error(`expected health status ok, got ${JSON.stringify(body)}`);
  }
});

const init = await expectJson("init repo", "POST", `/repos/${encodePath(repo)}/init`, {
  did,
  handle: host,
  rev: config.initRev,
  signingKeyP256Hex: signingKeyHex,
  reset: config.reset,
});

const didDocument = await expectJson(
  "DID document",
  "GET",
  "/.well-known/did.json",
  null,
  (body) => {
    if (body.id !== did) {
      throw new Error(`DID document returned id ${body.id}, expected ${did}`);
    }
    const serviceEndpoint = atprotoServiceEndpoint(body);
    if (serviceEndpoint !== baseOrigin) {
      throw new Error(
        `DID document returned service endpoint ${serviceEndpoint}, expected ${baseOrigin}`,
      );
    }
  },
);

const handleDid = await expectText("handle DID", "GET", "/.well-known/atproto-did", null, (body) => {
  if (body.trim() !== did) {
    throw new Error(`handle DID returned ${body}, expected ${did}`);
  }
});

const mutation = await expectJson("seed record", "POST", `/repos/${encodePath(repo)}/records`, {
  path: config.recordPath,
  rev: config.recordRev,
  record,
});

const describe = await expectJson(
  "describe repo",
  "GET",
  `/xrpc/com.atproto.repo.describeRepo?repo=${encodeQuery(host)}`,
  null,
  (body) => {
    if (body.did !== did) {
      throw new Error(`describeRepo returned DID ${body.did}, expected ${did}`);
    }
    if (!body.collections?.includes(collection)) {
      throw new Error(`describeRepo did not include collection ${collection}`);
    }
  },
);

await expectJson(
  "repo status",
  "GET",
  `/xrpc/com.atproto.sync.getRepoStatus?did=${encodeQuery(did)}`,
  null,
  (body) => {
    if (body.did !== did || body.active !== true) {
      throw new Error(`unexpected repo status ${JSON.stringify(body)}`);
    }
  },
);

await expectJson(
  "get record",
  "GET",
  `/xrpc/com.atproto.repo.getRecord?repo=${encodeQuery(host)}&collection=${encodeQuery(collection)}&rkey=${encodeQuery(rkey)}`,
  null,
  (body) => {
    if (body.uri !== `at://${did}/${collection}/${rkey}`) {
      throw new Error(`unexpected record URI ${body.uri}`);
    }
  },
);

const repoCar = await request("GET", `/xrpc/com.atproto.sync.getRepo?did=${encodeQuery(did)}`);
const contentType = repoCar.headers.get("content-type") ?? "";
const carBytes = await repoCar.arrayBuffer();
if (!repoCar.ok || !contentType.includes("application/vnd.ipld.car") || carBytes.byteLength === 0) {
  throw new Error(
    `getRepo CAR check failed: status=${repoCar.status} content-type=${contentType} bytes=${carBytes.byteLength}`,
  );
}

const atRepoUri = `at://${did}`;
const atRecordUri = `${atRepoUri}/${collection}/${rkey}`;
const pdslsRepoUrl = `https://pdsls.dev/${atRepoUri}`;
const pdslsRecordUrl = `https://pdsls.dev/${atRecordUri}`;

console.log(
  JSON.stringify(
    {
      ok: true,
      baseUrl: config.baseUrl,
      repo,
      did,
      handle: host,
      handleDid: handleDid.trim(),
      didDocumentServiceEndpoint: atprotoServiceEndpoint(didDocument),
      publicKeyMultibase: init.publicKeyMultibase,
      latestCommit: mutation.latestCommit,
      latestRev: mutation.latestRev,
      collection,
      rkey,
      atRepoUri,
      atRecordUri,
      carBytes: carBytes.byteLength,
      pdslsRepoUrl,
      pdslsRecordUrl,
      generatedSigningKey: config.signingKeyHex ? false : true,
      signingKeyP256Hex: signingKeyHex,
      handleIsCorrect: describe.handleIsCorrect,
    },
    null,
    2,
  ),
);

async function expectJson(label, method, path, body, validate = undefined) {
  const response = await request(method, path, body);
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

async function expectText(label, method, path, body, validate = undefined) {
  const response = await request(method, path, body);
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`${label} failed status=${response.status}: ${text}`);
  }
  validate?.(text);
  return text;
}

async function request(method, path, body = null) {
  const headers = {
    authorization: `Bearer ${config.adminToken}`,
  };
  let payload;
  if (body !== null) {
    headers["content-type"] = "application/json";
    payload = JSON.stringify(body);
  }
  return fetch(new URL(path, `${config.baseUrl}/`), {
    method,
    headers,
    body: payload,
  });
}

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) {
    console.error(`${name} is required`);
    process.exit(2);
  }
  return value;
}

function optionalEnv(name, fallback = undefined) {
  const value = process.env[name];
  return value === undefined || value === "" ? fallback : value;
}

function repoNameFromDidOrHandle(did, handle) {
  if (did.startsWith("did:gsv:")) {
    return did.slice("did:gsv:".length);
  }
  if (did.startsWith("did:web:")) {
    return did.slice("did:web:".length);
  }
  return handle;
}

function atprotoServiceEndpoint(didDocument) {
  return didDocument.service?.find((service) => service.id === "#atproto_pds")
    ?.serviceEndpoint;
}

function parseRecordPath(path) {
  const parts = path.split("/");
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    throw new Error(`PDS_RECORD_PATH must be collection/rkey, got ${path}`);
  }
  return parts;
}

function encodePath(value) {
  return encodeURIComponent(value);
}

function encodeQuery(value) {
  return encodeURIComponent(value);
}

function assertP256Hex(value) {
  if (!/^[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error("PDS_SIGNING_KEY_P256_HEX must be 64 hex characters");
  }
}

async function generateP256PrivateKeyHex() {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const jwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
  if (!jwk.d) {
    throw new Error("generated P-256 key did not include private scalar");
  }
  return bytesToHex(base64UrlDecode(jwk.d));
}

function base64UrlDecode(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), "=");
  return Uint8Array.from(Buffer.from(padded, "base64"));
}

function bytesToHex(bytes) {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
