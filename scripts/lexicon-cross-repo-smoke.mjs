#!/usr/bin/env node
import { webcrypto } from "node:crypto";

const crypto = globalThis.crypto ?? webcrypto;

const config = {
  baseUrl: requiredEnv("PDS_BASE_URL").replace(/\/+$/, ""),
  adminToken: requiredEnv("PDS_ADMIN_TOKEN"),
  authorityDomain: optionalEnv("PDS_LEXICON_AUTHORITY_DOMAIN", "gsv.app"),
  sourceRepo: optionalEnv("PDS_LEXICON_SOURCE_REPO"),
  sourceDid: optionalEnv("PDS_LEXICON_SOURCE_DID"),
  sourceHandle: optionalEnv("PDS_LEXICON_SOURCE_HANDLE"),
  targetRepo: optionalEnv("PDS_LEXICON_TARGET_REPO", `lexicon-target-${Date.now().toString(36)}`),
  collection: optionalEnv("PDS_LEXICON_COLLECTION"),
};

const base = new URL(config.baseUrl);
const sourceRepo = config.sourceRepo ?? base.hostname;
const sourceDid = config.sourceDid ?? `did:web:${sourceRepo}`;
const sourceHandle = config.sourceHandle ?? base.hostname;
const targetDid = `did:gsv:${config.targetRepo}`;
const targetHandle = `${config.targetRepo}.${base.hostname}`;
const collection = config.collection ?? collectionFromAuthorityDomain(config.authorityDomain, "crossRepoSmoke");
const rkey = `cross-${Date.now().toString(36)}`;
const expectedOverride = `${config.authorityDomain}=${sourceDid}`;

await expectJson("health", "GET", "/xrpc/_health", null, (body) => {
  if (body.status !== "ok") {
    throw new Error(`expected health status ok, got ${JSON.stringify(body)}`);
  }
});

await ensureRepoInitialized(sourceRepo, sourceDid, sourceHandle, false);
await initRepo(config.targetRepo, targetDid, targetHandle, "2222222222222", true);

const lexicon = recordLexicon(collection);
const published = await expectJson(
  "publish source Lexicon",
  "POST",
  `/repos/${encodePath(sourceRepo)}/lexicons`,
  lexicon,
  (body) => {
    if (
      body.id !== collection ||
      body.stored !== true ||
      body.published !== true ||
      body.uri !== `at://${sourceDid}/com.atproto.lexicon.schema/${collection}`
    ) {
      throw new Error(`unexpected Lexicon publication response ${JSON.stringify(body)}`);
    }
  },
);

await expectJson(
  "source Lexicon record",
  "GET",
  `/xrpc/com.atproto.repo.getRecord?repo=${encodeQuery(sourceDid)}&collection=com.atproto.lexicon.schema&rkey=${encodeQuery(collection)}`,
  null,
  (body) => {
    if (
      body.uri !== `at://${sourceDid}/com.atproto.lexicon.schema/${collection}` ||
      body.value?.$type !== "com.atproto.lexicon.schema" ||
      body.value?.id !== collection
    ) {
      throw new Error(`unexpected source Lexicon record ${JSON.stringify(body)}`);
    }
  },
);

const created = await createTargetRecord();
await expectJson(
  "target cached Lexicons",
  "GET",
  `/repos/${encodePath(config.targetRepo)}/lexicons`,
  null,
  (body) => {
    if (!Array.isArray(body.lexicons) || !body.lexicons.includes(collection)) {
      throw new Error(`target repo did not cache ${collection}: ${JSON.stringify(body)}`);
    }
  },
);

await expectJson(
  "target dynamic record",
  "GET",
  `/xrpc/com.atproto.repo.getRecord?repo=${encodeQuery(targetDid)}&collection=${encodeQuery(collection)}&rkey=${encodeQuery(rkey)}`,
  null,
  (body) => {
    if (body.uri !== `at://${targetDid}/${collection}/${rkey}` || body.value?.$type !== collection) {
      throw new Error(`unexpected target record ${JSON.stringify(body)}`);
    }
  },
);

console.log(
  JSON.stringify(
    {
      ok: true,
      baseUrl: config.baseUrl,
      authorityDomain: config.authorityDomain,
      expectedWorkerEnv: {
        PDS_LEXICON_AUTHORITY_DIDS: expectedOverride,
      },
      sourceRepo,
      sourceDid,
      targetRepo: config.targetRepo,
      targetDid,
      collection,
      publishedLexicon: published.uri,
      targetRecord: `at://${targetDid}/${collection}/${rkey}`,
      latestCommit: created.latestCommit,
    },
    null,
    2,
  ),
);

async function createTargetRecord() {
  const body = {
    path: `${collection}/${rkey}`,
    rev: "2222222222223",
    validate: true,
    record: {
      $type: collection,
      text: "validated from a Lexicon published by another repo",
      createdAt: new Date().toISOString(),
    },
  };
  const response = await request("POST", `/repos/${encodePath(config.targetRepo)}/records`, body);
  const text = await response.text();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw new Error(`target create returned non-JSON status=${response.status}: ${text}`, {
      cause: error,
    });
  }
  if (!response.ok) {
    if (String(parsed.error ?? parsed.message ?? "").includes("Lexicon")) {
      throw new Error(
        `target create failed to resolve ${collection}. Set Worker env PDS_LEXICON_AUTHORITY_DIDS=${expectedOverride}. Response: ${JSON.stringify(parsed)}`,
      );
    }
    throw new Error(`target create failed status=${response.status}: ${JSON.stringify(parsed)}`);
  }
  if (parsed.validationStatus !== "valid" || !parsed.latestCommit || !parsed.recordCid) {
    throw new Error(`unexpected target create response ${JSON.stringify(parsed)}`);
  }
  return parsed;
}

async function ensureRepoInitialized(repo, did, handle, reset) {
  const status = await expectJson("repo status", "GET", `/repos/${encodePath(repo)}/status`);
  if (status.initialized) {
    if (status.did !== did) {
      throw new Error(`repo ${repo} is initialized for ${status.did}, expected ${did}`);
    }
    return status;
  }
  return initRepo(repo, did, handle, "2222222222222", reset);
}

async function initRepo(repo, did, handle, rev, reset) {
  return expectJson("init repo", "POST", `/repos/${encodePath(repo)}/init`, {
    did,
    handle,
    rev,
    signingKeyP256Hex: await generateP256PrivateKeyHex(),
    reset,
  });
}

function recordLexicon(id) {
  return {
    lexicon: 1,
    id,
    defs: {
      main: {
        type: "record",
        key: "any",
        record: {
          type: "object",
          required: ["$type", "text"],
          properties: {
            $type: { type: "string", const: id },
            text: { type: "string", maxLength: 4096 },
            createdAt: { type: "string", format: "datetime" },
          },
        },
      },
    },
  };
}

async function expectJson(label, method, path, body = null, validate = undefined) {
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
  validate?.(parsed, response);
  return parsed;
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

function collectionFromAuthorityDomain(domain, name) {
  const labels = domain.split(".").filter(Boolean);
  if (labels.length < 2) {
    throw new Error(`PDS_LEXICON_AUTHORITY_DOMAIN must have at least two labels, got ${domain}`);
  }
  return `${labels.reverse().join(".")}.${name}`;
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

function encodePath(value) {
  return value.split("/").map(encodeURIComponent).join("/");
}

function encodeQuery(value) {
  return encodeURIComponent(value);
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
