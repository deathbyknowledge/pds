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

const xrpcRkey = "xrpc-seed";
const xrpcCreate = await expectJson(
  "XRPC createRecord",
  "POST",
  "/xrpc/com.atproto.repo.createRecord",
  {
    repo: did,
    collection,
    rkey: xrpcRkey,
    record: {
      $type: collection,
      text: "created through XRPC",
      createdAt: new Date().toISOString(),
    },
  },
  (body) => {
    if (body.uri !== `at://${did}/${collection}/${xrpcRkey}` || !body.cid || !body.commit?.cid) {
      throw new Error(`unexpected createRecord response ${JSON.stringify(body)}`);
    }
  },
);

const xrpcPut = await expectJson(
  "XRPC putRecord",
  "POST",
  "/xrpc/com.atproto.repo.putRecord",
  {
    repo: host,
    collection,
    rkey: xrpcRkey,
    record: {
      $type: collection,
      text: "updated through XRPC",
      updatedAt: new Date().toISOString(),
    },
  },
  (body) => {
    if (body.uri !== `at://${did}/${collection}/${xrpcRkey}` || !body.cid || !body.commit?.cid) {
      throw new Error(`unexpected putRecord response ${JSON.stringify(body)}`);
    }
  },
);

const xrpcDelete = await expectJson(
  "XRPC deleteRecord",
  "POST",
  "/xrpc/com.atproto.repo.deleteRecord",
  {
    repo: did,
    collection,
    rkey: xrpcRkey,
  },
  (body) => {
    if (!body.commit?.cid || !body.commit?.rev) {
      throw new Error(`unexpected deleteRecord response ${JSON.stringify(body)}`);
    }
  },
);

let latestCommit = xrpcDelete.commit.cid;
let latestRev = xrpcDelete.commit.rev;

const blobBytes = new TextEncoder().encode("hello from a GSV blob");
const uploadBlob = await expectJson(
  "upload blob",
  "POST",
  "/xrpc/com.atproto.repo.uploadBlob",
  blobBytes,
  (body) => {
    if (body.blob?.mimeType !== "text/plain" || body.blob?.size !== blobBytes.byteLength) {
      throw new Error(`unexpected uploadBlob response ${JSON.stringify(body)}`);
    }
  },
  { "content-type": "text/plain" },
);
const blobCid = uploadBlob.blob.ref?.$link;
if (!blobCid) {
  throw new Error(`uploadBlob response did not include blob ref: ${JSON.stringify(uploadBlob)}`);
}

const applySinceRev = latestRev;
await expectJsonStatus(
  "stale swapCommit",
  "POST",
  "/xrpc/com.atproto.repo.putRecord",
  {
    repo: did,
    collection,
    rkey: "swap-stale",
    swapCommit: xrpcPut.commit.cid,
    record: {
      $type: collection,
      text: "this should not commit",
    },
  },
  400,
);

await expectJsonStatus(
  "swapRecord absent assertion",
  "POST",
  "/xrpc/com.atproto.repo.putRecord",
  {
    repo: did,
    collection,
    rkey,
    swapRecord: null,
    record: {
      $type: collection,
      text: "this should not overwrite an existing record",
    },
  },
  400,
);

const applyWrites = await expectJson(
  "XRPC applyWrites",
  "POST",
  "/xrpc/com.atproto.repo.applyWrites",
  {
    repo: did,
    swapCommit: latestCommit,
    writes: [
      {
        $type: "com.atproto.repo.applyWrites#create",
        collection,
        rkey: "apply-seed",
        value: {
          $type: collection,
          text: "created through applyWrites",
          attachment: blobRef(blobCid, "text/plain", blobBytes.byteLength),
        },
      },
      {
        $type: "com.atproto.repo.applyWrites#create",
        collection,
        rkey: "missing-blob-ref",
        value: {
          $type: collection,
          text: "references a missing blob",
          attachment: blobRef(mutation.latestCommit, "application/octet-stream", 1),
        },
      },
      {
        $type: "com.atproto.repo.applyWrites#create",
        collection,
        value: {
          $type: collection,
          text: "created through applyWrites with generated rkey A",
        },
      },
      {
        $type: "com.atproto.repo.applyWrites#create",
        collection,
        value: {
          $type: collection,
          text: "created through applyWrites with generated rkey B",
        },
      },
    ],
  },
  (body) => {
    if (!body.commit?.cid || body.results?.length !== 4) {
      throw new Error(`unexpected applyWrites response ${JSON.stringify(body)}`);
    }
    const generatedUris = body.results.slice(2).map((result) => result.uri);
    if (
      generatedUris.some((uri) => typeof uri !== "string" || !uri.startsWith(`at://${did}/${collection}/`)) ||
      generatedUris[0] === generatedUris[1]
    ) {
      throw new Error(`applyWrites generated duplicate or invalid rkeys ${JSON.stringify(body)}`);
    }
  },
);
latestCommit = applyWrites.commit.cid;
latestRev = applyWrites.commit.rev;

await expectJson("directory sync", "POST", `/repos/${encodePath(repo)}/directory-sync`, null, (body) => {
  if (body.ok !== true || body.latestCommit !== latestCommit || body.latestRev !== latestRev) {
    throw new Error(`unexpected directory-sync response ${JSON.stringify(body)}`);
  }
});

const listRepos = await expectJson(
  "list repos",
  "GET",
  "/xrpc/com.atproto.sync.listRepos?limit=500",
  null,
  (body) => {
    const hostedRepo = body.repos?.find((repo) => repo.did === did);
    if (!hostedRepo) {
      throw new Error(`listRepos did not include ${did}: ${JSON.stringify(body)}`);
    }
    if (hostedRepo.head !== latestCommit || hostedRepo.rev !== latestRev) {
      throw new Error(`listRepos returned stale repo state: ${JSON.stringify(hostedRepo)}`);
    }
  },
);

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

const head = await expectJson(
  "repo head",
  "GET",
  `/xrpc/com.atproto.sync.getHead?did=${encodeQuery(did)}`,
  null,
  (body) => {
    if (body.root !== latestCommit) {
      throw new Error(`unexpected repo head ${JSON.stringify(body)}, expected ${latestCommit}`);
    }
  },
);

const hostStatus = await expectJson(
  "host status",
  "GET",
  `/xrpc/com.atproto.sync.getHostStatus?hostname=${encodeQuery(base.hostname)}`,
  null,
  (body) => {
    if (body.hostname !== base.hostname || body.status !== "active" || typeof body.seq !== "number") {
      throw new Error(`unexpected host status ${JSON.stringify(body)}`);
    }
  },
);

const reposByCollection = await expectJson(
  "list repos by collection",
  "GET",
  `/xrpc/com.atproto.sync.listReposByCollection?collection=${encodeQuery(collection)}&limit=500`,
  null,
  (body) => {
    const hostedRepo = body.repos?.find((repo) => repo.did === did);
    if (!hostedRepo) {
      throw new Error(`listReposByCollection did not include ${did}: ${JSON.stringify(body)}`);
    }
  },
);

const listBlobs = await expectJson(
  "list blobs",
  "GET",
  `/xrpc/com.atproto.sync.listBlobs?did=${encodeQuery(did)}`,
  null,
  (body) => {
    if (!Array.isArray(body.cids) || !body.cids.includes(blobCid)) {
      throw new Error(`expected blob ${blobCid}, got ${JSON.stringify(body)}`);
    }
  },
);

const missingBlobRefs = await expectJson(
  "list missing blobs",
  "GET",
  "/xrpc/com.atproto.repo.listMissingBlobs",
  null,
  (body) => {
    const expectedUri = `at://${did}/${collection}/missing-blob-ref`;
    const match = body.blobs?.find(
      (blob) => blob.cid === mutation.latestCommit && blob.recordUri === expectedUri,
    );
    if (!match) {
      throw new Error(`expected missing blob ref ${expectedUri}, got ${JSON.stringify(body)}`);
    }
  },
);

await expectBytes(
  "get blob",
  "GET",
  `/xrpc/com.atproto.sync.getBlob?did=${encodeQuery(did)}&cid=${encodeQuery(blobCid)}`,
  null,
  async (response, bytes) => {
    const contentType = response.headers.get("content-type") ?? "";
    if (!contentType.includes("text/plain") || new TextDecoder().decode(bytes) !== "hello from a GSV blob") {
      throw new Error(
        `unexpected blob response content-type=${contentType} bytes=${new TextDecoder().decode(bytes)}`,
      );
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

const missingBlob = await expectJsonStatus(
  "missing blob",
  "GET",
  `/xrpc/com.atproto.sync.getBlob?did=${encodeQuery(did)}&cid=${encodeQuery(mutation.latestCommit)}`,
  null,
  404,
);

await expectJsonStatus(
  "subscribeRepos requires websocket",
  "GET",
  "/xrpc/com.atproto.sync.subscribeRepos",
  null,
  426,
);
const subscribeRepos = await expectSubscribeReposEvent(
  `/xrpc/com.atproto.sync.subscribeRepos?cursor=0`,
);

const repoCar = await request("GET", `/xrpc/com.atproto.sync.getRepo?did=${encodeQuery(did)}`);
const contentType = repoCar.headers.get("content-type") ?? "";
const carBytes = await repoCar.arrayBuffer();
if (!repoCar.ok || !contentType.includes("application/vnd.ipld.car") || carBytes.byteLength === 0) {
  throw new Error(
    `getRepo CAR check failed: status=${repoCar.status} content-type=${contentType} bytes=${carBytes.byteLength}`,
  );
}

const checkoutCar = await request(
  "GET",
  `/xrpc/com.atproto.sync.getCheckout?did=${encodeQuery(did)}`,
);
const checkoutContentType = checkoutCar.headers.get("content-type") ?? "";
const checkoutCarBytes = await checkoutCar.arrayBuffer();
if (
  !checkoutCar.ok ||
  !checkoutContentType.includes("application/vnd.ipld.car") ||
  checkoutCarBytes.byteLength === 0
) {
  throw new Error(
    `getCheckout CAR check failed: status=${checkoutCar.status} content-type=${checkoutContentType} bytes=${checkoutCarBytes.byteLength}`,
  );
}

const blocksCar = await request(
  "GET",
  `/xrpc/com.atproto.sync.getBlocks?did=${encodeQuery(did)}&cids=${encodeQuery(latestCommit)}&cids=${encodeQuery(mutation.latestCommit)}`,
);
const blocksContentType = blocksCar.headers.get("content-type") ?? "";
const blocksCarBytes = await blocksCar.arrayBuffer();
if (
  !blocksCar.ok ||
  !blocksContentType.includes("application/vnd.ipld.car") ||
  blocksCarBytes.byteLength === 0
) {
  throw new Error(
    `getBlocks CAR check failed: status=${blocksCar.status} content-type=${blocksContentType} bytes=${blocksCarBytes.byteLength}`,
  );
}

const missingBlock = await expectJsonStatus(
  "missing repo block",
  "GET",
  `/xrpc/com.atproto.sync.getBlocks?did=${encodeQuery(did)}&cids=${encodeQuery(blobCid)}`,
  null,
  404,
);

const repoDiffCar = await request(
  "GET",
  `/xrpc/com.atproto.sync.getRepo?did=${encodeQuery(did)}&since=${encodeQuery(applySinceRev)}`,
);
const diffContentType = repoDiffCar.headers.get("content-type") ?? "";
const diffCarBytes = await repoDiffCar.arrayBuffer();
if (!repoDiffCar.ok || !diffContentType.includes("application/vnd.ipld.car") || diffCarBytes.byteLength === 0) {
  throw new Error(
    `getRepo diff CAR check failed: status=${repoDiffCar.status} content-type=${diffContentType} bytes=${diffCarBytes.byteLength}`,
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
      seedRecordCommit: mutation.latestCommit,
      latestCommit,
      latestRev,
      xrpcCreateCommit: xrpcCreate.commit.cid,
      xrpcPutCommit: xrpcPut.commit.cid,
      xrpcDeleteCommit: xrpcDelete.commit.cid,
      applyWritesCommit: applyWrites.commit.cid,
      listedRepos: listRepos.repos.length,
      listedReposByCollection: reposByCollection.repos.length,
      listedBlobs: listBlobs.cids.length,
      missingBlobRefs: missingBlobRefs.blobs.length,
      subscribeRepos,
      blobCid,
      missingBlobStatus: missingBlob.status,
      head: head.root,
      hostStatus,
      collection,
      rkey,
      atRepoUri,
      atRecordUri,
      carBytes: carBytes.byteLength,
      checkoutCarBytes: checkoutCarBytes.byteLength,
      blocksCarBytes: blocksCarBytes.byteLength,
      diffCarBytes: diffCarBytes.byteLength,
      missingBlockStatus: missingBlock.status,
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

async function expectText(label, method, path, body, validate = undefined) {
  const response = await request(method, path, body);
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`${label} failed status=${response.status}: ${text}`);
  }
  validate?.(text);
  return text;
}

async function expectBytes(label, method, path, body, validate = undefined, extraHeaders = {}) {
  const response = await request(method, path, body, extraHeaders);
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (!response.ok) {
    throw new Error(`${label} failed status=${response.status}: ${new TextDecoder().decode(bytes)}`);
  }
  await validate?.(response, bytes);
  return bytes;
}

async function expectJsonStatus(label, method, path, body, expectedStatus) {
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
  if (response.status !== expectedStatus) {
    throw new Error(
      `${label} returned status=${response.status}, expected ${expectedStatus}: ${JSON.stringify(parsed)}`,
    );
  }
  if (parsed.error === "MethodNotFound") {
    throw new Error(`${label} still returned MethodNotFound`);
  }
  return { status: response.status, body: parsed };
}

async function expectSubscribeReposEvent(path) {
  if (typeof WebSocket === "undefined") {
    return { skipped: "global WebSocket is unavailable in this Node runtime" };
  }

  const url = new URL(path, `${config.baseUrl}/`);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";

  return new Promise((resolve, reject) => {
    const socket = new WebSocket(url);
    const timeout = setTimeout(() => {
      socket.close();
      reject(new Error(`subscribeRepos did not deliver a binary frame before timeout`));
    }, 3000);

    socket.addEventListener("message", (event) => {
      const byteLength = binaryMessageLength(event.data);
      if (byteLength <= 0) {
        clearTimeout(timeout);
        socket.close();
        reject(new Error(`subscribeRepos returned an empty or non-binary frame`));
        return;
      }
      clearTimeout(timeout);
      socket.close();
      resolve({ binaryFrames: 1, firstFrameBytes: byteLength });
    });
    socket.addEventListener("error", () => {
      clearTimeout(timeout);
      reject(new Error(`subscribeRepos WebSocket failed`));
    });
  });
}

function binaryMessageLength(data) {
  if (data instanceof ArrayBuffer) {
    return data.byteLength;
  }
  if (ArrayBuffer.isView(data)) {
    return data.byteLength;
  }
  if (typeof Blob !== "undefined" && data instanceof Blob) {
    return data.size;
  }
  return 0;
}

async function request(method, path, body = null, extraHeaders = {}) {
  const headers = {
    authorization: `Bearer ${config.adminToken}`,
    ...extraHeaders,
  };
  let payload;
  if (body !== null) {
    if (body instanceof Uint8Array) {
      payload = body;
    } else {
      headers["content-type"] = headers["content-type"] ?? "application/json";
      payload = JSON.stringify(body);
    }
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

function blobRef(cid, mimeType, size) {
  return {
    $type: "blob",
    ref: { $link: cid },
    mimeType,
    size,
  };
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
