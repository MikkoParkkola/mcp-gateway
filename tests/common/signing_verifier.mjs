// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Independent ECMAScript oracle for the MIK-7406 response-signing test suite.
// No gateway signer or Rust canonicalization/input helper is used here.

import { createHmac, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const MIN_I64 = -(1n << 63n);
const MAX_I64 = (1n << 63n) - 1n;
const MAX_SAFE_INTEGER = BigInt(Number.MAX_SAFE_INTEGER);
const verifiedIds = new WeakMap();

function requireThat(condition, message) {
  if (!condition) throw new Error(message);
}

function checkUnicode(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(++index);
      requireThat(next >= 0xdc00 && next <= 0xdfff, "unpaired UTF-16 surrogate");
    } else {
      requireThat(code < 0xdc00 || code > 0xdfff, "unpaired UTF-16 surrogate");
    }
  }
}

// RFC 8785 uses ECMAScript number/string serialization and UTF-16 key ordering.
// Integer-domain validation happens against original numeric tokens below;
// floating-point values such as 1e20 must still use ECMAScript formatting here.
export function canonicalize(value) {
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "string") {
    checkUnicode(value);
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    requireThat(Number.isFinite(value), "non-finite JSON number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  requireThat(typeof value === "object", "unsupported JSON value");
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${canonicalize(key)}:${canonicalize(value[key])}`)
    .join(",")}}`;
}

// A syntax walk detects duplicate names BEFORE JSON.parse discards them.
// JSON.parse remains the syntax authority; this walk never interprets numbers.
function rejectDuplicateMembers(wire) {
  let offset = 0;
  function whitespace() {
    while (/[\t\n\r ]/.test(wire[offset] ?? "\0")) offset += 1;
  }
  function string() {
    requireThat(wire[offset] === '"', "expected JSON object key");
    const start = offset++;
    while (offset < wire.length) {
      const char = wire[offset++];
      if (char === "\\") offset += 1;
      else if (char === '"') {
        const value = JSON.parse(wire.slice(start, offset));
        checkUnicode(value);
        return value;
      }
    }
    throw new Error("unterminated JSON string");
  }
  function value() {
    whitespace();
    if (wire[offset] === '"') {
      string();
      return;
    }
    if (wire[offset] === "{") {
      offset += 1;
      whitespace();
      const names = new Set();
      if (wire[offset] === "}") {
        offset += 1;
        return;
      }
      while (true) {
        whitespace();
        const name = string();
        requireThat(!names.has(name), "duplicate JSON response member");
        names.add(name);
        whitespace();
        requireThat(wire[offset++] === ":", "expected JSON colon");
        value();
        whitespace();
        const separator = wire[offset++];
        if (separator === "}") return;
        requireThat(separator === ",", "expected JSON object separator");
      }
    }
    if (wire[offset] === "[") {
      offset += 1;
      whitespace();
      if (wire[offset] === "]") {
        offset += 1;
        return;
      }
      while (true) {
        value();
        whitespace();
        const separator = wire[offset++];
        if (separator === "]") return;
        requireThat(separator === ",", "expected JSON array separator");
      }
    }
    const start = offset;
    while (offset < wire.length && !/[\t\n\r ,\]}]/.test(wire[offset])) offset += 1;
    requireThat(offset > start, "missing JSON value");
  }
  value();
  whitespace();
  requireThat(offset === wire.length, "trailing JSON data");
}

function parseResponse(wire) {
  rejectDuplicateMembers(wire);
  const numericSources = [];
  const parsed = JSON.parse(wire, function (key, value, context) {
    if (typeof value === "number") {
      requireThat(typeof context?.source === "string", "lossless JSON reviver unavailable");
      numericSources.push({ holder: this, key, source: context.source });
    }
    return value;
  });
  requireThat(parsed !== null && typeof parsed === "object" && !Array.isArray(parsed), "response object required");
  const idSource = numericSources.find(({ holder, key }) => holder === parsed && key === "id")?.source;
  for (const { holder, key, source } of numericSources) {
    if (holder === parsed && key === "id") continue;
    if (/^-?(?:0|[1-9][0-9]*)$/.test(source)) {
      const exact = BigInt(source);
      requireThat(exact >= -MAX_SAFE_INTEGER && exact <= MAX_SAFE_INTEGER, "unsafe exact body integer");
    }
  }
  let typedId;
  if (parsed.id === null) typedId = null;
  else if (typeof parsed.id === "string") typedId = { kind: "string", value: parsed.id };
  else {
    requireThat(typeof parsed.id === "number" && /^-?(?:0|[1-9][0-9]*)$/.test(idSource ?? ""), "invalid numeric response ID");
    const exact = BigInt(idSource);
    requireThat(exact >= MIN_I64 && exact <= MAX_I64, "response ID outside signed i64");
    typedId = { kind: "number", value: exact.toString() };
    // The returned verified object retains the exact ID. Unsafe numeric IDs
    // become BigInt in this reference API, never a rounded Number or string ID.
    if (exact < -MAX_SAFE_INTEGER || exact > MAX_SAFE_INTEGER) parsed.id = exact;
  }
  return { parsed, typedId };
}

export function macInput(body, typedId, signature) {
  return {
    domain: "mcp-gateway-response-v2",
    body,
    request_id: typedId,
    alg: signature.alg,
    version: signature.version,
    nonce: signature.nonce,
    ts: signature.ts,
    key_id: signature.key_id,
  };
}

export function macHex(input, key) {
  return createHmac("sha256", Buffer.from(key, "utf8"))
    .update(canonicalize(input), "utf8")
    .digest("hex");
}

export function requestIdFor(verified) {
  requireThat(verifiedIds.has(verified), "object was not verified");
  return verifiedIds.get(verified);
}

function freezeVerified(value) {
  if (value !== null && typeof value === "object") {
    for (const child of Object.values(value)) freezeVerified(child);
    Object.freeze(value);
  }
  return value;
}

// Returns the single parsed and verified object, not a Boolean that encourages
// the caller to parse a second, potentially different representation afterward.
export function verifyResponse(wire, { key, keyId, expectedId, expectedNonce, now = Math.floor(Date.now() / 1000) }) {
  const { parsed, typedId } = parseResponse(wire);
  requireThat(parsed.jsonrpc === "2.0", "unsupported JSON-RPC envelope");
  requireThat(Object.hasOwn(parsed, "result") && !Object.hasOwn(parsed, "error"), "successful result-only response required");
  const result = parsed.result;
  requireThat(result !== null && typeof result === "object" && !Array.isArray(result), "object result required");
  const signature = result._signature;
  requireThat(signature !== null && typeof signature === "object" && !Array.isArray(signature), "signature object required");
  requireThat(Object.keys(signature).sort().join(",") === "alg,key_id,nonce,sig,ts,version", "unexpected signature members");
  requireThat(signature.version === 2 && signature.alg === "hmac-sha256", "unsupported signature format");
  requireThat(typeof signature.key_id === "string" && signature.key_id.trim() !== "" && signature.key_id === keyId, "wrong key ID");
  requireThat(signature.nonce === null || (typeof signature.nonce === "string" && Buffer.byteLength(signature.nonce, "utf8") > 0 && Buffer.byteLength(signature.nonce, "utf8") <= 256), "invalid signature nonce");
  requireThat(signature.nonce === expectedNonce, "unexpected nonce");
  requireThat(canonicalize(typedId) === canonicalize(expectedId), "unexpected request ID");
  requireThat(Number.isSafeInteger(signature.ts) && signature.ts >= 0 && Number.isSafeInteger(now), "invalid timestamp");
  requireThat(now - signature.ts <= 300 && signature.ts - now <= 30, "signature outside freshness window");
  requireThat(typeof signature.sig === "string" && /^[0-9a-f]{64}$/.test(signature.sig), "invalid MAC encoding");
  const body = Object.fromEntries(Object.entries(result).filter(([name]) => name !== "_signature"));
  const expected = Buffer.from(macHex(macInput(body, typedId, signature), key), "hex");
  requireThat(timingSafeEqual(Buffer.from(signature.sig, "hex"), expected), "MAC mismatch");
  verifiedIds.set(parsed, freezeVerified(typedId));
  return freezeVerified(parsed);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const input = JSON.parse(readFileSync(0, "utf8"));
    const verified = verifyResponse(input.wire, input.options);
    // CLI diagnostics preserve the typed ID separately; the module API above
    // returns the original verified object with a lossless BigInt when needed.
    process.stdout.write(JSON.stringify({ request_id: requestIdFor(verified), result: verified.result }));
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
