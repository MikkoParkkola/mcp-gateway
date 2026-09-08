// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import assert from "node:assert/strict";
import test from "node:test";
import { canonicalize, macHex, macInput, requestIdFor, verifyResponse } from "./signing_verifier.mjs";

const KEY = "independent-signing-test-key-0123456789abcdef";
const NOW = 1700000000;
const ID = { kind: "number", value: "1" };
const BODY = { content: [{ type: "text", text: "hello" }], isError: false };

function fixture({ body = BODY, id = ID, nonce = "test-nonce", timestamp = NOW } = {}) {
  const signature = { alg: "hmac-sha256", version: 2, nonce, ts: timestamp, key_id: "test-current" };
  signature.sig = macHex(macInput(body, id, signature), KEY);
  const response = { jsonrpc: "2.0", id: id?.kind === "number" ? "__LOSSLESS_NUMERIC_ID__" : (id?.value ?? null), result: { ...body, _signature: signature } };
  let wire = JSON.stringify(response);
  if (id?.kind === "number") wire = wire.replace('"id":"__LOSSLESS_NUMERIC_ID__"', `"id":${id.value}`);
  return { wire, options: { key: KEY, keyId: "test-current", expectedId: id, expectedNonce: nonce, now: NOW } };
}

test("RFC 8785 primitive serialization and UTF-16 property ordering", () => {
  // RFC 8785 sections 3.2.2 and 3.2.3: primary-source conformance values.
  // https://www.rfc-editor.org/rfc/rfc8785.html#section-3.2.2
  assert.equal(canonicalize([333333333.33333329, 1e30, 4.50, 2e-3, 1e-27, -0]), "[333333333.3333333,1e+30,4.5,0.002,1e-27,0]");
  assert.equal(canonicalize({ "\ufb33": 7, "😀": 6, "€": 5, "ö": 4, "\u0080": 3, "1": 2, "\r": 1 }), '{"\\r":1,"1":2,"\u0080":3,"ö":4,"€":5,"😀":6,"דּ":7}');
  assert.equal(canonicalize({ nested: [{ z: true, a: null }], escapes: "\b\t\n\f\r\0\\\"" }), '{"escapes":"\\b\\t\\n\\f\\r\\u0000\\\\\\\"","nested":[{"a":null,"z":true}]}');
  assert.throws(() => canonicalize("\ud800"), /surrogate/);
  assert.throws(() => canonicalize(Infinity), /non-finite/);
});

test("fixed v2 known answer agrees with handwritten canonical input and Python HMAC", () => {
  const signature = { alg: "hmac-sha256", version: 2, nonce: "test-nonce", ts: NOW, key_id: "test-current" };
  const input = macInput(BODY, ID, signature);
  const canonical = '{"alg":"hmac-sha256","body":{"content":[{"text":"hello","type":"text"}],"isError":false},"domain":"mcp-gateway-response-v2","key_id":"test-current","nonce":"test-nonce","request_id":{"kind":"number","value":"1"},"ts":1700000000,"version":2}';
  assert.equal(canonicalize(input), canonical);
  // Independently generated with Python hmac.new(KEY, canonical, sha256).
  assert.equal(macHex(input, KEY), "25108f07ec41691cd5db351e233d72a62b4dc49271ae79cfd2fb0d713c0d3fd0");
  const { wire, options } = fixture();
  const verified = verifyResponse(wire, options);
  assert.equal(verified.result.content[0].text, "hello");
  assert.deepEqual(requestIdFor(verified), ID);
  assert.throws(() => requestIdFor(JSON.parse(wire)), /not verified/);
});

test("body and every signature field mutation is refused", () => {
  const { wire, options } = fixture();
  for (const mutate of [
    (response) => { response.result.content[0].text = "changed"; },
    (response) => { response.result._signature.sig = "0".repeat(64); },
    (response) => { response.result._signature.ts += 1; },
    (response) => { response.result._signature.alg = "hmac-sha512"; },
    (response) => { response.result._signature.version = 1; },
    (response) => { delete response.result._signature.version; },
  ]) {
    const response = JSON.parse(wire);
    mutate(response);
    assert.throws(() => verifyResponse(JSON.stringify(response), options));
  }
  const relabeledKey = JSON.parse(wire);
  relabeledKey.result._signature.key_id = "forged-key-id";
  assert.throws(() => verifyResponse(JSON.stringify(relabeledKey), { ...options, keyId: "forged-key-id" }), /MAC mismatch/);
});

test("signature object is a closed six-member contract", () => {
  const { wire, options } = fixture();
  verifyResponse(wire, options);
  for (const name of ["trusted", "request_id", "domain"]) {
    const forged = JSON.parse(wire);
    forged.result._signature[name] = "attacker-controlled";
    assert.throws(() => verifyResponse(JSON.stringify(forged), options), /unexpected signature members/);
  }
});

test("verified response and typed-ID association are recursively immutable", () => {
  const { wire, options } = fixture();
  const verified = verifyResponse(wire, options);
  assert.throws(() => { verified.result.content[0].text = "forged"; }, TypeError);
  assert.throws(() => { verified.result._signature.key_id = "forged"; }, TypeError);
  assert.throws(() => { requestIdFor(verified).value = "2"; }, TypeError);
  assert.equal(verified.result.content[0].text, "hello");
  assert.deepEqual(requestIdFor(verified), ID);
});

test("nonce UTF-8 byte bounds reject valid-MAC invalid nonces", () => {
  for (const nonce of [null, "x", "x".repeat(256), "🦀".repeat(64)]) {
    const { wire, options } = fixture({ nonce });
    verifyResponse(wire, options);
  }
  for (const nonce of ["", "x".repeat(257), "🦀".repeat(65)]) {
    const { wire, options } = fixture({ nonce });
    assert.throws(() => verifyResponse(wire, options), /invalid signature nonce/);
  }
});

test("null, string and i64 extrema have independently pinned typed-ID MAC inputs", () => {
  const signature = { alg: "hmac-sha256", version: 2, nonce: "test-nonce", ts: NOW, key_id: "test-current" };
  for (const [id, encoded, mac] of [
    [null, "null", "6fca4467b943bf495e1e8eedf4e15bceb21a729bd5c02540356e0795a6f23e21"],
    [{ kind: "string", value: "1" }, '{"kind":"string","value":"1"}', "183ef29999c3c56b9ff3fd63bf3ea920b5474e3a1c97c87053adfa75b26fe771"],
    [{ kind: "number", value: "-9223372036854775808" }, '{"kind":"number","value":"-9223372036854775808"}', "755d3de10b5f9555087c5ff79748be4917df1aa18c58bc32991b87a698a95ed1"],
    [{ kind: "number", value: "9223372036854775807" }, '{"kind":"number","value":"9223372036854775807"}', "fb7a95d629f1d6d4a2de33ee3bd82343d8fb1080d9423441594e4964b4b3976e"],
  ]) {
    const canonical = '{"alg":"hmac-sha256","body":{"content":[{"text":"hello","type":"text"}],"isError":false},"domain":"mcp-gateway-response-v2","key_id":"test-current","nonce":"test-nonce","request_id":' + encoded + ',"ts":1700000000,"version":2}';
    assert.equal(canonicalize(macInput(BODY, id, signature)), canonical);
    assert.equal(macHex(macInput(BODY, id, signature), KEY), mac);
  }
});

test("nonce relabeling fails the MAC after expected-nonce equality passes", () => {
  const { wire, options } = fixture();
  const forged = JSON.parse(wire);
  forged.result._signature.nonce = "forged-nonce";
  assert.throws(() => verifyResponse(JSON.stringify(forged), { ...options, expectedNonce: "forged-nonce" }), /MAC mismatch/);
});

test("combined Unicode and floating-point envelope pins the cross-language vector", () => {
  const body = {
    nested: [{ z: "supplementary 😀", a: "\u000f\n\\\"" }], "דּ": 7, "😀": 6, "€": 5,
    numbers: [333333333.3333333, 1e30, 4.5, 2e-3, 1e-27, -0, 9007199254740991, -9007199254740991],
  };
  const id = { kind: "string", value: "unicode-\u200b-id" };
  const signature = { alg: "hmac-sha256", version: 2, nonce: "vector-🦀", ts: NOW, key_id: "test-current" };
  const bodyCanonical = String.raw`{"nested":[{"a":"\u000f\n\\\"","z":"supplementary 😀"}],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27,0,9007199254740991,-9007199254740991],"€":5,"😀":6,"דּ":7}`;
  const canonical = '{"alg":"hmac-sha256","body":' + bodyCanonical + ',"domain":"mcp-gateway-response-v2","key_id":"test-current","nonce":"vector-🦀","request_id":{"kind":"string","value":"unicode-\u200b-id"},"ts":1700000000,"version":2}';
  assert.equal(canonicalize(macInput(body, id, signature)), canonical);
  assert.equal(macHex(macInput(body, id, signature), KEY), "9deaafde7102ed0e4fb66513836842251c46035c009cca9c8a187625e5197f7f");
});

test("typed ID relabeling fails the MAC after expected-ID equality passes", () => {
  for (const nonce of ["test-nonce", null]) {
    const { wire, options } = fixture({ nonce });
    for (const [id, expectedId] of [[2, { kind: "number", value: "2" }], ["1", { kind: "string", value: "1" }]]) {
      const forged = JSON.parse(wire);
      forged.id = id;
      assert.throws(() => verifyResponse(JSON.stringify(forged), { ...options, expectedId }), /MAC mismatch/);
    }
  }
});

test("signed i64 extrema survive raw-wire verification without rounding", () => {
  for (const decimal of ["-9223372036854775808", "9223372036854775807"]) {
    const { wire, options } = fixture({ id: { kind: "number", value: decimal } });
    const verified = verifyResponse(wire, options);
    assert.equal(typeof verified.id, "bigint");
    assert.equal(verified.id.toString(), decimal);
    assert.equal(requestIdFor(verified).value, decimal);
  }
  for (const id of [null, { kind: "string", value: "id\u200b\u0000" }]) {
    const { wire, options } = fixture({ id });
    assert.deepEqual(requestIdFor(verifyResponse(wire, options)), id);
  }
});

test("unsupported numeric IDs cannot be coerced into supported IDs", () => {
  const { wire, options } = fixture();
  for (const numeric of ["9223372036854775808", "18446744073709551615", "-9223372036854775809", "1.5"]) {
    assert.throws(() => verifyResponse(wire.replace('"id":1', `"id":${numeric}`), options), /response ID/);
  }
});

test("all duplicate response members are refused even when duplicate values match", () => {
  const { wire, options } = fixture();
  for (const [before, after] of [
    ['"jsonrpc":"2.0"', '"jsonrpc":"2.0","jsonrpc":"2.0"'],
    ['"id":1', '"id":1,"id":1'],
    ['"result":', '"result":{},"result":'],
    ['"_signature":', '"_signature":{},"_signature":'],
    ['"text":"hello"', '"text":"hello","text":"hello"'],
    ['"nonce":"test-nonce"', '"nonce":"test-nonce","\\u006eonce":"test-nonce"'],
    ['"ts":1700000000', '"ts":1700000000,"ts":1700000000'],
  ]) {
    assert.notEqual(before, after);
    assert(wire.includes(before), "duplicate probe must reach its intended field");
    assert.throws(() => verifyResponse(wire.replace(before, after), options), /duplicate/);
  }
});

test("JSON-RPC envelope validation is independent of a valid result MAC", () => {
  const { wire, options } = fixture();
  for (const mutate of [
    (response) => { delete response.jsonrpc; },
    (response) => { response.jsonrpc = "1.0"; },
    (response) => { response.error = null; },
    (response) => { response.error = { code: -1, message: "forged" }; },
  ]) {
    const response = JSON.parse(wire);
    mutate(response);
    assert.throws(() => verifyResponse(JSON.stringify(response), options));
  }
});

test("valid-MAC freshness boundaries use injected verifier time", () => {
  for (const age of [300, -30]) {
    const { wire, options } = fixture({ timestamp: NOW - age });
    verifyResponse(wire, options);
  }
  for (const age of [301, -31]) {
    const { wire, options } = fixture({ timestamp: NOW - age });
    assert.throws(() => verifyResponse(wire, options), /freshness/);
  }
});

test("exact unsafe body integers reject while embedded JSON text stays opaque", () => {
  const unsafe = fixture({ body: { value: 9007199254740992 } });
  assert.throws(() => verifyResponse(unsafe.wire, unsafe.options), /unsafe exact body integer/);
  const text = '{"exact":18446744073709551615}';
  const safe = fixture({ body: { content: [{ type: "text", text }] } });
  assert.equal(verifyResponse(safe.wire, safe.options).result.content[0].text, text);
  const float = fixture({ body: { value: 1e20 } });
  const exponentWire = float.wire.replace('"value":100000000000000000000', '"value":1e+20');
  assert.notEqual(exponentWire, float.wire);
  assert.equal(verifyResponse(exponentWire, float.options).result.value, 1e20);
});
