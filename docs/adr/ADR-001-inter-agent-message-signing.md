# ADR-001: Inter-Agent Message Signing

**Date**: 2026-04-16
**Status**: Proposed
**Deciders**: Mikko Parkkola
**OWASP Reference**: ASI07 (Insecure Inter-Agent Communication)

---

## Context

### What ASI07 requires

OWASP Agentic Security Initiative risk ASI07 (Insecure Inter-Agent Communication) identifies three threats against agent-to-agent message flows:

1. **Message injection** -- an attacker fabricates tool responses that a consuming agent treats as authentic.
2. **Message tampering** -- a man-in-the-middle alters response content after it leaves the producing backend but before the consuming agent processes it.
3. **Replay attacks** -- a previously valid response is re-delivered to trick an agent into repeating a state-changing action.

The control requirement is that every inter-agent message carries application-layer authentication, integrity protection, and freshness guarantees, independent of the transport layer.

### What we have today

mcp-gateway already implements transport-layer protection:

- **mTLS** (`src/mtls/`): Mutual TLS with rustls, client certificate verification, OU/CN-based access control policies. This authenticates the TCP connection and encrypts data in transit.
- **Idempotency** (`src/idempotency.rs`): SHA-256-based deduplication of tool invocations, preventing duplicate side effects from LLM retries. However, this operates on request-side keys, not on response integrity.
- **Tool integrity** (`src/security/tool_integrity.rs` via `src/validator/rules/tool_poisoning.rs`): SHA-256 capability file pinning detects definition mutations. This protects tool definitions, not runtime message content.

### What is missing

mTLS protects the channel but not the message envelope. Once a response exits the TLS termination point (e.g., a compromised gateway node, a logging proxy, or a sidecar), there is no way for the consuming agent to verify:

1. That the response was produced by the claimed backend and endorsed by the gateway.
2. That the response content was not modified after signing.
3. That the response is fresh (not a replay of a previous legitimate response).

The pre-implementation OWASP compliance matrix (`docs/OWASP_AGENTIC_AI_COMPLIANCE.md`) listed ASI07 as incomplete and called for application-layer message signing plus nonce-based replay protection. The current matrix lists ASI07 as **COVERED** for the gateway boundary.

---

## Decision

Add **HMAC-SHA256 message signing** to `gateway_invoke` responses and **monotonic nonce validation** to `gateway_invoke` requests, opt-in via configuration.

### 1. Response signing

Every `gateway_invoke` response gains an optional `_signature` metadata block:

```json
{
  "content": [{"type": "text", "text": "..."}],
  "trace_id": "abc123",
  "_signature": {
    "alg": "hmac-sha256",
    "sig": "a1b2c3d4...64-hex-chars",
    "nonce": "req-nonce-echoed-back",
    "ts": 1713225600,
    "key_id": "default"
  }
}
```

The signature is computed as:

```
HMAC-SHA256(shared_secret, canonical_json(response_without_signature_block))
```

Where `canonical_json` is the existing `crate::hashing::canonical_json()` function, which produces deterministic JSON serialization via `serde_json::to_string`. The `_signature` key is removed from the object before computing the MAC to avoid circular dependency.

`key_id` identifies which shared secret was used, enabling secret rotation without downtime (the gateway can hold up to 2 active keys and will try the current key first, then the previous key during a rotation window).

### 2. Request nonce validation

Each `gateway_invoke` request accepts an optional `nonce` field:

```json
{
  "server": "hebb",
  "tool": "recall",
  "arguments": {"query": "..."},
  "nonce": "client-monotonic-1713225600-42"
}
```

When message signing is enabled:

- If a `nonce` is present, the gateway checks it against a sliding-window nonce store. Rejected if already seen within the replay window (default: 5 minutes, configurable). The nonce is echoed in `_signature.nonce` in the response.
- If a `nonce` is absent and `security.message_signing.require_nonce` is `true`, the request is rejected with a JSON-RPC error (`-32001`, "Nonce required when message signing is enforced").
- If a `nonce` is absent and `require_nonce` is `false` (default), the request proceeds without replay protection -- backward compatible.

The nonce store uses a `DashMap<String, Instant>` with periodic eviction, mirroring the pattern already established by `src/idempotency.rs`.

### 3. Configuration

```yaml
security:
  message_signing:
    enabled: false          # opt-in, default off
    shared_secret: "${MCP_GATEWAY_SIGNING_SECRET}"  # env var reference
    previous_secret: ""     # for rotation; empty = no rotation active
    require_nonce: false    # when true, requests without nonce are rejected
    replay_window: 300      # seconds; nonces older than this are evicted
    key_id: "default"       # identifier included in _signature.key_id
```

The `shared_secret` MUST be at least 32 bytes (256 bits). The gateway refuses to start if `enabled: true` and the secret is shorter than 32 bytes or empty. Secrets are loaded via the existing `dotenvy` / figment env-var expansion, never stored in plaintext config.

### 4. Verification by consuming agents

Consuming agents (e.g., Claude Code via the MCP client) verify responses by:

1. Extracting and removing the `_signature` block from the response JSON.
2. Recomputing `HMAC-SHA256(shared_secret, canonical_json(remaining_response))`.
3. Comparing the computed MAC against `_signature.sig` using constant-time comparison (`subtle::ConstantTimeEq`, already a dependency).
4. Checking that `_signature.ts` is within an acceptable clock skew window (recommended: +/- 60 seconds).
5. Checking that `_signature.nonce` matches the nonce they sent.

Verification is the client's responsibility. The gateway signs; it does not verify its own signatures.

---

## Consequences

### Positive

- **ASI07 coverage is now COVERED**. Application-layer message integrity is established independent of TLS termination.
- **Replay protection** prevents a captured response from being re-delivered to trick an agent into repeating actions.
- **Zero breaking changes**. The feature is opt-in (`enabled: false` by default). Unsigned responses are structurally identical to today's responses -- no `_signature` block is present. Clients that do not understand `_signature` can ignore it.
- **Leverages existing infrastructure**. `hmac` 0.13, `sha2` 0.11, `hex` 0.4, and `subtle` 2.6 are already in `Cargo.toml`. `DashMap` is already used for idempotency. `canonical_json()` exists in `src/hashing.rs`. No new dependencies required.
- **Auditable**. Signatures in the response body are captured by the existing NDJSON audit trail and can be verified after the fact.

### Negative / Risks

- **Shared secret management**. HMAC requires both gateway and client to possess the same secret. This is simpler than PKI but means secret distribution is an operational concern. Mitigation: env-var injection, integration with the existing keychain-based secret store (`src/secrets.rs`).
- **Performance overhead**. HMAC-SHA256 is fast (~3 Gbps on modern hardware). For a typical 1-4 KB tool response, signing adds <1 microsecond of CPU time. The `canonical_json` serialization is already performed for idempotency hashing on many code paths. Nonce lookup in `DashMap` is O(1). **Estimated total overhead: <10 microseconds per request**, negligible relative to network RTT and backend execution time.
- **Clock skew sensitivity**. The `ts` field enables freshness checks but requires roughly synchronized clocks between gateway and clients. Mitigation: the recommended skew window (60s) is generous, and NTP is ubiquitous. The timestamp is advisory -- clients can skip the check if clock sync is not guaranteed.
- **Nonce store memory**. At 100 requests/second with a 5-minute window, the nonce store holds ~30,000 entries. Each entry is approximately 80 bytes (nonce string + Instant), so ~2.4 MB. Acceptable for a gateway process.
- **Not end-to-end for multi-hop chains**. This signs gateway-to-client messages. If an agent chain involves multiple gateways, each hop has its own signing relationship. True multi-hop message provenance would require a signature chain or JWS-style envelope, which is out of scope for this ADR.

### Not addressed by this ADR

- **Agent identity attestation** (ASI03): This ADR authenticates messages from the gateway, not individual agent identities. Agent attestation (SPIFFE/SVID) is a separate concern.
- **Ed25519 / asymmetric signing**: HMAC was chosen over Ed25519 for simplicity (shared-secret model matches the single-gateway deployment pattern). A future ADR may introduce asymmetric signing for multi-gateway or federated deployments. The `_signature.alg` field is deliberately included to allow algorithm negotiation without breaking changes.
- **Request signing**: Only responses are signed. Request signing (client-to-gateway) is less critical because the gateway already authenticates requests via bearer tokens / mTLS. A future iteration could add request signing symmetrically.

---

## Implementation Sketch

### Files to create

| File | Purpose |
|------|---------|
| `src/security/message_signing.rs` | Core signing logic: `sign_response()`, `verify_nonce()`, `NonceStore` |
| `src/security/message_signing/tests.rs` | Unit tests for signing, nonce validation, key rotation |

### Files to modify

| File | Change |
|------|--------|
| `src/config/features/security.rs` | Add `MessageSigningConfig` to `SecurityConfig` |
| `src/security/mod.rs` | Add `pub mod message_signing;` |
| `src/gateway/meta_mcp/invoke.rs` | Post-dispatch: call `sign_response()` before returning; pre-dispatch: call `verify_nonce()` if enabled |
| `src/gateway/meta_mcp/mod.rs` | Hold `NonceStore` in `MetaMcp` struct (alongside existing `idempotency_cache`) |
| `docs/OWASP_AGENTIC_AI_COMPLIANCE.md` | Status implemented: ASI07 is COVERED with the message-signing control reference |

### Rough API shape

```rust
// src/config/features/security.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MessageSigningConfig {
    pub enabled: bool,
    pub shared_secret: String,       // resolved from env var at load time
    pub previous_secret: String,     // for rotation window
    pub require_nonce: bool,
    pub replay_window: u64,          // seconds
    pub key_id: String,
}

// src/security/message_signing.rs

use dashmap::DashMap;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

pub struct MessageSigner {
    secret: Vec<u8>,
    previous_secret: Option<Vec<u8>>,
    key_id: String,
}

pub struct NonceStore {
    seen: DashMap<String, Instant>,
    replay_window: Duration,
}

impl MessageSigner {
    /// Sign a response JSON value, returning a new value with `_signature` injected.
    pub fn sign_response(
        &self,
        mut response: Value,
        nonce: Option<&str>,
    ) -> Value {
        // 1. Remove _signature if somehow present
        // 2. canonical_json(response)
        // 3. HMAC-SHA256(secret, canonical)
        // 4. Inject _signature block with alg, sig, nonce, ts, key_id
        // 5. Return augmented response
    }
}

impl NonceStore {
    /// Check and register a nonce. Returns Err if replayed.
    pub fn check_and_register(&self, nonce: &str) -> Result<()> { ... }

    /// Evict expired nonces. Called periodically from a background task.
    pub fn evict_expired(&self) { ... }
}
```

### Integration point in invoke.rs

The signing would be injected in `invoke_tool_traced()` at the end of the response pipeline, after all existing post-processing (response inspection, cost warnings, recovery hints, trace augmentation) but before the final `Ok(result)` return:

```rust
// After all existing post-invoke processing, before return:
if let Some(ref signer) = self.message_signer {
    let nonce = args.get("nonce").and_then(Value::as_str);
    result = signer.sign_response(result, nonce);
}
```

Nonce validation would occur early in `invoke_tool_traced()`, after argument parsing but before dispatch:

```rust
// After argument parsing, before kill-switch check:
if let Some(ref nonce_store) = self.nonce_store {
    if let Some(nonce) = args.get("nonce").and_then(Value::as_str) {
        nonce_store.check_and_register(nonce)?;
    } else if self.require_nonce {
        return Err(Error::json_rpc(-32001, "Nonce required"));
    }
}
```

### Nonce eviction

A background `tokio::spawn` task runs every 60 seconds (matching the existing idempotency eviction pattern in `src/idempotency.rs`) to call `nonce_store.evict_expired()`.

---

## Alternatives Considered

| Alternative | Why rejected |
|-------------|-------------|
| **Ed25519 asymmetric signatures** | More complex key management (PKI), unnecessary for single-gateway deployments. The `alg` field allows future migration. |
| **JWS (RFC 7515) envelope** | Heavier format, adds `jsonwebtoken` signing overhead, less natural in MCP JSON-RPC responses. |
| **Rely on mTLS alone** | Does not protect against compromised intermediaries or log replay. OWASP ASI07 explicitly requires application-layer integrity. |
| **Sign at the transport layer (TLS channel binding)** | `tls-unique` / `tls-exporter` channel bindings are not widely supported across MCP clients and do not survive HTTP/2 connection pooling. |
| **Nonce as UUID instead of monotonic** | UUIDs work but are harder for clients to reason about ordering. Monotonic nonces (timestamp + counter) give natural freshness without requiring clock sync for ordering. Either format is accepted by the `NonceStore`. |

---

## References

- [OWASP Agentic Security Initiative - ASI07](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/tree/main/initiatives/agent_security_initiative/agentic-top-10)
- [RFC 2104 - HMAC](https://datatracker.ietf.org/doc/html/rfc2104)
- [mcp-gateway OWASP compliance matrix](../OWASP_AGENTIC_AI_COMPLIANCE.md)
- [mcp-gateway mTLS implementation](../../src/mtls/mod.rs)
- [mcp-gateway idempotency (nonce pattern reference)](../../src/idempotency.rs)
