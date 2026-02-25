# RFC-0043: LLM Key Server -- OIDC Identity to Temporary API Keys

**Issue**: [#43](https://github.com/MikkoParkkola/mcp-gateway/issues/43)
**Status**: Proposed
**Date**: 2026-02-25

---

## Context

The existing design doc (`docs/design/LLM_KEY_SERVER.md`) provides a detailed implementation blueprint. This RFC elevates that design to an architecture decision record, capturing the *why* and the trade-offs, and adding integration context with #32 (providers) and #51 (mTLS).

### Problem

mcp-gateway authenticates clients via static bearer tokens and API keys (`src/gateway/auth.rs`). This creates three operational gaps:

1. **No identity binding** -- a leaked key grants access with no trail back to a person
2. **Manual lifecycle** -- adding/revoking users requires config edits and restarts
3. **Single credential plane** -- the same static key is used for all contexts (CI, CLI, cloud apps)

### Prior Art

The existing `LLM_KEY_SERVER.md` design covers the full OIDC verification flow, token issuance, policy engine, and client integration examples. This RFC confirms that design and focuses on architectural decisions.

---

## Decision

### Architecture: Embedded Module, Not Separate Service

The key server runs as an embedded module within mcp-gateway, not as a separate microservice.

**Rationale**:
- Single deployment artifact (the gateway binary)
- Token validation has zero network hop (in-process `DashMap` lookup)
- Shared rate limiter state with existing auth middleware
- Operational simplicity for the primary deployment target (single-machine, multi-client)

**Trade-off**: Horizontal scaling requires the distributed state layer from #47. For single-instance deployments (the 95% case), embedded is optimal.

### Token Format: Opaque Bearer, Not JWT

Temporary tokens are opaque random strings (`mcpgw_<base64>`), not JWTs.

**Rationale**:
- Instant revocation -- delete from `DashMap`, no need to wait for JWT expiry
- No token size bloat in every request header
- Server-side validation is O(1) `DashMap` lookup (faster than JWT signature verification)
- No need for clients to parse token contents

**Trade-off**: Requires server-side state. Acceptable because the gateway already maintains extensive in-process state (`IdempotencyCache`, `ResponseCache`, `KillSwitch`).

### Auth Middleware Integration

The key server slots into the existing auth middleware as a secondary validation path:

```
Request arrives
  -> Extract bearer token
  -> Try static auth (existing ResolvedAuthConfig)  -- O(n) key comparison
  -> Try temporary token (KeyServer.validate)       -- O(1) DashMap lookup
  -> Reject
```

Static keys are checked first for backward compatibility and because they are the common case today. Once key server adoption grows, the order can be reversed.

### Identity to Scopes Mapping

```yaml
key_server:
  enabled: true
  token_ttl: 1h

  oidc:
    - issuer: "https://accounts.google.com"
      audiences: ["gateway-client-id"]
      allowed_domains: ["company.com"]

    - issuer: "https://token.actions.githubusercontent.com"
      audiences: ["mcp-gateway"]

  policies:
    - match: { domain: "company.com" }
      scopes:
        backends: ["*"]
        tools: ["*"]
        rate_limit: 100

    - match: { issuer: "https://token.actions.githubusercontent.com" }
      scopes:
        backends: ["tavily", "brave"]
        tools: ["tavily-search", "brave_*"]
        rate_limit: 50
```

Policy resolution is first-match-wins, identical to the existing `ToolPolicy` evaluation order. This is deliberate consistency -- operators learn one pattern.

---

## Integration Points

### With Existing Auth (`src/gateway/auth.rs`)

```yaml
Integration Point: auth_middleware
  Existing Component: ResolvedAuthConfig.validate_token()
  Integration Method: Secondary validation path after static key check
  Impact Level: Medium (new code path in hot path)
  Required Test Coverage:
    - Static keys still work when key server is enabled
    - Static keys still work when key server is disabled
    - Temporary token accepted after static key check fails
    - Expired temporary token rejected
    - Revoked temporary token rejected
```

### With Existing OAuth (`src/oauth/`)

The existing OAuth module handles *outbound* authentication (gateway authenticating to backends). The key server handles *inbound* authentication (clients authenticating to gateway). They are complementary, not overlapping.

```
Client -> [Key Server: OIDC inbound auth] -> Gateway -> [OAuth: outbound auth] -> Backend
```

### With Provider Transforms (#32)

When the provider/transform architecture lands, `AuthTransform` can consume the verified identity from request extensions to make per-provider authorization decisions:

```rust
// AuthTransform checks request extensions for VerifiedIdentity
// injected by key server auth middleware
let identity = request.extensions().get::<VerifiedIdentity>();
```

### With mTLS (#51)

mTLS and OIDC key server are complementary authentication layers:

| Layer | Purpose | Identity Source |
|-------|---------|----------------|
| mTLS | Transport-level mutual auth | X.509 certificate CN/SAN |
| Key Server | Application-level identity | OIDC token claims |

Both can be active simultaneously. mTLS authenticates the *connection*; the key server authenticates the *user*.

---

## Audit Trail Architecture

Every token lifecycle event is emitted as a structured log:

```rust
#[derive(Serialize)]
struct AuditEvent {
    event: &'static str,       // "token.issued", "token.used", "token.expired", etc.
    identity: VerifiedIdentity,
    token_jti: String,
    scopes: TokenScopes,
    client_ip: IpAddr,
    timestamp: DateTime<Utc>,
}
```

Events: `token.issued`, `token.used`, `token.expired`, `token.revoked`, `token.denied`, `token.invalid`.

These are emitted via `tracing::info!` with structured fields, queryable by any log aggregator. No separate audit store -- the existing tracing infrastructure handles this.

---

## How This Replaces Static Keys

### Migration Path

1. **Phase 1**: Key server ships disabled by default. Static keys unchanged.
2. **Phase 2**: Operators enable key server alongside static keys. Both work.
3. **Phase 3**: Operators migrate CI/CD to OIDC tokens. Static keys become admin-only fallback.
4. **Phase 4** (optional): Operators disable static keys entirely via `auth.api_keys: []`.

At no point are static keys forcibly removed. The migration is pull-based, not push-based.

### `secrets.env` Elimination

Currently:
```bash
# secrets.env -- static keys that never rotate
MCP_GATEWAY_TOKEN=sk-permanent-token-leaked-in-git-history
CLIENT_A_KEY=ck-another-permanent-key
TAVILY_API_KEY=tvly-actual-api-key
```

After key server:
```bash
# secrets.env -- only backend API keys remain (not client-facing)
TAVILY_API_KEY=tvly-actual-api-key
# Client keys replaced by OIDC -- no client secrets to manage
```

Client-facing static keys are eliminated. Backend API keys (`TAVILY_API_KEY`) remain because they authenticate the gateway to external services, not clients to the gateway.

---

## Implementation Phases

### Phase 1: Token Store + Endpoints (1.5 weeks)

- `src/key_server/mod.rs` -- module structure
- `src/key_server/store.rs` -- `TokenStore` trait + `InMemoryTokenStore` (DashMap)
- `src/key_server/handler.rs` -- `POST /auth/token`, `DELETE /auth/token/{jti}`
- Wire into `src/gateway/router.rs` as new routes
- Wire `KeyServer` into auth middleware as secondary path
- Background reaper task for expired tokens

**Verification**: Issue token via `POST /auth/token` with mock OIDC, use it for `gateway_search_tools`.

### Phase 2: OIDC Verification (1.5 weeks)

- `src/key_server/oidc.rs` -- JWT verification, JWKS fetching/caching
- Add `jsonwebtoken` dependency
- Support Google as first provider
- JWKS cache with TTL and automatic refresh on unknown `kid`
- Integration tests with mock OIDC provider (local JWKS endpoint)

**Verification**: Full flow -- OIDC token -> verify -> issue temporary token -> invoke tool.

### Phase 3: Policy Engine + Rate Limiting (1 week)

- `src/key_server/policy.rs` -- YAML policy config, first-match resolution
- Identity-to-scope mapping
- Per-identity rate limiting (extend existing `DashMap<String, Arc<ClientRateLimiter>>`)
- Audit event emission for all token lifecycle events

**Verification**: Different identities get different scopes. Rate limits enforced per-identity.

### Phase 4: Client Integration (1 week)

- CLI `mcp-gateway auth login --provider google` command
- Token caching in `~/.mcp-gateway/token.json` with auto-refresh
- GitHub Actions integration example
- Documentation

**Verification**: CLI login flow works end-to-end. GitHub Actions example tested.

---

## Dependencies

- **Blocks #80**: Multi-account router needs identity-aware token scoping
- **Depends on**: Nothing (additive to existing auth)
- **Complements #51**: mTLS provides transport auth; key server provides identity auth
- **Complements #32**: `AuthTransform` can consume verified identity from key server

---

## Effort Estimate

| Phase | Effort |
|-------|--------|
| Phase 1: Token store + endpoints | 1.5 weeks |
| Phase 2: OIDC verification | 1.5 weeks |
| Phase 3: Policy engine + rate limiting | 1 week |
| Phase 4: Client integration | 1 week |
| **Total** | **5 weeks** |

---

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| JWKS endpoint unavailability | Low | High | Cache JWKS aggressively (1hr TTL). Existing tokens remain valid during outage. |
| Token store memory growth | Low | Medium | Background reaper + `max_tokens_per_identity` cap (default 5). |
| Clock skew breaking JWT validation | Low | Medium | 5-minute leeway on `iat`/`exp` claims. |
| Complexity of multi-provider OIDC | Medium | Medium | Ship with Google only in Phase 2. Add providers incrementally. |
| Breaking existing auth | Low | High | Key server is opt-in (`enabled: false` default). Static keys always checked first. |

---

## Security Considerations

| Threat | Mitigation |
|--------|------------|
| Stolen temporary token | 1-hour expiry. Rate limits keyed on identity, not token. |
| OIDC token replay | Reject tokens with `iat` older than 5 minutes. |
| Token enumeration | Constant-time comparison. No information leakage in error responses. |
| JWKS poisoning | Pin known issuers in config. HTTPS-only JWKS URIs. |
| Admin token compromise | Admin endpoints require separate auth (`admin.bearer_token`). |

---

## Decisions Needed

1. **JWT library**: `jsonwebtoken` (mature, 4M downloads/month) vs `jose` (newer, more complete JOSE support). Recommend `jsonwebtoken` -- it covers our OIDC verification needs and is battle-tested.

2. **Token prefix**: `mcpgw_` prefix on tokens for grep-ability and accidental-commit detection by secret scanners. Confirm or suggest alternative.

3. **Admin auth**: Separate admin bearer token for revocation endpoints, or reuse static keys with admin role? Recommend separate token -- principle of least privilege.

---

## References

- Existing design: `docs/design/LLM_KEY_SERVER.md`
- Mercari LLM Key Server: https://engineering.mercari.com/en/blog/entry/20251202-llm-key-server/
- RFC 8693: OAuth 2.0 Token Exchange
- RFC 7636: PKCE (used by existing `src/oauth/`)
- OpenID Connect Discovery 1.0: https://openid.net/specs/openid-connect-discovery-1_0.html
- Current auth middleware: `src/gateway/auth.rs`
- Current config: `src/config.rs` (`AuthConfig`, `ApiKeyConfig`)
- `jsonwebtoken` crate: https://docs.rs/jsonwebtoken/latest/jsonwebtoken/
