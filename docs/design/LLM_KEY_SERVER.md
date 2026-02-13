# LLM Key Server Design

**Issue**: [#43 - LLM Key Server Pattern: OIDC Identity → Temporary API Keys](https://github.com/MikkoParkkola/mcp-gateway/issues/43)
**Status**: Draft
**Author**: rust-excellence-engineer
**Date**: 2026-02-13

---

## Problem Statement

The current `mcp-gateway` authentication (`src/gateway/auth.rs`) supports static bearer tokens and API keys configured in `gateway.yaml`. This creates operational challenges:

1. **Key leakage risk** -- permanent API keys leaked in logs, repos, or CI artifacts grant indefinite access
2. **No identity trail** -- bearer tokens authenticate the key, not the person; audit logs show "Client A" not "alice@company.com"
3. **Manual lifecycle** -- adding/removing users requires config file changes and gateway restart
4. **Multi-provider friction** -- each LLM backend (OpenAI, Anthropic, Google) requires separate key management

The LLM Key Server pattern (inspired by [Mercari Engineering](https://engineering.mercari.com/en/blog/entry/20251202-llm-key-server/)) replaces permanent keys with OIDC-verified identity mapped to short-lived gateway tokens.

## Current Authentication (Baseline)

From `src/gateway/auth.rs` and `src/config.rs`:

```yaml
# Current: static keys in config
auth:
  enabled: true
  bearer_token: "env:MCP_GATEWAY_TOKEN"
  api_keys:
    - key: "env:CLIENT_A_KEY"
      name: "Client A"
      rate_limit: 100
      backends: ["tavily"]
```

| Feature | Current | Proposed |
|---------|---------|----------|
| Token lifetime | Permanent | 1 hour (configurable) |
| Identity binding | None (key = identity) | OIDC subject claim |
| Audit trail | Client name from config | Email, org, device |
| Key rotation | Manual config change + restart | Automatic on expiry |
| Revocation | Remove from config + restart | Instant (revocation list) |
| Onboarding | Edit YAML, distribute key | Authenticate with IdP |

---

## Architecture

```
┌──────────────────────┐
│  User / Workload     │
│  (Google, GitHub,    │
│   Azure AD identity) │
└──────────┬───────────┘
           │ 1. OIDC ID Token (JWT)
           ▼
┌──────────────────────┐
│  Key Server Module   │
│  POST /auth/token    │
│                      │
│  a. Verify JWT sig   │
│  b. Check claims     │
│  c. Map to scopes    │
│  d. Issue temp key   │
└──────────┬───────────┘
           │ 2. Temporary Gateway Token
           │    (1hr, scoped, auditable)
           ▼
┌──────────────────────┐
│  MCP Gateway         │
│  (existing auth      │
│   middleware)         │
│                      │
│  Validates temp key  │
│  Enforces scopes     │
│  Logs identity       │
└──────────┬───────────┘
           │ 3. Proxied MCP requests
           ▼
┌──────────────────────┐
│  MCP Backends        │
│  (tavily, brave,     │
│   context7, etc.)    │
└──────────────────────┘
```

---

## OIDC Identity Verification Flow

### Token Exchange Endpoint

```
POST /auth/token
Content-Type: application/json

{
  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
  "subject_token": "<OIDC ID Token JWT>",
  "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
  "scope": "backends:tavily,brave tools:tavily-search,brave_web_search"
}
```

### Verification Steps

```rust
/// Verify an OIDC ID token and extract identity claims.
///
/// Steps:
/// 1. Decode JWT header to get `kid` (key ID)
/// 2. Fetch issuer's JWKS from discovery endpoint
/// 3. Verify signature against matching public key
/// 4. Validate standard claims (exp, iat, aud, iss)
/// 5. Extract identity claims (sub, email, groups)
async fn verify_oidc_token(
    token: &str,
    config: &OidcConfig,
    jwks_cache: &JwksCache,
) -> Result<VerifiedIdentity, AuthError> {
    // 1. Decode header (no verification yet)
    let header = jsonwebtoken::decode_header(token)?;
    let kid = header.kid.ok_or(AuthError::MissingKeyId)?;

    // 2. Fetch JWKS (cached, refreshed on cache miss for unknown kid)
    let jwks = jwks_cache
        .get_or_fetch(&config.issuer, &config.jwks_uri)
        .await?;
    let key = jwks
        .find(&kid)
        .ok_or(AuthError::UnknownKeyId(kid))?;

    // 3. Verify signature + standard claims
    let validation = jsonwebtoken::Validation::new(header.alg);
    // validation.set_audience(&config.allowed_audiences);
    // validation.set_issuer(&[&config.issuer]);
    let token_data = jsonwebtoken::decode::<IdTokenClaims>(token, key, &validation)?;

    // 4. Additional claim checks
    let claims = token_data.claims;
    if !config.allowed_domains.is_empty() {
        let domain = claims.email.split('@').last().unwrap_or("");
        if !config.allowed_domains.contains(&domain.to_string()) {
            return Err(AuthError::DomainNotAllowed(domain.to_string()));
        }
    }

    // 5. Return verified identity
    Ok(VerifiedIdentity {
        subject: claims.sub,
        email: claims.email,
        name: claims.name,
        groups: claims.groups.unwrap_or_default(),
        issuer: claims.iss,
    })
}
```

### JWKS Caching

JWKS (JSON Web Key Set) endpoints should be cached to avoid per-request HTTP calls:

```rust
pub struct JwksCache {
    /// Cached JWKS per issuer, with TTL
    cache: DashMap<String, CachedJwks>,
    http_client: reqwest::Client,
}

struct CachedJwks {
    keys: jsonwebtoken::jwk::JwkSet,
    fetched_at: Instant,
    ttl: Duration, // default: 1 hour
}

impl JwksCache {
    /// Get JWKS, fetching from remote if cache is stale or key ID is unknown.
    async fn get_or_fetch(&self, issuer: &str, jwks_uri: &str) -> Result<Arc<JwkSet>> {
        if let Some(cached) = self.cache.get(issuer) {
            if cached.fetched_at.elapsed() < cached.ttl {
                return Ok(Arc::new(cached.keys.clone()));
            }
        }
        // Fetch and cache
        let jwks = self.http_client.get(jwks_uri).send().await?.json().await?;
        self.cache.insert(issuer.to_string(), CachedJwks {
            keys: jwks,
            fetched_at: Instant::now(),
            ttl: Duration::from_secs(3600),
        });
        Ok(Arc::new(jwks))
    }
}
```

---

## Temporary API Key Issuance

### Key Structure

```rust
/// A temporary gateway token issued after OIDC verification.
#[derive(Debug, Serialize, Deserialize)]
pub struct TemporaryToken {
    /// Unique token identifier (for revocation)
    pub jti: String,
    /// The opaque bearer token value
    pub token: String,
    /// Identity that requested this token
    pub identity: VerifiedIdentity,
    /// Allowed scopes
    pub scopes: TokenScopes,
    /// Issued at (epoch seconds)
    pub iat: u64,
    /// Expires at (epoch seconds)
    pub exp: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenScopes {
    /// Allowed backends (empty = all allowed by policy)
    pub backends: Vec<String>,
    /// Allowed tools (empty = all tools on allowed backends)
    pub tools: Vec<String>,
    /// Rate limit override (0 = use default)
    pub rate_limit: u32,
}
```

### Token Generation

```rust
/// Issue a temporary token for a verified identity.
fn issue_token(
    identity: &VerifiedIdentity,
    requested_scopes: &RequestedScopes,
    policy: &AccessPolicy,
    config: &KeyServerConfig,
) -> Result<TokenResponse> {
    // 1. Resolve effective scopes (intersection of requested and allowed)
    let effective_scopes = policy.resolve_scopes(identity, requested_scopes)?;

    // 2. Generate cryptographically random token
    let mut token_bytes = [0u8; 32];
    rand::thread_rng().fill(&mut token_bytes);
    let token_value = format!(
        "mcpgw_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_bytes)
    );

    // 3. Create token record
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let token = TemporaryToken {
        jti: uuid::Uuid::new_v4().to_string(),
        token: token_value.clone(),
        identity: identity.clone(),
        scopes: effective_scopes,
        iat: now,
        exp: now + config.token_ttl.as_secs(),
    };

    // 4. Store in active tokens (for validation and revocation)
    // In distributed mode: stored in Redis with TTL
    // In single mode: stored in DashMap with background reaper

    Ok(TokenResponse {
        access_token: token_value,
        token_type: "Bearer".to_string(),
        expires_in: config.token_ttl.as_secs(),
        scope: token.scopes.to_string(),
    })
}
```

### Token Response

```json
{
  "access_token": "mcpgw_dGhpcyBpcyBhIHRlbXBvcmFyeSB0b2tlbg",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "backends:tavily,brave tools:*"
}
```

---

## Key Rotation and Revocation

### Automatic Expiry

Tokens are stored with TTL. No action needed for normal lifecycle:

| Store | TTL Mechanism |
|-------|---------------|
| In-memory (`DashMap`) | Background task reaps expired tokens every 60s |
| Redis | Native `EXPIRE` / `EXPIREAT` on key |

### Explicit Revocation

```
DELETE /auth/token/{jti}
Authorization: Bearer <admin-token>
```

```rust
/// Revoke a specific token by its JTI (JWT ID).
/// The token is added to a revocation set checked during validation.
async fn revoke_token(store: &dyn TokenStore, jti: &str) -> Result<()> {
    store.revoke(jti).await?;
    // In distributed mode: publish revocation event via pub/sub
    // so all gateway instances invalidate cached validations immediately
    Ok(())
}
```

### Bulk Revocation by Identity

Revoke all active tokens for a specific user (e.g., on employee offboarding):

```
DELETE /auth/tokens?subject=alice@company.com
Authorization: Bearer <admin-token>
```

### JWKS Key Rotation

When the OIDC provider rotates signing keys:

1. New tokens arrive signed with new `kid`
2. JWKS cache misses on unknown `kid`
3. Cache refetches JWKS from provider
4. New key is cached, old key remains until it naturally expires from cache
5. No gateway restart needed

---

## Integration with Existing Auth

The key server module integrates alongside the existing `ResolvedAuthConfig` in `src/gateway/auth.rs`:

### Auth Middleware Enhancement

```rust
/// Enhanced authentication: check static keys first, then temporary tokens.
pub async fn auth_middleware(
    State(auth_config): State<Arc<ResolvedAuthConfig>>,
    State(key_server): State<Option<Arc<KeyServer>>>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    // ... existing public path check ...

    let token = extract_bearer_token(&request);

    // 1. Try static auth (existing behavior, unchanged)
    if let Some(client) = auth_config.validate_token(token) {
        request.extensions_mut().insert(client);
        return next.run(request).await;
    }

    // 2. Try temporary token (new path)
    if let Some(ref ks) = key_server {
        if let Some(temp_token) = ks.validate_token(token).await {
            let client = AuthenticatedClient {
                name: temp_token.identity.email.clone(),
                rate_limit: temp_token.scopes.rate_limit,
                backends: temp_token.scopes.backends.clone(),
            };
            // Inject identity for audit trail
            request.extensions_mut().insert(temp_token.identity.clone());
            request.extensions_mut().insert(client);
            return next.run(request).await;
        }
    }

    // 3. Reject
    unauthorized_response("Invalid or expired token")
}
```

### Backward Compatibility

- Existing static `bearer_token` and `api_keys` continue to work unchanged
- Key server is opt-in via `key_server.enabled: true`
- When disabled, zero overhead (no OIDC verification, no token store)
- Static and temporary tokens can coexist (static checked first for performance)

---

## Access Policy Configuration

Map OIDC identities to gateway permissions:

```yaml
key_server:
  enabled: false
  token_ttl: 1h
  max_tokens_per_identity: 5

  # OIDC provider configuration
  oidc:
    # Google Workspace
    - issuer: "https://accounts.google.com"
      jwks_uri: "https://www.googleapis.com/oauth2/v3/certs"
      audiences: ["your-gateway-client-id"]
      allowed_domains: ["company.com"]

    # GitHub Actions (for CI/CD)
    - issuer: "https://token.actions.githubusercontent.com"
      jwks_uri: "https://token.actions.githubusercontent.com/.well-known/jwks"
      audiences: ["your-gateway-audience"]
      # No domain restriction for GitHub

    # Azure AD
    - issuer: "https://login.microsoftonline.com/{tenant}/v2.0"
      jwks_uri: "https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys"
      audiences: ["your-app-id"]

  # Access policies: map identity attributes to gateway permissions
  policies:
    # Default for any verified identity
    - match: { domain: "company.com" }
      scopes:
        backends: ["*"]
        tools: ["*"]
        rate_limit: 100

    # Restricted access for CI
    - match: { issuer: "https://token.actions.githubusercontent.com" }
      scopes:
        backends: ["tavily", "brave"]
        tools: ["tavily-search", "brave_web_search"]
        rate_limit: 50

    # Power users (by group claim)
    - match: { group: "ml-engineers" }
      scopes:
        backends: ["*"]
        tools: ["*"]
        rate_limit: 0  # unlimited
```

### Policy Resolution

Policies are evaluated in order. First match wins. If no policy matches, the request is denied.

```rust
pub struct AccessPolicy {
    pub rules: Vec<PolicyRule>,
}

pub struct PolicyRule {
    pub match_criteria: MatchCriteria,
    pub scopes: TokenScopes,
}

pub struct MatchCriteria {
    pub domain: Option<String>,
    pub issuer: Option<String>,
    pub group: Option<String>,
    pub email: Option<String>,
}

impl AccessPolicy {
    /// Resolve the effective scopes for a verified identity.
    /// Returns the scopes from the first matching policy rule.
    fn resolve_scopes(
        &self,
        identity: &VerifiedIdentity,
        requested: &RequestedScopes,
    ) -> Result<TokenScopes> {
        for rule in &self.rules {
            if rule.match_criteria.matches(identity) {
                // Intersection: grant only what is both allowed and requested
                return Ok(rule.scopes.intersect(requested));
            }
        }
        Err(AuthError::NoPolicyMatch(identity.email.clone()))
    }
}
```

---

## Rate Limiting Per Identity

Extend the existing `DashMap<String, Arc<ClientRateLimiter>>` in `ResolvedAuthConfig` to dynamically create rate limiters for temporary token holders:

```rust
impl KeyServer {
    /// Get or create a rate limiter for this identity.
    fn rate_limiter_for(&self, identity: &str, limit: u32) -> Arc<ClientRateLimiter> {
        self.rate_limiters
            .entry(identity.to_string())
            .or_insert_with(|| {
                let quota = Quota::per_minute(NonZeroU32::new(limit).unwrap_or(NonZeroU32::MIN));
                Arc::new(RateLimiter::direct(quota))
            })
            .clone()
    }
}
```

Rate limits are per-identity (not per-token), so refreshing a token does not reset the rate limit.

---

## Client Integration Examples

### GitHub Actions

```yaml
# .github/workflows/ai-review.yml
jobs:
  review:
    permissions:
      id-token: write  # Required for OIDC token
    steps:
      - name: Get Gateway Token
        id: token
        run: |
          OIDC_TOKEN=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=mcp-gateway" | jq -r '.value')

          GATEWAY_TOKEN=$(curl -sS -X POST https://gateway.company.com/auth/token \
            -H "Content-Type: application/json" \
            -d "{
              \"grant_type\": \"urn:ietf:params:oauth:grant-type:token-exchange\",
              \"subject_token\": \"$OIDC_TOKEN\",
              \"subject_token_type\": \"urn:ietf:params:oauth:token-type:id_token\",
              \"scope\": \"backends:tavily tools:tavily-search\"
            }" | jq -r '.access_token')

          echo "token=$GATEWAY_TOKEN" >> "$GITHUB_OUTPUT"

      - name: Use Gateway
        run: |
          curl -X POST https://gateway.company.com/mcp \
            -H "Authorization: Bearer ${{ steps.token.outputs.token }}" \
            -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"tavily-search","arguments":{"query":"test"}}}'
```

### CLI (Local Development)

```bash
# One-time: authenticate via browser OAuth flow
mcp-gateway auth login --provider google

# This opens browser, completes OAuth, exchanges for gateway token
# Token cached in ~/.mcp-gateway/token.json with auto-refresh

# Subsequent requests use cached token transparently
mcp-gateway invoke tavily tavily-search --query "rust async patterns"
```

### Python Client Library

```python
from mcp_gateway import GatewayClient

# Auto-discovers credentials from environment:
# 1. GOOGLE_APPLICATION_CREDENTIALS (service account)
# 2. gcloud auth (user credentials)
# 3. GitHub Actions OIDC (in CI)
client = GatewayClient("https://gateway.company.com")

# Token exchange happens automatically, with transparent refresh
result = client.invoke("tavily", "tavily-search", query="rust patterns")
```

---

## Audit Trail

Every temporary token operation is logged with full identity context:

```json
{
  "event": "token.issued",
  "identity": {
    "subject": "112233445566778899",
    "email": "alice@company.com",
    "issuer": "https://accounts.google.com"
  },
  "token_jti": "550e8400-e29b-41d4-a716-446655440000",
  "scopes": {
    "backends": ["tavily", "brave"],
    "tools": ["*"],
    "rate_limit": 100
  },
  "expires_at": "2026-02-13T14:00:00Z",
  "client_ip": "192.168.1.100",
  "timestamp": "2026-02-13T13:00:00Z"
}
```

Events logged: `token.issued`, `token.used`, `token.expired`, `token.revoked`, `token.denied` (policy mismatch), `token.invalid` (bad OIDC token).

---

## Security Considerations

| Threat | Mitigation |
|--------|------------|
| Stolen temporary token | 1-hour expiry limits blast radius |
| OIDC token replay | `iat` check: reject tokens older than 5 minutes |
| Token enumeration | Constant-time comparison, no information leakage |
| JWKS poisoning | Pin known issuers, validate HTTPS, cache with TTL |
| Rate limit bypass via token churn | Rate limits keyed on identity, not token |
| Admin token compromise | Admin operations require separate, non-OIDC auth |

---

## Migration Path

### Phase 1: Token Store Abstraction

1. Define `TokenStore` trait (in-memory and Redis implementations)
2. Add `/auth/token` endpoint (POST for issuance, DELETE for revocation)
3. Wire into existing auth middleware as secondary validation path
4. Static keys continue to work unchanged

### Phase 2: OIDC Verification

1. Add `jsonwebtoken` dependency for JWT verification
2. Implement JWKS fetching and caching
3. Support Google as first OIDC provider
4. Integration tests with mock OIDC provider

### Phase 3: Policy Engine

1. YAML-based policy configuration
2. Identity-to-scope mapping
3. Per-identity rate limiting

### Phase 4: Client Libraries

1. CLI `auth login` command
2. Python client with auto-refresh
3. GitHub Actions example workflow

---

## Configuration Reference

```yaml
key_server:
  enabled: false
  token_ttl: 1h
  max_tokens_per_identity: 5
  # Token cleanup interval (in-memory mode)
  cleanup_interval: 60s

  oidc:
    - issuer: "https://accounts.google.com"
      jwks_uri: "https://www.googleapis.com/oauth2/v3/certs"
      audiences: ["your-client-id"]
      allowed_domains: ["company.com"]
      # Max age of OIDC token (reject older tokens)
      max_token_age: 5m

  policies:
    - match: { domain: "company.com" }
      scopes:
        backends: ["*"]
        tools: ["*"]
        rate_limit: 100

  # Admin authentication (for revocation endpoints)
  admin:
    # Static admin token (for bootstrapping)
    bearer_token: "env:MCP_GATEWAY_ADMIN_TOKEN"
```

---

## References

- Current auth middleware: `src/gateway/auth.rs`
- Current auth config: `src/config.rs` (`AuthConfig`, `ApiKeyConfig`)
- Current OAuth module: `src/oauth/` (OAuth 2.0 + PKCE for backend auth)
- Issue: [#43](https://github.com/MikkoParkkola/mcp-gateway/issues/43)
- Mercari LLM Key Server: https://engineering.mercari.com/en/blog/entry/20251202-llm-key-server/
- RFC 8693: OAuth 2.0 Token Exchange
- RFC 7636: PKCE
- RFC 8414: OAuth Authorization Server Metadata
- OpenID Connect Discovery: https://openid.net/specs/openid-connect-discovery-1_0.html
