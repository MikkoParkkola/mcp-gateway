# Running the gateway for more than one person

A single-user gateway trusts whoever can reach the port. A multi-user gateway has
to answer three questions instead, and they are answered by three different
pieces of configuration:

| Question | Answered by | Config key |
| --- | --- | --- |
| Who is calling? | The key server, against your identity provider | `key_server` |
| What may they reach? | Key-server policy rules | `key_server.policies` |
| Who does the *backend* think is calling? | Identity propagation, per backend | `backends.<name>.identity_propagation` |

Configure only the first two and every user reaches your backends as the
gateway's own service account — they are separated from each other at the
gateway and merged again behind it. The third is what keeps one person's mail
out of another person's search results.

## 1. Who is calling

The key server verifies an OIDC token from your identity provider and exchanges
it for a gateway token. It is off by default.

```yaml
key_server:
  enabled: true
  token_ttl_secs: 3600
  max_tokens_per_identity: 5
  max_oidc_token_age_secs: 300        # replay window for the incoming OIDC token
  admin_token: env:GATEWAY_ADMIN_TOKEN
  oidc:
    - issuer: https://accounts.google.com
      audiences: ["<your-oauth-client-id>"]
```

`audiences` must be non-empty. An empty list would accept a token minted for any
client at that issuer, which is audience confusion — the config validator
refuses it rather than letting it start.

`jwks_uri` is resolved from the provider's discovery document by default. Set it
explicitly only for a provider that does not publish one.

Three endpoints come with it:

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/auth/token` | Exchange an OIDC token for a gateway token |
| `DELETE` | `/auth/token/{jti}` | Revoke one issued token |
| `DELETE` | `/auth/tokens` | Revoke every token for one subject |

The two revocation endpoints require `admin_token`. Leave it unset and they
return 503 — which is safe, but means you have no revocation path. Set it.

If your clients cannot perform the exchange, `key_server.delegated_bearer: true`
lets them present the raw OIDC token directly. Policy and provider verification
still run; only the exchange step is skipped.

## 2. What they may reach

Policy rules are first-match-wins. Each rule matches on identity and grants
scopes.

```yaml
key_server:
  policies:
    - match: { group: platform-admins }
      scopes:
        backends: ["*"]
        tools: ["*"]
        rate_limit: 0                  # 0 = unlimited
    - match: { domain: <your-email-domain> }
      scopes:
        backends: [github, jira]
        tools: ["*"]
        rate_limit: 120
```

`match` accepts `domain`, `issuer`, `email` and `group`; every field you set must
match. Order matters — put the narrow rules first, because the first rule that
matches is the only one that applies. There is no implicit allow-all rule at the
end: an identity that matches nothing gets nothing.

## 3. Who the backend thinks is calling

Identity propagation is per backend and opt-in. A backend without it keeps
today's behaviour: the gateway's static credential, shared by everyone.

```yaml
backends:
  github:
    command: ...
    identity_propagation:
      strategy: passthrough           # signed_assertion | passthrough | token_exchange | vault
      audience: https://api.github.com
      required: true
      session_mode: per_user
```

Pick the strategy by what the backend will accept:

- **`passthrough`** — the caller attaches its own backend credential and the
  gateway forwards it verbatim, storing and minting nothing. The right default
  for a client that runs its own OAuth flow.
- **`signed_assertion`** — the gateway signs an identity assertion. For
  first-party backends that trust the gateway.
- **`token_exchange`** — RFC 8693 against the backend's exchange endpoint. Also
  set `token_exchange_endpoint`, and `token_exchange_scope` if the endpoint
  wants one.
- **`vault`** — per-user stored credentials.

Two fields do the actual isolation work:

**`required: true`** is what makes it fail closed. With `required: false`, a
request that carries no identity falls through to the static credential — so the
one request that lost its identity is the one that runs as the service account.
For any backend holding personal data, set it to `true`.

**`session_mode`** declares the backend's isolation contract. `stateless` means
one transport is safe to share because identity travels per request.
`per_user` makes the gateway open a distinct transport per
`(backend, user, audience)`. If you are not certain the backend is stateless,
it is not stateless — a backend that binds anything to the session will leak it
across users.

## The name collision to avoid

`backends.<name>.passthrough: true` and
`identity_propagation.strategy: passthrough` are unrelated settings that read
alike.

- `strategy: passthrough` forwards the **caller's credential**. This is the
  multi-user feature.
- `passthrough: true` **disables the gateway's tool policy and input
  sanitisation** for that backend. It is a trust escalation, and on a
  multi-user gateway it removes the enforcement point that the policy rules in
  section 2 rely on.

Never set `passthrough: true` on a backend reachable by more than one person.

## Isolated personal accounts

The narrow case — several people sharing one gateway, each reaching their own
account on the same backend — is the three sections above with specific answers:

1. `key_server.enabled: true` with your provider in `oidc`.
2. A policy rule per group, narrow rules first.
3. On every personal-data backend: `strategy: passthrough` (or
   `token_exchange` if the backend mints its own), `required: true`,
   `session_mode: per_user`.

Then check it, because a misconfiguration here fails silently and looks like
success:

- Call a backend tool as user A, then as user B, and confirm the results differ
  where they should. Identical results from two identities is the failure
  signature.
- Send a request with no credential. With `required: true` it must be refused,
  not served from the static credential.
- Revoke user A's token via `DELETE /auth/token/{jti}` and confirm the next call
  is refused.

## Before exposing the port

- `auth.enabled: true` — the key server does not replace the transport-level
  gate; `/health` stays public via `auth.public_paths`.
- `mtls` or a TLS terminator in front. Bearer tokens on plain HTTP are readable
  by anything on the path, and the gateway refuses backend URLs that carry
  credentials over plain HTTP for the same reason.
- `security.tool_policy` and `security.firewall` stay enabled. They are the
  enforcement point the scopes in section 2 are expressed against.
- `admin_token` set, so revocation exists before you need it.

## Related

- [ADR-007 — identity propagation](adr/ADR-007-identity-propagation.md), the
  strategy model and why propagation is per backend.
- [ADR-008 — multi-user OAuth isolation](adr/ADR-008-multi-user-oauth-isolation.md),
  the rungs and why passthrough is the primary path.
- [OAUTH_CONFIG.md](OAUTH_CONFIG.md) for the provider-side setup.
- [DEPLOYMENT.md](DEPLOYMENT.md) for everything that is not identity.
