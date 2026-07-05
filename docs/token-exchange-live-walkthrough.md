# Live exercise: RFC 8693 token exchange against the gateway's own /auth/token

This walks through starting the gateway with `examples/token-exchange-live.yaml`,
sending a request as a real user, and watching a policy-scoped downstream
token arrive at a backend via `TokenExchangeStrategy` (MIK-6729). Every step
below hits real HTTP endpoints, no mocks.

## What you need first

- A real OIDC ID token for a user in the domain your policy matches
  (`example.com` in the sample config; edit `key_server.policies[0].match.domain`
  and `key_server.oidc[0]` to your own IdP tenant before running this).
- `GATEWAY_OIDC_CLIENT_ID` set to that IdP's client/audience id.
- A backend to receive the propagated token. The sample config points
  `backends.mail-svc.http_url` at a placeholder; point it at any MCP server
  you control, or just watch the exchange happen and expect the final
  backend call to fail once it reaches an unreachable placeholder host, the
  token exchange itself completes before that.

## 1. Start the gateway

```bash
mcp-gateway --config examples/token-exchange-live.yaml
```

This mounts, among others:

- `POST /auth/token` — the RFC 8693 token-exchange endpoint (`src/key_server/handler.rs`),
  outside the auth middleware because it IS the auth step.
- `GET /.well-known/jwks.json` — the gateway's own signing key, unauthenticated
  (`src/gateway/router/mod.rs`). The `mcp-gateway` OIDC provider entry in the
  config verifies against this same endpoint, closing the loop: the gateway
  trusts tokens it signed itself.

## 2. Log in as the user: exchange the real OIDC token for a gateway bearer

```bash
curl -s http://127.0.0.1:39400/auth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
  --data-urlencode "subject_token=$REAL_OIDC_ID_TOKEN" \
  --data-urlencode 'subject_token_type=urn:ietf:params:oauth:token-type:id_token'
```

The response is a `TokenExchangeResponse`:

```json
{"access_token": "<opaque bearer>", "token_type": "Bearer", "expires_in": 300, "scope": "...", "jti": "..."}
```

Save `access_token` as `$GATEWAY_TOKEN`. This is the same endpoint and wire
format `TokenExchangeStrategy` uses internally in step 4, just with a human
holding the OIDC token instead of a gateway-signed assertion.

## 3. Call the gateway as that user

```bash
curl -s http://127.0.0.1:39400/mcp \
  -H "Authorization: Bearer $GATEWAY_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"gateway_invoke","arguments":{"server":"mail-svc","tool":"..."}}}'
```

`auth_middleware` (`src/gateway/auth.rs`) validates `$GATEWAY_TOKEN` against
the key server's in-memory store, resolves the caller's `VerifiedIdentity`,
and attaches it to the request. That identity flows through
`MetaMcpCallerContext` into `resolve_caller_credential`.

## 4. What happens next, invisibly: the backend-scoped exchange

Because `backends.mail-svc.identity_propagation.strategy` is `token_exchange`,
the gateway does not forward your `$GATEWAY_TOKEN` to `mail-svc`. Instead
`TokenExchangeStrategy::propagate`:

1. Mints a short-lived, gateway-signed assertion for the SAME user identity
   (issuer `mcp-gateway`) via `SignedAssertionStrategy::mint` — this is the
   `subject_token`.
2. Signs an RFC 7523 `private_key_jwt` client assertion authenticating the
   gateway itself as the OAuth client.
3. POSTs both, form-urlencoded, to `token_exchange_endpoint`
   (`http://127.0.0.1:39400/auth/token` — the gateway's own endpoint again)
   with `scope=backends:mail-svc tools:mail_read`.
4. The key server verifies the assertion against the `mcp-gateway` OIDC
   provider entry (JWKS fetched from the gateway's own `/.well-known/jwks.json`),
   matches the same policy rule (the assertion carries the user's original
   email through unchanged), and mints a NEW opaque bearer scoped to
   exactly `backends: ["mail-svc"]`, `tools: ["mail_read"]`.
5. That new bearer is cached in-memory keyed on `(subject, audience)` and
   injected as `Authorization: Bearer <scoped token>` on the outbound call
   to `mail-svc`. A second call within the 300s TTL reuses the cached token
   with zero additional HTTP round trips.

`mail-svc` never sees your original `$GATEWAY_TOKEN`; it sees a token scoped
to only what the policy grants, minted for that specific request's identity.

## 5. Where to see it in the audit log

`security.transparency_log` is enabled in the sample config, writing NDJSON
to `./token-exchange-demo.jsonl`. After step 3, look for a line like:

```json
{"action":"idp_mint","subject":"<user subject>","backend":"mail-svc","audience":"https://mail-svc.internal","timestamp":"..."}
```

`action` is `idp_mint` on success and `idp_refuse` on a fail-closed refusal
(for example, if the user has no propagable identity and the backend is
`required: true`). Neither the minted assertion nor the scoped bearer ever
appears in this log; only who, which backend, which audience, and when
(`src/identity_propagation/mod.rs::audit_identity_propagation`).

## Fail-closed checks worth trying

- Drop the `mcp-gateway` OIDC provider entry from `key_server.oidc` and
  repeat step 3: the backend-scoped exchange in step 4 now gets a real
  `401`/policy-denial from `/auth/token`, and the call to `mail-svc` fails
  closed rather than falling back to a shared credential.
- Remove `token_exchange_endpoint` from the backend config entirely: the
  gateway refuses before making any network call, since an unconfigured
  endpoint is a config error, not a reachability problem.
