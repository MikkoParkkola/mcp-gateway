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

## 0. If you ran `mcp-gateway init`, undo two of its defaults

`init` writes a single-user config. Two of its settings silently defeat
everything below:

```yaml
auth:
  enabled: true
  single_user: true                   # REMOVE — turns off the per-user OAuth isolation guard
  public_paths:
    - "/health"
    - "/mcp"                          # REMOVE — leaves the MCP endpoint anonymous
```

`public_paths` is what keeps an endpoint reachable without a token. Leaving
`/mcp` on that list means every policy rule in section 2 is optional: a caller
who simply omits their credential reaches the gateway anyway. Cut it to
`["/health"]`.

`single_user: true` is a hint that turns off the per-user OAuth isolation guard.
More than one API key, or any OIDC issuer, overrides the hint — but do not rely
on that. Remove the line.

One more parallel path to close: `auth.bearer_token` and `auth.api_keys` are
static credentials checked at the transport gate. They do **not** carry an
identity and are **not** constrained by the key-server policies in section 2.
A static bearer that was handed out for a single-user deployment keeps working
as an unrestricted credential after you enable the key server. Inventory them,
and keep the master bearer operator-only.

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
| `DELETE` | `/auth/tokens?issuer={issuer}&subject={subject}` | Revoke every token for one identity; `issuer` is required (400 without it) |

The two revocation endpoints require `admin_token`. Leave it unset and they
return 503 — which is safe, but means you have no revocation path. Set it.

If your clients cannot perform the exchange, `key_server.delegated_bearer: true`
lets them present the raw OIDC token directly. Policy and provider verification
still run; only the exchange step is skipped. The cost is revocation: the
endpoints above revoke tokens the gateway issued, and a raw provider token is
not one of them. In delegated mode your only revocation lever is the identity
provider, so keep provider token lifetimes short.

## 2. What they may reach

Policy rules are first-match-wins. Each rule matches on identity and grants
scopes.

```yaml
key_server:
  policies:
    - match: { issuer: <your-idp-issuer>, group: platform-admins }
      scopes:
        backends: ["*"]
        tools: ["*"]
        rate_limit: 0                  # 0 = unlimited
    - match: { issuer: <your-idp-issuer>, domain: <your-email-domain> }
      scopes:
        backends: [github, jira]
        tools: ["*"]
        rate_limit: 120
```

`match` requires `issuer`, which must equal one of `key_server.oidc[].issuer`,
and accepts `domain`, `email` and `group`; every field you set must match. A rule
with no issuer, an unconfigured one, or a blank condition fails to load.

- `email` and `domain` match only a **verified** address: the token must carry
  `email_verified: true` (or `"true"`). Microsoft Entra ID omits it by default,
  so use issuer-only or `group` rules there; Keycloak sends it only with the
  client's `email verified` mapper on. The same applies to `allowed_domains`.
- Both compare ASCII case-insensitively. `domain` is exact, not a suffix:
  `corp.com` does not match `eu.corp.com`.
- An issuer-only rule admits every account the issuer signs for your audience.
  That is right for a tenant-pinned issuer such as Entra's
  `https://login.microsoftonline.com/<tenant>/v2.0`, and wrong for a public one:
  on `https://accounts.google.com` or `https://token.actions.githubusercontent.com`
  it fails to load. Any other multi-tenant issuer has the same problem, so give
  it a `domain`, `email` or `group` condition too.

Order matters — put the narrow rules first, because the first rule that
matches is the only one that applies. There is no implicit allow-all rule at the
end: an identity that matches nothing gets nothing.

## 3. Who the backend thinks is calling

Identity propagation is per backend and opt-in. A backend without it keeps
today's behaviour: the gateway's static credential, shared by everyone.

```yaml
security:
  transparency_log:
    enabled: true                     # mandatory when any backend sets required: true
    path: "~/.mcp-gateway/transparency/transparency.jsonl"

backends:
  github:
    http_url: https://mcp.example-backend.invalid/mcp
    identity_propagation:
      strategy: passthrough           # signed_assertion | passthrough | token_exchange | vault
      audience: https://api.github.com
      required: true
      session_mode: per_user
```

**Identity propagation is HTTP-only.** A stdio backend drops
per-request headers, so the gateway refuses the config at load rather than
dispatching without the credential. A propagation-configured backend also
cannot carry its own enabled `oauth` block — the two would fight over the same
credential slot.

**`required: true` needs the transparency log enabled.** The audit helper treats
a missing log as a silent no-op, which would mint a per-user credential with no
durable record — so a required backend with no transparency log refuses every
request with `identity-propagation audit unavailable`. Enable the log in the
same change, not afterwards.

Pick the strategy by what the backend will accept:

- **`passthrough`** — the caller attaches its own backend credential in the
  `x-mcp-passthrough-authorization` header and the gateway forwards it verbatim,
  storing and minting nothing. The header is deliberately not `Authorization`,
  so the gateway's own auth token is never forwarded to a backend. This requires
  a client that knows to send it; a client that only speaks the aggregated tool
  surface will not, and on a `required` backend those calls are refused.
- **`signed_assertion`** — the gateway signs an identity assertion. For
  first-party backends that trust the gateway.
- **`token_exchange`** — RFC 8693 against the backend's exchange endpoint. Also
  set `token_exchange_endpoint` (use HTTPS — the credential leaves the gateway
  on that call), and `token_exchange_scope` if the endpoint wants one.
- **`vault`** — per-user stored credentials. Not usable from a raw backend block
  alone; it is bound through an account descriptor. Treat the three strategies
  above as the configurable set.

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
- `passthrough: true` **disables input sanitisation** for that backend's
  `tools/call` requests. Tool-name validation, the scope check and the firewall
  still run, so it is narrower than the name suggests — but it hands unsanitised
  caller input straight to a backend, which is a trust decision you do not want
  to make on behalf of other people.

Set `passthrough: true` only on a fully-trusted internal backend, never on one
reachable by more than one person.

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

## Per-user consent journey (hosted)

The section above assumes a backend will already accept the caller's identity
(passthrough or token exchange). A browser-OAuth backend like Google Workspace
does not — each person has to click through an actual consent screen once. The
hosted consent journey is the gateway-rendered version of that click-through,
for callers verified through a configured `session` bridge (Open WebUI today,
see below): a user who hits a `personal_managed` backend refusal gets a
gateway-sealed connect link in the refusal message, follows it to
`/accounts/v1/journeys/{id}/start`, is redirected to the provider, lands back
on the gateway's `/accounts/v1/callback`, and sees a gateway-rendered outcome
page. They can review their connected accounts and disconnect at
`/accounts/v1/complete` at any time. The grant is committed and stored per
user, so completing or failing one user's journey never touches another
user's credential. A caller authenticated only by OIDC (no bridge), or a POST
to the journey API with no bridge configured, keeps getting the existing
refusal text with no link — the link is only minted for bridge-verified
callers.

### Configure it

```yaml
accounts:
  # ...existing schema_version, enabled, deployment, instance_id, store_dir,
  # authority_dir, current_key_id, keys unchanged...
  hosted:
    public_origin: "https://chat.example.com"   # https origin only: no path, query, userinfo or default port
    return_paths: ["/"]                          # absolute paths the outcome page may land on; compared byte-exact
  adapters:
    - kind: openwebui_signed_header               # existing fields (installation_id, header, issuer, hmac_secret_ref, ...) unchanged
      session:                                     # new, required: enables the connect-link bridge; exactly one adapter may carry it
        user_endpoint: "http://127.0.0.1:8090/api/v1/auths/"   # Open WebUI's session-user endpoint; https, or http on a loopback literal
        cookie_name: token                          # Open WebUI's session cookie name (default "token")
  descriptors:
    google-workspace:
      mode: personal_managed
      provider: google
      issuer: "https://accounts.google.com"
      resource: "https://www.googleapis.com/"
      authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth"
      token_endpoint: "https://oauth2.googleapis.com/token"
      revocation_endpoint: "https://oauth2.googleapis.com/revoke"
      client_id: "<web client id>"
      client_secret_ref: "env:GOOGLE_OAUTH_CLIENT_SECRET"
      redirect_uri: "https://chat.example.com/accounts/v1/callback"   # must equal public_origin + /accounts/v1/callback
      scopes: ["https://www.googleapis.com/auth/gmail.readonly"]
      send_resource_parameter: false                                 # Google REST takes no RFC 8707 resource parameter; must be declared explicitly
      authorize_extra: { access_type: offline, prompt: consent }      # required for Google — see checklist step 5
```

`issuer`, `resource`, `client_id`, `authorization_endpoint`, `token_endpoint`
and `redirect_uri` are all required on a `personal_managed` descriptor;
`send_resource_parameter` must be declared (`true` or `false`, never omitted).
`redirect_uri` is checked at startup against `public_origin + /accounts/v1/callback`
for every `personal_managed` descriptor; a mismatch refuses the configuration.
`hosted` also requires exactly one adapter carrying a `session` block. See the
full worked config in `src/personal_accounts/config/journey_tests.rs`.
Omitting `accounts.hosted` mounts no route and changes no existing refusal
text. To roll back, remove `accounts.hosted` AND every adapter's `session`
block, then restart: a `session` block without `hosted` refuses to start
(`session requires accounts.hosted; without it no bridge is mounted`).

### Open WebUI side

The adapter verifies the assertion Open WebUI signs when
`FORWARD_USER_INFO_HEADER_JWT_SECRET` is set: an HS256 JWT in
`X-OpenWebUI-User-Jwt` (Open WebUI 0.9.6). Set the adapter's `header` to that
name and point `hmac_secret_ref` at the same secret. The tool connection to the
gateway must also send an API key listed in `allowed_api_key_names`.

Setting that secret changes Open WebUI globally: it then sends only the signed
header, and stops sending the plain `X-OpenWebUI-User-*` headers, to every tool
connection and model endpoint. Check that nothing else relies on the plain
headers before turning it on.

### Reverse-proxy front door

`public_origin` is the origin the browser already has open when it follows the
connect link — in the reference deployment that is the chat client's (Open
WebUI's) public hostname, which is not necessarily the same vhost that fronts
the gateway's own `/mcp` traffic in [Reverse Proxy](DEPLOYMENT.md#reverse-proxy).
Whatever front door serves `public_origin` (nginx, Caddy, a Cloudflare tunnel,
…) must forward `/accounts/v1/*` to the gateway, ordered before that origin's
own catch-all, and pass it through unmodified; everything else on that origin
keeps going to the chat client as before. The routes under the prefix:

- `POST /accounts/v1/journeys`, `GET /accounts/v1/journeys/{id}` — owner API
- `GET /accounts/v1/journeys/{id}/start` — the link the connect offer sends the user to
- `GET /accounts/v1/callback` — the provider's redirect target
- `GET /accounts/v1/complete`, `GET /accounts/v1/assets/complete.js` — the outcome/manage page
- `DELETE /accounts/v1/connections/{account_id}` — disconnect, called from the manage page

### Limits (`accounts.limits`)

| Field | Default | Meaning |
|---|---|---|
| `journeys_total` | 1024 | Active (`pending`/`started`) journeys, gateway-wide |
| `journeys_per_user` | 8 | Journey creations per principal, sliding 10-minute window |
| `starts_per_minute_per_user` | 10 | `start` invocations per principal, sliding 60 s window |
| `journeys_created_per_minute` | 120 | Journey creations gateway-wide, sliding 60 s window |
| `store_entries` | 10000 | Existing cap on the connected-account credential store, unrelated to the journey table |
| `authority_bytes` | 16777216 | Existing byte cap on the same credential store |

Every field rejects zero and overflow; there is no way to disable a limit,
only raise it.

### Google OAuth web-client checklist

1. Google Cloud Console -> APIs & Services -> Credentials -> **Create OAuth
   client ID** -> Application type **Web application**.
2. Authorized redirect URIs: exactly `<public_origin>/accounts/v1/callback`
   (for example `https://chat.example.com/accounts/v1/callback`) — no
   trailing slash, must byte-match the descriptor's `redirect_uri`.
3. Enable the API(s) behind the scopes you request (the Gmail API for
   `gmail.readonly`, for example).
4. Put the client secret in the environment variable `client_secret_ref`
   points at; never inline it in config.
5. Set `authorize_extra.access_type: offline` and `prompt: consent`. Without
   `offline`, Google's token response carries no `refresh_token` and the
   journey fails `no_refresh_token`; Google also only issues a `refresh_token`
   on first consent unless `prompt=consent` forces reissue on reconnect.

## Before exposing the port

- `auth.enabled: true`, `auth.public_paths` cut to `["/health"]`, and
  `auth.single_user` removed. The key server does not replace the transport-level
  gate, and a public `/mcp` makes the gate optional.
- Static `auth.bearer_token` / `auth.api_keys` inventoried; the master bearer
  stays operator-only.
- `auth.api_keys` hold `key_sha256` digests from `mcp-gateway hash-key`, never the
  keys, and a key handed to someone temporary carries `expires_at`.
- `mtls` or a TLS terminator in front. Bearer tokens on plain HTTP are readable
  by anything on the path, and the gateway refuses backend URLs that carry
  credentials over plain HTTP for the same reason.
- `security.tool_policy` and `security.firewall` stay enabled. They are the
  enforcement point the scopes in section 2 are expressed against.
- `admin_token` set, so revocation exists before you need it — and remember it
  does not reach raw provider tokens in delegated mode.
- `security.transparency_log.enabled: true` if any backend sets `required: true`.

## Related

- [ADR-007 — identity propagation](adr/ADR-007-identity-propagation.md), the
  strategy model and why propagation is per backend.
- [ADR-008 — multi-user OAuth isolation](adr/ADR-008-multi-user-oauth-isolation.md),
  the rungs and why passthrough is the primary path.
- [OAUTH_CONFIG.md](OAUTH_CONFIG.md) for the provider-side setup.
- [DEPLOYMENT.md](DEPLOYMENT.md) for everything that is not identity.
