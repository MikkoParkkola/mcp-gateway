# Upgrading to 4.0.0

From any 3.x release. No migration edits your `gateway.yaml`, and the gateway makes no automatic
change to your configuration on upgrade. It starts on an unchanged configuration unless one of items 2, 8, 12, 13, 16, 17, 27, 29, 30, 34, 35, 37, 38, 39, 40, 41, 43, 44, 46 or 51 refuses it
(listed in bold below).

On the first `serve` after the upgrade, the gateway prints a one-time notice to stderr listing
items 1-4, 6, 11, 23-27, 30-34, 37, 39, 43 and 45 below, then stamps the new version. The notice is printed rather than logged, so
`--log-level error` and `RUST_LOG` filters cannot swallow it.

The rest of the list has no startup notice, for two different reasons. Items 5 and 9 are
changes to the license and to a removed CLI surface rather than to running behaviour. Items
7 and 8 are decided per backend, so there is no single moment at startup at which
the binary could know whether a given deployment is affected. Item 10 changes the shipped
deployment files, not the binary's behaviour on an existing route, and so does item 21.
Items 38 and 51 refuse the start with their own error, which names the setting, so a notice would
only repeat it; item 51 also warns once per `role: admin` rule at every load.

**Items 2, 8, 12, 13, 16, 17, 27, 29, 30, 34, 35, 37, 38, 39, 40, 41, 43, 44, 46 and 51 refuse the gateway's start (item 41 only for an API key configured as plaintext `key`; item 43 only with auth on and no working audit log; item 44 only for a secret written as `file:...` that names a missing, loose, oversized or empty file; item 46 only for `enforce` without a signing key; item 51 only for a `role: admin` rule whose only condition is `domain`; item 16 only while `trust_caller_identity_headers` is still set; item 17 only for a `key_server` rule without a configured issuer or with a blank matcher; item 37 only above one declared replica; item 39 only while `server.request_timeout` is set; item 27 for a bare `exact` grant under `fail_on_error: true` or a `declared` known agent with agent identity on; item 30 only for a bad `GATEWAY_ATTESTATION_MODE`; item 38 only for a credential over plain HTTP on a network bind without mTLS; item 40 only for a secret reference that resolves to nothing or to an empty value). Item 7 permanently fails the backend it names,
with one warning, and the gateway starts without it.** Read those first if you are
upgrading a running deployment.

## What changed

| # | Change | Action needed |
|---|---|---|
| 1 | OAuth credentials are stored per issuer | Re-authorize each OAuth backend once |
| 2 | A malformed `env_files` line fails startup | Fix the line the error names |
| 3 | Protocol `2024-10-07` is no longer advertised | None for conforming clients — see below |
| 4 | Rate-limited responses no longer trip the breaker | None — this removes a failure mode |
| 5 | One license across the repository | Commercial users need a commercial license |
| 6 | Caching requires an identifiable protocol revision | Send the version header, or `initialize` the session |
| 7 | An OAuth backend must be on TLS or loopback | Put TLS in front of it, or move it to `127.0.0.1` — no opt-out |
| 8 | A credential-bearing backend on plain `http://` is refused at load | Use TLS, or set `allow_cleartext_credentials: true` on that backend |
| 9 | The savings estimates are gone from stats | Drop `--price`; compute cost from `total_cached_tokens` yourself |
| 10 | Shipped probes move from `/health` to `/livez` and `/readyz` | Repoint your own probes; `/health` still answers |
| 11 | Webhook `notify` defaults to off and is scoped per caller | Add `notify: true` to webhooks that should notify |
| 12 | `auth.api_keys[].name` must be non-empty and unique | Name every key, once |
| 13 | Identity grants match on `authority` and `subject`; `write` scope is gone | Rewrite `write` grants as `execute` |
| 14 | Cached and idempotent results are kept per caller | None; expect per-key cache hit rates and a one-TTL idempotency gap |
| 15 | Discovery shows a caller only what it could invoke | None to configure; see below for what non-admin callers stop seeing |
| 16 | `trust_caller_identity_headers` is replaced by `security.caller_identity` | Choose a mode; list your proxies and an authority, or configure Cloudflare Access |
| 17 | Key-server rules need an issuer and a verified email; revocation needs an issuer | Add `issuer` to every `key_server.policies[].match`; pass `issuer` to `DELETE /auth/tokens` |
| 21 | The Helm chart and enterprise-alpha manifests start | Write `config.backends` as a map (`{}`); expect task records to last only as long as the pod |
| 22 | The governance store location is configurable | None; set `control_plane.store_dir` if the config directory is read-only |
| 23 | `logging/setLevel` on `/mcp` and `/mcp/{name}` needs an admin key | Send it with an admin key, or declare a level per request in `_meta` |
| 24 | `notifications/tools/list_changed` from backend edits reaches only callers of that backend | None; a key that must hear about every backend needs `backends: ["*"]` |
| 25 | Admin-panel grant, policy and decision writes return 409 | Change grants with `mcp-gateway identity grants`, policies in `security.*`; keep the old store files |
| 26 | `subscriptions/listen` needs a credential and is scoped to it | Send a credential with the listen request; re-subscribe after a token is revoked or expires |
| 27 | Exact agent grants name their proof source | Rewrite each bare `exact` grant as `!exact {source: mtls, id}` or `!exact {source: jwt, id}`; give `known_agents` entries a source |
| 28 | A modern `tools/call` without an idempotency key is admitted, unprotected | None by default; set `server.idempotency_key: required` once your modern clients send keys |
| 29 | A config key the gateway does not read fails the load | Fix the spelling of, or delete, each key the error names |
| 30 | Attestation is off by default; unrecognised modes fail startup | Set `GATEWAY_ATTESTATION_MODE=observe` to keep the audit lines |
| 31 | Tool calls with undeclared argument keys are refused | Stop sending the key, or set `input_schema_enforcement: standard` (or `off`) on that backend |
| 32 | An API key or key-server rule with no `backends` reaches no backend | Add `backends: ["*"]` for the old behaviour, or list the backends it needs; the gateway warns per affected key at startup |
| 33 | `/metrics` requires its own scrape token | Set `server.metrics_token`; give Prometheus the token through a dedicated scrape job |
| 34 | The inbound WebSocket listener is gone; `server.ws_port` fails the load | Delete `server.ws_port`; connect clients over HTTP (`POST /mcp`) or stdio |
| 35 | A config or env file other users can read fails the load (Unix) | `chmod 600` the file; on Kubernetes keep the chart's `fsGroup` and `defaultMode` |
| 36 | The Helm chart pins its pod identity to 1001 and caps the `state` volume at `1Gi` | Remove any `podSecurityContext` override; raise `stateVolume.sizeLimit` if HOME outgrows `1Gi` |
| 37 | More than one replica is refused while per-process state is on; the chart defaults to one replica | Keep `replicaCount: 1`, or set `server.modern_protocol: false` with the key server and accounts off |
| 38 | A credential over plain HTTP on a network bind refuses the start | Enable `mtls`, or set `server.cleartext_http` to say who protects the traffic |
| 39 | `server.request_timeout` fails the load; `server.max_body_size` caps every route, oversize gets HTTP 413 / JSON-RPC -32600 | Delete `server.request_timeout` and bound calls with per-backend `timeout`; keep `max_body_size` positive, lower it if you relied on the 2 MiB webhook cap |
| 40 | A secret reference that resolves to nothing fails the load | Set the variable the error names, or write `${VAR:-}` where empty is intended |
| 41 | API keys are configured as sha256 digests; a plaintext `key` fails the load | Replace each `key` with `key_sha256` from `mcp-gateway hash-key`; clients keep the same key |
| 42 | `webhooks.rate_limit` is enforced, per endpoint, default 100 per minute | Raise it above your provider's peak rate, or set `0` for no limit |
| 43 | With auth on, the audit log is required, records who and the outcome, and fails closed | Enable `security.transparency_log` on a writable path; on Kubernetes set `audit.existingClaim` to keep the log |
| 44 | `file:` secret references; a literal starting `file:` is now a reference | Point `file:` at an absolute, owner-only (or group-read via `fsGroup`) file; change a literal secret that starts with `file:` |
| 45 | `/health` answers 503 `degraded` while a backend's circuit breaker is open | Expect it on `/health` monitors; Kubernetes probes (`/livez`, `/readyz`) are unaffected |
| 46 | Attestation `enforce` enforces on every route; it needs a signing key | Set `GATEWAY_ATTESTATION_SIGNING_KEY`; send the token on every call; call tools one by one instead of playbooks and code mode |
| 51 | A `role_mapping` `role: admin` rule grants full gateway admin; a domain-only admin rule fails the load | Review existing `role: admin` rules; replace a domain-only one with `group` or `email` |
| 52 | Only `tools.listChanged` is advertised, and only over HTTP; `resources/subscribe` and `resources/unsubscribe` are refused | Drop any wait for `resources/updated`, `resources/list_changed` or `prompts/list_changed`; poll `resources/list` or `prompts/list` instead |

Numbers 18-20 are intentionally unused.

## 1. OAuth credentials are stored per issuer

Tokens stored by 3.x are **not migrated**. Nothing is lost and nothing is silently reused
under a new key: each OAuth backend simply re-authenticates on its next use.

Expect one authorization prompt per OAuth backend, once. No config change is needed. If your
deployment is unattended, trigger each backend deliberately rather than discovering the prompt
on a user's first call.

## 2. A malformed line in an `env_files` file now fails startup

In 3.x a line that could not be parsed was skipped silently, so a typo cost one missing
environment variable and the gateway started anyway — usually failing later, somewhere
unrelated.

In 4.0.0 the same typo refuses the start and names the offending line. This is the change most
likely to surprise a running deployment, because a file that "worked" for months can hold a bad
line that never mattered until now.

Before upgrading a production gateway, start it once against your real `env_files` in a
throwaway environment. A refused start with a line number is a one-minute fix; a refused start
during a deploy window is not.

## 3. Protocol version `2024-10-07` is no longer advertised

`2024-10-07` is not a revision the MCP specification has ever defined. It was listed in the
gateway's supported set from the first negotiation commit until 4.0.0, where it was removed
(`src/protocol/mod.rs:32-37`).

The removal changes what the gateway *claims*, not how it answers. `server/discover` publishes
the supported set as the gateway's own statement of what it speaks, so an invented revision in
that list was a false claim. Negotiation itself was never affected: `negotiate_version` matches
exactly, and no conforming client can request a revision that does not exist.

Nothing is rejected. A client naming `2024-10-07` in `initialize` gets `2025-11-25` back —
the same fallback any unrecognized version string gets, before and after this release
(`tests/integration.rs:37`). There is no error and no refused session.

`2024-11-05` and every later revision negotiate exactly as before. The startup notice advises
upgrading a client that speaks only `2024-10-07`; in practice such a client would have been
getting the fallback all along.

## 4. Rate-limited backend responses no longer count as failures

HTTP 429 and its equivalents are excluded from the error budgets and from the circuit breaker
(GH #475). In 3.x a backend that was merely busy could be tripped open and taken out of
rotation — the gateway punished a backend for applying backpressure correctly.

The gateway's own per-backend limiter (`failsafe.rate_limit`) is covered by item 53.

There is nothing to change. Expect fewer spurious breaker openings, and note that a genuinely
broken backend that happens to answer 429 will now stay in rotation longer.

One boundary is deliberate and worth knowing: a capacity failure worded as a throttle — for
example `request throttled: upstream out of capacity` — is still treated as rate limiting and
therefore still exempt. Narrowing that needs a rate-limit co-signal and is not in 4.0.0.

## 5. One license across the repository

4.0.0 retires the MIT core and the per-file allowlist that enumerated it. Every first-party file
in this repository is now under the **PolyForm Noncommercial License 1.0.0**
([ADR-013](adr/ADR-013-single-noncommercial-license.md), [LICENSES.md](../LICENSES.md)).

Noncommercial use is unaffected. Commercial use requires a commercial license — see
[COMMERCIAL.md](../COMMERCIAL.md). If you adopted the gateway under the previous MIT core, this
is the change to route past whoever approves your licensing, not a runtime concern.

## 6. Responses are cached only for a known protocol revision

The response cache is now keyed by the protocol revision the request was served under, and a
request whose revision cannot be identified is not cached at all
(`cache_protocol_revision`, `src/protocol/meta.rs:514`). A modern request carries its revision
in the body. A legacy request must supply it in the `MCP-Protocol-Version` header, or have
bound one by completing `initialize` on the session.

In 3.x the cache had no such key, so a response fetched for a caller that declared no revision
could be served to a caller asking under a different one. Refusing to key what cannot be
identified is the safe half of that trade, and the skip is deliberate rather than a fallback.

**This is the item most likely to surprise you.** A client that sends no
`MCP-Protocol-Version` header *and* does not run `initialize` — a bare stateless `POST`, which
is common in load generators, probes and simple scripts — loses response caching entirely on
upgrade, and that traffic goes to your backends instead. Nothing errors; throughput and backend
load change. The gateway's own rate limits (default 100 rps, burst 50) then apply to calls that
previously never reached them.

Send `MCP-Protocol-Version` on stateless requests, or complete `initialize` and reuse the
session. Either restores caching; neither requires a configuration change.

## 7. An OAuth backend must be on TLS or loopback

The bearer token an OAuth backend's transport attaches is a replayable credential, so it no longer
goes on the wire in cleartext. `https://` is always accepted; `http://` only when the host is
loopback (`localhost`, `127.0.0.0/8` or `::1`). Anything else fails the backend with
`refusing to send an OAuth token in cleartext to <origin>`, and the gateway starts without it.
`http://[::ffff:127.0.0.1]` counts as non-loopback; use `http://127.0.0.1`.

Put TLS in front of the backend, or move it to a loopback address. There is no opt-out. Backends
without OAuth may still use plain `http://`.

## 8. A credential-bearing backend on plain `http://` is refused at load

An enabled backend whose `http_url` or `a2a_url` is `http://` to a host off this machine, and
whose configuration carries a credential, fails the load. Credential-bearing means an `oauth`
section (even with `enabled: false`), identity propagation, secret injection, any static header,
or userinfo or a query string in the URL. The error names the backend and never echoes the URL.

Use TLS, or set `allow_cleartext_credentials: true` on that backend to accept the exposure. See
[REMOTE_BACKENDS.md](REMOTE_BACKENDS.md). The flag does not lift item 7: an OAuth backend on `http://` off loopback is
still refused, flag or not.

## 9. The savings estimates are gone from stats

The `stats --price` flag, the `gateway_get_stats` `price_per_million` argument, and the
`tokens_saved` and `estimated_savings_usd` response fields are removed. They were estimates with no
measured basis. Drop `--price` from scripts, and compute cost from `total_cached_tokens` with your
own price.

## 10. Probes read `/livez` and `/readyz`, not `/health`

`/health` answers 503 whenever the health tracker marks any backend down. The Helm chart and
the enterprise-alpha manifests used it for the liveness, readiness and startup probes, so one
flapping upstream restarted every replica, and a backend that was down at deploy time kept new
pods from ever starting. The container `HEALTHCHECK` also dialled `localhost`, which the Host
gate refuses on a `0.0.0.0` bind with no `public_url`, so the image reported itself unhealthy.

4.0.0 adds two endpoints that never read backend health:

- `/livez` answers 200 while the process serves. Use it for liveness and container healthchecks.
- `/readyz` answers 200 once the config has loaded and the listener is up. Use it for readiness
  and startup. It deliberately does not fail on a backend: there is no per-backend `required`
  setting, and one unreachable upstream is not a reason to take the gateway out of rotation.
  Since item 43 it does fail, with 503, while an auth-enabled gateway's audit log cannot append.

Both are public exactly when `/health` is. A config that lists only `/health` under
`auth.public_paths` exposes all three, and one that omits `/health` requires a credential on all
three. You do not need to add them to `public_paths`.

The shipped chart, manifests, `Dockerfile` and single-node compose file now point at the new
endpoints and dial `127.0.0.1`. If you wrote your own probes, or a load balancer health check,
against `/health`, repoint them. `/health` is unchanged and remains the place to read backend
state, so keep it for dashboards and alerts.

## 11. Webhook notifications are opt-in and scoped to the caller

A capability webhook's `notify` now defaults to `false`. In 3.x it defaulted to `true`, and the
event went to every connected session regardless of who owned it. With `notify: true`, a session
now receives the event only if its API key may access the capability backend
(`capabilities.name`), the same check that gates tool calls to that backend.

Nothing errors: a webhook that relied on the old default is still received and acknowledged, and
its response reports `"notified": false`. Add `notify: true` to each webhook that should reach
MCP sessions, and give the keys that should see those events access to the capability backend.
An API key whose `backends` list is `["*"]` is unaffected by the scoping; one with no `backends`
reaches no backend at all (item 32).

The check runs at delivery, against the credential the session was opened with: a key-server
token that is revoked or expires stops receiving on its open stream. With authentication on, a
session that presented no credential (a public-path connection) receives no webhook events. With
authentication off, every session receives them, as before.

Installs already stamped 4.0.0 by a pre-release build get this notice once, on their next start.

## 12. API key names must be non-empty and unique

An API key's `name` is its identity-grant subject (`api_key:<name>`). In 3.x names were
optional and could repeat, so two keys named alike held each other's personal-capability grants
and a nameless key could hold none. Config load now refuses an empty or whitespace-only name,
and a name used by more than one key, whether or not `auth.enabled` is set. The error names the
duplicate. Give each key its own name; renaming a key moves its grants, so update any
`api_key:` grant subjects to match.

## 13. Identity grants match on authority and subject

Three changes to `security.identity_grants`, all in `docs/identity_grants.md`:

- **The label is display text.** Grants, owners and callers compare on `authority` and
  `subject` only. In 3.x a differing `label` denied, so a grant labelled `Alice` never matched
  the API key `alice`, whose runtime label is its name. Grants that failed only on the label now
  allow. Review personal grants whose subject matches a caller but whose label does not; those
  are the ones that start allowing.
- **`read` means read-only capabilities.** Dispatch asks for `read` when the capability declares
  `metadata.read_only: true` and `execute` otherwise. An `execute` or `any` grant covers both. In
  3.x dispatch always asked for `execute`, so a `read` grant never allowed anything.
- **`write` is refused.** Dispatch cannot tell a write from any other non-read-only call, so a
  `write` grant never matched. A grants file containing one now fails to parse: startup fails
  under the default `fail_on_error: true`, and a reload is refused with the grants in force left
  in place. Rewrite it as `execute`. The CLI `--scope` no longer accepts `write`.

`GrantSubject` no longer implements `PartialOrd`/`Ord`, and its `PartialEq` ignores `label`.
`GrantScope::Write` and `IdentityGrantScopeArg::Write` are removed.

## 14. Cached and idempotent results are kept per caller

In 3.x, callers authenticated only by an API key or the admin bearer shared one response-cache
namespace and one idempotency key space. Two keys calling one tool with one set of arguments got
one cached result, and one key could replay another's stored result under the same idempotency
key. On the direct `/mcp/{name}` route, callers identified by mTLS, trusted identity headers or an
OAuth agent shared the idempotency key space as well.

Each authenticated caller now keys on its own principal: its OIDC identity or identity-propagation
binding when it has one, else its grant subject (mTLS, trusted headers, OAuth agent), else a digest
of the validated API key or bearer. The key's `name` is never used. Callers with no credential,
such as a gateway with `auth.enabled: false`, still share one namespace.

No configuration changes. What to expect:

- **Cache hit rates fall to the per-key rate** on deployments with several keys, and upstream call
  volume can rise until each key has warmed its own entries. Watch `mcp_cache_hits_total`.
- **Idempotency entries written before the upgrade do not replay** for an authenticated caller: a
  retry sent across the upgrade runs again instead of replaying. The gap lasts at most one
  idempotency TTL. Where a duplicate side effect matters, upgrade during a low-write window.
- **An authenticated caller that resolves to no principal** is served without the cache and without
  the idempotency guard rather than pooled. No shipped authentication path produces one; if
  `mcp_cache_bypass_total` or `mcp_idempotency_guard_skipped_total` with
  `reason="unresolved_principal"` ever counts, report it. Both carry a `route` label (`meta` or
  `direct`).

## 15. Discovery shows a caller only what it could invoke

In 3.x, invocation was checked per caller but most discovery was not. A key scoped to one backend
was shown every other backend's tool names, schemas and counts, and a tool denied by the global
`tool_policy` was listed to every caller, anonymous ones included, and then refused when called.

Discovery now matches invocation, and nothing callable was removed. A tool, backend, count or
suggestion reaches a caller only if the same checks a call faces would admit it: the routing
profile, the transport's authorizer (backend scope, `tool_policy`, the key's `allowed_tools` /
`denied_tools`, mTLS policy, agent-auth scopes), the admin-only capability rule and identity grants.
This covers `tools/list`, `tools/list?query=`, `tools/resolve`, `gateway_search_tools`,
`gateway_search`, `gateway_list_tools`, `gateway_list_servers` (and its `tools_count`), the
`initialize` instructions and their counts, the meta-tool descriptions, did-you-mean hints,
`predicted_next`, `_cost_suggestion`, `gateway_list_disabled_capabilities` and the
`gateway_set_state` count. There is no opt-out: an opt-out would be a disclosure switch.

What changes for callers:

- **Scoped keys, OIDC users and anonymous callers see fewer tools, smaller counts and a shorter
  routing guide.** Tools denied by `tool_policy` disappear from every listing.
- **A withheld item answers like an absent one.** `gateway_list_tools(server=X)` for a backend the
  caller may not reach returns `Backend not found: X`, where 3.x returned a "not available in the
  routing profile" message. A direct-name call of a surfaced tool the caller may not invoke answers
  `-32601 Unknown tool` instead of a 403 that named the backend.
- **`gateway_get_stats` and `gateway_webhook_status` are admin-only.** Their data describes every
  caller's traffic. A non-admin no longer sees them in `tools/list` and is refused by name. The
  `mcp-gateway stats` command sends no credential, so against a gateway where it is not an admin
  it is now refused; call the tool with an admin key instead.
- **`gateway_get_profile` and `gateway_set_profile` show non-admins a profile's name and
  description only**, not its allow/deny patterns.
- **A non-admin `/health` returns `status` and `version` only.** The backend count is admin-only.
  Probes should read `/livez` and `/readyz` (§10) or `status`.
- **A refused playbook step reads `step not permitted for this caller`** in `step_errors`, instead
  of a refusal naming the target.
- **The direct route `POST /mcp/{name}` `tools/list`** now follows the upstream `nextCursor` for up
  to 32 pages, drops entries it cannot parse, keeps only tools that route's `tools/call` admits,
  and answers `{ "tools": [...] }` with no `nextCursor` and no other upstream key. An inbound
  `cursor` is ignored. A catalogue longer than 32 pages is refused with JSON-RPC `-32005`
  (`data.reason = "direct_list_page_cap"`) and counted in
  `mcp_direct_tools_list_page_cap_exceeded_total{backend}`, never truncated.
- **The quickstart guide's "Cost tracking" section is split** into "Cost report" and
  "Statistics", so a non-admin keeps the `gateway_cost_report` docs.

Embedders calling `MetaMcp` directly: `handle_initialize`, `handle_tools_list_for_session`,
`handle_tools_list_with_params`, `handle_tools_list_with_url_override` and `handle_tools_resolve`
take an `InvokeScope` in place of a `CallerStanding`. `InvokeScope::unscoped(standing)` gives the
operator's unfiltered view.

## 16. Caller identity headers need a proven source

In 3.x, `security.identity_grants.trust_caller_identity_headers: true` let any client that could
reach the gateway pick its own grant subject and authority with `X-Gateway-Identity-*` or
`Cf-Access-Authenticated-User-*`. Nothing checked that the request came through the proxy, and
a caller that sent `X-Gateway-Identity-Authority: https://accounts.google.com` with a victim's
`sub` held the victim's OIDC grants.

- **The old key fails to load.** Remove it and set `security.caller_identity` instead
  (`docs/identity_grants.md`). `true` becomes `mode: trusted_proxy` with `trusted_proxies`
  (the exact IPs of the proxies that connect to the gateway) and an `authority`, or
  `mode: cloudflare_access` with `team_domain` and `audiences`. `false` needs no change.
- **Proxy obligation.** In `trusted_proxy` mode each proxy MUST strip or overwrite every
  client-supplied `X-Gateway-Identity-*` header. The IP allowlist proves the request came
  through the proxy, not that the proxy wrote the header. Startup logs this at `warn`.
- **Headers from any other peer are refused with 403.** The peer is the direct TCP peer;
  `X-Forwarded-For` is never read, so a proxy chain lists its last hop.
- **`X-Gateway-Identity` and `X-Gateway-Identity-Authority` are gone.** Proxies send
  `X-Gateway-Identity-Subject` (and optionally `-Label`); either removed header gets 400. The
  authority is always the configured one, and it may not be `mtls`, `agent_oauth`, `api_key`,
  a `key_server.oidc` issuer or the Access issuer.
- **Loopback proxies need `auth.enabled: true`;** `0.0.0.0` and `::` are always refused. A
  same-host `cloudflared` moves to `cloudflare_access`.
- **Cloudflare Access is verified.** `Cf-Access-Jwt-Assertion` is checked against
  `https://<team_domain>/cdn-cgi/access/certs`, `aud` and `exp`. `Cf-Access-Authenticated-User-*`
  is never read; sent without a valid assertion it gets 401.
- **Rewrite grants.** Grants for the `trusted_header` authority, or for an authority a proxy used
  to send, move to the configured `authority`. Access grants key on
  `(https://<team_domain>, <Access sub>)`, not on email.
- **Stricter values.** A repeated identity header, a non-UTF-8 one, an `X-Gateway-Identity-*` value over
  512 bytes, or a `Cf-Access-Jwt-Assertion` over 8 KiB is
  refused with 400 instead of truncated or first-wins.

Embedders: `MetaMcp::with_trusted_identity_headers(bool)` and
`MetaMcp::trust_caller_identity_headers()` are replaced by
`with_caller_identity(CallerIdentityConfig)`, and `KeyServerOidcConfig.max_token_age_secs` by
`token_age: TokenAgeCap` (`MaxIat(secs)` keeps the old behaviour).

## 17. Key-server OIDC rules need an issuer and a verified email

Before 4.0 an email or domain rule matched the raw `email` claim, whether or not the identity
provider had verified it. On a self-service or multi-tenant IdP anyone could set their address
to `ceo@corp.com` and match. Rules also needed no issuer, so a token from a second configured
IdP could satisfy a rule written for the first.

- **Every `key_server.policies[].match` needs an `issuer`** equal to a configured
  `key_server.oidc[].issuer`. A rule with no issuer, a blank or unconfigured issuer, or a blank
  `email`/`domain`/`group` fails to load, and the error names the rule index. `match: {}` no
  longer parses.
- **Issuer-only rules on `https://accounts.google.com` or
  `https://token.actions.githubusercontent.com` fail to load** (with or without the scheme or a
  trailing slash). Such a rule admits every Google account, or every GitHub workflow, that gets a
  token for your audience. Add a `domain`, `email` or `group` condition. Any other multi-tenant
  issuer behaves the same way; the gateway only recognises these two.
- **Email and domain rules and `allowed_domains` need `email_verified: true`.** The verifier
  keeps `email` only when the claim is JSON `true` or the string `"true"`, and otherwise treats
  the token as having no email. Microsoft Entra ID omits the claim by default, so Entra users lose
  email and domain matches: move them to issuer-only rules (the issuer pins the tenant) or group
  rules before upgrading, or they get 403 at token exchange. Okta and Auth0 send it when the
  `email` scope is granted; Keycloak only with the client's `email verified` mapper on.
- **Matching is ASCII case-insensitive and `domain` is exact.** `Alice@Corp.COM` matches
  `alice@corp.com` and `corp.com`. `domain: corp.com` does not match `eu.corp.com`; give each
  subdomain its own rule. An address without exactly one `@` has no domain.
- **`DELETE /auth/tokens` requires `issuer`** as well as `subject`, and returns 400 without it.
  The per-identity token cap also counts `(issuer, subject)`, so the same `sub` at two IdPs no
  longer shares a cap or a revocation. The token store is in memory, so the upgrade restart drops
  every issued key-server token; clients exchange again.
- **Control-plane role mapping** gets the same verified-email and case-insensitive matching with
  no config change.
- **Identity propagation** stops carrying an unverified email: the gateway-signed assertion's
  `email` claim is empty for such users. A backend keyed on the propagated email must key on
  `sub` plus `tenant` instead. The assertion carries no `email_verified` claim, so when
  `/auth/token` exchanges the gateway's own assertion (the `token-exchange-live` example), match
  it with an issuer-only rule on the `mcp-gateway` issuer, not an email or domain rule.

## 21. The Helm chart and enterprise-alpha manifests start

The chart has never been able to start, from its introduction (#292, which already had
`serve --host`; `--host` has been non-global since v2.0.0) up to this release. Three fatal errors
stood in line, each one hiding the next:

1. The container args were `serve --config … --host 0.0.0.0 --port N`. `--host` and `--port` are
   top-level flags and `serve` takes only `--stdio`, so the process exited 2. The args now carry
   no subcommand, which is the form the single-node compose file already uses.
2. `config.backends: []` is a list, and the gateway reads `backends` as a map, so the config
   failed to load. The default is now `backends: {}`. If you override `config.backends`, write it
   as a map keyed by backend name.
3. The root filesystem is read-only and the task store lives under `$HOME`, so opening it failed.
   The pod now mounts a `state` volume (`emptyDir`) at `/var/lib/mcp-gateway` and sets
   `HOME=/var/lib/mcp-gateway`, which covers the task store, the gateway data directory, the
   upgrade stamp and the npm/uv caches.

A fourth refusal came before any of these on a cluster: the image declares `USER gateway`, a name
the kubelet cannot check against `runAsNonRoot: true`, so the pod was never created. The pod
security context now sets `runAsUser: 1001`, the image's gateway user.

Task records live in the `state` volume. An `emptyDir` survives a container restart, and a pod
that is replaced (rollout, eviction, reschedule) starts empty. This release has no
chart setting for a persistent volume.

Each pod has its own `state` volume, so a task created on one pod is unknown to another. Both
shipped defaults now run one pod, and more than one is refused while the task surface is on
(item 37).

The control-plane store still sits next to the config on
the read-only ConfigMap mount, so governance mutations stay off in a chart install (one WARN at
startup). That is tracked separately.

Both still serve the bearer token over plain HTTP inside the cluster. Item 38 makes that a
declared choice, `cleartext_http: cluster_internal`, rather than a silent one.
## 22. The governance store location is configurable

New `control_plane.store_dir`. When it is unset, the store stays at
`<config dir>/<config stem>-control-plane`, so existing installs do not move. When it is set, it
must be absolute after `~` expansion, and with auth on a gateway that cannot write it refuses to
start. The
store has no lease: one gateway process per `store_dir`. The admin API
(`GET /ui/api/control-plane`) adds `mutation_disabled_reason` (`auth_off` or `store_unavailable`)
and `base_source` (`explicit` or `default`), and a 503 mutation answer names the cause and the
path.

Helm: the chart's config directory is a read-only ConfigMap, so the default location cannot be
created there, and a chart install reports `store_unavailable`. Governance mutation on Helm needs
a persistent `store_dir`; an `emptyDir` would lose a revocation on restart.

## 23. `logging/setLevel` needs an admin key

In 3.x any caller could send `logging/setLevel` to `POST /mcp`. The gateway forwarded the level
over its own credential to every running shared backend, so a key scoped to one backend could
switch every shared backend to `debug` for every user. A shared backend is one process with one
log level, so there is no per-caller level to set on it. The direct route `POST /mcp/{name}`
forwarded it to that one backend for any key scoped to it, which changes the level for every other
user of the backend.

The method now needs an admin key on both routes. Any other caller gets HTTP 403 with JSON-RPC error `-32600`,
the same shape as an admin-only tool refusal, and the refusal is written to the audit log. Nothing
is stored and nothing is forwarded. With auth disabled, every HTTP caller is
the same anonymous, non-admin client, so the method is refused to every HTTP caller. Stdio is
unchanged. On such a gateway, set levels at start instead: the gateway's own level with
`--log-level` or `MCP_GATEWAY_LOG_LEVEL` (see `docs/DEPLOYMENT.md`, environment variables), and a
stdio backend's level through that backend's own `env:` entry or arguments in `gateway.yaml`.

The 2026-07-28 protocol revision removed this method, so only older clients send it, usually right
after `initialize`. To receive fewer log messages, declare a level per request in `_meta`; the
gateway's own `notifications/message` already follow that level.

## 24. Backend edits notify only the callers of that backend

In 3.x, adding, removing or reviving a backend from the admin UI sent
`notifications/tools/list_changed` to every session on the legacy GET stream. The frame has no
content, but its timing told every caller that an operator had edited some backend, including
backends the caller could not use.

On an authenticated gateway the frame now reaches a session only if its API key may access the
edited backend: the same check that gates tool calls to it. A key whose `backends` list is `["*"]`
or empty is still told about every edit. After a removal, the callers whose key named the removed
backend are told, because the check reads the key, not the registry. The check runs at delivery
against the credential the session was opened with, so a revoked or expired key-server token is not
told. A session that presented no credential is told nothing. With authentication off, every
session is told, as before.

Nothing errors: a client that is no longer told keeps its cached tool list until it next calls
`tools/list`. Listeners on `subscriptions/listen` are scoped the same way; see item 26.

## 25. Admin-panel grant and policy edits are refused

In 3.x, `POST /ui/api/control-plane/grants`, `…/policies` and `…/decisions` wrote to the
control-plane store (`store/` under the directory from item 22) and answered 200. Dispatch never
read that store. A grant revoked there was still enforced and a grant added there was never
enforced; the same held for policies. The page then showed the store's rows, which could hide an
enforced grant, or show SSRF protection as off while it was on, and it called itself "Mutating".

Those three routes now check RBAC and then return **409** with `reason_code`
`grants_managed_in_identity_grants_file` or `policies_managed_in_gateway_config`. Nothing is
written, including the audit log. A caller without admin still gets 403. The page shows
"Read Only", lists `no_mutation_endpoint` in `current_limits`, reports `GovernanceMutation` as
unavailable, and adds `authority`, which names where each kind is enforced.

What is enforced has not changed. Grants come from the file at `security.identity_grants.path`,
edited with `mcp-gateway identity grants grant|revoke|list`. Policies come from
`security.sanitize_input` and `security.ssrf_protection`. The store still holds the governance
audit log, which the page and SIEM export read, so the note in item 22 about a persistent
`store_dir` now applies to the audit log only.

Existing rows in `store/grants.json` and `store/policies.json` are no longer shown. Leave them on
disk: 4.1 will bring them back as unenforced drafts that need re-approval. **Do not delete or
hand-edit them.**

## 26. `subscriptions/listen` needs a credential and is scoped to it

Authenticated gateways only; with authentication off nothing changes.

In 3.x every `subscriptions/listen` stream shared one channel with no caller identity: each
listener received every `notifications/tools/list_changed`, whatever backend had changed, and a
listener whose token was later revoked or expired kept receiving until it disconnected.

A listen request now needs a credential that authenticates. Without one it is refused with HTTP 401
and JSON-RPC error `-32001` before it takes one of the 256 listener slots. **This hits the default
install:** the starter config enables authentication and lists `/mcp` under `public_paths`, so an
anonymous listener there now gets 401 instead of a stream. Other methods on a public `/mcp` are
unchanged.

`notifications/tools/list_changed` reaches only listeners whose key may access the changed backend,
by the same rule as item 24. The credential is re-checked at each notification the listener would
receive; a listener whose credential was revoked or has expired is closed at that point instead.
Re-subscribe with a fresh credential. Task notifications keep their open-time ownership rule. A
revoked listener on a quiet gateway holds its slot until the next notification it would receive.

## 27. Exact agent grants name their proof source

In 3.x an identity grant bound to `agent: {exact: runner}` (written `agent: !exact runner` in
YAML) matched any caller whose proven agent id was `runner`. An mTLS subject and an agent-JWT
`sub` are separate namespaces, so a grant written for one also admitted the other.

A grants-file row with a bare `exact` id is now refused at load, and the error lists every such
row. Rewrite each one yourself; the gateway will not choose:

```yaml
agent: !exact {source: mtls, id: "spiffe://TRUST_DOMAIN/runner"}  # SAN URI, else the bare CN
agent: !exact {source: jwt, id: runner}                            # the agent's client_id
agent: any                                 # only if every agent of the subject is meant
```

In a JSON grants file the same row is `"agent": {"exact": {"source": "jwt", "id": "runner"}}`.

Until the file is fixed, personal capabilities fail closed: startup fails under
`fail_on_error: true`, and a hot reload keeps the previous grants. This applies whatever
`security.agent_identity.enabled` says.

`identity grants grant --agent` needs `mtls:<id>` or `jwt:<id>`; a bare id, `declared:<id>` and
a DN fragment such as `mtls:CN=runner` are refused.

`security.agent_identity.known_agents` rejects a bare string and names the sources it may use.
A `source: declared` entry refuses load when `agent_identity.enabled` is true and
`allow_unverified_agent_identity` is false; with agent identity disabled it loads with a warning.

## 28. A modern `tools/call` without an idempotency key is admitted, unprotected

The vendor `_meta` key `io.mcp-gateway/idempotency-key` makes a side-effecting
call at-most-once: a re-issue after a broken stream, under a new request id, is
recognised and answered from the first execution instead of running again.

Earlier 4.0 builds refused a modern-era `tools/call` (one whose `_meta` carries
`io.modelcontextprotocol/protocolVersion`) with `-32602` when it carried no key,
unless the tool was marked read-only. No standard MCP client sends that key, so
those calls now **succeed, unprotected**, by default. Legacy frames were always
admitted this way.

- At-most-once holds only for calls carrying a key or a task. A call carrying
  neither cannot be recognised as a re-issue; if a client re-sends it, it runs twice.
- `server.idempotency_key` takes `optional` (default) or `required`. `required`
  restores the `-32602` refusal, and the error names the key.
- `required` refuses exactly: a modern call carrying no key and no task, to a
  tool not marked read-only, on the meta route (`POST /mcp`) and stdio. Legacy
  frames, read-only tools, task calls and the backend route `POST /mcp/{name}`
  (which performs no sync admission) are admitted in both modes.
- "Read-only" means an exact `idempotency.read_only_tools` entry or a gateway
  discovery tool, never a backend's own `readOnlyHint`. The metric label
  `gateway_read_only` reports that decision.
- The era marker is chosen by the client, so `required` is a contract for
  cooperating clients, not a security boundary.
- `server` is restart-scoped: a change takes effect on restart.

**Migration.** Watch `mcp_unkeyed_calls_total` by `era` and `gateway_read_only`
(labels carry no identity). The counter sees the sync-admission routes only
(the meta route and stdio); un-keyed traffic on `POST /mcp/{name}` never appears
in it. Once modern clients send keys, set:

```yaml
server:
  idempotency_key: required
```

A warning names the backend and tool of a modern un-keyed call, at most once per
tool per 10 minutes. The gateway remembers at most 1024 (backend, tool) pairs
for this; when full it forgets expired pairs first, then the oldest, so a tool
it forgot can warn again inside the 10 minutes.

## 29. A config key the gateway does not read fails the load

In 3.x the config file could carry keys nothing read, and they were dropped in silence. A
misspelling therefore looked like a setting: `key_server: {enabeld: true}` loaded, and the key
server stayed off.

In 4.0.0 every key in the config file must be one the gateway reads. The load fails and one error
lists every offending key, sorted, as a dotted path from the top of the file, with list entries
as `[index]`:

```text
Configuration validation error: Unrecognised config key(s) in /etc/mcp-gateway/gateway.yaml:
auth.api_keys[0].bakends, backends.brave.timout, key_server.enabeld. 4.0 refuses keys it does
not read; fix the spelling or delete the key.
```

The error is printed on one line. Fix the spelling of each named key, or delete it. The same
check runs on `gateway_reload_config` and on file-watch reloads: a refused reload keeps the running
config and reports the error.

- **`backends.<name>.idle_timeout` is refused.** It was retired in 3.x and only warned. It never
  had an effect. The error names it and says why. Delete it, or use `stop_when_idle_for` on a
  backend declared with a `command`.
- **`backends.<name>.circuit_breaker` is refused.** `examples/circuit-breaker.yaml` showed it
  until 4.0, but nothing read it: every backend's breaker has always used
  `failsafe.circuit_breaker`. Delete the block; tune the global settings instead.
- **A backend that names two transports is refused.** `command` and `http_url` together loaded as
  a stdio backend and ignored `http_url`, `streamable_http` and any `a2a_*` key. The error names
  each ignored key and the key that selected the transport. Keep one transport per backend.
- **A key that belongs to a feature the binary was built without** (`cost_governance`, or a
  backend's `a2a_url` and `a2a_agent_card_path`) is named as such rather than as a misspelling.
  Release images carry both features.
- **Environment variables are not checked.** `MCP_GATEWAY_*` variables are read as config keys,
  and a misspelt one such as `MCP_GATEWAY_SERVER__PROT` is still ignored without a word. Only the
  file is checked, so deployments that set `MCP_GATEWAY_TOKEN`, `MCP_GATEWAY_LOG_LEVEL` or
  `MCP_GATEWAY_LOG_FORMAT` load as before.
- **YAML merge keys (`<<:`) were never applied**, and are now refused as a key named `<<`. Write
  the merged keys out in full.

No key in any gateway config under `examples/`, in the Helm chart's rendered config, in the
enterprise-alpha manifest or in the config `mcp-gateway init` writes is refused.

## 30. Attestation is off by default, and a bad mode fails startup

In 3.x an unset `GATEWAY_ATTESTATION_MODE` attached an observe-mode validator, and any value
the gateway did not recognise, `enforce` included, logged a warning and fell back to observe.
A deployment that set `enforce` ran unenforced and was told so only in a log line.

- **The default is off.** Unset, empty or `off` attaches no validator, so no
  `attestation_observe_reject` audit lines are written. Set `GATEWAY_ATTESTATION_MODE=observe`
  to keep them.
- **`enforce` enforces.** See item 46.
- **Any other value fails startup** with an error naming the value. The value is still trimmed and
  matched case-insensitively, so `Observe` and ` OFF ` keep working.
- **A 3.x `enforce` setting always behaved as observe.** To keep what it actually did, set
  `GATEWAY_ATTESTATION_MODE=observe`. Deleting the variable turns attestation off.

## 31. Tool calls with undeclared argument keys are refused

A `tools/call` whose arguments carry a key the tool's `inputSchema` does not declare, at the top
level or nested inside objects and arrays, now returns `isError: true` and never reaches the
backend. Before 4.0 such keys were forwarded to MCP backends unchecked.

- **MCP backends**, on `/mcp` (including `gateway_invoke`, stdio and code mode) and on the direct
  `/mcp/{name}` route, passthrough backends included. The schema is the one the caller's own
  `tools/list` returned; a tool the gateway has not yet listed for that caller is forwarded
  unchecked and counted as `input_schema_unknown`.
- **Capabilities** refuse nested undeclared keys too. A top-level `additionalProperties: true` is
  now honoured, which relaxes 3.x behaviour.
- An object schema that lists `properties` (at least one) or `patternProperties` without stating
  `additionalProperties` counts as closed. `{"type": "object"}` and `properties: {}` alone stay
  free maps.

For a backend whose tools rely on JSON Schema's open default, set
`input_schema_enforcement: standard` on that backend. To disable the check, set `off`. A boolean
value is a config error.

A `gateway_execute` chain now stops at the first step whose result carries `isError: true`,
backend tool errors included, and reports that step's index as a failed step. Before, the chain
ran the remaining steps. This matches the chain's documented contract, "stops at the first
error".

## 32. An API key or key-server rule with no `backends` reaches no backend

In 3.x an `auth.api_keys[]` entry without `backends` (or with `backends: []`) reached every
backend, including one added later. It now reaches none: `"*"` is the only wildcard. Add
`backends: ["*"]` for the old behaviour, or list the backends the key needs. The gateway starts
either way, prints this item in the one-time 4.0.0 notice, and logs one warning per key with no
backends, naming the key. An admin key that only manages the UI can ignore that warning.

The same applies to `key_server.policies[].scopes.backends`: a rule without it now grants no
backend, and the key server refuses to issue the token (403 `no_backends_granted`) instead of
issuing an all-backends one. A rule that matches no identity still answers 403 `access_denied`,
so the two are told apart. Each such rule is warned about at startup with its index and issuer.
A token request whose `backends:` scope names none of the rule's backends is also refused with
`no_backends_granted`. Tool lists are unchanged: an empty `tools` still means every tool on the
granted backends.

## 33. `/metrics` requires its own scrape token

In 3.x `/metrics` sat outside authentication and answered anyone who could reach the port,
and its labels name your backends. It now answers only `Authorization: Bearer <token>` where
the token is `server.metrics_token`, a literal or `env:VAR`, and returns 401 with
`WWW-Authenticate: Bearer` until it is set. Prefer the `env:VAR` form, so the token stays out of
the config file. The token is resolved at startup: setting or changing it takes effect after a
restart, not on a config reload.

- **A missing `env:` variable does not stop startup.** Unset, missing or empty all mean no
  token: the gateway starts, logs a WARN naming the field and the variable, and `/metrics`
  answers 401. This differs from `auth.bearer_token` on purpose: a scrape credential must not
  be able to take the gateway down.
- **The admin bearer is refused on purpose**, and the scrape token opens nothing but
  `/metrics`. Two credentials, two surfaces.
- **Give Prometheus the token through a dedicated scrape job** (`authorization:
  {type: Bearer, credentials_file: ...}`), or through the Helm chart's ServiceMonitor
  (`metrics.serviceMonitor.enabled`, which sends it with `bearerTokenSecret`). Do not add it to
  a generic annotation-driven `kubernetes-pods` job: that job would send the token to every
  annotated pod in the cluster.
- **Helm chart:** set `metrics.existingSecret` (and `metrics.secretKey`, default `token`) to
  the Secret holding the token. The chart then renders `server.metrics_token`, the
  `MCP_GATEWAY_METRICS_TOKEN` env reference and the `prometheus.io/*` annotations. Without it
  the chart no longer renders those annotations, so a stock install is not scraped to `up=0`.
- **enterprise-alpha:** the manifests drop the `prometheus.io/*` annotations and read the token
  from the optional Secret `mcp-gateway-metrics` (key `token`).

## 34. The inbound WebSocket listener is removed, and `server.ws_port` fails the load

In 3.x, `server.ws_port` spawned a WebSocket listener beside the HTTP server. It only echoed
text frames back: it never served MCP, sat outside the Origin/Host guard and had no
authentication, so no client could reach a tool through it.

- **The listener is gone.** Clients connect via stdio or HTTP (`POST /mcp`).
- **`server.ws_port` in the config file is a retired key and refuses the load**, on start and on
  reload, with `server.ws_port` is retired: the inbound WebSocket listener was removed in 4.0;
  ... Remove server.ws_port. Delete the key. Like every `MCP_GATEWAY_*` variable,
  `MCP_GATEWAY_SERVER__WS_PORT` is not checked; it is now ignored, so remove it too.
- **WebSocket is not a backend transport either.** No backend config reaches the WebSocket client
  in `src/transport/websocket.rs`; backends use stdio, HTTP (Streamable HTTP or SSE) or A2A.

## 35. A config or env file other users can read fails the load

In 3.x a config file readable by other local accounts drew one WARN in the HTTP startup banner,
stdio never checked it, and env files were never checked at all. Both can hold credentials.
On Unix the gateway now checks the config file, and every `env_files` entry, before reading it.
The check follows symlinks, so a Kubernetes `..data` link is judged by the file it points to.

| Mode bits | File owned by the gateway's user | File owned by another user |
|---|---|---|
| any world bit (`o+r`, `o+w`, `o+x`) | refused | refused |
| group write | refused | refused |
| group read | refused | allowed |
| owner only (`0600`, `0400`) | allowed | allowed |

Group read is allowed only on a file the gateway does not own, because there the group is how it
reads the file. That is the case for a root-owned Kubernetes projection with `fsGroup`.

- **A refused config file fails every command that loads it**, `doctor` and `config export`
  included. The error names the path, the mode and the fix: `chmod 600 <path>`.
- **A refused env file fails `serve`, stdio and reload.** `doctor`, `config export` and the other
  commands that do not serve print a warning and skip the file.
- **Helm:** the chart now sets `podSecurityContext.fsGroup: 1001` and
  `configVolume.defaultMode: 288` (octal `0440`), so the projected config is `root:1001 0440`.
  Without them the projection is `root:root 0644` and is refused. `fsGroup` renders only as 1001,
  the image's group: any other value, root included, fails `helm template` (item 36), so a mesh
  that injects its own group is not supported. Keep `defaultMode` at `288`: the gateway reads
  the root-owned file through group read, and a world bit is refused.
- **enterprise-alpha:** `base/deployment.yaml` carries the same `fsGroup` and `defaultMode`.
- **Docker Compose:** the bind-mounted `gateway.yaml` keeps its host mode and owner, and the
  container runs as UID 1001. `chmod 600` it and `chown 1001` it; that passes whoever your host
  user is. `chmod 640` with group 1001 passes only while the file's owner is not UID 1001, because
  group read on a file the gateway owns is refused.
- **The fix the error names depends on ownership.** On a file the gateway owns it is
  `chmod 600`. On a file another user owns, `chmod 600` would lock the gateway out, so it names
  the group route instead: Helm `podSecurityContext.fsGroup` and `configVolume.defaultMode`.
- **The check and the read use one handle.** The mode is taken with `fstat` on the open file the
  gateway then reads, so a file swapped or loosened in between is not loaded.
- **Windows is not checked.** It has no mode bits, and ACL inspection is out of scope.
- **`mcp-gateway init` already writes `0600`**, so a config it created passes unchanged. One
  written by an older release, or copied into place, may need the `chmod`.

Parent directory permissions, and the `capabilities/` files, are not checked.

## 36. The Helm chart pins its pod identity and caps its `state` volume

- **`podSecurityContext.runAsUser`, `runAsGroup` and `fsGroup` accept only 1001**, the image's
  UID/GID. The values schema refuses any other value, root included, so `helm lint` and
  `helm template` fail; a template guard refuses it again when schema validation is skipped.
  Item 35's config read relies on that `fsGroup`. **Remove any `fsGroup` or `runAsUser`
  override** you set for item 35 or an earlier chart; a mesh that injects its own group is not
  supported.
- **The `state` emptyDir under HOME has a `sizeLimit` of `1Gi`.** A pod whose task store and
  npm/uv caches outgrow it is evicted and restarts empty. Raise it with
  `--set stateVolume.sizeLimit=4Gi`; the value is required. enterprise-alpha's
  `base/deployment.yaml` carries the same `1Gi`.
- **enterprise-alpha stops mounting a service account token.** The gateway never calls the
  Kubernetes API; run `mcp-gateway kubernetes` from a place that has kubectl credentials.

## 37. More than one replica is refused while per-process state is on

Key-server tokens, managed accounts custody and task records each live in one process. Behind
a Service with no session affinity, a token minted on one pod is a 401 on another, a revoke
reaches one pod, and a task created on one pod is not found on another.

- **New `server.replicas`, default 1, is declared, not observed.** Above 1, startup refuses
  with a reason per feature: `key_server.enabled` (the `InMemoryTokenStore`), enabled
  `accounts` (`single_process` custody), and `server.modern_protocol`, on by default, which
  serves the tasks extension. Set `replicas: 1`, or turn the modern protocol off with the
  key server and accounts off.
- **Helm chart:** `replicaCount` now defaults to 1 (it was 2). The chart writes
  `server.replicas` from it, fails the render on the same rules, and fails when a
  `config.server.replicas` you set disagrees. A `helm upgrade` that carried `replicaCount: 2`
  now fails until you pick one of the remedies above.
- **Without the chart, set `server.replicas` to the number of processes you run.** The
  default of 1 is a declaration made on your behalf, not a detection: a hand-written
  multi-replica deployment that leaves it at 1 is never refused.
- **Recreate:** while any of the three is on, the modern protocol included (so a default
  install), the chart renders `strategy: Recreate`, and so does the enterprise-alpha
  manifest. An upgrade has a short outage. With all three off the chart keeps
  `RollingUpdate`.
- **enterprise-alpha:** `base/deployment.yaml` runs one replica and `base/configmap.yaml`
  declares `server.replicas: 1`. Change both together.
- **`kubectl scale` and an HPA bypass this check**, because they change the pod count without
  the declaration. Don't scale that way. See `docs/DEPLOYMENT.md`, "Replica Count and
  per-process state".

## 38. A credential over plain HTTP on a network bind refuses the start

In 3.x a gateway with `auth.enabled` bound to `0.0.0.0` served bearer tokens and API keys over
plain HTTP without a word. It now refuses to serve when all of these hold:

- the listener is reachable from the network: a non-loopback bind, or a `server.public_url`
  whose host is not loopback;
- it accepts a credential over HTTP: `auth.enabled`, `agent_auth.enabled` or
  `key_server.enabled` (the key server takes OIDC ID tokens on this listener);
- `mtls.enabled` is off, so the listener is not TLS;
- `server.cleartext_http` is `refuse`, the default.

The error names the exposure and both fixes. Loopback binds with no declared `public_url` are
unaffected, and so is a gateway with no credential (the open-tools refusal covers that one).
`server.allow_unauthenticated_network_bind` does not answer it: that says authentication happens
in front of the gateway, not encryption. The check runs when `serve` starts, because `--host` is
applied after the config loads, and on every reload: a reload that adds a non-loopback
`public_url`, or removes the Service-name one `cluster_internal` needs, is refused the same way.

`server.cleartext_http` names who protects the traffic instead. Every value but `refuse` is logged
at WARN on every start.

- **`tls_terminated_upstream`**: a reverse proxy, ingress or tunnel terminates TLS in front of
  the gateway. Honest only if nothing reaches the plain-HTTP port except that proxy.
- **`cluster_internal`**: callers reach the pod only over the cluster network, by its Service
  name. Accepted only when `server.public_url`'s host is `<svc>.<ns>.svc` or
  `<svc>.<ns>.svc.<cluster domain>`, whole labels, where the cluster domain is
  `server.cluster_domain` (default `cluster.local`). An ingress hostname is refused and pointed
  at `tls_terminated_upstream`.
- **`host_local_publish`**: a container binds `0.0.0.0` and the host publishes the port on
  loopback only, as `deploy/single-node/docker-compose.yaml` does. Honest only while every
  publish is `127.0.0.1:`.

The shipped deployments keep starting (item 21):

- **Helm chart:** credential mode renders `server.cleartext_http` from the new value
  `server.cleartextHttp`, default `cluster_internal`, and then always renders an ingress-only
  NetworkPolicy (egress is restricted only with `networkPolicy.enabled: true`, so backends on any
  port stay reachable). The chart fails to render when `cluster_internal` meets a `service.type`
  other than `ClusterIP` or a `config.server.public_url` other than this release's own Service
  name (`<fullname>.<namespace>.svc[.<cluster_domain>]`); set
  `server.cleartextHttp=tls_terminated_upstream` when an ingress terminates TLS in front of the
  pod. Mesh mode accepts no credential and renders no value.
- **enterprise-alpha:** `base/configmap.yaml` sets `cleartext_http: cluster_internal` beside its
  `public_url`. Change both together if an ingress fronts the pod.
- **compose:** sets `MCP_GATEWAY_SERVER__CLEARTEXT_HTTP: host_local_publish` beside its loopback
  publish.

## 39. `server.request_timeout` fails the load, and `server.max_body_size` is enforced

In 3.x neither key did anything. No server-wide timeout existed: each call is bounded by its
backend's `timeout`. `/mcp` and `/mcp/{name}` capped bodies at a hard-coded 10 MiB, and every
other route, webhooks included, used the framework's 2 MiB default.

- **`server.request_timeout` is removed and now stops startup; delete it.** It never did
  anything. Set per-backend `timeout` to bound calls. The load fails, on start and on reload,
  and the error includes:

  ```text
  `server.request_timeout` is retired: the server-wide request timeout was removed in 4.0; it was never enforced. Calls are bounded by the per-backend `timeout`. Remove server.request_timeout.
  ```
- **`server.max_body_size` is now enforced on every route**, read once at startup
  (default 10 MiB). `0` would refuse every body, so it now fails the load; set a positive byte
  count.
- **An oversize body on `/mcp` and `/mcp/{name}` now gets HTTP 413 with JSON-RPC -32600**
  ("Request body exceeds server.max_body_size"), where it used to get 400 with JSON-RPC -32700.
  Clients that matched on -32700 must also handle 413 / -32600.
- **Routes that parsed with a framework extractor (webhooks, key server, admin UI) now accept up
  to the 10 MiB default**, up from 2 MiB. Lower `server.max_body_size` if you relied on that.

## 40. A secret reference that resolves to nothing fails the load

In 3.x an unset or empty secret became an empty credential without a word. `${GITHUB_TOKEN}`
with `GITHUB_TOKEN` unset expanded to `""`, so the backend was sent `Authorization: Bearer `.
An `env:` reference to a variable that was set but empty passed validation, and so did a literal
`bearer_token: ""`. A `{env.X}` template in a capability, webhook or injected credential sent
`""` when `X` was unset. Each of these now fails instead.

- **`${VAR}` with no default must be set and non-empty** in the `headers` and `env` of every
  enabled backend and in `capabilities.directories`. The error names the field and the variable:
  `backends.github.headers.Authorization references ${GITHUB_TOKEN}, which is not set (or is
  empty) and has no default. Set it, or write ${GITHUB_TOKEN:-} to allow empty.` One load reports
  every such reference, together with every `env:` secret below that does not resolve. A `${`
  that is not a `${NAME}` reference (names are uppercase, as in `${github_token}` written
  lowercase) is refused too, instead of being sent verbatim. As in a POSIX shell, `${VAR:-text}` falls back to
  `text` when `VAR` is unset **or empty** (3.x used the default only when unset), and `${VAR:-}`
  is the way to say empty is intended.
- **A disabled backend is not expanded.** Its `${VAR}` text stays as written, so a variable only
  a disabled backend needs does not stop startup. Enabling it from the admin panel writes the
  file and reloads; while the variable is unset that reload fails, names the variable, and the
  running config is kept. The file already says `enabled: true`, so set the variable (or disable
  the backend again) before the next restart, which would otherwise refuse to start.
- **An empty secret is refused like a missing one.** `auth.bearer_token`, `auth.api_keys[].key`,
  `agent_auth.agents[].hs256_secret` and `key_server.admin_token` written as `env:NAME` fail when
  `NAME` is unset or empty: `auth.api_keys['ci'].key references environment variable 'CI_KEY',
  which is empty; empty secrets are refused.` An empty literal in any of these four fails too
  (`auth.bearer_token is empty.`), including when the config is built in code rather than
  loaded, and the key server never accepts an empty admin bearer.
- **`{env.X}` templates fail at call time.** Capability, webhook and injection templates resolve
  when they are used, not at load, so the tool call or webhook delivery errors
  (`{env.X} is not set or is empty`) instead of sending an empty credential. Write `{env.X:-}`
  where empty is intended. A credential injection rule whose `{env.X}` is unset used to be
  skipped; the call now fails. A capability `auth.key` (`env:X`, `{env.X}` or a bare `X`) whose
  variable is set but empty fails the call too.
- **A listed env file that does not exist is still allowed**, but every unresolved-reference error
  now ends with `(env files listed but not found: <paths>)`, so a mistyped `env_files` path shows
  up next to the variable it failed to supply.

`server.metrics_token` is unchanged: an unset or empty variable (or an unreadable `file:`, item 44) there still leaves the gateway
running with `/metrics` closed (item 33). No error prints a secret value.

## 41. API keys are configured as sha256 digests, with optional expiry

In 3.x `auth.api_keys[].key` held the key itself, or `env:VAR` whose value was the key. Anyone
who could read the config, the environment or a debug log could replay it. The gateway only
ever needs the key's hash, so 4.0 stores the digest instead.

- **A plaintext `key` fails the load.** The error names the key and says to run
  `mcp-gateway hash-key`. It says the same for `key: env:VAR`, and the variable is not read.
  Setting both `key` and `key_sha256`, or neither, also fails the load. The file is not
  rewritten for you: a rewrite would drop comments, and an `env:` key lives outside the file.
- **Migrate each key.** Run `printf %s "$KEY" | mcp-gateway hash-key` and put the output in
  `key_sha256`:

  ```yaml
  auth:
    api_keys:
      - name: laptop
        key_sha256: "sha256:<64 lowercase hex>"
  ```

  The key is read from stdin, never an argument, so it stays out of shell history. One trailing
  newline is stripped, so `echo "$KEY" |` gives the same digest. Check a digest with
  `printf %s "$KEY" | mcp-gateway hash-key --verify sha256:<hex>` (exit 0 match, 1 mismatch,
  2 malformed).
- **For `env:` keys, store the digest in the variable or secret instead of the key.** A
  variable that still holds the key fails the load, and the error names the variable, never
  its value. Nothing is silently hashed.
- **Clients keep the same key.** Only the config changes. `principal` values, session owners
  and log lines are unchanged: the principal is the first 12 hex characters of the digest,
  which is what 3.x derived from the key.
- **Optional `expires_at`** (RFC 3339, for example `"2027-01-01T00:00:00Z"`). After it, a
  matching key is refused with 401 and a `warn` naming the key. An expired key does not stop
  the gateway from starting; it logs a `warn` at startup instead. Omitting `expires_at` keeps
  the 3.x behaviour. Removing or renewing a key still needs a config edit and a restart.
- `auth.bearer_token` and `key_server.admin_token` are unchanged and still plaintext.
- **Library API:** `ApiKeyConfig::key` is now `Option<String>` and is refused at load;
  `ApiKeyConfig::resolve_key()` is replaced by `resolve_digest()`, which returns the 32 digest
  bytes. `ResolvedApiKey::key` is replaced by `digest` and `expires_at`. The new
  `mcp_gateway::config::api_key_digest_spec(&[u8])` returns the `sha256:<hex>` form.

## 42. `webhooks.rate_limit` is enforced

Before 4.0 the key was parsed and ignored. Each webhook endpoint now accepts at most
`rate_limit` requests per minute (burst up to the same number) and answers `429` with
`Retry-After: 60` beyond that. Only requests that pass the signature check count, so unsigned
traffic cannot use up a real sender's budget. The default is 100. `0` means no limit.

A sender that bursts above the limit loses events: most providers, GitHub included, do not
retry a `429`. Set `webhooks.rate_limit` above your busiest sender's peak, or `0`. The value is
read at startup; a reload that changes `webhooks` needs a restart.

## 43. With auth on, the audit log is required and fails closed

An authenticated gateway used to run with no tool-call audit, and when the log did run it
named an API-key label rather than a person and skipped every refused or failed call.

- **An auth-enabled config without `security.transparency_log.enabled: true` fails to
  load**, with "auth is enabled, so security.transparency_log must be enabled with a
  writable path". There is no opt-out. `serve --stdio` obeys the same rule. With auth off
  nothing changes.
- **An audit log that cannot open stops startup** when auth is on. It used to warn and
  serve without one.
- **Kubernetes needs a writable volume at the log path.** The Helm chart does this for you in
  credential mode: the log goes to `/var/lib/mcp-gateway/audit/transparency.jsonl` on an
  `audit` volume. That volume is an `emptyDir` (`audit.sizeLimit`, default `1Gi`) and **dies
  with the pod**. Set `audit.existingClaim` to a PersistentVolumeClaim to keep it, or ship
  the log out with `control_plane.export`. `podSecurityContext.fsGroup` (default 1001) makes
  the claim writable. Each replica writes its own chain. Mesh mode renders none of this. The
  enterprise-alpha manifests carry the same volume and config.
- **A failed append now refuses calls** when auth is on. The call whose record failed gets
  HTTP 503, JSON-RPC `-32005`, "audit log unavailable; the call may have run but its result
  is withheld". Do not blindly retry it. Later calls, and the direct route `/mcp/{name}`,
  are refused before dispatch, and `/readyz` returns 503, until one probe append succeeds.
  `/readyz` itself tries that probe, so a drained pod recovers without traffic; `/livez`
  stays 200, so the pod is not restarted. Watch `mcp_audit_append_failures_total` and
  `mcp_audit_degraded`. Probe records carry `type: "audit_probe"`.
- **The log is not rotated yet, and a full volume stops the gateway.** Rotation is a separate
  item due before 4.0.0 final. Until then, when the log's volume fills every append fails
  with `storage_full`: tool calls get 503 and `/readyz` returns 503 (its body names the
  cause), and the counter reads `mcp_audit_append_failures_total{cause="storage_full"}`.
  Size the volume for your traffic: a tool call writes one or two records of roughly 1 KiB,
  so the chart's default 1Gi holds on the order of half a million calls. Archive or export
  the file before it fills; the gateway recovers on its own once an append succeeds. The
  chart always writes the log to the `audit` volume, whatever
  `config.security.transparency_log.path` says, and prints a warning at install while
  `audit.existingClaim` is unset.
- **Every record carries `schema_version: 2`**, plus `trace_id`, `outcome`
  (`ok`, `tool_error`, `denied`, `invalid`, `error`), `error_code` for the last three, and
  `who`: `credential_kind`, `principal` (12 hex characters of the credential's sha256),
  `account`, and for a verified caller `authority` and `subject`, the `(issuer, sub)`.
  An email or a display label is never written. `caller` stays for one major version as a
  copy of `who.account`. Entries without `schema_version` are v1; both verify in one file.
- **Refused and failed tool calls now write a record**, and so do cache hits. Expect more
  log volume on a gateway that refuses a lot.
- **The direct route `POST /mcp/{name}` writes the same invocation record** for every
  `tools/call`, refused ones included. It used to write none. Each invocation record now
  carries `route`: `meta` for `gateway_invoke`, `direct` for this route. On a direct
  record `server` is `{name}`, `request_hash` covers the `params` the caller sent,
  `response_hash` covers the JSON-RPC body it received, and the correlation key is the
  caller's W3C trace id, else the trace id. A tools/call too malformed to name a tool is
  recorded as `invalid` without `tool`. Other methods on this route (`tools/list`, `resources/read`,
  `prompts/get`) and the agent-identity refusal are not recorded, as on the meta route.
- **A direct-route `tools/call` with no `params`, no `name`, or an empty `name` is now
  refused** with HTTP 400 and JSON-RPC -32602 ("tools/call requires params.name"). It used
  to be forwarded to the backend without the per-tool authorization check, because there
  was no tool name to check.
- **On the direct route, a key scoped away from a backend is now refused after the body is
  read.** It still gets 403 and -32003 for a backend it may not use, including one that
  does not exist. A body that is not JSON, or a JSON-RPC envelope that does not parse, now
  gets its 400 first.
- **`request_hash` covers the whole `gateway_invoke` params the caller sent**, `_full` and
  `_claim` included, and **`response_hash` covers the value `gateway_invoke` returned**,
  after trace, prediction and provenance augmentation. The message-signing `_signature` is
  added later, at delivery, so it is not under the hash. Both used to cover an intermediate
  value, so
  hashes from 3.x records do not compare with 4.0 ones. A failed call has no
  `response_hash`.
- **`mcp-gateway init` writes `security.transparency_log.enabled: true`** under the default
  path `~/.mcp-gateway/transparency/transparency.jsonl`.

## 44. Secrets can be read from files with `file:`, and a literal starting `file:` is now a reference

Wherever a whole-value secret takes `env:NAME`, it now also takes `file:/absolute/path`:
`auth.bearer_token`, `auth.api_keys[].key_sha256` (the file holds the digest), `agent_auth.agents[].hs256_secret`,
`key_server.admin_token`, `security.message_signing.shared_secret` and `previous_secret`,
`server.metrics_token`, `accounts.keys`, `accounts.adapters[].hmac_secret_ref` and
`accounts.descriptors[].client_secret_ref`. The secret is the file's content. A descriptor's
`client_secret_ref` is read each time the client secret is used, as its `env:` form is; every other
field is read once, at startup.

- **The path must be absolute.** `~`, relative paths and `${VAR}` inside the path are not expanded;
  `file:secrets/token` fails with `... is not an absolute path.`
- **The file is held to the item 35 rule**: a file other users can read or change fails the load,
  and so does a group-readable file this process owns. It must be UTF-8 and at most 64 KiB.
- **Exactly one trailing newline is stripped** (`\n` or `\r\n`), as `kubectl create secret
  --from-file` and `echo` add one. Anything beyond that one is part of the secret. A file that is
  empty after the strip fails, as an empty `env:` value does (item 40).
- **Breaking:** a literal secret that happens to start with `file:` is now read as a reference.
  There is no escape syntax; change the secret.
- **Rotation needs a restart** (except `client_secret_ref`, which picks up the new file on its next
  use). A reload whose `file:` secret has new content reports
  `restart required for: file:/path` (the path, never the value) and keeps the running secret.
- **Aliasing:** an adapter `hmac_secret_ref` and a gateway credential that name the same file (after
  symlinks resolve), or two files with the same content, are refused, as two `env:` references to
  one variable are.

Capability YAMLs are unchanged: their `file:/path.json:field` form keeps its own meaning, and a
capability cannot use `file:` to read a whole file as a secret.

On Kubernetes, mount the Secret as a volume and point the field at the key's file:

```yaml
# pod spec
securityContext:
  fsGroup: 1001            # a group the gateway process is in
volumes:
  - name: gateway-secrets
    secret:
      secretName: gateway-secrets
      defaultMode: 0440    # 288 in JSON; group read is how a non-owner reads it
# container
volumeMounts:
  - name: gateway-secrets
    mountPath: /run/secrets/gateway
    readOnly: true
```

```yaml
# gateway.yaml
auth:
  bearer_token: file:/run/secrets/gateway/bearer-token
```

The Helm chart does not yet mount extra Secret volumes for you.

## 45. `/health` reports an open circuit breaker

In 3.x an open breaker never showed anywhere. The breaker reported its state as `"open"`, and
`/health`, the admin panel and the redacted `/ui/api/status` compared it against `"Open"`, so
the comparison never matched. `/health` went to 503 only when the health tracker also failed.

- **`/health` now returns 503 with `status: "degraded"` while any backend's circuit breaker is
  open.** External monitors that read `/health` will see it. `/livez` and `/readyz` do not read
  backend state and still answer 200, so Kubernetes probes are unaffected: one open breaker does
  not restart or unready a pod.
- **The admin panel shows that backend as `Down` and `Blocked`**, and the redacted
  `/ui/api/status` counts it in `degraded_count`.
- A half-open breaker, which is letting trial requests through, still counts as healthy.
- The `circuit_state` field in the admin `/health` body keeps its values (`closed`, `open`,
  `half_open`).

## 46. Attestation `enforce` enforces on every route

In 3.x `enforce` ran as observe (item 30). In 4.0.0 `GATEWAY_ATTESTATION_MODE=enforce` refuses,
with JSON-RPC -32002, every call whose token is missing, forged, expired or not scoped to the
tool.

- **It needs `GATEWAY_ATTESTATION_SIGNING_KEY`.** Enforce with an unset, empty or
  whitespace-only key fails startup: without a key every call would be refused.
- **Where the token goes.** In the `attestation` argument on `gateway_invoke`, including
  signed calls. In `params._meta["io.mcp-gateway/attestation"]` on the direct
  `/mcp/{backend}` route and on surfaced tools called by name. The gateway strips the
  `_meta` key before forwarding on the direct route, for every method and for passthrough
  backends too, so no backend receives the token.
- **The error names the boundary**: `Attestation rejected at gateway_invoke` on the meta
  route, `at direct_route` on `/mcp/{backend}`. The direct route checks the token before
  the idempotency guard, so a replayed call needs a valid token as well.
- **Tasks.** A task-mode `gateway_invoke` re-checks its original token when the worker
  dispatches it, so a queued task needs a token that outlives the queue. A surfaced tool run
  as a task has no token at dispatch and is refused. Task recovery reads need a fresh token in
  `_meta["io.mcp-gateway/recovery"].attestation`.
- **Playbooks and code mode are refused.** Under enforce, `gateway_run_playbook` and
  `gateway_execute` answer -32002 "multi-step plans carry no attestation in 4.0.0", keyed
  or not. Their steps are synthesized and carry no token. Call each tool with its own token.
- **Only `tools/call` is checked on the direct route.** `resources/read`, `prompts/get` and
  other methods are forwarded without an attestation check.

## 51. SSO admin rules now grant full gateway admin

A `control_plane.role_mapping` rule with `role: admin` used to make its identity
an admin of the control plane only. Everything else (the admin meta-tools and the
`/ui/api/*` admin routes) read a flag that no SSO identity could set, so an SSO
user could not be a gateway admin at all.

- **A `role: admin` rule now grants gateway admin on every surface**: kill,
  revive, reload, stats and webhook status, backend and capability editing,
  import, and the control plane. **Review your existing `role: admin` rules
  before upgrading**: a rule written for the control plane now also grants kill,
  reload and backend editing. Each one logs a warning at load that says so.
- **A `role: admin` rule whose only condition is `domain` fails to load.** Name the
  identity provider's admin group (`group`) or, for a small team, exact `email`
  addresses. A `domain` rule for any other role still loads.
- Admin is decided per request from the live mapping, so a reload that removes the
  rule revokes admin on the next request, including for tokens issued before it.
- Header identities (`trusted_proxy`, `cloudflare_access`) and mTLS certificates
  never confer admin. The static bearer and `api_keys[].admin: true` are
  unchanged.

To make SSO users admins, add:

```yaml
control_plane:
  role_mapping:
    rules:
      - { issuer: <your-idp-issuer>, group: <your-admin-group>, role: admin }
```

## 52. The gateway advertises only the change notifications it delivers

3.x advertised `resources.subscribe`, `resources.listChanged` and `prompts.listChanged` as
`true`, but never sent `notifications/resources/updated`, `resources/list_changed` or
`prompts/list_changed`. A client that subscribed waited forever and got no error. Now:

- `initialize` and `server/discover` report all three as `false`, on both protocol eras.
- `tools.listChanged` stays `true` over HTTP. Every change to the tool set now sends
  `notifications/tools/list_changed` once to the GET stream and to `subscriptions/listen`:
  a backend added, modified or removed (config reload or the admin UI), a capability file
  reloaded, a backend revived. Before, only the admin UI did.
- On the 2025 GET stream it now arrives as a standard `event: message` carrying the bare
  JSON-RPC notification. 3.x wrapped it in a gateway envelope (`event: notification`,
  `{"source","event_type","data"}`) that MCP clients do not read; a client parsing that
  envelope reads `method` at the top level instead.
- `serve --stdio` reports `tools.listChanged: false`, because it has no channel for an
  unsolicited notification.
- **`resources/subscribe` and `resources/unsubscribe` are refused** with `-32601`, "this
  gateway does not deliver resources/updated", instead of being forwarded to the backend.
  To see changes, poll `resources/list` or `resources/read`.

Not covered: a backend's own `notifications/tools/list_changed` is still not relayed (the
gateway's listing refreshes from its metadata cache), and on the direct route `/mcp/{name}`
`resources/subscribe` still reaches the backend, whose `resources/updated` the gateway does
not relay. Poll there too.

The legacy `initialize` result differs from 3.5.0 in exactly those three flags (and, over
stdio, `tools.listChanged`).

## 53. A gateway rate-limit refusal is no longer reported as an open circuit breaker

When a backend's own `failsafe.rate_limit` ran out of tokens, the gateway refused the
call with "Circuit breaker open for backend 'x'", although the breaker was closed, and
counted each refusal as a backend failure in the error budgets. One caller's burst past
the limit could therefore auto-disable a capability, or kill the backend, for every
caller.

- **The refusal now reads `Rate limit exceeded for backend 'x'`.** The JSON-RPC code is
  still `-32000`. The recovery hint is `RATE_LIMITED` (back off and retry), not
  `CIRCUIT_OPEN`. Clients or alerts that matched "Circuit breaker open" to detect
  throttling must match the new text.
- **Rate-limit refusals are not sampled by the error budgets**, so they can no longer
  disable a capability or kill a backend.
- **`mcp_backend_circuit_state` follows the breaker only.** A rate-limit refusal no
  longer drops it to 0.
- A breaker that is really open is unchanged: same message, and it still counts as a
  failure.

## 61. A backend that refuses a managed account's token forces one refresh, then a reconnect

In 3.x and in the 4.0 betas, a managed personal account (`accounts.descriptors`,
`mode: personal_managed`) was refreshed only when its token expired. If the provider revoked
the grant earlier, every call returned a generic backend error that said "retry", with the
same dead token each time, for up to the token's lifetime, which is often an hour.

- **The first HTTP 401 from the backend forces one refresh of that account's token.** If the
  provider answers `invalid_grant`, the account is marked reconnect-required and the call is
  refused with the reconnect offer (JSON-RPC -32001 on `gateway_invoke`, HTTP 403 and -32003
  on `/mcp/{backend}`), exactly as an expired grant is today.
- **Otherwise the caller is told whether a retry can help.** The tool result's `recovery`
  (or, on `/mcp/{backend}`, the error's `data`) carries `error_code: UPSTREAM_AUTH_REJECTED`
  with `retry: true` when the token rotated or the provider was unreachable, and
  `UPSTREAM_AUTH_REJECTED_PERSISTENT` with `retry: false` when this token was already
  force-refreshed and the backend still refuses it. That is a scope or permission problem,
  not a dead token. The gateway retries nothing automatically.
- **At most one forced refresh per token revision, across restarts.** The revision is
  recorded in the account store before the provider is asked, whatever it answers. A
  backend that refuses every token costs one provider round trip per token revision.
- **Only the status decides.** A 200 result whose text says "401" is passed through as it is
  today.
- **A 401 or 403 from any HTTP backend is no longer retried.** Retrying repeats the refusal
  with the same credential. A 429, a 5xx, a 400 and a 404 are retried as before. A 404 and a
  400 still re-initialize an expired MCP session. Chain steps follow the same rule.
- **Every route:** `gateway_invoke`, a capability (REST) call, `/mcp/{backend}`, and the
  re-dispatch of an elicitation the gateway bridges for a legacy client.
- **The audit log's `error_code` changes for a backend 401 on a capability (REST) call:**
  `-32000` instead of `-32600`. The capability executor now reports a 401 as the backend's
  refusal, not as an invalid request. A 401 that ends in the reconnect refusal is recorded as
  that refusal: `outcome: denied` with `-32001` when the reconnect offer is attached. A 401 or
  403 from an MCP backend over HTTP keeps `-32000`.
- **Not covered:** backend-level OAuth (`backends.<name>.oauth`), which is planned for 4.1,
  and external (token-exchange) descriptors, which hold no refreshable grant.

**Rolling back to an earlier 4.0 beta is not supported once a forced refresh has happened.**
The account store's authority file then records `forced_revision` for that account. An
earlier 4.0 binary refuses an authority file with a field it does not know, so its account
custody does not start, and with it the gateway. The file is sealed, so the field cannot be
removed by hand. It is removed for an account when that account's token next rotates or the
user reconnects. Rolling back to 3.x is unaffected: 3.x does not read the account store.

## After upgrading

- Confirm the version stamp advanced: the notice prints once and not again.
- Re-authorize OAuth backends at a time you choose rather than on a user's first call.
- If startup is refused, read the error — item 2 is the one that refuses rather than warns.

## Other behaviour changes

These need no action and have no startup notice.

- **Cost budgets survive a restart.** Today's cost-governance spend is reloaded from
  `costs.json` at startup, so a restart no longer resets the daily budgets. A budget that
  has blocked stays blocked until UTC midnight. Each process keeps its own `costs.json`.
- **Default capability directories are `capabilities` only.** A 3.x gateway also loaded
  a private capability checkout under `$HOME/github` if it existed. If you relied on that,
  add the directory to `capabilities.directories`.
- **Paginated backends show their whole tool catalogue.** The metadata cache now follows
  `nextCursor`, so tools past a backend's first `tools/list` page appear in search, listing
  and counts. One refresh of a paginated backend costs up to 32 list requests or 120 s. A
  drain that stops early keeps what was read, reports its tool count as "at least", and
  increments `mcp_backend_list_truncated_total{backend,reason}`, where `reason` is
  `page_cap` (32 pages), `cursor_repeat` (the backend repeated a `nextCursor`) or
  `fill_budget` (120 s spent).

## Rolling back

Keep the 3.x `gateway.yaml` you had before migrating API keys (item 41): 3.x reads `key` and
cannot read `key_sha256`, so a rollback puts that copy back. Beyond that, downgrading loads the
same file, because 4.0.0 itself never edited it. The upgrade
leaves the 3.x token files in place — its migration prints the notice and stamps the version,
and touches no credential (`src/commands/upgrade.rs:264`). A rollback therefore picks those
files back up rather than prompting again, unless the tokens expired in the meantime. What 4.0.0
wrote under the per-issuer key is simply not read by 3.x.

Within 4.0, a rollback to an earlier beta is unsupported once a managed account has had a
forced refresh (item 61): that beta cannot open the account store and refuses to start.
