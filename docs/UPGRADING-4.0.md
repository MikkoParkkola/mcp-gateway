# Upgrading to 4.0.0

From any 3.x release. No migration edits your `gateway.yaml`, and the gateway makes no automatic
change to your configuration on upgrade. It loads unchanged unless items 8, 12 or 28 refuse it.

On the first `serve` after the upgrade, the gateway prints a one-time notice to stderr listing
items 1-4, 6, 11 and 23-26 below, then stamps the new version. The notice is printed rather than logged, so
`--log-level error` and `RUST_LOG` filters cannot swallow it.

The rest of the list has no startup notice, for two different reasons. Items 5 and 9 are
changes to the license and to a removed CLI surface rather than to running behaviour. Items
7 and 8 are decided per backend, so there is no single moment at startup at which
the binary could know whether a given deployment is affected. Item 10 changes the shipped
deployment files, not the binary's behaviour on an existing route, and so does item 21.

**Items 2, 8, 12, 13 and 28 refuse the gateway's start. Item 7 permanently fails the backend it names,
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
| 28 | A config key the gateway does not read fails the load | Fix the spelling of, or delete, each key the error names |

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
An API key whose `backends` list is `["*"]` or empty is unaffected by the scoping.

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

Each pod has its own `state` volume, and both shipped defaults run two pods: `replicaCount: 2`
in the chart's `values.yaml` and `replicas: 2` in the enterprise-alpha `base/deployment.yaml`.
The Service has no session affinity. A task created on one pod is unknown to the other, so a
poll, cancel or result request routed to the other pod answers as if the task did not exist.
If your clients use the task API, set `replicaCount: 1` (or `replicas: 1`) until shared task
storage exists.

The control-plane store still sits next to the config on
the read-only ConfigMap mount, so governance mutations stay off in a chart install (one WARN at
startup). That is tracked separately.
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

## 28. A config key the gateway does not read fails the load

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

## After upgrading

- Confirm the version stamp advanced: the notice prints once and not again.
- Re-authorize OAuth backends at a time you choose rather than on a user's first call.
- If startup is refused, read the error — item 2 is the one that refuses rather than warns.

## Rolling back

Downgrading to 3.x loads the same `gateway.yaml`, because 4.0.0 never edited it. The upgrade
leaves the 3.x token files in place — its migration prints the notice and stamps the version,
and touches no credential (`src/commands/upgrade.rs:264`). A rollback therefore picks those
files back up rather than prompting again, unless the tokens expired in the meantime. What 4.0.0
wrote under the per-issuer key is simply not read by 3.x.
