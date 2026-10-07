# Upgrading to 4.0.0

From any 3.x release. No migration edits your `gateway.yaml`, and the gateway makes no automatic
change to your configuration on upgrade. It starts on an unchanged configuration unless an item
below refuses it.

Each item's section begins with its startup behaviour, in one line:

- **Startup:** prints a notice: the first `serve` after the upgrade prints a one-time notice to
  stderr naming the item, then stamps the new version. The notice is printed rather than logged,
  so `--log-level error` and `RUST_LOG` filters cannot swallow it.
- **Startup:** no notice: nothing is printed at startup; read the item before upgrading. A reason
  may follow, such as a change that is decided per backend or per capability file.
- **Startup:** refuses to start: the gateway refuses to start, with its own error naming the
  setting or file, until the setting is changed. A condition may follow. Such an item needs no
  separate notice: the error would only be repeated.
- **Startup:** fails a backend: the gateway starts, but permanently fails the backend it names.
- **Startup:** fails a capability file: the gateway starts, but refuses an affected capability
  file at load with an error that names it.

**If you are upgrading a running deployment, search this guide for "refuses to start", "fails a
backend" and "fails a capability file" first.**

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
| 18 | Never assigned | None |
| 19 | Never assigned | None |
| 20 | Never assigned | None |
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
| 34 | The inbound WebSocket listener is gone; `server.ws_port` is ignored with a warning | Delete `server.ws_port`; connect clients over HTTP (`POST /mcp`) or stdio |
| 35 | A config or env file other users can read fails the load (Unix) | `chmod 600` the file; on Kubernetes keep the chart's `fsGroup` and `defaultMode` |
| 36 | The Helm chart pins its pod identity to 1001 and caps the `state` volume at `1Gi` | Remove any `runAsUser`, `runAsGroup` or `fsGroup` override other than 1001; raise `stateVolume.sizeLimit` if HOME outgrows `1Gi` |
| 37 | More than one replica is refused while per-process state is on; the chart defaults to one replica | Keep `replicaCount: 1`, or set `server.modern_protocol: false` with the key server and accounts off |
| 38 | A credential over plain HTTP on a network bind refuses the start | Enable `mtls`, or set `server.cleartext_http` to say who protects the traffic |
| 39 | `server.request_timeout` is ignored with a warning; `server.max_body_size` caps every route, oversize gets HTTP 413 / JSON-RPC -32600 | Delete `server.request_timeout` and bound calls with per-backend `timeout`; keep `max_body_size` positive, lower it if you relied on the 2 MiB webhook cap |
| 40 | A secret reference that resolves to nothing fails the load | Set the variable the error names, or write `${VAR:-}` where empty is intended |
| 41 | API keys are configured as sha256 digests; a plaintext `key` fails the load | Replace each `key` with `key_sha256` from `mcp-gateway hash-key`; clients keep the same key |
| 42 | `webhooks.rate_limit` is enforced, per endpoint, default 100 per minute | Raise it above your provider's peak rate, or set `0` for no limit; library users: the `mcp_gateway::session_sandbox` and `mcp_gateway::tunnel` modules are removed |
| 43 | With auth on, the audit log is required, records who and the outcome, and fails closed | Enable `security.transparency_log` on a writable path; on Kubernetes set `audit.existingClaim` to keep the log |
| 44 | `file:` secret references; a literal starting `file:` is now a reference | Point `file:` at an absolute, owner-only (or group-read via `fsGroup`) file; change a literal secret that starts with `file:` |
| 45 | `/health` answers 503 `degraded` while a backend's circuit breaker is open | Expect it on `/health` monitors; Kubernetes probes (`/livez`, `/readyz`) are unaffected |
| 46 | Attestation `enforce` enforces on every route; it needs a signing key and an audience, and tokens are bound to one audience | Set `GATEWAY_ATTESTATION_SIGNING_KEY` and `GATEWAY_ATTESTATION_AUDIENCE`; mint tokens with the audience; send the token on every call; call tools one by one instead of playbooks and code mode |
| 47 | WebSocket is a backend transport (`ws_url`); a `wss://` URL pasted into `add` or the admin UI becomes one | Nothing, unless you want a WebSocket backend: see §47 for what is refused on `ws_url` |
| 48 | A backend that fails to start counts toward its circuit breaker; `Error::CircuitOpen` carries the last failure | Match `CircuitOpen { backend, .. }` in code that used `CircuitOpen(name)`; read the start error in the refusal |
| 49 | The audit log rotates at 64 MiB and keeps 12 sealed segments; `audit verify` reads every segment and detects a deleted or truncated active file | Copy or archive the segments together, never rotate the log externally, and size the volume for `(retain_segments + 1) x max_segment_bytes` (Helm refuses an emptyDir too small) |
| 50 | Every hot-path audit append is bounded (5 s wait, 5 s write); a stalled audit disk answers 503 and `/readyz` reports `stalled` instead of hanging the gateway | Alert on `mcp_audit_append_timeouts_total` and the `stalled` `/readyz` body; a mount that never recovers needs a restart |
| 51 | A `role_mapping` `role: admin` rule grants full gateway admin; a domain-only admin rule fails the load | Review existing `role: admin` rules; replace a domain-only one with `group` or `email` |
| 52 | Only `tools.listChanged` is advertised, and only over HTTP; `resources/subscribe` and `resources/unsubscribe` are refused on `/mcp` (`/mcp/{name}` still forwards them) | Drop any wait for `resources/updated`, `resources/list_changed` or `prompts/list_changed`; poll `resources/list` or `prompts/list` instead |
| 53 | A backend's own rate-limit refusal reads `Rate limit exceeded for backend 'x'` (hint `RATE_LIMITED`, code still -32000) and no longer counts against the error budgets or `mcp_backend_circuit_state` | Match the new text in clients and alerts that looked for "Circuit breaker open"; watch `mcp_backend_rate_limited_total` for throttling |
| 54 | An mTLS key, OAuth token file, capability `file:` credential or `--ca-key` other users can read is refused; an mTLS cert, CRL, grants or control-plane file they can change is refused (Unix) | `chmod 600` a secret file, `chmod go-w` a trust file; on Kubernetes mount a key Secret with `defaultMode: 288` and `fsGroup` |
| 55 | A `tools/call` carrying `inputResponses` without the `requestState` the gateway issued is refused with `-32602` instead of being forwarded | Echo the `requestState` from the `input_required` result on every retry; send `inputResponses` only as an answer to it |
| 56 | Reserved: lands with a pending change | None yet |
| 57 | Never assigned | None |
| 58 | The gateway mints every legacy session id: a client-supplied `Mcp-Session-Id` that names no live session is replaced, an empty one counts as absent, and logs, audit and the dashboard carry an 8-hex fingerprint instead of the id | Use the `Mcp-Session-Id` the response returns; to separate users, turn auth on and keep `/mcp` off the public paths; match new audit and log entries by fingerprint (entries from before the upgrade by raw id); library users: `first_session_id` is removed |
| 59 | A call to a tool not yet listed for that caller lists the backend first, as the caller; under `closed`, an unreadable list or a tool the complete list lacks is refused | To forward such calls, set the backend's `input_schema_enforcement: standard`; a rate limit of 1 can refuse a cold call, since its list spends a token |
| 60 | Capability pins read CRLF line endings as LF | Windows only: re-run `mcp-gateway cap pin` on a file you pinned while it had CRLF line endings |
| 61 | A backend 401 on a managed account forces one token refresh, then answers with the reconnect offer or `UPSTREAM_AUTH_REJECTED`; HTTP 401 and 403 are no longer retried; a REST 401's audit `error_code` is -32000 | Handle `recovery.error_code`; do not roll back to an earlier 4.0 beta after a forced refresh |
| 62 | A bridged input exchange that runs out of rounds returns the backend's last question with a continuation instead of `-32003` | A client that treated `-32003` as final: answer the returned `inputRequests` and resend with the `requestState` it carries, or treat it as unfinished |
| 63 | An error result (`isError: true`) is never served from the response cache or the capability cache; the next call is dispatched again | None; to shed load from a failing backend, rely on the circuit breaker and `failsafe.rate_limit` |
| 64 | Text after a line break (lone CR, NEL, LS, PS) inside a capability's `sha256:` line is hashed | Inspect, then re-pin, a pinned file whose pin line contains one |
| 65 | `/readyz` and `/health` answer 503 until the startup capability scan has loaded every directory; the compose healthcheck probes `/readyz` | Size a startup probe to cover the scan; expect `/health` 503 for the first moments after start |
| 66 | A non-admin call to a callback-registering capability is refused with HTTP 403 and JSON-RPC -32600 and logged as an authorization refusal | Match 403/-32600 where clients or alerts matched the old 400/-32603 "Configuration error" |
| 67 | Every `tasks/*` method, and `subscriptions/listen` naming `taskIds`, on `POST /mcp/{name}` is refused with JSON-RPC -32601 and never reaches the backend | Poll and cancel tasks through `POST /mcp` |
| 68 | Windows: the task store and the personal-account store run, with owner-only DACLs; a store directory on a junction, network drive or FAT/exFAT volume, and a 3.x token file other accounts can read, are refused | Windows only: put the stores on a local NTFS or ReFS path; run the `icacls` lines the refusal prints, in PowerShell, on a flagged 3.x token file |
| 69 | `POST /mcp/{name}` `tools/call` runs the dispatch controls `gateway_invoke` runs (kill switch, capability auto-disable, session profile, cost and error budgets, response gates, response-firewall Block); with message signing on, outside `security.posture: hardened`, it is refused with -32001 | Move direct callers under message signing, outside `hardened`, to `gateway_invoke`; expect direct calls refused, accounted and gated as `gateway_invoke` calls are |
| 70 | `/api/costs` takes a session id only in the `X-Cost-Session-Id` header (`?session=` is 400); the HTTP trace span records the method and route, never the URI; a dashboard link presented from another machine is used up | Move `?session=<id>` to the header; open the dashboard link on the gateway's own machine, by its loopback URL, first time |
| 71 | Dashboard sessions end after 30 minutes idle or 8 hours total; the dashboard's own refresh is not activity; an ended session gets a 401 that clears the cookie | Log in again with `mcp-gateway dashboard-link`; set `auth.dashboard_session` to change the limits |
| 72 | Env files are re-read every 2 s and reloaded when their content changes; after any failed reload, including a refused `config.yaml`, the gateway retries every 2 s until one succeeds | Expect a broken or refused config to be retried, with its warning at most once a minute; fix or revert it rather than waiting for a file event |
| 73 | A task-augmented call to a surfaced tool is confirmed when its tool entry is destructive or cannot be read from the slot the call runs on: always for verified callers on identity-propagating backends, and otherwise while the tool is missing from the shared tool list | Declare the `elicitation` capability to answer the prompt, or call without `task` |
| 74 | With cost governance on, a stdio gateway saves `costs.json` when the client closes stdin and every 5 minutes, so a restart keeps today's spend | None; give stdio gateways that must keep separate budgets their own `MCP_GATEWAY_CONFIG_DIR` |
| 75 | A backend tool whose description fails the tool-poisoning check is withheld from every tool list and refused by name; `allow_flagged_tools` serves one explicitly; `BackendConfig` gains a field; `security::scope_collision::detect_collisions` is removed | Read the `Tool withheld` warnings; pin a tool you trust; add `allow_flagged_tools` to any `BackendConfig` struct literal; drop calls to `detect_collisions` |
| 76 | Opt-in anomaly detection learns from admitted calls, warms up before scoring, scores never-seen transitions 1.0, and its blocks cannot be downgraded by a rule; out-of-range anomaly thresholds, or an HTTP start where no caller can have a caller key, refuse the start when detection is on | With `anomaly_detection: true`, keep `anomaly_threshold` above 0.5, enable a caller identity source on HTTP, and drop rules that softened anomaly blocks |
| 77 | Capability calls, spec imports and discovery ignore `HTTP_PROXY`/`HTTPS_PROXY`; `capabilities.egress_proxy` names a proxy for capability calls | Set `capabilities.egress_proxy` if capability calls must leave through a proxy (not under `security.posture: hardened`, which refuses it) |
| 78 | A stdio gateway serves a `personal_managed` account to its local operator whatever `auth` says | None; to keep an account off a stdio gateway, do not declare it in that gateway's config |
| 79 | Identity grant changes (CLI, direct edits, the grants each start serves) are governance audit records with actor `unknown`; with auth on and grants on, a governance store that cannot open refuses the start | Set `control_plane.store_dir` to a writable directory; keep `<grant file>.journal.jsonl` beside the grant file |
| 80 | Discovery keeps a server's `env`, `headers` and argument boundaries and reads commented Zed settings; `DiscoveredServer` is `#[non_exhaustive]` | Library users build it with `DiscoveredServer::new`; check that `cap discover --write-config` output holds only credentials you mean to keep |
| 81 | Reserved: lands with a pending change | None yet |
| 82 | A signature chain a backend puts in a result's `_meta` is stripped; the new `security.signature_chain` lets the gateway sign an origin link | Nothing unless you consumed a backend-sent chain; to emit links, configure `security.signature_chain` |
| 83 | `MigratedCredential` gains a public `reachability` field and is `#[non_exhaustive]` | Library users: stop building `MigratedCredential` with a struct literal; read `reachability` for where a migrated grant can be used |
| 84 | A capability's OAuth `token_endpoint` gets the same destination check as its request URL; an IP-literal private, loopback or metadata endpoint is refused, so its token refresh fails | Name a private identity provider by hostname and reach it through `capabilities.egress_proxy`, or re-authenticate |
| 85 | The response firewall scans object keys as well as values; a credential-shaped key in a tool result is renamed to `[REDACTED:credential]` (`#2`, `#3`, ... on collision), and one in a question the client must echo refuses it | Read keys, not only values, when you match firewall findings; rely on key names only if they cannot look like a credential |
| 86 | `kubernetes controller --watch --format json` prints one compact JSON document per line, one line per cycle | Read the output as JSON Lines: parse each line on its own |
| 87 | `mcp-gateway cap import-url` refuses a URL whose host name resolves to a private, loopback or reserved address, and pins every name it fetches | Download an internal spec and run `mcp-gateway cap import <file>` |
| 88 | After SIGTERM the HTTP listener waits at most `server.shutdown_timeout` for open requests, then cuts them; mTLS uses the same bound instead of a fixed 30 s | Set `server.shutdown_timeout` above your longest request, and your orchestrator's kill timeout above twice that |
| 89 | A remote backend that runs without signed provenance is named in a startup warning and in `doctor` | None; to verify these backends, set `require_for_remote_backends` and add signed metadata |
| 90 | A `POST /mcp` whose `MCP-Protocol-Version` header names a revision the gateway does not serve is refused with HTTP 400 / `-32022` | Send a served revision in the header, or omit it |
| 91 | With agent identity on, only a proven principal satisfies `require_id` and `known_agents`; a self-declared label no longer does; `require_id` with no proof source (no `agent_auth`, no `mtls`, no hatch) now fails at load instead of refusing every call | Move callers to mTLS or validated agent tokens, or set `allow_unverified_agent_identity: true` |
| 92 | Six meta-tools leave the default `tools/list` until the feature behind each is configured | Configure the feature, or `meta_mcp.expose_stats_tool: true` for `gateway_get_stats` |
| 93 | The key server refuses (403) a token request whose scopes miss the matching policy rule | Request only scopes the rule allows |
| 94 | Per-caller firewall limits (budget, tenant guard, anomaly) key on the caller's identity, else its API key, on `/mcp` and `/mcp/{name}`; OAuth-agent and mTLS callers are scored; limits start fresh once at deploy | None; with client certificates that lack a SAN URI, make sure your CA issues unique CNs |
| 95 | List fills (discovery, search, resources, prompts) pass the circuit breaker and spend rate-limit tokens; their outcomes count toward the breaker; startup warm-up is recorded but never refused | If `failsafe.rate_limit` is tight, budget for list fills or keep list caches warm |
| 96 | A config, env, key, token, credential, certificate, CRL, grants or control-plane file owned by a user other than the gateway's or root is refused (Unix) | `chown` the file to the gateway's uid (`chown 1001` in the container), then `chmod 600` a secret or `chmod go-w` a trust file; root-owned Kubernetes projections still load |
| 97 | A bearer token plus an API key count as two users even with `auth.single_user`: no sole-operator account, isolation guard on | Keep one of the two credentials on a personal gateway |
| 98 | A new audit log begins with an `audit_segment_opened` record at counter 1; caller records start at counter 2, and SIEM export, the NDJSON sink and `entries_checked` include it | Where a SIEM rule, export consumer or script matches caller events, skip `event: audit_segment_opened`; chain and counter checks need no change |
| 99 | Windows: the config, OAuth token and client files, and generated mTLS certificates and keys are created owner-only; those and the secret files it only reads (env files, `file:` targets, TLS keys and credential files) are refused on read when another account can read or change them; trust files (TLS cert and CRL, identity grants and journal, control-plane grants and policies) are refused when another account can change them | Windows only: run the `PowerShell` lines the refusal prints; a trust file others may read keeps its readers |
| 100 | Proven identifiers (agent JWT `sub`, mTLS SAN URI or CN) key grants, `known_agents`, `principal_labels` and per-caller firewall limits verbatim: no trimming, no 512-character cap. Grants and firewall limits pick a certificate's subject by the agent-identity rule (first non-empty SAN URI, else CN) | A grant or allowlist entry naming the bare id no longer matches a padded proven id; reissue the credential without the padding. A certificate whose first SAN URI is empty now keys on its next non-empty SAN, not its CN: move grants that named the CN, and expect a fresh firewall budget bucket. Durable task ownership is unaffected: it keys on the OIDC actor or the API-key owner, not on these subjects |
| 101 | A restart that finds the audit log's `.hwm` missing, on a log that went through segment handling, writes an `audit_segment_hwm_missing` record; `audit verify` then fails the log for as long as it is kept | Investigate how the mark went missing; archive the log and start a new one to clear the failure |
| 102 | A backend with identity propagation admits at most 64 per-caller slots, 8 per caller; all anonymous callers count as one caller. Past a limit the request is refused | With auth off, expect at most 8 passthrough credentials served at once per backend; turn auth on to give each user their own 8 |
| 103 | Each grant decision on a personal capability writes an `identity_grant_decision` record to the audit log; under `FailClosed` a failed write answers `-32005` | Where a SIEM rule counts audit records per call, filter on `kind`; a call now carries a decision record beside its invocation record |
| 104 | A streaming session belongs to the caller's proven subject and its credential, not the credential alone: callers that share one API key, bearer token or no credential but prove different subjects no longer resume or delete each other's sessions | A client that proves a subject and renews its bearer token (a delegated OIDC bearer, an agent JWT) gets a new session with the new token: re-initialize after a refresh. None for other clients |
| 105 | `tasks/get`, and a repeat of a task-augmented call, re-check a finished task against current policy before returning its result. Under attestation `enforce` the read needs a valid recovery token (else -32002); a task whose dispatch an identity grant refused reads back as the current grant denial (-32004); each such read of a personal capability writes an `identity_grant_decision` audit record, unless it repeats the last one written for that task, caller and target within 10 minutes (item 117). Task records name the calls that produced them (record version 5); a failed upstream task whose error is the peer's own records that (record version 6) | Send a fresh `_meta["io.mcp-gateway/recovery"].attestation` on every read of a finished task; before rolling back to a beta, read item 105 and back up `tasks.store_dir` |
| 106 | Under `security.posture: hardened`, an HTTP MCP request with no per-caller identity is refused with 403 (`-32600`): a shared API key, the static bearer and a dashboard session alone are refused | Give each caller an identity: an IdP (OIDC or Access), a trusted proxy header, an mTLS client certificate or an agent JWT; or mark a key held by one person `kind: personal`. Dashboard MCP calls need an IdP or Access subject |
| 107 | A backend can be set to verify or require an upstream gateway's signature chain; this gateway then preserves it and appends its own link | Nothing unless you chain gateways; to chain, set `signature_chain`, `chain_origins` and `chain_signer` on the upstream backend |
| 108 | A `cacheScope` the gateway delivers is always `private`: a backend's `public` (or a malformed value) is rewritten on every route, and `CacheScope::Public` can no longer be built | A cache in front of the gateway that relied on a backend's `public` no longer shares across callers; that sharing was never safe. Rust users of the library: `CacheScope::Public` now holds `std::convert::Infallible` and `CacheScope::for_list` is removed; use `CacheScope::Private` |
| 109 | A backend or capability call whose destination the SSRF guard refuses after DNS resolution answers `-32600 "SSRF blocked: ..."` on the first attempt, in every posture; before, it was tried three times and answered `-32000`. Under `security.posture: hardened`, HTTP and WebSocket backends reach only public addresses: `localhost` and private-network backends are refused | Match the new code where a client matched `-32000` for this case. Under `hardened`, run a local backend over stdio, or keep it on `standard` |
| 110 | With `tenant_guard.arg_keys` set, invocation records name the tenants a call reached (hashed), and an `attribution` field says how far that reaches: `cached_delivery`, `uninspected` (part of the response was not read: JSON text over 1 MiB, JSON-shaped text that fails to parse or nests too deep, encoding nested past three layers, or a reply refused for its signature chain) or `cached_delivery_uninspected` | With `uninspected`, the listed `tenants` were read, but the response may reach others that were not: do not read an empty or short list as complete. None for deployments without `arg_keys` |
| 111 | A stdio gateway keeps durable tasks for its local operator in `<tasks.store_dir>/stdio`, its own directory beside HTTP's: `tasks/get`, `tasks/update` and `tasks/cancel` now answer on stdio, and no HTTP caller can reach a stdio task. A second stdio gateway on the same config finds that store held and serves without tasks, advertising none. An HTTP gateway pointed explicitly at a store a stdio gateway holds fails to start, and its error names the likely holder | Nothing for separate stores. If you set two configs' `tasks.store_dir` so that HTTP lands on another gateway's `stdio` directory, give each gateway its own `tasks.store_dir`. Back up `tasks.store_dir` with every gateway that writes under it stopped |
| 112 | Under `security.posture: hardened`, message signing is forced on and needs a 32-byte secret; every successful `tools/call` result whose nonce was admitted, on `/mcp`, `/mcp/{backend}` and over `serve --stdio`, is signed over the nonce in `params._meta["io.mcp-gateway/nonce"]` (answers given before admission are unsigned); a legacy client must declare elicitation, the direct route serves legacy clients only their `initialize`, and an unconfirmable legacy destructive call is refused | Before adopting `hardened`: set `security.message_signing.shared_secret`, send one fresh nonce per `tools/call`, and make legacy clients declare elicitation (or move them to 2026-07-28) |
| 113 | A task the backend answered with its own upstream task now writes a second invocation record when the gateway settles it: `route: "task_recovery"`, `correlation_source: "task_id"`, joined to the submission record by a new `task_id` field. Under `FailClosed`, a failed write settles the task `-32005` with no backend content | Readers that assume one record per call, or that `route` is `meta` or `direct`, see a new value. None without a transparency log |
| 114 | Under `security.posture: hardened`, backends named in `security.hardened.private_backends` may reach loopback, RFC 1918 and unique-local addresses (never link-local or `fd00:ec2::254`); every other backend stays public-only. A listed name that is not a configured backend refuses start, and changing the list needs a restart | To run a local or in-cluster HTTP backend under `hardened`, list it; list only what needs it |
| 115 | A legacy session now expires after `streaming.session_ttl` of inactivity, not at that age; when it ends (an owned `DELETE /mcp` or the reaper), its routing profile, workflow state, cost bucket and other per-session state are reclaimed, and its cost stays in the aggregate | None. A client that kept a session open across the 30-minute mark keeps it, and its profile, while it stays active |
| 116 | A key-server OIDC issuer, `jwks_uri` or `discovery_url` that is `http://` to a host off this machine refuses to start; a token naming such an issuer is refused; an https issuer's discovery document may not name a cleartext `jwks_uri`. `http://` to a loopback host is allowed and now works | Use `https://` for every `key_server.oidc` URL, or a loopback host for local testing |
| 117 | A read of a finished task that meets the same grant decision as the last record written for that task, caller and target, in every field but the timestamp and trace id, writes no new `identity_grant_decision` record for 10 minutes (held in memory: not across a restart, nor for new keys once 4,096 are tracked); a changed decision (such as a revoked grant) is written at once, and dispatch decisions are never suppressed | A SIEM rule that counted one decision record per poll of a finished task should count per decision change instead |
| 118 | Audit log: a restart that finds the active segment ending below the signed `.hwm` writes `audit_segment_hwm_missing`, whether the tail was torn or cut at a line; a torn-tail repair record whose dropped line `.hwm` already counted carries `committed: true` and is a finding in its own right; Live verify also fails when the record at `.hwm`'s counter is not the one `.hwm` recorded | None; a log that verified before still verifies. Investigate a new finding as tail loss or an edit |
| 119 | A stdio or WebSocket backend whose `initialize` answer selects a protocol revision the gateway does not speak fails its start; a WebSocket backend that rejects the proposed revision is retried once at the highest revision both sides speak | A backend that fails to start with "Backend selected protocol version" needs a revision from the supported list, or a `protocol_version` pin it accepts |
| 120 | A task stored by a 4.0.0 beta (record version below 5) that holds backend output is delivered only when its upstream descriptor names the call, checked against current policy; otherwise `tasks/get` and a repeat of its task-augmented call answer -32003 | Re-run the call under a new idempotency key to get a fresh result. Nothing for an upgrade from 3.5.x, which has no task store |
| 121 | A task still running when the shutdown drain runs out is cancelled before the task store closes, and the next start settles it as interrupted (a task with a configured upstream recovery adapter stays managed, as after any restart) | None; raise `server.shutdown_timeout` if long tasks should be allowed to finish at shutdown |
| 122 | A capability that declares `providers.fallback` logs a CAP-011 warning at load; the fallback was never executed and still is not. A malformed fallback entry now fails that capability's load instead of being dropped | Remove the `fallback` block; fix or remove a malformed entry |
| 123 | A capability provider key the gateway does not read logs a CAP-012 warning naming its path; `cap validate` runs the structural checks and fails on a structural error | Fix or delete the keys CAP-012 names; expect `cap validate` to fail where the loader would skip the file |
| 124 | `mcp-gateway add <name>` uses a pinned, existing package or the vendor-hosted endpoint for every built-in server; 18 names that had no working server are removed and `jira` is now `atlassian` | Re-add a removed server with `--command`/`--url`; existing `gateway.yaml` entries are not changed |
| 125 | A 2026-07-28 `subscriptions/listen` stream opens with a `notifications/subscriptions/acknowledged` notification instead of a JSON-RPC response | A client that read the subscription id from the response `result` reads it from the notification `params._meta` |
| 126 | `mcp-gateway add <registry name>` writes the server's `${VAR}` env or header references, its OAuth stanza and its transport dialect; it writes the server disabled when a reference does not resolve or the server can reach any address (Playwright, Chrome DevTools, fetch, git without a pinned repository). `init` (local profile) enables memory, sequential-thinking, context7 and time. Enabling a backend with an unresolved reference is refused | Set the named variable, then `enabled: true`; nothing changes for backends already in `gateway.yaml` |
| 127 | `service: cli` capabilities now run: a pinned capability whose command is on the `capabilities.process_commands` list starts a local process (no shell, private directories, cleared environment). Unpinned ones and unlisted commands are refused | Set `capabilities.process_execution: disabled` to keep the 3.x behaviour; list your own CLI capabilities in `capabilities.process_commands`; set `capabilities.files.*` roots for path parameters |
| 128 | MCP Events: a subscription to `backend.<name>.resource_updated`, `resources_changed` or `prompts_changed` on an SSE-handshake HTTP, A2A, identity-propagating (personal or external account included) or (multi-user) per-user OAuth backend answers `-32014` naming the reason, never a silent subscription; stdio, WebSocket and streamable HTTP backends offer the three events | Set `streamable_http: true` where the backend speaks it; otherwise poll `resources/list` or `prompts/list` for that backend |
| 129 | A capability that declares `auth.required: true` is left out of `tools/list` and search until its credential exists (an environment or `env_files` variable that is set and non-empty, or a stored login for its `oauth:` provider); 79 bundled capabilities declare it. A `keychain:` or `file:` key and a per-caller account credential cannot be checked here and stay listed | Set the key the capability names; a call to a hidden capability by name is unchanged |
| 130 | With `tenant_guard.arg_keys` set, every frame the gateway sends a caller (answers, errors, notifications and server requests, on every transport) is checked: a caller whose frames name more than one tenant inside `window_secs` gets a `tenant_read` audit record with `cross_tenant_read: flagged`, or `unattributable` without an identity (for an answer on `POST /mcp`, `/mcp/{name}` or stdio the fields ride its `response_delivery_attempt` record); an unreadable response counts as a tenant of its own. The new key `tenant_guard.cross_tenant_reads` takes `off`, `observe` (default) or `block`. Tenant ids are compared across backends | None. Set `off` to silence it, or `block` to withhold such frames; namespace tenant ids that two backends reuse |
| 131 | A capability `webhooks:` route that names no `method` accepts `POST`, as its documentation said; it accepted only `GET`, so a sender that POSTed got 405 | A route that relied on the `GET` default: add `method: GET` |
| 132 | The shipped `gws_*` Google Workspace capabilities (18) now run through the `gws` command-line tool; their input schemas follow the tool's own parameters | Install `gws` (`npm i -g @googleworkspace/cli`) and sign in; a caller that sent the old parameter names sends the new ones (see each capability's schema) |
| 133 | `cloudflare_manage` is removed and replaced by 11 REST capabilities (`cloudflare_*`) against the Cloudflare API v4; the npm package it declared never existed | Call the specific `cloudflare_*` capability; set the account or zone as an input. `deploy_worker` is not included yet |
| 134 | `metacognition_verify` is removed from the public catalogue: it needs a private tool nobody else can install | None for other users; keep a private copy of the file if you run that tool |
| 135 | `cisco_scanner` scans skills locally through `skill-scanner`; its `scan_mcp_server` operation and `trawl_extract` are held and refuse to run, because the gateway cannot confine where those tools connect | Use the skill-scanning operation; no action for the held ones, `trawl_extract` refuses with a message naming MIK-7788, and a `scan_mcp_server` call fails input validation with a message naming `scan_skill_file` and MIK-7788. `trawl_extract` lost its `js`, `plan_only` and `no_cache` flags, which the old template never passed |
| 136 | `gmail_save_attachment` writes only into `capabilities.files.downloads` and no longer takes `output_dir`; `calendar_get_attachment` returns Google's field names (`fileUrl`, `fileId`, `mimeType`, `iconLink`) | Set `capabilities.files.downloads` (and optionally `downloads_quota_bytes`); read `fileUrl`/`fileId` instead of `file_url`/`file_id` |
| 137 | A stdio backend may send one JSON-RPC message of at most 16 MiB (one newline-terminated line); a longer one fails the call and stops that backend's process. Before 4.0 there was no limit | Set `backends.<name>.max_frame_bytes` (64 KiB to 1 GiB) on a backend whose responses are legitimately larger |
| 138 | `mcp_gateway::key_server::oidc::OidcError` gained three variants (`InsecureIssuer`, `InsecureFetch`, `ClientUnavailable`) and is not `#[non_exhaustive]`, so an exhaustive `match` on it no longer compiles | Add the three arms, or end the `match` with a wildcard arm |
| 139 | A relay refusal of a catalogue read (`prompts/get`, `resources/read`) on the meta route now answers HTTP 403, as a `tools/call` relay refusal does; before it was HTTP 200 with the error in the body | A client that branches on the HTTP status of a refused catalogue read should treat 403 as a refusal; the JSON-RPC error (`-32002`) is unchanged |
| 140 | `RuntimeProvenanceReceipt::backend_ok` is now `Option<bool>`, and an event receipt carries none (the JSON has no `backend_ok` field). Before, an event receipt claimed `true`, which nothing had observed | An embedder that reads or builds the field uses `Some(..)`; a verifier reads `subject_kind` first and treats a missing `backend_ok` as not observed. Receipts already stored still read |
| 141 | A successful `cli` or `mcp` capability result no longer carries a credential the gateway injected into the child (an env value, or the resolved `token_env`): every string value and key is rewritten to `[redacted]` and the document is otherwise intact; with the `firewall` feature the credential scanner runs on it too. Values the caller sent are left in the result, since a tool legitimately returns them (with the `firewall` feature the scanner can still replace one that looks like a credential). Without the `firewall` feature only the literal removal of injected values applies: a credential the child invents or reads from elsewhere is not recognised, in results or in error text. The removal is literal: a credential the child encodes (base64, URL escapes) or splits across separate values is not matched. Numbers are redacted only for an injected value of 4 or more digits: a number that contains it, or that equals it once its leading zeros are dropped (an injected `0042` redacts the number 42 wherever it appears); the sign is ignored, so -42, 42.0 and -42.0 are redacted too, and a redacted key that collides with another is renamed `[redacted]#2`, `#3`, ... | A capability whose tool must return an injected value cannot: read it from the child's own source instead |
| 142 | `mcp_gateway::gateway::destructive_confirmation::ConfirmationOutcome` gained the variant `Undelivered` and is not `#[non_exhaustive]`, so an exhaustive `match` on it no longer compiles. `require_destructive_confirmation` now returns `Undelivered` when no session could carry the question; a timed-out or cancelled question stays `Unsupported` | Add an `Undelivered` arm handled like `Unsupported`, or end the `match` with a wildcard arm |
| 143 | The `gateway_search_tools` output schema describes each `matches` row as `anyOf` a tool row (`server`, `tool`, `description`, `score`) or an event row (`kind: event`, `name`, `description`, `inputSchema`); it described tool rows only, so a strict client rejected an answer holding an event. `limit` now caps tool and event rows together: an answer could hold `limit` tools plus `limit` events | A client that reads the row schema at `items.properties` reads `items.anyOf[0].properties` for tool rows and `items.anyOf[1]` for event rows; one that sizes for `2 × limit` rows gets at most `limit` |
| 144 | `ProvidersConfig::process` and `ProvidersConfig::integrity` are no longer public fields: a program built on the crate reads them through `process()` and `integrity()` and cannot set them, so only the loader marks a definition `Integrity::Verified`; `register_capability` replacing a definition drops its cached answers | An embedder that read the fields calls the getters; one that set `integrity` loads the definition through the capability loader instead; one that replaces `mcp` definitions keeps the runtime that started their children driven, or drops it |
| 145 | The `plugin` command is removed (`search`, `install`, `uninstall`, `list`), with `mcp_gateway::registry::marketplace` and `mcp_gateway::config::MarketplaceConfig`; a `marketplace:` block in the config loads and warns once | Delete the `marketplace:` block and `~/.mcp-gateway/plugins`; add tools as `backends:` entries or capability files (`mcp-gateway cap`) |
| 146 | An OAuth backend whose authorization server, authorization endpoint, token endpoint or registration endpoint is `http://` to a host off this machine fails at connect, and so does a redirect from one to such a URL; a capability that sends a credential (`auth.required`, or a header, query or body template that fills in `{env.X}` or `{keychain.X}`) and names an `http://` `base_url` or `endpoint` off this machine fails to load, and a templated one is refused at call time. `http://` to a loopback host is allowed, and is no longer proxied | Serve the authorization server and the capability's API over `https://`, or on a loopback host (`localhost`, `127.0.0.1`, `[::1]`). `allow_cleartext_credentials` does not cover either |
| 147 | A capability whose declared output root is not object-shaped (an array, a string, a type list) advertises `outputSchema` as an object and publishes `structuredContent` under `items` | Read `structuredContent.items` for the nine shipped capabilities listed below, and for your own; the text content is unchanged |
| 148 | An `http_url` backend with no `streamable_http` key POSTs `initialize` first and falls back to the legacy SSE `GET` only when that POST is refused with a 4xx that is not about the credential or a retry (any but 401, 403, 407, 408, 429); `add --url` no longer writes `streamable_http: false`. An explicit `true` or `false` is tried first, and when the server refuses it with such a 4xx the other transport is tried once, with a warning naming the backend and the value to set. `TransportConfig::Http::streamable_http` is now `Option<bool>` | None. A config the old `add --url` wrote keeps working; to skip the refused request, set the value the warning names or remove the key. MCP Events follow the transport the backend connected with; a subscribe starts an undetected backend first, a failed start answers `-32000`, and SSE is refused with `-32014` |
| 149 | A meta-tool result whose payload says `isError: true` (a failed `gateway_invoke`, or a backend's own tool error) carries `isError: true` on the outer `tools/call` result; it was always `false`, with the failure only in the text | A client that read failure from the text alone keeps working; one that treated `isError: true` as a protocol failure should read the text and its `recovery` hint instead |
| 150 | `mcp_gateway::cli::invoke::resolve_args` takes a fourth parameter, `kv_schema: Option<&Value>`: `key=value` text is typed by that input schema; `None` keeps the old behaviour | An embedder passes the tool's input schema, or `None` |
| 151 | A legacy client that calls without a credential (authentication off, or on with the path in `auth.public_paths`, as `/mcp` is in the shipped presets) and does not resume a session the gateway issued is counted under one shared identity by the anomaly detector, the tenant guard and the call budget; in 3.x each such request was a new session and the first call in it | None unless these controls refuse such clients: give them a credential, have them keep the `mcp-session-id` from `initialize`, or raise the limit |
| 152 | A weekday step `*/n` in a cron expression matches only the days `n` divides; the old match also tried each day plus 7, so `*/2` matched every day and `*/3` to `*/13` (except `*/7`) matched extra days; `*/1`, `*/7` and `*/14` up are unchanged | Check each scheduled job and `schedule.tick` subscription whose weekday field uses `/`; one meant to run daily uses `*` |
| 153 | Two credentials that resolve to one principal (the same key listed twice, or two digests sharing their first 48 bits) are refused at load, reload and startup | Remove the duplicate entry, or replace one of the two credentials |
| 154 | A same-key retry after a lost round (a broken stream, a timeout, a reload stopping the backend mid-call, an HTTP 5xx, or a 400, 404, 407, 408, 429 or session-expiry answer) is served the uncertain-outcome notice instead of the original error; `BackendUnavailable` frees the key | A client that read a served error as "the work failed" treats the notice as "may have run" and checks before re-issuing under a new key |
| 155 | A caller signed in through the key server (an `/auth/token` token or a delegated OIDC bearer) has a principal of the form `kst:<sha256 hex>` or `oidc:<sha256 hex>`, no longer 12 hex characters | Update any log or audit query that matched these callers' 12-hex principal |
| 156 | A REST capability body field that is a pure placeholder (`"{cursor}"`) now sends an explicit `null` the property's schema admits (`type: [string, "null"]`); 3.x left the field out. A null the schema does not admit is still left out, and query and path parameters are unchanged | To keep the field out, leave the argument out instead of sending `null`; a static param or URL default for the same name still fills it, as before |
| 157 | `webhooks.base_path` may not overlap a gateway route | Move the receiver to a path outside `/mcp`, `/ui`, `/dashboard`, `/accounts/v1`, `/auth`, `/.well-known` and the probe paths |
| 158 | `audit verify --anchor <file>` checks the log against an off-host copy of its `.hwm`: a log that no longer holds the anchored record fails, and so does a wiped log. `mcp_gateway::security::transparency_log::verify_audit_log` takes a fourth parameter, `anchor: Option<&Path>`; `None` keeps the old behaviour. A log whose oldest surviving segment starts its chain from another hash than the expired boundary it links to now fails verification | Copy `<log>.hwm` off the host on your own schedule and pass it to `audit verify --anchor`. An embedder passes `None` or the anchor path |
| 159 | Cost accounting keeps running sums: a key's 24h, 7d and 30d windows are accurate to the hour, a per-tool breakdown past 256 distinct tools shows the rest as `(other)`, and a key idle for 30 days with no set budget is dropped. `CostTracker::evict_old_records` is removed | None. Library users: drop any call to `evict_old_records`; nothing is left to evict |
| 160 | With cost governance on, the budget enforcer keeps its own day row for every budgeted tool and key and for up to 256 other names per map; spend of later names counts in `tool_overflow_usd` or `key_overflow_usd`, and rows from earlier days without a budget are removed. `EnforcerSnapshot` and `PersistedCosts` gain the two fields | None. Library users building either type with a struct literal add the two fields |
| 161 | `add`, `remove`, `setup wizard` and `cap discover --write-config` keep the comments in `gateway.yaml`, except those on lines the change deletes (a removed backend's entry, or a field an edit drops), which the command names by line number. On a file with comments, a change they cannot write as a text edit (a flow-style `backends:` mapping, or a comment inside a changed value) is refused: nothing is written, the command exits non-zero and names the comment lines. A file without comments is rewritten as before. 3.x rewrote the file and dropped every comment | Rerun with `--force` to rewrite the file without its comments, or edit the file by hand. Scripts that run these commands on a hand-commented flow-style file need `--force` |
| 162 | With gateway authentication off and agent authentication on, each agent owns its tasks apart, keyed on the `client_id` its token validates as (a renewed token for the same agent keeps them); every agent had shared one task owner | None. Tasks an agent created before the upgrade stay under the old shared owner, so the agent no longer finds them under its own |


## 1. OAuth credentials are stored per issuer

**Startup:** prints a notice

Tokens stored by 3.x are **not migrated**. Nothing is lost and nothing is silently reused
under a new key: every OAuth backend re-authenticates once, on its next use.

Expect one authorization prompt per OAuth backend, once. No config change is needed. If your
deployment is unattended, trigger each backend deliberately rather than discovering the prompt
on a user's first call.

`mcp-gateway accounts migrate-credentials` applies only to personal-account
credentials (those under an `accounts` descriptor). It needs an `accounts` block with a `personal_managed`
descriptor and writes only the personal-account store, which an ordinary `backends.<name>.oauth`
backend never reads, so it cannot keep that backend's credential. Every 3.x token belongs to an
ordinary backend. To keep one, bind that backend to a personal account (an `accounts`
descriptor in place of its `oauth` block) and run the command.

Your 3.x token files are left untouched in `~/.mcp-gateway/oauth/` at mode 0600.

## 2. A malformed line in an `env_files` file now fails startup

**Startup:** prints a notice; refuses to start

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

**Startup:** prints a notice

`2024-10-07` is not a revision the MCP specification has ever defined. It was listed in the
gateway's supported set from the first negotiation commit until 4.0.0, where it was removed
(`src/protocol/mod.rs:32-37`).

The removal changes what the gateway *claims*, not how it answers. `server/discover` publishes
the supported set as the gateway's own statement of what it speaks, so an invented revision in
that list was a false claim. Negotiation itself was never affected: `negotiate_version` matches
exactly, and no conforming client can request a revision that does not exist.

Nothing is rejected at `initialize`. A client naming `2024-10-07` there gets `2025-11-25` back —
the same fallback any unrecognized version string gets, before and after this release
(`tests/integration.rs:37`). There is no error and no refused session. A request that names
`2024-10-07` in its `MCP-Protocol-Version` header is refused; see item 90.

`2024-11-05` and every later revision negotiate exactly as before. The startup notice advises
upgrading a client that speaks only `2024-10-07`; in practice such a client would have been
getting the fallback all along.

## 4. Rate-limited backend responses no longer count as failures

**Startup:** prints a notice

HTTP 429 and its equivalents are excluded from the error budgets and from the circuit breaker
(GH #475). In 3.x a backend that was merely busy could be tripped open and taken out of
rotation — the gateway punished a backend for applying backpressure correctly.

The gateway's own per-backend limiter (`failsafe.rate_limit`) is covered by item 53.

There is nothing to change. Expect fewer spurious breaker openings, and note that a genuinely
broken backend that happens to answer 429 will now stay in rotation longer.

A throttle phrase alone is not a rate limit. An error worded only as a throttle — for example
`request throttled: upstream out of capacity` — counts toward the error budgets and the circuit
breaker, and gets the generic recovery hint instead of `RATE_LIMITED`. A tool result with
`isError: true` worded that way counts as an answered call, like any other tool error. A real
throttle carries a `429` or a rate-limit phrase (`too many requests`, `rate limit`,
`RESOURCE_EXHAUSTED`).

## 5. One license across the repository

**Startup:** no notice, a license change rather than a change to running behaviour

4.0.0 retires the MIT core and the per-file allowlist that enumerated it. Every first-party file
in this repository is now under the **PolyForm Noncommercial License 1.0.0**
([ADR-013](adr/ADR-013-single-noncommercial-license.md), [LICENSES.md](../LICENSES.md)).

Noncommercial use is unaffected. Commercial use requires a commercial license — see
[COMMERCIAL.md](../COMMERCIAL.md). If you adopted the gateway under the previous MIT core, this
is the change to route past whoever approves your licensing, not a runtime concern.

## 6. Responses are cached only for a known protocol revision

**Startup:** prints a notice

The response cache is now keyed by the protocol revision the request was served under, and a
request whose revision cannot be identified is not cached at all
(`cache_protocol_revision` in `src/protocol/meta.rs`). A modern request carries its revision
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

**Startup:** no notice, decided per backend; fails a backend, with one warning, and the gateway starts without it

This is decided per backend, so there is no single moment at startup at which the binary could
know whether a given deployment is affected, and no startup notice names it.

The bearer token an OAuth backend's transport attaches is a replayable credential, so it no longer
goes on the wire in cleartext. `https://` is always accepted; `http://` only when the host is
loopback (`localhost`, `127.0.0.0/8` or `::1`). Anything else fails the backend with
`refusing to send an OAuth token in cleartext to <origin>`, and the gateway starts without it.
`http://[::ffff:127.0.0.1]` counts as non-loopback; use `http://127.0.0.1`.

Put TLS in front of the backend, or move it to a loopback address. There is no opt-out. Backends
without OAuth may still use plain `http://`.

## 8. A credential-bearing backend on plain `http://` is refused at load

**Startup:** no notice, decided per backend; refuses to start, with an error that names the backend

This is decided per backend, so there is no single moment at startup at which the binary could
know whether a given deployment is affected, and no startup notice names it.

An enabled backend whose `http_url` or `a2a_url` is `http://` to a host off this machine, and
whose configuration carries a credential, fails the load. Credential-bearing means an `oauth`
section (even with `enabled: false`), identity propagation, secret injection, any static header,
or userinfo or a query string in the URL. The error names the backend and never echoes the URL.

Use TLS, or set `allow_cleartext_credentials: true` on that backend to accept the exposure. See
[REMOTE_BACKENDS.md](REMOTE_BACKENDS.md). The flag does not lift item 7: an OAuth backend on `http://` off loopback is
still refused, flag or not.

## 9. The savings estimates are gone from stats

**Startup:** no notice, a removed CLI surface rather than a change to running behaviour

The `stats --price` flag, the `gateway_get_stats` `price_per_million` argument, and the
`tokens_saved` and `estimated_savings_usd` response fields are removed. They were estimates with no
measured basis. Drop `--price` from scripts, and compute cost from `total_cached_tokens` with your
own price.

## 10. Probes read `/livez` and `/readyz`, not `/health`

**Startup:** no notice, changes the shipped deployment files, not the binary's behaviour on an existing route

> Superseded in part by item 65: `/readyz` also waits for the startup capability scan, and the compose healthcheck now probes `/readyz`.

`/health` answers 503 whenever the health tracker marks any backend down. The Helm chart and
the enterprise-alpha manifests used it for the liveness, readiness and startup probes, so one
flapping upstream restarted every replica, and a backend that was down at deploy time kept new
pods from ever starting. The container `HEALTHCHECK` also dialled `localhost`, which the Host
gate refuses on a `0.0.0.0` bind with no `public_url`, so the image reported itself unhealthy.

4.0.0 adds two endpoints that never read backend health:

- `/livez` answers 200 while the process serves. Use it for liveness and container healthchecks.
- `/readyz` answers 200 once the config has loaded and the listener is up (since item 65, also
  once the startup capability scan has finished). Use it for readiness
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

**Startup:** prints a notice

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

**Startup:** no notice, the start is refused with its own error, which names the setting or file; refuses to start

An API key's `name` is its identity-grant subject (`api_key:<name>`). In 3.x names were
optional and could repeat, so two keys named alike held each other's personal-capability grants
and a nameless key could hold none. Config load now refuses an empty or whitespace-only name,
and a name used by more than one key, whether or not `auth.enabled` is set. The error names the
duplicate. Give each key its own name; renaming a key moves its grants, so update any
`api_key:` grant subjects to match.

## 13. Identity grants match on authority and subject

**Startup:** no notice, the start is refused with its own error, which names the setting or file; refuses to start

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

**Startup:** no notice

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

**Startup:** no notice

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

**Startup:** no notice, the start is refused with its own error, which names the setting or file; refuses to start, only while `trust_caller_identity_headers` is still set

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

**Startup:** no notice, the start is refused with its own error, which names the setting or file; refuses to start, only for a `key_server` rule without a configured issuer or with a blank matcher

> Superseded in part by item 51: a `role: admin` rule whose only condition is `domain` now fails the load.

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
  no config change, except a `role: admin` rule whose only condition is `domain`, which item 51
  refuses.
- **Identity propagation** stops carrying an unverified email: the gateway-signed assertion's
  `email` claim is empty for such users. A backend keyed on the propagated email must key on
  `sub` plus `tenant` instead. The assertion carries no `email_verified` claim, so when
  `/auth/token` exchanges the gateway's own assertion (the `token-exchange-live` example), match
  it with an issuer-only rule on the `mcp-gateway` issuer, not an email or domain rule.

## 21. The Helm chart and enterprise-alpha manifests start

**Startup:** no notice, changes the shipped deployment files, not the binary's behaviour on an existing route

> Superseded in part by item 25: grant and policy edits are refused on every install, not only in a chart install.

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
that is replaced (rollout, eviction, reschedule) starts empty. The chart has no
setting for a persistent `state` volume (the audit log has one, `audit.existingClaim`, item 43).

Each pod has its own `state` volume, so a task created on one pod is unknown to another. Both
shipped defaults now run one pod, and more than one is refused while the task surface is on
(item 37).

The control-plane store still sits next to the config on
the read-only ConfigMap mount, so a chart install reports the store unavailable (one WARN at
startup). Since item 25, grant and policy edits are refused on every install; the store keeps
the governance audit log and any 3.x grant and policy rows (item 25).

Both still serve the bearer token over plain HTTP inside the cluster. Item 38 makes that a
declared choice, `cleartext_http: cluster_internal`, rather than a silent one.
## 22. The governance store location is configurable

**Startup:** no notice

> Superseded in part by item 25: the store no longer takes grant or policy edits.

New `control_plane.store_dir`. When it is unset, the store stays at
`<config dir>/<config stem>-control-plane`, so existing installs do not move. When it is set, it
must be absolute after `~` expansion, and with auth on a gateway that cannot write it refuses to
start. The
store has no lease: one gateway process per `store_dir`. The admin API
(`GET /ui/api/control-plane`) adds `mutation_disabled_reason` (`auth_off` or `store_unavailable`)
and `base_source` (`explicit` or `default`), and a 503 mutation answer names the cause and the
path.

Helm: the chart's config directory is a read-only ConfigMap, so the default location cannot be
created there, and a chart install reports `store_unavailable`. Since item 25 the store
takes no new grant or policy edit, but it still holds the governance audit log and the 3.x rows
that 4.1 will import as drafts, so keep `store_dir` persistent on Helm.

## 23. `logging/setLevel` needs an admin key

**Startup:** prints a notice

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

**Startup:** prints a notice

In 3.x, adding, removing or reviving a backend from the admin UI sent
`notifications/tools/list_changed` to every session on the legacy GET stream. The frame has no
content, but its timing told every caller that an operator had edited some backend, including
backends the caller could not use.

On an authenticated gateway the frame now reaches a session only if its API key may access the
edited backend: the same check that gates tool calls to it. A key whose `backends` list is `["*"]`
is still told about every edit; a key with an empty list reaches no backend and is told nothing
(item 32). After a removal, the callers whose key named the removed
backend are told, because the check reads the key, not the registry. The check runs at delivery
against the credential the session was opened with, so a revoked or expired key-server token is not
told. A session that presented no credential is told nothing. With authentication off, every
session is told, as before.

Nothing errors: a client that is no longer told keeps its cached tool list until it next calls
`tools/list`. Listeners on `subscriptions/listen` are scoped the same way; see item 26.

## 25. Admin-panel grant and policy edits are refused

**Startup:** prints a notice

In 3.x, `POST /ui/api/control-plane/grants`, `…/policies` and `…/decisions` wrote to the
control-plane store (`store/` under the directory from item 22) and answered 200. Dispatch never
read that store. A grant revoked there was still enforced and a grant added there was never
enforced; the same held for policies. The page then showed the store's rows, which could hide an
enforced grant, or show SSRF protection as off while it was on, and it called itself "Mutating".

Those three routes now return **409** with `reason_code`
`grants_managed_in_identity_grants_file` or `policies_managed_in_gateway_config` (a decision of
any other kind gets 422). A caller without admin still gets 403. Where the control-plane store
is unavailable, as in a default Helm install (item 22), they answer **503**
`CONTROL_STORE_UNAVAILABLE` instead of 409. Nothing is written to the control-plane store or its audit log; the
admin-action record of item 51 is separate. The page shows
"Read Only", lists `no_mutation_endpoint` in `current_limits`, reports `GovernanceMutation` as
unavailable, and adds `authority`, which names where each kind is enforced.

What is enforced has not changed. Grants come from the file at `security.identity_grants.path`,
edited with `mcp-gateway identity grants grant|revoke|list`. Policies come from
`security.sanitize_input` and `security.ssrf_protection`. The store still holds the governance
audit log, which the page and SIEM export read, and the rows below, so keep the persistent
`store_dir` of item 22.

Existing rows in `store/grants.json` and `store/policies.json` are no longer shown. Leave them on
disk: 4.1 will bring them back as unenforced drafts that need re-approval. **Do not delete or
hand-edit them.**

## 26. `subscriptions/listen` needs a credential and is scoped to it

**Startup:** prints a notice

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

**Startup:** prints a notice; refuses to start, for a bare `exact` grant under `fail_on_error: true` or a `declared` known agent with agent identity on

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

**Startup:** no notice

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

**Classification.** Every tool the gateway exposes is classified read-only or
side-effecting as data. Capabilities: `metadata.read_only`, required in every
capability YAML. Meta tools: one table, `META_TOOL_EFFECTS`; a name absent from
it is side-effecting. Backend MCP tools: the operator's `idempotency.read_only_tools`
list decides admission, and only an explicit `readOnlyHint: true` or
`idempotentHint: true` permits a resend; an unannotated tool is side-effecting
by declared default (ADR-012 A1), whatever its name suggests. Playbooks and
Code Mode run through `gateway_run_playbook` and `gateway_execute`, both
side-effecting entries; each step is a tool classified by its own entry. A2A
skills are exposed as ordinary backend tools without read-only hints, so they
are side-effecting unless the operator lists them. `prompts/get` and
`resources/read` are protocol reads that do not pass through execution
admission, so the key and `required` mode do not apply to them.

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

**Startup:** no notice, the start is refused with its own error, which names the setting or file; refuses to start

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

- **Retired keys load and warn once; they are not refused (#2360).** `backends.<name>.idle_timeout`
  was retired in 3.x and never had an effect. `backends.<name>.circuit_breaker` was never read:
  every backend's breaker uses `failsafe.circuit_breaker`. `server.ws_port` (item 34) and
  `server.request_timeout` (item 39) also warn and are ignored. Each warning names the key and says
  why, for example `` `backends.x.idle_timeout` is ignored since 4.0: backend idle hibernation was
  never implemented, ... ``. Delete the keys when convenient; use `stop_when_idle_for` on a
  `command` backend for idle shutdown, and tune `failsafe.circuit_breaker` for breakers. A retired
  key is matched only at its own place: `server.idle_timeout` is refused like a misspelling.
- **Keys whose own name starts with `_` or `x-` are annotations (#2360).** They load wherever
  this key check applies and are never read. A few sections reject every extra key while they are
  parsed (for example `auth.dashboard_session`), and an annotation there still fails the load. Annotations are never read, so notes such as `_legacy_env: {...}` or a top-level `x-anchors:` block keep
  working. No setting starts with either prefix, so such a key is never a misspelling, and it is
  never bound: `key_server: {_enabled: true}` leaves the key server off. Entries of maps you name
  yourself (`env`, `headers`, backend names) are data, not keys, and are unaffected.
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

**Startup:** prints a notice; refuses to start, only for a bad `GATEWAY_ATTESTATION_MODE`

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

**Startup:** prints a notice

A `tools/call` whose arguments carry a key the tool's `inputSchema` does not declare, at the top
level or nested inside objects and arrays, now returns `isError: true` and never reaches the
backend. Before 4.0 such keys were forwarded to MCP backends unchecked.

- **MCP backends**, on `/mcp` (including `gateway_invoke`, stdio and code mode) and on the direct
  `/mcp/{name}` route, passthrough backends included. The schema is the one the caller's own
  `tools/list` returned. The first time a caller uses a tool the gateway has not yet listed for
  it, the gateway lists that backend's tools once, as that caller, before judging the call; §59
  describes what happens when that list cannot be read.
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

**Startup:** prints a notice

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

**Startup:** prints a notice

> Superseded in part by item 44: `server.metrics_token` also accepts a `file:` reference.

In 3.x `/metrics` sat outside authentication and answered anyone who could reach the port,
and its labels name your backends. It now answers only `Authorization: Bearer <token>` where
the token is `server.metrics_token`, a literal, `env:VAR` or `file:` path (item 44), and returns 401 with
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

## 34. The inbound WebSocket listener is removed, and `server.ws_port` is ignored

**Startup:** prints a notice

In 3.x, `server.ws_port` spawned a WebSocket listener beside the HTTP server. It only echoed
text frames back: it never served MCP, sat outside the Origin/Host guard and had no
authentication, so no client could reach a tool through it.

- **The listener is gone.** Clients connect via stdio or HTTP (`POST /mcp`).
- **`server.ws_port` in the config file is a retired key: it loads, opens no listener, and warns
  once**, on start and on reload, with `server.ws_port` is ignored since 4.0: the inbound
  WebSocket listener was removed in 4.0 and no WebSocket listener is opened; ... Remove
  server.ws_port. Delete the key. (Before #2360 it refused the load.) Like every `MCP_GATEWAY_*` variable,
  `MCP_GATEWAY_SERVER__WS_PORT` is not checked; it is now ignored, so remove it too.
- **Outbound WebSocket is a backend transport** (`ws_url`, see §47). Only the inbound listener is
  removed.

## 35. A config or env file other users can read fails the load

**Startup:** no notice, the start is refused with its own error, which names the setting or file; refuses to start

> Superseded in part by item 96: the file's owner must be the gateway's user or root, whatever the mode.

In 3.x a config file readable by other local accounts drew one WARN in the HTTP startup banner,
stdio never checked it, and env files were never checked at all. Both can hold credentials.
On Unix the gateway now checks the config file, and every `env_files` entry, before reading it.
The check follows symlinks, so a Kubernetes `..data` link is judged by the file it points to.

| Mode bits | File owned by the gateway's user | File owned by root | File owned by any other user |
|---|---|---|---|
| any world bit (`o+r`, `o+w`, `o+x`) | refused | refused | refused |
| group write | refused | refused | refused |
| group read | refused | allowed | refused (item 96) |
| owner only (`0600`, `0400`) | allowed | allowed | refused (item 96) |

Group read is allowed only on a file the gateway does not own, and item 96 narrows that to root, because there the group is how it
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
  user is. Keeping host ownership with `chmod 640` and group 1001 no longer works: item 96 refuses
  a file a host user owns.
- **The fix the error names depends on ownership.** On a file the gateway owns it is
  `chmod 600`. On a root-owned file, `chmod 600` would lock the gateway out, so it names
  the group route instead: Helm `podSecurityContext.fsGroup` and `configVolume.defaultMode`. A file
  any other user owns is refused first, with the `chown` fix of item 96.
- **The check and the read use one handle.** The mode is taken with `fstat` on the open file the
  gateway then reads, so a file swapped or loosened in between is not loaded.
- **Windows checks ACLs instead of mode bits** (item 99).
- **`mcp-gateway init` already writes `0600`**, so a config it created passes unchanged. One
  written by an older release, or copied into place, may need the `chmod`.

Parent directory permissions, and the `capabilities/` files, are not checked.

The file itself must be a regular file (a symlink to one is fine, which is how Kubernetes projects a
Secret or ConfigMap). A FIFO, device, directory, `/dev/stdin`, `/dev/fd/N` or shell process substitution
`<(...)` given as a config, env file, `file:` secret, key, token, credential or trust file is refused on
Unix, naming what it is; write the content to a file instead. Before 4.0 a FIFO there hung the start.

Item 54 applies this rule to TLS keys, OAuth token files, capability credential files and the
CA key, and a write-only form of it to certificates, CRLs and grant and policy files.

## 36. The Helm chart pins its pod identity and caps its `state` volume

**Startup:** no notice

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

**Startup:** prints a notice; refuses to start, only above one declared replica

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

**Startup:** no notice, the start is refused with its own error, which names the setting or file; refuses to start, only for a credential over plain HTTP on a network bind without mTLS

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

## 39. `server.request_timeout` is ignored, and `server.max_body_size` is enforced

**Startup:** prints a notice; refuses to start, only while `server.max_body_size` is `0`

In 3.x neither key did anything. No server-wide timeout existed: each call is bounded by its
backend's `timeout`. `/mcp` and `/mcp/{name}` capped bodies at a hard-coded 10 MiB, and every
other route, webhooks included, used the framework's 2 MiB default.

- **`server.request_timeout` is removed and ignored; delete it.** It never did anything. Set
  per-backend `timeout` to bound calls. The config still loads, on start and on reload, and the
  gateway warns once:

  ```text
  `server.request_timeout` is ignored since 4.0: the server-wide request timeout was removed in 4.0; it was never enforced. Calls are bounded by the per-backend `timeout`. Remove server.request_timeout.
  ```

  (Before #2360 this refused the load.)
- **`server.max_body_size` is now enforced on every route**, read once at startup
  (default 10 MiB). `0` would refuse every body, so it now fails the load; set a positive byte
  count.
- **An oversize body on `/mcp` and `/mcp/{name}` now gets HTTP 413 with JSON-RPC -32600**
  ("Request body exceeds server.max_body_size"), where it used to get 400 with JSON-RPC -32700.
  Clients that matched on -32700 must also handle 413 / -32600.
- **Routes that parsed with a framework extractor (webhooks, key server, admin UI) now accept up
  to the 10 MiB default**, up from 2 MiB. Lower `server.max_body_size` if you relied on that.

## 40. A secret reference that resolves to nothing fails the load

**Startup:** no notice, the start is refused with its own error, which names the setting or file; refuses to start, only for a secret reference that resolves to nothing or to an empty value, other than `server.metrics_token`, which warns instead

> Superseded in part by item 41: API keys are `key_sha256` digests, so the `env:` reference checked here is `auth.api_keys[].key_sha256`.

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
- **An empty secret is refused like a missing one.** `auth.bearer_token`, `auth.api_keys[].key_sha256`,
  `agent_auth.agents[].hs256_secret` and `key_server.admin_token` written as `env:NAME` fail when
  `NAME` is unset or empty: `auth.api_keys['ci'].key_sha256 references environment variable 'CI_KEY',
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

**Startup:** no notice, the start is refused with its own error, which names the setting or file; refuses to start, only for an API key configured as plaintext `key`

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

**Startup:** no notice

Before 4.0 the key was parsed and ignored. Each webhook endpoint now accepts at most
`rate_limit` requests per minute (burst up to the same number) and answers `429` with
`Retry-After: 60` beyond that. Only requests that pass the signature check count, so unsigned
traffic cannot use up a real sender's budget. The default is 100. `0` means no limit.

A sender that bursts above the limit loses events: most providers, GitHub included, do not
retry a `429`. Set `webhooks.rate_limit` above your busiest sender's peak, or `0`. The value is
read at startup; a reload that changes `webhooks` needs a restart.

Library users: the `mcp_gateway::session_sandbox` and `mcp_gateway::tunnel` modules are removed. Nothing in the gateway constructed either; drop the imports.

## 43. With auth on, the audit log is required and fails closed

**Startup:** prints a notice; refuses to start, only with auth on and no working audit log

> Superseded in part by item 49: the log rotates, and a full volume expires old segments by default instead of stopping calls.

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
- **A full volume.** Item 49 added rotation: by default the oldest sealed segments expire to
  make room. Before the first rotation there is no sealed segment to expire, so a volume that
  fills that early still fails appends as below. With `rotation.on_disk_full: refuse`, a full volume makes every append fail
  with `storage_full`: tool calls get 503 and `/readyz` returns 503 (its body names the
  cause), and the counter reads `mcp_audit_append_failures_total{cause="storage_full"}`.
  Size the volume with item 49's rule, and archive or export segments you must keep; the
  gateway recovers on its own once an append succeeds. The
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

**Startup:** no notice, the start is refused with its own error, which names the setting or file; refuses to start, only for a secret written as `file:...` that names a missing, loose, oversized or empty file, other than `server.metrics_token`, which warns instead

Wherever a whole-value secret takes `env:NAME`, it now also takes `file:/absolute/path`:
`auth.bearer_token`, `auth.api_keys[].key_sha256` (the file holds the digest), `agent_auth.agents[].hs256_secret`,
`key_server.admin_token`, `security.message_signing.shared_secret` and `previous_secret`,
`server.metrics_token`, `accounts.keys`, `accounts.adapters[].hmac_secret_ref` and
`accounts.descriptors[].client_secret_ref`. The secret is the file's content. A descriptor's
`client_secret_ref` is read each time the client secret is used, as its `env:` form is; every other
field is read once, at startup.

- **The path must be absolute.** `~`, relative paths and `${VAR}` inside the path are not expanded;
  `file:secrets/token` fails with `... is not an absolute path.` A descriptor's `client_secret_ref`
  is checked at load too, although its file is read only at use: an empty or relative `file:` path
  refuses to start with `client_secret_ref file: must name an absolute path`, where a 4.0 beta
  started and failed at the first token refresh.
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

**Startup:** prints a notice

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

**Startup:** no notice, the start is refused with its own error, which names the setting or file; refuses to start, only for `enforce` without a signing key or an audience

In 3.x `enforce` ran as observe (item 30). In 4.0.0 `GATEWAY_ATTESTATION_MODE=enforce` refuses,
with JSON-RPC -32002, every call whose token is missing, forged, expired or not scoped to the
tool.

- **It needs `GATEWAY_ATTESTATION_SIGNING_KEY`.** Enforce with an unset, empty or
  whitespace-only key fails startup: without a key every call would be refused.
- **It needs `GATEWAY_ATTESTATION_AUDIENCE` too.** A token now names the destination it was
  minted for, in a required `audience` claim, and a gateway accepts only its own. Pick one
  stable name per gateway: replicas of one gateway share it, two gateways never do. Enforce
  with an unset or blank audience fails startup. `observe` starts without one and audits
  every token as an audience mismatch. A token without the claim is refused as malformed, so
  whatever mints tokens must stamp the audience; no 3.x gateway-issued token outlives its
  expiry, so nothing needs migrating.
- **Where the token goes.** In the `attestation` argument on `gateway_invoke`, including
  signed calls. In `params._meta["io.mcp-gateway/attestation"]` on the direct
  `/mcp/{backend}` route and on surfaced tools called by name. The gateway strips the
  `_meta` key on the direct route right after the audit record hashes the params as sent,
  and before parsing, telemetry and forwarding, for every method and for passthrough
  backends too. Only the audit hash and the attestation check see the token; neither
  protocol telemetry nor any backend receives it.
- **The error names the boundary**: `Attestation rejected at gateway_invoke` on the meta
  route, `at direct_route` on `/mcp/{backend}`. The direct route checks the token before
  identity-propagation minting and before the idempotency guard, so an unattested call
  mints no per-user credential, and a replayed call needs a valid token as well.
- **Every direct-route method that reaches a backend is checked.** What the token must grant:

  | Method on `/mcp/{backend}` | The token must grant |
  |---|---|
  | `tools/call`, `prompts/get` | the tool or prompt `name` |
  | `resources/read`, `resources/subscribe`, `resources/unsubscribe` | the resource `uri` |
  | `tools/list`, `resources/list`, `resources/templates/list`, `prompts/list`, `completion/complete`, `logging/setLevel` | nothing: any authentic, unexpired token |
  | any other method | `"*"` |
  | `initialize`, `ping`, `notifications/*` | exempt |

  A call missing its `name` or `uri` needs `"*"`. Capability strings are not namespaced: a
  token granting `search` grants the tool `search` and a prompt named `search`, so issue
  tokens narrowly.
- **Tasks.** A task-mode `gateway_invoke` re-checks its original token when the worker
  dispatches it, so a queued task needs a token that outlives the queue. A surfaced tool run
  as a task carries the creating request's `_meta` token to its dispatch, where it is
  re-checked the same way. Task recovery reads need a fresh token in
  `_meta["io.mcp-gateway/recovery"].attestation`.
- **Playbooks and code mode are refused.** Under enforce, `gateway_run_playbook` and
  `gateway_execute` answer -32002 "multi-step plans carry no attestation in 4.0.0", keyed
  or not. Their steps are synthesized and carry no token. Call each tool with its own token.
- **A subscription does not outlive its token, because no update outlives the call that
  carried it.** The gateway keeps no subscription state and relays no later
  `notifications/resources/updated`. The direct route discards every backend notification.
  The meta route streams a notification to a client only while the call that raised it is in
  flight, and a stdio backend's notifications reach a caller only as progress on its own
  call. So an attested `resources/subscribe` opens no data flow that the token's expiry
  would have to end. This limitation predates 4.0.0; it is not a change.

## 47. WebSocket backends (`ws_url`)

**Startup:** prints a notice

A backend can be reached over WebSocket:

```yaml
backends:
  realtime:
    ws_url: "wss://rt.example.com/mcp"
    protocol_version: "2025-11-25"   # optional
    headers: { Authorization: "Bearer ${RT_TOKEN}" }
    timeout: 30s
```

- **One session, one credential.** Every caller shares one socket to the backend, one MCP
  session and the one static credential in `headers`, so the backend sees a single client. The
  headers travel once, on the upgrade request; a rotated credential takes effect on the next
  connect (a restart of that backend, or a reconnect after the socket drops).
- **Credentials over `ws://`.** `ws://` to a host off this machine with any credential (`headers`,
  `secrets`, userinfo, a query string, `oauth`) refuses the load unless the backend sets
  `allow_cleartext_credentials`, the same rule as `http://`. `wss://` passes.
- **Refused on `ws_url`:** `oauth` (it needs a per-request bearer the socket cannot refresh),
  `identity_propagation`, and `secrets` with `inject_as: header` or `query`. `inject_as: argument`
  works.
- **Legacy handshake only.** The transport always runs `initialize`. A `protocol_version` of
  `2026-07-28` or later on `ws_url` refuses the load, and a peer that only speaks the stateless
  revision fails the start with "WebSocket MCP initialize failed". A peer that rejects the proposed
  revision and lists the ones it speaks is retried once at the highest revision both sides speak;
  a peer that selects a revision the gateway does not speak fails the start.
- **Public roots only.** `wss://` trusts the bundled web PKI roots; a private CA fails at start
  with a TLS error.
- **Bounded start.** A peer that accepts TCP and stalls the upgrade fails the call after the
  backend `timeout`, and the failure counts toward that backend's breaker (§48).
- **`mcp-gateway add` and the admin UI** store a pasted `ws://` or `wss://` URL as `ws_url`;
  discovery does the same for `MCP_SERVER_*_URL` variables and client-config `url` entries.
- **Logs.** The URL is logged by origin only. tungstenite's handshake logging is capped at DEBUG,
  so even `RUST_LOG=trace` does not print the upgrade request with its query and headers.

## 48. A backend that fails to start counts toward its circuit breaker

**Startup:** prints a notice

In 3.x a start failure (a stdio command that cannot spawn, an HTTP or WebSocket backend that
cannot connect) was returned to the caller and never recorded, so only health probes could trip
the breaker. It now counts on every transport, on the request and the notification path. Once
the breaker opens, callers get:

```text
Circuit breaker open for backend '<name>'; last failure: <the start error>
```

The same text reaches meta-route callers in the recovery hint. For a stdio backend the start
error can name the configured command.

**Breaking, public API:** `mcp_gateway::error::Error::CircuitOpen(String)` is now
`CircuitOpen { backend: String, last_failure: Option<String> }`. A `match` on the old tuple
variant no longer compiles; match `CircuitOpen { backend, .. }`.

## 49. The audit log rotates, and verify spans its segments

**Startup:** prints a notice

With auth on, the audit log is required (item 43). Before this release it grew until its
volume filled, and then every call was refused with `storage_full`. It now rotates at 64 MiB.
The active file keeps its path, and sealed segments sit beside it as
`transparency.jsonl.00000000000000000001` and so on. The gateway keeps 12 sealed segments and
deletes older ones. For each deletion it first writes an `audit_segment_expired` record into the
log, so a deletion can be verified, and a missing file with no such record is reported as
tampering. Set `security.transparency_log.rotation.retain_segments` and `max_segment_bytes`
(1 MiB to 128 MiB) to change this. Rotation cannot be turned off.

`audit verify <path>` now reads every segment beside `<path>`, even when `<path>` itself is
missing. Copy or archive the segments together: a segment you delete by hand makes verify fail.
To keep the log longer, ship it out (SIEM, `control_plane.export`) and size the volume. Disk use
is at most `(retain_segments + 1) x max_segment_bytes`, plus one record and a 1 MiB reserve.

If the volume still fills, the gateway deletes the oldest sealed segment, records the deletion
with `reason: storage_full`, and carries on. It keeps a 1 MiB `transparency.jsonl.reserve` file
beside the log so that record can still be written on a full disk. The reserve exists once the
log has rotated at least once. Set `rotation.on_disk_full: refuse` to keep every record and go
unready instead (the item 43 behaviour).

Do not rotate, rename or move the log's files with an external tool (logrotate,
`copytruncate`, a cron `mv`). Only the gateway may touch them: any external rotation breaks the
hash chain, and verify then reports it as tampering.

One gateway process writes a log path, on every platform. The log takes a writer lease on
`<path>.lock` when it opens and holds it until the gateway exits. A second gateway on the same
path is refused at startup, with an error naming the path, whatever the auth setting. This is
enforced because the writer keeps the chain's counter and hash in memory, so two writers would
fork the chain. `audit verify` and `audit show` only read and take no lease, so they work beside
a running gateway.

A restart where the supervisor starts the new process before the old one has exited waits for
the lease for up to 10 seconds, then refuses; the wait is not configurable in 4.0. Stop the old
gateway first when its shutdown can take longer. Replicas
must not share a log path: use one replica per volume, or put the pod name in the path. The Helm
chart deploys with the Recreate strategy when the audit log is on a persistent volume, so the
old pod exits before the new one starts.

The lease needs a filesystem with working byte-range locks. A local disk has them; some network
shares (NFS without lockd, some SMB setups) do not, and there the lease cannot exclude a writer
on another host.

Before this version, a writer did not hold a lease. When upgrading, stop the old gateway before
starting this one on the same log path: an older binary cannot see the lease, so a supervisor
that overlaps the two could still let both write once. `mcp-gateway audit verify` reports any
fork that results.

Sizing: one tool call writes one or two records of about 1 KiB, so each MiB holds roughly
500-1000 calls, and the default 832 MiB holds the last 400k-800k calls. For more, set
`audit.existingClaim` to a larger PersistentVolumeClaim and raise `audit.rotation.retainSegments`.
The Helm chart refuses to render an emptyDir whose `sizeLimit` cannot hold
`(retainSegments + 1) x maxSegmentBytes + 1Mi` within 90%.

The governance log (`<control_plane.store_dir>/audit.jsonl`) also rotates, at 16 MiB with 4
segments kept, so it uses at most 80 MiB. Size the `store_dir` volume for that.

The SIEM exporter (`control_plane.export`) now follows segments across a rotation. If retention
deletes a segment before it was exported, the exporter re-anchors, reports `reanchored`, and
counts the skipped segments in `mcp_audit_export_segments_skipped_total`.

The log now carries housekeeping records that SIEM tailers and `control_plane.export`
consumers see: `audit_segment_sealed`, `audit_segment_opened`, `audit_segment_expired`, and the
rare `audit_segment_torn_tail_dropped` and `audit_segment_hwm_missing` (item 101). A parser that rejects an `event` value it does not know
must accept these.

Deleting or truncating the active `transparency.jsonl` is now detected. A
`transparency.jsonl.hwm` file records how far the log got, and verify reports the missing
counters. After a power loss on the hot invocation path, which flushes but does not fsync,
verify can report such a gap for records that never reached disk. To verify a copied set that
has no `.hwm`, run `audit verify --archive <path>`, which reports tail completeness as unchecked.
On a signed log, `.hwm` is signed too.

On its own, `.hwm` detects a partial deletion, not a total one. Anyone with write access to the
whole audit directory (a compromised gateway service account, a shared volume, a log-shipping
agent's credentials, not only full host control) can delete every segment and the `.hwm`
together, and a log stored only in that directory cannot prove it existed. An off-host anchor
can: keep a copy of `<log>.hwm` off the host and verify with `audit verify --anchor` (item 158),
which fails on a wiped or rolled-back log. To keep the records themselves, forward them off-host:
`control_plane.export` writes a local NDJSON file, and the protection holds only once an agent
running as another account ships that file to a store (a SIEM, for example) where the gateway
account cannot delete or alter records already landed.

A log written before this release is read as segment 0 and verifies unchanged. If it is over
256 MiB, verify still refuses it; archive it before upgrading.
## 50. A stalled audit disk answers 503 within seconds instead of hanging

**Startup:** no notice

With auth on, every tool call waits for its audit record (item 43). Before this release a
filesystem that stopped answering (a hung NFS mount, a throttled volume) blocked that write
indefinitely, and the blocked writes used up the server's worker threads until the gateway stopped
answering at all. Now every audit append on the request path runs off the request threads and is
bounded: the invocation record on both routes (`gateway_invoke` and `POST /mcp/{name}`), the
response delivery attempt, and the identity-propagation mint, refuse and revoke records. Each waits
at most 5 s behind another append, then writes for at most 5 s. A mint whose record times out is
refused, so no credential is issued without a durable record.

When the bound expires, the call is refused with 503 (`AuditUnavailable`), the log is marked
stalled, `mcp_audit_append_timeouts_total` goes up and `/readyz` answers 503 with
`audit log unavailable: stalled`. Later calls are refused at once, without waiting, until the
stuck write returns. When it returns, the log clears itself; a failed write leaves it degraded with
the real cause (item 43). With auth off (`BestEffort`) calls keep being served, and `/readyz` stays
200.

A write the kernel never returns cannot be abandoned, so a mount that never recovers keeps the
gateway refusing calls until it is restarted. Alert on `mcp_audit_append_timeouts_total` and on
the `stalled` `/readyz` body.

A call refused this way can still gain an invocation record when the stuck write finally lands.
That record has no `response_delivery_attempt` record after it: an invocation record with no
delivery attempt means the result was withheld.

## 51. SSO admin rules now grant full gateway admin

**Startup:** no notice, the start is refused with its own error, which names the setting or file; refuses to start, only for a `role: admin` rule whose only condition is `domain` (and warns once per process for each distinct `role: admin` rule)

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
- **Every admin action is audited, and refused while the audit log is down.** An
  admin meta-tool call (kill, revive, reload, stats, webhook status), allowed or
  refused, writes an `admin_action` record with `surface: "meta_tool"` and the
  `tool`. Its `outcome` is the admin decision (`ok` or `denied`), written before
  the tool runs, not the tool's result. Every request to `/ui/api/*` other than
  `GET` or `HEAD` (reload, backends, capabilities, import, and the control-plane
  grant, policy and decision POSTs) writes one with `surface: "admin_ui"`, the
  matched `route` template, `method` and `http_status`. The body and the query
  are never logged. Each record's `who` names the caller: the credential and,
  for an SSO admin, the issuer and subject, never an email. With auth on, while
  the log is known to be down these requests answer 503 (`AuditUnavailable`) and
  the action does not run; a control-plane POST then answers 503, not 409. If
  the log fails on the record for a UI request that has already run, the answer
  is also 503: the action may have happened, so check before retrying. An admin
  meta-tool call is recorded before it runs, so a 503 there means it did not.

To make SSO users admins, add:

```yaml
control_plane:
  role_mapping:
    rules:
      - { issuer: <your-idp-issuer>, group: <your-admin-group>, role: admin }
```

## 52. The gateway advertises only the change notifications it delivers

**Startup:** no notice

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

**Startup:** no notice

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
- **New counter `mcp_backend_rate_limited_total{backend}`** counts these refusals, on
  requests and notifications. Now that they are excluded from the budgets and the
  circuit gauge, this is where they show. A backend's own 429s stay in
  `mcp_backend_requests_total{status="rate_limited"}`.
- A breaker that is really open is unchanged: same message, and it still counts as a
  failure.

## 54. Keys, tokens and credential files others can read, and trust files they can change, are refused

**Startup:** no notice, the start is refused with its own error, which names the setting or file; refuses to start, only with mTLS on and a key other users can read or a cert, CA or CRL they can change, or with `fail_on_error` and an identity-grants file they can change

> Superseded in part by item 96: the file's owner must be the gateway's user or root, whatever the mode.

Item 35's rule, unchanged, now covers four more files that hold secrets. A refusal names the file,
its mode and the fix, and points at item 35.

| File | When it is read | A refusal |
|---|---|---|
| `mtls.server_key` | at startup | stops the gateway |
| OAuth token files under `~/.mcp-gateway/oauth/` | each time a backend token is looked up | logs an ERROR and treats the token as absent, so the backend asks for authorisation again. The new token is saved `0600`. |
| a capability credential `file:/path.json:field` | on each tool call that uses it | fails that call |
| the CA key given to `mcp-gateway tls issue-server` / `issue-client` as `--ca-key` | when the command runs | the command exits 1 and issues nothing |

Six more files decide whom the gateway trusts. They may stay readable by others, but a file that
other users can **change** is refused (group- or world-write bit set). Fix: `chmod go-w <file>`.

| File | When it is read | A refusal |
|---|---|---|
| `mtls.server_cert`, `mtls.ca_cert`, `mtls.crl_path` | at startup | stops the gateway |
| the identity-grants file | at startup, on grant reload, and by `mcp-gateway identity` | at startup it stops the gateway if `fail_on_error` is set, otherwise no grants load and personal capabilities fail closed; on reload it is logged and the live grants stay; the CLI exits 1 |
| control-plane `grants.json` / `policies.json` | on each control-plane read | that operation fails, and nothing is overwritten |

Files the gateway writes itself pass, whatever the umask: grants, control-plane collections, OAuth
tokens and the keys from `tls init-ca` / `issue-*` are created `0600`, and the certificates those
commands write are set to `0644`. `file:` secret references in the config (item 44) were already
held to item 35.

- A key or token that was readable by others may already have been copied. Rotate the key, or revoke
  the token with the provider, rather than only running `chmod`.
- OAuth token files written by 3.x may be `0644`. `chmod 600 ~/.mcp-gateway/oauth/*_tokens.json`
  keeps them, or let the gateway ask for authorisation again. The refusal is logged at ERROR once
  per file, then at DEBUG, so a busy backend does not flood the log.
- **Kubernetes:** mount a TLS key Secret the way the chart mounts the config: `defaultMode: 288`
  (octal `0440`) on the Secret volume, and `podSecurityContext.fsGroup` set to a group the gateway's
  UID is in (1001 in the image). The file is then `root:1001 0440` and passes. Without them it is
  `root:root 0644` and is refused.
- **Docker Compose:** a bind-mounted key keeps its host mode and owner. `chmod 600` and `chown 1001` it (item 96 refuses any other owner).
- `mcp-gateway config export` now writes the client config it edits as `0600`, and says so on
  stderr when that changes the file's mode.

## 55. Answers without the gateway's `requestState` are refused

**Startup:** prints a notice

A `tools/call` carrying `inputResponses` without the `requestState` this gateway issued is
refused with `-32602` ("inputResponses are not accepted without the requestState this
gateway issued") instead of being forwarded to the backend.

- **Why.** Every interim the gateway relays carries a `requestState` it minted, so an honest
  retry always presents one. Forwarded without it, the answers reached the backend as a fresh
  call, and a backend that ignores the field ran the call again.
- **Who is affected.** Only a client that sends answers it was never asked for. A retry that
  echoes the `requestState` it received is unchanged, and `inputResponses: {}` still runs.
- **Idempotency.** The refusal happens before dispatch and releases the idempotency key, so
  the same key can be used for a corrected call.

## 58. Session ids are always minted by the gateway

**Startup:** prints a notice

A legacy HTTP session id is the only thing that proves a session is yours when
the caller has no credential, so the gateway now treats it as a secret.

- **A client-supplied `Mcp-Session-Id` that names no live session is replaced.**
  The new id comes back in the `Mcp-Session-Id` response header. A client that
  keeps sending its own id instead of the one it was given gets a new session on
  every request and receives no server-to-client prompts (elicitation, sampling,
  roots). Before this release the gateway adopted the id the client chose, which
  let any caller pick an id before another caller and share its stream.
- **An empty or whitespace-only `Mcp-Session-Id` counts as absent.** On `DELETE`
  it is a 400, the same as a missing header (it was a 404, "no owned session").
- **Every unauthenticated caller is one class.** With auth off that is every
  caller; with auth on it is callers on public paths. Whatever name they carry,
  the session id is the only thing that tells them apart, so anyone who holds an
  id owns that session. To separate users, turn auth on and keep `/mcp` off the
  public paths.
- **Logs carry an 8-hex fingerprint, not the id.** So do the firewall audit log
  and the transparency log when they are on. `mcp-gateway audit show --session`,
  which reads the transparency log, accepts the raw id or its fingerprint; entries
  written before the upgrade hold the raw id and are found by the raw id only. A fingerprint is for correlation only:
  two sessions can share one, so a lookup can return another session's entries. The `session_id` field keeps its
  name in the firewall audit NDJSON and the transparency log; tools that parse it
  get an 8-hex value from this release on. Ids in files written before the upgrade
  stay raw, but they name no live session: sessions do not survive the restart.
  The dashboard's cost view (`/ui/api/costs`, `by_session[].session_id`) shows the
  fingerprint too; the admin API `/api/costs` keeps raw ids, since inspecting a
  session by id needs one. It takes that id in the `X-Cost-Session-Id` header
  (item 70).
- **The gateway's own HTTP trace span recorded the full URI** at DEBUG, query
  string included, until item 70. It now records the method and route template
  only. A layer you add that logs request headers or URIs still prints whatever
  it sees, including the raw `Mcp-Session-Id`.
- A legacy destructive call with no usable session, an empty id included, is
  unchanged: it runs with a warning that nobody could be asked.
- Library users: `NotificationMultiplexer::first_session_id` and
  `ProxyManager::first_session_id` are removed, `get_or_create_session_for` is
  no longer public, and `get_or_create_session(Some(id))` returns `id` only when
  that session is already live.

## 59. A tool call on a cold catalogue lists the backend first

**Startup:** prints a notice

The first time a caller uses a tool the gateway has not yet listed for it, the gateway lists that
backend's tools once, as that caller, before judging the call (§31). Before this release such a
call was forwarded unchecked. A call on a catalogue older than the backend's `cache_ttl` refreshes it the
same way; if that refresh fails, the call is judged against the last list.

- **If the backend cannot be reached** (connection refused, no answer within its `timeout`, or
  a transport error), the call gets the same error a failed tool call to that backend gets, and
  under `closed` it counts toward the error budget as a failed call does. Nothing changes for a
  dead backend except that the first call now fails at the list rather than at the call.
- **If the backend answers but its tool list cannot be read** (it returns an error or a list the
  gateway cannot parse), `closed` refuses the call with "the gateway could not read this tool's
  input schema for you; list the backend's tools and retry". Such a refusal is not counted as a
  backend failure. `standard` forwards the call in both cases and counts `input_schema_unknown`,
  so the call itself then succeeds or fails. `off` never lists.
- **A tool name the backend's fresh, complete list does not contain is now refused under
  `closed`**, where it used to be forwarded. A backend that serves tools it does not list can no
  longer have those tools called under `closed`; set that backend's `input_schema_enforcement:
  standard` to keep serving them (counted as `input_schema_absent_forward`).
- **When the gateway cannot read a backend's whole tool list** (the list is longer than the
  32-page cap, repeats a page cursor, or takes longer than the list time budget), a tool outside
  the part read cannot be checked: `closed` refuses it; set that backend's
  `input_schema_enforcement: standard` to forward such calls (counted as
  `input_schema_truncated_forward`). `mcp_backend_list_truncated_total`'s `reason` label says
  which stop fired.
- **Shared catalogues.** On a backend whose catalogue is shared (no per-user propagation), a call
  that carries the caller's own credential never triggers this list, because the shared list runs
  under the gateway's login and would judge the caller against a catalogue it was never shown.
  Such a call stays on the "could not read" refusal under `closed` until discovery,
  `gateway_search` or a credential-free list warms the catalogue.
- **Latency.** The list is bounded by the backend's `timeout` and the call itself by another, so
  the first cold call to a slow backend can take up to about twice `timeout` under `standard`,
  once per backend slot per cooldown window.
- **Cooldown.** After a failed or timed-out tool list, or one whose result could not be kept
  because the cache was invalidated meanwhile, the gateway does not ask that backend again for
  10 s. Inside that window cold tool calls, discovery and `gateway_search` on that backend fail
  fast instead of each waiting out a fresh list, and each gets the error the failed list got. A
  list that failed with an HTTP error status or an I/O or TLS error starts no window, so the next
  call lists again and gets the backend's own error; the circuit breaker bounds those retries. A
  caller that disconnects mid-list does not start this window.
- **Circuit breaker and rate limit.** The list obeys the caller's slot failsafe. An open breaker
  refuses the call with the same circuit-open error a dispatch gets, and a failed or successful
  list counts toward the breaker as a dispatch does. A cold call spends a token for its metadata
  fetch, at most once per slot per `cache_ttl` (and at most once per cooldown window after a
  failed fetch), so a limit of 1 can refuse a cold call as rate-limited. A refusal from the
  breaker or the limiter is counted as `input_schema_fill_refused` with `reason="circuit"` or
  `reason="rate"`.
- **`Mcp-Param-*` headers.** The first call may now carry them, which earlier 4.0 builds sent only
  after a list.
- **New `mcp_input_schema_events_total` kinds.** `input_schema_fetched`,
  `input_schema_fetch_failed`, `input_schema_fill_cancelled`, `input_schema_fill_cooldown`,
  `input_schema_fill_refused` (with `reason`), `input_schema_refused_unavailable`,
  `input_schema_refused_truncated`, `input_schema_refused_absent`,
  `input_schema_truncated_forward`, `input_schema_absent_forward` and
  `input_schema_fetch_skipped_a3`, beside the existing `input_schema_unknown`. See
  [DEPLOYMENT.md](DEPLOYMENT.md#prometheus-metrics).
- No new config key.

The 32 pages and the 10 s above are the values of `LIST_MAX_PAGES` and `LIST_FILL_COOLDOWN` at
release; a test fails the build if either constant changes without this text.

## 60. Capability pins read CRLF line endings as LF

**Startup:** no notice, decided per capability file; fails a capability file, with an error that names the file

A capability's `sha256:` pin used to be computed over the file's raw bytes. A pinned file that
Git checked out with CRLF line endings on Windows (`core.autocrlf`), or that an editor re-saved
with them, hashed differently, and the capability was refused as tampered ("Capability hash
mismatch (rug-pull protection)") although nothing in it had changed. Now the hash reads each
CRLF pair as LF before it is computed. YAML reads the two as the same line break, so the two
files are the same capability. A lone CR that is not part of a CRLF pair is still content, and
it still changes the hash.

Pins over LF files, which covers every capability this repository ships, are unchanged.

**Action, Windows only:** a pin you made with `mcp-gateway cap pin` over a file that had CRLF
line endings at the time was computed over those bytes, and it stops matching. Re-pin the file:

```sh
mcp-gateway cap pin path/to/capability.yaml
```

To reproduce a pin from a shell, strip the CR of each CRLF first:
`sed 's/\r$//' capability.yaml | grep -v '^sha256:' | sha256sum`. The recipe assumes the
pin line holds only the pin: text after a CR, NEL, LS or PS on it is hashed by the gateway
and dropped by `grep -v` (item 64).

## 61. A backend that refuses a managed account's token forces one refresh, then a reconnect

**Startup:** no notice

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

## 62. A bridged exchange that runs out of rounds can be resumed

**Startup:** no notice

The gateway asks a 2025-era (legacy) client a backend's questions in-band and retries the
backend with the answers, for a bounded number of rounds (three). When a backend was still asking after
the last round, the call failed with `-32003` ("asked for input and the bridged exchange
could not be completed"). The backend's progress was lost, and a retry started over.

Now the call returns the backend's **last** interim result: its `inputRequests`, and a
`requestState` holding a gateway-sealed continuation of that round. Resending `tools/call`
with the answers in `inputResponses` and that `requestState` resumes the exchange where the
backend stopped. The continuation is bound to the caller like any other (MRTR.2). The last
round is held to the client's declared capabilities, its per-request capability list and the
response firewall first, so an undeclared question is still refused with the capability it
needs. The idempotency key is not settled, as before: a backend that stopped to ask has not
acted.

For code that uses the library's `mcp_gateway::gateway::input_bridge` module directly:
`BridgeError` is now `#[non_exhaustive]`; `RoundsExhausted` carries the last round
(`last`); and a new `Undeclared` variant, itself `#[non_exhaustive]`, reports a last round
that asks for a capability, mode or method the session never declared. `InputBridge::run`
never hands back such a round.

Action: a client that treated `-32003` from a bridged call as final now gets a result it can
answer. If it cannot answer, it can treat the result as unfinished, the same as any
`input_required` result. Library code that matches on `BridgeError` needs a wildcard arm.

## 63. Error results are never served from a response cache

**Startup:** no notice

In 3.x and in the 4.0 betas, the response cache stored an error result like any answer and
served it to every later call with the same key until the TTL ran out (60 s by default). That
included the gateway's own refusals: a rate-limit refusal, an open breaker, a failed connect.
One 10 ms throttle could therefore answer hundreds of calls with a stale refusal after the
bucket had refilled, and a backend that recovered kept being reported as failing.

- **A result with `isError: true` is no longer cached**, whether the gateway produced it or the
  backend returned it. The next call is dispatched again.
- **The capability cache behaves the same way.** A 2xx upstream body carrying `isError: true`
  is not stored (a non-2xx response never was).
- Successful results are cached exactly as before, under the same keys and TTLs.
- The idempotency store is unchanged: a caller retrying with the same idempotency key still
  receives its own settled outcome, including a failure, as ADR-012 requires.

What to check: a deployment that leaned on a cached error to shed load from a failing backend
now reaches that backend on every call. Use the circuit breaker and `failsafe.rate_limit`
for that; they are the load-shedding controls.

## 64. Text after a line break inside a pin line is hashed

**Startup:** no notice, decided per capability file; fails a capability file, with an error that names the file

The pin hash excludes a capability's top-level `sha256:` line. YAML also ends a line at a
lone carriage return (CR not followed by LF), NEL (U+0085), LS (U+2028) and PS (U+2029), so
text after one of those on that line is parsed as content, and it was excluded from the hash
with the pin. Now only the pin itself is excluded: everything after such a break on the pin
line is hashed like the rest of the file.

**Action:** only a pinned file whose `sha256:` line contains one of those breaks is affected, and it
now fails verification until re-pinned. No shipped capability contains one. Inspect such a
file before re-pinning it, since the text after the break is content that was not covered by
the old pin: `mcp-gateway cap pin path/to/capability.yaml`.

## 65. Readiness waits for the capability catalogue

**Startup:** no notice

The capability catalogue loads in the background after the listener binds, so a large
capability directory does not delay startup. Until now, `/readyz` and `/health` answered 200
during that load, and a pod or container was sent traffic while its catalogue was empty or
partial; capability calls in that window failed with `Not found`.

Now both wait for the startup scan. `/readyz` answers 503 with the body `capabilities
loading`, and `/health` answers 503 `degraded`, until every configured capability directory
has been read. The admin `/health` view adds `capability_backend.loaded`. A gateway with
capabilities disabled has nothing to wait for and is ready at once. `/livez` is unchanged,
so a slow scan never restarts a pod. Hot reloads after startup do not affect readiness.

The shipped manifests follow: the compose healthcheck probes `/readyz` instead of `/livez`,
and the example `RuntimeProfile` the `Gateway` references probes readiness on `/readyz` and
liveness on `/livez` instead of `/health`. The container image healthcheck stays on `/livez`.
The CRD's `RuntimeProfile` defaults stay `/health`, because `MCPServer` resources use the same
profile type and an MCP server has no `/readyz`.

**Action:** a startup probe on `/readyz` must allow for the scan. The shipped Kubernetes
and Helm startup probe allows 60 seconds; the bundled catalogue loads in well under one.
A monitor that alerts on the first `/health` 503 after a start should allow for the same
window.

## 66. A callback-registration admin denial is a refusal, not a configuration error

**Startup:** no notice

A capability that registers a caller-supplied address with a third party (a webhook or
callback URL) is reserved for admin callers. A non-admin call to one was refused with a
configuration error: HTTP 400, JSON-RPC -32603, a message starting "Configuration error:",
and an audit record with outcome `error`. It is now refused like an admin-only tool:

- HTTP 403, JSON-RPC -32600, the same message without the "Configuration error:" prefix.
- The gateway logs the "Tool invocation refused by authorization" warning naming the tool.
- A `tools/call` over HTTP or stdio is refused at admission, before the invocation audit log
  is written, so it leaves the warning only, like every other admission refusal. Where the
  refusal does reach that log, its outcome is `denied` with error code -32600.
- Playbook steps were already refused as a denial and are unchanged.

**Action:** only a client, alert or log query that matched the old 400/-32603 answer or the
"Configuration error" text for this refusal needs to match 403/-32600 instead.

## 67. Task calls on per-backend routes are refused

**Startup:** no notice

`POST /mcp/{name}` forwarded `tasks/get`, `tasks/update`, `tasks/cancel` and every other
`tasks/*` method to the backend unchanged, with no owner check. Callers allowed on the same
backend share its credential, so the backend could not tell them apart: one caller holding
another's task id could read that task's result or cancel it.

In 4.0, task calls on per-backend routes are refused until they carry an owner check:

- Every `tasks/*` method on `POST /mcp/{name}`, in any letter case, and `subscriptions/listen`
  naming `taskIds`, is answered with JSON-RPC -32601 (HTTP 200). Nothing reaches the backend.
- `POST /mcp` still serves tasks, with each task visible only to the caller that created it.
- Every other method on `POST /mcp/{name}` forwards as before, including a `tools/call`
  carrying `task`, and `subscriptions/listen` without `taskIds`.

**Action:** a client that polled or cancelled backend tasks through `POST /mcp/{name}` now
gets -32601. Create and follow tasks through `POST /mcp` instead.

## 68. Windows runs the task and personal-account stores, owner-only

**Startup:** no notice

Before 4.0 both stores refused to start on Windows: their custody lock and their privacy
checks existed only for unix. In 4.0 they run on Windows with protection equivalent to the unix
`0700` directories and `0600` files:

- Every directory and file the stores create is owner-only from its first instant: owner is the
  gateway's account, one grant to that account, and nothing inherited from the parent.
- On every open, each store directory and file is checked on the open handle and refused when
  another account is granted access, the owner is someone else, the DACL inherits or is NULL,
  or the object is a symlink or junction. A store directory reached through a junction, on a
  network drive, or on a volume with no ACLs (FAT32, exFAT) is refused.
- The directories stay open for as long as the store runs, so they cannot be renamed or
  swapped for a junction underneath it.
- A 3.x OAuth token file offered for migration is refused when other accounts can read it
  (the 3.x gateway wrote it with the directory's inherited ACL). The refusal names the rule it
  broke and prints the `icacls` commands, for PowerShell, that make the file owner-only.

Unix behaviour is unchanged.

**Action (Windows only):** keep the store directories on a local NTFS or ReFS path, not a
mapped drive or a junction. If a 3.x token migration is refused, run the printed `icacls` lines
in PowerShell (as an administrator when it says the file has another owner) and retry.

## 69. Per-backend routes run the same dispatch controls as `gateway_invoke`

**Startup:** no notice

`POST /mcp/{name}` `tools/call` skipped controls that `gateway_invoke` enforces: the kill
switch, capability auto-disable, the session's routing profile, cost budgets, the error budget,
response gates, and a response-firewall Block. A caller could reach a killed backend, spend past
its budget, or receive a result `gateway_invoke` would have refused.

In 4.0, both routes run one implementation of each control:

- A killed backend, a disabled capability, a tool outside the session's profile, or a key over
  its cost budget is refused on `POST /mcp/{name}` with the JSON-RPC error `gateway_invoke`
  returns (HTTP 200). Nothing reaches the backend.
- Direct calls record spend and count toward the error budget, so they can auto-kill a backend.
- Response contract, inspection and context-integrity settings apply to direct results.
- A result the response firewall blocks is refused with -32600 "Response blocked by security
  firewall", as on `gateway_invoke`; a retry with the same idempotency key replays that refusal.
- With message signing on, outside `security.posture: hardened`, `tools/call` on
  `POST /mcp/{name}` is refused with -32001 "message signing is enabled; use gateway_invoke".
  Under `hardened` the direct route signs its results instead (item 112).
- The kill switch and capability auto-disable are now checked at admission: task creation,
  admission plans and signing preparation refuse a killed backend or disabled capability up
  front (-32000) instead of at dispatch.

**Action:** a client that called backends directly under message signing, outside the
`hardened` posture, must move to `gateway_invoke`. Expect direct calls to be refused, accounted and gated exactly as
`gateway_invoke` calls are.

## 70. Secrets stay out of the request URI and its trace

**Startup:** no notice

The gateway's HTTP trace span recorded the full request URI at DEBUG, query string included. Two
secrets travelled there: a raw session id in `GET /api/costs?session=<id>`, and the one-time
dashboard link value in `/dashboard?bootstrap=<value>`. With `tower_http=debug` logging on, both
reached the log.

- The span now records the method and the matched route template only (for example
  `/mcp/{name}`), for every route the gateway traces. It never records the query string, a path
  value or a header.
- `/api/costs` selects a session by the `X-Cost-Session-Id` request header. `?session=` is refused
  with HTTP 400 and a message naming the header. `?key=` (an API key's name) is unchanged. Sending
  both `?key=` and the header is refused.
- A dashboard link presented from anywhere but the gateway's own machine is refused, as before, and
  is now also used up. The refusal says so. A copy left in a browser history, a proxy log or a
  `Referer` header therefore dies on its first use elsewhere. On the gateway's own machine, a
  refusal because no admin credential is configured still leaves the link usable.

**Action:** scripts that call `/api/costs?session=<id>` send `X-Cost-Session-Id: <id>` instead.
Behind a reverse proxy on the same host, open the dashboard link by the gateway's loopback URL on
first use: a forwarded first attempt now uses the link up, and a restart prints a fresh one.
With an HTTPS `server.public_url` on a plain-HTTP listener (the `tls_terminated_upstream` shape),
the loopback URL shows a one-time code instead of signing in there, since the session cookie must
be `Secure` and belongs to the public origin (#2130). Type `<public_url>/dashboard/handoff` into the
browser and enter the code within 60 seconds; the session cookie is then set on the public origin.
The code works once and never appears in a URL, so the proxy's access log does not record it; do
not configure the proxy to log request bodies for that path.

## 71. Dashboard sessions expire, and logout ends them

**Startup:** no notice

A dashboard session opened from the startup link used to last as long as the gateway
process. Its cookie said `Max-Age=86400`, but the server never enforced that, so a copied
cookie kept working. There was no logout.

In 4.0:

- A session ends after 30 minutes without activity, or 8 hours after sign-in, whichever
  comes first. The cookie's `Max-Age` matches the 8-hour limit.
- The dashboard's own 5-second refresh does not count as activity, so an unattended tab
  signs out at the idle limit. Clicks and page changes in `/ui` do count.
- Both limits are measured on the monotonic and the wall clock, so a machine that sleeps
  overnight wakes to an ended session.
- The dashboard has a **Log out** button. `POST /dashboard/logout` ends the session on the
  server, not only in the browser, redirects to `/ui`, and works while the audit log is
  unavailable.
- A request with an ended session cookie gets a 401 that says the session ended and clears
  the cookie, instead of "Missing Authorization header". A bearer token sent with it is
  still honoured, and on a public path the request proceeds as unauthenticated.
- `mcp-gateway dashboard-link` asks the running gateway for a fresh single-use link, so
  signing in again needs no restart. It reads the static bearer token or an admin API key
  from `MCP_GATEWAY_TOKEN`, never from an argument. The link still opens only from the
  machine running the gateway, so a gateway bound to a network address answers 409.
  The endpoint behind it, `POST /ui/api/dashboard-link`, refuses a dashboard session and an
  SSO login with 403.

Sessions are held in memory by each replica. Run the dashboard against one replica, or use
sticky sessions.

**Action:** none for most installs. To change the limits:

```yaml
auth:
  dashboard_session:
    idle_timeout_secs: 1800      # 30 minutes
    absolute_timeout_secs: 28800 # 8 hours
```

Both must be above zero, and the idle limit may not exceed the absolute one; the gateway
refuses to start or reload otherwise. A reload applies shorter limits to sessions already
open; a longer absolute limit reaches sessions opened after it, because a browser keeps the
cookie lifetime it was given.

Library users: `DashboardBootstrap::issue_session` and `session_is_valid` are removed.

## 72. Env files are polled, and a failed reload is retried

**Startup:** no notice

A 3.x gateway and earlier 4.0 betas watched each env file's directory, fixed at startup. An
env file reached through a link (`current/.env` after a release switch, or an env file that
is itself a symlink) kept reloading from the old target, and no change was seen on NFS or
FUSE mounts.

In 4.0:

- A gateway serving HTTP from a config file, named with `--config` or `MCP_GATEWAY_CONFIG`
  or found by discovery, re-reads every listed env file every 2 seconds and reloads when its
  content differs from what is loaded. A file that appears later is picked up. A stdio
  gateway watches no files, as before; any gateway that loaded a config file offers the
  `gateway_reload_config` meta-tool.
- A lookup error on an env file (a link loop, a directory the gateway cannot search) fails
  the load instead of reading as a missing file.
- After any failed reload, whatever caused it, the reload is retried every 2 seconds until
  one succeeds. A refused config (a posture refusal, or a change a reload refuses, such as
  new message-signing material) is re-evaluated each time and refused each time; no backend
  is started or stopped and the refused config is not published. The identity-grants file is
  reloaded on its own at each attempt, as on any reload, and a changed grants file still
  takes effect. Its warning is logged at most once a minute per file unless the error
  changes.
- A change to a restart-only field, such as `server.port`, is not a failure: the reload
  succeeds, applies what can change live, reports the rest as needing a restart, and is not
  retried.

**Action:** none required. A broken or refused `config.yaml` now stays in retry until it is
fixed or reverted, so fix it rather than waiting for the next file event.

## 73. Task calls to surfaced tools are confirmed unless known to be harmless

**Startup:** no notice

The confirmation gate for a task-augmented `tools/call` to a surfaced tool read the tool's
`destructiveHint` from the shared tool list. On a backend with `identity_propagation`, calls
run on the caller's own session, whose tool list the shared one does not describe; an empty or
different shared list let a destructive task call run without confirmation.

In 4.0:

- On a backend with `identity_propagation`, every modern task-augmented call to a surfaced tool
  from a caller with a verified identity is confirmed. The prompt says the tool could not be
  classified rather than calling it destructive. A caller with no verified identity runs on the
  shared tool list, so it is classified from that list like any other backend.
- On other backends, a surfaced tool missing from the shared tool list (an upstream that refuses
  an anonymous `tools/list`, or before warm-start finishes) is confirmed the same way, with a
  warning in the log naming the server and tool.
- A client without the `elicitation` capability gets JSON-RPC -32021 for these calls. The
  confirmation runs before attestation, so under attestation enforce an unattested call to
  such a tool gets -32021 (or the confirmation prompt) rather than the attestation refusal
  -32002.
- Calls without `task`, legacy-revision calls and non-surfaced tools are unchanged.
- A confirmation is bound to the caller's verified identity. A caller with none (authentication
  off) cannot be confirmed, so its task call to a destructive or unclassified surfaced tool is
  refused with JSON-RPC -32003 whatever it declares; it can call without `task`, or authenticate.
- A confirmation already granted is honoured even if the tool list changes before the answer.

**Action:** clients that make task calls to surfaced tools on these backends should declare
`elicitation` and answer the prompt, or call without `task`.

## 74. A stdio gateway writes `costs.json`

**Startup:** no notice

With `cost_governance` enabled, a stdio gateway (`mcp-gateway --stdio`) loaded today's spend
from `costs.json` at startup but never saved it, so each restart reset the daily budgets.

In 4.0 the stdio gateway saves the file as the HTTP gateway does:

- when the client closes stdin, after the calls still in flight have finished;
- every 5 minutes while it runs.

A gateway stopped any other way (killed, or its task cancelled when embedded) loses at most the
last 5 minutes of spend. The file is per process: two gateways sharing one data directory
(`MCP_GATEWAY_CONFIG_DIR`, default `~/.mcp-gateway`) each enforce their own budget, and the file
holds whichever saved last.

**Action:** none for most setups. If several stdio gateways share a data directory and you need
each to keep its own budget across restarts, give each its own `MCP_GATEWAY_CONFIG_DIR`.

## 75. Tools with a poisoned description are withheld

**Startup:** no notice

A backend tool's description goes to the model as instructions. 4.0 checks every tool a backend
lists against the tool-poisoning rule (AX-010: hidden instructions, secret-file paths,
exfiltration patterns). A tool that fails it at blocking severity:

- is left out of every tool list the gateway serves: `tools/list` on `/mcp` and `/mcp/{name}`,
  `gateway_list_tools`, `gateway_search_tools` and surfaced tools;
- is refused by name, for every caller of that backend, on both routes, once any listing has
  shown it. The refusal names the tool and the rule, and the backend never receives the call;
- is logged once per distinct description, as a `Tool withheld` warning naming the backend, the
  tool, the rule, the findings and a digest of the description.

A warn-level finding (long whitespace runs, control characters, an oversized description) is
served as before.

A tool name that no listing has ever returned is still forwarded when called by name, because the
gateway has shown its description to no one. This narrows the original goal ("cannot be invoked by
name") to "cannot be invoked by name once the gateway has observed its descriptor", by maintainer
decision. The alternative, refusing every name the caller has not listed first, was rejected
because it breaks every client that calls a remembered tool name without listing.

The gateway remembers at most 4,096 withheld tool names per backend. A backend that withholds more
is marked saturated, with one warning naming the cap: from then on every tool of that backend is
withheld from every list and refused by name, since a name past the cap could not be recorded. The
mark clears only on restart. A tool entry that cannot be parsed is withheld too, and one such entry
no longer fails the rest of the list. A backend that lists the same name twice, one copy
unparseable, has that name withheld in every copy. A name withheld by more than 64 callers stays blocked
until restart.

To serve a withheld tool you trust, pin its current description:

```yaml
backends:
  my-backend:
    allow_flagged_tools:
      tool_name: "<64-hex digest from the warning>"
```

A changed description has a new digest and is withheld again. A pin that is not 64 lower-case hex
characters is refused at load.

For code that embeds the crate: `BackendConfig` has a new public field, `allow_flagged_tools`, so a
struct literal that lists every field needs it (`Default::default()` works).
`security::scope_collision::detect_collisions` and `ScopeCollision` are removed. Nothing in the
gateway called them, and a tool is always addressed as backend plus name, so two backends sharing a
name do not collide.

**Action:** after upgrading, look for `Tool withheld` warnings. Pin any tool you have reviewed and
trust. If you build `BackendConfig` with a full struct literal, add `allow_flagged_tools`.

## 76. Anomaly detection now learns, and its blocks stand

**Startup:** no notice, the start is refused with its own error, which names the setting or file; refuses to start, only with `anomaly_detection` on and an out-of-range anomaly threshold, or on HTTP with no source of a caller key

`security.firewall.anomaly_detection` was accepted and did nothing. The firewall scored every call
against a transition record that nothing wrote to, so every call scored a neutral 0.5 and no
threshold above 0.5 ever flagged or blocked anything. The detector now learns from the calls the
firewall admits, on both the meta route and the per-backend `/mcp/{name}` route. Each call is
scored against its caller's own previous call; what counts as usual is learned from all admitted
calls together.

- A caller's first call, or a call after a tool with fewer than
  `security.firewall.anomaly_min_observations` recorded transitions (new, default 20), is
  *warming up*. It is not scored, never flagged and never blocked.
- A transition never seen after a warmed-up tool scores 1.0, and a seen one scores
  `1 - confidence`. The old never-seen score was 0.95, below a rarely seen one.
- A call refused by the firewall is not learned, so retrying a blocked call cannot teach the
  detector to accept it.
- A score at or above `anomaly_block_threshold` is refused, and a firewall rule can no longer
  downgrade that refusal to allow or warn. The refusal carries JSON-RPC error `-32002` on every
  route; the per-backend `/mcp/{name}` route used to answer `-32600`.
- With `anomaly_detection: true`, the gateway refuses to start when `anomaly_threshold` is not
  above 0.5 and at most 1.0, when `anomaly_block_threshold` is not above `anomaly_threshold` and
  at most 1.0, or when `anomaly_min_observations` is 0. With detection off nothing is checked.
- With the firewall and `anomaly_detection` on, an HTTP start is also refused when no caller can
  carry a caller key: `auth.enabled`, `mtls.enabled` and `agent_auth.enabled` all false and
  `security.caller_identity.mode: off`. Every such call would arrive with an empty key, and the
  detector refuses a call it cannot attribute, so the gateway would refuse every call that has no
  session. The error names `anomaly_detection` and `auth.enabled`. Stdio is not checked. Any one
  of those sources passes the check even if it is optional, such as `mtls.require_client_cert:
  false`; a caller that then presents no key is still refused per call, unless it holds a legacy
  session, whose id stands in for the key.
- A caller with no caller key has no A/B projection arm of its own (it gets the control arm) and
  no prefetch hints: neither is recorded or served for it, and its calls emit no A/B event. Arms
  are now derived from the caller key, so restart any A/B measurement window at the upgrade.
- The default config has no behaviour change: `anomaly_detection` and `anomaly_block_threshold`
  are off by default.
- Known limit: the model is shared, so while a tool is still warming up (its first 20 recorded
  transitions, plus any calls already in flight when it reaches 20) any admitted caller's calls
  shape what counts as usual after it.

**Action:** if you set `anomaly_detection: true`, expect real scores and, with a block threshold,
real refusals once each tool has 20 recorded transitions. Check that `anomaly_threshold` is above
0.5, and drop any firewall rule you relied on to soften anomaly blocks. On HTTP, turn on
`auth.enabled` (or another caller identity source) or turn `anomaly_detection` off.

## 77. Capability calls, imports and discovery ignore `HTTP_PROXY` and `HTTPS_PROXY`

**Startup:** no notice

Capability calls, OpenAPI import by URL (`mcp-gateway cap import`), capability discovery
(`mcp-gateway cap discover`) and the web UI's import followed `HTTP_PROXY`, `HTTPS_PROXY`
and `ALL_PROXY` from the environment. A proxied request is resolved by the proxy, not the
gateway, so it skipped the gateway's SSRF check on resolved addresses: with a proxy set, a
capability could reach loopback, private networks or a cloud metadata endpoint through it.

In 4.0 these clients ignore the proxy environment variables and connect directly;
capability calls and imports check every resolved address. To proxy capability calls, name
the proxy in config:

```yaml
capabilities:
  egress_proxy: "http://proxy.internal:3128"
```

- Every capability call then goes to that proxy, and the proxy resolves destination names.
  Private-range enforcement for names becomes the proxy's job; IP-literal destinations are
  still refused. A plain `http://` destination sends its URL and headers, credentials
  included, to the proxy.
- The value must be an `http://` or `https://` URL with a host; anything else fails the
  config load. It applies at restart. Startup logs a warning naming the proxy (without
  credentials).
- Imports and discovery have no proxy setting and always connect directly. So do one-shot
  capability calls from the CLI (`mcp-gateway cap test`, `mcp-gateway tool invoke`); the key
  applies to the gateway's own capability calls.
- Unchanged: backend connections still follow the environment proxy.

**Action:** if capability calls must leave through a proxy, set `capabilities.egress_proxy`.
Imports that could only reach their spec through a proxy must be fetched another way, for
example downloaded and imported from a file.

## 78. A stdio gateway serves its local operator's personal accounts

**Startup:** no notice

A `personal_managed` account served a stdio gateway's caller only when HTTP auth was on with
`auth.single_user: true`, at most one API key, no OIDC issuer and no identity adapter. A stdio gateway
with the default `auth.enabled: false` refused every account-bound call with "the request
carries no verified end-user identity".

In 4.0 a stdio gateway serves its managed accounts to its one caller, the local process that
started it, whatever the `auth` block says. `auth` configures the HTTP listener only. An HTTP
gateway is unchanged: it serves the sole-operator account only under the single-user settings
above. This covers a REST capability bound with `auth.account` and an MCP backend bound to
the account when it is called through `gateway_invoke`; the direct `/mcp/{name}` route still
needs a verified end-user identity.

Anyone who can start the gateway as the same OS user already holds its data directory, where the
account store lives, so this grants no one new access. Several stdio gateways sharing one data
directory share its accounts.

**Action:** none. To keep an account off a stdio gateway, leave it out of that gateway's config.

## 79. Identity grant changes are recorded in the governance log, and need it

**Startup:** no notice, the start is refused with its own error, which names the setting or file; refuses to start, only with auth on, identity grants on and a governance store that cannot open

`identity grants` CLI changes, edits made directly to the grant file, and the grants each
start serves are now governance audit records (actor `unknown`, action `mutate_grant`).

- With auth on and identity grants on, the gateway refuses to start (HTTP and `serve --stdio`)
  when the governance store cannot open, instead of starting without it: "identity grants need
  the governance audit log when auth is on". Set `control_plane.store_dir` to a writable
  directory. With auth off nothing changes.
- The CLI writes a journal beside the grant file (`<grant file>.journal.jsonl`, mode 0600). Keep
  it with the grant file; deleting it makes the next start record the history as indeterminate.
- A grant change that is applied but cannot be recorded stays applied, and the reload outcome
  says `UNRECORDED`. If the audit plan cannot be written first, the reload is refused and a start
  serves no grants until it can.
- The gateway reads the grant file under a lock file beside it. On a read-only filesystem (for
  example a Kubernetes Secret or ConfigMap mount) it reads without the lock. When it cannot
  create the lock because the directory is missing or it may not write there, the grant file
  counts as unreadable: with `fail_on_error` the start is refused, otherwise no grants are
  served until a reload can read them.
- `ControlPlaneAuditEvent` gains a `grant_change` field, so a struct literal of it in code that
  builds against this crate needs `grant_change: None`. Serialised events without it are unchanged.

## 80. Discovery keeps env, headers and argument boundaries

**Startup:** no notice

`mcp-gateway cap discover` and the setup wizard import MCP servers from client config files
(Claude, Cursor, Windsurf, Codex, Zed). They used to keep only the command line or URL:

- a server's `env` (stdio) and `headers` (HTTP) were dropped, so an imported backend could not
  start or authenticate;
- `args` were joined with spaces, so an argument containing a space or a quote changed;
- Zed's `settings.json`, which allows comments and trailing commas, was skipped when it had any.

In 4.0 all three survive. `cap discover --write-config` writes the `env` and `headers` values
into the backend it adds; on Unix the config file is written owner-only (item 35). Those values are usually
credentials, so everywhere else they are shown by key only: discover's JSON and YAML output,
logs and `Debug` output print `<redacted>` for every value; the table and `--shadow` reports
do not show them.

A client's `${env:NAME}` is written as the gateway's `${NAME}`. A key whose value uses a variable
only the client resolves (`${input:…}`, `${workspaceFolder}`, `${userHome}`) is left out, with a
warning naming the client, server and key, so the written config always loads.

A value that contains `${VAR}` is expanded by the gateway when the config loads, like any backend
`env` or `headers` value; if `VAR` is not set, the load is refused and the error names the field
(`backends.<name>.env.<KEY>`).

`setup export --target zed` into a settings file with comments or trailing commas no longer fails
with a bare parse error: it leaves the file untouched and prints the entry to paste by hand.

For code that uses the library, `mcp_gateway::discovery::DiscoveredServer` gains the fields `env`
and `headers` (`SecretMap`, whose `Debug` and `Serialize` show keys only) and is now
`#[non_exhaustive]`. Build one with `DiscoveredServer::new` and set the fields after.

**Action:** after `cap discover --write-config`, review the written backends: they now carry the
credentials the client config held. Library users replace struct literals with
`DiscoveredServer::new`.

## 82. Backend signature chains are stripped; the gateway can sign an origin link

**Startup:** no notice, the start is refused with its own error, which names the setting or file; refuses to start, only with `security.signature_chain` set and invalid

A backend result's `_meta["io.mcp-gateway/signature-chain"]` is now removed on every route, and
from stored replays, before anything is delivered. Only this gateway may put a chain on a result.

The new optional `security.signature_chain` gives the gateway an Ed25519 chain identity:

```yaml
security:
  signature_chain:
    signing_key: "env:CHAIN_SEED"   # base64 of a 32-byte seed
    key_id: "gw-eu-1"               # 1 to 64 bytes
    emit: on_request                # or always
```

With it set, a `gateway_invoke` result from an MCP backend (and its synchronous idempotent replay)
carries one signed origin link when the request sends `params._meta["io.mcp-gateway/chain-nonce"]`
(a 1 to 256 byte string, else `-32602`), or on every such result under `emit: always`. The link
covers the delivered result and sits under the v2 `_signature` MAC. The direct `/mcp/{name}` route
links its live `tools/call` results. Capability results, meta-only tools, Code Mode, playbooks,
cache hits and direct-route idempotent replays are not linked in 4.0: the direct replay store can
hold a gateway-authored side-effect notice and records no origin. The `gateway_invoke` `nonce` is
the link's fallback nonce only while `message_signing` is enabled; with it off, a link carries the
chain nonce or `null`. A result that cannot carry a link is
refused with `-32001`. A change to `signing_key`, `key_id` or `emit` needs a restart; a reload
that changes one is refused.

**Action:** none unless a client read a chain a backend sent. To emit links, set
`security.signature_chain`.

## 83. `MigratedCredential` has a public `reachability` field

**Startup:** no notice

`accounts migrate` now says where a migrated grant can be used: over stdio, and over HTTP only
when the configuration asserts a single user, in each case through a REST capability or an MCP
backend bound to the account; over HTTP the direct `/mcp/{name}` route still needs a verified
end-user identity. For
library users, the report type
`MigratedCredential` gains a public `reachability: String` field and is marked
`#[non_exhaustive]`.

**Action:** library users only. Code that builds `MigratedCredential` with a struct literal, or
destructures it without a trailing `..`, no longer compiles; read the fields of the value `migrate_legacy_credential_offline` returns instead.

## 84. Capability OAuth refresh sends tokens only where the capability may call

**Startup:** no notice

A capability with an `oauth:` credential refreshes an expired token by sending the refresh
token, the client ID and any client secret to its `auth.token_endpoint`. That endpoint was
never checked: a capability could name a loopback, private or cloud-metadata IP address as
its token endpoint and receive them there.

In 4.0 the token endpoint gets the same destination check as the capability's own request
URL, before anything is sent:

- An IP-literal endpoint in a private, loopback, link-local or metadata range is refused.
  The refresh fails and the stored token stays expired, so the caller must re-authenticate.
- An endpoint named by hostname is resolved and checked on a direct connection, like any
  capability call, and refused if it resolves to such an address.
- Error messages that name a malformed URL no longer include its userinfo, query or
  fragment.

**Action:** if a capability's identity provider lives on a private network, name it by
hostname and set `capabilities.egress_proxy` to a proxy that can reach it (item 77; under
`security.posture: standard`, since `hardened` refuses the key): the proxy resolves the name,
so the refresh goes through it. An IP-literal private endpoint is
refused either way.

## 85. The response firewall scans object keys

**Startup:** no notice

Before 4.0, the response firewall scanned only the values in a backend's JSON, so a
credential or prompt injection placed in an object key reached the client unchanged. In
4.0 both scanners scan keys as well.

- A key that carries prompt-injection text is reported and acted on by the firewall rule,
  like the same text in a value.
- A key that carries a credential is reported and renamed: the credential span becomes
  `[REDACTED:credential]`. The entry and its value are kept. If the new name is already in
  use, the key gets the first free `#2`, `#3`, ... suffix, so no two keys merge.
- A question the client must answer and echo (`inputRequests` in an `input_required`
  result, or a question relayed by the input bridge) is never rewritten: a credential in
  one of its keys refuses the response, as one in a value already did.
- Detection is pattern-based. A key that only looks like a credential, such as a public
  `0x`-prefixed 64-digit hex hash, is renamed too.
- A key finding's description ends in `(object key)`, and its matched text is the redacted
  key, never the credential. A prompt-injection finding's matched text, from a key or a
  value, has credentials masked too. With `credential_redaction` off the payload is left
  as it is and the finding carries no quote at all.

**Action:** none for most deployments. If a backend uses credential-shaped strings as
object keys, expect those keys to be renamed; use other key names.

## 86. `kubernetes controller --watch --format json` prints JSON Lines

**Startup:** no notice

A watch runs until it is stopped, so its JSON output is a stream. Each reconcile cycle now
prints its report as one compact JSON document on its own line (JSON Lines, also called NDJSON).
Earlier releases printed each report as indented JSON over many lines, so no line parsed on its
own. Without `--watch`, `--format json` still prints one indented document (#1909).

**Action:** a script reading `--watch --format json` parses each line on its own, for example
with `jq -c .` or a line-by-line JSON reader.

## 87. `cap import-url` refuses names that resolve to internal addresses

**Startup:** no notice

`mcp-gateway cap import-url` refused a private or loopback IP address written in the URL,
but a host name was resolved when the request was sent and never checked. A name that
resolved to a loopback, private, link-local or cloud metadata address, in the base URL or
in a redirect, was fetched.

In 4.0 `cap import-url` checks every address a name resolves to on each connection and
connects only to those checked addresses, as capability calls and `cap import` of a spec
by URL already do:

- A base URL whose host resolves to a blocked address fails with
  `SSRF check failed for base URL: SSRF blocked: '<host>' resolves to a private/reserved address`.
  The address it resolved to is not named, so the error answers no internal DNS.
- A redirect to such a name is not followed.
- Public names are unaffected. Environment proxies stay ignored (item 77).

**Action:** to build capabilities from an internal API, download its spec and run
`mcp-gateway cap import <file>`.

## 88. The HTTP listener gives open requests `server.shutdown_timeout`, then stops

**Startup:** no notice

After SIGTERM or Ctrl+C, a plain-HTTP gateway waited for every open request to finish,
with no limit. One request that never finished, such as a hung upstream call or a long
stream, kept the process running until the orchestrator killed it. The mTLS listener waited
a fixed 30 seconds whatever the config said.

In 4.0 both listeners stop the same way (#2147):

- New connections are refused as soon as the signal arrives.
- Open requests get `server.shutdown_timeout` (default 30 s) to finish. Requests still
  running at the deadline, including open event streams, are cut.
- The gateway then saves its state and waits, within the same bound, for any in-flight
  work the cut released, before it stops its backends.

**Action:** if some requests run longer than `server.shutdown_timeout`, raise it. Keep the
orchestrator's kill timeout (for example Kubernetes `terminationGracePeriodSeconds`) above
twice `server.shutdown_timeout`, so the gateway can finish its own shutdown.

## 89. Remote backends without signed provenance are named at startup and in `doctor`

**Startup:** no notice

Signed provenance for remote backends stays off by default. With it off, an enabled HTTP, A2A or
WebSocket backend that has no entry under `security.remote_server_signing.backends` runs without
a provenance check. The gateway now logs one warning at startup naming each such backend, and
`doctor` reports the same text as a `remote_provenance` warning. A backend that has an entry is
verified when the config loads, as before, and is not named. The warning is printed once per
start, not on a hot reload; run `doctor` after a reload that adds a remote backend (#1943).

**Action:** none. To verify these backends, set
`security.remote_server_signing.require_for_remote_backends: true` and add signed metadata for
each of them.

## 90. A request header naming an unserved protocol version is refused

**Startup:** prints a notice

3.x ignored the `MCP-Protocol-Version` header on `POST /mcp` and answered the request anyway.
4.0.0 reads it. A header that names a revision the gateway does not serve gets HTTP 400 with
JSON-RPC error `-32022` ("unsupported protocol version"), and `data.supportedVersions` lists the
stateless revisions it does serve; the list is empty when `server.modern_protocol` is off.
`2024-10-07` counts as unserved. A request without the header, or with a served revision, is
answered as before.

**Action:** a client that sends this header must send a revision the gateway serves, or omit it.

## 91. Agent identity rests on proof, not on a label the caller sends

**Startup:** prints a notice

In 3.x, with `security.agent_identity.enabled`, a caller's own `X-Agent-ID` header, `agent_id`
query parameter or unsigned JWT `agent_id` claim satisfied `require_id` and `known_agents`, so
any client could name itself onto the allowlist. Only a proven principal satisfies them now: the
mTLS client-certificate subject (first non-empty SAN URI, else CN) or the `sub` of an agent token the
gateway validated. The unsigned JWT claim is no longer read; the header and query label are kept
for telemetry and cost attribution.

A label that differs from the proven principal is refused unless
`security.agent_identity.principal_labels` lists it for that principal. With mTLS, where subjects
cannot be compared with short labels, `security.agent_identity.incomparable_proof_sources`
(for example `[mtls]`) accepts and audits the mismatch for that source only.

**Action:** move callers that relied on a label to mTLS or validated agent tokens. To let a label
satisfy `require_id` and `known_agents` again, set
`security.agent_identity.allow_unverified_agent_identity: true`. `known_agents` entries now name
their source (item 27). Nothing changes with agent identity disabled.

`require_id` with no proof source (no `agent_auth`, no `mtls`, hatch off) used to load and then
refuse every call; the gateway now refuses to start, naming the fix. Duplicate `principal_labels`
entries for one principal also fail at load, and the hatch logs a warning on every load.

## 92. Six meta-tools leave the default tool list

**Startup:** prints a notice

`gateway_get_stats`, `gateway_cost_report`, `gateway_run_playbook`, `gateway_set_profile`,
`gateway_get_profile` and `gateway_list_profiles` were listed in `tools/list` unconditionally.
Each is now listed only when it can answer: a cost registry, a non-empty playbook engine, a
configured routing profile, and for statistics `meta_mcp.expose_stats_tool: true`. The default
HTTP list drops from 17 tools to 11, stdio from 16 to 10.

Every meta-tool name still dispatches by name, over HTTP and stdio alike. A caller that invokes one
it was not shown gets the tool's own answer: some succeed, others return that tool's own error, and
none answers "no such tool".

**Action:** a client that calls only what `tools/list` shows reaches these six once the feature
behind each is configured; set `meta_mcp.expose_stats_tool: true` to list `gateway_get_stats`.

## 93. The key server refuses a token request that misses the policy

**Startup:** prints a notice

In 3.x, a token request to the key server whose requested backends or tools did not overlap the
matching policy rule got an empty scope list, and an empty list means "all": the token reached
every backend and tool. The exchange now answers 403 and issues no token. A request that leaves
`backends` or `tools` empty is still granted the rule's full scope, as before.

A rule whose own `backends` list is empty is a different case, covered in item 32.

**Action:** a client that requests scopes must request only ones its matching rule allows. A
requested backend outside the rule gets 403 `no_backends_granted`; a requested tool outside it
gets 403 `access_denied`, whose message reads as though no policy matched.

## 94. Per-caller firewall limits key on the caller, on every route

**Startup:** no notice

The firewall's per-caller controls (the call budget, the tenant guard and anomaly detection) now
key on who the caller is, on the meta route and the per-backend `/mcp/{name}` route alike:

- A caller with a resolved identity (an OIDC or key-server login, a trusted-proxy or Access
  identity, an mTLS certificate, or an OAuth agent) is keyed on that identity. Otherwise an
  authenticated API key is keyed on the key. The identity wins over the key, so one person keeps
  one budget across keys and token exchanges.
- An OAuth-agent or mTLS caller on a modern (2026-07-28) `POST /mcp` was refused by these
  controls as having no identity. It is now counted and scored.
- On the per-backend `/mcp/{name}` route every caller of one backend shared one budget, one tenant
  count and one anomaly history. Each caller now has its own, and it is the same one the caller
  has on `/mcp`.
- A legacy session no longer gets a fresh budget or tenant count: an authenticated caller is
  keyed on its identity, not its session. A caller with no identity at all (authentication off)
  is keyed on its session, or on the backend on `/mcp/{name}`, as before.
- The three controls share that one key, so anomaly detection also follows the caller rather than
  the session: a caller with two sessions open at once feeds one sequence history, and each call is
  scored against the caller's previous call on either session.
- The dashboard's MCP calls are keyed on the dashboard's own credential. The dashboard link opens
  one session at a time, so that is that session's budget and tenant count.
- An mTLS caller is identified by its certificate's first non-empty SAN URI, else its CN; a renewed
  certificate for the same subject keeps its limits. Without a SAN URI, identity relies on your
  CA issuing unique CNs. A certificate with neither is not an identity.
- The default config has no behaviour change: the budget, the tenant guard and anomaly detection
  are off by default.

What you will observe once, at deploy: every per-caller budget, tenant count and anomaly history
starts fresh, because the keys they are stored under changed. Limits are counted again from zero,
and anomaly detection warms up again for each caller.

**Action:** none required. If you issue client certificates without a SAN URI, check that your CA
issues unique CNs, since two certificates with one CN share their limits.

## 95. List fills count toward the breaker and the rate limiter

**Startup:** no notice

In 3.x, a list fill (the `tools/list`, `resources/list`, `resources/templates/list` or
`prompts/list` a cold cache sends for discovery, `gateway_search`, `gateway_list_tools`,
resources or prompts) went straight to the backend. It ignored an open circuit breaker,
spent no `failsafe.rate_limit` token, and its outcome never reached the breaker.

In 4.0 every list fill a request starts, including the background refresh a discovery request
starts, is gated like a tool call:

- An open breaker refuses it with the circuit-open error, and sends nothing.
- It spends one `failsafe.rate_limit` token from the same budget as tool calls. A cold-cache
  burst over N list keys spends N tokens.
- A list that cannot be reached counts as a failure toward the breaker. A throttled answer counts
  as neither. An answer that arrives but cannot be used counts as reachable, is logged as a
  warning and is counted in `mcp_backend_requests_total{status="list_unusable"}`.

Startup warm-up fills are never refused and spend no token, but their outcome is recorded, so a
backend that is down at startup opens its breaker before traffic arrives.

**Action:** if `failsafe.rate_limit` is tight, allow for list fills in the budget, or keep the list
caches warm (`meta_mcp.warm_start`).

## 96. A secret or trust file must belong to the gateway's user or to root

**Startup:** no notice, the start is refused with its own error, which names the setting or file; refuses to start, only for a config, env, key or trust file that a third account owns

In 3.x the mode check of items 35 and 54 ignored who owned the file, except that it allowed group
read on a file the gateway did not own. An account that owns a file can `chmod` it, so a secret
file another account owns could be read by that account, and a trust file (TLS certificate, CRL,
identity grants, control-plane collection) could be changed by it. The mode check passed.

On Unix the gateway now refuses a config, env, key, token, credential, certificate, CRL, grants
or control-plane file unless its owner is the gateway's effective user or root (uid 0), whatever
the mode. The check runs before the mode rules, on the same handle as the read.

- **The error names the file, the owner uid and the fix.** For a secret file the fix is
  `chown <gateway uid> -- <file> && chmod 600 -- <file>`; the `chmod` is needed because a group-read
  mode stays refused once the gateway owns the file. For a trust file it is `chown <gateway uid> -- <file> && chmod go-w -- <file>`: `chown` keeps a group- or world-write bit, which the trust rule still refuses. The printed command quotes the path and ends options with `--`.
- **Kubernetes:** unchanged. A projected ConfigMap or Secret is root-owned (`root:<fsGroup> 0440`)
  and still loads.
- **Docker Compose:** the container runs as UID 1001, so `chown 1001` the bind-mounted file and
  `chmod 600` it if it holds a secret (a certificate or CRL keeps its read bits; `chmod go-w` it if others can write it). The `chmod 640` and `chgrp 1001` layout that kept host ownership (item 35) is
  refused now.
- **A shared service group** that gives several accounts a file no longer works: give the gateway's
  user the file, or mount it root-owned.
- **Windows** is covered by item 99.

**Action:** run `stat -c '%u %a' <file>` (`stat -f '%u %Lp'` on macOS) on each secret and trust file.
An owner that is neither the gateway's uid nor `0` needs the `chown`.

## 97. A bearer token and an API key are two users, even with `single_user`

**Startup:** no notice

With `auth.single_user: true`, a gateway with an `auth.bearer_token` and one API key counted as
single-user. Both credentials were served the sole operator's personal accounts, and the
per-user OAuth isolation guard (ADR-008) stayed off.

In 4.0 the bearer token counts as a credential beside the API keys. Two credentials are two
users whatever `single_user` says: the sole-operator account is not served to either, and the
isolation guard is on. The gateway still starts. A bearer-only or one-key-only gateway is
unchanged, and so is any `auth.bearer_token` spelling (`auto`, `env:`).

**Action:** a personal gateway that added a client key beside its bearer token keeps exactly one
of the two: remove `auth.bearer_token` or the extra API key.

## 98. A new audit log begins with an open record

**Startup:** no notice

In 3.x, the first record in a new audit log was the first caller event, at counter 1.

In 4.0 a new log (one with no records yet) begins with an `audit_segment_opened` record:
`segment_seq` 0, counter 1, `prev_entry_hash` `genesis`. The first caller record is counter 2.
A log that already holds records is not changed.

With the record in place, `audit verify` fails a never-rotated log whose high-water mark is
missing once any caller record follows the open record, so a tail cut is no longer read as
clean. A log cut back to the open record alone still reads as a fresh log, as does a deleted
log; only an anchor kept off the host catches that.

The record is signed and chained like any other, so every consumer that follows the chain gets
it: SIEM export and the NDJSON file sink forward it, the export metrics count it, and
`audit verify` counts it in `entries_checked`. Readers that select records by session or kind
(`audit show`, the dashboard's governance view) never show it.

**Action:** where a SIEM rule, export consumer or script matches caller events, skip records
whose `event` is `audit_segment_opened`. Chain and counter checks need no change: the sequence
starts at 1 with no gap.

## 99. Windows checks secret and trust files, and creates them owner-only

**Startup:** no notice, the start is refused with its own error, which names the setting or file; refuses to start, only on Windows, for a secret file another account can read or change, or a trust file it can change

In 3.x and early 4.0 a Windows gateway created these files with the directory's inherited ACL and
read them unchecked (item 35 covers unix only). In 4.0 it does both, in two classes that match
the unix mode rules:

- **Secret files** (config, env files, `file:` targets, TLS private keys, OAuth token and client
  files, credential files). The gateway creates the config file, OAuth token and client files,
  and generated mTLS certificates and keys owner-only: one grant to the gateway's account,
  nothing inherited. Env files, `file:` targets, TLS keys you supply and credential files are
  inputs it only reads: it checks them and never fixes their ACL. A read of any secret file is
  refused when another account is granted access, the owner is someone else, or the DACL
  inherits or is NULL. A DACL that is not marked protected is refused as
  inheriting even when it holds no inherited entry: an old-style ACL, which some tools show as
  protected, is refused too. The repair below marks it protected.
- **Trust files** (TLS certificates and CRLs, the identity-grants file and its journal, the
  control-plane `grants.json` and `policies.json`) may be read by others but never changed by
  them. A read, and an append to the journal, is refused when another account can write, or the
  owner is not the gateway's account, SYSTEM or Administrators.
- A secret file is refused on a volume that keeps no ACLs (FAT, exFAT): Windows accepts the
  owner-only descriptor there and discards it, so the create is refused: no secret is written;
  the empty file is removed, and a refusal that could not remove it says so. Keep the config,
  keys and token files on NTFS or ReFS.
- The check and the read use one handle. Like unix, a link is followed and its target judged; a
  directory or other non-regular file is refused.
- The refusal names every rule broken and prints the PowerShell lines that repair it, for the
  file's class. `load_client_id` reads a public OAuth client id and is the one exception: it is
  not checked.

Repair a **secret file** (owner-only, one grant to the gateway's account; `<sid>` is that
account's SID, which the refusal prints):

```powershell
$acl = New-Object System.Security.AccessControl.FileSecurity
$acl.SetSecurityDescriptorSddlForm('D:P(A;;FA;;;<sid>)', 'Access')
(Get-Item -LiteralPath '<path>').SetAccessControl($acl)
```

Repair a **trust file** (the gateway's account, SYSTEM and Administrators keep full control,
Everyone keeps read, so no legitimate reader is locked out and every foreign write is removed):

```powershell
$acl = New-Object System.Security.AccessControl.FileSecurity
$acl.SetSecurityDescriptorSddlForm('D:P(A;;FA;;;<sid>)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;WD)', 'Access')
(Get-Item -LiteralPath '<path>').SetAccessControl($acl)
```

When the file has another owner, run the lines as an administrator with `takeown /F '<path>'`
first and `icacls '<path>' /setowner '*<sid>'` last; the refusal prints them in that order.
A path with characters outside letters, digits, space and `\ : . _ - ( )` gets a description of
the same repair instead of commands.

Unix behaviour is unchanged.

**Action (Windows only):** if a file is refused, run the printed lines in PowerShell (as an
administrator when it says the file has another owner) and retry.

## 100. Proven identifiers are compared verbatim

**Startup:** no notice

In 3.x, a proven identifier (the `sub` of an agent token the gateway validated, or an mTLS
client certificate's SAN URI or CN) was trimmed of surrounding whitespace before it keyed
anything. Grant subjects and per-caller firewall keys were also cut to 512 characters, and
took only a certificate's first SAN URI. A proven `" admin "` therefore resolved as the
distinct principal `admin`, and two ids that share a 512-character prefix shared grants and a
firewall budget.

In 4.0 a proven identifier keys grants, `known_agents`, `principal_labels` and per-caller
firewall limits exactly as proven: no trimming and no cap. An empty value is skipped. Grants and
firewall limits pick a certificate's subject by the agent-identity rule: the first non-empty SAN
URI, else the CN.

**Action:** a grant or allowlist entry that names the bare id no longer matches a padded proven
id; reissue the credential without the padding. A certificate whose first SAN URI is empty now
keys on its next non-empty SAN, not its CN: move grants that named the CN, and expect a fresh
firewall budget bucket. Durable task ownership is unaffected: it keys on the OIDC actor or the
API-key owner, not on these subjects.

## 101. A restart records a missing high-water mark

**Startup:** no notice

In early 4.0, a restart that found `<path>.hwm` missing wrote a fresh mark from whatever the
active file held. Deleting `.hwm`, cutting the tail and restarting therefore made
`audit verify` pass again (item 98 and the expiry case of item 49 caught the cut only until
that restart).

In 4.0, when `.hwm` is missing at startup and the log went through segment handling (a sealed
segment exists, or the active file opens with an open record and holds more than it), the
gateway first chains an `audit_segment_hwm_missing` record, logs a warning and increments
`mcp_audit_hwm_missing_total`, then writes the fresh mark. The log keeps running. `audit verify`
fails on the record in live mode and warns in `--archive` mode. When retention or disk-full
expiry deletes the segment holding it, the finding survives: every later `audit_segment_opened`
record carries its counter as `hwm_missing_at`, so the failure lasts as long as the log.

A pre-D6 log (no open record) and a log holding only its genesis open record (a crash before
the first mark) still get a fresh mark without the record. A crash between the first caller
record and its first mark is indistinguishable from a cut and is recorded. A changed
`shared_secret` makes the old mark unreadable and is recorded too. So is a torn final line the
mark already counted (a committed record, not a crash mid-write), and a record recovery cannot
verify (edited, unlinked or oversized).

**Action:** treat the record as possible tail loss and investigate. To clear the live failure,
archive the log's files together and let the gateway start a new log. Like the other
`audit_segment_*` records (item 49), SIEM rules that match caller events can skip it.

## 102. Per-caller backend slots are capped

**Startup:** no notice

In 3.x, each caller of a backend with `identity_propagation` got its own upstream connection
(a pool slot, and on a stdio backend its own child process), with no limit. A passthrough
caller picks its own slot by the credential it sends, so a caller that changed the credential
on every request could open any number of them.

In 4.0 a backend admits at most 64 caller slots, and one caller at most 8. With auth off,
every caller is the same anonymous caller and shares one budget of 8. A request that needs a
new slot past either limit is refused (JSON-RPC `-32000`) and counted in
`mcp_backend_identity_slots_refused_total`; it is never served on the shared connection. A
notification is dropped with HTTP 429. Slots free up as idle ones are reclaimed (5 minutes
idle).

**Action:** with auth off, expect at most 8 passthrough credentials served at once per backend.
Turn auth on to give each user their own budget of 8.

## 103. Grant decisions are written to the audit log

**Startup:** no notice

In 3.x, an identity-grant decision on a personal capability reached only the tracing log, and an
allow reached nothing. In 4.0, with a transparency log configured, each such decision writes one
`identity_grant_decision` record (allow `ok`, deny `denied`) with the subject's authority and
subject, the capability, tool, scope, reason and grant id, and the call's `trace_id`. Listings and
public or shared capabilities write none. Under `FailClosed`, a record that cannot be written
answers the call with `-32005`, as an invocation record does.

**Action:** where a SIEM rule or script counts audit records per call, filter on `kind`.

## 104. A session belongs to its subject and credential

**Startup:** no notice

In 3.x, a streaming session belonged to the credential that opened it. Callers that proved
different subjects (an agent JWT `sub`, a trusted identity header, Cloudflare Access, an mTLS
certificate) behind one shared API key or bearer token, or with authentication off, could resume
and delete each other's sessions and read each other's notifications by presenting the session
id. In 4.0 a session belongs to the subject and the credential together, on POST, GET and DELETE
alike. A different subject, or the same subject under another credential, is given a new session.
The credential half is what the caller presented, so a renewed token is another credential: in 3.x
a delegated OIDC bearer kept its session across a refresh, and now it does not. Callers that prove
no subject keep the 3.x behaviour.

**Action:** a client that proves a subject and renews its bearer token mid-session must
re-initialize with the new token and use the new `Mcp-Session-Id`. Other clients need no change.

## 105. A finished task's result is re-checked against current policy

**Startup:** no notice

In the 4.0.0 betas, `tasks/get` returned a finished task's stored result with no invocation
policy, and a repeated task call with the same key answered from the stored task. A tool that was
withheld, a backend that was killed, or a grant that was revoked after the task finished did not
stop either. In 4.0 both paths run the policy for the calls that produced the result before
returning it: the identity grants, the caller's backend scope, the active profile, the kill
switch, capability disable and withheld tools, plus the recovery attestation when enforcement is
on. A refused read returns the policy error and no result.

The task record now lists those calls (server and tool names, never arguments). A
`gateway_invoke` or surfaced-tool task records its call at creation; a playbook or `gateway_execute`
task records the calls it actually dispatched when it settles. A row written by a beta has no
list: its one call is recovered from its upstream descriptor when that is consistent and checked
as above, and a row that holds backend output without recoverable provenance, every such
playbook or `gateway_execute` row included, is refused -32003 (item 120). Only beta task stores contain such rows.

**Rollback:** a record that carries calls is written as version 5, and a failed upstream task
whose error is the peer's own as version 6 (MIK-7887); a version 4, 5 or 6 row makes
a beta (which reads versions 1 to 3) refuse to open the task store, so the gateway does not start.
4.0.0 does not keep those rows readable by the betas. The task store is the directory
`tasks.store_dir` (default `~/.mcp-gateway/tasks`). Back it up before upgrading. Clearing it to
start a beta is destructive: it abandons every task and every task idempotency key, it is not a
migration, and a repeated call then runs again. Restoring an older backup can lose completion and
idempotency knowledge and replay external effects that already completed. 3.x has no task store
and is not affected.

Three client-visible changes follow from that check:

- Under attestation `enforce`, reading a finished task (`tasks/get`, or a repeat of a task-augmented
  call) needs a currently valid token in `_meta["io.mcp-gateway/recovery"].attestation`. Without
  one the read returns -32002 and no result. Under `observe` the read is delivered.
- A task whose dispatch an identity grant refused now reads back as the current grant denial
  (-32004), not as the failure it stored, for as long as the grant stays denied.
- A read of a finished task writes an `identity_grant_decision` record to the audit log when the
  target is a personal capability, beside the record the worker wrote at dispatch; an unchanged
  decision is usually suppressed for 10 minutes (item 117; not across a restart, and not for a
  new task, caller and target key once 4,096 live keys are tracked).

**Action:** none on upgrade. A client that attests calls must send a fresh recovery token in
`_meta["io.mcp-gateway/recovery"].attestation` on every read of a finished task, as it already
does for a working one. Where a SIEM rule counts decision records per call, expect more records
for polled tasks, reduced as item 117 describes.

## 106. Hardened requires a per-caller identity

**Startup:** no notice, applies only to `security.posture: hardened`

`security.posture: hardened` is new in 4.0. Under it, every HTTP MCP request, on `/mcp` (POST,
GET and DELETE) and on `/mcp/{name}`, must identify one caller before its body is read. Any of
these identifies one: a subject proven by an IdP (OIDC or Cloudflare Access), a trusted proxy
header, an mTLS client certificate, an agent JWT, or an API key configured `kind: personal`.
A request that has none is refused with HTTP 403 and JSON-RPC `-32600 "per-caller identity required
(security.posture=hardened)"`.

A shared API key (`kind: shared`, the default), the static bearer token and a dashboard session
are shared credentials, so on their own they are refused. That includes MCP calls from the
dashboard: under hardened, the dashboard needs an IdP or Access subject. stdio is exempt.
`security.posture: standard`, the default, is unchanged.

**Action:** before adopting `hardened`, give every HTTP caller an identity, or set
`kind: personal` on an API key that exactly one person holds:

```yaml
auth:
  api_keys:
    - name: alice
      key_sha256: "sha256:..."
      kind: personal
```

## 107. Gateways can verify and extend each other's signature chains

**Startup:** no notice, the start is refused with its own error, which names the setting or file; refuses to start, only with a backend set to `verify` or `require` and an incomplete chain setting

A backend that is itself a chain-signing gateway can now be verified hop by hop:

```yaml
security:
  signature_chain: {signing_key: "env:CHAIN_SEED", key_id: "gw-edge"}
  remote_server_signing:
    trusted_keys:
      gw-core: {algorithm: ed25519, public_key: "<base64>"}
backends:
  core:
    http_url: "https://core.example/mcp/tools"
    signature_chain: require   # off (default) | verify | require
    chain_origins: [gw-core]
    chain_signer: gw-core
```

For such a backend this gateway sends each call its own random challenge and checks the reply's
chain before anything else reads it: trusted signers, signatures, origin, linkage, content, the
challenge, and freshness within `message_signing.replay_window`. A verified chain is delivered
unchanged, with this gateway's link appended, so the client verifies the whole chain. Under
`require`, a chain that is absent or fails a rule is refused with `-32001`, naming the rule, and so
are an interim reply and a task-augmented call. Under `verify`, the result is delivered with this
gateway's link marked `up: unverified`, which a client verifier refuses. A chain that would exceed
`max_links` or 16 KiB when this gateway appends its link is refused in either mode.

Chained results are not served from the response cache, and an idempotent replay of one carries
no chain. Chaining covers `gateway_invoke` and direct-route `tools/call`, for requests that carry a
chain nonce. Tasks, Code Mode, playbooks and capability backends are not chained.

**Action:** none unless you chain gateways. The three backend settings are refused at startup,
naming the field, when `chain_origins` or `chain_signer` is missing or names a key absent from
`trusted_keys`, or when this gateway has no `security.signature_chain`.
## 108. A delivered `cacheScope` is never `public`

**Startup:** no notice

In 3.x, the direct backend route (`/mcp/{name}`) forwarded a backend's own result unchanged, so a
backend that answered `"cacheScope": "public"` to a call computed from the caller's session reached
the client as `public`, and a shared cache could serve it to other callers. In 4.0 every result the
gateway delivers (HTTP, batch, SSE, stdio, task envelopes and webhook `message` events) is clamped: a
`cacheScope` that is not `"private"` is delivered as `"private"`. A result with no `cacheScope` is
unchanged, and nested tool data is never rewritten. For library users, `CacheScope::Public` now
carries `std::convert::Infallible`, so no value can be built, and `CacheScope::for_list` is removed.
Data persisted before 4.0 with `public` scope, such as a stored task result, keeps its stored value
and is read and delivered as `private`; nothing needs to be flushed.

**Action:** none for clients. A shared cache that relied on a backend's `public` must stop; the
gateway will not vouch for a response it computed from one caller's state. Rust code that named
`CacheScope::for_list` or built `CacheScope::Public` should use `CacheScope::Private`.

## 109. SSRF refusals are typed, and hardened pins backend destinations

**Startup:** no notice; fails a backend, only under `security.posture: hardened` and only a backend at a loopback or private-network address

**Every posture.** When the SSRF guard resolves a destination's name and refuses the address it
gets (a capability endpoint, or a backend under `hardened`), the call now answers JSON-RPC
`-32600` with a message starting `SSRF blocked:`, after one attempt. Before, the refusal looked
like a connection failure: it was tried three times, counted against the capability backend's
health and answered `-32000 "<label> failed: error sending request"`. Ordinary connection failures keep
their retries.

**Under `security.posture: hardened`**, which is new in 4.0:

- `security.ssrf_protection` is forced on and `security.trust_configured_backends` off, whatever
  the file says, so the proxy-time check covers configured backends too.
- HTTP and WebSocket backends connect only to public addresses. A name is resolved once, every
  address it resolves to is checked, and the connection goes to a checked address; a WebSocket
  keeps the configured name for TLS SNI and `Host`. An IP literal is refused before anything
  connects. `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` are ignored for backend traffic, since
  a proxy would resolve the name instead.
- An OAuth backend's authorization server, token endpoint, registration endpoint and every
  redirect hop are held to the same rule.
- So a backend at `localhost`, `127.0.0.1`, an RFC 1918 or unique-local address, or a
  link-local address is refused on its first connect with `-32600 "SSRF blocked: ..."`.
  stdio backends are unaffected.

The policy is applied by the gateway's backend registry. An embedder that builds its own
`BackendRegistry` gets it when it passes the registry to `ReloadContext::new` with a hardened
config; a backend it started before that keeps its connection until it restarts.

**Action:** where a client matched `-32000` for a refused capability destination, match `-32600`.
Before adopting `hardened`, move local backends to stdio, or keep the deployment on `standard`.

## 110. Invocation records name the tenants a call reached

**Startup:** no notice, applies only with `security.firewall.tenant_guard.arg_keys` set

With `arg_keys` configured, the guard does not need to be enabled for this. Every transparency-log
invocation record then names the tenants the call reached, request and response, as sorted
16-hex SHA-256 hashes in `tenants`, next to the kernel's `data_classes`. Raw tenant ids are
never written. At most 1024 hashes are kept; past that the record adds `tenants_total`.

The `attribution` field says how far that list reaches:

- absent: the response was attributed as the backend returned it, before the gates;
- `cached_delivery`: the value was served past the gates, from a cache or an idempotent replay,
  so it is attributed from what was delivered, and carries no `data_classes`;
- `uninspected`: some of the response was not read for tenants. Any string in the response that
  opens like JSON (`{` or `[`) is parsed; it is unread when it is over the 1 MiB parse bound or
  fails to parse, including nesting past the parser's depth limit and bracket-led prose. A
  double-encoded JSON string is decoded and read, up to three layers; deeper encoding is unread.
  A reply refused for its signature chain is also unread. `tenants` still lists what was read. The record carries this even when `tenants` is empty;
- `cached_delivery_uninspected`: both.

**Action:** none unless you consume these records. Under `uninspected`, treat `tenants` as a
lower bound, not a complete list.

## 111. A stdio gateway keeps durable tasks in its own store

**Startup:** no notice; refuses to start, only an HTTP gateway whose `tasks.store_dir` is a running stdio gateway's `stdio` directory

A stdio gateway (`serve --stdio`) now serves the tasks extension for the client that spawned it.
A task-augmented `tools/call` with an idempotency key becomes a durable task, and `tasks/get`,
`tasks/update` and `tasks/cancel` answer on stdio. Before, stdio answered every such call
synchronously and `tasks/*` answered `-32601`.

The store is `<tasks.store_dir>/stdio`, its own directory beside the HTTP gateway's
`tasks.store_dir`, so an HTTP gateway and a stdio gateway on one config never contend for one lease. A
task survives a restart and a moved base directory, and no HTTP caller can read, cancel or update
it: the store keys it under the local operator, a principal no HTTP credential can name.

- A second stdio gateway on the same config finds the store held. It serves as before, answers
  task-augmented calls synchronously, and advertises no tasks extension in `initialize` or
  `server/discover`.
- An HTTP gateway whose `tasks.store_dir` is set to another gateway's `stdio` directory fails to
  start while that gateway holds it. The error names the likely holder.
- `tasks.recovery_adapters` stays an HTTP feature: stdio settles every interrupted task on start.

**Action:** none for separate stores. Give each gateway its own `tasks.store_dir` if two configs
point HTTP at a stdio directory. Back up `tasks.store_dir` with every gateway that writes under it
stopped; the `stdio` subdirectory is inside it.

## 112. Hardened signs every tool call and requires elicitation

**Startup:** refuses to start, only under `security.posture: hardened` and only without a signing secret of at least 32 bytes

Everything here applies only under `security.posture: hardened`; `standard` is unchanged.

- **Signing.** `security.message_signing.enabled` is forced on, whatever the file says, so
  `security.message_signing.shared_secret` must resolve to at least 32 bytes (an env-only
  `${VAR}` reference resolves) or the gateway refuses to start. Every successful `tools/call`
  result whose nonce was admitted, on `/mcp`, on `/mcp/{backend}` and over `serve --stdio`,
  carries the v2 `_signature`. Over stdio the posture is the one the process started with, and
  every `tools/call`, not only `gateway_invoke`, is signed when its nonce is admitted, and
  needs one when `require_nonce` is true (with it false, a call that sends no nonce is not
  replay-checked, as on HTTP); a stdio caller
  is still the operator who spawned the process (SECURITY.md), so signing there proves the
  answer's origin and stops a replayed nonce, it does not change who may call. Its nonce is
  `params._meta["io.mcp-gateway/nonce"]` (`gateway_invoke` keeps `arguments.nonce`; sending both
  is refused `-32602`). A nonce is admitted once, before dispatch, in one replay store for both
  routes: a resent nonce, including on a confirmation follow-up or a retry after a failed
  dispatch, is refused, so send a new one per request (after a task-augmented call's challenge
  the first nonce was never spent, so resending it there is accepted). `require_nonce` stays your choice. A
  malformed nonce is refused `-32602` early, but not first: authentication runs before it on
  both HTTP routes, session admission on `/mcp`, and backend routing and the task-method and
  retry-field checks on `/mcp/{backend}`. It runs before tool policy and dispatch, so a call
  the policy would refuse gets `-32602` for a malformed nonce instead of the policy refusal, and
  is counted as an invalid-nonce rejection. Under `standard` with `message_signing` enabled,
  where only a `gateway_invoke` is signed, its nonce is judged after the invocation policy
  instead, on `/mcp` and over `serve --stdio` alike: a denied call gets the policy refusal and
  counts no nonce rejection. Answers
  given before the nonce is
  admitted are delivered unsigned and leave the nonce unspent: a task-augmented destructive
  call's confirmation challenge or refusal, and on `/mcp/{backend}` a tool-policy or
  undeclared-key refusal. A result that cannot be signed is refused `-32603`.
- **Elicitation.** A legacy (2025-era) client must declare `elicitation` in `initialize`.
  Without it, `initialize` is refused with 403 and `-32600 "client must declare elicitation
  (security.posture=hardened)"` and no session is created. Every other legacy request, and
  `GET /mcp`, is served only inside a session such an `initialize` opened. The direct route
  keeps no session, so it refuses every legacy request except a declaring `initialize`, and
  classifies a request the way `/mcp` does: a modern header over a legacy body is refused.
- **Destructive calls.** A legacy destructive call that nobody can confirm is refused
  (`-32001`) instead of proceeding with a warning.
- **Reload.** A reload that changes the posture is refused with the posture's reason first,
  since changing it also changes what it forces.

**Action:** before adopting `hardened`, set the signing secret, send one fresh nonce per
`tools/call`, and make legacy clients declare elicitation or move them to 2026-07-28.

## 113. A recovered upstream task writes a settlement record

**Startup:** no notice, applies only with a transparency log

A task-augmented call can be answered by the backend with a task of its own. The gateway settles
it later, from the worker that follows the upstream task or from the owner's `tasks/get`. That
settlement now writes its own invocation record, before the result is committed:

- `route: "task_recovery"`, with `server`, `tool` and the gateway `task_id`;
- `correlation_source: "task_id"`, and `session_id` holds the task id;
- `request_hash` is the hash of `{"task_id": <id>}`, since the recovering path does not hold the
  original request; the call's own request hash is on the submission record;
- `response_hash`, `outcome`, `error_code`, `tenants` and `data_classes` as on a live call. A
  recovered result a gate refuses settles as a `-32603` failure; its `outcome` keeps the class a
  live call's record gives that refusal (`denied` for a response-firewall refusal), and
  `error_code` is the code the task committed;
- `who` names only the principal the task was admitted under, with no credential kind.

The submission record carries the same `task_id` whenever the backend's task handle was captured.
Under `FailClosed`, a failed settlement write settles the task `-32005 "audit log unavailable"`
with no backend content. Under `BestEffort`, it is logged and counted in
`mcp_audit_settlement_write_failures_total`, and the task settles as before.

**Action:** none unless you consume these records. Join a settlement record to its submission by
`task_id`. A crash between the record and the commit can leave two settlement records for one
task; it never leaves delivered content unrecorded. The record is written before the commit, so
a commit that then loses (to a cancel that lands first, or a store failure) leaves a record for
a recovery that did not land. A live call has the same window: its record is written
(`src/gateway/meta_mcp/invoke.rs:1219-1221`) before its result is stored for delivery
(`src/gateway/router/handlers.rs:1798`), and stands if that delivery then fails.

## 114. Hardened can name backends that may reach private networks

**Startup:** refuses to start, only under `security.posture: hardened` and only when `security.hardened.private_backends` names a backend that is not configured

New key `security.hardened.private_backends: [backend names]`, default empty, read only under
`security.posture: hardened` (under `standard` it is accepted and has no effect).

- A listed backend may reach loopback (127.0.0.0/8, ::1), RFC 1918 (10/8, 172.16/12,
  192.168/16) and unique-local (fc00::/7) addresses, by literal or by name: names are still
  resolved once and pinned, and redirects and OAuth endpoints are held to the same rule. It
  never reaches link-local (169.254.0.0/16, fe80::/10, which includes 169.254.169.254) or the
  AWS IPv6 metadata address `fd00:ec2::254`, and every other special-use range item 109 refuses
  stays refused.
- Every backend not listed keeps item 109's public-only rule.
- A listed name that is not under `backends` refuses start, naming it.
- `security.hardened` is restart-only: a reload that changes it is refused with
  `config reload refused: security.hardened requires restart`.

**Action:** to adopt `hardened` with a local or in-cluster HTTP backend, add its name to
`security.hardened.private_backends`. List only the backends that need it.

## 115. Sessions expire when idle, and their state goes with them

**Startup:** no notice

`streaming.session_ttl` (default 30 minutes) used to be measured from a legacy session's
creation. A session that only POSTs holds no stream, so a busy one was reaped at that age, and
since 4.0 never adopts a presented id, its next request got a new session on the default routing
profile, losing a profile narrowed by `gateway_set_profile`. The TTL is now idle time: every
request that resumes or acts under the session, on `/mcp` and on the direct `/mcp/{name}` route,
renews it. The reaper sweeps every `streaming.session_reaper_interval` (default 60 seconds) and
reaps a session that has had no request for the TTL and has no open stream at the sweep. An open
stream holds the session but does not renew the TTL, so a session whose stream closes after the
TTL has passed with no request is reaped at the next sweep, not a full TTL later.

When a session ends, by its owner's `DELETE /mcp` or by the reaper, the state kept under its id
is reclaimed: routing profile, workflow state, cost bucket, last-tool entry, cached-token counter
and spec-preview promotions. Before, these were never removed and grew with every session. The
ended session's calls, tokens and cost stay in the operator's aggregate totals. A call still in
flight when the session ends, or one that starts after it (a task worker, an input-round resume, a
call released from a confirmation), holds the session until it finishes; when it does, the state
it wrote under the ended id is removed too, however long it ran. A second pass two minutes after
the end stays as a backstop.

**Action:** none. A client that relied on a session being replaced after 30 minutes should send
`DELETE /mcp` instead.

## 116. Key-server OIDC URLs must be HTTPS off this machine

**Startup:** refuses to start, only when a `key_server.oidc` issuer, `jwks_uri` or `discovery_url` is `http://` to a host that is not loopback

The gateway fetches each provider's discovery document and signing keys from these URLs. Over
cleartext, anyone on the path could swap the keys and mint tokens the key server accepts. Earlier
releases already fetched only over HTTPS (a redirect to `http://` included), so that swap was not
reachable; but the issuer check only logged a warning, and it now refuses at load.

- `key_server.oidc[N] issuer '...' is non-HTTPS and off this machine` (or
  `key_server.oidc[N].jwks_uri` / `.discovery_url`) at load. The `jwks_uri` and
  `discovery_url` are not echoed.
- A token whose `iss` names such an issuer is refused at verification too.
- An https issuer's discovery document that names an `http://` `jwks_uri`, loopback included,
  is refused, as before.
- `http://` to `localhost`, `127.0.0.0/8` or `::1` is allowed, as for backend credentials. It
  was refused at fetch time before, so a loopback `jwks_uri` such as the one in
  `examples/token-exchange-live.yaml` now works. A loopback issuer's discovery document may
  name a loopback `jwks_uri`.
- An issuer that is not a URL (the gateway's own `mcp-gateway`) is unaffected; only its
  explicit `jwks_uri` is fetched and checked.
- A redirect while fetching keys or discovery may only move to `https://`, and a loopback
  fetch follows no redirect and never uses a proxy.

**Action:** use `https://` for every `key_server.oidc` URL, or a loopback host for local testing.

## 117. An unchanged grant decision on a polled finished task is written once per window

**Startup:** no notice, the audit log holds fewer `identity_grant_decision` records, only for repeated reads of a finished task

A read of a finished task (`tasks/get`, or a repeat of a task-augmented call) re-checks the
grants of the calls that produced it (item 105). Each read used to write a decision record, so a
client polling once a second wrote about 86,400 identical records a day for one task.

- A re-check writes no record when the last record written for the same task, caller and
  target is identical in every field but its timestamp and trace id and is less than 10 minutes
  old. A subject's display label is not part of the caller, so relabelling it changes nothing.
- Any change is written at once: a revoked grant, another reason, another grant id.
- An unchanged decision is written again once 10 minutes have passed, so polling stays visible.
- Decisions made while dispatching a call are never suppressed.
- Suppression is held in memory: a restart writes the next decision again, and once 4,096 live
  task, caller and target keys are tracked a new key is recorded on every read.

**Action:** a SIEM rule that counted one decision record per poll should count decision changes.

## 118. The audit log keeps a cut or interrupted high-water finding

**Startup:** no notice, a restart and Live verify report a new `audit_segment_hwm_missing` finding where a tail was lost below `.hwm`

- A restart that finds the newest surviving record below the signed `.hwm` writes
  `audit_segment_hwm_missing`, whether the active file was torn, cut at a line, emptied or
  deleted. The replacement open record carries the finding too, so a crash before the marker
  cannot lose it.
- A torn-tail repair record (`audit_segment_torn_tail_dropped`) whose dropped line `.hwm` had
  already counted carries `committed: true` and is a finding in its own right.
- Live verify also fails when the record at `.hwm`'s counter is not the one `.hwm` recorded.

**Action:** none for a healthy log. Investigate a new finding as tail loss or an edit.

## 119. stdio and WebSocket backends negotiate the protocol revision like HTTP

**Startup:** no notice, a backend that selects a revision the gateway does not speak fails its start

The client proposes a revision and the backend selects one. HTTP already refused a selection
outside the revisions the gateway speaks and retried a version rejection at the highest revision
both sides speak; stdio and WebSocket now do the same.

- stdio: the selection is checked on the first answer and on the retry, and the retry's selection
  is the revision used, not the one the retry proposed.
- WebSocket: a rejection that lists the backend's revisions is retried once on the same socket.
  A rejection that lists none, or none in common, still fails with "WebSocket MCP initialize
  failed".
- stdio diagnostics name the backend's error code, no longer its message, and stdio debug logs
  record line lengths, no longer the backend's lines or the frames sent to it.
- On stdio and WebSocket an `initialize` answer selecting `2026-07-28` is accepted, and the era
  probe settles the dialect. HTTP still requires a legacy selection, because its
  `MCP-Protocol-Version` header follows the selection.

**Action:** a backend that fails to start with "Backend selected protocol version" needs a
revision from the supported list, or a `protocol_version` pin it accepts.

## 120. A task stored by a 4.0.0 beta is re-checked or refused

**Startup:** no notice, `tasks/get` on such a task may answer -32003

A 4.0.0 beta wrote task records (versions 1 to 4) that do not name the backend tool a result
came from. A read of a finished task re-checks those tools against current policy (item 105).
A beta row that went to an upstream task keeps a descriptor naming its one call, and that call
is checked. Any other beta row has nothing to check, since the backend's current tool list is
no record of what ran, so it is refused, plan or single call, unless it holds no backend output.

**Action:** re-run a refused call under a new idempotency key (the old key finds the refused
row). Nothing for an upgrade from 3.5.x.

## 121. A task still running when the shutdown drain runs out is cancelled

**Startup:** no notice, a long task is cut off at shutdown instead of running on

Before, a task whose backend call outlasted `server.shutdown_timeout` kept running after the task
store closed, and could still call its backend while the backends were stopping. Now the drain
cancels it, waits a bounded time for it to end, and only then closes the store; on HTTP the drain
and the cancellation together take at most nine tenths of `server.shutdown_timeout`, so the drain
itself now gets four fifths of it; on stdio both fit what is left of the EOF teardown window. The record stays `working` until the next start settles it through the
interrupted-task table (`gateway_restart_after_dispatch`, or `gateway_restart_before_dispatch` when
the task was cancelled before it reached the backend); a task whose backend is a configured `tasks.recovery_adapters`
entry with a durable upstream handle stays managed `working`, as after any restart, and an owner
`tasks/get` resolves it. This applies to HTTP shutdown and to stdio EOF.

**Action:** none. Raise `server.shutdown_timeout` if long tasks should be allowed to finish.

## 122. Capability fallback providers are warned as not executed

**Startup:** no notice, a capability that declares `providers.fallback` logs a CAP-011 warning and is still served; fails a capability file, only when a fallback entry does not parse (null included)

A capability YAML could list `providers.fallback`, and the gateway parsed and validated it, but
calls were only ever sent to `providers.primary`. That is unchanged in 4.0: a fallback is not
tried when the primary fails. Loading such a capability now says so instead of accepting the
block silently. A fallback entry that does not parse as a provider used to be dropped without a
word; it now fails the load of that capability, like a malformed `primary`. An empty list declares
no provider and loads without a warning.

**Action:** delete the `fallback` block from your capability files, and fix or delete any entry
that does not parse.

## 123. Unread capability provider keys are warned, and `cap validate` checks structure

**Startup:** no notice, a capability with a provider key the gateway does not read logs a CAP-012 warning per key and is still served

A key under `providers.<name>` that no provider field reads (a misspelled `methd`, say) used to be
dropped without a word. It now logs CAP-012 naming its path, for example
`providers.primary.config.methd`. Keys starting with `_` or `x-` are notes and are not reported.
Capabilities that declare `command`, `args` or `transport` warn too until this gateway version reads
those keys.

`mcp-gateway cap validate` used to run only the basic check and print "valid". It now runs the same
structural checks as the loader: it prints each warning, and exits non-zero on a structural error,
the same file the loader would skip.

**Action:** fix or delete the keys CAP-012 names. A script that runs `cap validate` should expect a
failure for a file the loader would refuse.
## 124. The built-in server registry points at servers that exist

**Startup:** no notice

`mcp-gateway add <name>` and the dashboard's registry tab read a built-in list of servers. Of its
45 npm packages, 30 did not exist on npm and 7 were deprecated, and none was pinned to a version.
Every entry is now a pinned npm or PyPI release or a vendor-hosted URL, and CI looks each one up.
Backends already in your `gateway.yaml` are not touched; this changes only what `add` writes.

Repointed to the vendor's own package or hosted endpoint: tavily, brave-search, postgres, redis,
github, gitlab, linear, sentry, asana, aws, cloudflare-workers, slack, fetch, semgrep, playwright,
notion, airtable, stripe, pinecone, qdrant. Pinned: exa, perplexity, filesystem, mysql, memory,
sequential-thinking. `jira` is now `atlassian` (Atlassian's hosted Jira and Confluence server).

Removed, because no maintained server exists at a resolvable package:

| Name | Reason |
|---|---|
| everything-search | pointed at the MCP protocol test server, not a search tool |
| sqlite | reference server archived upstream, no release since 2025-04 |
| surrealdb, discord, wikipedia, 1password, snowflake | no published MCP server package |
| gcp, bigquery, gmail, google-calendar, google-drive, google-sheets | packages never existed or are deprecated; Google services are covered by the bundled Google capabilities |
| puppeteer | deprecated upstream; use `playwright` |
| pieces | package does not exist |
| openai | package does not exist; the gateway is not a chat-completion gateway |
| datadog | the hosted endpoint is labelled unstable and its login flow is undocumented |
| pagerduty | the vendor's server repository is archived |

**Action:** none for existing configs. To keep using a removed server, add it with an explicit
command or URL: `mcp-gateway add <name> -- <command>` or `mcp-gateway add --url <url> <name>`.

## 125. A listen stream opens with the acknowledgement notification

**Startup:** no notice

A 4.0 beta answered `subscriptions/listen` with a JSON-RPC response as the first event on the
stream. The 2026-07-28 specification defines that response as the end of the subscription, so a
conformant client saw its stream close as it opened. The first event is now a
`notifications/subscriptions/acknowledged` notification: the subscription id is in
`params._meta` under `io.modelcontextprotocol/subscriptionId`, and `params.notifications` names
what the gateway delivers (`toolsListChanged`, and the task ids it accepted under `taskIds`).
Prompt and resource changes are not delivered, so they are not acknowledged.
When the gateway itself ends a subscription (for example, its credential stops
authenticating), the last event is the listen request's own response, a `complete` result,
which the specification defines as a graceful end. A reader that falls too far behind has lost
updates, so its stream just closes, with no response.

**Action:** a client written against the beta that read the subscription id from the response
`result` reads it from the notification instead.
## 126. `add` writes the whole server, and leaves it off when it cannot start

**Startup:** no notice

`mcp-gateway add <name>` for a built-in server used to write only its command or URL. The gateway
starts a stdio server with a cleared environment, so a server that needed `TAVILY_API_KEY` started
without it, while `add` printed the key as set. Now `add` writes:

- for a stdio server, `env: { NAME: "${NAME}" }` for each variable it needs (or the value you gave
  with `-e NAME=...`);
- for a hosted server that logs in with OAuth, `oauth: {}`, so the first use opens the login in a
  browser; for one that takes a token in a header, the header with a `${VAR}` reference (or the
  value from `-e`);
- `streamable_http` as the endpoint speaks it, for a registry server; for `--url`, nothing, and the
  gateway detects the transport at connect (item 148).

`add` writes the server **disabled**, and prints why, when a `${VAR}` it wrote does not resolve
(unset or empty in the environment and every `env_files` entry), because an enabled backend with an
unresolved reference stops the gateway from loading its config. Playwright, Chrome DevTools and
fetch are always added disabled: they can open any address, and the private-network guard covers REST capabilities
only. Git is added disabled too, because without `--repository <path>` it acts on any repository a call names. Turning a backend on from the dashboard is refused, naming the variable, while one of its
references does not resolve.

`mcp-gateway init` (local profile) now writes the servers that need no account enabled: memory,
sequential-thinking, context7 and time. A server whose launcher (`npx`, `uvx`) is not on PATH is skipped
with a message. `mcp-gateway list --available` lists the whole library.

**Action:** none for existing configs. After `add`, set any variable it names, then set
`enabled: true` on the server.

## 127. CLI capabilities run local processes

**Startup:** no notice, a capability that declares `service: cli` is served and runs its command when called

Through 3.x a capability with `service: cli` loaded but never ran its command: the gateway treated it as
REST with an empty URL. It now runs the command, under these rules:

- Only a pinned capability (`sha256:` matching the file) runs a process. An unpinned one is refused.
- The command and its leading fixed arguments must match an entry of `capabilities.process_commands`
  exactly. The default list holds the commands of the shipped catalogue; setting the key replaces it.
- No shell is involved. Each call runs in a fresh private directory that is also its `HOME` and temp
  area, with a cleared environment plus the names the capability lists, and is killed with every
  process it started when it times out or its output passes the cap.
- A parameter that names a file must resolve inside the configured `capabilities.files.<root>`; no root
  is configured by default. The check canonicalizes the path, then the child opens it: a local process
  that can write inside a root can swap a path for a symlink between the two, so no other user (by
  owner, group or ACL) may write to a root (`uploads`, `projects`, `downloads`) or to any directory
  above it. An `mcp` capability whose server scopes its file access to one root names that root under
  `root_env` (variable: root), for example `OPENPENCIL_MCP_ROOT: projects`: the server starts with the
  canonical root path, a changed root restarts it, and an unset root sets nothing. A parameter that names a
  network destination makes the capability refuse to run, because the gateway cannot confine where a
  child process connects.

**Action:** to keep 3.x behaviour, set `capabilities.process_execution: disabled`. To run your own CLI
capabilities, pin them (`mcp-gateway cap pin`) and list their commands in
`capabilities.process_commands` (the list then replaces the default).

## 128. Backend upstream events are refused where the gateway cannot listen

**Startup:** no notice, a subscription to such an event answers -32014

MCP Events turns a backend's `notifications/resources/updated`,
`notifications/resources/list_changed` and `notifications/prompts/list_changed` into the events
`backend.<name>.resource_updated`, `backend.<name>.resources_changed` and
`backend.<name>.prompts_changed`, listened for on one shared connection per backend while an
event subscription needs it (stdio, WebSocket, streamable HTTP). A `resource_updated`
subscription names a `uri` from the backend's own resource list; bursts of one kind become one
event per second.
The four kinds of backend below do not offer them in 4.0, and say why:

| Backend | `data.reason` | Why |
|---|---|---|
| `http_url` without `streamable_http: true` (the SSE handshake, `/sse` or not) | `sse_handshake_transport` | the handshake stream is read only up to its `endpoint` event |
| `a2a_url` | `a2a_transport` | A2A carries no MCP notifications |
| an `identity_propagation` block (`required: false` included), or an `account` whose descriptor is `personal_managed` or `external` | `identity_propagation` | the shared connection would observe under the gateway's credential, not the subscriber's |
| a per-user OAuth login (`oauth` without `shared_account: true`), on a multi-user gateway | `per_user_credential` | as above: the credential is one person's |

`events/list` does not list these names for such a backend. `events/subscribe` on one answers
`-32014 Unsupported` with `data = {"feature": "backendEvents", "value": <name>, "reason": <reason>}`,
before any callback traffic, to a caller who may reach the backend; any other caller gets
`-32011`, the answer for a name that does not exist. A disabled backend (`enabled: false`) is
absent and also answers `-32011`.

**Action:** set `streamable_http: true` on an HTTP backend that speaks streamable HTTP. For the
others, poll `resources/list` or `prompts/list` instead.

## 129. A capability that needs a login is listed once the login exists

**Startup:** no notice

The bundled catalogue is a library: it ships capabilities for many services, and most need an
account. A capability that declares `auth.required: true` used to be listed whether or not its key
existed, so a new install showed tools that could only fail. It is now left out of `tools/list` and
search until its credential exists:

- an `env:NAME` (or `{env.NAME}`, or bare `NAME`) key whose variable is set and non-empty in the
  environment or an `env_files` entry;
- an `oauth:<provider>` key whose provider has a stored login.

A `keychain:` or `file:` key, and a per-caller account credential, cannot be checked without reading
a secret or knowing the caller, so those capabilities stay listed. Calls are unchanged: a hidden
capability invoked by name behaves as before.

**Action:** if a capability you use disappeared from the list, set the variable it names; supplying
the key lists it again. `mcp-gateway cap list` marks each one the gateway would not list, with
`off: needs <KEY>` (or `off: needs a <provider> login`).

## 130. Frames naming a second tenant for one caller are recorded, or withheld

**Startup:** no notice, applies only with `security.firewall.tenant_guard.arg_keys` set

With `arg_keys` set, every frame the gateway sends a caller is checked for the tenants it names:
answers and errors, notifications, server-to-client requests and webhook deliveries, on HTTP, the
POST and GET streams, the direct route and stdio. Content the gateway read but did not show
(before a capability transform, a cache or idempotency replay, a stored task's output) counts
too, and a response it could not read counts as a tenant of its own. When one `caller_key`'s
frames name more than one tenant inside `window_secs`, the new key
`tenant_guard.cross_tenant_reads` decides: `observe` (the default) writes a `tenant_read`
audit record with `cross_tenant_read: flagged` (for an answer on `POST /mcp`, `/mcp/{name}` or stdio, the same fields ride the answer's own `response_delivery_attempt` record, written over the frame the judge left, so it costs no second record), `block` withholds the frame with a JSON-RPC
error, and `off` checks nothing. A caller with no identity is recorded as `unattributable`.
On those three routes a dispatched answer that names a tenant writes no `event: tenant_read`
record: its read fields (`caller_key`, `tenants`, `attribution`, `cross_tenant_read`) ride its
`response_delivery_attempt` record. Notifications, server requests, stream events and the few
errors stdio builds before dispatch (a bad signing envelope) still write a standalone `tenant_read`
record. So an audit rule that counts reads selects either event carrying `tenants` or
`attribution`, and one that flags anomalies matches `cross_tenant_read` on either event.
Tenant ids are compared across backends, so two backends that reuse one id count as one tenant.
Name tenant fields that appear inside backend content in `arg_keys`. The judge scans the document that is emitted, so a configured name equal to a wrapper member (`message`, `method`, `source`, `event_id`) also attributes, for responses, notifications and non-message stream events (#2846). A webhook subscription made while the check was off has no caller key until it renews, so its deliveries that name a tenant count as unattributable.

**Action:** none. Set `off` to silence it, or `block` to withhold such frames; namespace tenant
ids that two backends reuse.

## 131. A webhook route without a `method` accepts POST

**Startup:** no notice, decided per capability file

A capability file's `webhooks:` route that omits `method` now accepts `POST`, the default its
documentation always named. It used to accept only `GET`, so a webhook sender, which POSTs,
was answered 405. Routes that name `method` are unchanged, and so are REST provider calls,
which still default to `GET`.

**Action:** a route that relied on the `GET` default needs `method: GET`.

## 132. Google Workspace capabilities run through gws

**Startup:** no notice, the `gws_*` capabilities are served and run `gws` when called

These capabilities loaded in 3.x but never ran. Each is now pinned and runs one `gws` subcommand with structured arguments. Their input schemas were rewritten to the parameters the tool accepts, and defaults declared in a schema now fill missing parameters.

**Action:** install `gws`, sign in, and update callers to the new parameter names.

## 133. cloudflare_manage is replaced by Cloudflare REST capabilities

**Startup:** no notice, `cloudflare_manage` no longer appears in the catalogue

The MCP package it declared was never published, so it could not run. Eleven REST capabilities (DNS records, WAF rules, R2 buckets and objects, and zone and account listings) replace it, one HTTP method per file.

**Action:** switch to the `cloudflare_*` capability for the operation you need and pass the account or zone.

## 134. metacognition_verify is removed

**Startup:** no notice, `metacognition_verify` no longer appears in the catalogue

It depended on a tool that is not published, so it could not run on any other machine.

**Action:** none, unless you use that tool privately; keep your own pinned copy of the capability file.

## 135. Two network-reaching CLI capabilities are held

**Startup:** no notice, the capabilities load and refuse at call time

A child process can follow a redirect or a DNS rebind to a private address, and the gateway cannot stop it from outside. Until the tool refuses private addresses at connect time (MIK-7788), `trawl_extract` returns `not executable`, and `cisco_scanner` does not offer `scan_mcp_server`: a call is refused with a message naming `scan_skill_file` and MIK-7788. The default `capabilities.process_commands` list does not admit `trawl` or `mcp-scanner remote` either, so a capability you pinned yourself that runs one of them is refused until you list it (an entry is a `command` plus `args_prefix`, for example `mcp-scanner` with `--analyzers yara remote`; setting the key replaces the shipped list, so keep the shipped entries you still need). No 3.x release ran `service: cli` capabilities, so nothing that worked before stops working.

**Action:** none.

## 136. Attachment capabilities save to a configured directory and return Google's field names

**Startup:** no notice, `gmail_save_attachment` refuses until `capabilities.files.downloads` is set

The embedded script that wrote a caller-chosen path is gone. A declarative `save_file` step decodes the payload, accepts one portable file name, never overwrites or follows a link, writes mode 0600, and stops at `downloads_quota_bytes` (default 1 GiB). The saved path is returned, never the bytes.

**Action:** configure the downloads directory; update readers of `calendar_get_attachment` to Google's field names.

## 137. Stdio backends have a message size limit, set per backend

**Startup:** no notice, the limit applies to every stdio backend from the first message

Through 3.x the gateway read a stdio backend's output line by line with no ceiling, so a peer that never sent a newline could grow its memory without bound. A message (one line) over 16 MiB now fails the call and stops that backend's process; the error names the backend setting.

**Action:** a backend whose single responses can exceed 16 MiB (a large base64 payload or export) sets `max_frame_bytes` under `backends.<name>`, for example `max_frame_bytes: 67108864`. The range is 64 KiB to 1 GiB, and it is valid only on a backend declared with a `command`.

## 138. `OidcError` gained three variants

**Startup:** no notice, a library API change rather than a change to running behaviour

`mcp_gateway::key_server::oidc::OidcError` is a public enum, and it is not `#[non_exhaustive]`. Since 3.5.x it has three new variants, all unit variants with no payload because the refused URL is never echoed (it can carry userinfo, a path or a query): `InsecureIssuer` (a provider issuer that is cleartext and off this machine), `InsecureFetch` (a discovery or JWKS fetch that names such a URL) and `ClientUnavailable` (the HTTP client could not be built at startup). A `match` on `OidcError` that lists every variant and has no wildcard arm no longer compiles. The gateway binary and its configuration are not affected.

**Action:** an embedder that matches on `OidcError` adds the three arms, or ends the `match` with `_ =>`. Treat all three as a refusal of the token or the provider, the same as `InsecureJwksUri`.

## 139. A catalogue relay refusal answers HTTP 403 on the meta route

**Startup:** no notice, the status changes for a refused catalogue read from the first request

With relay detection set to `block`, a `prompts/get` whose arguments, or a `resources/read` whose URI, carry content another caller was delivered is refused with JSON-RPC error `-32002`. On the meta route that refusal used to travel as HTTP 200 with the error in the body, while the same refusal of a `tools/call` answered 403. Both now answer 403. The JSON-RPC error code and message are unchanged, and the direct route already answered 403.

**Action:** a client that reads the HTTP status of a meta-route catalogue read and treats 200 as "the call was answered" should handle 403 as a refusal and read the JSON-RPC error from the body, as it already does for a refused `tools/call`. A client that only reads the JSON-RPC body needs no change.

## 140. `backend_ok` on a provenance receipt is optional

**Startup:** no notice, a library API and receipt-format change rather than a change to running behaviour

`mcp_gateway::trust::RuntimeProvenanceReceipt::backend_ok` was a `bool`. It is now `Option<bool>`: an event receipt (`subject_kind: event`) carries `None` and its JSON has no `backend_ok` field, because an event is a delivery, not a tool result, and nothing observed a success. Through the 4.0 betas an event receipt signed `backend_ok: true`. Runtime receipts are unchanged on the wire (`true` or `false`, same field position), so stored receipts and their signatures still verify and read. Replay scoring abstains on an event receipt, and on any receipt without the field.

**Action:** an embedder that reads `receipt.backend_ok` as a `bool`, or sets it, uses `Option<bool>` (`Some(true)`, `Some(false)`). A verifier treats a missing `backend_ok` as not observed, never as success.

## 141. A successful capability result loses the credentials the gateway injected

**Startup:** no notice, the first successful `cli` or `mcp` capability call returns the redacted result

A `cli` or `mcp` capability is started with credentials the gateway injects (an `env` value, or the resolved `token_env`). Before 4.0 a tool that echoed one of them in a successful result handed it to the caller. Now every string value and key of the result that contains an injected value has it replaced with `[redacted]`, and the rest of the document is unchanged; numbers are redacted only for an injected value of 4 or more digits, either a number that contains it or one equal to it by value, since a child that prints `012345` as a JSON number writes `12345` (an injected `0042` therefore redacts every number 42 in the result). The sign is ignored on that comparison, since an injected value has none: -42, 42.0 and -42.0 are redacted as well. A redacted key that collides with another is renamed `[redacted]#2`, `#3`, and so on. A credential-shaped value the gateway did not inject (one the child read from elsewhere) is not removed here: it reaches the response firewall whole, as on every other route, so the firewall's rules, its Block and its audit finding apply to it; the same holds for the error excerpt of a failed `cli` or `mcp` call, except that a credential the 2 KiB excerpt cut would split is dropped whole. With the firewall off, or `credential_redaction` off, such a value reaches the caller unchanged, as a REST capability result does. Values the caller sent are left in place, since a tool legitimately returns them. The match is literal: a credential the child encodes (base64, URL escapes) or splits across values is not found.

**Action:** a capability whose tool must return an injected value can no longer do so through the result; read the value from its own source instead. A client that compares results byte for byte should expect `[redacted]` where an injected value used to appear.

## 142. `ConfirmationOutcome` gained `Undelivered`

**Startup:** no notice, a library API change rather than a change to running behaviour

`mcp_gateway::gateway::destructive_confirmation::ConfirmationOutcome` is a public enum, and it is not `#[non_exhaustive]`. `require_destructive_confirmation` now answers `Undelivered` when the question never reached a client (no live session could carry it), and keeps `Unsupported` for a question that was delivered but not answered (it timed out, or its channel closed). The gateway refuses or proceeds on both the same way; under hardened signing it gives the call's nonce back only after `Undelivered`, since a delivered question may have been seen. A `match` that lists every variant and has no wildcard arm no longer compiles.

**Action:** an embedder that matches on `ConfirmationOutcome` adds an `Undelivered` arm that does what its `Unsupported` arm does, or ends the `match` with `_ =>`.

## 143. `gateway_search_tools` rows are tools or events, and `limit` caps both

**Startup:** no notice, a changed output schema and a shorter answer when events match

With MCP Events enabled, a search answer adds an event row for each matching event after the tool
rows. The published output schema described tool rows only, with `server`, `tool`, `description`
and `score` required, so a client validating against it rejected an answer holding an event row.
Each row is now `anyOf` a tool row or an event row (`kind: event`, `name`, `description` required,
`inputSchema` optional). Event rows were also added up to `limit` on top of `limit` tool rows; the
answer now holds at most `limit` rows in all, tools first. `total_available` still counts every
match.

**Action:** a client that reads `items.properties` reads `items.anyOf[0].properties` for tool rows
and `items.anyOf[1]` for event rows. Raise `limit` to see more event rows when tools fill it.

## 144. A capability's pin state and process configs are read-only outside the crate

**Startup:** no notice, a library API change rather than a change to running behaviour

`mcp_gateway::capability::ProvidersConfig` carried two public fields: `process`, the typed
configuration of each `cli` or `mcp` provider, and `integrity`, the pin state of the file the
definition came from. A process provider runs only when `integrity` is `Integrity::Verified`, so a
program built on the crate could set that field on a definition it built itself and run a local
process from a definition that never passed the pin check. Both fields are now crate-private. They
are read through `ProvidersConfig::process()` and `ProvidersConfig::integrity()`, and only the
capability loader sets `Verified`. A definition deserialized or built any other way stays
`Unpinned`, as before. The loader also records a fingerprint of the whole definition, and a
process runs only while the definition still matches it: a verified definition cloned and then
changed (its schema, arguments or any other field) is refused. For a process provider the response
cache keys on the same fingerprint, so a different definition under the same name never reads
another's answers. Other providers keep the epoch key: on an executor with no shared policy epoch,
or for a request that snapshotted the epoch before a replacement, a REST call can still return the
answer the earlier definition cached, within its TTL. That answer is stale, but no process starts
and no request goes out.
The gateway's own response cache keys on the policy epoch a request snapshots when it starts:
a request that began before a replacement can still be answered from the earlier, pinned
definition's cache entry (it is ordered before the replacement), and one that begins after it
never is. `CapabilityBackend::register_capability` replacing a definition of the same
name now also drops the answers cached for it and stops its running `mcp` children, so an
unpinned replacement meets the process check instead of the pinned original's cached result. Its children are stopped on the runtime that started them:
keep that runtime driven, or drop it. A runtime that is kept but no longer driven (a current-thread
runtime after `block_on` returns) stops them only when it next runs. Dropping it drops the queued
stop, and a child's whole process tree ends when the last holder of that child lets go; a call
still in flight elsewhere keeps the child running until that call is released (MIK-7923, to be
fixed in 4.0.1).

**Action:** an embedder that read `providers.process` or `providers.integrity` calls the getter of
the same name. One that set `integrity`, or that edits a loaded definition before running it,
loads the definition it means to run through the capability loader, which checks its `sha256:`
pin.

## 145. The `plugin` command and the `marketplace` config block are removed

**Startup:** no notice, a removed CLI surface (a leftover `marketplace` block logs one warning, not the upgrade notice)

`mcp-gateway plugin search`, `install`, `uninstall` and `list` are gone. `install` downloaded a
manifest and wrote it under `marketplace.plugin_dir`, but no gateway path ever loaded what it
wrote: an installed plugin added no backend, tool or capability. The default marketplace,
`https://plugins.mcpgateway.io`, does not resolve. The flags and variables that went with the
command (`--marketplace-url`, `--plugin-dir`, `MCP_GATEWAY_MARKETPLACE_URL`,
`MCP_GATEWAY_PLUGIN_DIR`) are gone with it.

- **`marketplace` in the config file is a retired key: it loads, does nothing, and warns once**,
  on start and on reload, with `` `marketplace` is ignored since 4.0: the `plugin` command was removed in 4.0, and nothing else read this block: no gateway path loaded the plugins it installed. Remove the marketplace block. ``
- **Library break:** the `mcp_gateway::registry::marketplace` module and
  `mcp_gateway::config::MarketplaceConfig` are removed, and `Config` has no `marketplace` field.

**Action:** delete the `marketplace:` block and the `~/.mcp-gateway/plugins` directory (or your
`plugin_dir`). Add tools as `backends:` entries or as capability files (`mcp-gateway cap`), which
the gateway does load. Drop `plugin` calls from scripts.

## 146. Cleartext OAuth authorization servers and credential-bearing capability URLs are refused

**Startup:** no notice, decided per backend and per capability file; fails a backend, at connect, with one warning, and the gateway starts without it; fails a capability file, with one warning that names the field

A client secret, an authorization code and a refresh token are bearer material: anyone on the
path can replay them. 4.0 already refused an OAuth bearer to an `http://` backend off this
machine (item 8 and the OAuth transport guard). The authorization server the backend points at
was not held to the same rule, and neither was a capability's own API.

- **OAuth authorization server:** the authorization server a backend advertises, and the
  authorization, token and registration endpoints that server advertises, must be `https://`, or
  `http://` on a loopback host. These URLs come from discovery documents, so the check runs when the backend
  connects, not at config load. A refused backend fails with one warning naming the endpoint
  (`OAuth token_endpoint is cleartext http:// to a host off this machine`), and the gateway starts
  without it. A redirect from any OAuth request to such a URL is refused the same way, under
  every destination policy.
- **Capabilities:** a capability with `auth.required: true` whose
  `providers.<name>.config.base_url` or `endpoint` is `http://` to a host off this machine fails
  to load, with a warning naming that field. A URL built from a caller's parameters is checked
  when it is called, before the credential is read. The REST, GraphQL and JSON-RPC paths and the
  capability OAuth refresh all apply it. A capability with no credential (`auth.required: false`)
  is held to the same rule when a header, query parameter or body template fills in a gateway
  secret (`X-Api-Key: '{env.KEY}'`, `key: '{keychain.svc}'`); the warning names that template
  field as well as the URL field. Otherwise it is not affected, except that no capability
  request that started on `https://` or loopback follows a redirect to `http://` off this
  machine. A loopback request no longer goes through
  `capabilities.egress_proxy`.
- **Loopback** is `localhost` (any case), `127.0.0.0/8` and `[::1]`, the same classifier as the
  backend guard. `localhost.` (trailing dot), `*.localhost`, `localhost.localdomain` and
  IPv4-mapped IPv6 (`[::ffff:127.0.0.1]`) are not loopback here: a name that has to go through a
  resolver is not known to stay on the machine. An `http://` loopback authorization server is
  reached directly, never through `HTTP_PROXY` or `ALL_PROXY`.

**Action:** if a backend's authorization server or a credential-bearing capability used plain
`http://` off this machine, move it to `https://`, or run it on a loopback host. There is no
override: `allow_cleartext_credentials` covers a backend's own static credentials only. If either
ran over cleartext before, treat the client secrets, refresh tokens and API keys it sent as
exposed and rotate them.

## 147. Non-object capability output roots arrive under `items`

**Startup:** no notice

MCP 2025-11-25 restricts a tool's `outputSchema` root to `type: "object"` and
types `structuredContent` as a JSON object; a client that checks this can refuse
the tool, or the whole `tools/list`. A capability whose `schema.output` declares
a root `type` other than `object` is now shown as

```json
{"type": "object", "properties": {"items": <declared schema>}, "required": ["items"]}
```

and its result is published as `{"items": <result>}` in `structuredContent`. The
text content still carries the result in its declared shape, and output
validation still checks it against the declared schema.

The shipped capabilities this changes: `country_info`, `hackernews_ask`,
`hackernews_show`, `hackernews_top`, `number_facts` (a string root),
`public_holidays`, `sentry_list_issues`, `uuid_generate` and `wayback_cdx`. A
capability file of your own changes the same way when its root is not
object-shaped: an array or scalar `type`, a type list such as
`["object", "null"]`, or no `type` and no `properties` (a root `anyOf`, say).
The nested schema is given an `$id` of the form
`urn:mcp-gateway:declared-output:<content hash>` when it has none (or has
`""` or `"#"`), so its own `#/...` references still resolve inside it; a root
`$schema` is repeated on the wrapper. A schema in the draft-04 dialect, which
scopes references with `id` rather than `$id`, is not covered. A root with `properties` and no `type` is
advertised with `type: "object"` added and is otherwise unchanged.

## 148. An `http_url` backend detects its transport when `streamable_http` is unset

**Startup:** no notice, decided per backend at connect, with one warning when a configured transport is refused and the other answers

An `http_url` backend with no `streamable_http` key POSTs `initialize` first
(Streamable HTTP) and falls back to the legacy SSE `GET` only when that POST is
refused with a 4xx other than 401, 403, 407, 408 or 429; those are about the
credential or a retry, not the transport. `add --url` no longer writes
`streamable_http: false`, so a server added that way connects over Streamable
HTTP when it speaks it.

An explicit `true` or `false` is still tried first. When the server refuses it
with such a 4xx, the other transport is tried once, and a warning names the
backend and the value to set. A config the old `add --url` wrote keeps
working; to skip the refused request, set the value the warning names or remove
the key.

MCP Events (`backend.<x>.resource_updated`, `resources_changed`,
`prompts_changed`) follow the transport the backend actually connected with.
While no connection has detected it, `events/list` lists a backend's events
provisionally, and `events/subscribe` starts the backend first, as a
`tools/call` would, bounded by the backend's `timeout`. Over Streamable HTTP
the subscription is accepted; over the legacy SSE handshake it is refused with
`-32014` `sse_handshake_transport`; a start that fails or times out, or a
circuit that is open, answers `-32000`, as `tools/call` does. An explicit
`streamable_http: false` that never connected is refused as before. A
connection that later switches to SSE withdraws the backend's subscriptions.

Library users: `TransportConfig::Http::streamable_http` is now `Option<bool>`.

## 149. A failed meta-tool call sets `isError` on the `tools/call` result

**Startup:** no notice

A meta-tool result whose payload says `isError: true` (a failed
`gateway_invoke`, or a backend's own tool error) now carries `isError: true` on
the outer `tools/call` result. It was always `false`, with the failure only in
the text.

A client that read failure from the text alone keeps working. One that treated
`isError: true` as a protocol failure should read the text and its `recovery`
hint instead.

## 150. `resolve_args` takes the tool's input schema

**Startup:** no notice

`mcp_gateway::cli::invoke::resolve_args` gains a fourth parameter,
`kv_schema: Option<&Value>`. With a schema, a `key=value` value is typed by it as a
gateway call coerces it (`count=007` against an integer is `7`, `flag=TRUE` against a boolean is
`true`, `zip=007` against a string stays `"007"`); JSON from `--args` or stdin is left as
written. `None` keeps the old behaviour. `mcp-gateway invoke` passes the tool's schema.

## 151. Keyless legacy clients without a session share one anomaly history

**Startup:** no notice

This applies when `security.firewall.anomaly_detection` is on, `anomaly_block_threshold` is
set, and legacy clients call the gateway without a credential: either authentication is off,
or it is on and the path they call is listed in `auth.public_paths` (the shipped presets list
`/mcp`). In 3.x such a client that sent no `mcp-session-id` was given a new session on every
request. Anomaly scoring followed that session, so each call was the first in its session: it
scored 0.5 and built no history, and a block threshold above 0.5 never blocked it. In 4.0
every keyless legacy request that does not resume a session the gateway issued is scored as
one shared caller. The calls of all such clients form one sequence, and the block threshold
applies to them together. A client that keeps the `mcp-session-id` its `initialize` returned
keeps its own history, as before, and a client that presents an API key or token is scored
under its own credential.

If such clients are now refused, give them a credential (turn authentication on, or have them
present a key on a public path), have them reuse their session, raise
`anomaly_block_threshold`, or remove it to log without blocking. The 4.0 tenant guard
(`tenant_guard`) and call budget (`budget`) count these clients the same way. With
authentication off, budgets are best-effort; turn authentication on for per-caller
enforcement.

## 152. A stepped weekday field in a cron expression matches only its own days

**Startup:** no notice, scheduled jobs and `schedule.tick` timers with a weekday step from `*/2` to `*/13`, other than `*/7`, fire on fewer days

A weekday step `*/n` matches a day when `n` divides its number (Sunday 0 to
Saturday 6). The scheduler also tested each day's number plus 7, meant as
Sunday's alias, so a step matched a day when `n` divided either number:
`0 9 * * */2` ran every day, and `*/3` ran on five days instead of three. It
now tests 7 for Sunday only, so `*/2` matches Sunday, Tuesday, Thursday and
Saturday, as cron defines it. `*/8` to `*/13` each lose one day. `*/1`, `*/7`
and `*/14` or more match the same days as before.
3.x had the same behaviour.

Check every scheduled job and `schedule.tick` subscription whose weekday field
uses `/`. If it was meant to run every day, use `*` instead.

## 153. Two credentials may not share one principal

**Startup:** no notice, the start is refused with its own error, which names both credentials; refuses to start

A configured bearer token or API key is identified by the first 48 bits of its SHA-256 digest,
and sessions, grants, journals and task owners are keyed on that principal. Two credentials
with the same principal, such as one key listed twice under two names, were one caller: in
3.5.0 and 3.5.1 each could attach to the other's sessions, and in the 4.0.0 pre-releases each
could also read and cancel the other's tasks. Config load, reload and startup now refuse such
a configuration, naming the two credentials and never a secret or digest. The check covers
the bearer token and API keys configured together. Identities issued at runtime cannot
collide with them (item 155). A principal that a removed credential once held is not
checked. The encoding of configured principals is unchanged, so existing sessions,
grants and tasks stay readable. Remove the duplicate entry, or replace one of the two
credentials.

## 154. A retry after a lost round is told the outcome is uncertain

**Startup:** no notice

A call that carries an idempotency key and fails after its request may have
reached the backend keeps its key settled, so a same-key retry never runs the
work twice. What the retry is served changed:

- When nothing that came back shows whether the work ran (a broken stream, a
  timeout, a config reload stopping the backend mid-call, an HTTP 5xx, or an
  HTTP 400, 404, 407, 408, 429 or session-expiry answer), the retry
  gets the uncertain-outcome notice under the first caller's error code. It
  used to get the original error, which read as "the work failed".
- An answer that shows the outcome (a JSON-RPC error, a 401 or 403 credential
  refusal, or any other HTTP 4xx refusal) is served as before.
- A backend that could not take the request (`BackendUnavailable`, a cold
  `tools/list` timeout, a stdio backend with no writer) frees the key, and the
  retry runs. Freeing it is safe because the request never left the gateway: a
  cold `tools/list` timeout sent only the read-only `tools/list`, never the
  `tools/call`. That timeout is now reported as `BackendUnavailable`, not
  `BackendTimeout`.

Library users: `Error::is_pre_dispatch` is `true` for `BackendUnavailable`, and
`security::safe_http_status_error` returns `TransportPermanent` for the 4xx
refusals above. `chains` retries `BackendUnavailable`. See ADR-012.

## 155. Key-server callers have their own principals

**Startup:** no notice

A caller signed in through the key server, with a token from `/auth/token` or a delegated
OIDC bearer, used to get the same kind of principal as a configured credential: the first
48 bits of a SHA-256 digest. An API key configured by digest could therefore share an OIDC
user's principal. Sessions, tasks, event subscriptions and the response cache key these
callers on their verified OIDC identity, so the shared principal showed where the
principal itself is recorded, such as audit attribution. These callers now get
`kst:<sha256 hex>` (token) or `oidc:<sha256 hex>` (bearer), which no configured principal
can equal. Configured principals are unchanged. Update any log or audit query that matched
these callers' old 12-hex principal.

## 156. An admitted explicit null reaches a REST capability's JSON body

**Startup:** no notice

When a body template field is a pure placeholder (`body: {cursor: "{cursor}"}`) and the caller
sends `"cursor": null` for a property whose `type` admits null (`[string, "null"]`), the
backend now receives `{"cursor": null}`. 3.x left the field out. The null wins over a schema
`default` that fills the same parameter in the URL. A null the schema does not admit, a
placeholder nothing fills and the template's own literal `null` are still left out. Query and
path parameters are unchanged, because they cannot carry a JSON null.

To keep the field out, leave the argument out instead of sending `null`. A static param or a URL
default for the same name still fills it, as before.

## 157. `webhooks.base_path` may not overlap a gateway route

**Startup:** no notice, the start is refused with its own error, which names the setting and the path, and for an overlap also the route; refuses to start

With the webhook receiver enabled, `webhooks.base_path` is mounted beside the gateway's own
routes. A path on or under one of them, such as `/mcp/hooks`, put a webhook handler where the
gateway's own handlers are expected, and a path over one, such as `/ui/api/backends`, made axum
panic at startup. Config load and reload now refuse an enabled receiver's `base_path` that is
equal to, under or over any route the gateway listener registers, and a path axum cannot mount
as written (`/`, a trailing `/`, an empty, `.` or `..` segment, `{`, `}`, or a segment starting
with `:` or `*`). The default `/webhooks` is unaffected, and a disabled receiver is not
checked. Choose a path outside the gateway's own routes.

## 158. `audit verify --anchor` checks the log against an off-host anchor

**Startup:** no notice

Nothing on the host proves an audit log once existed after its sealed segments
and `.hwm` are deleted and the active file is cut to empty, or after the log is
rolled back and `.hwm` rewritten to match. Keep a copy of `<log>.hwm` off the
host and pass it to `mcp-gateway audit verify --anchor <file>`: the log must
still hold the record the copy names, or verification fails, in live and
archive mode.

- An anchor that is missing, torn, unparseable or fails its MAC is refused
  (exit 1), never ignored. An anchor written with a shared secret is refused
  when no secret is configured.
- An anchor inside a range that retention expired fails with "predates the
  retained range": verify with a newer anchor. An anchor at the last record
  of the newest expired segment passes only for a signed log (a
  `shared_secret` set): without one, the expiry record that vouches for it
  can be forged. Take anchors more often than retention expires segments.
- `verify_audit_log` gains a fourth parameter, `anchor: Option<&Path>`. With an
  anchor, a log with no file left is a failed verdict (`ok == false` at the
  anchor's counter) rather than a `NotFound` error.

Independently, a log whose oldest surviving segment opens with a
`prev_entry_hash` other than the `prev_segment_final_hash` it links to now
fails verification. The gateway never writes such a log.

## 159. Cost accounting keeps running sums

**Startup:** no notice

Per-key and per-session cost accounting kept one record per answered call and
never trimmed it, so a caller without a credential (authentication off, or
`/mcp` public as in the shipped presets) grew gateway memory once per request.
It now keeps running sums, and what it holds no longer depends on the call
count:

- A key's 24h, 7d and 30d windows sum hourly buckets (at most 721). A window
  counts its whole cutoff hour, so it can include up to one hour of older
  spend at its edge. Budget enforcement is the cost-governance enforcer and is
  unchanged.
- Per-tool breakdowns (per key, per session and per session-less caller) keep
  at most 256 rows; later tools share one `(other)` row, and every total stays
  exact.
- A key with no spend for 30 days and no budget set through `set_key_budget`
  is dropped on a later call, and reads as a key that never spent.

Library users: `CostTracker::evict_old_records` is removed. Nothing called it
in the gateway, and there is nothing left to evict.

## 160. The budget enforcer's day rows are bounded

**Startup:** no notice

With cost governance on, the budget enforcer kept a per-tool and a per-key day
row for every name that ever spent and never removed one. Now:

- A tool or key with a budget always keeps its own row, so budget checks are
  unchanged.
- Other names get their own row up to about 256 per map (calls racing on a
  first insert can add a few more). Past that, or for a name
  longer than 256 bytes, their spend is counted in `tool_overflow_usd` or
  `key_overflow_usd`. It still counts toward the global daily budget.
- Rows from an earlier day without a budget are removed on a later spend.

`EnforcerSnapshot` and the saved `costs.json` (`PersistedCosts`) carry the two
overflow totals; the admin cost stats show them as `tool_overflow_spend_usd`
and `key_overflow_spend_usd`. A file saved by an earlier
build loads with both at 0.

Library users: code that builds `EnforcerSnapshot` or `PersistedCosts` with a
struct literal adds the two fields.

## 161. CLI config writes keep comments, or refuse

**Startup:** no notice

`mcp-gateway add`, `remove`, `setup wizard` and `cap discover --write-config`
(including the `--shadow` adoption) used to re-serialise `gateway.yaml`
whenever the change was not a single block-style backend, which dropped every
comment in the file, including the credential warning `init` writes.

They now edit the file as text, one backend at a time, and write it once.
Comments on lines the change deletes go with them (a removed backend's entry,
or a field an edit drops), and the command names those comment lines. When a
change cannot be written as text (a flow-style `backends:` mapping, or a
comment inside a changed value) and the file has comments, the command writes
nothing, exits non-zero, and names the line numbers of the comments a rewrite
would drop. It never prints their text, which could hold a quoted secret. A
file without comments is rewritten as before.

`--force` keeps the old behaviour only for a change that cannot be written as
text: it names the same lines, then rewrites the file without them, for
example `mcp-gateway remove old-server --force`.

## 162. Agent tokens own their tasks apart when gateway authentication is off

**Startup:** no notice

With gateway authentication off and agent authentication on, every caller
holding a valid agent token shared one task owner, so one agent could read,
update, cancel or replay another agent's task and listen to its
notifications. Each agent now owns its own tasks, keyed on the `client_id`
its token validated as, so a renewed token for the same agent keeps them.
With agent authentication off nothing changes: callers share the one auth-off
pool, as before. (With it on, a request without an agent token is refused.)

Tasks an agent created before the upgrade were stored under the shared owner,
so they stay in that pool: the agent that created them no longer finds them
under its own owner.

## Upgrading from 3.5.x: a walkthrough

This is the path CI rehearses on every change: `scripts/release/nfr_upgrade_1_rehearsal.sh`
upgrades a 3.5.1 gateway with an API key and a mounted backend to this build, checks it, and
rolls it back. Steps that the rehearsal checks name the check in brackets; the others are
precautions it does not exercise.

1. Stop the 3.5.x gateway and copy `gateway.yaml` and the data directory
   (`~/.mcp-gateway` by default) somewhere safe. The config copy is what a rollback restores.
2. Install 4.0 and run the upgrade step against the same data directory. It prints the
   breaking-change notice once, advances `version.stamp`, and leaves `gateway.yaml` and the
   OAuth token files byte-identical [PHASE2.STAMP_ADVANCED, PHASE2.CONFIG_PRESERVED,
   PHASE2.CREDENTIALS_PRESERVED]. `--dry-run` shows what it would do without writing.

   ```bash
   mcp-gateway upgrade --dry-run --data-dir ~/.mcp-gateway
   mcp-gateway upgrade --data-dir ~/.mcp-gateway
   ```

3. Give every API key an explicit `backends` list, or `["*"]` for all: a 3.x key without one
   reached every backend and now reaches none (item 32). Then replace every plaintext
   `auth.api_keys[].key` with its digest (item 41). The same key keeps working
   [PHASE2.API_KEY_MIGRATED_TO_DIGEST]:

   ```bash
   printf %s "$KEY" | mcp-gateway hash-key                   # put the output in key_sha256
   printf %s "$KEY" | mcp-gateway hash-key --verify sha256:<hex>
   ```

4. With auth on, enable the audit log on a writable path (item 43):
   `security.transparency_log.enabled: true` and `path`.
5. Start the gateway. If it refuses, the error names the setting or file; the bold list at the
   top of this guide says which items refuse the start, and each item says what to change.
6. Check a real caller: the same API key reaches the same backend tool
   [PHASE2.ACTIVE_CALLER_POST_UPGRADE], and the call left an audit record
   [PHASE2.AUDIT_LOG_WRITTEN].
7. Optional: `server.modern_protocol: false` turns off the 2026-07-28 protocol revision, and an
   `initialize` for it is then refused [PHASE3.MODERN_OFF_INITIALIZE_REFUSED].

To go back, follow [Rolling back](#rolling-back): restore the config copy from step 1 and start
3.5.x. It warns "Downgrade detected", leaves the stamp alone and serves the same caller
[PHASE4.DOWNGRADE_WARNING_LOGGED, PHASE4.STAMP_UNCHANGED, PHASE4.ACTIVE_CALLER_POST_ROLLBACK].

## After upgrading

- Confirm the version stamp advanced: the notice prints once and not again.
- Re-authorize OAuth backends at a time you choose rather than on a user's first call.
- If startup is refused, read the error: it names the setting or file. The bold list at the top
  says which items refuse the start.

## Other behaviour changes

These need no action and have no startup notice.

- **Cost budgets survive a restart.** Today's cost-governance spend is reloaded from
  `costs.json` at startup, so a restart no longer resets the daily budgets. A budget that
  has blocked stays blocked until UTC midnight. Each process keeps its own `costs.json`.
  Item 74 covers stdio.
- **Default capability directories are `capabilities` only.** A 3.x gateway also loaded
  a private capability checkout under `$HOME/github` if it existed. If you relied on that,
  add the directory to `capabilities.directories`.
- **Paginated backends show their whole tool catalogue.** The metadata cache now follows
  `nextCursor`, so tools past a backend's first `tools/list` page appear in search, listing
  and counts. One refresh of a paginated backend costs up to 32 list requests or 120 s. A
  drain that stops early keeps what was read, reports its tool count as "at least", and
  increments `mcp_backend_list_truncated_total{backend,reason}`, where `reason` is
  `page_cap` (32 pages), `cursor_repeat` (the backend repeated a `nextCursor`),
  `fill_budget` (120 s spent) or `unreadable_page` (a page had no `tools` array; the
  drain reads on, but the catalogue is never treated as complete).

## Rolling back

Keep the 3.x `gateway.yaml` you had before making the 4.0 edits, and put it back to roll back.
4.0.0 itself never edits the file, but several items ask you to, and 3.x cannot read the
result: 3.x reads `key` and not `key_sha256` (item 41), and reads a `file:` secret as the
literal text `file:...` (item 44). The upgrade leaves the 3.x token files in place — its
migration prints the notice and stamps the version, and touches no credential
(`migrate_4_0_0_release_notice` in `src/commands/upgrade.rs`). A rollback therefore picks those
files back up rather than prompting again, unless the tokens expired in the meantime, or a
credential migrated with `mcp-gateway accounts migrate-credentials` was refreshed on 4.0 against
a provider that rotates refresh tokens: that refresh retires the copy in the old file, and 3.x
has to authorize again (item 1). What 4.0.0
wrote under the per-issuer key is simply not read by 3.x.

Within 4.0, a rollback to an earlier beta is unsupported once a managed account has had a
forced refresh (item 61): that beta cannot open the account store and refuses to start.
