# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

<!-- New entries go here, under the heading that fits, never under a tagged release below. -->

### Added

- `file:/absolute/path` secret references wherever `env:NAME` is accepted. The file is held to the
  item 35 mode rule, capped at 64 KiB, and has one trailing newline stripped. An empty file fails
  the load. A reload reports a rotated file as needing a restart. Capability YAMLs are unchanged.
  A literal secret starting with `file:` is now a reference (breaking; UPGRADING-4.0 item 44).
  (C9, MIK-7570.SECRET.2)

### Changed

### Fixed

- **BREAKING: only delivered change notifications are advertised.** `resources.subscribe`,
  `resources.listChanged` and `prompts.listChanged` were advertised and never delivered.
  They are now `false`, and `resources/subscribe`/`unsubscribe` are refused with `-32601`.
  `tools.listChanged` is announced for every tool-set change over HTTP (config reload,
  capability reload, admin UI, revive), as a standard `message` event on the 2025 GET
  stream rather than the gateway's envelope, and is `false` over stdio. See UPGRADING-4.0
  item 52.

### Security

- **Legacy HTTP session ids are minted by the gateway and never adopted** (F9, MIK-7585,
  #1140). A client-chosen `Mcp-Session-Id` that names no live session gets a fresh `gw-` id
  instead of becoming the session's id, so an unauthenticated caller can no longer pick an id
  ahead of another caller and receive or answer its elicitation prompts. Every
  unauthenticated caller is one owner class, separated only by holding the minted id. An
  empty or whitespace id is treated as absent (DELETE answers 400, was 404). Session ids in logs, the
  firewall audit log and the transparency log are 8-hex fingerprints; `audit show --session` finds
  entries by the raw id or its fingerprint (a fingerprint can collide). Breaking for library users: `first_session_id` is removed from
  `NotificationMultiplexer` and `ProxyManager`, and `get_or_create_session_for` is no
  longer public. See UPGRADING-4.0 item 58.
- **The direct route `POST /mcp/{name}` writes the audit log's invocation record**
  (MIK-7570.AUDIT.2). Every `tools/call` on it, refused, failed or malformed included,
  now writes the same `schema_version: 2` record as `gateway_invoke`, with `route:
  "direct"`; meta-route records carry `route: "meta"`. With auth on, a failed append
  withholds the result (503, -32005). The backend-scope check now runs after the body is
  parsed, so its refusal names the tool; it still answers 403 for an unknown backend.
  A direct-route `tools/call` naming no tool is refused (400, -32602) instead of being
  forwarded without the per-tool authorization check.
  See UPGRADING-4.0 item 43.

## [4.0.0-beta.2] - 2026-09-25

> **Pre-release.** The second 4.0 beta. It is the first beta with container images:
> `v4.0.0-beta.1` published to GitHub, crates.io and npm, but its image was never promoted
> because the tag's container smoke test failed (fixed in #1018), so
> `ghcr.io/mikkoparkkola/mcp-gateway:4.0.0-beta.1` does not exist. Like beta.1 it is not
> feature complete: the criteria still open for 4.0.0 are listed under *Known gaps* in
> [`docs/release/4.0.0-beta.2-notes.md`](docs/release/4.0.0-beta.2-notes.md). It contains
> every entry below this heading, everything in `[4.0.0-beta.1]`, and the `[4.0.0]` section
> further down, which describes the 4.0 line and is not yet released as a final version.
> Breaking changes from 3.x are listed in [`docs/UPGRADING-4.0.md`](docs/UPGRADING-4.0.md).
> Install it by exact version (`cargo install mcp-gateway --version 4.0.0-beta.2`,
> `npm install @mikkoparkkola/mcp-gateway@next`, `ghcr.io/mikkoparkkola/mcp-gateway:4.0.0-beta.2`);
> no stable channel (`latest`, Homebrew, the MCP Registry) moves to it.

### Highlights

The 4.0 line serves MCP protocol revision 2026-07-28 by default beside 2025-11-25 and earlier:
stateless `POST /mcp` with no handshake, `server/discover`, retry-based input requests, a
caller-scoped `subscriptions/listen`, the tasks extension and optional idempotency keys, with
one replica while it is on. On stdio, `server/discover` lists only the older revisions. For teams, each caller now sees and invokes only what it was granted,
and cached results, notifications and subscriptions stay per caller. SSO `role_mapping` admin
rules grant full gateway admin, key-server OIDC rules need an issuer and a verified email, and
with auth on the tool-call audit log is required and fails closed. API keys are SHA-256 digests
with an optional expiry that is enforced, and `/metrics` has its own token. The gateway refuses to start on an
unrecognised config key, a config file other users can read, an unresolved secret or, with auth
on, cleartext HTTP on a network bind. The Helm chart now installs and serves with its defaults. What is still open for 4.0.0 is under *Known gaps* in the beta.2 notes.

### Added

- **With auth on, the tool-call audit log is required and fails closed
  (breaking).** An auth-enabled config without `security.transparency_log.enabled:
  true` fails to load, and a log that cannot open stops startup. Every entry
  carries `schema_version: 2`, `trace_id`, `outcome`, `error_code` and `who`
  (credential kind, key fingerprint, verified issuer and subject; never an email).
  Refused and failed calls are recorded. A failed append answers HTTP 503 /
  JSON-RPC -32005 and unreadies `/readyz` until an append succeeds. The Helm
  chart and enterprise-alpha mount a writable `audit` volume. The log is not
  rotated yet. See UPGRADING-4.0.md item 43.

### Changed

- **API keys are configured as sha256 digests, with an optional expiry
  (breaking).** `auth.api_keys[].key` is refused at load; set `key_sha256` to the
  output of the new offline `mcp-gateway hash-key` (key on stdin, `--verify`
  checks one). An `env:` variable must hold the digest, not the key. The
  optional `expires_at` refuses a matching key with 401 after that instant.
  Clients keep their keys, and principals are unchanged. See
  `docs/UPGRADING-4.0.md` item 41.
- **Breaking:** a `control_plane.role_mapping` rule with `role: admin` now makes its
  SSO identity a gateway admin on every admin surface (admin meta-tools, `/ui/api/*`),
  not only the control plane. The mapping is read per request, so a reload revokes
  admin at once. A `role: admin` rule whose only condition is `domain` fails to load,
  and each admin rule logs a warning at load. Header identities never confer admin.
  See `docs/UPGRADING-4.0.md` item 51 (E1, MIK-7570.ADMINSSO.1).

### Fixed

- **A modern-era stdio caller is handed a continuation instead of `-32003`.**
  When a backend asks for input over stdio and the call declared the capability
  in its own `_meta`, the gateway now answers with an `InputRequiredResult` whose
  `requestState` the client can retry with, and the retry completes. The
  continuation is bound to a nonce drawn once per stdio process, so a second
  process sharing the keyring cannot redeem it. The input bridge stays legacy-only,
  and HTTP callers with no verified identity are still refused `-32003`
  (MIK-7570.STDIO.1).

- **An open circuit breaker now degrades `/health` (breaking for `/health` monitors).** The
  breaker reported `"open"` and every consumer compared against `"Open"`, so `/health`, the
  admin panel and the redacted `/ui/api/status` never saw an open breaker. `BackendStatus.circuit_state`
  is now the typed `CircuitState`, serialised as the same `closed` / `open` / `half_open` strings.
  `/health` answers 503 `degraded` while a breaker is open, the admin panel shows the backend
  `Down` and `Blocked`, and `/livez` / `/readyz` stay backend-blind. See item 45 in
  [`docs/UPGRADING-4.0.md`](docs/UPGRADING-4.0.md). (MIK-7570.BREAKER.1)

- **Attestation `enforce` enforces (breaking).** It refuses, with -32002, a
  call whose token is missing or invalid: `gateway_invoke` (the `attestation`
  argument), the direct `/mcp/{backend}` route and surfaced tools
  (`_meta["io.mcp-gateway/attestation"]`, stripped before forwarding).
  Playbooks and code-mode plans are refused under enforce. Enforce without
  `GATEWAY_ATTESTATION_SIGNING_KEY` fails startup. See
  `docs/UPGRADING-4.0.md` item 46.

- **BREAKING: `webhooks.rate_limit` is enforced.** It was parsed and never read. Each
  webhook endpoint now gets its own per-minute budget and answers `429` past it; the
  default is 100 per minute and `0` disables the limit. See `docs/UPGRADING-4.0.md` item 42.

- **Cost budgets survive a restart.** The gateway loaded `costs.json` at startup and
  discarded it, so every restart reset the daily cost budgets to zero. Today's spend (UTC)
  is now reloaded into the budget enforcer; a file saved on an earlier day is ignored.
  A budget that has blocked stays blocked across a restart until UTC midnight.

## [4.0.0-beta.1] - 2026-09-25

> **Pre-release.** The first 4.0 beta, cut so 3.x users can start testing 4.0 before the final
> release. It is not feature complete: the criteria still open for 4.0.0 are listed under
> *Known gaps* in [`docs/release/4.0.0-beta.1-notes.md`](docs/release/4.0.0-beta.1-notes.md).
> It contains every entry below this heading and everything in the `[4.0.0]` section further
> down, which describes the 4.0 line and is not yet released as a final version. Breaking
> changes from 3.x are listed in [`docs/UPGRADING-4.0.md`](docs/UPGRADING-4.0.md).
> Install it by exact version (`cargo install mcp-gateway --version 4.0.0-beta.1`,
> `npm install @mikkoparkkola/mcp-gateway@next`, `ghcr.io/mikkoparkkola/mcp-gateway:4.0.0-beta.1`);
> no stable channel (`latest`, Homebrew, the MCP Registry) moves to it. No container image was
> published for beta.1; see `[4.0.0-beta.2]`.

### Added

- **A `-full` image variant carrying the runtimes stdio backends spawn.**
  `ghcr.io/mikkoparkkola/mcp-gateway:latest-full` adds Node.js 24, `uv`, `git`
  and `openssh-client` to the default image, and carries `curl` and a `python3`
  that NodeSource depends on. It does not carry `pnpm`, `yarn` or `bunx`.
  Node comes from NodeSource rather than the distribution, whose 20.19.2 is
  below the floor stdio backends declare. The release publishes `latest-full`, `<version>-full` and
  `<major>.<minor>-full` alongside the tags they mirror, plus the
  `sha-<commit>-full` provenance tag the list is composed under; as on the
  default image, `latest-full` and `<major>.<minor>-full` move only for a
  stable release, so a candidate is reachable only by its exact version. The
  default image is unchanged.

  `docs/DEPLOYMENT.md` previously answered this case with "install Node.js in
  the image", which leaves each operator maintaining a private layer that
  nothing keeps in step with the gateway it fronts — and which fails silently
  when it falls behind, because a stale runtime is only visible when a backend
  that needs it stops starting.
  ([@terafin](https://github.com/terafin), [#644](https://github.com/MikkoParkkola/mcp-gateway/pull/644))

- **A hosted consent journey lets a chat client's users connect their own
  OAuth account, with no separate admin step.** Today a `personal_managed`
  backend refuses a caller who has not connected yet and stops there. With
  `accounts.hosted` configured and a bridge adapter in place (Open WebUI
  today), that refusal instead carries a gateway-sealed connect link: the
  user follows it, is sent to the provider (Google, in the reference
  configuration), and lands back on a gateway-rendered outcome page over
  `/accounts/v1/*`. They can review and disconnect their own accounts at any
  time from `/accounts/v1/complete`. Each grant is scoped and committed per
  user, so an unconnected caller never reaches another user's credential.
  Enabling it needs `accounts.hosted.public_origin` and `return_paths`, an
  adapter with a `session` block, and each `personal_managed` descriptor's
  `redirect_uri` set to `<public_origin>/accounts/v1/callback`; see
  `docs/MULTI_USER.md` for the full configuration and the reverse-proxy
  routing it needs. Omitting `accounts.hosted` mounts no route and changes no
  existing refusal text.

### Fixed

- **The default capability directories no longer include a checkout under `HOME`.**
  `capabilities.directories` defaulted to `capabilities` plus
  a private capability checkout under `$HOME/github` whenever it existed, so a
  gateway loaded capabilities from a path no configuration named. The default is now
  `capabilities` alone; list any other directory explicitly.

- **`server.max_body_size` is enforced on every route (breaking).** It was read
  nowhere: `/mcp` and `/mcp/{name}` hard-coded 10 MiB and every other route,
  webhooks included, used the framework's 2 MiB default. An oversize body now
  gets HTTP 413 everywhere; on `/mcp` and `/mcp/{name}` the JSON-RPC code is
  -32600 (was 400, JSON-RPC -32700). `max_body_size: 0` now fails the load.
  See UPGRADING-4.0.md item 39.

- **A modern `tools/call` without an idempotency key is admitted.** Earlier 4.0
  builds refused it with `-32602` unless the tool was marked read-only, which
  made write tools unusable from standard MCP clients, none of which send the
  vendor `_meta` key `io.mcp-gateway/idempotency-key`. Such a call now runs
  unprotected, as legacy frames always did: at-most-once holds only for calls
  carrying a key or a task. The new `server.idempotency_key: optional | required`
  (default `optional`) restores the refusal under `required`, for modern
  un-keyed, un-tasked calls to tools not marked read-only on the meta route and
  stdio only. New counter `mcp_unkeyed_calls_total{era, gateway_read_only}` shows
  the traffic to watch before switching. See UPGRADING-4.0.md section 28 and the
  ADR-012 addendum.

- **The Helm chart and the enterprise-alpha manifests start.** They never had,
  since the chart arrived in #292: `serve --host` exited 2, `backends: []` failed
  the map-typed config, and the task store could not open under a read-only
  root with no writable `HOME`. Ahead of all three, the kubelet refused the pod
  because the image names its user and `runAsNonRoot` needs a number. The args
  drop the subcommand, `backends` is `{}`, the pod mounts an `emptyDir` `state`
  volume at `/var/lib/mcp-gateway` with `HOME` pointing at it, and the pod runs
  as UID 1001. A new CI step installs the chart on the PR's own image in kind
  and requires Ready and `/livez` 200; the existing kind job drives `pause` and
  could not see any of this. See `docs/UPGRADING-4.0.md` item 21.

- **Governance mutation no longer turns off without saying why.** The store
  lived next to the config file, so any install with a read-only config
  directory (every Helm install) served governance read-only, and the admin API
  gave the same "not configured" answer as for auth being off. A new
  `control_plane.store_dir` places the store; when it is set, it must be
  absolute, and with auth on writable, or the gateway refuses to start. When it is unset, the
  location is unchanged and an unwritable directory still degrades to
  read-only, but `GET /ui/api/control-plane` now reports
  `mutation_disabled_reason` (`auth_off` or `store_unavailable`) and
  `base_source`, the 503 on a mutation names the path, and each start logs the
  directory in use. See `docs/UPGRADING-4.0.md` item 22.

- **The `-full` variant's smoke gate bounds every probe.** Four of its six probes
  resolve over the network — npx and uvx fetch a package, git fetches a remote —
  and none was bounded. On a runner whose resolver stops answering, the gate
  waits on the first probe until the job is killed hours later and reports only
  `cancelled`, with nothing in the log between the step's first line and the
  cancellation. Each probe now runs under a per-probe ceiling, and a probe that
  hits it reports which one and how long it waited, so a stalled network is a red
  step in seconds that names itself instead of an invisible wait.
  ([@terafin](https://github.com/terafin), [#744](https://github.com/MikkoParkkola/mcp-gateway/pull/744))

- **Two backends running the same command no longer share a package cache.**
  `npx -y <pkg>` installs into a cache directory shared by every process on the
  host, and concurrent installs into one tree can tear it — after which npm
  trusts the damaged tree and every later spawn of that command fails with
  `MODULE_NOT_FOUND`, reported as "Backend timeout" with zero tools. Each
  backend now gets its own cache directory. An operator-set
  `npm_config_cache` is left alone.
  ([@terafin](https://github.com/terafin), [#622](https://github.com/MikkoParkkola/mcp-gateway/pull/622); the smoke-gate port lock it relies on was restored by
  [@terafin](https://github.com/terafin) in [#695](https://github.com/MikkoParkkola/mcp-gateway/pull/695))

### Changed

- **The Helm chart pins its pod identity and bounds its scratch volume
  (breaking).**
  `podSecurityContext.runAsUser`, `runAsGroup` and `fsGroup` render as 1001, the
  image's gateway user, and the values schema refuses any other value, root
  included, so `helm lint` and `helm template` fail. The `state` emptyDir
  carries `sizeLimit` from `stateVolume.sizeLimit` (default `1Gi`), and
  enterprise-alpha's carries the same `1Gi`. Remove any `fsGroup` or `runAsUser`
  override. See `docs/UPGRADING-4.0.md` item 36. The enterprise-alpha Deployment no
  longer mounts a service account token: the gateway never calls the
  Kubernetes API. The kind real-image check now sends an MCP `initialize` and
  a tool listing and requires a JSON-RPC result.

- **A config key the gateway does not read fails the load (breaking).** A
  misspelt key such as `key_server: {enabeld: true}` used to load in silence
  and leave the setting at its default. The config file is now checked after
  it parses, and one `ConfigValidation` error lists every offending key as a
  dotted path with `[index]` for list entries, for example
  `auth.api_keys[0].bakends` or `backends.brave.timout`. Backend keys hidden
  by the flattened transport are checked against a fixed list. The retired
  `backends.<name>.idle_timeout`, which only warned, is refused with its
  explanation. `MCP_GATEWAY_*` environment variables are not checked. Reloads
  run the same check and keep the running config on refusal. See
  UPGRADING-4.0.md item 29.
- **Attestation is off by default, and `enforce` or an unrecognised
  `GATEWAY_ATTESTATION_MODE` fails startup (breaking).** An unset mode used to
  attach an observe-mode validator, and every unrecognised value, `enforce`
  included, fell back to observe with a warning, so a deployment that asked
  for enforcement silently ran without it. Unset, empty or `off` now attaches
  no validator; set `observe` to keep the audit lines. `enforce` is refused at
  load until it covers the direct route and multi-step plans. See
  `docs/UPGRADING-4.0.md` item 30.
- **A credential over plain HTTP on a network bind refuses the start
  (breaking).** With `auth`, `agent_auth` or the key server on, a non-loopback
  bind or `public_url`, and no mTLS, the gateway refuses to serve, and a reload
  into that state is refused. `server.cleartext_http` names the protection
  instead: `tls_terminated_upstream`, `cluster_internal` (Service-name
  `public_url` only) or `host_local_publish`, each logged at WARN on every
  start. The Helm chart (`server.cleartextHttp`), enterprise-alpha and compose
  set it. See `docs/UPGRADING-4.0.md` item 38.
- **`/metrics` requires a dedicated scrape token (breaking).** It sat outside
  authentication and its labels name your backends. It now answers only
  `Bearer <server.metrics_token>` and returns 401 otherwise, the admin bearer
  included. A missing `env:` variable leaves the gateway running with
  `/metrics` closed. The Helm chart advertises `/metrics` only when
  `metrics.existingSecret` is set and can render a ServiceMonitor. See
  `docs/UPGRADING-4.0.md` item 33.
- **A config or env file other users can read fails the load on Unix
  (breaking).** A world-readable config drew one warning in the HTTP banner,
  stdio never checked it, and env files were never checked, though both can
  hold credentials. Any world bit or group write is now refused, and so is
  group read on a file the gateway owns. Group read stays allowed on a file it
  does not own, as with a root-owned Kubernetes projection under `fsGroup`.
  The Helm chart and enterprise-alpha set `fsGroup: 1001` and a `0440` config
  mode. Windows is not checked. See `docs/UPGRADING-4.0.md` item 35.
- **A secret reference that resolves to nothing fails the load (breaking).**
  `${VAR}` with no default expanded to `""` when `VAR` was unset, so a missing
  token was sent upstream as `Authorization: Bearer `. An enabled backend's
  `headers` and `env`, and `capabilities.directories`, now refuse an unset or
  empty `${VAR}` with no default, naming every such field in one error;
  `${VAR:-default}` now also applies the default to an empty variable, as
  POSIX does, and `${VAR:-}` allows empty on purpose. A disabled backend keeps
  its text unexpanded. An `env:` secret that is unset or empty, and an empty
  literal bearer token, API key, agent HS256 secret or key-server admin token,
  are refused. `{env.X}` templates and capability `auth.key` values error at
  call time when `X` is unset or empty instead of sending `""`; `{env.X:-}`
  allows empty on purpose. A `${...}` that is not a `${NAME}` reference is
  refused. Errors name listed env files that were not
  found. See `docs/UPGRADING-4.0.md` item 40.
- **`subscriptions/listen` needs a credential and is scoped to it (breaking).**
  Every listen stream shared one channel with no caller identity, so each
  listener was told about every backend's tool changes, and a revoked token kept
  its stream. On an authenticated gateway a listen without a credential that
  authenticates is now refused with HTTP 401 (`-32001`) before it takes a slot,
  including on the starter config's public `/mcp`. `tools/list_changed` reaches
  only listeners whose key may access the changed backend, re-checked at each
  delivery by the rule the legacy stream uses; a revoked or expired credential
  closes the stream. With auth off every listener is told. See
  `docs/UPGRADING-4.0.md` item 26.
- **An exact identity grant names the agent's proof source (breaking).** A grant
  bound to `agent: {exact: runner}` admitted any caller whose proven id was
  `runner`, so a JWT `sub` and an mTLS subject that happened to match shared
  the grant. The binding is now `!exact {source: mtls|jwt, id}` and matches
  only a caller proven by that source. A 3.x bare row is refused at load, and
  the error lists every such row with its replacement; the gateway does not
  pick a source or widen to `any`. `identity grants grant --agent` takes
  `mtls:<id>` or `jwt:<id>`. `known_agents` rejects a bare string, naming the
  source it must declare, and a `source: declared` entry refuses load when
  agent identity is enabled without `allow_unverified_agent_identity`.
  See `docs/UPGRADING-4.0.md` item 27.
- **Tool calls with undeclared argument keys are refused (breaking, security).**
  A key the tool's `inputSchema` does not declare, at the top level or nested
  inside objects and arrays, now returns `isError: true` without reaching the
  backend, on `/mcp` and on the direct `/mcp/{name}` route, `passthrough`
  included. MCP backends previously received such keys unchecked, so a model
  that invented a field sent it straight through. The schema is the caller's
  own catalogue entry; an unlisted tool is forwarded and counted. Capabilities
  refuse nested keys too, and now honour a top-level `additionalProperties:
  true`. The per-backend `input_schema_enforcement: closed | standard | off`
  (default `closed`) is the escape hatch. A `gateway_execute` chain
  now stops at the first step whose result is `isError: true`, as its
  contract says. See `docs/UPGRADING-4.0.md` item 31. (MIK-7570.SCHEMA.1)

- **`notifications/tools/list_changed` from an admin backend edit reaches only
  callers of that backend (breaking).** Adding, removing or reviving a backend
  told every session on the legacy GET stream, so a caller learned when an
  operator edited a backend it cannot use. On an authenticated gateway the
  frame now reaches a session only if its key may access the edited backend,
  re-checked at delivery, so a revoked token is not told. With auth off every
  session is told. `subscriptions/listen` is scoped by item 26. The unused
  `notifications/roots/list_changed` sender, which nothing called, is removed.
  See `docs/UPGRADING-4.0.md` item 24.
- **Admin-panel grant and policy edits are refused with 409 (breaking).**
  `POST /ui/api/control-plane/grants`, `…/policies` and `…/decisions` wrote to
  the control-plane store and answered 200, but dispatch never read that store,
  so the edit was accepted and ignored. The page also merged the store's rows
  over the enforced ones, so it could show an enforced grant as revoked or SSRF
  protection as off. The routes now check RBAC and return 409 naming the config
  that is enforced (`security.identity_grants.path` and `mcp-gateway identity
  grants`, or `security.sanitize_input` / `security.ssrf_protection`), with no
  store or audit write. The page shows only enforced grants and policies, reads
  "Read Only", and adds `authority`. The store still feeds the audit view. See
  `docs/UPGRADING-4.0.md` item 25.
- **`logging/setLevel` over HTTP needs an admin key (breaking).** The meta route
  forwarded the level over the gateway's own credential to every shared backend,
  so any key, including one scoped to a single backend, could switch every
  shared backend to `debug` for every user; the direct route `POST /mcp/{name}`
  did the same for one backend. Non-admin callers on both routes now get HTTP 403
  with JSON-RPC `-32600`, and the refusal is audited. With auth off nobody is
  admin, so the method is refused. Stdio is unchanged. See
  `docs/UPGRADING-4.0.md` item 23.
- **A tool count is no longer reported as `0` before a backend has been
  enumerated.** `gateway_list_servers`, the `initialize` preamble and the
  `gateway_list_tools` / `gateway_search_tools` descriptions all derive their
  total from the tool cache, which is filled lazily; a backend that had not been
  asked yet contributed `0`, so a cold gateway advertised "0 tools across N
  backends" and its discovery descriptions said there was nothing to search.
  The total is now stated as a floor ("at least N tools") until every backend
  has been enumerated, and left unstated only when none has — so a partially
  warmed gateway keeps its number instead of losing it. `gateway_list_servers`
  gains `tools_known` beside `tools_count`, so a reader can tell "exposes no
  tools" from "not asked yet".


- **Six meta-tools are now listed only where they can answer.** `gateway_get_stats`,
  `gateway_cost_report`, `gateway_run_playbook`, `gateway_set_profile`,
  `gateway_get_profile` and `gateway_list_profiles` were listed in `tools/list`
  unconditionally, so a default deployment spent context on six tools whose only
  possible reply was "not configured". Each is now gated on the thing that lets it
  answer: a cost registry, a non-empty playbook engine, a configured routing
  profile, and for statistics a new `meta_mcp.expose_stats_tool` opt-in (the usage
  collector is always attached, so its presence never gated anything). The default
  HTTP surface drops from 17 tools to 11, stdio from 16 to 10, and the
  `NFR.PERF.4` band from `14..=17` to `9..=17`, all at admin standing.

  **This is a disclosure change, not a capability removal.** All seventeen names
  still dispatch by name on every deployment. A caller that invokes a tool it was
  not shown gets the tool's own answer — for a gated one, a refusal naming the
  configuration to add — never "no such tool". An operator who wants a tool back
  in the listing configures the feature it reports on; `meta_mcp.expose_stats_tool:
  true` restores `gateway_get_stats`. Operator-visible consequence: a client that
  enumerates `tools/list` and refuses to call anything absent from it will stop
  reaching these six until the corresponding feature is configured. See
  `docs/design/2026-09-16-meta-tool-surface-compaction.md`.

### Removed

- Removed the `session_sandbox` and `tunnel` modules. No configuration key reached
  either: nothing constructed a `SandboxEnforcer` outside its own tests and a
  benchmark, and there is no `tunnel:` section (a config that has one already
  fails the load as an unread key). The `session_sandbox/*` benchmark group goes
  with them. Also removed `src/gateway/ui/costs.rs`, a second `/ui/api/costs`
  handler that no module declared, so it was never compiled.

- **`server.request_timeout` (breaking).** Nothing read it; each call is bounded by
  its backend's `timeout`. A config that still sets it now fails to load with an
  explanation. See UPGRADING-4.0.md item 39.

- **The inbound WebSocket listener and `server.ws_port` (breaking).** The
  listener only echoed text frames back; it served no MCP, ran outside the
  Origin/Host guard and had no auth. A config that still sets `server.ws_port`
  now fails to load with an explanation. Clients connect over HTTP
  (`POST /mcp`) or stdio. See UPGRADING-4.0.md item 34.
- **WebSocket is not a configurable backend transport.** Earlier entries and
  the README listed it, but `TransportConfig` offers only stdio, HTTP
  (Streamable HTTP or SSE) and A2A, and no config path builds the WebSocket
  client in `src/transport/websocket.rs`. The docs no longer list it.

## [4.0.0] - 2026-09-19

> Upgrading from 3.x: see [`docs/UPGRADING-4.0.md`](docs/UPGRADING-4.0.md). No migration edits a
> 3.x `gateway.yaml`; strict `env_files` parsing, cleartext credential backends, empty or repeated
> API key names and `write` identity grants refuse a start rather than warning. The first start from a 3.x install prints the changes that
> need an operator action.

> **What the performance numbers are, and are not.** The 4.0.0 comparison against
> 3.5.0 is a component benchmark, not an end-to-end one. It measures in-process
> work with `criterion` — no wire, no backend, no queue — and reports a point
> estimate with a bootstrap confidence interval. It therefore produces **no P50
> and no P99**: a confidence interval is not a percentile, and the repository has
> no client-to-backend harness at any version to take percentiles from. What the
> measurement does support: over the 47 cases 3.5.0 and 4.0.0 share, the worst
> regression is +6.07% (`session_sandbox/check_tool_denied`, 86.27 ns to 94.18 ns)
> and the largest movement is a 67% improvement. Nothing approaches the 5% P50 or
> 10% P99 budgets those bounds were written against. Read it as headroom on
> component cost, and do not quote it as end-to-end latency.

### Added

- **The kill-switch error budgets are tunable from the config file** (GH #475).
  An `error_budget:` section sets the backend failure-rate `threshold`,
  `window_size`, `window_duration` and `min_samples`, and an
  `error_budget.capability:` sub-section sets the same four plus a recovery
  `cooldown` for the per-capability budget. Every key is optional and an absent
  key keeps the value that has been shipping, so a config without the section
  behaves exactly as before. Values are validated at load and refused with the
  offending field named rather than clamped: a threshold outside `(0.0, 1.0]`
  (`.nan` included), a window of zero or of more than 100000 calls, a zero
  `window_duration` or `cooldown`, and a `min_samples` above its own
  `window_size`, which describes a budget that can never be evaluated. An
  unknown key at either level is refused too, so a typo is not read as a
  default. The section is read when the meta-MCP server is built, so an edit to
  it is reported as restart-required rather than appearing to take effect.

- **`meta_mcp.exposed_meta_tools` restricts the meta-tool surface** (requested by [@Bruce-Poating](https://github.com/Bruce-Poating), [#449](https://github.com/MikkoParkkola/mcp-gateway/issues/449)):
  an allow-list of meta-tools to expose, enforced on both `tools/list` and
  `tools/call` for every meta-tool built-in, including the two Code Mode tools
  (`gateway_search`, `gateway_execute`). The field is new in 4.0.0 and defaults to
  empty, which exposes everything as before, so no existing configuration changes
  behaviour on upgrade. An allow-list that omits `gateway_invoke` is honoured and
  logged as a warning, since it leaves backend tools unreachable through the
  gateway. `meta_mcp.surfaced_tools` is a separate list and is unaffected.

- **First start after upgrading to 4.0.0 prints what changed underneath it.**
  The release re-keys OAuth credentials, refuses a malformed `env_files` line at
  startup instead of ignoring it, stops advertising protocol revision
  2024-10-07 and stops counting rate limiting against error budgets. Each is
  announced once, on the first start from a 3.x install; the notice reads no
  configuration and writes none.

- **MCP protocol revision 2026-07-28, behind `server.modern_protocol`.** The
  revision removes the `initialize` handshake, protocol sessions and the
  `Mcp-Session-Id` header, `ping`, `logging/setLevel` and server-initiated
  requests; it adds `server/discover`, per-request metadata, multi-round-trip
  requests, required result and cacheability fields, and the standard request
  headers.

  **The switch is on by default in 4.0.0.** A stock gateway serves 2026-07-28 to
  a client that asks for it, and downgrades to the highest revision the client
  supports otherwise. Set `server.modern_protocol: false` to serve the legacy
  generation only. With it off, a client asking for 2026-07-28 is refused with
  `UnsupportedProtocolVersion` — an answer it can act on — rather than served
  half a revision, where the half that works hides the half that does not.
  Clients on 2025-11-25 and earlier are unaffected either way, and the gateway
  serves both generations on one endpoint.

  `server/discover` is answered regardless of the switch, on stdio and
  Streamable HTTP. It is additive, and it is the only probe that works in both
  directions once the handshake is gone.

  **With the switch on, a retry reaches one replica.** The consumed-continuation
  ledger and the mint counter are process-local, and so is the continuation key
  each process generates at startup: an envelope opens only on the replica that
  minted it, which is what makes a continuation single-use across replicas
  without a shared store. The cost is that a retry landing on any other replica
  is refused, and a restart invalidates the continuations outstanding against
  the process it replaced. This binds only when `server.modern_protocol` is on;
  with it off, scale as before.

  **The tasks extension is advertised on the 2026-07-28 surface.**
  `server/discover` lists `io.modelcontextprotocol/tasks` in its capabilities, so a
  modern client can run a long `tools/call` as a task, poll it with `tasks/get`,
  and stop it with `tasks/cancel`; `tasks/update` is answered, but a task takes no
  input responses in 4.0.0. A task belongs to the caller that created it,
  and a returned handle still resolves after a restart within its retention window.
  The legacy `initialize` result does not carry the extension. The task model is
  knowingly short of the full extension specification in 4.0.0; MIK-7311 owns
  completing it.

### Changed

- **BREAKING: key-server OIDC rules need an issuer and a verified email.**
  An email or domain rule matched the raw `email` claim whether or not the
  IdP had verified it, so on a self-service IdP anyone could claim
  `ceo@corp.com` (the nOAuth pattern). The OIDC verifier now keeps `email`
  only when `email_verified` is `true` (or `"true"`), which covers
  `allowed_domains`, key-server policies, control-plane role mapping and the
  propagated identity assertion at once. Every `key_server.policies[].match`
  must name a configured `issuer`; blank discriminators and issuer-only rules
  on `accounts.google.com` or GitHub Actions fail to load. Email and domain
  compare ASCII case-insensitively, and `domain` is exact rather than a
  suffix. `DELETE /auth/tokens` requires `issuer`, and revocation and the
  per-identity cap key on `(issuer, subject)`. See
  `docs/UPGRADING-4.0.md` item 17.
- **BREAKING (behaviour): callers stop sharing cached and idempotent results.**
  Two API keys (or the admin bearer and a key) calling the same tool with the
  same arguments shared one response-cache entry and one idempotency key
  space, so one caller could be served another's result. An authenticated
  caller with no OIDC identity, grant subject or propagation binding now keys
  on the digest of its validated secret (`cred:`), never on the key's name. The
  direct `/mcp/{name}` route now separates mTLS, trusted-header and OAuth-agent
  callers as the meta route already did. An authenticated caller that resolves
  to no principal bypasses the cache and the idempotency guard
  (`mcp_cache_bypass_total`, `mcp_idempotency_guard_skipped_total`, reason
  `unresolved_principal`, labelled by `route`). Anonymous callers still share one namespace. No
  configuration change; see `docs/UPGRADING-4.0.md` item 14.
- **BREAKING: caller identity headers can no longer be spoofed.**
  `security.identity_grants.trust_caller_identity_headers` is removed and a
  config that still sets it fails to load. Its replacement,
  `security.caller_identity`, has three modes. `off` (default) reads no
  identity header. `trusted_proxy` honours `X-Gateway-Identity-Subject` and
  `-Label` only from a TCP peer listed in `trusted_proxies`, under the
  configured `authority`; any other peer sending them gets 403, and
  `X-Gateway-Identity` and `X-Gateway-Identity-Authority` get 400.
  `cloudflare_access` takes the identity only from a verified
  `Cf-Access-Jwt-Assertion` (team certs, `aud`, `exp`) and answers
  `Cf-Access-Authenticated-User-*` without one with 401. Before, any client
  that reached the gateway chose its own subject and authority, including an
  OIDC issuer's. A repeated identity header, an `X-Gateway-Identity-*` value over 512 bytes, or a
  `Cf-Access-Jwt-Assertion` over 8 KiB is refused
  instead of truncated. Refusals count in `mcp_identity_header_refused_total`,
  ignored headers in `mcp_identity_header_ignored_total`. Loopback proxies need
  `auth.enabled: true`. `KeyServerOidcConfig.max_token_age_secs` becomes
  `token_age: TokenAgeCap`, and `MetaMcp::with_trusted_identity_headers` becomes
  `with_caller_identity`. See `docs/UPGRADING-4.0.md` item 16.
- **BREAKING: identity grants written as documented now match.** Grants,
  owners and callers compare on `authority` and `subject`; `label` is display
  text. Before, a grant labelled differently from the runtime label (an API
  key's name) never matched, so personal grants that differ from their caller
  only in label now allow. Dispatch asks for `read` on a capability declaring
  `metadata.read_only: true` and `execute` otherwise, and `execute` covers
  `read`; a `read` grant previously never allowed anything. The `write` scope,
  which dispatch never asked for, is removed: a grants file using it is refused
  at load, and the CLI `--scope` no longer accepts it. `GrantSubject` equality
  ignores `label` and it no longer implements `Ord`; `GrantScope::Write` is
  gone. The doc and CLI examples now use subjects the gateway emits
  (`api_key:alice`, `agent: any`). See `docs/UPGRADING-4.0.md` item 13.
- **BREAKING: `auth.api_keys[].name` must be non-empty and unique.** A key's
  name is its identity-grant subject, so two keys sharing one held each other's
  grants. Config load refuses an empty or repeated name. See
  `docs/UPGRADING-4.0.md` item 12.
- **BREAKING: shipped probes read `/livez` and `/readyz` instead of `/health`.**
  `/health` answers 503 when any backend is down, and the Helm chart and
  enterprise-alpha manifests used it for liveness, readiness and startup, so
  one flapping upstream restarted every replica and a backend down at deploy
  time kept pods from starting. `/livez` (liveness) and `/readyz` (readiness,
  startup) answer 200 while the gateway serves and never read backend health.
  Both are public exactly when `/health` is, so no `public_paths` edit is
  needed. The `Dockerfile` and single-node compose healthchecks now dial
  `http://127.0.0.1:39400/livez`; `localhost` was refused with 403 by the Host
  gate on a `0.0.0.0` bind with no `public_url`. `/health` is unchanged. See
  `docs/UPGRADING-4.0.md` item 10.

- **BREAKING: an HTTP backend that uses OAuth must be reached over TLS or on
  loopback** (CodeQL `rust/cleartext-transmission` #90, #91; CWE-319). The
  bearer token this transport attaches is a replayable credential, so it is no
  longer put on the wire in cleartext. `https://` is always accepted;
  `http://` is accepted only when the host is loopback — `localhost`, any
  address in `127.0.0.0/8`, or `::1` — because a local MCP backend has no
  certificate and its traffic never leaves the machine. Anything else is
  refused twice: the backend fails to start with
  `refusing to send an OAuth token in cleartext to <origin>`, and the token is
  refused again at request time if an SSE-advertised message endpoint ever
  downgrades the scheme. IPv4-mapped IPv6 (`http://[::ffff:127.0.0.1]`) is
  deliberately treated as non-loopback; use `http://127.0.0.1` instead.
  **Migration**: put TLS in front of the backend, or move it to a loopback
  address. There is no configuration flag to opt out — a flag would re-enable
  the finding, and 4.0.0 is the release allowed to break this. Backends without
  OAuth are unaffected and may still use plaintext `http://`.

- **A backend that would send credentials in cleartext is refused at config load** (code-scanning alerts #90, #91): an enabled backend whose `http_url` or `a2a_url` is `http://` against a host off this machine, and whose configuration is credential-bearing — an `oauth` section (including one with `enabled: false`), identity propagation, secret injection, any static header whatever its name, or userinfo or a query string in the URL — no longer starts the gateway. The predicate is deliberately blunt: a header named `X-Trace-Id` and a query of `?page=2` trip it too, because whether a given header or query carries a secret is not decidable at config load, and a name list would only catch the operators who guessed the same names we did. Such a credential is readable by every host on the path and replayable for as long as it is valid, and a config typo should not be what decides that. Loopback is exempt, decided by the same classifier the Origin gate uses. **Breaking for operators pointing any of that configuration at a plain-`http` internal host**: use TLS, or set `allow_cleartext_credentials: true` on that backend to accept the exposure. The refusal names the backend and never echoes the URL, which is the credential-bearing string.

- **Destructive meta-tools are refused over stdio** (MIK-7246): `gateway_kill_server` carries `destructiveHint: true`, and the gateway asks the operator to confirm such a call before running it. That ask travels over the elicitation channel, which only the HTTP transport has — stdio speaks to one process over two pipes and can reach nobody. A destructive tool called over stdio is now refused with `-32001` and a message naming the action, rather than executed with a warning. **Breaking for stdio operators who kill backends through the gateway**: reach the management tools over the HTTP listener with a client that answers `elicitation/create`, or change the backend's configuration directly. Neither an unobtainable confirmation nor an operator decline counts against the caller's failure budget — the gate working is not the client misbehaving.

- **OAuth credentials are keyed by the authorization server that granted
  them.** MCP 2026-07-28 requires a client to key persisted credentials by the
  issuer identifier, to not reuse them with a different authorization server,
  and to re-register when that server changes. Tokens and dynamically
  registered client ids were keyed on the backend name alone, so moving a
  backend to a new authorization server presented it a client id it never
  issued — surfacing later as a confusing rejection rather than the
  re-registration it should have been.

  **On upgrade, backends using OAuth re-authenticate once.** Credentials stored
  by an earlier version carry no issuer and so cannot be attributed to one;
  they are not served to any. Reading them under the old key would defeat the
  separation this change exists to enforce, so the gateway re-registers and
  re-authorizes instead. No configuration change is needed.

- **BREAKING: a malformed line in an `env_files` file now refuses the start.**
  Earlier versions skipped an unparseable line silently, so a typo cost one
  missing variable and surfaced later as an unauthenticated backend. The loader
  now fails startup and names the file, the line number and the category of
  fault; the offending line is never echoed, because the offending line is the
  secret. **Migration**: start once before rolling out and fix what it names — a
  file that parsed by luck under 3.x now has to parse by grammar. Assigning
  `HOME` in a reloaded env file reports `restart required` rather than moving
  where a later `~` points.

- **`2024-10-07` is no longer advertised as a supported protocol version.** It
  is not a revision the specification has ever defined; it was introduced with
  the first version-negotiation commit in January and has been offered to every
  client since. It was inert for negotiation — no conforming client can request
  a revision that does not exist — but `server/discover` publishes this list as
  the gateway's own statement of what it speaks, which turns an unused constant
  into a claim.

- **A response is cached only under a protocol revision the gateway can
  identify.** The response cache is keyed by the revision a request was served
  under, and a request whose revision cannot be determined is not cached at all
  (`cache_protocol_revision`, `src/protocol/meta.rs:514`). A modern request
  carries its revision in the body. A legacy-shaped request must supply it in
  the `MCP-Protocol-Version` header or have bound one by completing
  `initialize` on the session (`:522`). Anything else resolves to "no revision",
  which is documented as fail-closed and means skip the cache (`:512`). Earlier
  versions had no such key, so a response fetched for a caller that declared no
  revision could be served to a caller asking under a different one.

  **A stateless client loses response caching on upgrade.** A bare `POST` that
  sends no `MCP-Protocol-Version` header and never runs `initialize` — the shape
  common to load generators, probes and short scripts — is no longer served from
  cache, and that traffic reaches the backends instead. Nothing errors, so the
  symptom is throughput and backend load rather than a failure, and the
  gateway's own rate limits then apply to calls that previously never reached
  them. Send the header on stateless requests, or complete `initialize` and
  reuse the session; either restores caching and neither needs a configuration
  change.

- **BREAKING: one license covers the whole repository — PolyForm Noncommercial
  1.0.0.** 4.0.0 retires the MIT core and the per-file allowlist that enumerated
  it, so every first-party file in the tree is Noncommercial from this release
  onward ([ADR-013](docs/adr/ADR-013-single-noncommercial-license.md),
  [LICENSES.md](LICENSES.md)). **Migration**: commercial use that relied on the
  MIT-headered core needs a commercial license — see
  [COMMERCIAL.md](COMMERCIAL.md). Releases already published under MIT keep the
  terms they shipped under; this is not retroactive.

- **`gateway_search` no longer emits ranking signals that never vary.** Thirteen
  of sixteen were the constant `1.0` in every response. The per-tool ranking
  block falls from 534 to 304 bytes.

### Removed

- Removed the ungrounded savings estimates from gateway statistics: the
  `stats --price` flag, the `gateway_get_stats.price_per_million` argument,
  the `tokens_saved` and `estimated_savings_usd` response fields, and the public
  `StatsSnapshot::tokens_saved`, `StatsSnapshot::estimated_savings_usd`, and
  `UsageStats::cost_savings` fields.

- Removed `.mit-core-allowlist`, the per-file manifest that enumerated which
  sources carried an MIT header. A single repository-wide license leaves it
  nothing to enumerate ([ADR-013](docs/adr/ADR-013-single-noncommercial-license.md)).

### Fixed

- **Competitive shadow-scan exports now stay portable and loadable.** The
  generated grep rules use the system `grep -E` on macOS and Linux, while the
  Nginx example preserves quoted and escaped log values.

- **A backend whose SSE response opens with a retry priming frame is no longer
  a transport error** (reported by [@Bruce-Poating](https://github.com/Bruce-Poating), [#563](https://github.com/MikkoParkkola/mcp-gateway/issues/563)). Servers built on `rmcp` with its default
  `sse_retry` prepend such a frame -- a `data:` line with nothing after it,
  plus `id:` and `retry:` -- to every POST response stream. 3.5.x took the
  first `data:` line verbatim and failed the whole call with
  `Failed to parse SSE data: EOF while parsing a value at line 1 column 0`, so
  no such backend could be used at all. The response stream is now decoded
  frame by frame: a block whose joined `data` is empty carries no event, and
  fields that are neither `data` nor `event` are ignored, so the exchange
  resolves on the frame that actually holds the JSON-RPC response.

- **Windows stdio backends start with a usable environment, and quoted
  commands parse by host rules.** `APPDATA` and `LOCALAPPDATA` were never
  passed to stdio child processes, so a backend resolving its own
  configuration under those paths started degraded on Windows. Configured
  stdio commands now go through a single parser, `transport::split_command`,
  which follows `CommandLineToArgvW` on Windows so the backslashes in a path
  survive; spawn, lifecycle, diagnostics, the UI summary and `doctor` all
  read that one parser, and `doctor` fails on invalid quoting instead of
  reporting a false `PASS`.
  ([@yfcyfc123234](https://github.com/yfcyfc123234), [#522](https://github.com/MikkoParkkola/mcp-gateway/pull/522),
  [#564](https://github.com/MikkoParkkola/mcp-gateway/pull/564))

- **A backend that rejects the gateway's protocol version is negotiated down
  rather than failed.** A Streamable HTTP backend supporting 2025-06-18 or
  earlier answered `initialize` with a `400`, and the gateway gave up instead
  of offering a revision that backend could accept. The gateway now adopts
  the server-selected version for post-handshake headers, negotiates when a
  version is rejected by HTTP status, and fails the backend by name only when
  the selection is genuinely unsupported.
  (reported by [@luochen1990](https://github.com/luochen1990),
  [#517](https://github.com/MikkoParkkola/mcp-gateway/issues/517))

- **A throttled backend no longer looks like a failing one.** A rate-limited
  response counted against the backend error budget, the per-capability budget
  and the circuit breaker exactly as a `500` did, so a caller fast enough to be
  throttled could open a circuit on a backend that was answering correctly.
  `429`, `too many requests`, `rate limit`, `RESOURCE_EXHAUSTED` and `throttled`
  now record the backend as reachable and contribute no budget sample at all —
  neither success nor failure, because a throttle says nothing about health.
  Every exclusion increments `mcp_error_budget_suppressed_total`, so the
  suppression is visible rather than inferred.
  (requested by [@crepererum](https://github.com/crepererum),
  [#475](https://github.com/MikkoParkkola/mcp-gateway/issues/475))

- **A failed config load no longer leaks its env files into the process.**
  Reading a config file used to apply every `env_files` entry it named to the
  process environment before validating the file, so a refused reload changed
  the environment a capability resolved its credentials from and a refused
  reload was only a partial no-op. Env files now resolve into an overlay that a
  failed load discards, so the environment is left exactly as the last accepted
  configuration left it.

  A **malformed** line now fails startup rather than being skipped, naming the
  file, the line number and the category of fault. The offending line is never
  echoed, because the offending line is the secret. A `~` in an `env_files`
  path resolves exactly once, at startup; each file is applied before the next
  is expanded, so a file that sets `HOME` moves where a later `~` points, and a
  reload reuses the paths startup recorded rather than resolving them again.
  Assigning `HOME` in a reloaded env file reports `restart required` instead.

  Capability credentials resolve through that overlay. An `env:` key on a
  capability used to read the process environment directly, so a value an env
  file supplied reached a `${VAR}` expansion in the config but not the
  credential a capability sent upstream. Both now read the same value, and the
  process environment is still the last place looked.

  `GATEWAY_ATTESTATION_SIGNING_KEY` and `GATEWAY_ATTESTATION_KEY_ID` read the same overlay,
  under fixed variable names rather than through a `{env.VAR}` reference in
  configuration. An env file can supply them, and the process environment is
  still the last place looked.

- **A `{env.VAR}` secret now reads the env-file overlay.** Env files no longer
  load into the process environment, and secret resolution still read only that
  environment, so a webhook secret or capability credential written as
  `{env.VAR}` and supplied by an env file expanded to the empty string. The
  resolver now consults the overlay first and the process environment after,
  matching how `env:` credential keys already resolved.

- **A webhook secret that resolves to nothing is refused.** An empty HMAC key is
  one anyone can compute, so every forged signature verified. An empty resolved
  secret is now rejected the same way a missing one is, whatever made it empty.

- **The provenance signing key reads the env-file overlay.** Runtime provenance
  stamping took `GATEWAY_ATTESTATION_SIGNING_KEY` from the process environment, so
  a key supplied by an env file no longer reached it and the signer stayed
  uninstalled. The key and its id now resolve through the overlay.

- **A config rewrite no longer persists a resolved secret.** Every
  read-modify-write path — the admin UI and the CLI commands that edit
  `gateway.yaml` — used to load the config with `env:` references and `${VAR}`
  placeholders already resolved, then serialise the result back to disk in
  plaintext. Those paths now load the file literally: references are preserved
  as written, and a value an env file or an `MCP_GATEWAY_*` variable supplies
  never reaches the struct that is written out. A write is still validated,
  against the env files the config being written names.

- **A reload is no longer refused over a reference the parser would ignore.**
  Env files are no longer applied to the process, so a `${K}` or `$K` reference
  to a key another env file defines can no longer expand on a reload, and the
  gateway refuses the reload rather than silently substituting nothing. That
  refusal now matches `dotenvy`'s own grammar: an unbraced name ends at the
  first non-alphanumeric character, a tab before `#` starts a trailing comment,
  and comments, single-quoted values and escaped `\$` are inert as they always
  were. Scanning is per logical line, as the parser reads them.

### Security

- **Discovery now matches invocation; nothing callable was removed** (GitHub #555).
  A caller is shown a tool, a backend or a count only if it could invoke it.
  Before, `tools/list`, `gateway_search_tools`, `gateway_search`,
  `gateway_list_tools`, `gateway_list_servers`, the `initialize` guide and its
  counts, the meta-tool descriptions, `tools/resolve`, did-you-mean hints,
  `predicted_next`, `_cost_suggestion`, `gateway_list_disabled_capabilities`
  and `gateway_set_state` were decided by the admin bit and the routing
  profile only, so a key scoped to one backend was shown another's tool
  names and schemas, and a tool denied by the global `tool_policy` was listed
  to every caller and then refused. Each surface now keeps an entry only if
  the silent form of the invocation checks admits it: routing profile, the
  transport's authorizer (backend scope, tool policy, per-key tool scope,
  mTLS, agent-auth scope), the admin-capability rule and identity grants.
  Discovery writes no invocation audit record. A withheld backend or tool is
  answered exactly as an absent one (`BackendNotFound`, `-32601 Unknown tool`).
  `gateway_get_stats` and `gateway_webhook_status` are admin-only, profile
  filter patterns are shown to admins only, a non-admin `/health` carries
  `status` and `version` only, and the direct route `POST /mcp/{name}`
  `tools/list` drains up to 32 upstream pages and answers the filtered
  `{tools}` with no cursor (`-32005` past the cap). See
  [`docs/UPGRADING-4.0.md`](docs/UPGRADING-4.0.md) §15.

- **Webhook notifications reach only callers scoped to the capability backend,
  and are off unless a webhook opts in.** A webhook with `notify` enabled was
  sent to every connected session, so on a gateway shared by several API keys
  one caller could receive another integration's payload. `notify` now defaults
  to `false`, and when enabled a session receives the event only if its caller
  passes `can_access_backend` for `capabilities.name`. The session's credential
  is re-validated at every delivery, so a revoked or expired token stops
  receiving on a stream it opened while valid. With authentication on, a
  session that presented no credential receives nothing. Breaking: a 3.x
  webhook that relied on the old default stops notifying until it sets
  `notify: true`. See
  [`docs/UPGRADING-4.0.md`](docs/UPGRADING-4.0.md) item 11.

- **Resource and prompt methods follow the caller's backend scope.** On the
  meta route, `resources/*` and `prompts/*` now check the API key or token's
  backend list the way `tools/call` does. Lists leave out backends the caller
  may not use, a resource on such a backend answers as if it did not exist,
  and a prompt fetch answers 403. Reads, subscriptions and prompt fetches also
  carry the caller's own identity to a backend that requires it; without one,
  that backend is left out of lists and prompt fetches are refused.

- **The key server refuses a token whose requested scopes miss the policy.**
  A restricted rule plus a request with no overlapping backends or tools
  produced an empty scope list, which tokens read as "all". The exchange now
  returns 403 instead.

- **Anomaly detection reports when it cannot see, instead of scoring a call
  neutral.** It was keyed on the session, and a per-request session makes every
  call look like a first call — scoring 0.5 against a 0.7 threshold, forever.
  The control kept running and stopped protecting.

- **Per-caller state is reclaimed on a deadline as well as on disconnect.** The
  disconnect trigger fires on an SSE close or `DELETE /mcp`, neither of which
  exists in the new revision, so every registered cleanup handler would simply
  never run.

- **A destructive call that cannot be confirmed is refused on the modern path.**
  The gate proceeded on a warning when elicitation was unsupported *or there was
  no session*; with sessions removed, every modern destructive call would take
  that branch. The legacy path keeps its documented behaviour. The governed set
  now comes from the `destructiveHint` annotation rather than one hardcoded
  name.

- **Multi-round-trip continuations are sealed, bound and single-use.** A
  backend's opaque state is encrypted inside the gateway's own envelope rather
  than handed to the client, bound to the caller and the original request, and
  redeemable once.

  **Retry forwarding is not implemented in this release.** The minting,
  sealing and single-use ledger exist and are tested; unsealing a continuation
  and forwarding the retry to the backend does not. A well-formed retry is
  refused with `-32602` and "retry forwarding is not available on this build"
  rather than being run as a fresh call, because running it fresh would repeat
  whatever the first attempt already did. MIK-7325 owns the forwarding path.

- **`tools/call` no longer drops a retry's `inputResponses` and
  `requestState`.** Both were silently discarded, so an elicitation could never
  complete and the destructive-confirmation gate ran without the answer it
  exists to collect.

- **Dynamic client registration declares `application_type`, and a returned
  `iss` is validated before an authorization code is redeemed** (RFC 9207).
  Persisted credentials gain an issuer-keyed storage key, since a credential is
  not valid with an authorization server that never issued it.

## [3.5.1] - 2026-09-04

### Changed

- **`gateway_search` returns L0 by default** (MIK-7084): tool name, one-line purpose, and score. `detail=l1` adds signature, when-to-use, and required params; `detail=l2` returns the full `input_schema`. `include_schema=true` still maps to L2 and is deprecated, not removed. Ranking diagnostics (`ranking` reasons and signals) are omitted unless `explain=true`. `gateway_search_tools` also omits `ranking` unless `explain=true`.

### Fixed

- **`prompts/list` and `resources/list` no longer stall on a slow or hung
  backend.** Both handlers aggregated every backend sequentially, so a single
  backend that was slow to answer held the whole request for its full transport
  timeout (often 120s). On a gateway with 50+ backends this blew past client
  connect timeouts on every (re)connect, and the gateway's late response
  surfaced as an "unknown message ID" error. Backends are now fetched in
  parallel and each fetch is bounded by a short timeout, so a slow or hung
  backend is skipped instead of blocking the list. Reported and fixed by
  [@terafin](https://github.com/terafin) from a 56-backend deployment, in
  [#465](https://github.com/MikkoParkkola/mcp-gateway/pull/465).

- **The aggregation timeout is configurable** via
  `meta_mcp.prompts_resources_fetch_timeout` (default `10s`). Operators with
  unusually slow backends can raise it without a code change.
  ([@terafin](https://github.com/terafin), [#465](https://github.com/MikkoParkkola/mcp-gateway/pull/465))

- **A cancelled transport request no longer strands its `pending` entry.**
  When an outer timeout drops an in-flight stdio or WebSocket request before
  the transport's own request timeout fires, a RAII guard removes the entry
  from the transport's `pending` map on drop, so a late response finds no
  dangling sender and the map does not grow across reconnect loops.
  ([@terafin](https://github.com/terafin), [#465](https://github.com/MikkoParkkola/mcp-gateway/pull/465))

- **Unreadable gateway config now reports a diagnosis** instead of a generic
  failure, so a permissions or parse problem is visible at startup.
  (reported by [@Bruce-Poating](https://github.com/Bruce-Poating), [#437](https://github.com/MikkoParkkola/mcp-gateway/issues/437); [#461](https://github.com/MikkoParkkola/mcp-gateway/pull/461))

- **Sampling POST-backs are bound to the prompted session**, so a late
  sampling response cannot land on a different client.

- **Glob L0 ranking drops disabled tools** and still assigns a score, so
  search results do not advertise tools the operator turned off.
  ([#470](https://github.com/MikkoParkkola/mcp-gateway/pull/470))

## [3.5.0] - 2026-08-28

### Added

- **`mcp-gateway init` generates an admin credential for the install** and
  writes it into `gateway.yaml`, along with `auth.public_paths` covering
  `/health` and `/mcp` so tool calls keep working. This is what makes the
  credential requirement below survivable on a new install: management needs a
  credential, and now there is one.

  An upgrade does not rewrite an existing config. If you manage the gateway
  today with authentication off, see the BREAKING note below for the edit to
  make by hand.

- **A way into the dashboard that a browser can actually use.** A browser
  cannot attach an `Authorization` header to a navigation, so `serve` prints a
  link once:

  ```
  DASHBOARD (opens once, then remembered in this browser):
    http://127.0.0.1:39400/dashboard?bootstrap=...
  ```

  Opening it exchanges a single-use value for a session cookie and redirects,
  so nothing stays in the address bar. The value in the link is **not** the
  admin credential; it works once, dies with the process, and is redeemable only
  from this machine, so a link left in a shell history is spent.

  Locality is established from the connection's peer address rather than from
  the `Host` header, which the caller writes and a reverse proxy rewrites —
  nginx's default for a bare `proxy_pass` is the upstream address, so a
  forwarded request used to arrive carrying a loopback `Host`. A request with a
  forwarding header is refused as well, since a proxy on this same machine also
  connects from loopback. A proxy that strips those headers remains
  indistinguishable from a local browser; the printed value is sensitive. The cookie carries
  an opaque handle rather than the credential, `HttpOnly` and
  `SameSite=Strict`, and `Secure` when the listener speaks TLS. Details in
  [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#opening-the-dashboard).

- **Config files are written readable only by you** (`0600`) on Unix, on every
  path that writes one — `init`, the dashboard's edits, and the config-export
  command. The file holds this gateway's credentials, and until now it
  inherited the process umask.

  Windows has no equivalent here and the file takes the directory's inherited
  permissions; stated rather than silently implied by the sentence above.

  An existing file is **reported, not changed**: the startup log names it, its
  mode, and the `chmod` to fix it. Silently re-permissioning a file you own is
  its own surprise. It does not stay wide forever either — writes replace the
  file from a scratch file created `0600`, so the next config write tightens
  it.

### Security

- **Origin validation on the HTTP surface (CWE-346).** Reported by Avishai
  Gonen, Pluto Security. `mcp-gateway serve` accepted requests on `/mcp`
  without checking `Origin` or `Host`, and the identity used when
  authentication is disabled carried admin rights and access to every backend.
  A web page could therefore reach the gateway's local port and call its tools
  with whatever credentials the gateway holds.

  A related shape is worth stating precisely, because the mechanism that
  closes it is not the obvious one. The handler accepts a request body without
  requiring a JSON content type, a session, or a prior `initialize`, so a
  cross-origin form POST can reach `tools/call` without triggering a preflight.
  That vector is closed by the origin check below and by nothing else: a form
  POST from a browser carries `Origin`, and the request is refused on it. No
  content-type requirement was added, because non-browser MCP clients do not
  reliably send one and refusing them would break the callers this gateway
  exists to serve.

  Separately, the checks below apply to browsers only; a process running under
  the same user account is not constrained by them.

  Two changes, both required:

  - `Origin`, `Host`, the HTTP/2 `:authority` and `Sec-Fetch-Site` are checked
    ahead of authentication, so a cross-site request is refused before an
    identity is assigned. A request without `Origin` is not refused on that
    ground, since non-browser MCP clients do not send one — but the `Host`
    check applies to every request regardless, so a client that reaches the
    gateway by a name it does not answer to is refused whether or not it is a
    browser. `Sec-Fetch-Site` covers the no-CORS GET, which the Fetch standard
    omits `Origin` from.
  - The identity used when authentication is disabled no longer carries admin.

- **A playbook step now faces the caller's own permissions.** Found while
  reviewing the fix above, and pre-existing rather than introduced by it. The
  per-caller checks — backend scope, tool allow-list, global tool policy,
  certificate policy and agent scope — ran at the HTTP router, which inspects
  the incoming request. A playbook's steps come from the stored playbook, so
  their targets never appeared in that request and the router had nothing to
  check: a restricted client could reach a backend through a playbook that it
  could not reach directly.

  The check moved to the single point every backend invocation passes through,
  ahead of every side effect, so a refused call reads no cached result, consumes
  no replay nonce, mints no credential and charges no budget. Code-mode steps
  and surfaced tools pass the same check.

  Operator-visible consequences:

  - A client with `backends` or `allowed_tools` set may now see a playbook step
    refused that previously ran. That is the fix working; widen the client's
    scope if the access was intended.
  - A refused call answers HTTP `403` rather than `200` with the refusal in the
    body.
  - Under `on_error: continue`, a refused step is recorded in a new
    `step_errors` field on the playbook result, keyed by step name, alongside
    the existing `steps_failed`. A run that fails nothing omits the field
    entirely, so successful output is unchanged. A refusal is never retried,
    since retrying a permission denial cannot change the answer.
  - `PlaybookResult` gained that field and is now `#[non_exhaustive]`. Code
    constructing it with a struct literal must change; code reading it need not.

  Standing limitation, unchanged: a process running under the same user account
  is not constrained by any of this.

- **stdio gained the tool-policy check it never had.** The stdio transport
  applied the global tool policy to `gateway_invoke` alone, so a playbook or
  code-mode step reached a backend with no policy check. Every dispatch shape
  now passes the same check. Certificate policy is deliberately not applied
  there: stdio presents no certificate, so evaluating it would refuse every
  call once any certificate rule existed.

### Changed

- **BREAKING: an agent's key material is checked at startup.** With
  `agent_auth.enabled = true`, a config that previously loaded is now refused
  when an agent:

  - sets an `hs256_secret` shorter than the 32-byte minimum, or one whose
    `env:` variable is unset. `DecodingKey::from_secret(b"")` is a valid key,
    so an empty secret verifies a token anyone can sign — that agent
    authenticates the world. A secret that is merely short is not forgeable by
    inspection, but it falls under the project's minimum and is refused on the
    same line;
  - sets both `hs256_secret` and `rs256_public_key`. The algorithm is read
    from the token header, so the caller picks which key verifies it and the
    agent is only as strong as the weaker one. Configure exactly one;
  - sets neither, and so can verify nothing.

  The refusal names the agent and the reason. To upgrade: rotate any secret
  below 32 bytes, and drop one key from any agent holding both.

- **BREAKING: server management requires a credential.** With `auth.enabled =
  false`, `gateway_kill_server`, `gateway_revive_server`,
  `gateway_reload_config` and `gateway_reload_capabilities` are unavailable.
  Those four change the gateway for every session. `gateway_set_profile` and
  `gateway_set_state` are NOT gated: each writes only the caller's own session
  and cannot widen what that caller reaches, and gating the first stopped
  nothing anyway, since a profile can be chosen at `initialize` through the
  same call with no credential. This applies to callers over HTTP. A stdio
  caller is treated as admin, because the client that spawned the process
  already holds whatever the operator holds and could edit the config file
  directly; withholding it there would remove management from exactly the
  single-user setup this protects. `/dashboard` and the
  management endpoints under `/ui/api/` return `403`. So does `/api/costs`,
  which reports spend across every key and session and was previously open —
  note that is the top-level route, not `/ui/api/costs`, which already required
  admin. `/ui/api/status` returns counts without backend names, and
  `/health` returns a backend count and overall health rather than names.
  Ordinary tool invocation is unchanged, so local MCP clients are unaffected.

  To restore them on an existing install, set `auth.enabled = true` with a
  bearer token — and list `/health` and `/mcp` under `auth.public_paths` at the
  same time:

  ```yaml
  auth:
    enabled: true
    bearer_token: "<your token>"
    public_paths: ["/health", "/mcp"]
  ```

  The second half is not optional. Turning authentication on gates **every**
  path, so enabling it alone makes the MCP client you already configured start
  failing — a worse outcome than the missing dashboard it was meant to fix.
  `mcp-gateway init` writes this shape for a new install; an upgrade does not
  rewrite your config, so this is the step to take by hand. The startup log
  says the same.

  Without a credential the gateway cannot distinguish its operator from any
  other caller that reaches the port, so admin now follows an explicit
  credential.

- **The gateway refuses to serve when its tools are reachable without a
  credential.** Reachable means a non-loopback bind, or a `server.public_url`
  declaring a name a proxy or tunnel answers to; open means authentication is
  off, or an entry in `auth.public_paths` covers the `/mcp` tool surface. Public
  paths are matched by prefix, so `""`, `/`, `/m` and `/mcp` all count, while
  `/health` and `/metrics` do not. The refusal happens
  before the listener binds, so such a configuration never opens a port. It
  names which of the two conditions fired and how to fix that one. Where
  authentication terminates in front of the gateway — a sidecar, a mesh, a
  reverse proxy — set `server.allow_unauthenticated_network_bind = true`, which
  is logged on every start while it remains set.

  This is a real break for a deployment that binds wide with authentication
  off. It is the shape a browser or any other caller on the network can drive
  today, which is why it now stops rather than warns.

  **The shipped deployment templates were that deployment.** The Helm chart and
  the Kubernetes base bind `0.0.0.0` — a pod that binds loopback receives
  nothing — and carried no `auth` section at all, so an unmodified install would
  now exit at startup instead of serving. Both now require a credential and read
  it from a Secret:

  ```yaml
  # values.yaml
  auth:
    existingSecret: mcp-gateway-auth   # kubectl create secret generic ...
    secretKey: token
  ```

  **Upgrading the chart therefore needs that Secret created first.** Without it
  Kubernetes stops the pod with `CreateContainerConfigError`, naming the Secret
  and key it could not find — the container never starts, so there are no
  gateway logs to read.

  If a service mesh authenticates before anything reaches the pod, set
  `auth.mode=mesh`. That renders `server.allow_unauthenticated_network_bind`
  AND removes the credential and its Secret reference; setting the override on
  its own leaves credential mode active and the pod still demanding a token.

  **Both templates now also declare `server.public_url`.** On a `0.0.0.0` bind
  the Host gate admits a NAME only when it is declared, so an install that did
  not declare one answered the kubelet's numeric probes — staying green —
  while refusing every caller that dialled the Service DNS name. The chart
  derives the name from the release and namespace; the raw Kubernetes base
  carries the default `mcp-gateway` namespace and a comment saying to edit it.
  **Applying the base into another namespace, or fronting it with an ingress,
  means editing that one line**, and a refusal is logged with the Host it
  rejected.

  The Docker Compose template needed no credential: it publishes to
  `127.0.0.1:39400` on the host, so the container's `0.0.0.0` is the container's
  own interface. It now says so with
  `MCP_GATEWAY_SERVER__ALLOW_UNAUTHENTICATED_NETWORK_BIND`, which stops being
  true the moment that publish is widened.

  It is also a break, less obviously, for a reachable gateway whose
  `auth.public_paths` contains a blank entry — a stray `-` in that YAML list.
  Because public paths match by prefix, a blank entry is a prefix of every path
  and makes the whole gateway public, `/mcp` included, whatever `auth.enabled`
  says. Such a config previously started and read as protected. It now refuses,
  and the message names the list. Remove the empty entry.

- `server.public_url` is re-read on each request, so a configuration reload
  takes effect without a restart — **unless applying it would leave the tools
  reachable without a credential**, in which case the reload is refused and
  no backend is started or stopped and no configuration is published.

  It does not claim more than that. Reading a config file applies any
  `env_files` it names to the process environment before the file is validated,
  so a refused reload is not a complete no-op, and that is true of every failed
  reload rather than only this one.

  The refusal is judged against the configuration that would be **in force**,
  not against the file. `auth` and the override are not applied by a reload —
  the router snapshots them at startup — so declaring a `public_url` and
  enabling authentication in one edit does not pass the check.

  It then says which of two things a restart does with that same file, because
  they differ. A file that also enables authentication would not be refused for
  this reason on a restart: set both and restart, and that is the documented
  fix. A file that only declares the name will *refuse* at the next start,
  planned or not, so revert it or close the tool paths.

  Not refused *for this reason* is the whole promise. A restart reads the whole
  file, so a missing `env:` reference or an unreadable certificate can still
  stop it — this check answers its own question and no other.

- The startup log states what the anonymous identity cannot do and how to
  restore it, reports when the gateway binds to a non-loopback address while
  authentication is disabled, and warns on every start while
  `server.allow_unauthenticated_network_bind` is set — including when
  authentication is enabled with tool paths left public, which is the shape that
  escape hatch is most often reached from.

### Fixed

- **A backend that was not listening when the gateway started is no longer
  invisible for the rest of the process.** Warm-start made one attempt, and a
  backend that missed it kept an empty tool cache forever. Discovery skips a
  backend with an empty cache and a semantic query never fills one, so
  `gateway_search` could not see a backend that `gateway_execute` reached
  perfectly well. Warm-start now retries on a slow cadence, re-resolving the
  backend by name each attempt so a config reload is respected.

- **An empty tool list is no longer believed the first time.** A backend that
  answered with no tools had that emptiness cached like any other answer, so an
  earlier bounded retry re-read the same cached emptiness within microseconds
  and never reached the backend again. The cache entry is now invalidated
  between attempts, so the retry asks the question it was written to ask.

- **A mistyped backend command is reported instead of retried forever.** A
  spawn failure lost its error kind at the transport boundary, so a command
  that does not exist looked exactly like a port that was not listening yet —
  and warm-start respawned it once a minute for the life of the process with
  nothing saying the configuration was wrong. A missing command and a
  non-executable file are now permanent failures that stop both retry
  predicates. HTTP statuses are deliberately left unclassified: this protocol
  overloads 404 and 400 to mean the session expired, so a status-only
  classifier would be unsafe.

- **stdio mode has a health loop.** It never had one, so a backend that died
  while the gateway ran in stdio mode stayed dead until restart. The loop is
  now shared with the HTTP path. Both background tasks — the reaper and the
  health loop — are aborted through a guard on every exit path; previously the
  reaper was aborted only on the EOF path, and a dropped task handle detaches
  rather than stops, so a host cancelling `run_stdio` left both holding the
  backend registry alive.

- **Retry backoff is jittered, as it was already documented to be.** The module
  described full-jitter backoff and slept the plain exponential, so callers
  backing off from one failure woke together and hit the recovering service as
  a single burst — precisely the thundering herd the jitter was named for.

- **The Homebrew formula no longer mutates quarantine attributes during
  install.** It also emits an explicit release version rather than inferring
  one.

- **A config file reached through a symlink now reloads when its target is
  written.** The watcher followed the path it was given and nothing else, so a
  deployment that points `gateway.yaml` at a released file and rewrites that
  file in place produced no matching event, and the gateway kept serving the
  configuration it started with. The link is resolved on every filesystem
  event, so repointing it at a new release and editing that file is picked up
  too, as long as the new target sits in a directory watched at startup — the
  link's own directory and the directory of the target it pointed at then. A
  retarget outside those directories is tracked in #453. A plain config file is
  unaffected: it resolves to itself.

## [3.4.0] - 2026-07-27

### Added

- **`stop_when_idle_for`: release backend processes the gateway started, after
  they go unused (#392).** The gateway starts backends lazily but never stopped
  one once started, so every backend touched even once stayed resident for the
  life of the process. Measured on a six-day-uptime machine: `codex` held 37 MB
  for 21 hours to do 1.8 seconds of work; `trvl` 67 MB for 11.6 hours to do 7.6
  seconds.

  ```yaml
  backends:
    tavily:
      command: "npx -y tavily-mcp@0.1.4"
      stop_when_idle_for: 5m
  ```

  Valid **only for a backend the gateway starts itself** — one declared with a
  `command`. For a backend reached over a URL the gateway can close its client
  connection, but that does not stop the server on the other end, so the setting
  is **rejected at config load** rather than silently accepted. Locality does not
  grant ownership: a local HTTP MCP server on `127.0.0.1` is still not ours to
  stop. Absent means never stop, so upgrading changes no behaviour.

  Configurable per backend in the admin panel, which offers the control only
  where it applies and refuses it with an explanation elsewhere.

  Adds a third lifecycle state. A backend stopped on purpose is neither healthy
  nor failed: `Dormant` does not trip or heal a circuit breaker and is not probed
  by the health loop, so a sleeping backend no longer reports as degraded. A real
  fault still wins — an open breaker reports `Unhealthy` even for a backend that
  opted into stopping.

  In-flight work is refused rather than interrupted: a sweep that finds a request
  running declines, and the next one retries.

### Changed

- **BREAKING for library users: four config-writing functions moved module.**
  `write_config_and_reload`, `write_config_and_reload_outcome`,
  `mutate_config_and_reload`, and `ConfigMutation` now live in `config_reload`
  instead of `config_persistence`. Rust code calling them by the old path stops
  compiling and needs one import changed; `load_config_or_default` and
  `write_config` did not move. Nothing changes for anyone running the binary.

  The two modules referenced each other in a cycle, which no Rust build
  complains about and which made both harder to reason about. No compatibility
  re-export is provided, because a re-export from `config_persistence` would
  recreate the cycle it removes. The break is documented here rather than
  deferred to 4.0.0 deliberately: two of the four names are new in this release
  and never shipped, and crates.io lists no reverse dependencies on this crate
  (`/api/v1/crates/mcp-gateway/reverse_dependencies`, total 0, checked
  2026-07-27). Private consumers outside the registry cannot be ruled out.

- **`failsafe.retry.max_attempts` now means attempts, not retries.** It was
  passed straight to `backon`, which counts retries, so every backend made
  `max_attempts + 1` calls: a configured `3` produced four, and the shipped
  default of `3` has always meant four.

  The two user-facing statements of this setting already contradicted each
  other — `examples/gateway-full.yaml` documented it as "Total attempts
  (1 original + 2 retries)" while the struct doc said "Maximum retry attempts".
  The code now matches the example and the name.

  **Action required if you tuned around the old behaviour:** backends make one
  fewer call per request than before. Raise `max_attempts` by one to keep the
  previous number of calls. `max_attempts: 0` clamps to a single attempt rather
  than none.

- **A config-file reload now logs once, on completion, instead of twice.** The
  file watcher had its own copy of the reload sequence, and that copy logged
  `Config reload: applying patch` with the change summary before applying and a
  bare `Config reload: complete` afterwards. The watcher now runs the same
  reload used by the meta-tool and the admin UI, so a single line is emitted
  when the reload finishes, carrying the same change summary plus whether a
  restart is required. **If you grep logs for `applying patch`, that string is
  gone**; match on `Config reload: complete` and read the `changes` field. A
  reload that finds nothing to do logs at debug level, as before.

- **Helm charts track the 3.4.0 release.** `deploy/helm/mcp-gateway` and
  `deploy/helm/mcp-gateway-crds` `appVersion` and the default image `tag` move
  to `3.4.0`; both chart `version`s go to `0.1.2` for republishing. Bumped
  in the same commit as the crate version rather than at release time, so the
  repository never describes a 3.4.0 gateway that Helm would install as 3.3.2.

### Removed

- **`BackendConfig::idle_timeout` removed** (Rust API only; config files unaffected). The field was
  parsed, documented in `examples/gateway-full.yaml` as "Hibernate after 5 min
  idle", and read by exactly one thing in the codebase: a `Debug` formatter.
  Nothing enforced it. Operators set it in good faith — one real config carried
  `idle_timeout: 10m` on a stdio backend whose child then ran for over three days
  and burned 10.4 CPU-hours.

  Two attempts to implement it were reviewed and rejected. The blocker is not
  difficulty: the name spans stdio child-process lifetime, per-user session TTL,
  HTTP connection pooling, and remote scale-to-zero. Closing an HTTP client
  transport does not scale down the service behind it, so no single
  implementation can be correct for every transport.

  **Impact on existing configs: none at load time.** Config parsing tolerates
  extra keys, so files carrying `idle_timeout` keep loading unchanged. The
  gateway now logs a warning naming the key so its inertness is visible rather
  than silent. Note that any command which rewrites the config will drop the key
  along with surrounding comments, since the writer re-serialises from memory —
  delete it by hand first if you care about the comments.

  **Impact on API consumers:** code constructing `BackendConfig` with a struct
  literal that sets `idle_timeout` will no longer compile. Remove the field.

  **Why this is a minor bump and not a major one.** Removing a `pub` field is
  an incompatible change to the Rust library API, and that argues for 4.0.0.
  Two things argue the other way and win. The field was dead: setting it did
  nothing, so no behaviour changes for anyone. And the versioned surface of this
  project is the CLI and the config format, not the Rust library API — the crate
  ships a binary, the `pub` types exist for modularity and testing, and
  crates.io reports zero reverse dependencies. That scope is now stated
  explicitly in the README's **Versioning and stability** section rather than
  left to be inferred, which is the part that was genuinely missing before.

  The counter-argument was taken seriously: a policy published in this release
  cannot retroactively bind the promise made in 3.3.2, and zero reverse
  dependencies shows nobody HAS broken, not that breaking is permitted. It loses
  on cost. A major number spent on removing a field that never did anything
  makes every future major number mean less. Embedders should pin an exact
  version.

  The versioned surfaces are unaffected either way: configs carrying the key
  keep loading, and no command changes behaviour.

  **A replacement is planned: `stop_when_idle_for` (#392).** It does what
  `idle_timeout` claimed to do — stop a backend process the gateway started once
  it has been unused for a given time, and restart it on the next request — but
  scoped correctly. It is valid only where the gateway owns the process
  lifecycle (a backend with a `command`), and is rejected at config load for
  externally managed HTTP endpoints, because closing a client connection does
  not stop a server the gateway did not start. Local HTTP MCP servers are
  included in that exclusion: locality does not grant ownership.

  It also introduces a third health state. A backend stopped on purpose is
  neither healthy nor failed, and without `Dormant` a sleeping backend trips its
  own circuit breaker and shows as degraded.

### Fixed

- **The deployment guide said the Prometheus endpoint was off by default.** It
  has been on in a default build, and it is unauthenticated, so an operator
  following the guide could be exposing `/metrics` without knowing. The feature
  table now says so and points at the section explaining how to keep it off the
  public internet.

  The same section now lists `mcp_backend_idle_stop_close_failures`, the counter
  `stop_when_idle_for` raises when a backend refuses to shut down, together with
  the alert rule to watch it and what an operator does when it fires. A backend
  that will not stop can leave its child process alive, and until now nothing
  told anyone that had happened.

- **Two admin UI config edits at once could lose one of them silently.** Saving
  a config wrote the file first and took the reload lock afterwards, and every
  save on Unix used the same temp filename, `<config>.tmp`. Two saves arriving
  together therefore wrote the same temp file: whichever renamed first shipped
  the other's bytes while reporting its own edit saved, and the second rename
  failed with `Failed to replace config file: No such file or directory`. A
  test that runs eight concurrent saves reproduces it on the first iteration.
  Temp filenames are now unique per write, and the write happens inside the
  same lock as the reload, so a save reloads its own bytes.

  The same symptom had a second cause one layer up: each admin UI save read the
  whole config, changed one backend, and wrote the whole thing back, and the
  read happened before the lock. Two saves therefore both started from the
  pre-edit config, and the second wrote the first person's change out of
  existence while telling both callers it had saved. Adding, removing, and
  editing a backend now do the read, the change, the write, and the reload
  under one lock, so an edit that waits its turn builds on what it waited for.
  A test queues one edit behind another and fails if the queued edit erases it.

  Both bugs predate this release; they are fixed here because the reload work
  is what made the boundary visible.

- **Concurrent config reloads could orphan a backend process (#397).** A reload
  stops a modified backend and then registers its replacement, and registration
  replaces by name. Nothing serialized reloads, and four paths can trigger one
  at the same time: the `gateway_reload_config` meta-tool, the admin UI reload
  button, every admin UI backend edit, and the config-file watcher that fires
  when the file changes on disk. Two reloads racing could each
  register a replacement; the second registration discarded the first, and if
  ordinary traffic had started that first replacement in the gap, its child
  process was left running with nothing holding a handle to it — the exact leak
  `stop_when_idle_for` exists to prevent. A reload now holds a lock across the
  whole transaction — reading the config file, comparing it against the live
  one, applying the difference, and publishing the result — so the next reload
  compares against a config that already includes the previous one's work.
  Holding the lock only around the apply step is not enough: both reloads would
  have already decided "backend added" against the same stale live config
  before they queued, and both would still register.

- **Duration parsing rejected every `ms` value.** The parser tested the `"s"`
  suffix before `"ms"`, so `100ms` took the seconds branch and failed to parse
  `100m` as an integer. Affected every duration field in the config. Values
  using `ms` failed the config load outright rather than being misread, so no
  config that previously loaded changes meaning.

- **Config writes could park an admin request forever.** A save waited on the
  reload lock with no bound, and that lock is held across a whole reload:
  stopping backends, re-registering, republishing. One slow backend shutdown
  parked every settings-panel edit indefinitely, with retries queueing behind
  it. A write that is *waiting* for the lock now gives up after five seconds and
  answers 503, which is a refusal the caller can retry rather than a request
  that never returns. The bound covers the wait only. Once a write wins the
  lock it still runs the reload to completion, so the one edit that triggers a
  slow backend shutdown can still take as long as that shutdown takes; what no
  longer happens is every other edit queueing behind it forever. Reloads stay
  unbounded on purpose: refusing one would silently drop a change already
  written to disk, and a refused write changed nothing.

- **The scratch file a config save writes through could be silently reused.**
  The name came from a counter private to one process, and it was opened in a
  mode that truncates whatever is already there. A second gateway process, a
  leftover from a crashed run, or a wrapped counter put two writers on one file.
  The save now claims the file exclusively and moves to the next name rather
  than truncating a file someone else holds. It never deletes a scratch file it
  did not create, since a live writer may own it.

- **On Windows the config was written in place, so a crash mid-write truncated
  it.** Every other platform wrote to a scratch file and renamed it into place,
  which is atomic; Windows took a separate branch that did not, and no test
  reached it. Both branches are gone, replaced by one path every platform takes,
  with a bounded retry for the sharing violations Windows raises when another
  handle is momentarily open. The remaining Windows-specific piece, classifying
  OS error 32 as transient, is unverified on Windows itself.

- **A config write could block a runtime worker thread.** The rename retry above
  slept between attempts, in a synchronous function reached from an async task
  that holds the reload lock, lengthening the exact wait the five-second bound
  exists to cap. It also retried on permission errors, which are permanent on
  Unix, paying every sleep before failing anyway. Retries are immediate now.

- **The alert rule this release documents is now tested, offline.** Prometheus'
  own `promtool` checks it on four cases: silent when the counter is flat, firing
  after a single increment, resolving once that increment ages out of the window,
  and firing per backend rather than across all of them. The rules and their
  tests live in `deploy/prometheus/`. A test also covers the export half of the
  counter's path, that the recorder carries this metric name and its `backend`
  label through to scrape output. It issues the counter directly rather than
  driving a real failing shutdown, so it pairs with the existing pool tests
  covering the increment itself; neither half was observed before.

## [3.3.2] - 2026-07-15

### Fixed

- **OAuth: send the RFC 8707 resource indicator on every OAuth request (#369).**
  The MCP authorization spec (rev 2025-06-18) requires clients to include the
  `resource` parameter on the authorization request and on every token request
  so the authorization server can audience-bind the issued token to the target
  MCP server. The gateway discovered the protected-resource metadata but never
  sent `resource` back, so spec-strict providers (e.g. kapa.ai) rejected the
  login flow with `server_error`. The discovered resource identifier (falling
  back to the configured MCP endpoint URL when a server publishes no
  protected-resource metadata) is now threaded into all four OAuth requests:
  the authorization URL, the `authorization_code` exchange, `refresh_token`,
  and `client_credentials`. Reported by @crepererum.

### Changed

- **Helm charts track the gateway release.** `deploy/helm/mcp-gateway` and
  `deploy/helm/mcp-gateway-crds` `appVersion` and the default image `tag` now
  point at `3.3.2` (were stale at `2.19.0`); both chart `version`s bumped to
  `0.1.1`.

## [3.2.1] - 2026-07-07

### Changed

- **Internal refactor (MIK-6863).** Split the 3038-line `src/backend/mod.rs`
  into focused submodules (`pool`, `lifecycle`, `ops`, `metadata`,
  `cached_metadata`, `registry`, `annotations`, plus `tests`/`pool_tests`) so no
  file exceeds the 800-line hygiene cap. Pure move refactor: no behavioural or
  public-API change, identical test coverage.

## [3.2.0] - 2026-07-07

### Added

- **Per-user transport/session pool (MIK-6735).** Each caller identity now gets
  its own isolated upstream MCP transport slot instead of sharing a single
  connection. One identity's reconnect or failure no longer disrupts others on
  the same backend. Pool keys are `Shared | PerUser{binding}`; the `Shared`
  path is byte-identical to prior single-transport behaviour for backends that
  do not opt into per-user isolation.
- **Per-slot failsafe isolation.** The circuit breaker, rate limiter, and
  health tracker now live on each pool slot rather than a single backend-wide
  instance. A per-user slot tripping its circuit breaker Open can no longer
  reject another identity's healthy slot.
- **Identity-aware notifications.** `notify_with_headers()` routes client
  notifications to the caller's own pool slot. Notifications resolve the
  caller's session-bucket binding only and stay within the caller's identity
  (fire-and-forget, no response body, no cross-tenant path).
- **Pool telemetry.** `mcp_backend_pool_slots` gauge plus debug slot-count
  logging on slot creation and idle eviction.

### Changed

- Idle per-user pool slots are evicted after a TTL (300s, 60s sweep) to bound
  resource growth under many distinct identities.
- Config now accepts per-user isolation settings (previously rejected),
  retaining the http-required and oauth-conflict fail-closed validation.

## [3.1.3] - 2026-07-06

### Security

Hardening from a pre-release security audit. Four independent findings, no
externally observed exploitation.

- **Bearer token and API key comparison is now constant-time (CWE-208).** The
  auth layer compared the presented credential against configured secrets with
  `==`, whose early-exit on the first differing byte leaks match-prefix length
  through timing. Comparison now uses `subtle::ConstantTimeEq`, matching the
  existing constant-time path in the key server. Accepted and rejected
  credentials are indistinguishable by timing.

- **`tools/list` responses are now scanned by the firewall (OWASP ASI01
  tool-poisoning).** Backend-supplied tool `description`/metadata strings
  reached the client without passing through the response scanner that already
  guards the `tools/call` path, so a malicious backend could smuggle prompt
  injection or embedded credentials in tool metadata. Both the direct
  `tools/list` route and the aggregated discovery surface (`gateway_list_tools`
  / `gateway_search_tools`) now run the same `Firewall::check_response`
  scan-and-redact pass. The check is a no-op when the firewall feature or
  response scanning is disabled, so behavior is unchanged when unconfigured.

- **`TokenInfo` no longer leaks OAuth secrets through its `Debug` output.** The
  derived `Debug` impl printed `access_token`, `refresh_token`, and
  `client_secret` verbatim, so any log line or panic message that formatted a
  `TokenInfo` exposed live credentials. `Debug` is now a manual impl that
  redacts the three secret fields while preserving the non-sensitive fields for
  diagnostics.

- **`OpenApiConverter::convert_url` now validates its target against the SSRF
  deny list before fetching.** Converting an OpenAPI spec from a URL fetched
  the address with no private/reserved/loopback check, while every other
  capability fetch path (jsonrpc, graphql, executor, discovery, transport)
  already gated on `validate_url_not_ssrf`. A spec URL supplied on the CLI is
  untrusted input, so the converter now runs the same guard unconditionally,
  rejecting link-local, private, and loopback targets before any request.
  Beyond the literal pre-check, both `convert_url` and the OpenAPI import HTTP
  endpoint (`POST /ui/api/import/openapi`, admin-only, `fetch_spec`) now build
  their reqwest client with `PinningResolver` (validates every resolved IP,
  closing the DNS-rebinding TOCTOU window) and a redirect policy that
  re-validates each hop and stops at >=5 redirects, so a hostname that resolves
  to — or 3xx-redirects into — an internal address is rejected. On the UI
  endpoint these guards stay gated on the operator's `ssrf_protection` flag.


## [3.1.2] - 2026-07-06

### Security

- **Passthrough upstream session id is now partitioned per caller identity
  (MIK-6785).** This closes the second code path of the session-sharing class
  fixed for the minting path in 3.1.1 (MIK-6784). In Passthrough mode the direct
  backend route left the caller identity key unset, so every passthrough caller
  shared the empty-key default upstream-session bucket. Against a stateful
  upstream that binds data to the `MCP-Session-Id` rather than the bearer token,
  one passthrough caller could be served another caller's session-bound data.
  The forwarded backend credential is now hashed at its single read point via
  SHA-256 into a stable, collision-safe per-caller bucket key; the raw token is
  never logged or stored except as that one-way in-memory session-map key. Each
  distinct passthrough credential selects its own session bucket, the same
  credential reuses its bucket, and the no-credential non-required path keeps the
  shared default bucket, so single-tenant behavior is unchanged. With this the
  entire upstream session-sharing class is closed across both code paths and no
  follow-up remains.

## [3.1.1] - 2026-07-06

### Security

- **Upstream MCP session id is now partitioned per caller identity (MIK-6784).**
  One `HttpTransport` instance is shared across all gateway users for a given
  backend, and the upstream `MCP-Session-Id` was held in a single shared slot.
  It was written from the first caller's response and then attached to every
  other caller's outbound request. Against a stateful upstream that binds data
  to the session id rather than the bearer token, one user's session-bound data
  could be served to another. Session state is now keyed by the caller's stable
  identity binding and never stored on shared transport state; the empty-key
  default bucket keeps single-tenant behavior unchanged. Session expiry evicts
  only the affected caller, and transport close terminates every per-identity
  session. Also folded in: a startup warning when single-user mode coexists with
  an OAuth-enabled backend, and config-load rejection of an enabled OIDC
  provider that has an empty audience list. Passthrough mode still uses the
  shared default bucket (the trusted-internal path the audit scoped out) and is
  tracked as a follow-up.

### Fixed

- **stdio serve boots without a mounted config (Glama build).** An explicit
  `--config <path>` that does not exist was a hard error, so
  `mcp-gateway serve --stdio --config /config.yaml` exited non-zero when the
  file was absent — the exact shape of Glama's container build smoke-test,
  which passes that placeholder while the generated Dockerfile never writes the
  file. The stdio serve path now downgrades a missing explicit `--config` to
  the normal no-config resolution (fallback locations, env vars, then defaults)
  with a stderr warning. Scoped to stdio only: the HTTP server path stays
  fail-loud so a missing intended config can never silently start with
  authentication disabled.

## [3.1.0] - 2026-07-05

### Added

- **RFC 8693 token-exchange identity propagation** (MIK-6729). A backend can
  opt in per backend with `strategy: token_exchange`. The gateway exchanges a
  gateway-signed subject assertion for a scoped downstream token at the
  backend's token-exchange endpoint, then injects that token on the call. The
  gateway stores no credential. Exchanged tokens live in process memory keyed
  by subject and audience with per-entry expiry, and the client assertion is
  minted fresh for each call. The strategy stays dormant until a backend opts
  in.

### Fixed

- **`/auth/token` now uses standard OAuth form-encoding.** The key server's
  `POST /auth/token` endpoint accepted a JSON request body. The key server is
  disabled by default, and this endpoint is opt-in; even so, the JSON body
  did not match RFC 8693 / RFC 6749 §4.1.3, which specify
  `application/x-www-form-urlencoded`. Off-the-shelf OAuth clients already
  send form-encoded requests, so this aligns a dormant, opt-in endpoint with
  the standard. A JSON body now gets HTTP 415 Unsupported Media Type.

## [3.0.2] - 2026-07-05

### Fixed

- **Fail closed when identity propagation is required but the transport cannot
  carry it.** A backend configured with `identity_propagation.required` on a
  non-HTTP transport (stdio/websocket) previously minted and audited an
  identity token that the transport then silently dropped, letting the call
  proceed unauthenticated under the shared gateway static credential. Added
  `Transport::carries_identity_headers` (default false, HTTP overrides true)
  and the dispatch path now refuses before minting when propagation is
  required and the transport cannot carry it.
- **Bounded transparency-log reads to prevent memory exhaustion (MIK-6710).**
  `log_contains_signed_entry`, `verify_log_inner`, and `show_session_entries`
  loaded the entire audit log into memory with no size bound, so an
  unbounded or attacker-grown transparency log could exhaust gateway memory
  on every audit verify or show call. Reads are now capped at 256 MiB and
  fail closed instead of allocating an oversized buffer. Crash recovery
  (`recover_chain_state`, run on every logger open) no longer reads the whole
  file either; it now scans backward from the last 4 MiB to find the final
  complete line, so recovery time no longer scales with total log size.
  Hash-chain verification logic is unchanged.
- **Pinned the admin-UI htmx CDN script with Subresource Integrity.** The
  bundled web UI loaded htmx from unpkg with no integrity attribute, so a
  compromised CDN could serve altered JavaScript. The script tag now carries a
  SHA-384 SRI hash and `crossorigin=anonymous`. The web UI is opt-in and
  normally localhost-bound, so severity is low.

## [3.0.1] - 2026-07-03

Security hardening fast-follow for the 3.0.0 end-user identity-propagation
feature. No API changes; both items close latent gaps on the per-user
credential path.

### Security

- **Fail-closed provider adapter (MIK-6741).** `McpProvider::invoke` now
  refuses to dispatch a backend configured with `identity_propagation.required`,
  because the `Provider` trait carries no per-user identity and would otherwise
  fall back to the shared gateway session. No live route reaches this adapter
  today; the guard is a tripwire so a future wiring cannot become a silent
  identity bypass. (`src/provider/mcp_provider.rs`)
- **Tamper-evident credential-propagation audit (MIK-6740).** The direct
  `/mcp/{name}` route now writes redacted `idp_mint` / `idp_refuse` events to
  the transparency log at the mint and refuse decision points. Entries carry
  only subject / backend / audience / reason — never token or assertion bytes
  (enforced structurally and by a canary-secret regression test). Audit writes
  are best-effort and never fail the user request; the mint/refuse decision
  itself remains fail-closed. (`src/gateway/router/backend_handlers.rs`)

> **Breaking change.** The default OAuth posture changes: a gateway with
> `auth.enabled: true` no longer serves one stored backend token to every
> caller (see `src/oauth/storage.rs`). See "Added" and "Security" below,
> and `docs/UPGRADING-3.0.md` for the upgrade path.

### Added

- **Per-user OAuth isolation as the fail-closed default** (ADR-008, MIK-6742; see `docs/adr/ADR-008-multi-user-oauth-isolation.md`). On a multi-user gateway, a backend that requires a per-user OAuth identity now refuses a call that lacks a verified end-user identity instead of falling back to a shared stored token. Two invariants are enforced end to end:
  - **INV-1**: a per-user backend never falls back to a shared or other-principal token. Required-and-unresolved always refuses.
  - **INV-2**: a multi-user gateway never serves a gateway-held OAuth token to an arbitrary caller, unless the operator explicitly opts a backend into `oauth.shared_account: true` (logged). Multi-user detection is itself fail-closed: auth enabled implies multi-user unless the operator declares `auth.single_user: true`; more than one API key or any OIDC issuer overrides that declaration.
  - Coverage spans both call paths that resolve an OAuth token: MCP backends (`MetaMcp::enforce_oauth_isolation`) and capability-backed REST connectors (`validate_oauth_isolation` in `src/capability/execution_context.rs`). (#316, #317)
- **RFC 9728 protected-resource metadata + refresh-task lifecycle** (MIK-6750; #316). The gateway now advertises per-backend OAuth requirements so a capable MCP client can run its own browser-based login and attach its own token per request instead of relying on a gateway-held credential. OAuth refresh tasks are scoped to transport lifetime and are aborted when a transport is discarded, closing an orphaned-task leak.
- **Client-supplied OAuth passthrough** (MIK-6746). A caller can attach its own backend credential on the request; the gateway forwards it without storing a copy, covering the direct backend route (`/mcp/{name}`) as well as meta-MCP dispatch.
- **v3.0.0 upgrade posture-notice migration** (#318, MIK-6742). Read-only: on first startup after upgrading, the gateway backs up the existing `gateway.yaml` to `gateway.yaml.bak.<old_version>`, detects whether the deployment declares a multi-user posture, and prints a one-time notice. No config field is changed automatically. See `docs/UPGRADING-3.0.md`.
- **End-user identity propagation to backend MCP servers** (MIK-6704 epic; ADR-007 framework-first). The gateway can mint a per-user credential for a backend configured with `identity_propagation` and attach it on the wire, instead of forwarding only a shared static credential. A strategy-agnostic async `IdentityPropagation` trait with a first-party `SignedAssertionStrategy` (ES256 assertions signed by the gateway key) is wired across every invocation surface: meta-MCP dispatch (`gateway_invoke`), Code Mode (`gateway_execute`, single + chain), and the direct backend route (`/mcp/{name}`).
  - **Fail-closed (IDP.2):** a `required` backend refuses the call (never a static-credential fallback) when there is no verified identity, no strategy wired, minting fails, or a minted header does not parse. Non-HTTP transports (stdio/websocket) cannot carry the credential header and are rejected at config load. #317 extends this fail-closed behavior to every direct-route method.
  - **Tenant isolation (IDP.3):** per-request credential headers are passed by value and never stored on the shared transport.
  - **Identity-aware caching (IDP.8):** a collision-safe `cache_binding` (user + audience) is mixed into the response and idempotency cache keys, so per-user results cache in isolation rather than leaking across users or being dropped.
  - Deferred as tracked follow-ups (not in this release): additional strategies token-exchange (MIK-6729) and vault (MIK-6730), per-user transport/session pooling (MIK-6735, `session_mode: per_user` stays fail-closed until then), transparency-log audit of propagation events (MIK-6740), and `McpProvider` adapter hardening (MIK-6741).

### Changed

- **Major version bump to 3.0.0** ("Trust Fabric"): per-user OAuth isolation (ADR-008), identity propagation (ADR-007), transparency-log per-entry HMAC verification (MIK-6700), control-plane read-reflects-store (MIK-6701), collision-safe role-mapping hot-reload (MIK-6702), and server-run SIEM evidence export (MIK-6703).
- **Default OAuth posture on auth-enabled gateways.** Previously, any gateway with `auth.enabled: true` served each backend's stored OAuth token to every authenticated caller. Now a backend requiring per-user identity refuses calls lacking one. Existing `gateway.yaml` files load unchanged; the upgrade migration only backs up the file and prints a notice (see Added, above). To keep the previous shared-credential behavior, add one line: `auth.single_user: true` for a personal gateway, or `oauth.shared_account: true` under a specific backend for an intentionally shared service account.

### Security

- **Cross-user OAuth token exposure closed** (ADR-008, MIK-6742, MIK-6751, MIK-6752). Before this release, a shared/multi-user gateway stored one OAuth token per `(backend, resource)` and attached it caller-agnostically, so one user's call to a personal-OAuth backend (for example Gmail) could be served with another user's login. This predates 3.0.0 and is closed by the INV-1/INV-2 guards described above.
- Bump `cmov` 0.5.3 → 0.5.4 (GHSA-3rjw-m598-pq24). Bump `quick-xml` 0.40 → 0.41 (RUSTSEC-2026-0194/0195, MIK-6731).

## [2.19.0] - 2026-06-08

### Added

- **Capability response projection applied at dispatch** (MIK-3534, closes the MIK-3530 epic): a capability may now declare a canonical `projection: ProjectionSpec`, and `gateway_invoke` applies it to the dispatched response — mapping backend fields onto the canonical schema (`actor`/`subject`/`env_time`/`url`/`body`) while preserving the untouched payload under `_raw`. The descriptor field added in MIK-3531 (`Tool.projection`) is now surfaced from the capability via `to_mcp_tool`, and the projection engine from MIK-3533 is now wired into the live path. Projection is applied **last** — after `response_transform` and output-schema validation — so it is leak-safe by construction: `_raw` is built from the already-redacted, already-validated payload, so a field redacted by `response_transform` can never reappear. It rides the same `_full` opt-out as `response_transform` (so the response cache and idempotency layers inherit correctness), operates on the inner capability payload rather than the MCP envelope (avoiding bug #167), never projects error envelopes, and passes the response through untouched when the spec resolves no fields (fail-fast). Internal orchestration (chain / playbook steps) requests the unprojected payload so step-output interpolation is unaffected. Covered by tests for the redaction-leak guard, `_full` bypass, text-envelope fail-fast, error-envelope skip, and inner-payload targeting.

## [2.18.0] - 2026-06-08

### Added

- **Projection engine** (MIK-3533): `projection::project(response, spec)` maps a backend response onto the canonical schema (`Actor`/`Subject`/`EnvTime`/`Url`/`Body`) using a `ProjectionSpec`'s per-field dotted source paths (e.g. `assignee.email` → `Actor.email`). The original payload is always preserved under `_raw`. **Fail-fast:** if a spec resolves no canonical fields against a response, the original response is returned unchanged rather than an empty projection — a projection never silently drops data. Pure, no behavior change yet (not wired into the dispatch path; that is the per-backend-mappings step, MIK-3534). Covered by tests for leaf projection, fail-fast, empty spec, partial resolution, and scalar stringification.

## [2.17.0] - 2026-06-08

### Added

- **`list_tools` role filter** (MIK-3532): `gateway_list_tools` accepts an optional `role` argument (`selector` / `extractor` / `enricher` / `action`) and returns only tools of that role, in both the single-backend and aggregate paths. A tool's effective role is its explicit `role` tag (MIK-3531) if present, otherwise inferred conservatively from its name + `readOnlyHint` (read-only `search`/`list`/… → selector, `get`/`read`/… → extractor, everything else → action — the safe default). So the filter is useful immediately without every tool being hand-tagged. An invalid `role` value is rejected (fail-fast) rather than silently returning everything. The `gateway_list_tools` meta-tool is itself tagged `selector`. Covered by unit tests for inference, explicit-tag precedence, matching, and argument parsing.

## [2.16.0] - 2026-06-08

### Added

- **Tool descriptor carries `role` + `projection`** (MIK-3531, completes the foundation): the MCP `Tool` descriptor now has two optional fields — `role` (`selector`/`extractor`/`enricher`/`action`) and `projection` (a `ProjectionSpec`). Both default to `None` and are omitted from the wire for untagged tools, so existing payloads serialize and deserialize byte-for-byte as before. This is the descriptor surface the projection epic consumes: `list_tools` role filtering (MIK-3532) and response projection (MIK-3533/3534) build on it. No behavior change. Serialization-contract tests assert untagged tools omit the fields and pre-existing JSON still parses, and that tagged tools round-trip role + projection.

## [2.15.1] - 2026-06-08

### Fixed

- **Stdio-mode warm-start never prefetched backend tools** (MIK-4649): in `serve --stdio` mode (how Claude Code / Codex connect), warm-start started each backend but **skipped tool prefetch** — that step was gated on HTTP mode only. Subprocess MCP backends (e.g. `codex`) were therefore left with an empty tool cache, and since discovery skips empty-cache backends, their tools never appeared in `gateway_search` / `tools/list`. Tool prefetch now runs in both transport modes. Root-caused empirically against the live gateway: `codex mcp-server` serves `tools/list` fine, but the gateway logged only pings for it and never a tool fetch. Regression test asserts prefetch occurs in both modes.

## [2.15.0] - 2026-06-08

### Added

- **Projection layer foundation** (MIK-3531, part of the MIK-3530 epic): new `src/projection/` module with the canonical projection vocabulary — `Actor`, `Subject`, `EnvTime`, `Url`, `Body`, a `Projected<T>` wrapper that always preserves the untouched backend payload under `_raw`, a `ProjectionSpec` (declarative canonical-field → source-path mapping), and a `Role` enum (`selector` / `extractor` / `enricher` / `action`, defaulting to `action`). Types and serialization contract only — no behavior change. Subsequent PRs wire `role`/`projection` onto the tool descriptor and add the projection logic that consumes a `ProjectionSpec` (MIK-3532 / MIK-3533 / MIK-3534). Covered by round-trip serialization tests.

## [2.14.0] - 2026-06-08

### Added

- **Response-projection safety: `_full` opt-out + fail-fast warning** (MIK-3533): the gateway already supports per-capability `response_transform.project` (trimming proxied responses to listed fields). This release makes it safe to rely on:
  - **`_full: true`** — passing `_full: true` in a tool call's arguments bypasses response projection and returns the unprojected payload. The flag is a gateway directive: it is stripped before the request reaches any backend, and a `_full` call bypasses the response cache and idempotency replay so its (unprojected) result can never be served to, or replayed from, a normal projected call.
  - **Fail-fast warning** — if a projection would empty a previously-populated payload (e.g. the spec names fields absent from this particular response), the gateway logs a warning and still applies the projection. It does **not** fall back to the full response, because `project` can be a privacy/allowlist boundary and a fallback would risk leaking the dropped fields; callers who want the full payload pass `_full: true`.

  Covered by deterministic tests (`json_is_populated` truth table, projection-to-absent-field empties payload, healthy-projection passthrough).

## [2.13.0] - 2026-06-08

### Added

- **Retry transient outbound transport errors with backoff** (MIK-5081): capability calls run inside the gateway's own tokio runtime, so a momentary connect/timeout failure reaching an upstream (e.g. `api.linear.app` under host load) previously surfaced straight to the caller as a `BACKEND_ERROR`. Outbound REST, GraphQL, and JSON-RPC requests now retry transient connection/timeout failures up to 3 attempts with exponential backoff (100ms, 200ms). HTTP error *statuses* (4xx/5xx) are not retried. Covered by a deterministic regression test.
- **`/health` reflects real backend health, not just the circuit breaker** (MIK-5080): `/health` derived overall health solely from circuit-breaker state, so a backend timing out under load reported healthy until the breaker tripped Open. Registry `BackendStatus` now carries `healthy`, `consecutive_failures`, and `latency_p95_ms` from the health tracker, and the **in-process capability backend** (previously absent from `/health` entirely, and the source of the original incident) now has its own health tracker: it records every capability execution outcome and is folded into overall health and exposed as a `capability_backend` field in the admin `/health` payload. Overall health now requires a non-Open circuit *and* live health trackers across both registry and capability backends.

## [2.12.2] - 2026-06-08

### Fixed

- **stdio logs corrupted the JSON-RPC stream** (#224): `serve --stdio` wrote tracing output to stdout, interleaving log lines (with ANSI escapes) among the newline-delimited JSON-RPC frames and breaking MCP clients such as Claude Desktop. `setup_tracing` now writes all log output to stderr regardless of mode, so stdout carries protocol only. Added a regression test that spawns `serve --stdio` and asserts every stdout line is valid JSON. Thanks to @robn for the report and the `strace` diagnosis.
- **`tool list` hard-failed on a missing capability directory** (#225): the command errored with "Capabilities directory does not exist" when its local capability-YAML directory was absent, and its naming implied it reflected the running gateway's config (it does not — it ignores `-c gateway.yaml` and `capabilities.enabled`). `tool list` now degrades gracefully (empty catalogue, exit 0) with a one-line note clarifying it scans a local catalogue independent of server config; the `--help` text and command description were corrected to match. Thanks to @robn for the report.

## [2.12.1] - 2026-05-25

### Fixed

- **`linear_get_issue` cache TTL** (#205): set TTL to 0 to fix claim-protocol read-after-write failures where `verify_claim` returned `Missing` immediately after `linear_create_comment` due to stale cached issue JSON.
- **Capability hot-reload watcher race at startup** (#188): watcher exited early with "No capability directories to watch" because it read `backend.watched_directories()` before the async loader had registered paths. Fix: synchronous `register_directories` call before the async loader spawns, so the watcher always sees populated paths from boot.
- **Capability count drift** (#199): synced `capability_count` 112→113 across `benchmarks/public_claims.json`, `capabilities/README.md`, `docs/COMMUNITY_REGISTRY.md`, and `docs/BENCHMARKS.md`; restores `public_claims_validation` test suite to 7/7.

### CI / Build

- **npm trusted publishing + provenance attestation** (#203): replaced `NPM_TOKEN` secret with OIDC trusted publishing; npm packages now carry provenance attestation.
- **Automated package + formula publish** (#201): release workflow now publishes the npm package and Homebrew formula automatically on tag push.
- **Dropped NPM_TOKEN fallback** (#202): removed the legacy secret fallback after trusted publishing was confirmed live.
- **Least-privilege CI workflow permissions** (#214): top-level `permissions: contents: read` added to `ci.yml`, resolving CodeQL `actions/missing-workflow-permissions` findings.
- **Dependabot bumps**: `serde_json` 1.0.149→1.0.150, `jsonwebtoken` 10.3.0→10.4.0, `tower-http` 0.6.10→0.6.11, `rcgen` 0.14.7→0.14.8; CI actions: `docker/build-push-action` 7.1→7.2, `docker/setup-buildx-action` 4.0→4.1, `actions/setup-node` 5.0→6.4, `docker/metadata-action` 6.0→6.1, `trufflesecurity/trufflehog`.

### Docs

- **README "vs Anthropic MCP Tunnels" section** (#204, MIK-4696): added comparison section for users evaluating the official Anthropic tunneling offering.

## [2.12.0] - 2026-05-20

### Added

- **OAuth cancellation-survival** (MIK-4486): the interactive browser handshake for OAuth-enabled backends now runs on a detached `tokio::spawn` task. When the calling MCP request future is cancelled (e.g. the client times out before the user finishes browser auth), the OAuth task continues to completion and persists the token to `~/.mcp-gateway/oauth/`. The next call from the client finds the cached token and skips re-authorization. Previously, request cancellation killed the callback server and any browser auth that landed afterwards went nowhere. Docs: `docs/OAUTH_CONFIG.md § First-time interactive authorization`.
- **OAuth discovery progress at INFO level** (MIK-4486): `Discovering …` and `Discovered …` log lines in `src/oauth/metadata.rs` promoted from DEBUG to INFO so operators can see the full handshake progression in the default log without flipping `RUST_LOG`.
- **OAuth cancellation-survival regression test** (MIK-4486): new `tests/oauth_cancellation.rs` pins the `tokio::spawn`-survives-outer-drop semantics the fix relies on.
- **Windows x86_64 release artifact**: release workflow now builds and publishes `mcp-gateway-windows-x86_64.exe` for `x86_64-pc-windows-msvc`.
- **MCP tool annotation policy** (MIK-2985): ADR-003 documents the hybrid pass-through/fill policy; gateway meta-tools now carry annotation titles plus all four MCP 2025-11-25 behavior hints.

### CI / Build

- **Windows compile coverage in CI**: `ci.yml` now runs `cargo check --all-features` on `windows-latest` in addition to the existing Linux checks.

### Docs

- **README Windows install path**: install table and direct-download section now include the Windows MSVC release binary.
- **`docs/always-load-pins.md`** (MIK-3639): client-side pin-set rationale for Claude Code v2.1.121 `alwaysLoad` flag — recommends `hebb`, `linear`, `gateway-core`, `apple-calendar` as hot-path always-loaded MCP servers with rollback procedure.

### Tests

- **Windows path regressions**: added coverage proving Windows-style path separators do not bypass tool-poisoning detection and do not destabilize capability hash pinning.

### Fixed

- **Proxy-time SSRF check trusts configured backends** (MIK-3529): the guest-side SSRF re-check in `authorize_destination` no longer rejects operator-declared backend URLs that resolve to loopback or private IP ranges. A new `security.trust_configured_backends` flag (default `true`) exempts URLs matching a configured backend host from the proxy-time guard; set to `false` to restore strict re-checking. Dynamic/unconfigured destinations continue to be SSRF-validated. Resolves the regression where the gateway blocked traffic to its own configured `127.0.0.1` MCP backends.

## [2.11.0] - 2026-04-25

### Changed

- **Dual licensing introduced** (Path C, MIK-3034 / MIK-3036): designated Enterprise Edition modules are now licensed under PolyForm Noncommercial 1.0.0; everything else remains MIT. See [LICENSE-EE.md](LICENSE-EE.md) and the License section of the README for the full file list.
- Every EE-designated source file now carries an `// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0` header.
- Releases prior to v2.11.0 remain entirely MIT and stay MIT forever; the new license terms apply only to commits in v2.11.0 and later that touch EE-designated paths.

### Added

- **Output schema enforcement** in `MetaMcp::invoke`: tool results are validated against the capability's declared output schema for both meta-MCP and backend-routed dispatch paths. Non-conforming results return an LLM-readable "Tool result validation failed" error so agents can self-repair.

## [2.10.0] - 2026-04-16

### Security

- **Destructive confirmation gate** (OWASP ASI09): Meta-tools annotated as destructive now require explicit user confirmation before execution, preventing unintended data loss from autonomous agents.
- **HMAC-SHA256 message signing** (OWASP ASI07, ADR-001): Inter-agent messages carry HMAC-SHA256 signatures with nonce-based replay protection, ensuring message integrity and authenticity across the gateway mesh.
- **Anomaly blocking gate** (OWASP ASI10): Anomaly detector promoted from warn-only to active blocking — anomalous tool invocation patterns are now rejected, not just logged.
- **Response content inspection**: Outbound responses scanned for credential exfiltration patterns (API keys, tokens, secrets) before reaching the AI client.
- **Tool poisoning validator**: Hash-pinned capability definitions detect tampering in OpenAPI-imported tool schemas.

### Added

- **A2A transport adapter — Phase 1**: Google Agent2Agent (A2A) protocol support with types, client, translator, and provider. Proxy A2A agents as native MCP backends. Feature-gated behind `a2a` (included in defaults).
- **Upgrade command** (`mcp-gateway upgrade`): Version-stamp tracking, what's-new registry with arrow-style output, config backup before migrations, and post-upgrade migration framework.
- **`gateway_reload_capabilities` meta-tool**: Agent-callable hot-reload of capability definitions without gateway restart.
- **FSM state-gated tool visibility** (#113): Finite state machine controls which tools are surfaced based on session state, enabling multi-step workflows where tools appear/disappear as the conversation progresses.
- **Structured self-healing error responses** (#115): Tool invocation errors now include structured recovery hints (retry, fallback tool, parameter correction) for autonomous agent self-repair.
- **Response transforms wired into `gateway_invoke`** (#118): Per-capability field projection and PII redaction now applied inline during tool invocation, not just in playbooks.
- **Universal protocol adapters**: GraphQL and JSON-RPC 2.0 adapters join HTTP REST — backends speaking any of the 3 protocols are proxied transparently.
- **SKILL.md / agentskills.io compatibility** (#114): Parser, registry, and CLI for the emerging agent skills specification.
- **Multi-platform MCP guides**: Prompts and annotations tailored for Claude, GPT, Gemini, and other LLM clients.
- **Trawl web extraction capability**: Structured web content extraction as a built-in capability.
- **8 knowledge capabilities**: Gzip/deflate/brotli compression added to reqwest; 8 new knowledge-domain capabilities bundled.
- **OAuth refresh improvements**: `client_id`/`client_secret` sent on token refresh; Google capabilities migrated to new auth flow.
- **Kani formal verification proofs**: State machine and kill-switch budget decision correctness proved with Kani.

### Changed

- **Unified error handling**: Router, SSE, WebUI, webhook, and middleware error responses consolidated into shared HTTP error builders with consistent JSON-RPC error codes.
- **Config runtime contract**: Reload outcomes now distinguish restart-required vs. hot-reloadable changes; restart-required outcomes exposed to callers.
- **Backend metadata cache**: Coalesced cache refreshes with shared snapshots reduce redundant backend queries.
- **Meta-MCP prompt cache**: Isolated into dedicated module for testability.
- **Prometheus metrics hardened**: Install and export logic made more robust.

### Fixed

- Missing `KeyInit` import for HMAC message signing.
- Clippy `doc_markdown` warnings in invoke.rs.
- Skills parser doc comment incorrectly compiled as doctest.
- Stale "4 meta-tools" claims removed from all public surfaces.
- JSON-RPC response serialization and contract hardening.
- Stdio request parsing alignment and pending-write clearing on failure.
- Backend notification routing via `notify`.
- Provider tool content preservation.
- Transform chain error context propagation.
- HTTP close header contract alignment.
- Public capability count claims updated (93 to 101).

### Docs

- **OWASP Agentic AI compliance matrix**: 8/10 Top 10 items covered, with per-item status and mitigation references.
- **ADR-001**: Inter-agent message signing design (OWASP ASI07).
- **ADR-002**: A2A transport adapter design.
- **AP2/Galileo evaluation**: Independent agent protocol evaluation results.
- **README**: Agent-first install flow, OWASP 8/10 badge, independent review links (Ruach Tov), VS Code / Cursor one-click install badges, tool count corrections.
- **CODEOWNERS** added.

### CI / Build

- TruffleHog secrets scanning job.
- Workflow action SHAs pinned.
- Release workflow lint fix and pre-publish gate.
- Published crate contents curated (`include` list).
- Dependabot automation added.
- Smithery manifest added.

### Tests

- Firewall action resolution proof.
- Kill-switch budget decision proof.
- Kani state machine proofs.
- Meta-MCP tool-count assertions updated for `gateway_reload_capabilities`.
- README startup claim guards.

## [2.9.1] - 2026-03-24

### Changed

- **refactor: extract `build_meta_mcp` helper** — ~110 lines of duplicated Meta-MCP construction logic consolidated into a single reusable function.

### Fixed

- **Notion capability `database_id` parent type** — `notion_create_page.yaml` now correctly supports `database_id` as a parent type in addition to `page_id`.

### Dependencies

- **tokio-tungstenite** bumped to 0.29.0.

### Tests

- **6 new stdio edge-case tests** — covers malformed JSON, empty lines, oversized payloads, concurrent requests, graceful shutdown, and partial reads (2576 total).

## [2.9.0] - 2026-03-24

### Added

- **Native stdio transport** (`mcp-gateway serve --stdio`): gateway now reads newline-delimited JSON-RPC from stdin and writes responses to stdout, enabling direct use as a Claude Code / MCP stdio subprocess without a bridge script. Supports all MCP methods (`initialize`, `tools/list`, `tools/call`, `prompts/*`, `resources/*`, `logging/setLevel`, `ping`) and batch requests. Reuses the same `MetaMcp` dispatch logic as the HTTP server.
- **5 new capability YAML files**:
  - `capabilities/productivity/notion_create_page.yaml` — create a Notion page under any parent page or database
  - `capabilities/finance/stripe_create_payment_intent.yaml` — create a Stripe PaymentIntent (modern payments API)
  - `capabilities/developer/github_create_issue.yaml` — create a GitHub issue with labels, assignees, and milestone
- **`capabilities/developer/` directory** — new top-level category for developer-tool capabilities

## [2.7.3] - 2026-03-16

### Added

- **WebUI: Cost tracking dashboard** — new "Costs" tab at `/ui#costs` showing aggregate spend, per-key and per-session breakdowns with stat cards and tables. Backed by `GET /ui/api/costs` endpoint (admin-only, feature-gated behind `cost-governance`).

## [2.7.2] - 2026-03-15

### Fixed

- **Dependency minimum versions raised** — `Cargo.toml` version constraints now exclude all known vulnerable ranges: `bytes` ≥1.11.1 (RUSTSEC-2026-0007), `chrono` ≥0.4.20 (RUSTSEC-2020-0159), `rustls` ≥0.23.18 (RUSTSEC-2024-0399), `time` ≥0.3.47 (RUSTSEC-2026-0009), `tracing-subscriber` ≥0.3.20 (RUSTSEC-2025-0055).

### Added

- **Glama registry metadata** — `glama.json` for MCP server registry scoring and author verification.
- **Automated crates.io publishing** — release workflow now auto-publishes to crates.io on tag push.

## [2.7.1] - 2026-03-14

### Fixed

- **WebUI: JS syntax error breaking all views** — orphaned code block with top-level `return` statements caused `Uncaught SyntaxError: Illegal return statement`, preventing the entire UI from loading in any browser.
- **WebUI: missing Cache-Control header** — `/ui` response now sends `no-cache, no-store, must-revalidate` to prevent browsers from serving stale HTML after gateway rebuilds.
- **WebUI: confusing auth indicator** — when authentication is disabled, the auth bar now auto-detects this and shows a green "Auth disabled" status instead of the misleading red "Not authenticated" with a non-functional "Set API Key" link.

## [2.7.0] - 2026-03-14

### Added

- **Intelligent Tool Surfacing** (RFC-0081): Static tool pinning via `surfaced_tools` config — operators can expose high-value backend tools directly in `tools/list` for one-hop invocation while preserving the compact Meta-MCP surface for the rest.
- **Tool Annotations** (MCP 2025-11-25): All meta-tools now carry `readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint` annotations. `gateway_search_tools` includes `outputSchema`.
- **"Did You Mean?" suggestions**: Levenshtein-based typo correction on both meta-tool dispatch (`handle_tools_call`) and backend tool invocation (`gateway_invoke`).
- **Dynamic meta-tool descriptions**: Tool and server counts are live (`format!()`) instead of static "150+".
- **Enhanced initialize instructions**: Discovery-first pattern with "use `gateway_search_tools` FIRST" emphasis and dynamic counts.
- **SEP-1821: Filtered `tools/list`** (behind `spec-preview` flag): Optional `query` parameter triggers semantic search returning filtered tools with full schemas.
- **SEP-1862: `tools/resolve`** (behind `spec-preview` flag): Deferred schema loading — resolve a tool's full `inputSchema` by name on demand.
- **Dynamic promotion** (behind `spec-preview` flag): Session-scoped auto-surfacing of tools after successful `gateway_invoke`, with FIFO eviction at configurable max (default: 10).
- **`notifications/tools/list_changed`**: Gateway now sends the notification it already advertised — fired on backend connect/disconnect and config reload. Fixes MCP spec compliance gap.
- **Config path discovery**: Auto-detect `gateway.yaml` / `config.yaml` in cwd, `~/.config/mcp-gateway/`, and `/etc/mcp-gateway/` when `--config` is omitted.
- **Config validation**: `Config::validate()` checks port, backend name validity, and HTTP URL parseability at load time.
- 8 new synonym groups in search ranking (12 → 20 total).
- 78 new tests across both RFCs.

### Changed

- **Config split** (RFC-0080): `config/features.rs` (650 lines) split into 10 focused modules under `config/features/`.
- **Error handling overhaul**: 48 of 58 `Error::Internal(String)` replaced with 6 typed variants (`ConfigValidation`, `CircuitOpen`, `ToolNotFound`, `OAuth`, `Tls`, `ConfigWatcher`).
- **3 dependencies removed**: `dialoguer` (replaced with stdin prompt), `md5` (replaced with `sha2`), `open` (replaced with `std::process::Command`).
- `derive(Default)` applied where manual impl was equivalent (`UsageStats`).
- Surfaced tools respect routing profiles — blocked backends never leak through surfacing.
- Collision detection prevents surfaced tool names from shadowing meta-tools.

### Fixed

- 112 `collapsible_if` clippy warnings for Rust 1.93 stable compatibility.
- MSRV bumped to 1.88 (matching Docker image and CI).
- `criterion` 0.7→0.8, `metrics-exporter-prometheus` 0.16→0.18.

## [2.6.0] - 2026-03-13

### Added

- **Cost Governance** (RFC-0075): Per-tool, per-key, and global daily budgets with configurable alert thresholds (log, notify, block). Live spend dashboard at `/ui/api/costs`.
- **Security Firewall** (RFC-0071): Bidirectional request/response scanning with credential redaction (AWS keys, GitHub tokens, JWTs), prompt injection detection, shell/SQL/path traversal detection, per-tool glob rules, and NDJSON audit logging.
- **Config Export** (RFC-0070): Export sanitized gateway config as YAML/JSON. Supports Claude Code, Cursor, Windsurf, and Zed client formats via `mcp-gateway config export`.
- **Auto-Discovery** (RFC-0074): Discover MCP servers from npm, pip, and Docker sources with quality scoring and deduplication via `mcp-gateway discover`.
- **Semantic Search** (RFC-0072): TF-IDF ranked tool search across all tool names and descriptions with relevance feedback learning.
- **Tool Profiles** (RFC-0073): Usage analytics per tool with latency histograms, error categorization, usage trends, and persistent storage.
- 19 cross-feature integration tests covering all RFC combinations.
- Performance benchmarks for all v2.6.0 features (Criterion): firewall <1us, cost enforcer <100ns, semantic search <50us.
- Complete example config (`examples/gateway-full.yaml`) with all options documented.

### Changed

- **13 dependency upgrades**: reqwest 0.12->0.13, rand 0.9->0.10, rcgen 0.13->0.14, jsonwebtoken 9.3->10.3, quick-xml 0.37->0.39, x509-parser 0.16->0.18, axum-server 0.7->0.8, md5 0.7->0.8, dialoguer 0.11->0.12, clap_complete 4.5->4.6, tokio-tungstenite 0.28, rustls 0.23, time 0.3.
- rcgen 0.14 `Issuer` API migration -- removed ~60 lines of manual DER parsing in JWKS endpoint.
- rand 0.10 `RngExt` API migration across 4 modules.
- All 7 features compile-time gated with `#[cfg(feature)]` -- disable any with `--no-default-features`.

### Fixed

- `--no-default-features` build failure: `add`/`remove` commands gated behind `webui` feature.
- GitHub push protection false positive for Slack token test patterns in firewall redactor tests.

## [2.5.0] - 2026-03-12

### Added

- **Embedded Web UI** (`/ui`): htmx SPA with 5 views (Dashboard, Tools, Servers, Capabilities, Config), hash routing, search, YAML editor with line numbers. Feature-gated behind `webui`.
- **Operator Dashboard** (`/dashboard`): Server-rendered HTML with backend health matrix, cache hit rates, top tools. Auto-refreshes every 5 seconds.
- **Web UI Management API**: Server management, capability management, OpenAPI import via `/ui/api/*` endpoints.
- **WebSocket transport** for MCP backends.
- **Plugin CLI**: `plugin install`, `plugin list`, `plugin search`, `plugin uninstall` with marketplace support.
- **Setup wizard** (`mcp-gateway setup`) with 48-server registry.
- **CLI server management**: `add`/`remove`/`list`/`get` commands (Claude/Codex compatible syntax).
- **Doctor command** (`mcp-gateway doctor`) for configuration diagnostics.
- **MCP protocol version negotiation** for stdio transports.
- Load test suite and deployment documentation.

### Changed

- Agent-scoped tool permissions via OAuth 2.0 JWT identity.
- Cache key propagation for backend tool invocations.
- Engram-inspired O(1) tool registry with prefetching.
- Secret injection proxy with OS keychain integration.
- Durable capability chains with step-level checkpoint/retry.

### Fixed

- FD exhaustion from streaming session leak + unpooled connections.
- Split 12 oversized files under 800 LOC limit.
- All clippy pedantic warnings resolved.

## [2.4.0] - 2026-02-25

### Added

- **FastMCP 3.0 Provider Transforms & Playbook Engine** (#32): Dynamic tool transformation
  engine for FastMCP 3.0-compatible backends. `Provider` trait with `McpProvider`,
  `CapabilityProvider`, and `CompositeProvider` implementations. `TransformChain` with
  namespace, filter, rename, and response transforms.
- **LLM Key Server — OIDC to Scoped API Keys** (#43): Convert OIDC identity tokens to
  short-lived, capability-scoped API keys. `InMemoryTokenStore` with dual DashMap indices
  for O(1) validation and revocation. Background reaper for expired tokens. RFC 8693 token
  exchange endpoint with constant-time admin token comparison.
- **mTLS Authenticated Tool Access** (#51): Certificate-based authorization for tool
  execution. Client certificate verification against configured CAs. Per-capability mTLS
  enforcement with policy engine and cert identity extraction.
- **O(1) Tool Registry Lookup** (#78): `IndexedCapabilities` with `HashMap<String, usize>`
  name index. `get()` and `has_capability()` now O(1). Pre-built MCP Tool cache eliminates
  per-request `to_mcp_tool()` computation. Load dedup reduced from O(n²) to O(n).
- **Query Parameter Auth Injection** (`auth.param`): APIs requiring credentials as query
  parameters (e.g., `?apiKey=...`) now supported natively. No YAML workarounds needed.

### Fixed

- **Static Parameters in GET Requests**: `static_params` defined in capability YAML were
  merged into the substitution context but never appended as actual query parameters.
  Weather, recipe search, and other capabilities now send all configured static params.
- **XML Response Parsing**: Added `quick-xml` for XML-to-JSON conversion. Executor
  auto-detects XML `Content-Type` and parses accordingly. ECB exchange rates (29 EUR
  currency pairs) now working.
- **Stats Endpoint Performance**: `gateway_get_stats` replaced sequential `get_tools().await`
  loop (24 backends × 30s timeout worst case) with non-blocking `cached_tools_count()`.
  Response time reduced from >30s to ~0.1s.
- **Registry Test Assertions**: Updated capability count and metadata assertions to match
  post-dedup state (38 bundled capabilities).
- **Merge Conflict Resolution**: Resolved 6 conflict markers across Cargo.toml, config.rs,
  server.rs, and router.rs from stale stash pop.

### Changed

- **Capability YAML Naming Convention** (CAP-010): All capability YAML files renamed to
  match the `name` field declared in their configuration.
- **Capability Validator**: Support for non-REST services, complex placeholders, and
  runtime-injected auth placeholder whitelisting.

## [2.2.0] - 2026-02-13

### Added

- **Validate CLI** (`mcp-gateway validate`): Lint capability YAMLs against 9 built-in rules.
  SARIF output for CI integration. `--fix` flag auto-corrects common issues.
- **Response Transforms**: Per-capability field projection and PII redaction applied before
  the response reaches the AI client. Configured via `transform` block in capability YAML.
- **Playbooks**: Multi-step tool chains defined in YAML. Executed via the
  `gateway_run_playbook` meta-tool. Steps can reference previous outputs with `$prev`.

## [2.1.0] - 2026-02-13

### Added

- **Response Caching**: Tool responses cached with configurable TTLs.
  Per-capability `cache_ttl` override. Configurable `default_ttl` and `max_entries`.
- **Usage Statistics & Cost Tracking**: Real-time token savings tracking via
  `gateway_get_stats` meta-tool and `mcp-gateway stats` CLI command.
- **Capability Registry**: Install community capabilities with
  `mcp-gateway cap install <name>`. Search, list, and fetch from GitHub.
- **Smart Search Ranking**: `gateway_search_tools` results ranked by usage frequency.
  Persisted across restarts in `~/.mcp-gateway/usage.json`.
- **Keychain Integration**: Store API keys in macOS Keychain or Linux secret-service
  via `{keychain.name}` syntax. Session-cached for performance.
- **42 Starter Capabilities**: 25 zero-config (weather, Wikipedia, geocoding, Hacker News,
  npm/PyPI, country info, public holidays, etc.) and 17 free-tier (Brave Search, stock
  quotes, movies, IP geolocation, recipes, package tracking).
- **OpenAPI Import**: `mcp-gateway cap import spec.yaml` generates capability YAMLs
  from OpenAPI/Swagger specs automatically.
- **Metacognition Verification**: Capability for AI self-verification workflows.
- **Integration Tests**: Full test suite covering all 5 major features.
- **87 Unit Tests**: Comprehensive coverage across the codebase.

### Changed

- **Consolidated capabilities**: Registry and capabilities merged into single
  `capabilities/` directory as source of truth.
- **Large files split**: All source files refactored to 800 LOC or fewer.

### Fixed

- Resolved all 243 clippy pedantic warnings; `#![warn(missing_docs)]` enabled.

## [2.0.0] - 2025-01-25

### Changed

- **BREAKING**: Complete rewrite from Python to Rust
- Now requires Rust 1.85+ (Edition 2024)

### Added

- **Rust Implementation**: Full async/await with tokio runtime
- **MCP Protocol**: 2025-11-25 (latest specification)
- **Authentication**: Bearer token and API key auth with per-client rate limits
  and backend restrictions. Supports `auto`, `env:VAR`, or literal tokens.
- **Streaming / SSE**: Real-time backend notifications via Server-Sent Events.
  Notification multiplexer routes backend events to connected clients.
- **OAuth Support**: Per-backend OAuth configuration with dynamic client registration.
- **Failsafes**:
  - Circuit breaker with configurable thresholds
  - Exponential backoff retry (backoff crate)
  - Rate limiting (governor crate)
  - Concurrency limits per backend
- **Transport Support**:
  - stdio: Subprocess with JSON-RPC over stdin/stdout
  - HTTP: Streamable HTTP POST with session management
  - SSE: Server-Sent Events parsing
- **Architecture**:
  - Axum HTTP server with graceful shutdown
  - DashMap for lock-free concurrent access
  - Health checks and idle backend hibernation
  - Signal handling (SIGINT/SIGTERM)
- **Environment**: `env_files` config field loads `.env` files with `~` expansion
  before variable resolution.
- **Docker Support**: Official container image at `ghcr.io/mikkoparkkola/mcp-gateway`.
- **Homebrew**: `brew install MikkoParkkola/tap/mcp-gateway`.
- **JSON Logging**: `--log-format json` for structured log output.
- **Prometheus Metrics**: Optional `--features metrics` for request count, latency,
  circuit breaker state changes, and rate limiter rejections.

### Removed

- Python implementation (see v1.0.0 for Python version)
- Pydantic configuration (replaced with figment + serde)

## [1.0.0] - 2025-01-24

### Added

- Initial release of MCP Gateway (Python implementation)
- Meta-MCP Mode: 4 meta-tools for dynamic tool discovery
- Transport support: stdio, HTTP, SSE
- Configuration via YAML with Pydantic validation
- systemd/launchd service templates

[Unreleased]: https://github.com/MikkoParkkola/mcp-gateway/compare/v4.0.0-beta.2...HEAD
[4.0.0-beta.2]: https://github.com/MikkoParkkola/mcp-gateway/compare/v4.0.0-beta.1...v4.0.0-beta.2
[4.0.0-beta.1]: https://github.com/MikkoParkkola/mcp-gateway/compare/v3.5.1...v4.0.0-beta.1
[4.0.0]: https://github.com/MikkoParkkola/mcp-gateway/compare/v3.5.1...v4.0.0
[3.5.1]: https://github.com/MikkoParkkola/mcp-gateway/compare/v3.5.0...v3.5.1
[3.5.0]: https://github.com/MikkoParkkola/mcp-gateway/compare/v3.4.0...v3.5.0
[2.10.0]: https://github.com/MikkoParkkola/mcp-gateway/compare/v2.9.1...v2.10.0
[2.9.1]: https://github.com/MikkoParkkola/mcp-gateway/compare/v2.9.0...v2.9.1
[2.9.0]: https://github.com/MikkoParkkola/mcp-gateway/compare/v2.8.1...v2.9.0
[2.7.3]: https://github.com/MikkoParkkola/mcp-gateway/compare/v2.7.2...v2.7.3
[2.7.2]: https://github.com/MikkoParkkola/mcp-gateway/compare/v2.7.1...v2.7.2
[2.7.1]: https://github.com/MikkoParkkola/mcp-gateway/compare/v2.7.0...v2.7.1
[2.7.0]: https://github.com/MikkoParkkola/mcp-gateway/compare/v2.6.0...v2.7.0
[2.6.0]: https://github.com/MikkoParkkola/mcp-gateway/compare/v2.5.0...v2.6.0
[2.5.0]: https://github.com/MikkoParkkola/mcp-gateway/compare/v2.4.0...v2.5.0
[2.4.0]: https://github.com/MikkoParkkola/mcp-gateway/compare/v2.2.0...v2.4.0
[2.2.0]: https://github.com/MikkoParkkola/mcp-gateway/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/MikkoParkkola/mcp-gateway/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/MikkoParkkola/mcp-gateway/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/MikkoParkkola/mcp-gateway/releases/tag/v1.0.0
