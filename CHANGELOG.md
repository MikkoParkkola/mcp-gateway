# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

<!-- New entries go in changelog.d/<number>.<type>.md (see CONTRIBUTING.md); they are folded in here at release. -->

### Highlights

The 4.0 line serves MCP protocol revision 2026-07-28 by default beside 2025-11-25 and earlier:
stateless `POST /mcp` with no handshake, `server/discover`, retry-based input requests, a
caller-scoped `subscriptions/listen`, the tasks extension and optional idempotency keys, with
one replica while it is on. For teams, each caller now sees and invokes only what it was granted,
and cached results, notifications and subscriptions stay per caller. SSO `role_mapping` admin
rules grant full gateway admin, key-server OIDC rules need an issuer and a verified email, and
with auth on the tool-call audit log is required and fails closed. API keys are SHA-256 digests
with an optional expiry that is enforced, and `/metrics` has its own token. The gateway refuses to start on an
unrecognised config key, a config file other users can read (Unix by file mode, Windows by the file's access list), an unresolved secret
(except `server.metrics_token`, which warns and keeps `/metrics` closed, and a personal-account `client_secret_ref`, which is read only when a token is requested) or, with auth on, cleartext
HTTP on a network bind. The Helm chart now installs with its defaults and serves once the `mcp-gateway-auth` Secret exists. What is still open for 4.0.0 is under *Known gaps* in the beta.2 notes.

Evidence for each highlight, file and test: `src/config/mod.rs` and `tests/mik_7214_acs.rs` (MCP 2026-07-28); `src/gateway/router/authorization.rs` and `tests/a0_per_caller_cache.rs` (per-caller access); `src/control_plane/role_mapping.rs` and `src/gateway/router/sso_admin_tests.rs` (SSO admins); `tests/d1_audit_required.rs` (audit); `src/config/features/api_key.rs` and `tests/e4_hash_key_cli.rs` (keys); `tests/c1_unrecognised_config_keys.rs`, `src/config/secret_file_windows_tests.rs` and `src/gateway/server/cleartext_tests.rs` (refusing to start); `deploy/helm/mcp-gateway/values.yaml` (Helm chart).

### Added

- **The task store and the personal-account store run on Windows.** Directories and files are
  created owner-only and checked on every open (owner, grants, inheritance, junctions, network
  and non-ACL volumes), the directories are held open while the store runs, and custody uses a
  Windows file lock. A 3.x token file other accounts can read is refused with the `icacls` lines
  that fix it. One Windows-only module uses `unsafe` for the Win32 security calls (ADR-016).
  (#1473)
- `mcp-gateway doctor --start-stdio`: starts each stdio backend through the gateway's own
  launch (env, cwd) and reports why one that dies before `initialize` died: its exit status
  and a bounded, redacted stderr tail. Opt-in, since it runs the configured commands; a
  backend under a runtime profile is skipped. (#526)
- **The 3.5.1 upgrade rehearsal runs in CI.** A new `upgrade-rehearsal` job upgrades the
  v3.5.1 release binary to the pull request's build, turns the modern protocol off, rolls back,
  and fails when config, credentials, permissions, mounts or active callers do not survive.
  `scripts/release/nfr_upgrade_1_rehearsal.sh` now exits 1 when any check fails.

- **WebSocket is a backend transport (`ws_url`).** `WebSocketTransport` existed but no config
  reached it. A `ws_url` backend now connects with its static `headers` on the upgrade, is bounded
  by the backend `timeout` (the upgrade included), fails in-flight calls at once when the socket
  drops, and never logs more of its URL than the origin. `mcp-gateway add`, the admin UI and
  discovery store a `ws://`/`wss://` URL as `ws_url`. Refused on `ws_url`: cleartext `ws://`
  credentials off-host (without `allow_cleartext_credentials`), `oauth`, identity propagation,
  header or query `secrets`, and a stateless (2026-07-28+) `protocol_version`. UPGRADING-4.0 §47.

- `mcp_backend_rate_limited_total{backend}` counts requests and notifications refused by a
  backend's own `failsafe.rate_limit` before dispatch. Those refusals are excluded from the
  error budgets and the circuit gauge (F23), so this is where operators see them. See
  `docs/UPGRADING-4.0.md` item 53 (F23b).

- `file:/absolute/path` secret references wherever `env:NAME` is accepted. The file is held to the
  item 35 mode rule, capped at 64 KiB, and has one trailing newline stripped. An empty file fails
  the load. A reload reports a rotated file as needing a restart. Capability YAMLs are unchanged.
  A literal secret starting with `file:` is now a reference (breaking; UPGRADING-4.0 item 44).
  (C9, MIK-7570.SECRET.2)
- A per-call-id ledger for stdio bursts against a client that never answers its asks: every call
  must reach exactly one terminal response, and one client's silence must not disable the capability
  for other callers. 194 calls run per PR; the ticket's 1026-call
  burst (about 8 minutes) runs nightly and on a PR labelled `mrtr7b-full-burst`. (MIK-7479.STDIO.1)

### Changed

- **One gateway writes an audit log path.** The transparency log takes a writer lease on
  `<path>.lock` at startup and holds it; a second gateway on the same path is refused with an
  error naming the path, whatever the auth setting. A restart overlap waits up to
  10 seconds (not configurable). Appends no longer take a file lock.
  `audit show` and the SIEM exporter rescan once when the log rotates under them, and I/O errors
  from the log name the operation and the path. See UPGRADING item 49.
- A `tools/call` carrying `inputResponses` without the `requestState` this gateway issued is
  refused with `-32602` before dispatch instead of being forwarded as a fresh call. The
  idempotency key is released. UPGRADING-4.0 item 55. (MIK-7325.RETRY.1)

- **UPGRADING-4.0 item 50:** the invocation, delivery-attempt, direct-route and
  identity-propagation audit appends run off the request threads and are bounded (5 s waiting,
  5 s writing). A stalled audit disk answers 503 and marks the log stalled (`/readyz` 503
  `stalled`, `mcp_audit_append_timeouts_total`) instead of exhausting the workers.
- **Readiness waits for the capability catalogue.** `/readyz` and `/health` answer 503 until
  the startup capability scan has read every directory, so a pod or container is no longer
  sent traffic while its catalogue is empty; the admin `/health` view adds
  `capability_backend.loaded`. The compose healthcheck probes `/readyz`, and the example
  `Gateway` runtime profile probes `/readyz` and `/livez`. UPGRADING-4.0 §65.

- **BREAKING (UPGRADING-4.0 item 49):** the audit (transparency) log rotates at 64 MiB and keeps
  12 sealed segments, recording each deletion as a signed `audit_segment_expired` record.
  `security.transparency_log.rotation` sets `max_segment_bytes`, `max_segment_age_secs`,
  `retain_segments` and `on_disk_full` (`expire_oldest` or `refuse`). `audit verify` reads every
  segment, detects a deleted or truncated active file through `transparency.jsonl.hwm`, and gains
  `--archive`. The SIEM exporter and the governance audit view follow segments; the governance
  log rotates at 16 MiB x 4. Helm: `audit.rotation.*`, with a render guard on the emptyDir size.
- **Contributors: the 800-line file-size gate no longer counts a module declaration.** A
  `mod child;` line and the inert attributes directly above it (`#[cfg(test)]`,
  `#[path = "..."]` and the like) do not count toward a file's size, so attaching code
  extracted out of an over-ceiling file is not scored as growth. An inline `mod x { ... }`,
  a macro attribute and a `cfg_attr` still count. The baseline is re-recorded under the new count, with
  every row lower or equal. (#609)
- **The file-mode check covers every secret-bearing file (breaking).** An mTLS key, an OAuth
  token file, a capability `file:` credential or a `tls issue-*` `--ca-key` that other users can
  read is refused. The mTLS certs and CRL, the identity-grants file and the control-plane
  collections may be read by others but not changed by them. `config export` writes the client
  config it edits as `0600`. UPGRADING-4.0 item 54. (F18)

- **Breaking: a backend that fails to start counts toward its circuit breaker, on every
  transport.** `Error::CircuitOpen(String)` becomes `CircuitOpen { backend, last_failure }`, and
  the refusal reads `...; last failure: <start error>`. UPGRADING-4.0 §48.
- **tungstenite's handshake logging is capped at DEBUG**, even under `RUST_LOG=trace`: its TRACE
  line prints the upgrade request with its query string and headers.
- **Admin actions write an `admin_action` audit record and are refused while the
  audit log is down.** Admin meta-tool calls, allowed or refused, and every
  `/ui/api/*` request other than `GET` or `HEAD`, control-plane POSTs included,
  record who acted (issuer and subject for an SSO admin), the tool or route
  template, and the outcome; bodies and queries are never logged. With auth on
  they answer 503 while the log cannot be written. See `docs/UPGRADING-4.0.md`
  item 51.
- **A backend that refuses a managed personal account's token (HTTP 401) forces one refresh of
  that token**, then answers with the reconnect offer when the provider has revoked the grant,
  or with `recovery.error_code` `UPSTREAM_AUTH_REJECTED` (`retry: true`) or
  `UPSTREAM_AUTH_REJECTED_PERSISTENT` (`retry: false`). At most one forced refresh per token
  revision, recorded durably. A 401 or 403 from an HTTP backend is no longer retried. A downgrade
  to an earlier 4.0 beta after a forced refresh is unsupported. See UPGRADING-4.0 item 61.
  (A11, MIK-7570.RECONNECT.1)

### Fixed

- **Zed export and import use Zed's real settings file and format.** `setup export --target zed` now writes to Zed's config directory (`~/.config/zed/settings.json` on macOS, `$XDG_CONFIG_HOME/zed` on Linux, `%APPDATA%\Zed` on Windows); on macOS it previously wrote to Zed's data directory, which Zed never reads, so remove a `gateway` entry left there. Discovery now imports Zed's flat `command`/`args` and `url` entries, which it previously skipped (#1811).

- The 4.0.0 upgrade notice now includes `--config PATH` in the `accounts migrate-credentials`
  command it prints; without it the command stops unless `MCP_GATEWAY_CONFIG` is set.
- **Cost budgets survive a stdio gateway restart.** A stdio gateway loaded `costs.json` at
  startup but never wrote it, so every restart gave the daily budgets back. It now saves when
  the client closes stdin (after in-flight calls finish) and every 5 minutes while it runs, as
  the HTTP gateway does. Each save writes its own scratch file, so gateways sharing a data
  directory no longer write one scratch file between them.
- **A failed release or image-manifest job can be re-run for 14 days, not one.** The build
  binaries and image digests handed between jobs expired after a day, so a later re-run
  published a release with no binaries or failed to find the digests. They now last the
  repository's 14-day artifact retention, and a CI check keeps every such handoff there.
- **The release scope gate refuses a waived criterion that is still marked blocked.** Such a
  row let a release pass while the burnup still listed it as held. A test also pins the
  approved-waiver list to the ledger's waived criteria, so a waiver removed from the ledger
  cannot leave its approval behind.
- **A stdio backend that dies before `initialize` is reported at once, with its exit status.**
  It used to wait out the request timeout and report a timeout, with the child's stderr already
  discarded. The error now names the exit status and points at the gateway log, where one record
  carries the last 20 stderr lines (2 KiB at most) with argv, `env:` values and credential-shaped
  text redacted. The stderr never goes to MCP clients. A build without the `firewall` feature has
  no credential recogniser, so it logs a withheld marker instead of the text. `doctor
  --start-stdio` caps a whole start at 15 s. (#526, #1568)
- **A debug build of the gateway starts on Windows.** Clap's generated argument parser needs
  about 900 KB of stack in an unoptimized build, over the 1 MiB Windows gives a process's main
  thread, so even `--version` overflowed. The gateway now runs on a thread with an 8 MiB stack.
  Release builds were not affected.
- **On Windows, file locks now actually lock.** The advisory lock the control-plane store, the
  durable protocol-revision telemetry and the OAuth `client_id` self-heal rely on did nothing on
  non-unix platforms, so concurrent writers could lose each other's updates, and a caller could be
  handed a `client_id` that another writer then replaced on disk. The lock is now `LockFileEx`.
- **An error result is never replayed from a cache.** The response cache and the capability
  cache stored `isError: true` results, including the gateway's own rate-limit and open-breaker
  refusals, and served them to every call with the same key for the whole TTL (60 s by default).
  One throttle could answer hundreds of later calls with a stale refusal. Errors are now never
  cached; successes are cached as before. See `docs/UPGRADING-4.0.md` item 63 (F26, GH #1158).

- **A WebSocket backend's progress reaches the call that asked for it.** `WebSocketTransport`
  dropped every inbound notification. It now delivers `notifications/progress` to the call whose
  request carried that `progressToken`, under the stdio transport's rules: progress only, the
  token must belong to a live call, and a frame it cannot attribute is dropped. The caller gets
  its own token back through the request-scoped translation, as on stdio.
- **One caller's burst no longer disables a tool for every caller.** A refusal by a
  backend's own rate limiter was reported as "Circuit breaker open" and counted as a
  backend failure, so a burst past the limit could auto-disable the capability or kill
  the backend for all tenants. It is now `Rate limit exceeded for backend 'x'` (code
  still -32000, recovery hint `RATE_LIMITED`), is not sampled by the error budgets, and leaves
  `mcp_backend_circuit_state` alone. See `docs/UPGRADING-4.0.md` item 53 (F23).
- **Config reload follows a symlinked config across directories.** A link retargeted to a
  file in a directory the gateway was not watching reloaded once and then missed every later
  write, serving the old config silently; a directory the link left stayed watched forever. The
  watcher now follows the whole link chain on every change, including a Kubernetes ConfigMap's
  `..data` swap, a Capistrano-style `current` directory link retargeted by rename or by
  `rm` and `ln -s`, and reads the new release on reload. Limits are listed in DEPLOYMENT
  under "What triggers a config reload". (#453)
- **BREAKING: only delivered change notifications are advertised.** `resources.subscribe`,
  `resources.listChanged` and `prompts.listChanged` were advertised and never delivered.
  They are now `false`, and `resources/subscribe`/`unsubscribe` are refused with `-32601`.
  `tools.listChanged` is announced for every tool-set change over HTTP (config reload,
  capability reload, admin UI, revive), as a standard `message` event on the 2025 GET
  stream rather than the gateway's envelope, and is `false` over stdio. See UPGRADING-4.0
  item 52.
- **Capability pins survive CRLF line endings.** The `sha256:` pin now reads CRLF as LF, so
  a pinned capability that a Windows checkout or editor converted to CRLF is no longer
  refused as tampered. A lone CR still changes the hash. Capability YAML is checked out
  with LF on every platform (`capabilities/.gitattributes`), so the Windows binary embeds
  the same starter capabilities as the others. A pin made over CRLF bytes must be re-made: see
  UPGRADING-4.0 item 60. (#524)
- **`doctor` finds stdio commands on Windows.** It split `PATH` on `:`, which takes
  `C:\...` apart, so it reported every stdio backend's command missing. It now uses the
  platform separator and, on Windows, also the `.exe` name a spawn resolves a bare
  command to. (#524)
- **The `Windows check` CI job runs tests.** It compiles every test target for Windows
  and runs the library and binary unit tests, except `gateway::` and
  `personal_accounts::`, whose fixtures open stores that refuse on non-unix (#1142). Before,
  it ran `cargo check` only. (#524)

### Security

- **R2 checks a tool call even when the caller never listed the backend** (F13, MIK-7586,
  #1141). A `tools/call` on a cold catalogue slot now lists that backend's tools once, as the
  caller, before judging the call's argument keys, instead of forwarding it unchecked. Under
  `closed`, a list that cannot be read, a tool outside a truncated list and a tool a complete
  list lacks are refused; `standard` forwards and counts each case. The list is single-flight
  per slot, bounded by the backend's `timeout`, held off for 10 s after a failure, and obeys
  the slot's circuit breaker and rate limiter. A backend that cannot be reached answers, and
  is charged to the error budget, as a failed call to it would. New
  `mcp_input_schema_events_total` kinds; see UPGRADING §59.
- **Secrets stay out of the request URI and its trace.** The HTTP trace span records the method and
  route template, never the full URI, so a session id or a dashboard link value no longer reaches
  DEBUG logs. `/api/costs` takes a session id in the `X-Cost-Session-Id` header (`?session=` is 400),
  and a dashboard link presented from another machine is used up. UPGRADING-4.0 §70. (#1529)

- **The OWASP self-assessment matches the shipped controls.** It had claimed a
  tool-descriptor validator and a grant-collision check that never run on a request, a removed
  SSRF module path, and blocking by controls that are opt-in or observe-only. It now cites
  request-path and config-load controls (plus release-time supply-chain controls for ASI04),
  states which are on by default, adds the 4.0 multi-user controls, uses the 2026 OWASP ASI
  risk names, and reads 2/10 COVERED, 8/10 PARTIAL.
  CI fails when it cites a path or test that no longer exists.
  Withholding poisoned tool descriptors is tracked in #1441.

- **Task calls on `POST /mcp/{name}` are refused instead of forwarded.** The route passed
  `tasks/*` (and `subscriptions/listen` naming `taskIds`) to the backend with no owner check,
  so callers sharing a backend could read or cancel each other's tasks. These methods now
  answer JSON-RPC -32601 and never reach the backend; `POST /mcp` still serves tasks.
  See UPGRADING-4.0 item 67 (#1442).

- **A non-admin call to a callback-registering capability is refused as a denial.** It was
  answered as a configuration error (HTTP 400, JSON-RPC -32603). It is now HTTP 403,
  JSON-RPC -32600, the shape admin-only tools answer with, and logs the "refused by
  authorization" warning. See UPGRADING-4.0 item 66 for when the invocation audit log
  records it.

- **Capability pins cover text after a line break inside the pin line.** The pin hash
  excluded the whole `sha256:` line, but YAML also ends a line at a lone CR, NEL, LS or PS,
  so text after one was parsed yet not hashed. Only the pin value is excluded now; re-pinning
  a pinned CRLF file still verifies. See UPGRADING-4.0 item 64. (#1212)

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
- **Attestation `enforce` covers every method on the direct route (breaking)**
  (MIK-7570.ATTEST.1). `POST /mcp/{name}` now refuses, with -32002 and HTTP 403,
  any forwarded method whose token is missing or does not grant its target:
  `resources/read`, `resources/subscribe` and `resources/unsubscribe` match the
  URI, `prompts/get` the prompt name, list methods need an authentic token, and
  a method outside the table needs a `"*"` token. `initialize`, `ping` and
  notifications are exempt. The check runs before identity minting, and the
  token is stripped before telemetry. A surfaced tool run as a task carries its
  `_meta` token to dispatch. See UPGRADING-4.0 item 46.

## [4.0.0-beta.3] - 2026-10-06

> **Pre-release.** The third 4.0 beta, tagged without a changelog section and reconstructed
> from the `v4.0.0-beta.3` tree's own fragment assembly. Included again in 4.0.0, which is
> cumulative; this section is history.

### Highlights

The 4.0 line serves MCP protocol revision 2026-07-28 by default beside 2025-11-25 and earlier:
stateless `POST /mcp` with no handshake, `server/discover`, retry-based input requests, a
caller-scoped `subscriptions/listen`, the tasks extension and optional idempotency keys, with
one replica while it is on. For teams, each caller now sees and invokes only what it was granted,
and cached results, notifications and subscriptions stay per caller. SSO `role_mapping` admin
rules grant full gateway admin, key-server OIDC rules need an issuer and a verified email, and
with auth on the tool-call audit log is required and fails closed. API keys are SHA-256 digests
with an optional expiry that is enforced, and `/metrics` has its own token. The gateway refuses to start on an
unrecognised config key, a config file other users can read (Unix by file mode, Windows by the file's access list), an unresolved secret
(except `server.metrics_token`, which warns and keeps `/metrics` closed, and a personal-account `client_secret_ref`, which is read only when a token is requested) or, with auth on, cleartext
HTTP on a network bind. The Helm chart now installs with its defaults and serves once the `mcp-gateway-auth` Secret exists. What is still open for 4.0.0 is under *Known gaps* in the beta.2 notes.

Evidence for each highlight, file and test: `src/config/mod.rs` and `tests/mik_7214_acs.rs` (MCP 2026-07-28); `src/gateway/router/authorization.rs` and `tests/a0_per_caller_cache.rs` (per-caller access); `src/control_plane/role_mapping.rs` and `src/gateway/router/sso_admin_tests.rs` (SSO admins); `tests/d1_audit_required.rs` (audit); `src/config/features/api_key.rs` and `tests/e4_hash_key_cli.rs` (keys); `tests/c1_unrecognised_config_keys.rs`, `src/config/secret_file_windows_tests.rs` and `src/gateway/server/cleartext_tests.rs` (refusing to start); `deploy/helm/mcp-gateway/values.yaml` (Helm chart).

### Added

- **The task store and the personal-account store run on Windows.** Directories and files are
  created owner-only and checked on every open (owner, grants, inheritance, junctions, network
  and non-ACL volumes), the directories are held open while the store runs, and custody uses a
  Windows file lock. A 3.x token file other accounts can read is refused with the `icacls` lines
  that fix it. One Windows-only module uses `unsafe` for the Win32 security calls (ADR-016).
  (#1473)
- `mcp-gateway doctor --start-stdio`: starts each stdio backend through the gateway's own
  launch (env, cwd) and reports why one that dies before `initialize` died: its exit status
  and a bounded, redacted stderr tail. Opt-in, since it runs the configured commands; a
  backend under a runtime profile is skipped. (#526)
- **The 3.5.1 upgrade rehearsal runs in CI.** A new `upgrade-rehearsal` job upgrades the
  v3.5.1 release binary to the pull request's build, turns the modern protocol off, rolls back,
  and fails when config, credentials, permissions, mounts or active callers do not survive.
  `scripts/release/nfr_upgrade_1_rehearsal.sh` now exits 1 when any check fails.

- **WebSocket is a backend transport (`ws_url`).** `WebSocketTransport` existed but no config
  reached it. A `ws_url` backend now connects with its static `headers` on the upgrade, is bounded
  by the backend `timeout` (the upgrade included), fails in-flight calls at once when the socket
  drops, and never logs more of its URL than the origin. `mcp-gateway add`, the admin UI and
  discovery store a `ws://`/`wss://` URL as `ws_url`. Refused on `ws_url`: cleartext `ws://`
  credentials off-host (without `allow_cleartext_credentials`), `oauth`, identity propagation,
  header or query `secrets`, and a stateless (2026-07-28+) `protocol_version`. UPGRADING-4.0 §47.

- `mcp_backend_rate_limited_total{backend}` counts requests and notifications refused by a
  backend's own `failsafe.rate_limit` before dispatch. Those refusals are excluded from the
  error budgets and the circuit gauge (F23), so this is where operators see them. See
  `docs/UPGRADING-4.0.md` item 53 (F23b).

- `file:/absolute/path` secret references wherever `env:NAME` is accepted. The file is held to the
  item 35 mode rule, capped at 64 KiB, and has one trailing newline stripped. An empty file fails
  the load. A reload reports a rotated file as needing a restart. Capability YAMLs are unchanged.
  A literal secret starting with `file:` is now a reference (breaking; UPGRADING-4.0 item 44).
  (C9, MIK-7570.SECRET.2)
- A per-call-id ledger for stdio bursts against a client that never answers its asks: every call
  must reach exactly one terminal response, and one client's silence must not disable the capability
  for other callers. 194 calls run per PR; the ticket's 1026-call
  burst (about 8 minutes) runs nightly and on a PR labelled `mrtr7b-full-burst`. (MIK-7479.STDIO.1)
- `/metrics` counts the MCP protocol revision each inbound request asks for: `mcp_protocol_revision_observations_total{requested_revision,client,transport}` and `mcp_protocol_revision_unattributed_observations_total{client,transport}`, with revisions and client names folded into a fixed label set (`other` for the rest). A stdio gateway also keeps a restart-safe, labels-only aggregate in `protocol-revision-telemetry/window.json` under its data directory. (#480)
- **A stdio backend's progress reaches the client while the call is running.** 3.x dropped every notification a stdio backend sent. `notifications/progress` is now delivered to the call whose request carried that `progressToken`, as it arrives and under the client's own token. Only progress is routed this way, a token must belong to a live call, and a second call cannot claim a token that is already in use. (#600)
- **Container images are published for `linux/arm64` as well as `linux/amd64`.** A release tag's image, its `-full` variant and the image built from `main` are each a multi-platform list, built natively on each architecture and started once per architecture before publishing. 3.x published amd64 only. (#568, #602)
- **A single-user HTTP gateway serves the operator's own managed accounts.** With `auth.enabled: true`, `auth.single_user: true`, at most one API key, no key-server OIDC issuer and no `accounts.adapters`, a caller that authenticated with the bearer token or the one API key is treated as the sole operator, so the operator's `personal_managed` accounts (including credentials migrated from 3.x) serve its calls. A caller admitted anonymously through `public_paths` never gets them, and any other auth setup keeps requiring a verified end-user identity. This is an assertion by the operator, not a proof: people who share that credential share its stored accounts. (#661)
- **A backend with `identity_propagation` lists its tools, resources, resource templates and prompts per caller.** In 3.x these lists were fetched once without any caller's credential and every caller was shown the same catalogue. A caller with a verified identity now gets the lists the backend returns for that caller's own credential, on its own backend session, with `session_mode: per_user` and `session_mode: stateless` alike; a caller with no verified identity still sees the shared list, and a `required` backend is left out of a list whenever the fetch would not carry the caller's own credential. A caller's cached tool list is refetched once it expires, and a caller's backend session, with its cached lists, is dropped when a grant reload revokes that caller's grant. Backends without `identity_propagation` are unchanged. (#666, #672, #707, #727, #731, #734)
- **`mcp-gateway accounts migrate-credentials` keeps a 3.x OAuth credential instead of re-authorizing.** Run offline, once per backend, as `mcp-gateway accounts migrate-credentials --config PATH --descriptor-id ID --legacy-issuer URL` (add `--legacy-backend-name NAME` when the backend was renamed since 3.x); it reads the 3.x token file and writes the credential into the per-principal account store under the `accounts.descriptors` entry named. It needs an explicit `--config`, refuses rather than guesses when the issuer does not match the descriptor or the credential could not be used, and never modifies, renames or deletes the 3.x file, so a refusal leaves the deployment as it was. Without it, each OAuth backend asks for authorization once on its next use. (#680)
- **Grant changes apply to a running gateway on reload.** In 3.x the identity-grants file was read only at startup, so `mcp-gateway identity grants grant` or `revoke` took effect at the next restart. A running gateway now re-reads the file on every config reload: the `gateway_reload_config` meta-tool, the admin UI reload, and the automatic reload after `config.yaml` or an env file changes (editing the grants file alone does not trigger one). The reload report carries an `identity grants reloaded (...)` line with the added, removed and revoked counts, even when the config half is refused. A file that cannot be read or parsed is refused and the grants in force stay; a `busy` refusal means another grant reload was running. Restoring an older grants file re-grants what was revoked since, shown as a negative `revoked` count. See `docs/identity_grants.md`. (#755)
- `security.posture: standard | hardened` (default `standard`, which changes nothing). As of
  this release `hardened` enforces only: the context-integrity preset is raised to at least
  `team_shared` (`enterprise_strict` is kept) with `non_bypassable` on; the firewall and
  anomaly detection are on and an anomaly score at the block threshold blocks (1.0 unless set
  within `[0.9, 1.0]`; below 0.9 refuses start); a call whose transition cannot be learned
  because the learned-pair map is full is refused; and startup is refused on a build without
  the `firewall` feature. Changing the posture needs a restart; a reload that changes it is
  refused. A multi-user deployment running `standard` logs one startup warning and gets a
  `doctor` `security-posture` finding (advisory; the exit code is unchanged).
- security: core of multi-gateway Ed25519 signature chaining (ASI07): link signing, and chain verification pinned to the origin gateway and last signer; not yet wired into the invoke paths (#1954)
- The `identity grants` CLI now appends one line per successful add, `--replace` and revoke to a journal beside the grant file (`<grant file>.journal.jsonl`, mode 0600), recording the verb, grant id, row digests before and after, expiry, time and the OS account as an unauthenticated hint. A lock file beside the grant file spans the write and the append.
- Identity grant changes are now governance audit records: the gateway ingests the `identity grants` CLI journal exactly once, across crashes, at every start and grant reload (the file watcher included), records direct grant-file edits as `out_of_band` and lost history as `indeterminate`, and records the active grants each start serves (`loaded`, then `loaded_complete` with the count) before accepting a request. Audit events gain an optional `grant_change` field.
- **Remote backends without signed provenance are named.** Signed provenance for remote backends is opt-in. With it off, an enabled HTTP, A2A or WebSocket backend that has no signed metadata now appears in one startup warning, on HTTP and stdio starts, and in `doctor` as a `remote_provenance` warning. Provenance stays off by default. See `docs/UPGRADING-4.0.md` item 89. (#2195)
- The Helm chart renders API-key and OIDC auth: `auth.mode: api_keys` renders one `auth.api_keys` entry per `auth.apiKeys` item, and the Secret holds each key's `hash-key` digest. `auth.mode: oidc` renders the key server from `auth.oidc`. Neither gets the master bearer. `extraEnv` and `envFrom` carry backend secrets and refuse `MCP_GATEWAY_*` and chart-owned names. `persistence` keeps the state volume on a claim, with one replica and `Recreate`. Existing `credential` and `mesh` values render byte for byte as before. (MIK-7570.CHART.2)
- security: core of verbatim cross-principal relay detection (ASI10, partial): winnowed fingerprints, bounded per-process state and the relay predicate; not yet wired into the request or response paths (#2433)
- Under `security.posture: hardened`, an HTTP MCP request with no per-caller identity is refused with 403 (`-32600 "per-caller identity required (security.posture=hardened)"`) before its body is read, on `/mcp` and `/mcp/{name}`. A proven subject (IdP, trusted proxy, Access, mTLS, agent JWT) or an API key configured with the new `kind: personal` identifies a caller; a shared key, the static bearer and a dashboard session do not. `auth.api_keys[].kind` is `shared` by default. Upgrade guide item 106. (#2465)
- **Invocation records name the tenants a call touched.** With `security.firewall.tenant_guard.arg_keys`
  set (the guard itself may stay off), each transparency-log `invocation` record carries `tenants`:
  the tenant ids named by the request and by the tool result (text-JSON included), each as the 16-hex
  argument hash, sorted, never raw. Beside it is `data_classes` from the context-integrity kernel.
  Cache hits and idempotent replays are marked `attribution: "cached_delivery"`. At most 1024 tenants
  are kept per record, with `tenants_total` past that. The firewall audit `request` line carries the
  same hashed `tenants`. Records of calls that name no tenant are unchanged. (#2475, MIK-7116.MIN.1)
- stdio honours `notifications/cancelled`. The gateway stops its own handling of a cancelled `tools/call` at once, including one waiting for the client's answer to an elicitation, and never answers it; a backend that already received the call may still finish its work. A keyed call cancelled after it started is refused on retry rather than run twice. Ids that are not in flight, and `initialize`, are ignored. At end of input, stdio mode gives in-flight calls and its output writer 30 seconds together, even when the client has stopped reading its output; the shutdown steps after that are not yet bounded. (#2519)
- A stdio gateway keeps durable tasks for its local operator in `<tasks.store_dir>/stdio`: it serves `tasks/get`, `tasks/update` and `tasks/cancel`, a task survives a restart or a moved store directory, and no HTTP caller can read, cancel or update it. If that store cannot be opened, for example because another stdio gateway holds it, stdio serves without tasks and does not advertise them.
- **A recovered upstream task is recorded when it settles.** When a backend answers a task-augmented call with its own task, the gateway now writes a `task_recovery` invocation record as it settles that task, from the worker or from the owner's `tasks/get`, carrying the tenants and data classes the response gates saw. The submission record gains the same `task_id`. Under `FailClosed` a failed write settles the task `-32005` with no backend content. See UPGRADING-4.0 #113. (#2545)
- **MCP compatibility layer, documented.** `docs/PROTOCOL_COMPATIBILITY.md` lists which client and backend revision pairings work, which mid-call requests the gateway translates, and which it refuses, with the test behind each row. (#2585)
- MCP Events (opt-in, `events.enabled`): `events/list`, `events/subscribe` and `events/unsubscribe` over HTTP, with callback verification through an SSRF-pinned client, durable subscriptions and per-principal caps (MIK-7630).
- security: verbatim cross-principal relay detection on the direct backend route (`/mcp/{backend}`), off by default. New `security.firewall.collusion` section (`action: off | observe | block`, `window_secs`, `min_matches`, `common_principals`, `sources`, `non_egress`), checked at load. Under `block`, a call that sends out content another caller was delivered is refused with `-32002` (HTTP 403) before dispatch; under `observe` it is logged and audited. Known limits: the meta-MCP route follows in a later change; only the first and last 3 KiB of each delivered result are compared, so content from the rest of a larger result is not detected; verbatim text only (#2644)
- MCP Events delivery (MIK-7630 I2): subscribed events now reach their callback through a durable outbox with signed, retried, rate-limited and audited delivery, dead letters with caps, inbound webhook dedupe, and the firewall, tenant guard, budget and access checks applied to every attempt (#2651).
- security: verbatim cross-principal relay detection now also covers the meta-MCP route (`gateway_invoke`, surfaced tools, chains, playbooks, tasks, stdio and bridged input rounds), under the same `security.firewall.collusion` settings. Under `block`, a call that sends out content another caller was delivered is refused with `-32002` before dispatch, and its idempotency key is released. Prompt and resource reads are not covered on either route (#2678)
- **CLI capabilities run.** A capability with `service: cli` used to load and never run. It now runs its command with no shell, from arguments built out of validated parameters (a parameter is always exactly one argument and can never become an option), in a private directory with a cleared environment, an output cap, a timeout and whole-tree teardown. Only pinned capabilities whose command is on `capabilities.process_commands` run; `capabilities.process_execution: disabled` turns it off. See UPGRADING-4.0 item 127. (#2697)
- MCP Events deliveries carry the gateway's provenance receipt in `_meta`, inside the signed body, signed with the gateway's provenance key when provenance stamping is on (#2704).
- `mcp-gateway add <name>` now writes a built-in server's env or header references, its OAuth stanza and its HTTP dialect, and writes it disabled (with the reason) when a reference does not resolve or the server can reach any address; `mcp-gateway init` enables the servers that need no account; `mcp-gateway list --available` browses the library (MIK-7787).
- MCP Events dead letters (MIK-7630 I6): admins can list and replay dead-lettered deliveries through `/ui/api/events/dead-letters` or `mcp-gateway events dead-letters`; a replay re-checks access and re-scans the payload, and `gateway_search_tools` and `gateway_search` now return visible event types (#2709).
- Events: `task.settled` and `backend.<server>.tools_changed` are subscribable event types (owner-only and backend-visible respectively), started and stopped with their first and last subscriber. Gated by `events.sources`.
- `mcp-gateway add` knows seven more servers (time, git, chrome-devtools, grafana, mongodb, supabase, hubspot), 35 in all; documented counts are now checked against the registry (MIK-7787).
- Eight REST capabilities for Brave, Tavily, Firecrawl and Sentry join the bundled catalogue; each is listed once its API key is set (MIK-7787).
- MCP Events: a subscription to a backend upstream-notification event on a backend that cannot offer it (SSE-handshake HTTP, A2A, identity propagation or a personal account, per-user OAuth on a multi-user gateway) answers `-32014` naming the reason instead of subscribing silently (MIK-7630, #2691).
- **MCP capabilities run, and the catalogue is executable.** A capability with `service: mcp` now starts its declared stdio server for the call. The `gws_*` Google Workspace capabilities run through the `gws` tool, `cloudflare_manage` is replaced by Cloudflare API v4 REST capabilities, `gmail_save_attachment` saves into `capabilities.files.downloads`, and `metacognition_verify` is removed. `trawl_extract` and `cisco_scanner` `scan_mcp_server` stay held until their network access can be confined. See UPGRADING items 132 to 136.
- **Event subscriptions are audited, and an event delivery names the firewall verdict.** Subscribe, refresh, verification, unsubscribe, dead-letter and replay each write one governance record to the audit log; every attempt record carries the firewall verdict of its payload; an attempt with no audit logger is not sent. (#2759)
- MCP Events: a backend's `resources/updated`, `resources/list_changed` and `prompts/list_changed` notifications become the events `backend.<name>.resource_updated`, `resources_changed` and `prompts_changed` for stdio, WebSocket and streamable HTTP backends, listened for only while an event subscription needs them (MIK-7630, #2767).
- **MCP capabilities: operation requirements, a bounded wait, and pyghidra.** An operation can list the parameters it needs (refused before a process starts), a tool call can wait for background work to finish, and `pyghidra_reverse` now runs (eleven operations, ten of them read-only; import waits for analysis). Calls from before a capability unload or reload no longer start a process. The public capability count is 136; `trawl_extract` stays held.
- MCP Events: a backend's own `notifications/tools/list_changed` now produces `backend.<name>.tools_changed` for stdio, WebSocket and streamable HTTP backends, as well as the gateway's own tool-set announcements (MIK-7630, #2797).
- Tasks on `POST /mcp` now carry an input round: a backend that asks for input parks the task as `input_required`, `tasks/update` supplies the answers, and the gateway resumes the same call (MIK-7311).

### Changed

- **One gateway writes an audit log path.** The transparency log takes a writer lease on
  `<path>.lock` at startup and holds it; a second gateway on the same path is refused with an
  error naming the path, whatever the auth setting. A restart overlap waits up to
  10 seconds (not configurable). Appends no longer take a file lock.
  `audit show` and the SIEM exporter rescan once when the log rotates under them, and I/O errors
  from the log name the operation and the path. See UPGRADING item 49.
- A `tools/call` carrying `inputResponses` without the `requestState` this gateway issued is
  refused with `-32602` before dispatch instead of being forwarded as a fresh call. The
  idempotency key is released. UPGRADING-4.0 item 55. (MIK-7325.RETRY.1)

- **UPGRADING-4.0 item 50:** the invocation, delivery-attempt, direct-route and
  identity-propagation audit appends run off the request threads and are bounded (5 s waiting,
  5 s writing). A stalled audit disk answers 503 and marks the log stalled (`/readyz` 503
  `stalled`, `mcp_audit_append_timeouts_total`) instead of exhausting the workers.
- **Readiness waits for the capability catalogue.** `/readyz` and `/health` answer 503 until
  the startup capability scan has read every directory, so a pod or container is no longer
  sent traffic while its catalogue is empty; the admin `/health` view adds
  `capability_backend.loaded`. The compose healthcheck probes `/readyz`, and the example
  `Gateway` runtime profile probes `/readyz` and `/livez`. UPGRADING-4.0 §65.

- **BREAKING (UPGRADING-4.0 item 49):** the audit (transparency) log rotates at 64 MiB and keeps
  12 sealed segments, recording each deletion as a signed `audit_segment_expired` record.
  `security.transparency_log.rotation` sets `max_segment_bytes`, `max_segment_age_secs`,
  `retain_segments` and `on_disk_full` (`expire_oldest` or `refuse`). `audit verify` reads every
  segment, detects a deleted or truncated active file through `transparency.jsonl.hwm`, and gains
  `--archive`. The SIEM exporter and the governance audit view follow segments; the governance
  log rotates at 16 MiB x 4. Helm: `audit.rotation.*`, with a render guard on the emptyDir size.
- **Contributors: the 800-line file-size gate no longer counts a module declaration.** A
  `mod child;` line and the inert attributes directly above it (`#[cfg(test)]`,
  `#[path = "..."]` and the like) do not count toward a file's size, so attaching code
  extracted out of an over-ceiling file is not scored as growth. An inline `mod x { ... }`,
  a macro attribute and a `cfg_attr` still count. The baseline is re-recorded under the new count, with
  every row lower or equal. (#609)
- **The file-mode check covers every secret-bearing file (breaking).** An mTLS key, an OAuth
  token file, a capability `file:` credential or a `tls issue-*` `--ca-key` that other users can
  read is refused. The mTLS certs and CRL, the identity-grants file and the control-plane
  collections may be read by others but not changed by them. `config export` writes the client
  config it edits as `0600`. UPGRADING-4.0 item 54. (F18)

- **Breaking: a backend that fails to start counts toward its circuit breaker, on every
  transport.** `Error::CircuitOpen(String)` becomes `CircuitOpen { backend, last_failure }`, and
  the refusal reads `...; last failure: <start error>`. UPGRADING-4.0 §48.
- **tungstenite's handshake logging is capped at DEBUG**, even under `RUST_LOG=trace`: its TRACE
  line prints the upgrade request with its query string and headers.
- **Admin actions write an `admin_action` audit record and are refused while the
  audit log is down.** Admin meta-tool calls, allowed or refused, and every
  `/ui/api/*` request other than `GET` or `HEAD`, control-plane POSTs included,
  record who acted (issuer and subject for an SSO admin), the tool or route
  template, and the outcome; bodies and queries are never logged. With auth on
  they answer 503 while the log cannot be written. See `docs/UPGRADING-4.0.md`
  item 51.
- **A backend that refuses a managed personal account's token (HTTP 401) forces one refresh of
  that token**, then answers with the reconnect offer when the provider has revoked the grant,
  or with `recovery.error_code` `UPSTREAM_AUTH_REJECTED` (`retry: true`) or
  `UPSTREAM_AUTH_REJECTED_PERSISTENT` (`retry: false`). At most one forced refresh per token
  revision, recorded durably. A 401 or 403 from an HTTP backend is no longer retried. A downgrade
  to an earlier 4.0 beta after a forced refresh is unsupported. See UPGRADING-4.0 item 61.
  (A11, MIK-7570.RECONNECT.1)
- The MCP registry record (`server.json`) lists a `cargo` package beside the container image and declares the environment variables the gateway reads (`MCP_GATEWAY_CONFIG_DIR`, the `GATEWAY_ATTESTATION_*` trio, `SYMPHONY_PLUS_ATTESTATION`, `MCP_GATEWAY_FIREWALL_SKIP_KEYS`, `NO_COLOR`), none required and only the attestation signing key marked secret. The crate's documentation link points at docs.rs. (#518)
- A tool listed in `meta_mcp.surfaced_tools` whose backend reports a structurally invalid input schema (not a JSON object, or failing the capability loader's schema checks) is withheld from `tools/list` with a warning in the log, and a call to it by name is refused as `-32601 Unknown tool`; the backend's other tools stay listed. (#554)
- **A bridged input exchange that runs out of rounds is resumable.** Instead of `-32003`, the
  caller gets the backend's last question with a sealed continuation of that round, and
  resending with the answers resumes where the backend stopped. The last round is held to the
  client's declared capabilities first. `BridgeError` in the library's `input_bridge` module is
  now `#[non_exhaustive]` and gains an `Undeclared` variant. See UPGRADING-4.0 item 62. (#569)
- **A POST whose `MCP-Protocol-Version` header names a revision the gateway does not serve is refused.** 3.x ignored this header on `POST /mcp` and answered anyway. The gateway now answers HTTP 400 with JSON-RPC error `-32022` ("unsupported protocol version") and lists the stateless revisions it serves in `data.supportedVersions`, which is empty when `server.modern_protocol` is off. `2024-10-07` counts as unserved. A request without the header, or with a served revision, is unchanged. (#574)
- **Tool search understands common abbreviations and puts an exact name first.** `gateway_search_tools` now matches a short form against its full word and back (`k8s`/`kubernetes`, `cfg`/`config`/`configuration`, `msg`, `svc`, `pkg`, `db`, `img`, `perms`, `creds`), scored at the same discount as a synonym match; the added matches can only add tools to a query's results, never remove one. A tool whose name equals the query, ignoring case, now ranks above every other result, and among equal scores a name the query meets on a word boundary ranks higher. (#607)
- CI: the container image build and CodeQL scanning run once per merge to the release branch instead of on every pull-request push (image inputs still build on the pull request; pull requests into `main` are unchanged). Maintainer `throwaway/` test runs need only one test job (hosted for now; a dedicated self-hosted arm64 runner that admits only same-repository branches is prepared). Mutation proofs run as one batched workflow per pull request, with a per-mutant RED / SURVIVED / VOID result.
- **`DiscoveredServer` carries `env` and `headers` and is `#[non_exhaustive]`.** Library code builds it with `DiscoveredServer::new`; the new fields are `SecretMap`s whose `Debug` and `Serialize` show keys only (UPGRADING-4.0 item 80).
- With auth on and identity grants on, a governance store that cannot open now refuses the start (HTTP and `serve --stdio`) instead of starting without it. A grant reload whose audit plan cannot be written is refused and keeps the live grants; a change applied but not recorded stays applied and the reload outcome says `UNRECORDED`. See UPGRADING-4.0 item 79.
- CI: a pull request that changes only documentation (`docs/`, or Markdown/text at the repository root) skips the non-test jobs (clippy, feature matrix, Kani, Helm/kind, smokes, image build); every test job and the doc, claims and secret checks still run, and a failed decision runs everything (#2091)
- Library API: `MigratedCredential` gains a public `reachability` field and is `#[non_exhaustive]`; build it only through `migrate_legacy_credential_offline`, and destructure it with a trailing `..`.
- **`kubernetes controller --watch --format json` prints JSON Lines.** Each reconcile cycle prints one compact JSON document on its own line, so a reader can parse the stream line by line. It used to print indented JSON over many lines. Without `--watch` the output is unchanged. See `docs/UPGRADING-4.0.md` item 86. (#2135)
- **The 4.0.0 upgrade notice names four more changes**: the `-32022` refusal of an unserved `MCP-Protocol-Version` header, agent identity that needs a proven principal, the six meta-tools that leave the default `tools/list`, and the key server's refusal of a token request outside its policy. Each is now an UPGRADING-4.0 item (88-91). (#2205)
- Added a stdio test showing a legacy client whose `initialize` handshake omits `elicitation` is never sent an `elicitation/create` by the input bridge (#1991).
- Windows integration fixtures no longer share one task store, so spawned test gateways stop refusing each other (#1142).
- Single-quote Windows paths in YAML `env_files` test fixtures so `C:\Users` is not read as an escape (#1142).
- Check out text files as LF on every platform so byte-exact docs and claims tests pass on Windows (#1142).
- Test fixtures: `HttpGateway` children default to their own task store, fixing Windows store contention (Part of #1142).
- **BREAKING (library API):** `Backend::evict_identity_slots` and `Backend::evict_idle_per_user_entries` are now synchronous; callers drop `.await` (#2245).
- **BREAKING (library API):** `Error` has a new variant, `IdentitySlotsExhausted`; exhaustive matches on `Error` need an arm (#2300).
- Retired config keys load again, with one warning each (once per key per config file), instead of refusing the whole config: `backends.<name>.idle_timeout`, `backends.<name>.circuit_breaker`, `server.ws_port` (no listener opens) and `server.request_timeout`. A config key whose own name starts with `_` or `x-` is an annotation: it loads and is never read. Entries of maps you name yourself, such as `env`, `headers` and backend names, are data and are unaffected. Every other unread key still fails the load. UPGRADING items 29, 34 and 39 are updated. (#2360)
- Document the signed response surface, sender-only key rotation and the restart that every message-signing setting needs (#2412).
- Docker image builds and feature-combination jobs now run after merge to the release line, main and tags, not on every pull request into the release line; the published image is built and checked exactly as before.
- Breaking (library API), cache: a delivered `cacheScope` is never `public`. Every result the gateway sends is clamped to `private`, including a backend's own `public` on the direct route, task envelopes and webhook `message` events; `CacheScope::Public` is now uninhabited and `CacheScope::for_list` is removed. Task results stored before 4.0 with `public` are delivered as `private` (MIK-7211.PARENT.6, item 108 of the 4.0 upgrade guide). (#2474)
- Retained stdio results (the admission ledger and the idempotency cache) are now keyed by the stdio transport itself rather than by its principal name, so a context that only shares that name gets separate entries (MIK-7272.OWNER.3).
- Added stdio tests showing that keyless and legacy writes execute on every call, that each management tool keeps its keyed behaviour, and that a denied tool is refused before any retained result is replayed (MIK-7272.OWNER.1, OWNER.4).
- Every capability, meta tool and backend tool is classified read-only or side-effecting as data: an explicit `metadata.read_only` in each capability YAML, a meta-tool effects table, and the declared rule for backend tools (an annotation or the operator list, else side-effecting). No client-visible change. (MIK-7216)
- The binary crate root is back under the 800-line file ceiling (#2514).
- The 4.0 highlights in the README, release notes and multi-user guide each cite the file or test behind the claim: `src/config/mod.rs` and `tests/mik_7214_acs.rs` (MCP 2026-07-28); `src/gateway/router/authorization.rs` and `tests/a0_per_caller_cache.rs` (per-caller access); `src/control_plane/role_mapping.rs` and `src/gateway/router/sso_admin_tests.rs` (SSO admins); `tests/d1_audit_required.rs` (audit); `src/config/features/api_key.rs` and `tests/e4_hash_key_cli.rs` (keys); `tests/c1_unrecognised_config_keys.rs` and `src/gateway/server/cleartext_tests.rs` (refusing to start; Windows by file access list: `src/config/secret_file_windows_tests.rs`); `deploy/helm/mcp-gateway/values.yaml` (Helm chart) (#2518).
- The release workflow test suite now fails if the published-release re-check is deleted or moved before publication (#2520).
- test: a 2026-speaking backend that refuses `initialize` and `ping` is visible to `gateway_search` and leaves its circuit breaker closed (MIK-7217)
- **A response too large to inspect for tenants says so.** When tenant attribution is configured
  (`tenant_guard.arg_keys`), a response whose text block exceeds the 1 MiB parse bound is still
  not parsed, and a reply refused for its signature chain is never read. The invocation record now
  carries `attribution: "uninspected"` for either, or
  `"cached_delivery_uninspected"` on a cache hit or replay, rather than naming no tenant. A new
  value of the existing field; see UPGRADING item 110. (MIK-7116.MIN.1)
- test: the mTLS listener, the stdio chain-nonce refusal and the anomaly-blocking firewall build are covered end to end; the coverage contract records tiers and counts integration tests (MIK-7324)
- A stdio gateway's `server/discover` answer lists `2026-07-28` in `supportedVersions` when `server.modern_protocol` is on, as an HTTP gateway's does. The setting is read once, at stdio start.
- docs: the 4.0.0 coverage contract assigns a tier to every critical path, inventories its security-enforcing functions, and grades them with `scripts/release/critical_function_coverage.py` (MIK-7324)
- test: the OAuth authorization-code flow, token refresh and callback telemetry are covered end to end against a mock authorization server (MIK-7324)
- An HTTP start with anomaly detection on and no source of a caller key is refused, naming both settings.
- Docs: the 4.0 upgrade guide states that legacy sessions expire on idle time and release their per-session state when they end (item 115). (#2563)
- **`ReloadContext::new` returns a `Result`.** It fails when it cannot pair the registry with
  the running config's destination policy; `ConfigWatcher::start` reports the same error. (#2597)
- **Transport tests.** The legacy SSE handshake, session capture on responses, the OAuth bearer on the wire and stdio start refusals are now covered by tests. Three transport trace events keep their fields on one line; their output is unchanged. (MIK-7324)
- Tests: each per-session store returns to empty once its sessions expire, and a call still running when its session ends leaves nothing after the grace pass (MIK-7681, MIK-7682). (#2601)
- **Coverage grader.** The Critical-function grader now counts a call in a tracing macro's head-line arguments as missed and lists it as unverifiable. The stdio response debug event now reports `pending_count` in place of `pending_keys`. (MIK-7725)
- **Task tests.** Upstream capture, read-time recovery and the descriptor preflight are now covered by tests that assert each refusal. (MIK-7324)
- Release tooling: the bot-review sweep also requires a ledger link for any bot review whose summary body may carry a finding no inline thread does. (#2618)
- **Bridge tests.** Tests now cover the input bridge's round-start deadline and its pass-through of gate refusals on both gate calls. (MIK-7324)
- Tests: the account router's sign-in, unavailable, expired and retry paths are asserted for the connections page, disconnect, start and connect offer (MIK-7324). (#2623)
- Tests: five personal-accounts functions reach the 95% coverage line, covering the forced-refresh claim, the rotated-revision mark, key-literal refusal, revocation without a client secret and a refused code exchange (MIK-7324). (#2624)
- **Task store refusal test.** The test of a store opened under an unwritable home now requires the store's own refusal with nothing created, and checks that its permission setup blocks directory creation as well as files. (MIK-7749)
- Release tooling: CI fails when the burndown tracker summary disagrees with the two ledger checks (MIK-7730). (#2628)
- **Router log fields.** Six router log events (backend request, SSE connect, session delete, meta request, refused caller identity) compute their call-shaped fields before the event. Their output is unchanged. (MIK-7725)
- **Router guard tests.** Tests cover the origin guard's numeric-origin checks on a public bind and the response pass's refusal when a result has no policy target; seven guard log events (one in the direct guard, three in the origin guard, three in the response pass) compute their counts and values before the event. (MIK-7324)
- **Coverage runs no longer leave corrupt profiles.** Test children that run under a zero file-size limit write their profiles to a private temp directory outside the measured set. Probe children get time to finish writing their profiles before they are reaped. (#2639)
Router guards: the direct-route response firewall reads the tool name from the validated call and the origin check folds a hostless URL into its numeric-host refusal. No behaviour change (#2642).
- **Windows trusts SYSTEM and Administrators by SID value, not by SDDL text.** The Integrity-class check compared a rendered string per owner and per ACE; it now compares against two SIDs built once. No behaviour change. (#2643)
- A pull request into the release line that changes an image input (Dockerfile, `docker/**`, the smoke scripts, Cargo manifests, the Helm chart, `docker.yml`) builds and smoke-tests the image before merge again. Other release-line pull requests still build only after merge.
- **A refused grant-journal append on Windows now prints the PowerShell repair.**
  When the journal file's access list failed the integrity check, the error named the file but
  not the fix. It now prints the same icacls/PowerShell repair the secret-file check prints.
  (#2652)
- Tests: identity, task-intent, cost view, refusal-audit and direct-route router rows reach their coverage line; the tools/list result is built without an unreachable failure arm (MIK-7324). (#2657)
- **Lighter tool lookups on each call.** Header mirroring and the output-schema fallback read the cached tool in place instead of cloning it, and an empty withheld-name map answers without hashing the tool name. No behaviour change. (MIK-7536)
- **No payload copy for a call sent once.** A backend call that will not be resent moves its parameters and headers into its one send instead of copying them. No behaviour change. (MIK-7536)
- **Legacy POSTs no longer allocate a notification channel.** A session opens its broadcast channel and buffer only when a stream subscribes. A POST that mints or resumes a session allocates no channel; only a mint allocates the session record. Peak memory under a session-less legacy client drops sharply. No behaviour change. (MIK-7536)
- Tests: the Windows task-store and account-store custody helpers reach their coverage line, covering absent, shared, wrong-kind and unnameable store paths and a parent that refuses creation (MIK-7324). (#2673)
- Tests: the Windows child-environment allowlist test passes under coverage, and the coverage contract requires a failure-free Windows run and names the task SDK setup (MIK-7780, MIK-7781). (#2686)
- Tests: the stdio transport's handling of an id-less response is covered, and its parse log line is measurable by the coverage grader (MIK-7324). (#2694)
- Tests: the OAuth redirect hop reads the destination policy's refusal as an option, with no unreachable error arm (MIK-7324). (#2699)
- A capability that declares `auth.required: true` is listed only once its key is set or its `oauth:` provider has a login; calls to a hidden capability by name are unchanged (MIK-7787).
- docs: the release scope status grades verbatim relay detection (GH1945.COLLUDE.1) met on the meta and direct routes; ASI10 stays PARTIAL (#2722)
- Tests: an installed account holds its minter as one enum and revalidation is one ordered match, with the revalidate refusals covered (MIK-7324). (#2724)
- Tests: the journey owner API and the offer attach refusals are covered, and journey create binds its limits with the bridge check (MIK-7324). (#2734)
- tests: the upstream-followed task result is pinned as a relay source for verbatim relay detection (#2739)
- MCP Events search entries (MIK-7630 I6): the event entries now join the finished `gateway_search_tools` and `gateway_search` answer in one place; the answers are unchanged (#2744).
- Internal: Code Mode chain execution moved to its own file; no behaviour change (MIK-7787).
- Tests: the task store refuses as unavailable when its lease cannot be created (MIK-7324). (#2746)
- `mcp-gateway cap list` marks a capability the gateway would not list with `off: needs <KEY>` or `off: needs a <provider> login` (MIK-7787).
- Refactor: the direct backend route is split into ordered stages with the same behaviour and the same refusal order; the t8 guard scans every direct-route file and pins the stage order (MIK-7324). (#2752)
- Tests: the C6 mutation sample draws from a frozen sampling frame, and the direct route stages are graded as Critical rows (MIK-7324). (#2756)
- MIK-7799: an answer's cross-tenant read verdict rides its `response_delivery_attempt` record on `POST /mcp`, cutting the extra audit record per judged answer.
- performance: the gateway binary now uses mimalloc as its global allocator. On the workload benchmark, in two same-run interleaved runs of 30 repetitions on a shared host (not graded runs), p50 per call dropped by 9.7 and 6.6 microseconds; p99 dropped by 17.3 microseconds in the first run, and in the second the change could not be told apart from none (its interval spans zero); peak memory grew by about 5 to 6 MB (#2762)
- performance: the HTTP dispatch reads a request's params in place instead of copying the whole payload per call (#2763)
- **Stdio backend messages are limited to 16 MiB by default.** Before this, there was no limit. A backend that legitimately sends larger single messages sets `backends.<name>.max_frame_bytes` (64 KiB to 1 GiB). See UPGRADING item 137.
- **Public capability counts only capabilities that run.** The count is 135, not 137: `pyghidra_reverse` and `trawl_extract` load but are held, and `cisco_scanner`'s `scan_mcp_server` operation is not offered. They are named, with reasons, in `capabilities/README.md`.
- Refactor: task creates and transitions have separate commits, so no caller keeps an arm for an outcome that cannot happen (MIK-7324). (#2780)
- test: the shutdown-race backend test waits for the child's pid file instead of a fixed sleep, so it no longer fails on a loaded or instrumented host (#2794)
- firewall: the observed-relay warning ("Firewall: relay observed") now always logs `server` and `tool` (the direct route logged `backend`, a catalogue read logged `method`); alerts keyed on the old field names need updating (#2795)
- test: the signing stdio coverage probe recognises a child's profile when Windows reuses its process id (#2807)
- **`OidcError` has three new variants.** `mcp_gateway::key_server::oidc::OidcError` gained `InsecureIssuer`, `InsecureFetch` and `ClientUnavailable` since 3.5, and the enum is not `#[non_exhaustive]`: an embedder's exhaustive `match` on it no longer compiles. Add the three arms or a wildcard arm (UPGRADING-4.0 item 138).
- test: the shutdown-race backend test gates its child on a release file instead of a timed sleep, and the Windows coverage fallback uses PowerShell syntax (#2813)
- **Hardened signing now covers stdio.** Under `security.posture: hardened`, `serve --stdio` signs and nonce-checks every `tools/call`, not only `gateway_invoke`, as HTTP does; send a fresh nonce in `params._meta["io.mcp-gateway/nonce"]` per call (UPGRADING-4.0 item 112).
- test: the bounded audit-log contention test now holds the stalled write inside its bound and asserts the contenders queued on the permit instead of being refused (#2845)
- test: the bounded audit-log contention test releases its callers through one barrier on a paused clock, so every caller queues on the permit before any deadline passes and the test no longer depends on runner speed (#2863)
- Tests: stdio delivers a response or a progress frame only to its own caller, and a frame carrying any method is never taken as a reply (MIK-7324). (#2879)
- test: the T32 retry test kills the gateway while the receiver holds an attempt open, so it sees exactly five deliveries every run, and store tests pin that a crash after a claim spends that attempt (#2881)
- tasks: a failed upstream task whose error is the peer's own is stored as task record version 6, written only on such rows; a gateway that reads versions up to 5 refuses a task store holding one, so back up `tasks.store_dir` before upgrading; a backup taken after holds version 6 rows too (UPGRADING-4.0 item 105) (MIK-7887)
- **Shadow-rule exports cite the operator guide.** The header of `mcp-gateway doctor --shadow`
  output in every format (`grep`, `nginx`, `yaml`) now reads
  `# Source: docs/SHADOW_SCAN.md (static network-detection rules)` instead of naming a design
  document that is no longer published. The rules themselves are unchanged. A tool that matched
  the old header line needs updating. (#2995)
- **The README leads with why to use the gateway, in the 3.5.1 voice.** It opens with
  connecting an unlimited number of MCP servers, tools and APIs at a fixed context cost, the
  problem it removes and the flow diagram, then the Quick Start and a short *What's new in 4.0*.
  *Why use MCP Gateway?* returns with current facts. The full 4.0 change list moved to
  `docs/whats-new-4.0.md`. Package, registry and Homebrew descriptions carry the same lead.
  (#2998)
- A capability whose declared output root is not object-shaped (an array, a string, a type list such as `["object", "null"]`, or a typeless root without `properties`) now advertises an object `outputSchema` and publishes `structuredContent` under `items`, as MCP requires; the text content is unchanged. Nine shipped capabilities are affected, among them `sentry_list_issues`, `hackernews_top` and `number_facts` (MIK-7959).
- test: a killed response stream re-issued under a new id executes a side-effecting call once, and leaves a read-only call unaffected (MIK-7216)
- **Windows test gates state their reason.** Every test-side `cfg(unix)` gate now carries a one-line comment naming why the test is unix-only (mode bits, uid or inode identity, symlinks, process reaping, child environment). One cross-platform test (OAuth temp-file cleanup) lost its Unix gate and now runs on Windows; no product change. (MIK-7587)
- **A task notification carries the full task.** `notifications/tasks` now carries the task as `tasks/get` would return it to that reader, built at delivery: output states are re-authorized per reader against the reader's current credential, grant decisions and relay receipts are recorded as a read records them, and the frame is written to the transparency log as sent. A reader refused, or whose task cannot be read, gets the task id and status only. (MIK-7778)

### Removed

- **MITRE Fight Fraud Framework mapping removed.** `docs/compliance/MITRE-F3-MAPPING.md` and its README badge and links are gone. F3 models financial-fraud actors (card schemes, payment rails, cash-out); 108 of its 123 techniques fall outside a tool-call gateway, and the controls it rated are covered by the OWASP Agentic AI self-assessment. The one open finding, failed authentication with no throttle or lockout, is now listed under OWASP ASI03. (#2191)
- Removed 18 built-in registry names that had no maintained server (list and reasons in UPGRADING-4.0 item 124); `jira` is now `atlassian` (MIK-7787).
- **`mcp-gateway plugin` removed.** `plugin search`, `install`, `uninstall` and `list` are gone, with the marketplace module and `MarketplaceConfig`: nothing ever loaded what `install` wrote, and the default marketplace host does not resolve. A `marketplace:` block in the config now loads and warns once; delete it, and add tools as `backends:` entries or capability files instead (UPGRADING-4.0 item 145). (#2953)

### Fixed

- **Zed export and import use Zed's real settings file and format.** `setup export --target zed` now writes to Zed's config directory (`~/.config/zed/settings.json` on macOS, `$XDG_CONFIG_HOME/zed` on Linux, `%APPDATA%\Zed` on Windows); on macOS it previously wrote to Zed's data directory, which Zed never reads, so remove a `gateway` entry left there. Discovery now imports Zed's flat `command`/`args` and `url` entries, which it previously skipped (#1811).

- The 4.0.0 upgrade notice now includes `--config PATH` in the `accounts migrate-credentials`
  command it prints; without it the command stops unless `MCP_GATEWAY_CONFIG` is set.
- **Cost budgets survive a stdio gateway restart.** A stdio gateway loaded `costs.json` at
  startup but never wrote it, so every restart gave the daily budgets back. It now saves when
  the client closes stdin (after in-flight calls finish) and every 5 minutes while it runs, as
  the HTTP gateway does. Each save writes its own scratch file, so gateways sharing a data
  directory no longer write one scratch file between them.
- **A failed release or image-manifest job can be re-run for 14 days, not one.** The build
  binaries and image digests handed between jobs expired after a day, so a later re-run
  published a release with no binaries or failed to find the digests. They now last the
  repository's 14-day artifact retention, and a CI check keeps every such handoff there.
- **The release scope gate refuses a waived criterion that is still marked blocked.** Such a
  row let a release pass while the burnup still listed it as held. A test also pins the
  approved-waiver list to the ledger's waived criteria, so a waiver removed from the ledger
  cannot leave its approval behind.
- **A stdio backend that dies before `initialize` is reported at once, with its exit status.**
  It used to wait out the request timeout and report a timeout, with the child's stderr already
  discarded. The error now names the exit status and points at the gateway log, where one record
  carries the last 20 stderr lines (2 KiB at most) with argv, `env:` values and credential-shaped
  text redacted. The stderr never goes to MCP clients. A build without the `firewall` feature has
  no credential recogniser, so it logs a withheld marker instead of the text. `doctor
  --start-stdio` caps a whole start at 15 s. (#526, #1568)
- **A debug build of the gateway starts on Windows.** Clap's generated argument parser needs
  about 900 KB of stack in an unoptimized build, over the 1 MiB Windows gives a process's main
  thread, so even `--version` overflowed. The gateway now runs on a thread with an 8 MiB stack.
  Release builds were not affected.
- **On Windows, file locks now actually lock.** The advisory lock the control-plane store, the
  durable protocol-revision telemetry and the OAuth `client_id` self-heal rely on did nothing on
  non-unix platforms, so concurrent writers could lose each other's updates, and a caller could be
  handed a `client_id` that another writer then replaced on disk. The lock is now `LockFileEx`.
- **An error result is never replayed from a cache.** The response cache and the capability
  cache stored `isError: true` results, including the gateway's own rate-limit and open-breaker
  refusals, and served them to every call with the same key for the whole TTL (60 s by default).
  One throttle could answer hundreds of later calls with a stale refusal. Errors are now never
  cached; successes are cached as before. See `docs/UPGRADING-4.0.md` item 63 (F26, GH #1158).

- **A WebSocket backend's progress reaches the call that asked for it.** `WebSocketTransport`
  dropped every inbound notification. It now delivers `notifications/progress` to the call whose
  request carried that `progressToken`, under the stdio transport's rules: progress only, the
  token must belong to a live call, and a frame it cannot attribute is dropped. The caller gets
  its own token back through the request-scoped translation, as on stdio.
- **One caller's burst no longer disables a tool for every caller.** A refusal by a
  backend's own rate limiter was reported as "Circuit breaker open" and counted as a
  backend failure, so a burst past the limit could auto-disable the capability or kill
  the backend for all tenants. It is now `Rate limit exceeded for backend 'x'` (code
  still -32000, recovery hint `RATE_LIMITED`), is not sampled by the error budgets, and leaves
  `mcp_backend_circuit_state` alone. See `docs/UPGRADING-4.0.md` item 53 (F23).
- **Config reload follows a symlinked config across directories.** A link retargeted to a
  file in a directory the gateway was not watching reloaded once and then missed every later
  write, serving the old config silently; a directory the link left stayed watched forever. The
  watcher now follows the whole link chain on every change, including a Kubernetes ConfigMap's
  `..data` swap, a Capistrano-style `current` directory link retargeted by rename or by
  `rm` and `ln -s`, and reads the new release on reload. Limits are listed in DEPLOYMENT
  under "What triggers a config reload". (#453)
- **BREAKING: only delivered change notifications are advertised.** `resources.subscribe`,
  `resources.listChanged` and `prompts.listChanged` were advertised and never delivered.
  They are now `false`, and `resources/subscribe`/`unsubscribe` are refused with `-32601`.
  `tools.listChanged` is announced for every tool-set change over HTTP (config reload,
  capability reload, admin UI, revive), as a standard `message` event on the 2025 GET
  stream rather than the gateway's envelope, and is `false` over stdio. See UPGRADING-4.0
  item 52.
- **Capability pins survive CRLF line endings.** The `sha256:` pin now reads CRLF as LF, so
  a pinned capability that a Windows checkout or editor converted to CRLF is no longer
  refused as tampered. A lone CR still changes the hash. Capability YAML is checked out
  with LF on every platform (`capabilities/.gitattributes`), so the Windows binary embeds
  the same starter capabilities as the others. A pin made over CRLF bytes must be re-made: see
  UPGRADING-4.0 item 60. (#524)
- **`doctor` finds stdio commands on Windows.** It split `PATH` on `:`, which takes
  `C:\...` apart, so it reported every stdio backend's command missing. It now uses the
  platform separator and, on Windows, also the `.exe` name a spawn resolves a bare
  command to. (#524)
- **The `Windows check` CI job runs tests.** It compiles every test target for Windows
  and runs the library and binary unit tests, except `gateway::` and
  `personal_accounts::`, whose fixtures open stores that refuse on non-unix (#1142). Before,
  it ran `cargo check` only. (#524)
- **A config file that fails to load is no longer replaced with defaults.** `mcp-gateway add`, `mcp-gateway setup` and the admin UI's backend edits read an unparseable or invalid config file as an empty default and wrote that back, which wiped the configured backends. They now stop with `Failed to load <path>` and leave the file untouched; a missing file still starts from defaults. (#462)
- `mcp-gateway tls init-ca` marks the CA certificate for certificate and CRL signing, and `tls issue-server` and `tls issue-client` add an Authority Key Identifier, so strict X.509 clients (Python 3.13's default TLS context, `openssl verify -x509_strict`) accept the chain. Certificates issued earlier are not replaced; `docs/DEPLOYMENT.md` describes rolling to a new generation. (#487)
- "Did you mean" suggestions for an unknown tool name measure edit distance in characters, not bytes. A candidate name with non-ASCII characters (for example `café`) got a wrong distance, so a close match could be missed and a distant one offered. (#573)
- **A tool search with no results no longer panics on a non-ASCII query.** In 3.x, building tag suggestions for an empty result cut a query word at three bytes, which panicked when the cut fell inside a multi-byte character. It now cuts at three characters. (#607)
- **A backend `tools/call` no longer rebuilds the argument-key check on every call.** When the backend's tool list is already cached, the gateway now judges the call's argument keys against the cached schema in place. Before, it built the whole list-fill machinery and copied the cached tool definition on every call, which added fixed latency to each `tools/call`. The check itself is unchanged: a stale or missing list still refreshes before judging. (#613)
- **Env files follow a retargeted link.** An env file reached through a link (`current/.env` after
  a release switch, or an env file that is itself a symlink) kept reloading from the old target,
  because its directory watch was fixed at startup. A gateway serving HTTP from a config file,
  named or found by discovery, now re-reads env files every 2 seconds and reloads when their
  content differs from what is loaded, which also works on NFS and FUSE mounts; a stdio gateway
  watches no files, as before. A file that fails
  to load keeps the running values and is retried, with at most one warning a minute per file
  unless the error changes. A lookup error on an env file (a link loop, a directory the gateway
  cannot search) now fails the load instead of reading as a missing file. After a failed reload
  the gateway retries every 2 seconds until one succeeds, so a config edit that failed alongside a
  broken env file still applies once the env file is fixed. See `docs/DEPLOYMENT.md` and
  `docs/UPGRADING-4.0.md` item 72. (#1286)
- Firewall anomaly detection learns from real traffic: it scored every call a neutral 0.5 because nothing fed its transition record. It now learns from admitted calls on every route (one shared model; each call is scored against its caller's previous call), warms up before scoring (`anomaly_min_observations`, default 20), scores never-seen transitions 1.0, and its blocks cannot be downgraded by a rule and carry error -32002 on every route, the per-backend `/mcp/{name}` route included. Out-of-range thresholds refuse to load when detection is on. See UPGRADING-4.0 item 76. (#1756)
- **The published crate's tests build and pass.** Some tests read documentation, deploy
  manifests and release records that the crate did not include, so `cargo test` on the
  published crate failed to compile. Those files are now packaged, and CI builds the tests
  from the packaged crate on every pull request and runs them after each merge.
- `tls issue-server --san-dns` writes an IP literal (`127.0.0.1`, `::1`, `[::1]`) as an IP SAN instead of a DNS SAN, so a client dialling that address can verify the certificate; entries are trimmed. Only newly issued certificates change. An mTLS policy's `san_dns` pattern matches DNS SANs only (#1955).
- **Discovery keeps a server's `env`, `headers` and argument boundaries, and reads commented Zed settings.** `cap discover --write-config` writes them into the owner-only config; discovery's JSON, YAML and `Debug` output show the keys only. A client's `${env:NAME}` becomes `${NAME}`; a key using a client-only variable such as `${input:…}` is skipped with a warning. `setup export --target zed` into a commented file prints the entry to paste instead of failing (#1876).
- **Per-tool visibility checks no longer copy the capability definition.** 4.0's per-caller visibility checks each tool on `initialize` and `tools/list`, and each check cloned the full capability definition, which raised `tools/call` p99 latency under load. The checks now read the definition in place. (#2110)
- A stdio gateway serves its `personal_managed` accounts to its local operator whatever the `auth` block says; before, a stdio gateway with auth off refused every account-bound REST call with "the request carries no verified end-user identity". HTTP is unchanged: it serves the sole-operator account only under the single-user settings. `accounts migrate` now states where each migrated grant is reachable, and that an account-bound MCP backend still needs a verified end-user identity (#1961).
- A config reload reads the config file and env files on a thread of its own, so a read stalled on an NFS or FUSE mount no longer holds an async worker or blocks shutdown; at most one such read runs at a time (#1808).
- **Dashboard sign-in by link works behind a TLS-terminating proxy.** With an HTTPS `server.public_url` on a plain-HTTP listener, opening the link at the gateway's loopback URL no longer answers 409: it shows a one-time code, valid for 60 seconds, to enter at `<public_url>/dashboard/handoff`, which sets the session cookie on the public origin. The code never appears in a URL. `mcp-gateway dashboard-link` and the startup banner give the link in this shape. See UPGRADING-4.0 item 70. (#2130)
- **`cap discover --format json|yaml` stdout is one document.** The `--write-config` hint, progress lines and "No MCP servers found" text went to stdout after the listing, so piping the output into a JSON or YAML parser failed. In json/yaml mode those lines now go to stderr, and an empty result prints `[]`. Table mode is unchanged. (#2135)
- A plain-HTTP gateway no longer waits without limit for open requests after SIGTERM: the listener gives them `server.shutdown_timeout`, then cuts them. The mTLS listener uses the same bound instead of a fixed 30 s (#2147).
- Firewall per-caller limits (call budget, tenant guard, anomaly detection) key on the caller on every route: its resolved identity (OIDC, trusted proxy or Access, mTLS subject, OAuth agent), else its API key. OAuth-agent and mTLS callers on a modern `POST /mcp` are scored instead of refused as unidentified, and callers of the per-backend `/mcp/{name}` route no longer share one bucket per backend. Limits start fresh once at deploy. See UPGRADING-4.0 item 94. (#2155, #1785)
- A gateway that found its config by discovery (no `--config` or `MCP_GATEWAY_CONFIG`) now watches that file and polls its env files like a named config, and offers `gateway_reload_config` over HTTP and stdio; its governance store location and admin config edits are unchanged (#1868).
- **VS Code discovery reads `mcp.servers`.** Discovery read each key under `mcp` in a VS Code or Cursor `settings.json` as a server, so the shape VS Code documents (`"mcp": { "servers": { ... } }`) imported nothing. It now reads the servers under `mcp.servers`, with their command, args, env, URL and headers. A settings file with comments or trailing commas is read. (#2177)
- A `personal_managed` account bound to an MCP backend is now served to the sole operator (stdio, or a single-user HTTP gateway) through `gateway_invoke`, as it already was for REST capabilities; multi-user gateways still require a verified identity. (#2188)
- List fills for discovery, `gateway_search`, resources, resource templates and prompts now pass the backend's circuit breaker and spend rate-limit tokens, and their outcomes count toward the breaker. Startup warm-up fills are recorded but never refused (#1300).
- Unit tests compile on macOS again: the FIFO test fixtures no longer call an API that has no Apple implementation, and a new CI job compiles every test target on macOS.
- A bridged exchange whose retry round returns a malformed `input_required` result now fails as an upstream fault instead of being recorded as the completed call under the caller's idempotency key.
- A client that disconnects while its `tools/call` is in flight no longer frees the idempotency key: a retry under the same key is told the outcome is uncertain instead of running the call again. This covers `gateway_invoke`, its bridged input rounds and the direct `/mcp/{name}` route. (#2223)
- **A warm-up fill no longer reopens a backend the health probe shut off.** When the probe tripped a backend's circuit breaker after a run of answers that served nothing, a startup warm-up fill that listed successfully could reset the breaker and undo that decision. The probe's trip now counts as one a warm-up did not cause, so only the normal half-open probe closes it. (#2219)
- On Windows the transparency log now tells its active file apart by the file id instead of the creation time, so a file replaced within the NTFS tunnelling window is detected.
- A bridged round dispatched after an operator disabled the server is now refused before it reaches the backend, and the caller's idempotency key stays retryable.
- **Meta-MCP listings and reads serve the sole operator's connected accounts.** On a
  single-user gateway or over stdio, `gateway_invoke` served an account-bound backend while
  `gateway_list_tools`, search, `prompts/list`, `resources/list` and `resources/templates/list`
  omitted it and `prompts/get` and `resources/read` refused it. Every read path now resolves the
  credential for the caller its credential established, through the same sole-operator check.
  Multi-key and anonymous callers are still refused. (#2231)
- **`POST /mcp/{name}` serves the sole operator's connected accounts.** On a single-user
  gateway, an account-bound backend refused the operator on the per-backend route with "no
  verified end-user identity", while `gateway_invoke` served them. The route now resolves the
  credential, notification session and audit subject for the caller its credential established.
  Multi-key and anonymous callers are still refused. (#2190)
- **A tool call racing a capability reload no longer returns a config error, and a removed tool is refused, never admitted.** The identity-grant check and the dispatch path each looked the tool up twice; if a reload removed it in between, the call failed with `Capability not found`. Each now looks the tool up once, and a tool absent at the grant check gets the ordinary not-found refusal, so a reload that re-adds it before dispatch cannot skip its grant. (#2236)
- Live `verify` now reports a missing `.hwm` when disk-full expiry removed the last sealed segment and the active file opens with a segment-open record. A tail cut in that state used to verify clean.
- Agent identity config faults now fail at load: `require_id` with no proof source (`agent_auth`, `mtls`, or `allow_unverified_agent_identity`) and duplicate `principal_labels` keys are refused, and the gateway warns whenever `allow_unverified_agent_identity` is set.
- An `accounts` block that is disabled and configures no adapter no longer has its `file:` secrets read at load, and every account secret is read for the rotation report only after the block validates (#2248).
- **Rotating the `/metrics` token file is now reported on reload.** A `server.metrics_token` given as `file:` or `env:` was never recorded, so a reload stayed silent while the route kept serving the token it was built with. The reload now reports the rotation as needing a restart. (#2251)
- **A hung audit write found by the readiness probe now marks the log stalled.** When the audit log was degraded and its probe write hung, the probe's 2-second bound cancelled the append before it could record the stall or count `mcp_audit_append_timeouts_total`, so every call kept waiting 2 seconds for its 503. The bound now runs inside the append: the first probe timeout marks the log stalled and counts the timeout, and later calls fail at once. (#2252)
- **Every tool now refuses `inputResponses` that arrive without the `requestState` the gateway issued.** Before, only `gateway_invoke` and the chain form of `gateway_execute` did; other meta-tools accepted and ignored the answers. The refusal (-32602) now happens at the shared `tools/call` entry. (#2254)
- **Migration refuses an expired 3.x credential that has no refresh token.** It used to
  migrate as Connected and then fail on every call. A managed grant with no refresh token
  now asks the user to reconnect when it expires, instead of reporting the provider as
  unavailable forever. (#2255)
- `linear_attach_url` no longer sends `createAsUser`. Linear accepts that field only from OAuth applications, so under the capability's personal API key it failed the attachment. (#2256)
- **Backend names that differ only in punctuation or case no longer share a package cache, and bunx and yarn get their own.** `team.alpha` and `team_alpha` mapped to one cache directory, and `bunx` and `yarn` were given `npm_config_cache`, which they do not read. The cache directory name now carries a hash of the full name, and `bunx` gets `BUN_INSTALL_CACHE_DIR`, `yarn` gets `YARN_CACHE_FOLDER`, and `pnpm` gets `pnpm_config_store_dir` (and `npm_config_store_dir` for older pnpm). Package caches are downloaded once more after the upgrade. (#2258)
- **Chain steps and task-executed calls audit the caller's declared agent label.** The
  `X-Agent-ID` (or query) label was dropped from the audit record of every `gateway_run_chain`
  step and every call a background task made. (#2259)
- **The gateway's tool-change announcer now stops at shutdown.** The background task that announces tool-set changes had no shutdown branch, so it kept the whole application state alive after the HTTP server stopped. It now exits when shutdown fires, which matters to embedders and in-process tests; a process that exits was never affected. (#2260)
- A request whose idle per-caller slot was evicted just before it claimed the slot now records its start or dispatch failure on the live slot's circuit breaker, not on the evicted one (#2261).
- **Offline migration finds a 3.x credential when the account resource differs from the
  backend URL.** 3.x named its token file after the backend's `http_url`; migration looked it
  up under the descriptor `resource` and reported no credential when the two differed. It now
  uses the backend URL. (#2262)
- **An account descriptor's `client_secret_ref` must name an absolute path.** `file:` with an
  empty or relative path used to load and then fail at the first token refresh. The config is
  now refused at load. (#2263)
- **`mcp-gateway dashboard-link` reaches an mTLS listener.** New `--client-cert` and `--client-key` flags (or `MCP_GATEWAY_CLIENT_CERT` and `MCP_GATEWAY_CLIENT_KEY`) present a client certificate, and `--ca-cert` (or `MCP_GATEWAY_CA_CERT`) names the only CA the server certificate may chain to. Without `--url`, an mTLS config supplies `mtls.ca_cert` as that CA and a listener requiring a client certificate is refused up front when none is given. The `curl` workaround is gone from DEPLOYMENT. (#1832)
- A new audit log now begins with an `audit_segment_opened` record, so live `verify` reports a missing `.hwm` on a log that never rotated. A tail cut on such a log used to verify clean; a cut back to the open record alone still reads as a fresh log. Caller records in a new log start at counter 2 (UPGRADING item 98).
- `setup` no longer prints URL credentials or query tokens for HTTP and WebSocket backends in the import list (#2246).
- **A failed audit write on a refused direct call now keeps the caller's request id.** With the audit failure policy set to fail-closed, a scope refusal or an unrecognised backend answered the replacement 503 with `id: null`. The 503 now echoes the id of the request that was sent. (#2283)
- **The identity grant CLI keeps an mTLS SAN URI subject whole.** `--subject mtls:spiffe://…`
  was split at its last colon, writing a grant for authority `mtls:spiffe` that matched no
  caller. A built-in authority (`api_key`, `mtls`, `agent_oauth`) now ends at the first colon;
  an issuer-URL authority still ends at the last one. (#2291)
- WebSocket backend requests now time out when the outbound queue is full, instead of waiting past the configured timeout (#2253).
- A debug build can hold a task create between its commit and its ack, so a process test kills the real binary in that window; release builds do not carry the hook. (#2298)
- The child-reap tests no longer count a zombie as reaped. They now require the child to be gone from the process table, and a fixed 50 ms wait in a pool test is a bounded poll. (#2301)
- Closing a WebSocket backend now fails its in-flight requests at once instead of after their timeouts (#2257).
- `gateway_execute` refuses `inputResponses` sent without the `requestState` it issued, instead of re-running the chain (#2254).
- `gateway_search_tools` and `gateway_search` match a query against the name of the backend that serves each tool, so searching for a backend by name returns its tools instead of zero matches. Direct tool-name and description matches still rank first ([@terafin](https://github.com/terafin), [#2317](https://github.com/MikkoParkkola/mcp-gateway/pull/2317)).
- **A notification refused because its transport cannot carry the caller's credential is now audited.** On a stdio or websocket backend, such a refusal wrote no `idp_refuse` row, and a minting backend had already recorded `idp_mint` for a notification that was never sent. The refusal is now decided before minting and writes one `idp_refuse` row. A caller with no principal keeps the static path, as before. (#2310)
- **Tool listing and search omit a `required` backend for a caller without identity.** On a
  single-user gateway, an anonymous caller could list or search the tools of an account-bound or
  other `required` identity-propagation backend from its shared slot, while `gateway_invoke`
  refused the same caller. Tool discovery now applies the rule the prompt and resource catalogues
  use: such a backend is omitted, and naming it answers "backend not found". (#2326)
- **The account connections page no longer lists a descriptor-fenced grant as connected.** A
  grant from before an account descriptor change is refused at use and needs a reconnect; the
  page now shows it as not connected. (#2327)
- Windows process discovery no longer relies on `wmic` (removed from Windows 11 24H2 and Server 2025): it lists processes through PowerShell `Get-CimInstance Win32_Process` and reports a failed listing as an error. (#2328)
- A config file watched through a plain (non-symlink) path no longer fails to start on Windows: `read_link` on a regular file is os error 4390 there, and the watcher now checks the file type first. (#2329)
- **`initialize` and `tools/list` count visible capabilities by name.** Counting what a caller may invoke cloned every capability's tool, schemas included, on each listing. It now reads names only. (#2110)
- **`gateway_list_servers` no longer counts a `required` backend's cached tools for a caller
  with no identity.** The backend is still named, with `tools_count` 0 and `tools_known` false,
  matching the tool listings that omit it for that caller. (#2346)
- AX-010 no longer withholds a tool for ordinary usage guidance. "Before calling this tool" on its own now only warns, and the tool is still served. It still withholds when a read-like directive follows: read, include, copy, load, cat, fetch or open. "Encoded as base64" is a format note, not exfiltration; base64 blocks only next to send, upload, post or exfiltrate. Linear `prepare_attachment_upload` and `create_attachment`, Netdata Cloud `trigger_report` and axterminator `ax_visual_diff` are served again. (#2356)
- **Discovery responses are inspected once.** `gateway_list_tools`, `gateway_search_tools` and `gateway_search` were scanned twice by the response firewall: on their raw value, then again on the served copy, writing two audit entries. The served copy is no longer scanned again; a server-owned marker, which no backend or retried call can set, records that the raw value was inspected. (#2358, MIK-7407)
- The readiness test now holds the startup capability scan until it has seen "capabilities loading", so it no longer depends on timing. A debug build reads a gate file for this; release builds do not carry it. (#2376)
- Test: the 3.x grants refusal test reads an owner-only copy of its fixture, so it passes on Windows checkouts.
- **Secret-file fix commands are copy-safe and complete.** The `chown`/`chmod` line a refused file prints now quotes the path and ends options with `--`. A trust file owned by another user also gets `chmod go-w`, because `chown` keeps a group- or world-write bit the rule still refuses. The unreadable-config error names the process read-access requirement. See `docs/UPGRADING-4.0.md` item 96. (#2391)
- **WebSocket `close()` no longer waits behind a blocked send.** A full outbound queue held the sender slot while awaiting, so closing a stalled backend hung until the peer drained. The send now releases the slot first. (#2393)
- **An embedded capability backend no longer keeps `/readyz` and `/health` at 503.** A backend built and loaded through the public API had no way to report its startup scan complete. It now counts as loaded from creation; only the gateway's own background startup waits. (#2397)
- One load now lists every unset variable in a config field, and capability `env:` credential failures name the listed env files that were not found. The removed `mcp_gateway::session_sandbox` and `mcp_gateway::tunnel` library modules are documented in the upgrade guide. (#2400)
- Add a route test that two legacy sessions of one credential share one tenant bucket and another credential is unaffected (#2403).
- **An unkeyed `tools/call` no longer builds an idempotency representation it never uses.** Admission now builds the representation, which embeds the active routing profile's description, only when the call carries an idempotency key. Unkeyed calls skip that work on every call. (#613)
- **Refusals on `/mcp` reach the audit log.** A `gateway_invoke` refused by the router's scope
  check or by the request firewall, before the meta layer runs, now writes one `invocation` record
  with `outcome: denied` and the returned code, as the same refusal on `/mcp/{name}` already did.
  With auth on, a failed write answers 503/-32005 instead. (#2420)
- **The response firewall no longer searches well-known MCP field names on every call.** A tool result's own protocol keys, such as `content`, `type`, `text` and `isError`, are fixed names that match no injection pattern, and the gateway now skips them. Every string value and every other object key is still scanned, including near-miss spellings of protocol names. (#613)
- Make the era-probe tests wait for a slow peer instead of racing a fixed 2 s probe cap on a stalled runner (#2425).
- Tasks: an input round now closes at its stored continuation's deadline (about five minutes). A late `tasks/update` gets -32602 naming the deadline, and the task settles `cancelled` with that reason instead of resuming and then failing. A `tasks/update` to a settled task says how it settled. (#2429)
- Tasks: a resumed call's audit record now carries the updating request's declared agent label. (#2430)
- **Stateless calls get their own audit correlation key.** On the modern HTTP route a call without an OpenTelemetry trace id in `_meta` was logged under one shared correlation key, because the route carries "no session" as an empty session id. Such a call is now keyed on the trace id minted for that invocation (`correlation_source: trace_id`). Legacy sessions and `_meta` trace ids are unchanged. (#2464)
- **Idempotent replays on `/mcp` reach the audit log.** A `gateway_invoke` (or surfaced tool) call
  re-issuing a completed execution's idempotency key is answered from the stored result and now
  writes one `invocation` record with the original's request hash, as a first execution does. With
  auth on, a failed write withholds the replay with -32005. (#2472)
- Refuse a re-probe answer that arrives over a transport since replaced, and record `era_probe_discarded` with the reason (#2489).
- Windows test coverage: test fixtures that were skipped on Windows because of the home directory, symlink creation or a legacy lock helper now run there, and the gates that remain are listed under "Windows limitations" in CONTRIBUTING.md. Debug builds read `MCP_GATEWAY_TEST_HOME_DIR` for the home directory; release builds do not (#2368).
- A retried `gateway_set_profile` with the same idempotency key now replays its first result. The retry was refused as a key conflict, because the stored result was bound to the profile the call itself had just changed. (#2501)
- Task input-round tests no longer assume a free worker permit or an unbounded producer wait, which made them fail intermittently on Windows (#2506).
- **Idempotent replays on stdio reach the audit log.** A stdio `gateway_invoke` (or surfaced
  tool) call re-issuing a completed execution's idempotency key now writes one `invocation` record
  with the first execution's outcome and hashes, as on `/mcp`. A replayed `gateway_invoke` record
  also names the tenants of the value it delivers, marked `attribution: "cached_delivery"`. (#2480)
- **A direct-route refusal records the tenants it was refused for.** A `tools/call` on
  `/mcp/{name}` with no `arguments` member is scanned by the firewall over `params` itself; its
  invocation record now names those tenants too (MIK-7116.MIN.1). (#2523)
- stdio: a request id reused right after its answer can be cancelled, and a late cancel for the answered call no longer silences the next call that reuses the id (#2557)
- A disconnect or a reaped legacy session now reclaims its per-session profile, state and cost entries, and the stream reaper goes by last activity, not age (#2563, #2567).
- Under `security.posture: hardened`, a `tools/call` with a malformed signing nonce is refused `-32602` before the task-augmented gate can answer it.
- OAuth: with `callback_host` set to a loopback IP, the redirect URI names that address (IPv6 in brackets) and the callback server listens there, instead of advertising `localhost` a browser may resolve to the other address family (#2578). If your provider app registers the redirect as `http://localhost:...` while `callback_host` is a loopback IP, register the literal address instead, or leave `callback_host` unset
- The projection A/B arm and the prefetch hints key on the caller, not on the empty id every modern caller shared (#2591).
- A caller with no caller key gets the control shape, no A/B event and no hints; a legacy or stdio session still keys on its session.
- Arms are re-derived per caller on upgrade: restart or split an A/B measurement window at the deploy.
- The unread per-session cached-token counter is removed.
- A refused cloud metadata address (169.254.169.254, fd00:ec2::254) is named as a cloud metadata address instead of a private/reserved one; a refused host name still names no address (MIK-7633).
- A task's calls key their A/B arm and prefetch hints on the caller that created or resumed the task, as a direct call does (#2607).
- Tests: the cacheScope drift check reads whole source files and excuses only listed files, so a production writer after a test-gated item is no longer hidden. (#2616)
- Dev tooling: the MCP Events fail-fast stub refuses a malformed, negative or oversized Content-Length. (#2621)
- On stdio EOF, `run_stdio_on` returns within the 30 s drain plus a 10 s teardown window, even when a backend stop, the custody store or a task never finishes; an abandoned step is logged by name (MIK-7685).
- stdio and WebSocket backends negotiate the protocol revision like HTTP: a selection outside the revisions the gateway speaks fails the start, the stdio fallback retry adopts the revision the backend selects, and WebSocket retries a version rejection once at the highest shared revision (MIK-7721).
- A shutdown whose task drain runs out of time cancels the task workers still running before the task store closes, on HTTP shutdown and stdio EOF; their records are settled as interrupted on the next start, except tasks a configured upstream recovery adapter manages (MIK-7757).
- A capability that declares `providers.fallback` now logs a CAP-011 warning at load: fallback providers are not executed, and the capability is served from its primary. A malformed fallback entry fails the load instead of being dropped silently (#2677).
- `subscriptions/listen` opens its stream with `notifications/subscriptions/acknowledged`, naming the honoured filter, instead of a JSON-RPC response, which the 2026-07-28 specification defines as the end of a subscription; a subscription the gateway ends gracefully closes with that response, and one whose reader fell behind just closes (MIK-7766).
- **An accepted notification or client response over HTTP is answered 202 with no body.** It carried `{}` with a JSON content type, which MCP Streamable HTTP forbids; the session header is kept. Both the meta route and the direct `/mcp/{name}` route. (#2682, MIK-7759)
- A key under a capability provider that this gateway version does not read (a misspelling, for one) now logs a CAP-012 warning naming its path instead of being dropped silently. `mcp-gateway cap validate` runs the same structural checks as the loader: warnings print and a structural error fails the command (#2683).
- `mcp-gateway add <name>` now uses a pinned package that exists, or the vendor-hosted endpoint, for every built-in server; 30 of the 45 npm packages it named did not exist and 7 were deprecated. CI checks every entry (MIK-7787).
- **An event delivery is on the audit log before it is sent, and a retry stays inside 15 minutes.** The attributed record of each attempt is written first; if the log refuses it, nothing is POSTed and the attempt retries. `events.retry_window` above 15 minutes is refused at load. The `throttled` field of a subscribe refresh now follows the bucket and the waiting deliveries instead of a flag cleared on every send. (#2718)
- **A webhook route without a `method` accepts POST, a `transform.data` mapping without braces is a literal, and a restart drops subscriptions to routes that no longer exist.** A route that named no `method` accepted only GET, so a sender that POSTs got 405; it now accepts POST (see UPGRADING-4.0 item 131). The documented mapping grammar is a template or a literal, never a raw payload path. After the startup capability scan, subscriptions to webhook event types nothing offers are withdrawn with their pending retries. (#2732)
- Internal: a build without the dashboard feature no longer warns about an unused helper (MIK-7787).
- **Input validation reads array limits.** The input validator now enforces `minItems` and `maxItems`; the Cloudflare WAF capability requires its ruleset phase again.
- **An event replay is audited under the admin who triggered it.** The `events.replay` audit record now carries the admin credential instead of the gateway, for a single and a bulk replay. (#2774)
- fix: the relay receipt helpers build clean without the firewall feature (#2778)
- Events: a settled task's event reaches its owner after the task expired, `capabilities.events` advertises `listChanged: false` (nothing pushes catalogue changes), and a backend removed while the gateway was down loses its event subscriptions at the next start.
- audit: the stalled-write test waits on the stall gate instead of a poll budget, so a loaded runner no longer fails it (#2787)
- gateway: the catalogue read arms of meta dispatch are boxed, so a chain step no longer overflows a 2 MiB test thread stack (#2788)
- `/.well-known/oauth-protected-resource` now lists the OIDC issuers of an enabled key server with `delegated_bearer` in `authorization_servers`, so OAuth clients such as ChatGPT can find where to sign in.
- audit: a peer's own `-32001` or `-32004` is no longer recorded as a gateway `denied`: a settled upstream task, and a replay with no stored class, record `error` with the peer's code; a refusal a gateway gate noted, and a replay of one, stay `denied` (#2803)
- capability reload: an edited capability now revokes the in-flight calls that read its earlier definition, as a removed one already did (#2811)
- A capability reload that arrives before the startup scan completes is applied when the scan completes, instead of being dropped from the webhook routes (MIK-7862, #2818).
- **Concurrent calls can no longer overspend a budget.** With cost governance on, the budget check and the spend record were separate steps, so calls (or event deliveries) that ran at the same time could each pass the check against the same remaining allowance and overspend by up to one call's cost per extra caller. An allowed check now reserves its cost until the call settles, so later checks count it. Refusals, reasons and warnings are unchanged when calls do not overlap. (#2823)
- **`cap list` reports a config it cannot load.** A missing or malformed `--config` made `cap list` list readiness against the process environment and exit 0; it now prints the load error and exits non-zero.
- credential substitution is one pass: a secret that contains a placeholder such as `{q}` reaches the provider as written, and a caller value is never expanded. A caller can no longer supply the value of a key a credential rule owns when that credential resolves empty (#2827)
- **The lazy notification channel entry now states what a POST allocates.** Minting a session still allocates the session record; only the notification channel and its buffer wait for a stream to subscribe. A test now covers several streams subscribing to a new session at once. No behaviour change. (MIK-7853)
- capabilities: `sentry_list_issues` takes and sends `limit` (it sent an undocumented `per_page`), `sentry_get_issue` takes its issue ID as a string, both ask for the `event:read` scope only, and the Brave and Tavily output schemas accept the extra fields upstream sends (#2836)
- fix: the EVENTS.8 operator evidence script now fails a run whose subscription named another event or repo, and one whose unsubscribe the gateway did not apply to that subscription (#2838)
- capabilities: `cloudflare_purge_cache` needs exactly one of `purge_everything: true` or `files`, `cloudflare_update_dns_record` needs a field to change, and `cloudflare_get_waf_rules` works without `ruleset_phase` (it defaults to `http_request_firewall_custom`). The schema validator now reads `anyOf` and `oneOf` lists of required parameters on an object schema (#2849)
- A request body field filled from a caller value or a secret is sent as written even when it looks like a placeholder such as `{x}`, and a filled query template that contains literal braces such as `{}` is no longer dropped; a field whose placeholder nothing filled is still left out (#2854)
- Live audit-log verify now reports a high-water-mark hash mismatch at the mark's counter, not after the tail (#2855).
- Repeat suppression of identity grant decision records keys on stable caller fields, so relabelling a subject no longer writes a fresh record (#2857).
- A whole number outside the i64 range (such as 1e20) for a parameter declared `type: integer` is passed on as sent instead of being clamped to the largest or smallest 64-bit integer (#2858)
- `openpencil_design` opens files inside `capabilities.files.projects` (new `root_env` key for `mcp` capabilities), and `cisco_scanner` says why `scan_mcp_server` is held (#2862).
- `gateway_search_tools` publishes an output schema that event rows fit, and `limit` caps tool and event rows together (#2865).
- Adding a server from the registry: an OAuth server added with its login note now closes the form and shows the note as information; a server that needs arguments appended to its command is added disabled with what to append; and an empty `-e VAR=` for a required variable no longer counts as a value, so the server is added disabled until the variable resolves (#2871)
- events: a backend's resource_updated authorization is also refused when the backend leaves the registry while its catalogue lookup waits, as it already was when the backend turned ineligible (MIK-7894)
- The 4.0.0 upgrade notice (item 1) now says every OAuth backend re-authenticates once after the upgrade, and that `accounts migrate-credentials` applies only to backends bound to a personal account: it cannot keep an ordinary `backends.<name>.oauth` credential. 3.x token files are left untouched.
- `gateway_search_tools`, Code Mode search and `gateway_list_tools` now fill a backend's tool cache in the background when it was never filled, so a backend left out of a non-empty `meta_mcp.warm_start`, or one whose warm-start gave up, becomes searchable instead of staying invisible. The first search returns nothing for that backend and later ones match. A backend that is down is not asked once per search: concurrent fills share one `tools/list`, a failed fill holds further fills off for the fill cooldown, and I/O, HTTP and TLS failures, which do not start that cooldown, are bounded by the circuit breaker ([@terafin](https://github.com/terafin), [#3036](https://github.com/MikkoParkkola/mcp-gateway/pull/3036)).
- Add tests that a modern-era backend is searchable without any request to it, and that the meta-tool band matches public_claims.json (MIK-7217).
- Add an end-to-end test that `mcp-gateway upgrade` from 3.x emits the 4.0.0 notice once, stays silent on rerun and leaves the config untouched (MIK-7394).
- **Discovered-config reload tests no longer race for a port.** The tests start the gateway on `server.port: 0` and read the port it logs, and the `/livez` start-up probe has a per-request timeout. Tests only. (MIK-7634, MIK-7656)
- `POST /mcp/{name}/<sub-path>` now answers 404 instead of 500: the sub-path alias of the per-backend route never served, and is removed (MIK-7650).
- Answers on the per-backend route `/mcp/{name}` now write the `response_delivery_attempt` audit record that `POST /mcp` and stdio write. The record has the same fields, carries the read verdict, and withholds the answer under `FailClosed` when it cannot be written (MIK-7669).
- **Release matrix citations are current.** The supported matrix cites the live lines for the modern protocol constant, the `modern_protocol` default and the default protocol version, and the MRTR.7 stdio test header names the production caller of the input bridge. Docs and comments only. (MIK-7723)
- **Windows mutant rows run under pwsh.** The mutants workflow launches its Windows rows from pwsh, as the Windows check does, and a step fails the job if the shell holds an enabled backup or restore privilege, so an ACL-refusal mutant is judged in the same environment as CI. CI harness only. (MIK-7753)
- **A listen names its tasks where the tasks extension puts them.** `subscriptions/listen` reads the task filter from `notifications.taskIds` as well as the params root, as one filter. The ownership narrowing and the direct-route guard cover both placements, and the acknowledgement names the narrowed ids. (MIK-7778)
- Events: governance audit records name the real failure code of a refused verification, take the callback host stamped at fan-out, are labelled subscribe or refresh by the commit itself, and a dead letter the caps evict at once still leaves its record.
- Events: `task.settled` is published for tasks the startup recovery settles, because the task event source is installed before recovery runs instead of after (MIK-7840).
- Events: an attempt ending (revoked or overdue) that the audit log refuses is retried instead of being removed unrecorded; pre-upgrade records are documented as `unrecorded` and an attempt with no body as an empty body hash (MIK-7842).
- Fixed: task shutdown bounds the expiry join and store close, keeps the store open under a task that did not stop, and refuses a task started after the drain (MIK-7844).
- A backend start refused before it could connect (an OAuth and identity-propagation clash, an invalid URL or WebSocket header) no longer makes a later `hardened` registry pairing refuse that backend, and an HTTP start that read its destination policy before a pairing stamped one now refuses instead of connecting unpinned, with its OAuth client built under the same policy as its transport (MIK-7855).
- **An OAuth capability with an expired, unrefreshable or unreadable token is not listed.** `tools/list` and search no longer offer a capability whose login cannot be used. (MIK-7856)
- A provenance receipt's `backend_ok` is now optional and an event receipt carries none, where it used to sign `true` unobserved; scoring abstains on an event receipt (MIK-7859, UPGRADING-4.0 item 140).
- **A confirmation question that never reached the client no longer spends the signing nonce.** Under hardened signing, a destructive call refused because no session could carry its question gives its nonce back, so a retry carries the same nonce. A question that was delivered and then timed out or was cancelled keeps the nonce spent, since the operator may have seen it. (MIK-7869)
- **A server-ended listen names the server.** The terminal `subscriptions/listen` result now carries `io.modelcontextprotocol/serverInfo` in `_meta`, as every other result does. (MIK-7878)
- A startup subscription reconcile that cannot finish now logs a warning on every failed attempt and every 30 s of waiting for the capability scan, so a stalled start names its cause (MIK-7891).
- The EVENTS.8 evidence script now fails a run whose unsubscribe named another subscription than the verified subscribe (another callback URL or arguments), or whose subscribe or unsubscribe was batched with other calls; the dev shim records a digest of each call's event, callback URL and arguments instead of the URL itself (MIK-7892).
- events: authorization of a backend's upstream events now consults the live eligibility check, so a subscription or a queued event for a backend a reload made ineligible is refused at subscribe, fan-out and delivery alike; the delivery worker asks again after the audit waits, just before the send (MIK-7894)
- **A backend's `null` result reaches the client.** A backend that answered with `"result": null`
  over HTTP or WebSocket, or a replayed idempotent answer with a `null` result, reached the client
  as a frame with neither `result` nor `error`, which JSON-RPC 2.0 forbids. The `null` result is
  now delivered as sent; an error response still carries no `result`. Where response signing or
  signature-chain emission applies, a `null` result is refused like any other non-object result.
  (MIK-7924)
- **A call that races a reload can be retried under its idempotency key.** A backend that a reload or
  shutdown had stopped refused the call before sending anything, but the refusal settled the call's
  idempotency key as a failure, so a retry under the same key got that failure back for work that
  never ran. The refusal now frees the key, and a retry reaches the backend that replaced it. This
  refusal now answers `-32001` ("not found") instead of a backend-unavailable error, and is audited as
  `invalid` rather than `error`; it occurs only when a call races a reload or a shutdown. Warm start
  still retries such a backend after a reload. (MIK-7936)
- **A backend's slow tool list no longer delays its other event notices.** When a backend announced a
  tools change, the gateway refilled its cached tool list before handling anything else from that
  backend, so a `tools/list` that hung delayed every other notice on the session (resource and prompt
  changes, resource updates) for up to 30 seconds. The refill now runs alongside the session, which
  keeps delivering other notices; the `tools_changed` event still waits for the refreshed list.
  (MIK-7937)

### Security

- **R2 checks a tool call even when the caller never listed the backend** (F13, MIK-7586,
  #1141). A `tools/call` on a cold catalogue slot now lists that backend's tools once, as the
  caller, before judging the call's argument keys, instead of forwarding it unchecked. Under
  `closed`, a list that cannot be read, a tool outside a truncated list and a tool a complete
  list lacks are refused; `standard` forwards and counts each case. The list is single-flight
  per slot, bounded by the backend's `timeout`, held off for 10 s after a failure, and obeys
  the slot's circuit breaker and rate limiter. A backend that cannot be reached answers, and
  is charged to the error budget, as a failed call to it would. New
  `mcp_input_schema_events_total` kinds; see UPGRADING §59.
- **Secrets stay out of the request URI and its trace.** The HTTP trace span records the method and
  route template, never the full URI, so a session id or a dashboard link value no longer reaches
  DEBUG logs. `/api/costs` takes a session id in the `X-Cost-Session-Id` header (`?session=` is 400),
  and a dashboard link presented from another machine is used up. UPGRADING-4.0 §70. (#1529)

- **The OWASP self-assessment matches the shipped controls.** It had claimed a
  tool-descriptor validator and a grant-collision check that never run on a request, a removed
  SSRF module path, and blocking by controls that are opt-in or observe-only. It now cites
  request-path and config-load controls (plus release-time supply-chain controls for ASI04),
  states which are on by default, adds the 4.0 multi-user controls, uses the 2026 OWASP ASI
  risk names, and reads 2/10 COVERED, 8/10 PARTIAL.
  CI fails when it cites a path or test that no longer exists.
  Withholding poisoned tool descriptors is tracked in #1441.

- **Task calls on `POST /mcp/{name}` are refused instead of forwarded.** The route passed
  `tasks/*` (and `subscriptions/listen` naming `taskIds`) to the backend with no owner check,
  so callers sharing a backend could read or cancel each other's tasks. These methods now
  answer JSON-RPC -32601 and never reach the backend; `POST /mcp` still serves tasks.
  See UPGRADING-4.0 item 67 (#1442).

- **A non-admin call to a callback-registering capability is refused as a denial.** It was
  answered as a configuration error (HTTP 400, JSON-RPC -32603). It is now HTTP 403,
  JSON-RPC -32600, the shape admin-only tools answer with, and logs the "refused by
  authorization" warning. See UPGRADING-4.0 item 66 for when the invocation audit log
  records it.

- **Capability pins cover text after a line break inside the pin line.** The pin hash
  excluded the whole `sha256:` line, but YAML also ends a line at a lone CR, NEL, LS or PS,
  so text after one was parsed yet not hashed. Only the pin value is excluded now; re-pinning
  a pinned CRLF file still verifies. See UPGRADING-4.0 item 64. (#1212)

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
- **Attestation `enforce` covers every method on the direct route (breaking)**
  (MIK-7570.ATTEST.1). `POST /mcp/{name}` now refuses, with -32002 and HTTP 403,
  any forwarded method whose token is missing or does not grant its target:
  `resources/read`, `resources/subscribe` and `resources/unsubscribe` match the
  URI, `prompts/get` the prompt name, list methods need an authentic token, and
  a method outside the table needs a `"*"` token. `initialize`, `ping` and
  notifications are exempt. The check runs before identity minting, and the
  token is stripped before telemetry. A surfaced tool run as a task carries its
  `_meta` token to dispatch. See UPGRADING-4.0 item 46.
- **Container builds apply current Debian security updates.** The image's `apt-get upgrade` layer was restored from the build cache while the base image stayed unchanged, so published images, 3.x included, could ship Debian packages whose security fixes were already available. Every image build now re-runs the upgrade. Operators on a published image move to a 4.0 image; a 3.x deployment that stays on 3.x rebuilds its image from source with `docker build --no-cache`. No config change. (#535)
  Affects: published container images of 2.12.2 up to 3.5.1; the 4.0.0 pre-release images re-ran the upgrade. Operator action: move to a 4.0 image, or rebuild a 3.x image from source with `docker build --no-cache`.
- The key server no longer issues a full-access token for a scope request that misses its policy. From 2.4.0 (the first release with the key server) through 3.5.1, a token request whose requested backends or tools overlapped nothing in the matching policy rule got empty scope lists, and an empty list means "all": the token reached every backend, or every tool. The exchange now answers 403 and issues no token (UPGRADING item 93). Affected: 2.4.0 through 3.5.1, with the key server enabled; 4.0.0-beta.1 and later carry the fix. Action: upgrade. Then, in the key server's audit log, check each issued token whose `backends` or `tools` list is empty against the policy rule that matched: an empty list is expected only where the rule grants everything. Revoke any such token still live with `DELETE /auth/token/{jti}`. (#757)
  Affects: 2.4.0 through 3.5.1 with the key server enabled; the 4.0.0 pre-releases carry the fix. Operator action: check each key-server token issued with an empty backends or tools list against its matched policy rule and revoke any still-live mis-scoped token with DELETE /auth/token/{jti}.
- **Task calls to surfaced tools are confirmed unless the gateway knows they are harmless.**
  The destructive-call confirmation read the shared tool list, which on a backend with
  `identity_propagation` does not describe the caller's session, so a destructive task call
  could run unconfirmed. Such calls are now always confirmed there, and elsewhere whenever the
  tool is missing from the tool list. See UPGRADING-4.0 item 73. (#1623)
  Affects: 4.0.0 pre-releases only; 3.x unaffected. Operator action: a client that makes such task calls authenticates (the confirmation is bound to a caller the gateway can name) and declares the `elicitation` capability, or calls without `task`; otherwise none.
- **Windows checks secret and trust files, and creates them owner-only.** The config file, OAuth token and client files, and generated mTLS certificates and keys are created with one grant to the gateway's account. Those files, and the inputs the gateway only reads (env files, `file:` targets, TLS keys and credential files), are refused on read when another account can read or change them. Trust files (TLS certificate and CRL, identity grants and journal, control-plane grants and policies) may be read by others but are refused when another account can change them. The refusal names every broken rule and prints the PowerShell repair for the file's class. A create on a FAT or exFAT volume, which would discard its ACL, is refused: no secret is written; the empty file is removed, and a refusal that could not remove it says so. A pipe or device is refused as not a regular file. See UPGRADING-4.0 item 99. (#1718)
  Affects: 2.0.0 up to 3.5.1 and the 4.0.0 pre-releases. Operator action: on Windows, run the PowerShell repair printed for any secret or trust file refused at startup (UPGRADING-4.0 item 99), and keep secret files on an NTFS or ReFS volume, since FAT and exFAT keep no ACLs.
- Capability calls, OpenAPI/UI spec imports and capability discovery no longer follow `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`, which let a proxy bypass the gateway's SSRF checks; a new `capabilities.egress_proxy` key names a proxy explicitly (UPGRADING item 77). (#1881)
  Affects: 2.6.0 up to 3.5.1 and the 4.0.0 pre-releases. Operator action: set `capabilities.egress_proxy` (under `security.posture: standard`; `hardened` refuses it) if capability calls must go through a proxy, since `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` no longer apply; a spec import that could only reach its spec through a proxy is downloaded and imported from a file instead (UPGRADING-4.0 item 77).
- A destination the SSRF guard refuses after DNS resolution now answers `-32600 "SSRF blocked: ..."` after one attempt, in every posture, instead of three attempts and `-32000`. Under `security.posture: hardened`, `ssrf_protection` is forced on and `trust_configured_backends` off, and HTTP and WebSocket backends reach only public addresses: names are resolved once and pinned (a WebSocket keeps its SNI and `Host`), IP literals are refused before connecting, proxy environment variables are ignored, and an OAuth backend's authorization server, token and registration endpoints and redirect hops are checked the same way. Upgrade guide item 109. (#1942)
  Affects: the hardened posture is in no released version; the single `-32600` SSRF refusal replaces the retried `-32000` of 3.x and the pre-releases. Operator action: match SSRF refusals on `-32600`; to opt in to the posture, set `security.posture: hardened`.
- **Tools with a poisoned description are withheld.** Every backend tool list is checked with the
  tool-poisoning rule (AX-010). A tool that fails at blocking severity is left out of every list
  the gateway serves and refused by name, for every caller, once any listing has shown it. Each
  withheld description is logged once with a digest; `allow_flagged_tools` serves a reviewed tool,
  pinned to that digest. A tool entry that cannot be parsed is withheld, including every copy of
  a name the backend also lists unparseable; a tool-call notification for a withheld tool is
  refused; past 4,096 withheld names a backend has every tool withheld until restart. The unused
  `detect_collisions` is removed. UPGRADING-4.0 §75. (#1441)
  Affects: 2.0.0 up to 3.5.1 and the 4.0.0 pre-releases. Operator action: read the `Tool withheld` warnings and list any reviewed tool, with its digest, under that backend's `allow_flagged_tools`.
- **CI installs cosign 2.6.5.** The jobs that sign and verify release images and Helm charts
  installed cosign 2.5.2, which is affected by GHSA-fx35-mq7g-6g98 and GHSA-whqx-f9j3-ch6m. A CI
  check now fails any cosign pin below 2.6.5. Verify images with cosign 2.6.5 or later on 2.x, or 3.1.3 or later on 3.x.
  Affects: release-image and Helm-chart signing and verification jobs in CI for 3.x up to 3.5.1 and the 4.0.0 pre-releases; the gateway binary is unaffected. Operator action: verify images and charts with cosign 2.6.5 or later on 2.x, or 3.1.3 or later on 3.x.
- A capability's OAuth token refresh no longer sends the refresh token or client secret to an unchecked `token_endpoint`: the endpoint gets the capability's destination check, and URL-validation errors no longer echo userinfo, query or fragment (UPGRADING item 84). (#2113)
  Affects: 2.5.0 up to 3.5.1 and the 4.0.0 pre-releases. Operator action: if a capability's identity provider is on a private network, name it by hostname and set `capabilities.egress_proxy` to a proxy that reaches it, under `security.posture: standard` (UPGRADING-4.0 item 84); otherwise none.
- The response firewall scans JSON object keys as well as values. A credential-shaped key in a tool result is renamed to `[REDACTED:credential]` (with a `#n` suffix on collision), and one in a question the client must echo refuses the response (UPGRADING item 85). (#2132)
  Affects: 2.6.0 up to 3.5.1 and the 4.0.0 pre-releases. Operator action: if a backend uses credential-shaped strings as object keys, use other key names; clients see such keys renamed (UPGRADING-4.0 item 85); otherwise none.
- **Release jobs build without a cache.** The release verify job and the task SDK recovery
  workflow restored a Rust build cache, so an earlier run's saved output could be built into a
  release. Both now build cold, npm publishing turns setup-node's cache off, and a CI check fails
  any cache restored in a release job.
  Affects: release-gating CI jobs of 2.10.0 up to 3.5.1 and the 4.0.0 pre-releases (verify, and in the pre-releases the task SDK recovery check); the published binaries and crate were built in jobs that restored no cache. Operator action: none.
- **The control-plane store refuses a collection of another format version.** `grants.json` and `policies.json` are read only at the format version this build writes. A file at any other `schema_version` is refused, and the error names the file, the version found and the version supported; a write against it is refused and leaves the file as it is. Before, such a file loaded silently and the next write rewrote it in this build's format, dropping fields this build does not know. (#2142)
  Affects: 3.x up to 3.5.1 and the 4.0.0 pre-releases. Operator action: none.
- **Credential redaction covers overlapping matches.** When two credential patterns matched overlapping text, or one pattern matched twice with an overlap, the redactor could leave part of the credential in the response. Every match is now found in the original text and each overlapping run is replaced once. A credential finding's excerpt in the firewall audit log is the redacted text. (#2145)
  Affects: 2.6.0 up to 3.5.1 and the 4.0.0 pre-releases. Operator action: treat credential-finding excerpts in firewall audit logs written before the upgrade as sensitive.
- `mcp-gateway cap import-url` pins every host name it resolves and refuses one that resolves to a private, loopback or reserved address, in the base URL or a redirect (UPGRADING item 87). (#2160)
  Affects: 2.6.0 up to 3.5.1 and the 4.0.0 pre-releases. Operator action: to build capabilities from an internal API, download its spec and run `mcp-gateway cap import <file>` (UPGRADING-4.0 item 87); otherwise none.
- **Per-backend routes run the same dispatch controls as `gateway_invoke`.** `POST /mcp/{name}`
  `tools/call` skipped the kill switch, capability auto-disable, the session's routing profile,
  cost budgets, the error budget, response gates and a response-firewall Block. Each control now
  exists once and both routes call it; with message signing on, direct `tools/call` is refused outside `security.posture: hardened`.
  See UPGRADING-4.0 item 69. (#2194)
  Affects: 2.4.0 up to 3.5.1 and the 4.0.0 pre-releases. Operator action: move direct `tools/call` callers to `gateway_invoke` where message signing is on outside `security.posture: hardened` (hardened signs direct results).
- **Agent identity rests on proof, not on a label the caller sends.** From 2.10.1 through 3.5.1, with `security.agent_identity.enabled`, a caller's own `X-Agent-ID` header, `agent_id` query parameter or unsigned JWT `agent_id` claim satisfied `require_id` and `known_agents`, so any client could name itself onto the allowlist. Only a proven principal now satisfies them: the mTLS client-certificate subject (first SAN URI, else CN) or the `sub` of an agent token the gateway validated. The unsigned JWT claim is no longer read, and the header or query label is kept for telemetry and cost attribution. A label that differs from the proven principal is refused unless `security.agent_identity.principal_labels` lists it for that principal. Operators who relied on labels move their callers to mTLS or validated agent tokens, or set `security.agent_identity.allow_unverified_agent_identity: true` to let a label satisfy `require_id` and `known_agents` again; `known_agents` entries name their source (UPGRADING-4.0 item 27). With mTLS, a label that differs from the certificate subject is refused the same way; where subjects cannot be compared with short labels, list the source in `security.agent_identity.incomparable_proof_sources` (for example `[mtls]`) to accept and audit the mismatch for that source only. (#684, #692)
  Affects: 2.10.1 up to 3.5.1; the 4.0.0 pre-releases carry the fix. Operator action: move label-identified callers to mTLS or validated agent tokens, or set security.agent_identity.allow_unverified_agent_identity: true; give each known_agents entry its source (UPGRADING-4.0 item 27).
- With context integrity enforcing, a withheld or rewritten result no longer returns the matched injection text in `_context_integrity.classification.findings[].evidence` (it reads `"withheld"`); the gateway log records the original evidence. (#2213)
  Affects: 3.x up to 3.5.1 and the 4.0.0 pre-releases. Operator action: none.
- **Dashboard sessions expire, and logout ends them.** A session opened from the dashboard
  link lasted until the gateway restarted, and a copied cookie kept working. It now ends after
  30 minutes idle or 8 hours total (`auth.dashboard_session`), and the dashboard's own refresh
  does not count as activity. `POST /dashboard/logout` and a Log out button end it on the
  server. `mcp-gateway dashboard-link` prints a fresh single-use link without a restart. See
  UPGRADING-4.0 item 71. (#1618)
  Affects: 3.5.0 up to 3.5.1 and the 4.0.0 pre-releases. Operator action: none; the defaults apply, and `auth.dashboard_session` adjusts the limits.
- A proven identifier (agent JWT `sub`, mTLS SAN URI or CN) is now used verbatim for agent identity, grant subjects and per-caller firewall keys, so a padded subject such as `" admin "` no longer resolves as the principal `admin`, and a SAN longer than 512 characters is no longer truncated onto another certificate's key. Grants and per-caller firewall keys now pick a certificate's subject by the same rule as agent identity (first non-empty SAN URI, else CN).
  Affects: 3.x up to 3.5.1 and the 4.0.0 pre-releases (grant subjects; agent identity from a proven identifier is new in 4.0). Operator action: reissue any credential whose JWT `sub` or certificate subject carries padding, move grants that named a certificate's CN when its first SAN URI is empty and a later SAN URI is not, and write out in full any grant subject that was cut to 512 characters.
- The response firewall no longer refuses about 1 in 20,000 input-required continuations: a continuation token this gateway minted, which still opens under its own keys, is delivered unchanged instead of being read as a credential, while any other string of the same shape is still redacted (#2210).
  Affects: 4.0.0 pre-releases only; 3.x unaffected. Operator action: none.
- **A managed account grant stops serving when its account descriptor changes.** A grant
  connected or migrated under one descriptor kept serving after the operator changed that
  descriptor's scopes or client and restarted. The gateway now compares the grant's stored
  descriptor revision with the configured one before any refresh or release, and asks the
  user to reconnect on a mismatch. Reverting the edit restores the grant. (#2249)
  Affects: 4.0.0 pre-releases only; 3.x unaffected. Operator action: after changing an account descriptor's scopes or client, have each user reconnect that account, or revert the edit.
- **Legacy credential import checks the file's owner, not only its mode.** A 3.x credential
  file that is mode 0600 but owned by another user is refused. Before, a migration run as
  root could import a file another local user had planted as the operator's credential. (#2250)
  Affects: 4.0.0 pre-releases only; 3.x unaffected. Operator action: if a pre-release ran the legacy import as root or with permission to read other users' files (such as `CAP_DAC_READ_SEARCH`), confirm the imported personal accounts are the operator's own; otherwise none.
- **Unix secret and trust files must belong to the gateway's user or root.** A config, env, key, token, credential, certificate, CRL, grants or control-plane file owned by any other account is refused, whatever its mode. The error names the owner uid and the `chown` fix; root-owned Kubernetes projections still load. See UPGRADING-4.0 item 96. (#2266)
  Affects: 2.0.0 up to 3.5.1 and the 4.0.0 pre-releases. Operator action: `chown` each such file to the gateway's uid (`chown 1001` in the container), then `chmod 600` a secret or `chmod go-w` a trust file.
- **A notification on `/mcp/{name}` is refused where its caller's request would be.** Notifications used to fall back to the shared upstream session whenever the caller's credential could not be resolved, so a caller refused on a `required` identity-propagation, passthrough or account-bound backend, or on a gateway-held personal login behind a multi-user gateway, could still deliver `notifications/*` to it. Such a notification now gets `403` and reaches no upstream session; a passthrough refusal is audited as `idp_refuse`. Backends with no personal binding still take notifications on the shared session. (#2240)
  Affects: 3.x up to 3.5.1 and the 4.0.0 pre-releases. Operator action: none.
- **The identity grant CLI writes proven ids as given.** `mcp-gateway identity` trimmed the
  subject id and the `--agent` id, so a grant for a padded certificate or token subject was
  written for the bare id, which is a different principal. Ids are now stored verbatim; empty
  and whitespace-only ids are still refused. (#2284)
  Affects: 4.0.0 pre-releases only, for OIDC subjects (their grant check used the subject verbatim while the CLI trimmed it); 3.x unaffected (it trimmed both). Operator action: re-create with the exact subject any grant written by a pre-release CLI for a padded subject.
- **A bearer token and an API key are two users, even with `auth.single_user`.** A gateway with
  both counted as single-user, so both credentials were served the sole operator's personal
  accounts and the per-user OAuth isolation guard stayed off. The bearer token now counts as a
  credential. See UPGRADING-4.0 item 97. (#2241)
  Affects: 3.x up to 3.5.1 and the 4.0.0 pre-releases. Operator action: a personal gateway that needs to stay single-user keeps one credential, removing either `auth.bearer_token` or the extra API key.
- **A restart no longer launders a cut audit-log tail.** When `.hwm` was missing at startup, the gateway wrote a fresh mark from the surviving tail, so deleting `.hwm`, cutting the tail and restarting made `audit verify` pass. On a log that went through segment handling it now first chains an `audit_segment_hwm_missing` record; live verify fails on it, archive mode warns, and every later segment-open record carries it, so retention cannot erase it. (#2294)
  Affects: no released version. Operator action: none.
- A backend whose transport close never completes no longer stalls grant-reload revocation or the idle reaper: eviction closes each slot's transport in the background, bounded by `close_stage`, and shutdown waits for those closes (#2245).
  Affects: the idle reaper of 3.2.0 up to 3.5.1 and the 4.0.0 pre-releases; the grant-reload eviction of the 4.0.0 pre-releases only. Operator action: none.
- A backend with identity propagation admits at most 64 per-caller slots, and one caller at most 8; every anonymous caller counts as one. A passthrough caller could mint a new slot, with its own upstream connection, for each header value it sent. Past a limit the caller is refused (`mcp_backend_identity_slots_refused_total`), never served on the shared slot. Metadata probes no longer create slots (#2300).
  Affects: 3.2.0 up to 3.5.1 and the 4.0.0 pre-releases. Operator action: with auth off, expect at most 8 passthrough credentials served at once per backend; turn auth on to give each user their own budget (UPGRADING-4.0 item 102).
- At most 64 closes of evicted slots run at once per backend. A close that finds no free permit, or runs out of its `close_stage` budget is dropped and counted in `mcp_backend_eviction_close_abandoned_total` (#2300).
  Affects: no released version. Operator action: none.
- **A notification on `/mcp/{name}` carries its caller's credential, never the backend's static one.** A direct-route notification kept only the caller's session and went out under the backend's configured static headers. On a required-passthrough backend, any non-empty `x-mcp-passthrough-authorization` could deliver notifications under the gateway's own credential. Notifications now carry the resolved passthrough or minted credential with the same override rule as requests. They are refused when the transport cannot carry it, and forwarding one is audited as `idp_mint`. A caller header value that cannot be sent now withholds the static header of that name on requests and notifications alike. (#2292)
  Affects: 3.x up to 3.5.1 and the 4.0.0 pre-releases. Operator action: none.
- **A response-firewall Block on a tool listing or a task result is now refused, never served.** The direct route (`/mcp/{name}` `tools/list`) logged a blocking verdict and served the list; `gateway_list_tools` and `gateway_search_tools` redacted a blocked list and served it as a success; task results passed no firewall at all. The listing tools are now inspected on their raw value before it is serialised (so a quoted key or a split injection phrase is still seen), task results at settlement, and a Block answers with the JSON-RPC -32600 refusal; a task settles on that refusal, so `tasks/get` never serves the result. A list with any blocking finding (by default, credential material in a tool description) is refused whole. (#2349, #2350, #2351)
  Affects: 2.6.0 up to 3.5.1 and the 4.0.0 pre-releases (the task-result path: the pre-releases only). Operator action: none; a backend whose tool listing is now refused needs the flagged description fixed at the backend.
- `security.signature_chain`: the gateway can sign an origin link over each backend result, and a signature chain sent by a backend is now stripped (#2381).
  Affects: no released version (no release gave the chain key a meaning). Operator action: none unless a client trusted a chain a backend sent; to have the gateway sign origin links, set `security.signature_chain` (UPGRADING-4.0 item 82).
- **`dashboard-link` no longer echoes URL credentials.** A `--url` carrying userinfo or a query token was printed back in its error messages, along with the request URL inside the transport error. Errors now show only scheme, host and port. (#2394)
  Affects: no released version. Operator action: none.
- Every call to a personal capability now writes an `identity_grant_decision` record to the audit log for each grant decision, allow and deny, paired with the call by `trace_id`; under `FailClosed` a record that cannot be written answers `-32005` (MIK-7570.AUDIT.3).
  Affects: 3.x up to 3.5.1 and the 4.0.0 pre-releases. Operator action: where a SIEM rule or script counts audit records per call, filter on `kind` (UPGRADING-4.0 item 103); otherwise none.
- Security counters: `mcp_auth_failures_total{kind}` counts refused credentials (missing, invalid, expired API key, expired dashboard session, refused bootstrap link, token-exchange refusals) and `mcp_authz_denials_total{route, reason}` counts refused calls on the meta, direct, admin, admin-UI and control-plane routes, with auth on or off. Labels are fixed words and never name a caller, backend, tool or path. `docs/MULTI_USER.md` has example alerts. (MIK-7570.METRICS.2, #2401)
  Affects: no released version. Operator action: none; example alerts are in docs/MULTI_USER.md.
- A streaming session now belongs to the caller's proven subject and the credential it presented, not the credential alone. Two agents behind one shared API key, or two callers with authentication off, could resume and delete each other's sessions and read each other's notifications by presenting the session id. Now a different subject, or the same subject with another credential, gets a new session; POST, GET and DELETE apply one rule. Callers that prove no subject keep the old behaviour. (#2411)
  Affects: 2.0.1 up to 3.5.1 and the 4.0.0 pre-releases. Operator action: a client that proves a subject and renews its bearer token mid-session re-initializes with the new token and uses the new `Mcp-Session-Id` (UPGRADING-4.0 item 104); otherwise none.
- **A tool blocked after a keyed call is refused on the re-issue.** A tool withheld by the tool-poisoning check (AX-010) after a caller's first keyed call used to be answered from the idempotency cache when the caller repeated the key. The block is now checked before any replay on `/mcp`, `/mcp/{name}` and stdio. On `/mcp/{name}` the whole security gate (tool policy, per-tool scope, firewall) now runs before the cache, so a replayed call also counts toward firewall budgets. (#2445)
  Affects: 4.0.0 pre-releases only (their `/mcp/{name}` route answered a repeated key from the cache before the security gate; the AX-010 withholding itself is new in 4.0.0); 3.x unaffected. Operator action: none.
- A cost report covers only the caller's own spend. A request without a session (the 2026-07-28 protocol) opens no per-session cost bucket and gets no session report; per-key accounting and budgets are unchanged, and admins still see every key. A prompt cache key is derived only from a real session. (#2448)
  Affects: 4.0.0 pre-releases only; 3.x unaffected. Operator action: none.
- **A repeated task call and `tasks/get` are checked against current policy.** A task-augmented `tools/call` repeated with the same idempotency key and body, and `tasks/get` on a finished task, used to return the stored result without the invocation policy (identity grants, attestation, kill switch, capability disable, profile, withheld tools). Both now re-check the calls that produced the result first, on every repeat or read; a fresh task is still checked by its worker. A read of a finished task whose target is a personal capability also writes an `identity_grant_decision` audit record (an unchanged decision is usually suppressed for 10 minutes), so a SIEM rule counting decision records per call sees more for polled tasks (`docs/UPGRADING-4.0.md` items 105 and 117). Task records name those calls (record version 5); see `docs/UPGRADING-4.0.md` item 105 for rollback. (#2450)
  Affects: 4.0.0 pre-releases only; 3.x unaffected. Operator action: back up `tasks.store_dir` before upgrading if a rollback to a pre-release may be needed; under attestation `enforce`, a client reading a finished task sends a fresh token in `_meta["io.mcp-gateway/recovery"].attestation`.
- **The `-full` image no longer ships npm's vulnerable `brace-expansion` and `undici`.**
  The image's Trivy gate flagged brace-expansion 5.0.9 (CVE-2026-102276, CVE-2026-102278) and
  undici 6.27.0 (CVE-2026-19534) inside npm's vendored tree. Both are now overlaid with
  hash-pinned brace-expansion 5.0.12 and undici 6.29.0, the latest releases on the same majors.
  Affects: the `-full` image of the 4.0.0 pre-releases; 3.x unaffected (it had no `-full` image). Operator action: none.
- **A task waiting for input faces current policy before its pending requests are shown.** `tasks/get` and a repeated task-augmented call re-authorize the task's recorded calls before returning an `input_required` task, as they already did for a finished task's result. Once a tool is withheld, a grant revoked or a backend disabled, the backend's pending input requests are no longer delivered. The task itself is left unchanged, and it can be read and answered again once policy admits its calls. (#2466)
  Affects: 4.0.0 pre-releases only; 3.x unaffected. Operator action: none.
- On `/mcp/{name}`, a presented `mcp-session-id` is used only when the caller owns that session, by the same owner rule `/mcp` uses; otherwise the call runs with no session. (#2468)
  Affects: no released version. Operator action: none.
- A backend can verify or require an upstream gateway's signature chain; this gateway preserves it and appends its own link, so a client can verify every hop (#2483).
  Affects: no released version. Operator action: none; to opt in, set a backend's `signature_chain` to `verify` or `require`.
- Under `security.posture: hardened`, a set `capabilities.egress_proxy` refuses load: capability traffic through a proxy would bypass the destination policy. `standard` keeps the proxy. (#2491)
  Affects: no released version. Operator action: under `security.posture: hardened`, remove `capabilities.egress_proxy` or keep `security.posture: standard`; otherwise none.
- Keyed legacy `gateway_set_state` retries are now bound to the calling session, preventing one session of a principal from replaying another session's retained result when they reuse an idempotency key ([@blackmore-technology-group](https://github.com/blackmore-technology-group), [#2670](https://github.com/MikkoParkkola/mcp-gateway/pull/2670), fixes [#2505](https://github.com/MikkoParkkola/mcp-gateway/issues/2505)).
  Affects: 4.0.0 pre-releases only; 3.x unaffected. Operator action: none.
- Under `security.posture: hardened`, message signing is forced on, so a start without a signing secret of at least 32 bytes is refused, and every successful `tools/call` result on `/mcp` and on `/mcp/{backend}` carries the v2 `_signature` over the nonce in `params._meta["io.mcp-gateway/nonce"]`, admitted once before dispatch in one replay store for both routes. A legacy client must declare elicitation: only an `initialize` that declares it opens a session on `/mcp`, the direct route serves no other legacy request, and a legacy destructive call nobody can confirm is refused. A reload that changes the posture is now refused with the posture's own reason. Upgrade guide item 112. (#1942, #2544)
  Affects: no released version. Operator action: under `security.posture: hardened`, set `security.message_signing.shared_secret` to at least 32 bytes, send one fresh nonce per `tools/call`, and make legacy clients declare elicitation on `/mcp`, or move them to 2026-07-28; on `/mcp/{backend}` a legacy client gets only its `initialize`, so it moves to 2026-07-28 (Upgrade guide item 112).
- Under `security.posture: hardened`, backends named in the new `security.hardened.private_backends` may reach loopback, RFC 1918 and unique-local addresses, by literal, by pinned name, through redirects and OAuth endpoints; link-local (including 169.254.169.254) and the AWS IPv6 metadata address `fd00:ec2::254` stay refused for every backend, and unlisted backends stay public-only. A listed name that is not a configured backend refuses start, and the list is restart-only. Upgrade guide item 114. (#1942, #2559)
  Affects: no released version. Operator action: under `security.posture: hardened`, list each backend that must reach a private address in `security.hardened.private_backends` and restart; otherwise none.
- **Key-server OIDC URLs must be HTTPS off this machine.** A `key_server.oidc` issuer,
  `jwks_uri` or `discovery_url` that is `http://` to a non-loopback host refuses to start, and
  a token naming such an issuer is refused; before, the issuer only logged a warning. The key and
  discovery fetches already refused `http://` URLs and redirects to `http://`, so the warning did
  not open a cleartext key swap. Loopback `http://` is allowed and now works.
  See UPGRADING-4.0 item 116. (#2590)
  Affects: 2.4.0 through 3.5.1 and the 4.0.0 pre-releases, as a warning only (no cleartext key swap was reachable). Operator action: use `https://` for every `key_server.oidc` URL, or a loopback host for local testing.
- With `tenant_guard.arg_keys` set, an invocation record is marked `attribution: "uninspected"` whenever any JSON-shaped part of the response could not be parsed (too deep, malformed, or encoded past three layers); JSON carried inside strings, double-encoded text included, is now read for tenants.
  Affects: no released version. Operator action: none.
- **A hardened pairing refuses backends that connected unpinned.** An embedder that started an
  HTTP or WebSocket backend before pairing its registry with a hardened config kept a connection
  with no SSRF pin. `ReloadContext::new` (and registering such a backend into a hardened
  registry) now refuses, naming the backend; a start racing the pairing is refused when it
  publishes. The shipped binary pairs before any backend starts and is unaffected. (#2597)
  Affects: no released version. Operator action: none.
- **The OAuth authorization code is no longer logged.** The gateway wrote the authorization code it received on the OAuth callback to the debug log (`Received authorization code`). Releases since v2.0.1, v3.5.1 included, did this; anyone running with debug logging enabled may have authorization codes in stored logs. A code is single-use and short-lived, and PKCE binds it to its verifier, but it is still a credential. (MIK-7725)
  Affects: 2.0.1 through 3.5.1 and the 4.0.0 pre-releases. Operator action: delete or restrict access to stored debug logs that may contain `Received authorization code` entries.
- **OIDC refusals no longer echo the issuer.** A load-time refusal names only the issuer's
  origin, and a token refused for a cleartext issuer carries no part of it, so userinfo, a
  tenant path or a query never reaches logs or support threads. (#2615)
  Affects: no released version. Operator action: none.
- An audit replay after a failed fail-closed invocation record no longer records the withheld value as delivered (MIK-7718).
  Affects: no released version. Operator action: none.
- A finished task polled with an unchanged grant decision writes one decision record per 10 minutes instead of one per poll, except after a restart, or for a new key once 4,096 live keys are tracked; a changed decision is written at once (MIK-7692).
  Affects: no released version. Operator action: none.
- An audit log cut below its signed high-water mark, or interrupted between the torn-tail repair and the missing-mark marker, keeps the finding; verify checks the hash at the mark (MIK-7712).
  Affects: no released version. Operator action: none.
- **A task stored before targets were recorded is re-checked or refused.** Such a row (written
  by a 4.0.0 beta) recorded no call targets. Its one call is recovered from its upstream
  descriptor when it has a consistent one, and `tasks/get` and a repeated keyed call check that
  call against current policy. A legacy row without recoverable provenance, including a legacy plan, is
  refused `-32003` rather than judged by its backend alone when it would deliver backend output (a
  finished result or pending input requests); a working or cancelled one delivers none and is
  answered as before. (#2620)
  Affects: 4.0.0 pre-releases only; 3.x unaffected. Operator action: re-run a refused call under a new idempotency key, after checking whether its first run already had an external effect (UPGRADING-4.0 item 120); otherwise none.
- **Passthrough slot budgets key on the credential.** Two OAuth agents or two client
  certificates that share a display name no longer share one passthrough slot budget. (#2622)
  Affects: no released version. Operator action: none.
- **A firewall-refused direct `tools/list` is not a client success.** It no longer resets the
  caller's consecutive-failure count. (#2622)
  Affects: no released version. Operator action: none.
- **The handed-back input round counts against the request budget.** A last round that would
  take a bridged call past `BridgeBounds::requests` is refused instead of handed back. (#2622)
  Affects: no released version. Operator action: none.
- **`gateway_list_servers` counts a `required` account backend only for a caller with a view.**
  A caller whose stored grant is missing, unusable or fenced by a changed descriptor (the sole
  operator included) now sees `tools_count` 0 and `tools_known` false instead of the shared
  slot's count. The grant is read without refreshing or minting. (#2631)
  Affects: 4.0.0 pre-releases only; 3.x unaffected. Operator action: none.
- **The relay detector respects time order.** A copy delivered after an egress no longer
  excuses that egress or counts as evidence against it, when concurrent calls reach the
  detector out of order. (#2633)
  Affects: no released version. Operator action: none.
- **A refused OAuth redirect is reported as SSRF blocked.** A redirect hop the destination
  policy refuses during OAuth discovery, token or registration requests now answers
  `-32600 SSRF blocked` instead of a generic OAuth failure, so a policy refusal is told apart
  from an unreachable authorization server. (#2637)
  Affects: no released version. Operator action: none.
- **Cross-tenant reads are checked on every frame a caller receives.** With
  `tenant_guard.arg_keys` set, results, errors, notifications, server requests and webhook deliveries
  are judged against one per-process read history keyed on the caller. A caller whose
  frames name more than one tenant inside `window_secs` is marked `cross_tenant_read: flagged`;
  the new `tenant_guard.cross_tenant_reads` key takes `off|observe|block` and defaults to
  `observe`. (MIK-7116 MIN.2)
  Affects: 4.0.0 pre-releases only; 3.x unaffected. Operator action: none; set `security.firewall.tenant_guard.cross_tenant_reads: block` to refuse flagged callers instead of observing them.
- **A refused call no longer spends its hardened signing nonce.** Under `security.posture: hardened`,
  a meta tool call refused before the tool acts (hidden tool, answers to no question, admin-only,
  destructive with no way to ask) and a direct call refused by its idempotency key leave the nonce
  for the retry. The in-band confirmation challenge still spends it. (#2675)
  Affects: no released version. Operator action: none.
- **An agent-only or certificate-only caller can use idempotency keys.** A keyed `tools/call` from a
  caller proven only by an OAuth agent token or a client certificate is owned by that proven
  subject (the agent's client id; the certificate's SAN URI, else its CN) instead of being refused
  `-32003`. Callers with a credential keep their existing keys. (#2692)
  Affects: 4.0.0 pre-releases only; 3.x unaffected. Operator action: none.
- MCP Events re-checks a subscription's credential before every delivery: a revoked key-server token, a delegated bearer no longer granted, a rotated static bearer or a logged-out dashboard session stops delivery at the next attempt (#2695).
  Affects: no released version. Operator action: none.
- **No delivered error data or task envelope claims a `cacheScope` other than `private`.** Error
  data and the retained result of a task envelope whose `taskId` is not a string are clamped like
  results; nested tool data is untouched. (#2702)
  Affects: 4.0.0 pre-releases only; 3.x unaffected. Operator action: none.
- A capability argument such as `{env.NAME}` is no longer expanded to the gateway's own secret: references are resolved in the capability template before caller values are substituted (MIK-7787).
  Affects: 2.0.1 up to 3.5.1 and the 4.0.0 pre-releases (`{keychain.*}` from 2.1.0). Operator action: where untrusted callers could call capabilities, rotate every secret the gateway process can read through `{env.*}` or `{keychain.*}`, including ones no capability template referenced.
- security: relay detection gains an `allowed_flows` allowlist under `security.firewall.collusion` (up to 64 `{source, egress}` `server:tool` glob pairs; a matching flow is not reported or refused) and the counters `mcp_gateway_collusion_relay_total{action}` and `mcp_gateway_collusion_unkeyed_egress_total{action}` (#2731)
  Affects: no released version. Operator action: none.
- security: verbatim relay detection records a stdio receipt only after the answer passed the cross-tenant read judge and the audit write, so a withheld read leaves no receipt (#2748)
  Affects: no released version. Operator action: none.
- MIK-7116 MIN.2 typing: every handler on an MCP path returns a sealed `OutboundReply` naming its origin (judged answer, judged stream, gateway refusal); a source test pins the registered handlers.
  Affects: no released version. Operator action: none.
- MIK-7116 MIN.4: a fixture corpus of outbound frames measures the cross-tenant read verdict per principal-session (test only).
  Affects: no released version; test-only change. Operator action: none.
- security: verbatim relay detection records a direct-route receipt only after the answer passed the read judge, the fail-closed audit write and the read record, so a withheld read leaves no receipt (#2757)
  Affects: no released version. Operator action: none.
- security: verbatim relay detection records a meta HTTP receipt only after the grant slot and the read record have let the answer go out, so an answer either replaces leaves no receipt (#2768)
  Affects: no released version. Operator action: none.
- security: verbatim relay detection now covers `prompts/get` arguments, `resources/read` URIs and the results of both on the meta, direct and stdio routes, keyed as `tools/call` is; the stdio catalogue is the local operator (#2771)
  Affects: no released version. Operator action: none.
- The direct route decides credential resolution and the OAuth-isolation guard on the backend it captured, not a by-name lookup a reload can swap (MIK-7804). (#2772)
  Affects: 3.0.0 up to 3.5.1 and the 4.0.0 pre-releases. Operator action: none.
- Test: a block-mode test proves the audit entries for the read and the block of a cross-tenant read (MIK-7116 MIN.2 grading).
  Affects: no released version; test-only change. Operator action: none.
- **The default process list no longer admits `mcp-scanner remote`.** No shipped capability runs it, and the tool cannot refuse private addresses at connect time, so an operator-pinned capability using it would have run unguarded. List it under `capabilities.process_commands` to opt in; setting that key replaces the shipped list. See UPGRADING-4.0 item 135. (#2801)
  Affects: no released version. Operator action: none.
- relay: catalogue reads (prompts and resources) audit the caller's own session, answer a relay refusal with HTTP 403 on the meta route (was 200), record receipts in the delivered form, keep the context-integrity verdict of string and array results, skip classification with relay detection off, and the direct route's relay scan skips the substituted progress token (#2810)
  Affects: no released version. Operator action: a client that reads the HTTP status of a meta-route catalogue read handles 403 as a refusal and reads the JSON-RPC error from the body (UPGRADING-4.0 item 139); otherwise none.
- cli and mcp capability results no longer carry a credential the gateway injected into the child; see UPGRADING item 141 (#2819)
  Affects: no released version. Operator action: a capability whose tool must return an injected value reads it from its own source instead; a client comparing results byte for byte expects `[redacted]` there (UPGRADING-4.0 item 141); otherwise none.
- security: the cross-tenant read judge scans the document that is emitted: a configured `arg_keys` name equal to a wrapper member (`message`, `method`, `source`, `event_id`) now attributes, for responses, notifications and non-message stream events (#2846)
  Affects: no released version. Operator action: none.
- The daily cost budget no longer loses spend recorded at the UTC day boundary: the reset and every add are serialized (#2856).
  Affects: 2.6.0 up to 3.5.1 and the 4.0.0 pre-releases. Operator action: none.
- An audit-log restart now checks the record the high-water mark names even when it is the newest record, so an edit made under its stored hash or a forged signature there is recorded as a finding instead of carried forward (MIK-7884).
  Affects: no released version. Operator action: none.
- A prompt a backend sends through the gateway to the client is delivered and recorded in the same form: a backend copy of the reserved signature-chain member is dropped from both, so the relay receipt and audit record describe the bytes sent, and the firewall judges the prompt as the client receives it (MIK-7910).
  Affects: no released version. Operator action: none.
- relay detection: a bridged prompt is receipted only once it reached the client, so no session or a send cancelled first leaves no receipt, and an answer's receipt is built from what the caller finally receives (MIK-7887)
  Affects: no released version; relay detection first landed after v4.0.0-beta.2. Operator action: none.
- relay detection: a followed upstream task's failure is receipted at settlement only when it is the peer's own error, unchanged by every screen and by the audit; gateway errors, substitutes and errors of unknown author on older rows are never receipted (MIK-7887)
  Affects: no released version; relay detection on task routes first landed after v4.0.0-beta.2. Operator action: back up `tasks.store_dir` before upgrading if a rollback to a build that reads task records only up to version 5 may be needed (UPGRADING-4.0 item 105).
- relay detection: a change to a plan's answer keeps each step's receipt for the text the caller still got, a plan receipt is never rebuilt from engine-written text, and no receipt fingerprint crosses a cap cut or a removed leaf (MIK-7887)
  Affects: no released version; relay detection first landed after v4.0.0-beta.2. Operator action: none.
- The release procedure now cosign-signs the published Helm chart by its OCI digest and verifies the signature against a pinned signer identity and issuer before the publish counts as passed; before, the chart was pushed unsigned (RFC-0133 HELM.6).
  Affects: no released version; the chart is first published with 4.0.0. Operator action: verify the chart before installing with cosign verify against the chart digest reference, using the chart reference, signer identity and issuer published on the v4.0.0 GitHub release.
- An audit-log restart now records a finding when the active file ends on the high-water mark's own record but opens an older segment than the mark names, as a file rebuilt from an older sealed segment plus genuine later records does; before, it resumed as the older segment and the next rotation overwrote that sealed segment with nothing recorded.
  Affects: no released version. Operator action: none.
- a credential a cli or mcp capability child printed but the gateway never injected now reaches the response firewall whole, so it raises a finding, a Block and an audit entry instead of passing as a bare marker; see UPGRADING item 141 (#2993)
  Affects: no released version; 4.0 pre-release builds that include #2697 or #2819. Operator action: none with the default firewall settings; with the firewall or credential_redaction off, such a value in a cli or mcp result or error excerpt now reaches the caller unchanged, as a REST capability result already does, so turn the firewall on to have it redacted.
- the warning logged when a tool result does not match its declared output schema no longer quotes the result: it names each violation's path and its expected and actual type, and an undeclared key only as "undeclared key", since a value or key there can be a credential and the log is written before the response firewall runs (#2993)
  Affects: 3.5.1 and the 4.0 betas, for any capability with an output schema whose result breaks it. Operator action: treat gateway logs from those versions that contain "did not match its declared output schema" as possibly holding backend-returned secrets; a log pipeline that parsed the old mismatch text sees the new path-and-type form.
- An audit-log restart no longer renames an active file that ends in a seal record onto a segment that is already sealed; such a file is a copy, not an interrupted rotation, and is now recorded as a finding and sealed under a fresh name instead of replacing the genuine segment, and a restart refuses a sealed segment numbered at the last value instead of sealing onto it (MIK-7949).
  Affects: no released version. Operator action: none.
- the MCP events fail-fast harness (`scripts/dev/mcp_events_failfast.py`) now refuses to deliver a signed webhook over TLS below 1.2, instead of leaving the floor to the host's OpenSSL policy (#3003)
  Affects: the developer harness only, never the shipped gateway or its packages. Operator action: none.
- an `http://` backend on a loopback host is no longer sent through `HTTP_PROXY`/`ALL_PROXY` from the environment: cleartext to loopback, an OAuth bearer included, is allowed only because it never leaves the machine, and a proxy carried it off in cleartext (#3007)
  Affects: 2.0.0 through 3.5.1 and the 4.0 betas, for OAuth or static credentials on an `http://localhost`/`127.0.0.1`/`[::1]` backend, run with a proxy variable set and no `NO_PROXY` entry for that host. Operator action: none to upgrade; if such a gateway ran with a remote proxy configured, treat the loopback backend's bearer tokens as exposed to that proxy and rotate them.
- A direct-route delivery audit record now takes its outcome from the HTTP status as well as the body, so a notification refused with 403 or 429 is no longer recorded as delivered (`ok`); it matches the call's invocation record. A delivered answer with `result.isError: true` is now recorded as a tool error there too, not as `ok`.
  Affects: no released version. Operator action: none.
- An audit-log restart that repairs a torn line above the high-water mark now records the loss from the first dropped counter, not from the mark, so the full range of lost committed records stays on record after retention removes the segment that showed the gap.
  Affects: no released version. Operator action: none.
- an OAuth backend no longer sends its client secret, authorization code or refresh token over cleartext `http://` to a host off this machine. The authorization server and the authorization, token and registration endpoints that discovery returns, and every redirect from an OAuth request, must be `https://` or `http://` on a loopback host, under every destination policy. A loopback `http://` authorization server is reached directly, never through `HTTP_PROXY`/`ALL_PROXY`. A capability that sends a credential (`auth.required`) is held to the same rule: at load for a literal `base_url`/`endpoint`, and at send time for REST, GraphQL, JSON-RPC and its OAuth refresh; a capability request that started on TLS or loopback follows no redirect to cleartext off this machine, and a loopback one bypasses `capabilities.egress_proxy` (#3013)
  Affects: 2.0.1 through 3.5.1 and the 4.0 betas, for OAuth backends whose authorization server or its advertised endpoints are `http://` off this machine, and for capabilities with `auth.required: true` whose API URL is `http://` off this machine; also any capability (with or without a credential) whose request is redirected from `https://` or loopback to `http://` off this machine, or that targets loopback with `capabilities.egress_proxy` set. Operator action: such a backend now fails at connect, and such a capability file now fails to load (the warning names `providers.<name>.config.base_url` or `endpoint`). Move it to `https://`, or serve it on a loopback host (`localhost`, `127.0.0.1`, `[::1]`; `localhost.` with a trailing dot is not loopback). `allow_cleartext_credentials` does not cover either. If one ran over cleartext before, rotate the client secrets, refresh tokens and API keys it sent. A capability that relied on such a redirect now fails the call; a loopback capability now bypasses the egress proxy. A secret placed directly in a header or param template of a capability with `auth.required: false` is not yet covered (MIK-7958, 4.0.1). See UPGRADING-4.0 item 146.
- `serve --stdio` now exits even when its client stopped reading stdout: once the session has ended, the runtime waits at most 10 s for a stuck stdout write instead of hanging the process (MIK-7683).
  Affects: 3.x and earlier stdio mode. Operator action: none.
- A stdio client that stops reading stdout can no longer wedge the gateway with batches or malformed lines: the reader keeps reading, so EOF and cancels are still handled and the session ends within its drain deadline (MIK-7684).
  Affects: 3.x and earlier stdio mode. Operator action: none.
- Under the `standard` posture, a `gateway_invoke` that the caller is not allowed to make now gets its policy refusal even when it carries a malformed signing nonce, and no nonce rejection is counted for it; the nonce is judged after the invocation policy, as `UPGRADING-4.0.md` now states (MIK-7736).
  Affects: no released version. Operator action: none.
- Security: attestation tokens carry a required `audience` claim and a gateway accepts only its own; `enforce` needs `GATEWAY_ATTESTATION_AUDIENCE` (MIK-7795).
  Affects: 3.x up to 3.5.1 and the 4.0.0 pre-releases. Operator action: set `GATEWAY_ATTESTATION_AUDIENCE` on each gateway running attestation in `enforce` mode and mint tokens with that audience.
- Security: `gateway_invoke` judges and dispatches a call on the backend it captured, not a by-name lookup a reload can swap (MIK-7810).
  Affects: 3.x up to 3.5.1 and the 4.0.0 pre-releases. Operator action: none.
- **Only the capability loader can mark a definition pinned.** A program built on the crate could
  set `ProvidersConfig::integrity` to `Verified` on a definition it built, so a `cli` or `mcp`
  process provider ran without the `sha256:` pin check. `process` and `integrity` are now
  crate-private, read through `process()` and `integrity()`, and a process runs only while the
  definition matches the fingerprint taken when its pin was checked, so a verified definition
  copied and edited is refused. The response cache of a process provider keys on that fingerprint, and replacing a
  definition through `register_capability` stops its `mcp` children. See UPGRADING-4.0 item 144.
  (MIK-7814)
  Affects: no released version. Operator action: none; an embedder that read the fields calls the getters, and one that edits a loaded definition loads the edited one through the capability loader.
- **A `message` webhook's top-level `id` is judged as content by the cross-tenant read check.** The session-stream judge skips a `message` document's top-level `id` as JSON-RPC framing, and a webhook body was judged only on its raw form, so a `data` mapping that wrote another tenant's identifier into `id` reached the caller unflagged and, under `cross_tenant_reads: block`, unwithheld. The written `id` is now judged with its member name (MIK-7822).
  Affects: deployments with `tenant_guard.cross_tenant_reads` on, `id` listed in `tenant_guard.arg_keys`, and a webhook with `transform.event_type: message` whose `transform.data` maps a field into `id`.
  Operator action: none; upgrade. To check exposure before upgrading, look for `id` in `arg_keys` alongside such a webhook mapping.
- audit log: a restart no longer advances `.hwm` over a tail that contradicts it. A tail behind the mark in any segment (an older active file restored) or a record at the mark replaced by another is now recorded as a loss and the counters are never reused, in signed and unsigned logs (MIK-7884)
  Affects: no released version. Operator action: none.
- Security: a direct-route notification is charged to its credential, not its display label, so two keys with one label no longer share a notification budget (MIK-7885).
  Affects: no released version. Operator action: none.
- relay detection: receipts follow the delivered result. A redaction rebuilds the call's receipt from what goes out and keeps its sensitivity verdict, reading a failed task receipts the backend's error, and a stdio answer whose result is null delivers a result; the known limits are stated in the design doc (MIK-7887)
  Affects: no released version. Operator action: none.
- events: a static-bearer subscription is re-checked against the full SHA-256 of the bearer, not the 12-hex log fingerprint; older rows keep the fingerprint check (MIK-7889)
  Affects: no released version. Operator action: none.
- tasks: a stored task row older than the upstream-descriptor version no longer yields backend targets from a descriptor it could not have captured (MIK-7889)
  Affects: no released version. Operator action: none.
- capabilities: an MCP capability reload revokes under the lock that admits a call, so it cannot land between the epoch check and the lease; the path-confinement swap residual is stated for every root (MIK-7889)
  Affects: no released version. Operator action: none.
- The MCP events OAuth dev shim marks its token and registration answers no-store and refuses an oversize request body before reading it, and the EVENTS.8 run script empties its directory only when that directory's state.json names the script as its owner (MIK-7893).
  Affects: no released version. Operator action: none.
- events: a backend that becomes ineligible for upstream events after a reload stops delivering them: the listener rechecks eligibility at every delivery and reconnect, ends, and its upstream subscriptions are withdrawn; a tools notice also clears the resend-permitted set (MIK-7894)
  Affects: no released version. Operator action: none.
- The HTTP events listener no longer repeats the request URL, which can carry credentials in its query, in its error messages (MIK-7895).
  Affects: no released version. Operator action: none.
- A successful `cli` or `mcp` result no longer leaks an injected all-digit credential with
  leading zeros when the child prints it as a JSON number, which drops the zeros (`012345`
  came back as `12345`): numbers are now compared to such a credential by value as well as by
  text, with the sign ignored, and a credential past u64 is parsed by the same JSON parser that
  read the result, so both sides round alike. See UPGRADING-4.0 item 141. (MIK-7908)
  Affects: 4.0.0 pre-releases only; 3.x has no injected-value scrubbing (its firewall credential redaction is pattern-based and unchanged). Operator action: none.
- audit: on stdio, the `response_delivery_attempt` record is now written after the cross-tenant read judge, over the frame the client receives. A refused read is recorded as the refusal, and its read verdict rides that one record instead of a separate `tenant_read` event, as on `POST /mcp` and `/mcp/{name}` (MIK-7920).
  Affects: no released version; the cross-tenant read judge first landed after v4.0.0-beta.2. Operator action: none; a SIEM rule that reads stdio answers from `event: tenant_read` reads the same fields on `response_delivery_attempt` instead: `tenants` or `attribution` to count reads, `cross_tenant_read` to flag one (UPGRADING-4.0 item 130).
- A successful `cli` or `mcp` result no longer leaks an injected credential written in another
  number form, such as `+12345` or `1.5e10`, when the child prints it as a JSON number
  (`12345`, `15000000000.0`): such a credential is now compared to numbers by value. Any number
  equal in value to it is redacted, even one printed for another reason. Credentials shorter
  than 4 characters as injected (for example `1e5`) are still not looked for in numbers.
  (MIK-7954)
  Affects: 4.0.0 pre-releases only; 3.x has no injected-value scrubbing. Operator action: none.

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

### Removed

- Removed the `session_sandbox` and `tunnel` modules. No configuration key reached
  either: nothing constructed a `SandboxEnforcer` outside its own tests and a
  benchmark, and there is no `tunnel:` section (a config that has one already
  fails the load as an unread key). The `session_sandbox/*` benchmark group goes
  with them. Also removed `src/gateway/ui/costs.rs`, a second `/ui/api/costs`
  handler that no module declared, so it was never compiled.

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

## [4.0.0] - Unreleased

> **Not tagged yet.** No `v4.0.0` tag exists. The changes this section describes shipped in
> `4.0.0-beta.1`; its text has been corrected since, without adding changes. At the 4.0.0
> release it merges with `[Unreleased]` into one dated section.

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
  `429`, `too many requests`, `rate limit` and `RESOURCE_EXHAUSTED` now
  record the backend as reachable and contribute no budget sample at all —
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

  **A retry is forwarded through the sealed continuation.** The gateway opens
  the `requestState` it minted, checks that it is bound to this caller and this
  request, spends it once, and sends the backend's own state and the client's
  answers upstream beside `arguments`. Answers without that `requestState` are
  refused with `-32602` rather than run as a fresh call, because running it
  fresh would repeat whatever the first attempt already did.

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
[4.0.0]: https://github.com/MikkoParkkola/mcp-gateway/compare/v3.5.1...v4.0.0-beta.1
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
