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
  burst (about 8 minutes) runs on a PR labelled `mrtr7b-full-burst` and before every release. (MIK-7479.STDIO.1)

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
- **A failed release or image-manifest job can be re-run for 30 days, not one.** The build
  binaries and image digests handed between jobs expired after a day, so a later re-run
  published a release with no binaries or failed to find the digests. They now last the
  repository's 90-day artifact retention, past GitHub's 30-day re-run limit, and a CI check
  keeps every such handoff there.
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

## [4.0.0-beta.4] - 2026-11-15

> **Pre-release.** The fourth 4.0 beta. Included again in 4.0.0, which is cumulative;
> this section is history.

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
- MCP Events (opt-in, `events.enabled`): `events/list`, `events/subscribe` and `events/unsubscribe` over HTTP, with callback verification through an SSRF-pinned client, durable subscriptions and per-principal caps.
- security: verbatim cross-principal relay detection on the direct backend route (`/mcp/{backend}`), off by default. New `security.firewall.collusion` section (`action: off | observe | block`, `window_secs`, `min_matches`, `common_principals`, `sources`, `non_egress`), checked at load. Under `block`, a call that sends out content another caller was delivered is refused with `-32002` (HTTP 403) before dispatch; under `observe` it is logged and audited. Known limits: the meta-MCP route follows in a later change; only the first and last 3 KiB of each delivered result are compared, so content from the rest of a larger result is not detected; verbatim text only (#2644)
- MCP Events delivery: subscribed events now reach their callback through a durable outbox with signed, retried, rate-limited and audited delivery, dead letters with caps, inbound webhook dedupe, and the firewall, tenant guard, budget and access checks applied to every attempt (#2651).
- security: verbatim cross-principal relay detection now also covers the meta-MCP route (`gateway_invoke`, surfaced tools, chains, playbooks, tasks, stdio and bridged input rounds), under the same `security.firewall.collusion` settings. Under `block`, a call that sends out content another caller was delivered is refused with `-32002` before dispatch, and its idempotency key is released. Prompt and resource reads are not covered on either route (#2678)
- **CLI capabilities run.** A capability with `service: cli` used to load and never run. It now runs its command with no shell, from arguments built out of validated parameters (a parameter is always exactly one argument and can never become an option), in a private directory with a cleared environment, an output cap, a timeout and whole-tree teardown. Only pinned capabilities whose command is on `capabilities.process_commands` run; `capabilities.process_execution: disabled` turns it off. See UPGRADING-4.0 item 127. (#2697)
- MCP Events deliveries carry the gateway's provenance receipt in `_meta`, inside the signed body, signed with the gateway's provenance key when provenance stamping is on (#2704).
- `mcp-gateway add <name>` now writes a built-in server's env or header references, its OAuth stanza and its HTTP dialect, and writes it disabled (with the reason) when a reference does not resolve or the server can reach any address; `mcp-gateway init` enables the servers that need no account; `mcp-gateway list --available` browses the library.
- MCP Events dead letters: admins can list and replay dead-lettered deliveries through `/ui/api/events/dead-letters` or `mcp-gateway events dead-letters`; a replay re-checks access and re-scans the payload, and `gateway_search_tools` and `gateway_search` now return visible event types (#2709).
- Events: `task.settled` and `backend.<server>.tools_changed` are subscribable event types (owner-only and backend-visible respectively), started and stopped with their first and last subscriber. Gated by `events.sources`.
- `mcp-gateway add` knows seven more servers (time, git, chrome-devtools, grafana, mongodb, supabase, hubspot), 35 in all; documented counts are now checked against the registry.
- Eight REST capabilities for Brave, Tavily, Firecrawl and Sentry join the bundled catalogue; each is listed once its API key is set.
- MCP Events: a subscription to a backend upstream-notification event on a backend that cannot offer it (SSE-handshake HTTP, A2A, identity propagation or a personal account, per-user OAuth on a multi-user gateway) answers `-32014` naming the reason instead of subscribing silently (#2691).
- **MCP capabilities run, and the catalogue is executable.** A capability with `service: mcp` now starts its declared stdio server for the call. The `gws_*` Google Workspace capabilities run through the `gws` tool, `cloudflare_manage` is replaced by Cloudflare API v4 REST capabilities, `gmail_save_attachment` saves into `capabilities.files.downloads`, and `metacognition_verify` is removed. `trawl_extract` and `cisco_scanner` `scan_mcp_server` stay held until their network access can be confined. See UPGRADING items 132 to 136.
- **Event subscriptions are audited, and an event delivery names the firewall verdict.** Subscribe, refresh, verification, unsubscribe, dead-letter and replay each write one governance record to the audit log; every attempt record carries the firewall verdict of its payload; an attempt with no audit logger is not sent. (#2759)
- MCP Events: a backend's `resources/updated`, `resources/list_changed` and `prompts/list_changed` notifications become the events `backend.<name>.resource_updated`, `resources_changed` and `prompts_changed` for stdio, WebSocket and streamable HTTP backends, listened for only while an event subscription needs them (#2767).
- **MCP capabilities: operation requirements, a bounded wait, and pyghidra.** An operation can list the parameters it needs (refused before a process starts), a tool call can wait for background work to finish, and `pyghidra_reverse` now runs (eleven operations, ten of them read-only; import waits for analysis). Calls from before a capability unload or reload no longer start a process. The public capability count is 136; `trawl_extract` stays held.
- MCP Events: a backend's own `notifications/tools/list_changed` now produces `backend.<name>.tools_changed` for stdio, WebSocket and streamable HTTP backends, as well as the gateway's own tool-set announcements (#2797).
- **`schedule.tick` event source.** With `events.sources.schedule: true`, a client can subscribe to a wake-up on a five-field cron expression read in an IANA timezone (UTC by default). A skipped or repeated daylight-saving hour fires once. At most one tick every 5 minutes; an optional label of up to 64 characters comes back in each tick. Ticks missed while the gateway is down are not sent late, and a restart within the same minute does not repeat one. Bounds: `events.schedule.max_timers` (default 1000) and `max_timers_per_principal` (default 20). Off by default. See `docs/EVENTS.md`. (#3052)
- CI guard `event-source-scope`: a change that adds an MCP events source may not edit the events core under `src/events/`. Contributor-facing only; no runtime change. (#3054)
- MCP events: `watch.<capability>.changed`, off by default (`events.sources.rest_watch`). An API-key caller can watch a read-only REST capability; the gateway polls it every `interval` seconds (default 300, 60 to 3600) through the same controls as a tool call and emits when the answer changes. The payload names the changed JSON pointers and digests, never values. Credential-free capabilities share one poller per arguments; credentialed ones poll per principal under that principal's key; capabilities that need a per-user account are refused with -32014. (#3065)
- MCP events: gateway operational events, off by default (`events.sources.operational`): `gateway.budget.threshold` (50, 80 and 100 % of a daily budget), `gateway.budget.exhausted`, `gateway.backend.health_changed` (a backend's shared-slot circuit breaker) and `gateway.kill_switch.changed`. Health and kill-switch events reach admins only; a non-admin API-key holder receives only its own key's budget events, and callers without an API key have no budget of their own. Budget deliveries are not charged. (#3102)
- **Signed Helm chart on each stable release.** The tag run publishes the chart to `oci://ghcr.io/mikkoparkkola/charts/mcp-gateway`, pinned to the signed image digest and cosign-signed by the same workflow identity as the image (`.github/workflows/ci.yml@refs/tags/<tag>`). A published chart version is never replaced, and prerelease tags publish no chart. (#3235)
- A2A: an MCP client can delegate work to an agent that speaks only A2A 1.0 (JSON-RPC binding). A backend with `transport: a2a` and `a2a_url` now starts. It exposes the agent as one tool, `send_message`, and each call passes the same tool policy, firewall, budget, audit and relay checks as any tool call. Previously every A2A backend failed at first use.
  - The Agent Card is read from `/.well-known/agent-card.json`, or from `a2a_agent_card_path`.
  - The endpoint the card advertises must share the origin of `a2a_url`, and redirects are checked like any HTTP backend's.
  - Credentials written into `a2a_url` (`https://user:pass@host`) are sent to the agent as HTTP Basic, and never appear in URLs, errors or logs. A configured or propagated `Authorization` header takes their place, and over plain `http` they are refused except to a loopback address.
  - Only A2A 1.0 agents are supported: an agent that offers only 0.3 is refused at start, and the message names the versions it offers.
  - Library users: `mcp_gateway::a2a` is no longer public.
- CI guard `timing-asserts`: a test may not tell outcomes apart by a wall-clock window under 5 s. Tests that did now wait on an event, so a loaded runner can slow them but not fail them. Contributor-facing only; no runtime change. (#3678)
- **`EXTRA_APT_PACKAGES` on the `-full` variant.** The entrypoint installs the apt packages a deployment names (`iproute2` to route a backend's egress through a tunnel, say), so needing one more than the image carries no longer means forking it. Installing needs root, so the deployment asks with `--user root` and the entrypoint drops back to the gateway user before exec'ing it; the image still declares `USER gateway`, and with the variable unset a container runs exactly as it did before. The install runs non-interactively, is bounded, refuses an apt option in the list, and stops the container on a failure rather than starting without a package it was told to carry. It resolves versions at every start, and the list takes apt's pinning syntax (`iproute2=6.12.0-1`); a derived image stays the reproducible option, and is the only one open to a deployment that runs non-root. ([@terafin](https://github.com/terafin), [#729](https://github.com/MikkoParkkola/mcp-gateway/pull/729), #3705)
- **`/docker-entrypoint.d` on the `-full` variant.** Executable `*.sh` files in that directory run, and `*.envsh` files are sourced, in name order, before the gateway starts, so a deployment whose startup needs a route, a key or a cache warm mounts its own steps instead of forking the image. A container started as root runs them as root and then drops to the gateway user, so the directory is mounted read-only and owned by root. A variable an `.envsh` step exports reaches the gateway, except `HOME` in a container started as root; one it only assigns does not. A file that is not executable is skipped with a message, and a step that fails stops the container. The `-full` variant's health check allows a 60 s start period for the install; the default image is unchanged. ([@terafin](https://github.com/terafin), [#729](https://github.com/MikkoParkkola/mcp-gateway/pull/729), #3705)
- **Cancelling a task now cancels its upstream task.** When a task's backend accepted the call as an upstream task (`tasks.recovery_adapters`), the owner's `tasks/cancel` sends that backend one `tasks/cancel` naming the backend's own task id, through the trusted recovery adapter. It is sent once per task, best effort; a cancel that lands before the backend's reply arrived can only close the stream, and a gateway stopped between the claim and the send leaves the upstream task running. Task records of such a cancel are written as version 7: back up `tasks.store_dir` before rolling back to a beta (#3718).
- **The protocol-revision measurement window is per transport and restart-safe for HTTP.** A hidden switch, `--protocol-revision-window record` or `MCP_GATEWAY_PROTOCOL_REVISION_WINDOW=record` (not a config key), is off by default, which changes nothing. With `record`, each HTTP `serve` process opens its own segment in `protocol-revision-telemetry/window.json` before it serves, updates it every 5 s and seals it when shutdown starts. From that point, a request that reaches counting is refused with HTTP 503 and its own id, and is not served. Stdio counts are kept apart and are never certified. A request with no protocol revision is broken down by named client or User-Agent family; the breakdown is bounded and raw agents are never stored. The RFC-0060 U1 decision reads only the sealed segments from the declared production writer, so a crash, an overlapping or foreign gateway, or a coverage gap blocks the decision instead of skewing it. 4.0.0 ships with no measured data; the measurement moves to a later release. (#3920)
- **`keychain:` references read on Linux and macOS.** On Linux, through the Secret Service: a locked or missing entry is refused without spawning `secret-tool`, so no unlock dialog can open, and a missing `gdbus` or `secret-tool` is refused naming its package. On macOS, through `security-framework`, with keychain prompts switched off for the whole process; a call that would need a dialog fails as locked. Each read is bounded at 2 s, and its bytes are used exactly.
- **`keychain:` references read on Windows,** from Credential Manager generic credentials whose user is `mcp-gateway`. Each read is bounded at 2 s, and the secret blob is zeroed before the Win32 copy is freed. Every OS now has a keychain reader.
- **`secrets.store` setting.** Secrets saved through the gateway go to a fresh entry in the chosen store, all or nothing, and an old entry is never deleted. `files` writes a new owner-only file under `<config dir>/secrets/` and references it with `file:`. `auto`, the default, uses `files` until the keychain writer lands, and `keychain` is refused until then by name.
- A server preview now shows the name and version the server reports for itself, marked `reported_by_server`. The text is cleaned for display: control, invisible-format and line-separator characters are removed and each value is capped at 128 characters. The OpenAPI import preview carries the same key as `null`.
- A backend can list the only tools it offers: `backends.<name>.allowed_tools`, with the grammar of an API key's `allowed_tools`. A tool outside it is left out of every tool list and refused by name, including one the server adds later. The web UI's add and edit API (`POST`/`PATCH /ui/api/backends`) take the list, and the admin tools list marks each tool selected or not.
- **To do lists servers to adopt and client config files it cannot read.** `GET /ui/api/decisions` now carries an adopt decision for each MCP server another client's config file names that the gateway could adopt, with the radar's severity, and an item for each client config file the gateway cannot read (its file name and why: not a readable file, no permission, or did not parse). `GET /ui/api/decisions/count` answers the open count and its revision from memory, and the web UI's To do badge reads it. The client config files are scanned once for the discovery page, the control-plane radar and To do, and rescanned when one changes.
- **Activity lists calls an identity grant refused before they ran.** A call refused by the identity-grant check that left no invocation record of its own, such as a tool the caller's key withholds, is now one blocked row in `GET /ui/api/activity`. The row carries the caller, server and tool, and the receipt shows the refusing decision. It matches the outcome, server, caller and tool filters, and appears in both exports and the live stream. The row's caller is the verified identity the grant was checked for, not the API key name, so a caller filter by key name does not find it. A refused call that did leave an invocation record is still listed once, from that record. Re-checks when a stored result is handed back or a task is read are not new calls, so they add no row. Grant decision records now carry the server name and an `invocation_recorded` marker. A record written by an older gateway has neither, counts as recorded, and is never listed.
- **The web UI's settings save core.** A settings save writes `gateway.yaml` all or nothing across the file and the secret store. It edits only the changed keys in place, so every comment and untouched line stays. It refuses when the file changed since its preview, answering with a fresh preview. An edit it cannot prove in place gives a copyable patch instead, and nothing is written. A new secret goes to a fresh store entry, the old one is kept, and a failed commit puts the old file back. The save's audit record names the fields it changes, never their values. The Settings page uses it once its routes land.
  Affects: none yet; the routes that call it come later. Operator action: none.
- Activity: filter the list and both exports by rule id (`rule=`), and show each record's decision evidence (rule, grant, flags, findings, effect, revisions) on its receipt and its findings on the row, with a fixed line where evidence was not recorded; CSV exports gain a `findings_truncated` column (#4754)
- Activity: each call now shows how its answer was delivered (`effect`, from delivered through no_record) and the answer's findings (`answer_findings`) on the list, receipt and both exports, with an `effect=` filter; `outcome=cleaned` lists rewritten or annotated answers instead of answering 400; list, export and receipt state the integrity scope they checked (#4764)
- Transparency log: opening a log segment no longer reads up to 4 MiB to find its first line, which cut a 10,000-row Activity export from about 4 GB to about 0.64 GB of allocation (#4764)
- Added `POST /ui/api/key-server/audit/lookup-email`: a gateway admin gets the key server's retained issuance rows for an email through its keyed hash, with no stored copy of the email, a cursor, and one rate-limited budget per process.
- **The web UI shows each key only the pages and tabs it may open.** The shell reads the access report the gateway already sends with its status answer: the sidebar, the tabs and the command palette list only what the signed-in key can open, one line says why other pages are hidden, and a link or Back to a hidden page lands on the first open page. A report that is missing or malformed shows every page, and the gateway still refuses every hidden route itself. Signing out, or a 401, drops the report and the To do count, so the next key never sees the last key's pages or count.
- Added `mcp-gateway audit lookup-email --email-stdin`: an admin looks up the key server's retained issuance rows for an email from the command line. The email is read from stdin only, never an argument, and later pages are asked for with `--cursor-stdin`, the previous page's `next_cursor` on stdin (there is no `--cursor` option); the credential comes from `MCP_GATEWAY_TOKEN`; any HTTP, auth, read or decode failure exits nonzero.
- Added a Key audit page to the classic dashboard, shown to admins only: type an email to list the key server's retained token issuances for it. The field is emptied before the request is sent, the email goes in the request body once and never in the address bar, browser storage or history, and later pages are asked for with the server's sealed page token alone. A throttled lookup shows how long to wait.
- Tasks on `POST /mcp` now carry an input round: a backend that asks for input parks the task as `input_required`, `tasks/update` supplies the answers, and the gateway resumes the same call.
- **A client can cancel its own call.** A `notifications/cancelled` naming one of the client's
  own running requests now stops it, on `/mcp/{backend}` and for `tools/call` on `/mcp`. The
  gateway answers the request with JSON-RPC error -32800, and a 2025-protocol backend is told to
  stop by the id it received. A cancel naming another caller's request, or a request that is no
  longer running, is accepted and does nothing. An anonymous caller, with neither a verified
  identity nor a credential, cannot cancel.
- **An unset OAuth `token_refresh_buffer_secs` follows the token's lifetime**: the larger of
  300 s and 10 % of the lifetime the token answer stated; a set value is used as before. Stored
  tokens now keep that lifetime. See upgrading.d/8044-4.md.
- **A key server provider falls back to `{issuer}/.well-known/jwks.json` when its derived OIDC
  discovery URL cannot be reached** (connection error, timeout, non-2xx status, or a body that is
  not a discovery document), for at most five minutes. A discovery document that fails its checks,
  and an explicit `discovery_url`, never fall back.
- **The local capability commands read the gateway config's `capabilities.directories`**:
  `tool list`, `tool inspect`, `tool invoke`, `tool completions` and `skills generate` use the
  same directories the gateway serves, unless `-C` or `MCP_GATEWAY_CAPABILITIES` names one.
  `tool completions` now also reads `.yml` files.
- A2A: delegation to an A2A 1.0 agent now covers its whole task, not only a single blocking reply.
  - An agent that asks for input (`input-required`) has its question passed to the MCP client as an input round. The round is bound to the caller who was asked, and no other caller can answer it.
  - A task that keeps running is followed until it ends.
  - A call that is cancelled, times out, or whose round is declined or abandoned cancels the agent's task. An abandoned round is cancelled within 330 seconds.
  - An agent's answer gets the same firewall screening and provenance marking as any other tool result, whether it arrives on the call itself or through an MCP task.
  - Previously such a call returned an error saying the gateway could not relay the question, or that the agent returned before finishing.
- **Plan answers over 1 MiB are now covered by relay detection.**
  Such an answer used to drop every step receipt of its plan, so a relay of the plan's text went
  unseen. The answer is now read through a bounded sampled view: the step text it delivered is
  evidence, and its holder is excused for it. Detection is probabilistic: a large step's evidence is
  a thinned sample, so a 200-char relay out of a 900 KiB step is missed 88% of the time and a
  2,000-char one 0.4% (design §14.3 B1″ has the table). Every byte the view, its walks and the retained cuts
  use is reserved from a 32 MiB transient budget before it is allocated. An answer past the 4 MiB
  answer text cap, the view's entry cap or that budget fails closed: its steps' text stays
  evidence, and the plan's caller is refused for lost room (`bound="plan_answer_unread"`,
  `bound="plan_view_budget"`). Refused selections and view cuts are counted
  (`bound="plan_selection_budget"`, `bound="plan_view_cut_budget"`), as is a step whose leaf
  hashes do not fit (`bound="plan_leaf_hashes_skipped"`).
  Affects: deployments with relay detection enabled (`collusion.action` observe or block) in the
  4.0.0 pre-releases. Operator action: none; a relay of a large plan answer's text that used to
  pass is now refused (403 under block), and a caller whose plan answer cannot be read is refused
  for lost room, see UPGRADING.
- **A signed task submit refused before its task exists gets its nonce back, on `/mcp` and stdio.**
  A task submit refused for a key reused for other arguments, a key still being created, every task worker
  busy, sealed intake or a backend that requires a signature chain kept its signing nonce spent, so the
  honest re-send under that nonce was refused as a replay. It now gives the nonce back when nothing before
  the refusal acted, by the same rule as the other refusals. A submit the task store fails keeps it spent.
 
  Affects: 4.0.0 pre-releases only. Operator action: none.
- **`mcp-gateway doctor` warns when a stdio backend pins a registry npm package to a version npm marks deprecated.**
  The lookup is on by default: for each such pin, doctor asks registry.npmjs.org whether that version is
  deprecated. Only package names from the gateway's own registry are sent, and npm sees this host's IP
  address. Turn it off with `--no-registry-check`, `MCP_GATEWAY_DOCTOR_NO_REGISTRY_CHECK=1`, or
  `security.posture: hardened`. The check only ever warns; it never fails doctor.
- `meta_mcp.surfaced_tools` now applies on a config reload, with no restart. A reload validates
  the new list as startup does (a name that collides with a meta tool, or repeats, is dropped
  with a warning, and the reload still succeeds), swaps it in under the reload lock, and sends
  one `tools/list_changed` to every listener when the ordered list changed; an identical list
  sends nothing. One `tools/list` always reads one surfaced set. A surfaced task runs on the
  server its name resolved to when it was created; if a reload has since moved or removed the
  name, the task is refused before any backend is called ("surfaced target changed since the
  task was created", outcome `not_executed`). Thanks to @sblattj, whose request for
  usage-driven surfacing (#3953) this builds toward.
- Capability hot-reload heals instead of stopping silently: a periodic stale
  check, every 60 s and not a setting, reloads when the watched files drift with no file event, and every
  previously silent path (shutdown-channel lag or loss, a dead event source,
  a slow reload) now warns.
- **MCP Events from legacy SSE-handshake and A2A backends.** `backend.<x>.resource_updated`, `resources_changed`, `prompts_changed` and `tools_changed` are now offered for HTTP backends that speak the legacy HTTP+SSE transport (MCP 2024-11-05). They were refused with `sse_handshake_transport`. The events listener runs its own session on such a backend (GET the SSE endpoint, `initialize`, `notifications/initialized`, then `resources/subscribe`), separate from the session calls use. A switch to SSE detected in place reconnects the listener over SSE and keeps the subscriptions.
  - **A2A backends:** `backend.<a2a>.tools_changed` is delivered. The gateway re-reads the agent's tools at the catalogue's cache interval (at least once a second, at most once a day) and announces only a real change. A2A has no resources or prompts, so their three event names are refused `-32014` with the reason `a2a_no_such_capability`, which replaces `a2a_transport`. Backends reached with a caller's propagated identity stay refused as before.
- The web UI can preview a server before you add it: `POST /ui/api/previews` connects to an http(s) MCP server once, lists its tools with a read or write class, and disconnects. Nothing is saved, and none of the server's credentials are sent. A preview needs an admin token and a confirmation step, runs one at a time, and stops at 30 s, 4 MiB per response and 8 MiB in total. Command servers are refused until the preview sandbox lands. The OpenAPI import preview now shows the same preview block and a read or write class per tool.
- **Add a server with only the tools you tick.** The classic web UI's Add Server form has a **Preview tools** button. It shows what the preview will contact and what it withholds, and after **Start preview** it lists the server's tools with a checkbox each. Read tools start ticked; write tools, and names the gateway will not call, start unticked. **Add Server** then saves only the ticked tools as the backend's `allowed_tools`, so a tool the server adds later stays off until you tick it. Add is refused while nothing is ticked, when the listing was cut short, or when the form has changed since the preview. Without a preview, Add works as before and offers every tool.
- The gateway now keeps call history for the web UI's charts: calls, blocks, errors, firewall catches and cache hits in half-hour buckets over 48 hours and in host-local days over 30 days, overall and per server, tool, caller and caller-and-server. Each call counts once, refusals included, whether or not the audit log is on. Restarts, upgrades, config reloads, breaker pauses and kill-switch changes are kept as markers. Both survive a restart in `counters.json` beside `costs.json`. Admins read them at `GET /ui/api/metrics/series` and `GET /ui/api/markers`. Only configured servers, catalogued tools and verified callers get their own line; any other name a caller sends is only counted, never stored.
- **The web UI has a live event stream.** `GET /ui/api/stream` sends server-sent events: a `hello` that lists the kinds this caller gets, a `status` frame whenever the displayed status changes (counts only below admin), and, for admins, a `reload` frame after every applied config reload. Each frame carries an `id:` that resumes a dropped stream through `Last-Event-ID` or `?last_event_id=`. A stream never extends a dashboard session, is checked against the live credential every second, and ends when the session or its access changes. At most 32 streams run at once and 4 per credential; the next gets a 503 with `Retry-After`.
- The web UI's server list says what state each server is in and why: `running`, `paused` (failing, retrying on its own, with `next_retry_at`), `dormant`, `unhealthy`, `refused` (its runtime policy denies it), or `needs_sign_in`, with a one-line `reason` built from counts, never from a server's error text. `GET /ui/api/refusals` (admin only) lists what the gateway refused to apply: a server its runtime policy denies, a refused config reload, a refused add or edit, each with a stable cause code and a fix; causes are rebuilt from fixed wording, so a refused value is never repeated back. A server whose credentials go over plain `http://` because `allow_cleartext_credentials` is set is marked `cleartext_credentials_accepted`, and the gateway writes an audit record when such an override takes effect or ends, at start and on every reload, in HTTP and stdio mode alike. Existing `/ui/api/status` fields are unchanged.
- A running server whose recent calls are far slower than its own usual now reads `slow` in the web UI's server list: the p95 of its last 100 answered calls is over three times its usual p95 and at least 50 ms. The usual is learned from the server's own traffic since the gateway started, so a server with fewer than 500 answered calls since then never reads `slow`, and a slowdown that lasts becomes the new usual (a tenfold one shows for about 2,000 calls). `slow` never hides a worse state: paused, unhealthy, refused and sign-in states still win.
- The web UI can sign an OAuth backend in again. An admin with a dashboard session starts the sign-in from the backend's row, opens the provider's link, and confirms the result; the token is saved only on that confirm, and a cancel works at any point. Each backend row now shows whether it needs a sign-in (`needs_sign_in`), its sign-in status and expiry, and a sign-in in progress. One sign-in runs per backend at a time, shared with the CLI and startup logins. A row's sign-in status is one of `not_oauth`, `not_yet_checked`, `signed_in`, `expired`, `never_signed_in`, `re_sign_in_after_upgrade`, `waiting_elsewhere` or `provider_changed` (the provider changed its issuer since the gateway last discovered it, so sign in again).
- **The web UI can list MCP servers named in other apps' config files on this host.** `GET /ui/api/discovery` (admin only) returns the servers found in client config files (Claude, Cursor, VS Code, Windsurf, Zed, Continue, Codex and `~/.config/mcp`), each with its program name or URL origin, its env and header key names (values are never shown), the file it came from, whether it is already a backend, and whether it could be adopted, with each reason it could not. No network is scanned. Results are cached for 30 seconds and refreshed early when a client file changes; the cache holds no values.
- **The web UI can adopt a server it found in another app's config file as a disabled backend.** `POST /ui/api/discovery/adopt` (admin only) takes a find from `GET /ui/api/discovery` and the `gateway.yaml` revision it was listed against, never a command, URL or value. The server is read again from its client file and judged by the same rule as the listing; its literal env and header values go to the secret store and only their references to `gateway.yaml`, where the backend is added disabled, in place, with comments and layout kept. A change that cannot be made in place, a stale revision, a client entry changed since the listing, a name already in use and a value the store cannot hold are refused, and no answer or log line carries a value.
- **`environment` names the gateway in the web UI.** An optional top-level label such as `staging`, served by `/ui/api/config` and applied on reload.
- **API keys rotate without a gap.** An `auth.api_keys[]` entry accepts three optional rotation fields (ADR-022): `previous_key_sha256`, a previous digest accepted until `previous_expires_at`, and `principal`, which keeps the key's identity, and so its sessions, grants, journals and tasks, across a new digest. Both digests are matched in constant time, and a key with no previous digest can never match one. Load refuses a previous digest without an expiry, an explicit `principal` that another credential already resolves to, and any two equal digests among every key's current and previous digest and the bearer token. A previous digest takes the same `env:`, `file:` and `keychain:` references as `key_sha256`, and an adapter secret may not reuse it. A key without the fields behaves exactly as before.
- **`GET /ui/api/keys` lists the configured API keys for the web UI's Access page.** Admin only. Each key shows its name, backends, tool lists, admin flag, expiry, rate limit and last use, in table order; no secret, digest or principal is ever included. `last_used` is the key's last accepted match since the gateway started, and `null` before it.
- **The web UI's tool list and server status carry call counts.** `GET /ui/api/tools` gives
  every tool `calls_24h` (its calls in the last 24 hours) and `calls_prev_24h` (the same hours of
  the day before), and `GET /ui/api/status` gives each server the same two counts. Both answers
  gain `counts_since`, when counting began. The counts come from the persisted call counters in
  one read for any number of tools, so they survive restarts and cover every tool, not the 10
  most-called since start. A count is `null` when it could be low (calls folded into an
  overflow count, or no longer held), and every count is `null` when the counters are not
  running. The library's `StatsSnapshot::top_tools` now lists every tool; the gateway's own
  short lists still show 10.
- **Try a tool from the web UI.** `POST /ui/api/tools/call` runs one tool, as an admin, through the
  same dispatch as an MCP `tools/call` of `gateway_invoke`: every gate, budget, firewall, response
  scan and audit record applies. A tool its server did not declare read-only (`readOnlyHint`) runs
  only with `"confirm_write": true`; a `get_*` name alone does not count as a declaration. The
  answer carries the tool's result, `is_error`, `latency_ms` and a `receipt`: the invocation's
  trace id, which finds its Activity row. The status says whether the tool ran: 4xx means it did
  not, 200 that it ran (its own error included), 5xx that it may have; past 25 seconds the route
  answers 504 while the call finishes and is still recorded. Each call's `admin_action` record
  names the caller as `ui:` plus its usual label and links the invocation.
- The web UI's Gateway page has a source: `GET /ui/api/gateway` (admin only) answers in one read with the version, when the process started and its uptime, the environment name (from `environment` in the config, else the host name, else `default`), how many reloads this process attempted and applied with the outcome of the last, whether TLS is on and whether it requires client certificates, the version change this start recorded (with the 4.0.0 breaking-change items when the upgrade crossed from 3.x), the connected clients by the name each reported in `initialize` with when it was last seen (at most 100, newest first, with a total and a `truncated` flag, and a count of clients that reported none), and what the gateway refused while starting. A client's name is display text it chose itself, cleaned and cut to 64 characters; it is never an identity and decides nothing about what a session may call. The response carries no session id.
- `/metrics` reports the gateway's own health. `mcp_gateway_added_latency_seconds` is a histogram of the time the gateway added to each `POST /mcp` and `POST /mcp/{name}` call: the whole request time minus the time spent waiting on backends (overlapping backend waits count once; retries and backoff inside a backend transport count as backend wait, while the gateway's own admission, semaphore wait and retry backoff count as added latency). `mcp_gateway_sessions_active` is the number of client sessions held at scrape time. `process_resident_memory_bytes` is the resident memory of the gateway process, on Linux only and absent elsewhere or when it cannot be read. `process_start_time_seconds` is when the process started, in Unix seconds. All of them need `server.metrics_token`, like the rest of `/metrics`. `mcp_gateway_errors_total{kind}` counts the errors an HTTP client received from the gateway (a client on the stdio transport is not counted), by `kind` (`auth`, `request`, `internal` or `backend`), once per answer; `mcp_backend_requests_total` remains the backend-side view, and a tool result with `isError: true` is not counted.
- Web UI: for an admin key, the top bar of every page shows the gateway environment name as a chip, with a tooltip when the name falls back to the hostname or the default; any other key sees no chip.
- The gateway keeps a seven-day record of its own health in `health.json` in its data directory, next to `counters.json`: per half-hour the added-latency distribution, the errors clients received by kind, and the largest resident memory and session count sampled; per six-hour block the time it ran, the time it was down and how many restarts it had. A restart after a clean stop records its downtime as measured; after a crash, as estimated from the last save. The file holds only numbers and fixed words, never anything a client sent. It is saved once at startup before anything is served, every five minutes and at shutdown; a failed save is logged and never stops the gateway from starting. A file that does not decode is set aside and the record starts again.
- **Gateway restart refusal.** The bundled UI's admin-only `GET /ui/api/gateway/restart` reports `available=false` with platform-specific recovery guidance; `POST` accepts a strict `{confirm: string}` JSON body and records an attributed audit entry for its 409 refusal. The call is refused and the process does not restart.
- **The web UI can list the decisions an admin has open.** `GET /ui/api/decisions` (admin only) lists access requests (a subject and proven agent refused a personal capability for want of a grant, newer than any decision on it and not covered by a live grant) and changed capabilities (a capability file whose bytes no longer match their pin), with an opaque id, what each waits on and display-safe fields only: names that pass the backend-name rule or a keyed label, an issuer as its host, a changed file as counts, mapped types and its inferred risk class. The list is held in memory, kept current from the transparency log and a startup replay of it, and answered without a scan; while a source is still being read it answers 503 naming that source.
- **One read for the web UI's Overview page.** `GET /ui/api/overview` (admin only) returns the first screen in one call: server and tool totals, uptime and version; the first 24 servers by name with the rest counted; needs-you rows for every daily budget at or past its configured Notify percent (default 80); the newest five admin actions from the transparency log; and whether an API key exists. Every list is capped, so the body does not grow with the number of servers. A section the gateway cannot know yet is left out of the response rather than sent as zero, and a source that fails to read is named in `degraded`. Call counts, the flow map, chart markers, server states and the invalid-config row join as their sources land; sign-in and pending-decision counts are not available in this version.
- **The web UI's Overview read now carries calls, flows, markers and server problems.** `GET /ui/api/overview` adds the 24-hour call, block and error totals, with the previous 24 hours when counting covers them; ranks the 24 servers it lists by calls, each with its operator state and reason; adds the top 48 caller and server flows and the chart markers of the last day; and adds needs-you rows for a refused config reload (`invalid_config`), for refused edits and for servers the runtime policy denies (`refused`), plus whether any tool has been called in 30 days. The counter fields are left out when there is no counter store, and named in `degraded` when the clock cannot be read.
- The web UI answers every `/ui/...` link instead of 404: a deep link, a reload on a sub-page or a shared link now reaches a static page that sends you on to `/ui`, ready for the new UI's pages. The current UI is also reachable at `/ui/classic` and stays at `/ui` until the new UI replaces it. The new UI's files are served from `/ui/assets/` with long-lived caching and a strict Content-Security-Policy; unrouted `/ui/api/...` paths still answer 404.
- The new web UI's shell now renders at every `/ui/...` link instead of sending you on to `/ui`: the sidebar lists Overview, To do, Servers, Tools, Activity, Costs, Access, Policies and Gateway as a route line, each page's Status, Actions and Settings tabs are in the address, and Back, Forward, reload and shared links land on the same page and tab. Pages not yet built say so and link to the classic page. The theme follows the system's light, dark and high-contrast settings, there is a skip link, and touch targets are at least 44 px. `/ui` itself stays the classic page until the new UI replaces it.
- The new web UI's shell has a command palette: Ctrl+K or ⌘K, or the top bar's search, finds any page, action or setting and opens it on its tab; nothing runs from it. On phones a menu button opens the pages.
- The new web UI's shell shows a sign-in card at the same address when the gateway asks for sign-in: open the one-time link the terminal printed, enter the handoff code from another device, or paste an API key, which stays in the tab's memory only.
- The new web UI's top bar offers sign-out: it forgets a typed key and ends the browser's session on the gateway. While a key is being checked the button reads "Checking…", and a valid key the gateway does not let in is told so, apart from a wrong key.
- The new web UI's sign-in says plainly when the gateway is limiting sign-in attempts, and how long to wait before trying again.
- A refused sign-in link or code now returns the browser to the new web UI's sign-in, which says the link or code did not work and how to get a new one, instead of leaving it on a bare error page. Scripts and other clients get the same answer as before.
- A page in the new web UI that fails now says why: the gateway could not be reached, it answered with an error (with the HTTP code), its answer could not be read, the item was not found, or the page itself failed. A fault in the page's own code no longer reads as an unreachable gateway. The page's last data stays visible, muted, under the message, with the time it is from, and a Retry button runs the page again.
- The new web UI has one place screen readers hear it from. Page errors, a page the key may not open, data that stopped updating and started again, sign-in messages and a change in the To do count are said there, politely, as separate sentences; counters and charts never are. A sign-in field is marked invalid only when the gateway refused the key itself.
- A page in the new web UI that has nothing to show after about 300 ms shows that it is loading, and says so once to screen readers; a page that answers sooner never flashes it, and the frame never waits for the gateway to answer. One glossary gives each state a single word across every screen, in step with the gateway's own server states, and a dropped live stream reads "Updates stopped", never the word for a paused server.
- The new web UI has one table for every server state the gateway reports: each has its word, symbol, colour, the message shown while it matters and the next step, and a gateway explanation that carries raw policy codes is never shown. Data that stopped updating reads "Updates stopped at HH:MM · reconnecting" with its numbers muted, and a To do count that failed to load reads "?" rather than disappearing.
- The new web UI follows the gateway's live event stream: the top bar reads "Live" while it is open, and when it drops the page shows "Updates stopped at HH:MM · reconnecting" until it reconnects, resuming from the last event it saw. A stream that cannot be opened at all reads "Updates unavailable · reconnecting". It works with a key sign-in as well as a session, waits as long as the gateway asks, and stops on sign-out.
- **The new web UI has a Tools screen.** Tools › Status lists every tool the gateway offers, A to Z, with its server and description. A search over names and descriptions and a server picker narrow it, and the search survives a visit to a tool and back. Each tool's name opens its description, its read or write class and its input schema in place, and each tool has its own page. Everything works from the keyboard. The most-called list and Try a tool follow when their data is available.
- **The new web UI explains its numbers, states and settings in tooltips.** Each (i) opens on hover after a short pause, at once on keyboard focus, on Enter or Space, and on tap; Esc or tapping outside closes it, and it never covers what it explains or the next action. Screen readers hear the text once, as the button's description. The text loads after the page, so it never delays the first paint, and if the tooltip script stops working the text still shows on hover and focus. Tools › Status has the first one, beside the search. CI now checks every page and tab of the new UI for accessibility at phone and desktop widths, in dark and light, with a tooltip open.
- The gateway binary now carries the Linux sandbox that the web UI's command-server preview will run in: util-linux `unshare` makes fresh user, mount, PID, network, IPC and UTS namespaces, and the gateway's own helper builds a private read-only root (the preview gets a fresh 1 GiB home and a 256 MiB `/tmp`; homes, `/run`, `/var` and the gateway's state, config and data paths are absent or masked), drops every capability, sets resource limits and a seccomp filter, and runs the command with no network. Hosts that cannot provide it (Ubuntu 24.04+ without the one-time AppArmor step, `user.max_user_namespaces = 0`, containers) get a refusal naming the reason. Nothing starts a preview through it yet: command previews stay refused until the preview route adopts it.
- **`keychain:NAME` secret references.** Every gateway.yaml secret slot that accepts `env:` and `file:` now accepts `keychain:NAME`, naming an OS keychain entry (ADR-028): `auth.bearer_token`, `auth.api_keys[*].key_sha256`, `agent_auth.agents[*].hs256_secret`, `server.metrics_token`, `security.message_signing.shared_secret` and `previous_secret`, the transparency-log shared secret, `security.signature_chain.signing_key`, the record principal key, `key_server.admin_token`, `accounts.keys`, adapter `hmac_secret_ref` and `client_secret_ref`. The entry's bytes are used exactly, with nothing trimmed. A name outside `[A-Za-z0-9._-]{1,128}` fails the load naming the field only, since that text may be a mistyped secret. A missing, empty, locked or non-UTF-8 entry fails naming the field and the entry. The value is never named.
- **Every audit record says which check decided the call.** Each invocation and refusal record in the transparency log now carries a `decision` object, covered by the entry hash and signature: the configuration revision in force when the record was written (a keyed digest of the applied config, grants file, env files and the values the load consumed; capabilities are not yet included), the running revision and any fields waiting on a restart, and the kind of check that allowed or refused the call (firewall, tool policy, backend scope, grant, cost budget, response gate and the rest). A refusal whose check is not yet named records `unrecorded`, never an allow. Older records without the object still verify.
- **An audit record says what the called tool declared it could change.** The `decision` object on each invocation record is now version 2 and carries `declared_effect` (`read_only`, `may_write` or `undeclared`) with `declared_effect_source` (`tool_annotation` or `capability_definition`). It is the tool's own claim, read from the `readOnlyHint` the backend declared on every listed copy of the tool, or from the capability's definition, and never inferred from the tool's name; duplicates that disagree, a slot not yet listed, or a declaration a later partial listing withdrew record no effect. A cached answer keeps the effect its call was admitted with.
- **Per-server latency history.** The gateway keeps each server's p95 backend latency per half hour and per local day, beside its call counts, and saves it with them in `counters.json`. `GET /ui/api/metrics/series?metric=latency_p95` reads it for all servers or one (`server=`), with each slot's calls, failures, timeouts and late samples; the Overview read gains a `latency` member with the last hour per server and the slowest server, named once it has at least 21 calls in that hour. Only the send to the backend is timed, never the gateway's own waits, cache hits or refusals. A p95 is whole milliseconds, within about 12% of the real value plus up to 0.5 ms of rounding.
- **A delivery record now says what the gateway did to the answer.** Each
  `response_delivery_attempt` record on `POST /mcp`, `/mcp/{name}` and stdio carries
  `response_effect` (`delivered`, `annotated`, `rewritten` or `refused`) and `response_findings`:
  what this request's checks of the answer found, from both the response firewall scan
  (`firewall:` kinds) and response inspection (`inspect:` kinds), by kind, severity and part
  (`result` or `error`), never the content, at most 32 entries with `response_findings_total`
  beyond that. Findings are `null` when no check of this request read the answer (for example with
  response scanning and inspection both off).
  An answer this request did not produce (a cache hit, a replay, a task read, a plan or code-mode
  composite) states neither field, except a replay this request refused, which states `refused`.
  Older records have neither field; read their absence as "unknown", not as "delivered".
 
- **A firewall rule can be scoped to backends, API keys, and exceptions.** `security.firewall.rules[]` takes three optional keys: `servers` (globs over backend names), `keys` (API key names, matched exactly), and `except` (entries of `server`, `tool`, and `key`; a call that matches every field an entry sets is skipped). A rule without them applies to every call, as before. An empty `servers`, `keys` or `except` list, an `except` entry with no field set, or a glob that does not parse refuses the config at load; such a rule built without the load blocks its finding types on every tool. An answer that names no backend, such as a discovery listing or a notification, is judged as each registered backend's, so a rule scoped to any backend still covers it.
- **Firewall rules can confine a file tool to allowed folders.** A rule with `allowed_roots` and `path_args` refuses a covered call whose declared path argument resolves outside every allowed folder, before the backend sees it. The check judges the exact string the backend receives, without following links, and refuses what it cannot judge: a relative or unnormalised path, a remote backend, a capability call, a look-alike spelling, or a secret rule that would rewrite the path. Each refusal names its rule, its argument and a reason code, never the path. A root may start with `~` only as `~` or `~/`; `~user/...` and `~\...` are refused at load. `suggest_path_args` proposes the entries from a tool's input schema for the policies screen to offer. See docs/FIREWALL.md.
- The web UI's status answer (`GET /ui/api/status`) now says which pages and tabs the signed-in key may open, with one short reason for each page it hides, so the UI can leave out what the key cannot use instead of showing a page that refuses it. The answer comes from the same table every UI API route admits its caller through, so the two cannot disagree. With authentication off, admin pages read as hidden with the reason that authentication is off. With authentication on, a caller with no credential gets no such list.
- **A task worker's settlement refusal is recorded on the task.** When a task the gateway runs itself has its answer refused or redacted as it settles, the transparency log now gets a `task_settlement` record (with `response_effect`, its findings, and the trace of the worker's dispatch record), written before the task commits. A recovered upstream task's `task_recovery` record carries the same fields in that case.
- **The web UI's tool list carries each tool's last hour and a half-hour trend.** `GET /ui/api/tools` gives every tool `calls_1h` (its calls in the last two completed half hours, an exact hour ending at the start of the current half hour) and `calls_prev_1h` (the hour before that), plus `calls_series`, its calls in each of the last 12 half hours, oldest first, with the partial current half hour last. The answer gains `series_start`, the unix start of the first series point, so the UI labels the points without trusting its own clock. They come from the same persisted counters and the same single read as `calls_24h`, so they survive restarts. A count or point is `null` when it could be low, under the same rule as `calls_24h`, and all of them are `null` (the series as 12 nulls) when the counters are not running.
- **A refusal's decision record names the rule that made it.** Firewall and tool-policy refusals now record a stable `rule_id`: the rule's kind and an HMAC of its configured definition under a key derived from the record key. The same rule keeps its id across restarts and reloads, an edited rule gets a new one, and a reader of the log cannot test guesses about a short rule. A block that no configured rule decided (a severity default, anomaly, tenant, budget or relay check) records its kind without a rule id. A stored task read that a check refuses (on `tasks/get`) now names that check in its delivery record's `refused_by`: the kind, and the rule id when a configured rule decided. A stored result no longer served under the bindings that produced it is refused under the new kind `provenance`. The id is never sent to the refused caller.
- **A withheld task notification names the check that withheld its output.** A task-status notification whose stored output is withheld because a check refused it (a tool policy published after the task ran, the key's scope, a descriptor block, a broken schema, provenance) now records that check in its delivery record's `refused_by`: the kind, and the rule id when a configured rule decided. A notification withheld for any other reason records none, and the frame a subscriber gets is unchanged.
- **An mTLS refusal's decision record names the policy rule that made it.** A refusal decided by a configured mTLS rule records a stable `rule_id`: `mtls:` and an HMAC of the configured rule under the same key the firewall and tool-policy ids use. The same rule keeps its id across restarts, and an edited rule gets a new one. A refusal with no client certificate, or with no matching rule, records kind `mtls` without a rule id. A disabled policy records nothing. On the direct route, a policy that refuses every tool on a backend still answers "not found", as before. Identity grants also get keyed ids, kept beside the grant rows so the grant digest is unchanged. A grant refusal records no id, because no grant decides a refusal.
- **An allowed call's decision record names the rule that allowed it.** Until now every allowed call recorded `default_allow`, whichever check let it through. The record now names the most specific rule that allowed the call, by kind and keyed rule id: a matched identity grant (with the operator's `grant_id`), then an mTLS rule, then a tool-policy allow-list entry, then a firewall rule. A firewall rule that softens a blocking finding to allow outranks a grant. A call no rule allowed, or one allowed only by a policy's default action, still records `default_allow`. Listings and silent rechecks note nothing.
- **`VerifiedIdentity` has read-only accessors.** The library's `key_server::oidc::VerifiedIdentity` now offers `subject()`, `email()`, `name()`, `groups()` and `issuer()`, and the gateway reads an identity only through them. The type and its checked constructor moved into their own module, re-exported at the same path; its fields are unchanged in this release step. Library users can switch field reads to the accessors now: a later change makes the fields private.
- **A replayed call's record says what its tool declares.** A completed call served again from its stored result (the HTTP and stdio meta routes, and a per-caller replay lifted after its live proof) now records `declared_effect` and `declared_effect_source` on its `replayed` decision, as a live call does. The effect is read when the replay is served, from the slot the first execution ran under, so an edited declaration shows on the next replay; a capability's comes from its live definition, as the replaying caller sees it. A backend tool's replay records no effect when its result ran under more than one slot, was stored before this change, or its slot, tool or backend is gone, never another slot's; a capability's needs no stored slot, and records none once its definition is removed or hidden from the caller. A continuation records none.
- **A direct call's record says what its tool declares.** A `tools/call` on `/mcp/{backend}` now records `declared_effect` and `declared_effect_source` on its decision, read from the slot the call runs under: the caller's own per-user slot when its identity is propagated, otherwise the shared one. A repeated keyed call answered from the idempotency cache records the caller's slot as it is when the answer is served; one answered from a completed execution records the slot that execution ran on, looked up as stored, never the replaying caller's or the shared slot's. A slot that cannot say records no effect. A direct call naming a capability provider is answered as absent and records no grant.
- **Every refusal and allow site's decision record is pinned by a test.** A decision fixture table now drives one concrete call per site that records a refusal kind (`allowed_tools`, `capability_disabled`, `not_found`, `routing_profile`) or an allow, on the meta route, its HTTP gate, the direct route (shared and per-user backends), task replay and a chain step, and checks the record's exact kind, rule id, grant id, findings, declared effect and freshness, plus the answer the caller gets. Each allow row also checks that removing only the allowing rule refuses the call. Tests only: no gateway behaviour changes.
- **Admins can create an API key through the web UI's API.** `POST /ui/api/keys` (admin only) takes the key's name, backends, tool lists, admin flag, rate limit, an optional expiry (kept to the whole second) and the `gateway.yaml` revision it was listed against. The gateway generates the secret, writes only its digest to `gateway.yaml`, and returns the secret once, with `Cache-Control: no-store`. Every create needs the audit log: the write is recorded there before the file changes, naming who created which key, and if that record cannot be written, nothing is. `GET /ui/api/keys` now answers `{revision, keys}`, so a create can name the revision it read. A create that is refused writes nothing and answers with fixed text, for example for a name already in use, a revision that is no longer current, or a key that would turn the gateway multi-user (restart required). When the gateway cannot tell whether the write happened, it answers `state_uncertain` with no secret, and the operator reads the key list before creating the key again.
- **A server's optional owner.** `backends.<name>.owner` records who looks after a server (free text, at most 200 characters once trimmed, no control characters, refused at load otherwise). The web UI's admin-only server view (`/ui/api/config`) shows it, read from the published config, so a reload that changes only an owner takes effect at once and restarts nothing. The open `/ui/api/status` never carries it.
The web UI's settings can be previewed and saved through two admin routes: `POST /ui/api/settings/diff` returns the masked change to gateway.yaml, and `POST /ui/api/settings` saves it in place, keeping every comment, and reports the reload and any setting that needs a restart.
- Added `GET /ui/api/settings/secrets/unused` and `DELETE /ui/api/settings/secrets/unused/{name}?store=files|keychain` for a gateway admin: the first lists the secret entries the index records that no source names (the config, its env files, the process environment or a capability file), with their store and write time; the second deletes one of them. The delete holds the reload, config and vault locks, re-reads every naming source just before the store delete, and refuses an entry any source still names, an entry a `file:` reference or a second hard link reaches, and any delete while a config write is unsettled. A listing reads only and never shows a value. On Windows a files-store entry is listed but its delete is refused, because the gateway cannot yet check the file's links there. On macOS and Windows a keychain entry is listed but its delete is refused for now, because the system keychain can finish a timed-out delete after the gateway has stopped waiting; on Linux keychain entries are deleted. A refusal with nothing attempted answers 4xx and a delete whose outcome is not confirmed answers 503; a settings save or delete refused because the config is being written, or because config reload is not enabled, now answers 409 (it answered 503); reads such as the listing keep 503 for an answer they cannot give right now.
- **Settings save: the Policies screen's switches.** The UI settings save path can now change `security.tool_policy.enabled`, `security.tool_policy.default_action`, `security.tool_policy.use_default_deny`, `security.firewall.credential_redaction`, `security.firewall.collusion.action`, `security.sanitize_input` and `security.ssrf_protection`, each previewed as a diff and written in place with comments kept, and each applied on reload without a restart. A relay detection action other than `off` still needs the firewall on and is refused otherwise; while the detector's own thresholds are being changed, the reload reports relay detection as needing a restart.
- **`GET /ui/api/policies`: the Policies screen's read model (admin only).** It returns the tool policy (its switches, the built-in default denies and each configured entry, each with its config path) and, for every deny entry, the allow entries that override all of it or part of it, decided over concrete server and tool pairs by the gateway's own matcher in both the bare and the `server:tool` spelling. It also returns the firewall's finding rules in order, each with whether the screen may edit it and why not, the earlier rules that shadow it for each scan type (only an unscoped `*` or identical-match rule that decides that type), and, for a rule scoped by key or server, the surfaces where that scope applies differently. In a build without the firewall, `finding_rules` is `null` rather than an empty list. Computed from the published config, read-only.
- **`GET /ui/api/policies` answers the rest of the Policies screen.** Beside the tool policy and the finding rules it now returns the six scan types the screen offers (each with the side it runs on, every precondition and whether it is on, and whether the type is produced at all), the anomaly, tenant and budget guards and the cross-tenant read verdict (each with whether it runs, which of its refusals no rule can soften and which findings the rules decide), the credentials pair (the redaction switch and whether the pinned `{match: "*", scan: [credentials], action: warn}` rule is present, where, and which earlier rules shadow it fully or partly), the relay settings (the action and what it does, the lists, the firewall precondition and the gate's inferred sensitive classes, read-only) and the four tool limits with where each is edited. Every setting carries both the file's value and the value the gateway enforces, so a restart-only change shows as waiting for a restart. Only the six offered scan types are editable, and shadowing is reported only for the types a rule can decide (`pii`, `budget_exceeded` and `collusion_relay` are decided elsewhere or not produced).
- **The audit log warns when the file it writes to was rewritten under it.** When the transparency logger finds that the log it extends is no longer the one it wrote (its active file was replaced, restored from an older copy, forked at the same counter, emptied, or cut shorter than the logger left it), it now logs a warning, `audit log: the log this writer extends was rewritten`, naming the check that found it (`tail` or `shrink`). A rotation, a retention expiry and a resync of an untouched log raise nothing. A disk-full failure in the middle of a rotation can also raise it once, with nothing rewritten.
- **The dashboard's live stream carries activity and config changes.** The web UI stream now sends each new transparency-log record as an `activity` event and each governance-log record as a `config` event, as they are written. An admin scoped to some backends gets the activity of those backends only and no config events; callers with full (unscoped) activity access get both, the same callers the activity list shows config rows to; a gateway with no governance log sends no config events. Within one run of the gateway, a reconnect that sends its last event id resumes after that record with nothing repeated or skipped; after a restart it starts from the current end of the log, and when that record has left the log it starts again from the oldest record still kept. A stream that falls behind catches up from the log files, and a stream whose key loses access ends at its next check.
- **The audit log keeps one identity and names a log it replaced.** Every audit log now carries a stable `log_id`, minted once at its first open under this version and kept across restarts and rotations. A new audit log now begins with an `audit_log_identified` record after its open record, carrying the log's id, so caller records start at counter 3; SIEM export forwards it and `audit verify` counts it like any other record. When the active file is lost and the gateway starts a new log, the new log's first record names what survived of the old one (its id, if the running gateway held it, and the last high-water mark, if `.hwm` survived), and `audit verify` prints that as a warning, marked unverified unless the chain check authenticated that record. `audit verify` now also prints its warnings when the chain check fails, and shows control, bidirectional and zero-width characters from the log as visible escapes.
- **Config-write outcome records have a bounded, fail-closed writer.** The audit logger can now settle a config-write record (an intent, an outcome, an abandonment, a deferral or a stopped delivery) into the log the write was bound to, synced, under the same 5 s permit and write bounds as other audit appends. It refuses a record bound to another log or one whose fields it does not accept, and reports a write it could not confirm as unconfirmed rather than written. Settle records use their own `settle.` kind namespace, which no other audit append may write, so a reader of a plain kind such as `save` never receives one. The config writer moves onto it in a later release.
<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

- Administer a running gateway with `mcp-gateway api METHOD PATH` using `MCP_GATEWAY_TOKEN`, JSON request data and responses, and distinct exits for HTTP, usage, transport and credential errors. The command reuses the dashboard client's target and TLS checks, and the documented stable UI API routes are checked for removal, renaming and method changes.
- Added admin-only API key revocation with revision and identity checks, durable audit recording, and confirmation that the key is no longer authorized.
- API key configuration can record a CLI key’s approving admin key and reported host. A CLI key stands only while its approver does, on every authorization path, and the Keys screen shows the binding and host. A CLI key, or a dashboard session minted from its link, cannot create keys, mint further links or change `auth.*` settings, so nothing it does outlives its approver. Ordinary keys retain their existing behavior.
- **Contributors: one build for all of a change's mutation proofs.** A scratch commit can wrap each mutated expression in `mutant!("ID", mutated, original)`; one build with `--cfg mutants` then carries every mutant, and each test process switches on at most one, named by `MCP_GATEWAY_MUTANT`. A normal build expands the macro to `original` alone (no runtime check, no environment read), and a test scan of every tracked `.rs` file refuses any `mutant!` call outside `src/mutant.rs`, so no mutant site can be merged. No change for users of the gateway.
- **Contributors: mutation batches in one build.** `scripts/ci/mutants/run_mutants.py` gains a `schemata` mode: a batch lists `mutant!` IDs and the test rows each must fail, and the mutants workflow builds once with `--cfg mutants`, checks the IDs against the library's site listing, runs the rows with no mutant on, then runs each mutant's rows one process per row. A mutant counts as killed only when every row fails at its listed file and line. Hosted mutant runs now queue one at a time and record their wait. No change for users of the gateway.
<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

- **Recent writes in the restart preview.** For an unscoped gateway admin, `GET /ui/api/gateway/restart` now answers `recent_writes: {count, complete_secs}`: how many calls that could change something left the gateway in the current second and the 60 before it, and how many of those seconds the count covers (fewer than 60 in the gateway's first minute). A call counts unless its tool declared itself read-only; repeats answered from a stored result, cache hits, refused calls and health probes do not count. The admin status view and its live stream gain a `restart` member for the latest restart attempt, `null` until a restart is attempted.
- **Grant reloads name rows changed outside the gateway.** A grant row whose digest differs from what its journal and audit records name is still recorded with no actor, and is now also logged at warn level with the grant file, the row and both digests; the reload's answer counts such rows (`; N changed outside the gateway`). **Library:** `UiDecisionRecord` gains `decision` (the new non-exhaustive `UiDecisionKind`: `decline` or `accept`; a record without it reads as a decline), `rows` and `expires_at`; only a decline closes refusals.
- **Web UI: deny an open access request.** `POST /ui/api/decisions/{id}/resolve` with `action: deny` records one governance audit event: action `mutate_grant`, the administrator as actor, their reason, and a `ui_decision` body naming the subject, the agent, the scope digest they were shown and the exact refusals it closes. The request leaves the To do queue at once and stays closed after a restart; a later refusal of the same capability opens it again, and it can be denied again. A retry with the same digest answers the recorded outcome and writes nothing. The caller stays refused. **Library:** `ControlPlaneAuditEvent` gains the optional `ui_decision` field, with the new non-exhaustive types `UiDecisionRecord` and `UiDecisionEntry`.

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
- **Undated cost, profile and breaker records on a host clock that reads before 1970.** `CostRecord.timestamp`, session `started_at`, `EnforcerSnapshot.taken_at`, profile `created_at` / `last_used_secs`, `WindowStats` totals and `CircuitBreakerStats.last_trip_ms` are now `Option` (`None`, serialized `null`, where the clock could not date them) instead of 0, `KeyCost::budget_status` answers a new `BudgetStatus::Unknown`, pool idle and breaker-open timing run on the monotonic clock, and an upstream cancel claimed while dark is written undated and sent once the clock reads. Affects 4.0.0 pre-releases only.
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
- Every capability, meta tool and backend tool is classified read-only or side-effecting as data: an explicit `metadata.read_only` in each capability YAML, a meta-tool effects table, and the declared rule for backend tools (an annotation or the operator list, else side-effecting). No client-visible change.
- The binary crate root is back under the 800-line file ceiling (#2514).
- The 4.0 highlights in the README, release notes and multi-user guide each cite the file or test behind the claim: `src/config/mod.rs` and `tests/mik_7214_acs.rs` (MCP 2026-07-28); `src/gateway/router/authorization.rs` and `tests/a0_per_caller_cache.rs` (per-caller access); `src/control_plane/role_mapping.rs` and `src/gateway/router/sso_admin_tests.rs` (SSO admins); `tests/d1_audit_required.rs` (audit); `src/config/features/api_key.rs` and `tests/e4_hash_key_cli.rs` (keys); `tests/c1_unrecognised_config_keys.rs` and `src/gateway/server/cleartext_tests.rs` (refusing to start; Windows by file access list: `src/config/secret_file_windows_tests.rs`); `deploy/helm/mcp-gateway/values.yaml` (Helm chart) (#2518).
- The release workflow test suite now fails if the published-release re-check is deleted or moved before publication (#2520).
- test: a 2026-speaking backend that refuses `initialize` and `ping` is visible to `gateway_search` and leaves its circuit breaker closed
- **A response too large to inspect for tenants says so.** When tenant attribution is configured
  (`tenant_guard.arg_keys`), a response whose text block exceeds the 1 MiB parse bound is still
  not parsed, and a reply refused for its signature chain is never read. The invocation record now
  carries `attribution: "uninspected"` for either, or
  `"cached_delivery_uninspected"` on a cache hit or replay, rather than naming no tenant. A new
  value of the existing field; see UPGRADING item 110. (MIK-7116.MIN.1)
- test: the mTLS listener, the stdio chain-nonce refusal and the anomaly-blocking firewall build are covered end to end; the coverage contract records tiers and counts integration tests
- A stdio gateway's `server/discover` answer lists `2026-07-28` in `supportedVersions` when `server.modern_protocol` is on, as an HTTP gateway's does. The setting is read once, at stdio start.
- docs: the 4.0.0 coverage contract assigns a tier to every critical path, inventories its security-enforcing functions, and grades them with `scripts/release/critical_function_coverage.py`
- test: the OAuth authorization-code flow, token refresh and callback telemetry are covered end to end against a mock authorization server
- An HTTP start with anomaly detection on and no source of a caller key is refused, naming both settings.
- Docs: the 4.0 upgrade guide states that legacy sessions expire on idle time and release their per-session state when they end (item 115). (#2563)
- **`ReloadContext::new` returns a `Result`.** It fails when it cannot pair the registry with
  the running config's destination policy; `ConfigWatcher::start` reports the same error. (#2597)
- **Transport tests.** The legacy SSE handshake, session capture on responses, the OAuth bearer on the wire and stdio start refusals are now covered by tests. Three transport trace events keep their fields on one line; their output is unchanged.
- Tests: each per-session store returns to empty once its sessions expire, and a call still running when its session ends leaves nothing after the grace pass. (#2601)
- **Coverage grader.** The Critical-function grader now counts a call in a tracing macro's head-line arguments as missed and lists it as unverifiable. The stdio response debug event now reports `pending_count` in place of `pending_keys`.
- **Task tests.** Upstream capture, read-time recovery and the descriptor preflight are now covered by tests that assert each refusal.
- Release tooling: the bot-review sweep also requires a ledger link for any bot review whose summary body may carry a finding no inline thread does. (#2618)
- **Bridge tests.** Tests now cover the input bridge's round-start deadline and its pass-through of gate refusals on both gate calls.
- Tests: the account router's sign-in, unavailable, expired and retry paths are asserted for the connections page, disconnect, start and connect offer. (#2623)
- Tests: five personal-accounts functions reach the 95% coverage line, covering the forced-refresh claim, the rotated-revision mark, key-literal refusal, revocation without a client secret and a refused code exchange. (#2624)
- **Task store refusal test.** The test of a store opened under an unwritable home now requires the store's own refusal with nothing created, and checks that its permission setup blocks directory creation as well as files.
- Release tooling: CI fails when the burndown tracker summary disagrees with the two ledger checks. (#2628)
- **Router log fields.** Six router log events (backend request, SSE connect, session delete, meta request, refused caller identity) compute their call-shaped fields before the event. Their output is unchanged.
- **Router guard tests.** Tests cover the origin guard's numeric-origin checks on a public bind and the response pass's refusal when a result has no policy target; seven guard log events (one in the direct guard, three in the origin guard, three in the response pass) compute their counts and values before the event.
- **Coverage runs no longer leave corrupt profiles.** Test children that run under a zero file-size limit write their profiles to a private temp directory outside the measured set. Probe children get time to finish writing their profiles before they are reaped. (#2639)
Router guards: the direct-route response firewall reads the tool name from the validated call and the origin check folds a hostless URL into its numeric-host refusal. No behaviour change (#2642).
- **Windows trusts SYSTEM and Administrators by SID value, not by SDDL text.** The Integrity-class check compared a rendered string per owner and per ACE; it now compares against two SIDs built once. No behaviour change. (#2643)
- A pull request into the release line that changes an image input (Dockerfile, `docker/**`, the smoke scripts, Cargo manifests, the Helm chart, `docker.yml`) builds and smoke-tests the image before merge again. Other release-line pull requests still build only after merge.
- **A refused grant-journal append on Windows now prints the PowerShell repair.**
  When the journal file's access list failed the integrity check, the error named the file but
  not the fix. It now prints the same icacls/PowerShell repair the secret-file check prints.
  (#2652)
- Tests: identity, task-intent, cost view, refusal-audit and direct-route router rows reach their coverage line; the tools/list result is built without an unreachable failure arm. (#2657)
- **Lighter tool lookups on each call.** Header mirroring and the output-schema fallback read the cached tool in place instead of cloning it, and an empty withheld-name map answers without hashing the tool name. No behaviour change.
- **No payload copy for a call sent once.** A backend call that will not be resent moves its parameters and headers into its one send instead of copying them. No behaviour change.
- **Legacy POSTs no longer allocate a notification channel.** A session opens its broadcast channel and buffer only when a stream subscribes. A POST that mints or resumes a session allocates no channel; only a mint allocates the session record. Peak memory under a session-less legacy client drops sharply. No behaviour change.
- Tests: the Windows task-store and account-store custody helpers reach their coverage line, covering absent, shared, wrong-kind and unnameable store paths and a parent that refuses creation. (#2673)
- Tests: the Windows child-environment allowlist test passes under coverage, and the coverage contract requires a failure-free Windows run and names the task SDK setup. (#2686)
- Tests: the stdio transport's handling of an id-less response is covered, and its parse log line is measurable by the coverage grader. (#2694)
- Tests: the OAuth redirect hop reads the destination policy's refusal as an option, with no unreachable error arm. (#2699)
- A capability that declares `auth.required: true` is listed only once its key is set or its `oauth:` provider has a login; calls to a hidden capability by name are unchanged.
- docs: the release scope status grades verbatim relay detection (GH1945.COLLUDE.1) met on the meta and direct routes; ASI10 stays PARTIAL (#2722)
- Tests: an installed account holds its minter as one enum and revalidation is one ordered match, with the revalidate refusals covered. (#2724)
- Tests: the journey owner API and the offer attach refusals are covered, and journey create binds its limits with the bridge check. (#2734)
- tests: the upstream-followed task result is pinned as a relay source for verbatim relay detection (#2739)
- MCP Events search entries: the event entries now join the finished `gateway_search_tools` and `gateway_search` answer in one place; the answers are unchanged (#2744).
- Internal: Code Mode chain execution moved to its own file; no behaviour change.
- Tests: the task store refuses as unavailable when its lease cannot be created. (#2746)
- `mcp-gateway cap list` marks a capability the gateway would not list with `off: needs <KEY>` or `off: needs a <provider> login`.
- Refactor: the direct backend route is split into ordered stages with the same behaviour and the same refusal order; the t8 guard scans every direct-route file and pins the stage order. (#2752)
- Tests: the C6 mutation sample draws from a frozen sampling frame, and the direct route stages are graded as Critical rows. (#2756)
- An answer's cross-tenant read verdict rides its `response_delivery_attempt` record on `POST /mcp`, cutting the extra audit record per judged answer.
- performance: the gateway binary now uses mimalloc as its global allocator. On the workload benchmark, in two same-run interleaved runs of 30 repetitions on a shared host (not graded runs), p50 per call dropped by 9.7 and 6.6 microseconds; p99 dropped by 17.3 microseconds in the first run, and in the second the change could not be told apart from none (its interval spans zero); peak memory grew by about 5 to 6 MB (#2762)
- performance: the HTTP dispatch reads a request's params in place instead of copying the whole payload per call (#2763)
- **Stdio backend messages are limited to 16 MiB by default.** Before this, there was no limit. A backend that legitimately sends larger single messages sets `backends.<name>.max_frame_bytes` (64 KiB to 1 GiB). See UPGRADING item 137.
- **Public capability counts only capabilities that run.** The count is 135, not 137: `pyghidra_reverse` and `trawl_extract` load but are held, and `cisco_scanner`'s `scan_mcp_server` operation is not offered. They are named, with reasons, in `capabilities/README.md`.
- Refactor: task creates and transitions have separate commits, so no caller keeps an arm for an outcome that cannot happen. (#2780)
- test: the shutdown-race backend test waits for the child's pid file instead of a fixed sleep, so it no longer fails on a loaded or instrumented host (#2794)
- firewall: the observed-relay warning ("Firewall: relay observed") now always logs `server` and `tool` (the direct route logged `backend`, a catalogue read logged `method`); alerts keyed on the old field names need updating (#2795)
- test: the signing stdio coverage probe recognises a child's profile when Windows reuses its process id (#2807)
- **`OidcError` has three new variants.** `mcp_gateway::key_server::oidc::OidcError` gained `InsecureIssuer`, `InsecureFetch` and `ClientUnavailable` since 3.5, and the enum is not `#[non_exhaustive]`: an embedder's exhaustive `match` on it no longer compiles. Add the three arms or a wildcard arm (UPGRADING-4.0 item 138).
- test: the shutdown-race backend test gates its child on a release file instead of a timed sleep, and the Windows coverage fallback uses PowerShell syntax (#2813)
- **Hardened signing now covers stdio.** Under `security.posture: hardened`, `serve --stdio` signs and nonce-checks every `tools/call`, not only `gateway_invoke`, as HTTP does; send a fresh nonce in `params._meta["io.mcp-gateway/nonce"]` per call (UPGRADING-4.0 item 112).
- test: the bounded audit-log contention test now holds the stalled write inside its bound and asserts the contenders queued on the permit instead of being refused (#2845)
- test: the bounded audit-log contention test releases its callers through one barrier on a paused clock, so every caller queues on the permit before any deadline passes and the test no longer depends on runner speed (#2863)
- Tests: stdio delivers a response or a progress frame only to its own caller, and a frame carrying any method is never taken as a reply. (#2879)
- test: the T32 retry test kills the gateway while the receiver holds an attempt open, so it sees exactly five deliveries every run, and store tests pin that a crash after a claim spends that attempt (#2881)
- tasks: a failed upstream task whose error is the peer's own is stored as task record version 6, written only on such rows; a gateway that reads versions up to 5 refuses a task store holding one, so back up `tasks.store_dir` before upgrading; a backup taken after holds version 6 rows too (UPGRADING-4.0 item 105)
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
- A capability whose declared output root is not object-shaped (an array, a string, a type list such as `["object", "null"]`, or a typeless root without `properties`) now advertises an object `outputSchema` and publishes `structuredContent` under `items`, as MCP requires; the text content is unchanged. Nine shipped capabilities are affected, among them `sentry_list_issues`, `hackernews_top` and `number_facts`.
- MCP events: an event source can exempt an event type from the per-delivery budget charge; no shipped source does yet. It lets the operational source report an exhausted budget without charging it. (#3099)
  Affects: 4.0.0 pre-releases only. Operator action: none.
- **No idle flush task, and one trust card per tool version.** A grant-decision slot that decided nothing no longer spawns a flush task. A `tools/list` reuses each tool's trust-card reference while the tool is unchanged instead of recomputing it every time. (#3182)
- **Grant-decision records name the authority.** A decision record's `who` now carries the grant subject's authority as well as the subject. (#3182)
- **A refused answer keeps its request id without being read back.** When a grant-decision write fails after dispatch, the replacement -32005 answer carries the id recorded when the request was parsed. The gateway no longer buffers the replaced answer to find it, so an answer of any size keeps its id. (#3182)
- **A repeat `tools/list` re-serialises no tool.** The trust-card memo now keeps each projected descriptor and reuses it while the tool is unchanged, compared field for field, instead of serialising and deep-comparing every tool on every list. (#3279)
- **A repeat `tools/list` compares each tool schema once.** The trust-card memo now checks every tool field by name and walks each schema a single time, instead of a derived comparison followed by a second sign-of-zero walk. (#3296)
- **Fewer per-call copies on the request path.** The firewall's input scanner parses its free-text key override once per published env overlay instead of on every scan, and backend request metrics take a shared label instead of copying the backend name on every call. What is scanned and what is exported are unchanged.
- **A repeat meta `tools/list` recomputes nothing.** The meta tool list is built once per input set and its trust cards are projected once per list, then reused by identity. A list with any input changed is built and projected afresh. What is listed is unchanged.
- **A session is fingerprinted once.** The log-safe fingerprint of a streaming session id is computed when the id is made and read on every later request, instead of a SHA-256 per request. Logged values are unchanged.
- **The closed-keys schema check does less work per call.** A scalar argument skips the per-call memo, and a schema level is checked for matching no object once instead of once per key. Verdicts are unchanged.
- **`doctor` lists advanced settings.** `mcp-gateway doctor` now shows an "Advanced settings" line naming each key in your `gateway.yaml` that 4.0 leaves out of the configuration reference (tuning values the gateway manages itself). Each value you set is still applied; nothing needs to change. `mcp-gateway init` no longer writes `meta_mcp.cache_ttl`, whose value equalled the default.
- **One `url` key per backend.** A backend's address now takes a single `url` key; its scheme picks the transport (`http://` or `https://` for HTTP, `ws://` or `wss://` for WebSocket). `http_url` and `ws_url` keep working. Run `mcp-gateway upgrade` to rewrite them as `url` in place: it keeps every comment, lists the lines it changed, and changes nothing on a second run. It works on the file `--config` (or `MCP_GATEWAY_CONFIG`) names, and stops with an error, upgrading nothing, if that file does not exist. A backend it cannot edit (written in flow style, for one) is named for a hand edit. Every writer (`mcp-gateway add`, the setup wizard, `init` and the web UI) writes `url` for a backend it adds and keeps `url` where you wrote it; a backend whose value is not an address of its key's scheme keeps `http_url` or `ws_url`, since `url` would change its transport. Setting `url` beside `http_url` or `ws_url` is refused, naming both. A backend that ends up with two transport keys once the file and the environment merge (say `http_url` in the file and `MCP_GATEWAY_BACKENDS__<NAME>__WS_URL` in the environment) no longer loads: before, the second was dropped without a word; now the error names both keys, and you keep one. `MCP_GATEWAY_BACKENDS__<NAME>__URL` is refused too, naming the `__HTTP_URL` and `__WS_URL` variables that work.
- MCP Events: a webhook subscription whose event type a capability reload no longer offers, or no longer fully serves (a filter key or payload field it relies on is gone), is now held instead of deleted. A held subscription receives nothing, its queued records still drain, and it resumes on its own when the route serves it again; otherwise it ends at its lease or at the configured maximum lifetime from when it was first held. A refresh of a held subscription is accepted and answers `held` with the reason, the key and when it ends. The cap refusal lists the caller's held types, and `GET /ui/api/events/held` (admin) lists held subscriptions per type. The 30-second withdraw grace pass and its test environment variable are gone.
  Affects: 4.0.0 pre-releases only; 3.x has no MCP Events. Operator action: none.
- MCP Events: a REST watch subscription whose capability is removed, becomes side-effecting, or moves to another credential class is now held instead of deleted. Its poller makes no call while the subscription is held and resumes it when the capability is watchable again. A held watch keeps its sharing class and key across restarts, and a refused credential still ends the subscription.
  Affects: 4.0.0 pre-releases only; 3.x has no MCP Events. Operator action: none.
- **`cap search` and `cap registry-list` take `-C` for `--capabilities`.** The global `--config`
  also answers to `-c`, so on these two commands the short flag meant two things: a debug build
  panicked, and a release build read it as `--capabilities`. They now use `-C`, as every other
  command does, and `-c` means `--config` everywhere.
  Affects: 4.0.0 pre-releases and 3.x. Operator action: a script passing `-c <dir>` to either
  command passes `-C <dir>` or `--capabilities <dir>`.
- **Library: config writes have a locked editor; the whole-file writers are deprecated.**
  `config_persistence::edit_config(path, mode, edit)` and `edit_config_text(path, edit)`
  load, edit and write `gateway.yaml` under one hold of the config lock and keep its
  comments where they can; the new public `CommentLoss` mode says whether a write that
  would drop comments is refused or rewrites the file. `write_config`, `write_config_text`
  and `config_reload::write_config_and_reload[_outcome]` are deprecated (removal in 5.0):
  each replaces the file from the caller's copy with no concurrency check. See UPGRADING.
- CI guard `timing-asserts`: the last tests that told outcomes apart by a short wall-clock window now read an event or outcome, and the guard's allowlist shrinks from 15 rows to 3. Contributor-facing only; no runtime change. (#3694)
- **With auth on, the audit log is on by default.** An authenticated config no longer needs
  `security.transparency_log.enabled: true`. With auth on, no section puts the log at its default
  path, and a section that sets only `path` puts it at that path. Writing `enabled: false` with
  auth on still fails the load. With auth off nothing changes: the log stays off unless
  `enabled: true` is written, whatever `path` says. Commands that rewrite the config do not add
  the line.
  Library code: `security.transparency_log.enabled` is now `Option<bool>`; set it with
  `Some(true)` and read it with `is_enabled(auth_enabled)`.
  Affects: 4.0.0 pre-releases.
  Operator action: none.
- CI guard `timing-asserts`: it now also refuses a test `timeout` under 5 s, or with a window it cannot read, whose expiry fails the test, and the 27 existing ones are widened to hang bounds. Contributor-facing only; no runtime change. (#3710)
- Tests: the f24 tools-changed delivery test waits up to 120 s for an expected announcement instead of 20 s, and the stdio EOF rows handshake under their 30 s timeout before shortening it, so neither fails at random under full-suite load. No runtime change. (#3715)
- **Per-call work cut further.** With no transparency log, an answer is no longer copied
  into an audit value that nothing reads. A stdio backend's reply is parsed in one pass
  instead of being buffered and parsed again. `initialize` no longer copies every
  capability's schema to build its guide. The dispatch path skips an empty grant-slot wrap.
  Behaviour is unchanged.
- Tests: the stdio and HTTP periodic cost-save tests catch up a save tick skipped while an earlier save still held the write lock, so they no longer fail at random under load (seen on Windows coverage runs). No runtime change. (#3722)
- Internal: `protocol_revision_telemetry` is split into a directory module (durable window, observation, tests in their own files), and its file-size allowance is removed. Move only; no behaviour change. (#3728)
- **`accounts.schema_version` may be left out, and `validate` colour follows the terminal.** An
  `accounts` block without `schema_version` loads as `accounts.v1`, the only accepted value.
  `mcp-gateway validate` colours its output only on a terminal with `NO_COLOR` unset or empty, so piped
  output is plain without a flag. `--no-color` still forces plain output and is hidden from
  `--help`.
  Affects: 4.0.0 pre-releases.
  Operator action: none.
- **Backend error replies are parsed by one parser.** A stdio backend's `error` member is now
  parsed by the same JSON value parser as every other member, instead of a hand-written copy
  of it. Replies classify exactly as before, including at the nesting limit.
- Tests: a committed test forces a periodic cost-save tick to be skipped under a held write lock and checks the next tick catches it up. No runtime change. (#3734)
- **The gateway stops re-scanning the same catalogue.** Every tool-list answer used to run all
  egress content classifiers over the full catalogue again, about 1.2 ms when the text holds a
  non-ASCII character. A small bounded memo keyed by the exact text now reuses the scan, so a
  repeated answer costs about 10 µs. Findings, refusals, logs and policy decisions still apply
  on every answer.
- Internal: session expiry reads the runtime clock, the one the session reaper already ticks on. Production timing is unchanged; tests can now drive a session TTL on a paused clock. (#3739)
- **A file split no longer trips the file-size ratchet.** A new baseline row for a file over
  800 lines is accepted when a `# moved-from <path>` line above it names a listed file that
  shrank or left in the same change; the total excess still may not rise and a listed file
  still may not grow.
- **The macOS test-exclusion check reads a gate as a cfg predicate.** It evaluates each
  `cfg`, `#![cfg]` and `cfg_attr(.., ignore)` on macOS and Linux with all features, so a gate
  that names Linux but also runs on macOS is no longer listed, and one that names macOS but
  requires Linux is.
- CI: the timing guard judges every span a pull request adds or changes at a 10 s floor. A shorter window, a sleep or an expected-elapse timeout used as a window, a paced loop, a poll whose count times interval is under 10 s, or a short product timer slept against on the real clock is refused unless it uses the 30 s `HANG_BOUND` or carries a closed-set reason tag. Four window-shaped rows now wait on events, so they no longer fail at random under load. Adds `HANG_BOUND` to the doc-hidden `gateway::test_helpers`. No runtime change. (#3746)
- Internal: the 4.0 surface inventory lists `meta_mcp.prompts_resources_fetch_timeout` as INTERNAL, not AUTO, with the bounds the gateway already applies: each request to a backend is bounded by that backend's `timeout`, and a whole prompts or resources fetch by 10 s unless set. No behaviour change. New tests drain two pages whose total exceeds the backend timeout and list both pages. (#3750)
- **The `mcp_gateway` Rust library is internal and unsupported as of 4.0.** Every crate-root item
  (all 54 modules, the `Error`/`Result` and offline account-store re-exports,
  `MCP_PROTOCOL_VERSION`, `setup_tracing`) is `#[doc(hidden)]`, and docs.rs lists none of them.
  Paths still compile where they did, but carry no stability promise and may change in any
  release. The supported surface is the binary, its configuration and its HTTP and MCP interfaces. An
  embedder relying on library items should open an issue. See upgrading.d/8044-5.md.
 
- `--help` lists only what 4.0 keeps: the internal commands `kubernetes`, `ranking`, `runtime` and `trust` and the `-C/--capabilities` flag of `skills generate` and `tool invoke`, `list`, `inspect` and `completions` are hidden but still run and parse, and `add`, `remove`, `list` and `get` read the global `--config` instead of declaring their own (#3755).
- Internal: a route x check matrix test states, for every entry route of a backend `tools/call` (`/mcp` by `gateway_invoke` or surfaced name, `/mcp/{name}`, task submit and worker, stdio), which security check stages apply. It pins today's per-route gaps to the tickets that close them, so a later fix must update it. Test-only; no behaviour change. (#3756)
- **No remaining runtime clock read stops the gateway on a host clock before 1970; library calls that need a time return `Result`.** Firewall audit rows (request, response and dispatch) and transparency-log segment open records are written undated (`timestamp: null` with `clock_invalid: true`; `segment_opened_at: null`, and an undated segment rotates by size only), where a dispatch row used to carry the epoch. A personal-account dispatch and an identity-grant change are refused before anything moves, and the CLI's `identity grants` and `trust lab` commands exit non-zero naming the clock. `Task::create`, `Task::complete(&Value)` and `Task::fail(&JsonRpcError)` return `Result` (the outcome is passed by reference, so a refused call loses nothing), `TaskModelError` is `#[non_exhaustive]` with `ClockUnreadable`, `complete` with a non-object result now returns `Err(InvalidInput)`, `CatalogTrustLab::evaluate_card` returns `crate::Result`, and `EraObservation::from_outcome` takes `Option<DateTime<Utc>>`. Affects 4.0.0 pre-releases only.
- **Three more refusals of a signed call give its nonce back when nothing it did had acted.**
  The idempotency guard's refusal of a call whose key cache is full, the undeclared-argument refusal, and a
  chain step's dispatch-time policy refusal kept the signing nonce spent, so the honest call re-sent under
  that nonce was refused as a replay. They now follow the same rule as the relay refusal: the nonce stays
  spent if a credential was minted, a tool list was fetched from the backend or an earlier chain step was
  sent first.
  Affects: 4.0.0 pre-releases only. Operator action: none.
- **More refusals of a signed call give its nonce back when nothing it did had acted.**
  A stdio task call the task surface refused (no idempotency key, tasks extension not declared), a
  discovery call refused for its arguments (`gateway_search`, `gateway_search_tools`,
  `gateway_list_tools`), an unkeyed `gateway_execute` or `gateway_run_playbook` refused before it ran
  anything (an empty chain, a missing or malformed tool reference or arguments, an unknown playbook,
  a plan refused under enforced attestation), and a playbook step refused by its dispatch-time policy
  kept the signing nonce spent, so the honest call re-sent under that nonce was refused as a replay.
  They now give it back. An undelivered confirmation question now follows the same rule as every
  other refusal: the nonce stays spent if a credential was minted, a tool list was fetched from the
  backend, a confirmation grant was consumed or an earlier step was sent first.
  Affects: 4.0.0 pre-releases only. Operator action: none.
- **Per-call work cut further.** Judging whether a backend still offers a tool no longer
  copies the tool's whole listed definition, schema included; a `gateway_invoke` made two such
  copies per call. Reading a request's protocol fields no longer parses JSON-pointer paths, which
  allocated on every call. Behaviour is unchanged.
- **Per-call work cut further.** Checking a tool against a backend's catalogue that is still
  fresh no longer reserves the backend connection, arms a fetch deadline or builds fill state;
  a stale or empty catalogue is still fetched exactly as before. Behaviour is unchanged.
 
- **BREAKING: a backend's `secrets:` rules now apply on every route, and a rule the gateway cannot deliver safely is refused at load.** `inject_as: header` sent no header; `inject_as: query` put the secret in the tool call's arguments as `__query_<key>`; on the per-backend route `/mcp/{name}` no rule applied at all; and a config reload's rules took effect only after a restart, so a removed rule kept sending its secret. Rules are now applied where the backend's call is sent, on `gateway_invoke`, `/mcp/{name}` and tasks alike, and a reload's rules apply on the next call. The secret goes only into the copy that is sent: the gateway's own records, caches and stored tasks keep the arguments the caller sent. A backend that echoes the secret back in its answer is a separate matter, handled before release. The load now refuses a `query` rule, a `header` rule on a stdio backend, on a required identity binding, naming a header the gateway or the backend's own credential sets, or duplicating another header rule, and any rule on an A2A backend. Each message names the backend and the rule; see UPGRADING-4.0, "A backend's `secrets:` rules apply on every route".
  Affects: every release with `secrets:` rules. Operator action: a config the load refuses changes the rule as its message says.
- **The control-plane radar shows file names and URL origins.** For a server found in an MCP client's config file, the radar now shows the config file's name, not its full path, and the URL's origin, not the full URL, as `GET /ui/api/discovery` already did. A full path can name a user and a URL path can carry a token; the file is still one click away in its client.
- The key server's per-identity token cap holds under concurrent mints: a mint reserves its slot before the token exists, and the token is valid only once the mint finishes. Revoking an identity mid-mint cancels the mint (403); a mint that outlives its 30-second reservation answers 503 with Retry-After 1.
- Breaking (library): `TokenStore::insert` is removed in favour of `reserve`, `activate` and `abort`; `InMemoryTokenStore::new` takes the cap and token lifetime and the type no longer implements `Default`. See UPGRADING.
- Each key mint now writes a `token.issued` audit row (subject, issuer, `email_hash`, never the email) and waits for it to reach disk before the token is valid. With a fail-closed audit log a mint whose row cannot be confirmed answers 503 with Retry-After 1 and issues no token; with best-effort it goes on and counts `mcp_key_server_issuance_rows_total`. Keep the audit volume durable. See UPGRADING.
- **The activity list, export and receipt now agree on which delivery record belongs to a call.** A record reaches a call only if it lies within 256 KiB of log after the call's line; before, the three could answer differently and the list answer changed with the page size. A call whose record lies beyond the window reads `no_record`, and the list response and export manifest report how many such calls there were (`delivery_beyond_window`) and the window (`delivery_window_bytes`).
- Changed the admin email lookup to page with a sealed token: the next page is asked for with the cursor alone, so the email is sent once and never again. The token carries the keyed hash and window, is bound to the caller's credential (a dashboard session to its own session), expires in five minutes, and serves one page; any token that does not open gets one fixed 400.
- The install instructions now say `cargo install --locked mcp-gateway`, which builds the exact dependency versions the release was tested with. A new check installs the packaged crate without its lock file, as `cargo install` without `--locked` does, and starts it with the key server, whose startup refuses when the email-hash normalization moved; it runs on every release-line push, nightly, and must pass before a release publishes.
- test: a killed response stream re-issued under a new id executes a side-effecting call once, and leaves a read-only call unaffected
- **Windows test gates state their reason.** Every test-side `cfg(unix)` gate now carries a one-line comment naming why the test is unix-only (mode bits, uid or inode identity, symlinks, process reaping, child environment). One cross-platform test (OAuth temp-file cleanup) lost its Unix gate and now runs on Windows; no product change.
- **A task notification carries the full task.** `notifications/tasks` now carries the task as `tasks/get` would return it to that reader, built at delivery: output states are re-authorized per reader against the reader's current credential, grant decisions and relay receipts are recorded as a read records them, and the frame is written to the transparency log as sent. A reader refused, or whose task cannot be read, gets the task id and status only.
- **A `gateway_invoke` call copies its arguments less.** A call over HTTP used to deep-copy the
  tool arguments five times on its way to the backend; it now copies them twice (one working
  value, one outgoing request), and so does a call over stdio. Large arguments cost less memory
  and time per call. Behaviour is unchanged.
- **Six config keys that never had an effect are refused at load, and `mcp-gateway upgrade`
  removes them.** `backends.<name>.idle_timeout`, `backends.<name>.circuit_breaker`,
  `marketplace`, `server.request_timeout`, `server.ws_port` and `cost_governance.currency` used
  to load with a warning; the refusal now names each one, says why it went and points to
  `mcp-gateway upgrade`. A key repeated elsewhere in the file no longer switches off the check
  of backend keys. See upgrading.d/8044-2.md.
- **`mcp-gateway upgrade` replaces each plaintext `auth.api_keys[].key` with its `key_sha256`
  digest**, so a 3.x config loads after one run and the same keys still authenticate. A key
  held in `env:`, `file:` or `${...}` is never read; it is named for a hand fix with
  `mcp-gateway hash-key`. The report names entries and lines, never a key or a digest.
 
- **`mcp-gateway upgrade` never exits 0 on a file the loader cannot parse, or that still
  carries a removed or plaintext key.** It names each key it could not remove or hash (the
  version stamp and data migrations still run), and for a file it cannot parse it names the
  line and column and changes nothing. See upgrading.d/8044-3.md.
- **Library: `mcp_gateway::cli::invoke::ToolCatalogue::load` takes a list of directories**
  (`&[&str]`) instead of one, reading them in order: one that cannot be read is skipped with a
  warning, and a later definition of a name replaces an earlier one. A one-element slice reads
  one directory. `build_completion_tool_names` is removed. The library is internal to the binary
  and carries no stability promise.
- **Plan steps over 1 MiB, and steps staged once a plan holds 1 MiB, are now covered by relay
  detection.** Such a step is capped at staging, so its text used to leave no trace: a relay of
  it went unseen, and its holder was refused for relaying text it had itself received whenever
  another caller held that text whole. The step now keeps a bounded fingerprint sample and a
  compact filter in place of its text. Once the plan's answer is known, the text the answer
  delivered from the step is evidence, and its holder is excused for it. In a 2 MiB step a
  200-char relay is missed about 31% of the time (before, always). The attachments count
  toward the plan's staging bound and the global sketch budget; a step that finds no room is
  skipped (`bound="plan_step_fps_skipped"` when the plan is full, `bound="sketch_refused"`
  when the sketch store is) and its holder's refusal names lost room, not a relay. An excuse
  selection past its reserved room is dropped and counted (`bound="sketch_overfull"`). Plan
  answers over 1 MiB are covered too; see the added entry.
- **Library types change for a host clock that reads before 1970.** `ToolInvocationAudit.timestamp` (the agent tool audit) is now `Option<String>` and a new `clock_invalid` flag is set; the audit JSON reads `"timestamp": null, "clock_invalid": true` only on such a host and is unchanged otherwise. `TokenInfo::from_response` is replaced by `TokenInfo::from_response_at(.., now)`, which dates a token from the clock reading its request was checked against. `TokenStore::live_jti(&self, jti, now: u64)` and `TemporaryToken::is_expired(now)` judge a key-server token on a clock reading the caller supplies, so one access check judges every credential on one reading; an implementor of `TokenStore` must judge on that `now` and not read the clock. Affects 4.0.0 pre-releases only.
- **A signed `gateway_invoke` refused by relay detection gets its nonce back when nothing it did had acted.**
  Relay detection refused the call and kept its signing nonce spent, unlike the spend budget, a refused retry
  or the request firewall, so the honest call re-sent under that nonce was refused as a replay. It now follows
  the same rule: the nonce comes back only if no credential was resolved, no tool list was filled and no
  continuation was consumed first. Separately, a signed chain resume refused after its resume handle was
  spent (for example by the spend budget on the pending step) now keeps its nonce spent; before, it was given
  back although the handle was already consumed. Re-running such a chain runs its completed steps again;
  check what they did before re-running one that is not idempotent.
  Affects: 4.0.0 pre-releases only. Operator action: none.
- **A surfaced tool on a per-user passthrough backend is always sanitized.** With `security.sanitize_input` on, a call by a surfaced tool's own name to a per-user backend (identity propagation) is no longer exempt from input sanitizing, even when the backend is `passthrough`; a null byte in its arguments is refused and other control characters are stripped, as for any other backend. Exempting it let the answer show whether the caller's own catalogue has the tool. `gateway_invoke` and `gateway_execute` targets keep the passthrough exemption. See `upgrading.d/8356.md`.
  Affects: deployments with `sanitize_input` on and a per-user `passthrough` backend whose tools are surfaced. Operator action: none; call such a tool through `gateway_invoke` to keep the exemption.
- Config validation refuses a `capabilities.name` equal to a registry backend name, and CAP-003 refuses a capability `schema.input` that is a string, number, boolean or list, so the loader skips that capability. A missing, `null` or `{}` input schema still loads. `cap discover --write-config` skips a discovered server named like `capabilities.name` (the default export name, `gateway`) with a warning. See UPGRADING.
- **A keyed chain with a step missing on a per-user backend now runs its earlier steps, as it does on a shared backend.** A keyed `gateway_execute` chain (one that carries an idempotency key) whose step names a tool missing from the caller's own catalogue used to be refused whole before any step ran. Now each step is judged when the chain reaches it, so earlier steps run and the chain stops at that step with the missing-name answer. Per-user and shared backends now answer alike, and a step the caller may not see answers exactly as a missing one.
  Affects: clients that send keyed chains to per-user backends.
  Operator action: none.
- **A signed direct-route call that fails at the send keeps its nonce, as on `/mcp`.** Before, the direct route gave
  the nonce back when the backend could not be reached or refused before the send (open circuit, rate limit, identity
  slots exhausted, connect failure, backend unavailable, a login in progress). A start attempt cannot prove that no
  bytes left, so both routes now keep the nonce for every such failure; re-send under a fresh nonce.
  Affects: 4.0.0 pre-releases only. Operator action: none.
- On `/mcp`, a meta-tool reply's `_meta.provenance` receipt now sits in the outer `result._meta.provenance` instead of inside `content[0].text`.
- A backend that lists the same tool more than once in one `tools/list`, with conflicting hints, gets the stricter reading: the tool is retried only if every occurrence of it marks it read-only or idempotent, and answered from the response cache only if every occurrence marks it read-only.
- **`ImportedSkill.extra` values are now `serde_json::Value`.** A skill's extra
  frontmatter fields were the YAML parser's own tree type, the only YAML type in
  the crate's public API; they are now JSON values, so the later YAML backend
  swap stays out of the public API. A YAML tag `!t v` is the one-entry map
  `{"!t": v}`, boolean, integer and finite float keys become strings, and
  null, non-finite float, sequence, mapping and tagged keys drop their
  entry. A skill with a null, non-finite float, sequence, mapping or tagged
  key inside an extra field now registers with that entry dropped; before,
  `save` failed with "key must be a string" ("float key must be finite" for a
  non-finite float key). `skills.json` holds the same values after parsing;
  keys inside an extra value are now written sorted instead of in document
  order, and two keys that stringify the same are written once.
  Affects: Rust callers reading `ImportedSkill.extra`; CLI users see only the fix.
  Operator action: none; see UPGRADING for the API change.
- A playbook step whose tool result has `isError: true` is now a failed step that follows `on_error` (abort, continue, retry) instead of a completed one. A step that meets a busy managed-account custody ends the playbook instead of being null-filled: with the retryable error when nothing in the playbook was tried before it, and with a non-retryable error otherwise. `on_error: retry` no longer retries tool-reported errors (a call that failed in the gateway is still re-sent; keyed calls replay its stored failure), and a tool's text is kept out of the error message (at most 256 characters plus a cut marker, in the error's data). See UPGRADING.
- The input sanitizer (`security.sanitize_input`, on by default) no longer rebuilds a clean request: it now edits the request in place and copies only what it rewrites. Sanitizing a clean 1 or 3 MiB `tools/call` allocates a fixed amount (it allocated about 9 MB and 27 MB), so a refused 1 MiB call no longer costs about 9 MB more with the sanitizer on. An object with a key to rewrite is rebuilt by moving its members instead of copying them, so one control character in an argument key no longer buys a copy of everything beside it (it cost about 5.8 MB at 1 MiB). What it refuses and rewrites is unchanged. Measured on the router test fixture (body in one chunk, firewall off). Known limit in 4.0.0: rebuilding one very large flat object with a key to rewrite still allocates its index in proportion to its number of keys.
- **The filesystem, memory and sequential-thinking reference servers move to 2.0.0.** `mcp-gateway add` and `init` write `@modelcontextprotocol/server-*@2.0.0` instead of 1.0.0, the last release of upstream's legacy line. Their registry descriptions say "(Node 24+ recommended)": 2.0.0 recommends Node.js 24, and runs on Node 22 without a warning from the gateway. The filesystem server keeps its command-line folders, because the gateway offers its backends no MCP Roots. Configs already written keep 1.0.0; `upgrading.d/8511.md` has the steps to move one, including memory's graph.
- **The gate-day client run now works beside a running gateway.** The release procedure's BUILD.1 client step gives its verify gateway its own task store and its own HOME, so it no longer collides with, or reads the data of, the operator's running gateway. It checks the `claude` login first with `claude auth status`, which makes no model call, and pins the client with `DISABLE_AUTOUPDATER=1`. The run's record names the client version that actually ran. Its PASS check now requires the client's own `gateway_list_servers` call to have succeeded with a non-empty result, read from the client's stream-json output. The client and the verify gateway run outside the frozen worktree, and the step fails if that worktree changed or its HEAD moved during the run.
  Affects: the release procedure only; no shipped file changes.
  Operator action: none.
- **Bound anonymous callers now receive continuations on the direct route.**
  An anonymous caller that carries a passthrough identity binding now receives continuations
  on the direct route (POST /mcp/{name}), as on the meta route, charged to the shared
  anonymous/public quota. Unbound anonymous callers are still refused on both routes.
- **One redirect limit: five redirects followed, outside the OAuth client.** The SSRF redirect check, the HTTP transport, capability calls and capability discovery stopped after four redirects although each said five; they now follow five and refuse the sixth, as the OIDC fetches already did. The OAuth client keeps its own limit for now. The capability registry install and the spec import with SSRF protection off followed reqwest's default of ten; they now follow five, and the registry checks each hop against the SSRF policy, pins DNS, ignores an environment proxy and gives up after 30 seconds. `mcp-gateway stats`, the `mcp-gateway doctor` probes and `mcp-gateway skills import <url>` follow no redirect: each reports the redirect and the host it points to, never its path, query or credentials. See UPGRADING-4.0.
- **The capability response cache is bounded.** It kept every response whose key was never read again for as long as the gateway ran; it now holds at most 10 000 entries (exceeded by up to the number of concurrent writers until the next store evicts back), evicting expired entries first and then the oldest. Each cache has its own bound: `cache.max_entries` still bounds only the Meta-MCP response cache, not this one. Which capability responses are cached, their TTL and their key are unchanged; the two caches now use the same cache code.
- The security finding severity enums are now one type, `mcp_gateway::security::Severity`; the firewall's severity gains `Critical` (blocks, like High).
- `DivergenceRecord` now uses `mcp_gateway::runtime::Substrate` for both sides; `SubstrateTag` is removed. A serialized record spells its substrates `gvisor` and `apple_vm` (the config spelling) instead of `GVisor` and `AppleVm`. The gateway keeps records in memory only.
- **Delivery records now name the credential, as invocation records do.** Every `response_delivery_attempt`
  record in the transparency log carries `who.credential_kind` and `who.principal`. Before, they were absent
  and empty, so an API key named `bearer` (or `dashboard`, `anonymous`, `public`) could not be told apart from
  the built-in identity of that name in a delivery record. `caller`, `who.account`, `who.authority` and
  `who.subject` are unchanged.
- **Event subscription handles and new `eventId`s are keyed aliases; the admin dead-letter listing names `subscriptionAlias`.** An `events/subscribe` answer, the `x-mcp-subscription-id` header and a new event's `eventId` (and `webhook-id`) change once at the upgrade, and again if the record key changes; `subscriptionId` leaves the dead-letter listing, whose `subscription` filter still takes a stored id. Unsubscribe and refresh are unchanged (upgrading.d/8697.md).
- **`gateway_list_servers` reports `tools_count: null`, not `0`, for a backend whose tools are not known to the caller yet.** `tools_known: false` already marked such a row, but agents read the bare `0` as "this backend serves no tools" and gave up on working backends. The count is now null until the backend's tools are known for that caller (not enumerated yet, or not visible to it), and a number, possibly 0, once they are. The tool description says so and points at `gateway_list_tools(server)`. Reported in [#4040](https://github.com/MikkoParkkola/mcp-gateway/pull/4040) by [@terafin](https://github.com/terafin), who also wrote the fix; ported to the 4.0.0 line.
- `GET /ui/api/tools` now gives each tool a `class` (`read` or `write`) and a `class_source` (`declared` when the server set `readOnlyHint` itself, `inferred` when the gateway read it from the name), the same values the server preview shows.
- **Governance audit records are timed.** Each control-plane audit record now carries a `timestamp`, like invocation and admin-action records already do, so the Activity page can place config changes among calls in time order. Records written before 4.0 have none; the Activity list puts them just before the oldest timed governance record, in file order. The hash chain, `audit verify` and the SIEM export (which forwards each record whole) accept a log that mixes both.
- **The shadow scan offers adoption only for a server the gateway can run exactly as its client does.** A server found in a client config is no longer proposed for adoption when the gateway would run it differently, or would copy a secret into gateway.yaml as text. That covers a variable the gateway would not expand (`${input:...}`, or any `${...}` in a command, argument, working directory or URL), a non-string value, a client setting it does not carry (a sandbox, `envFile`, client OAuth, a timeout, a relative working directory, a socket endpoint), an entry its client keeps disabled, a template with a non-empty default (`${KEY:-value}`), literal text beside a variable (`sk-${SUFFIX}`; a single scheme word such as `Bearer ${TOKEN}` is fine), a template read as a secret reference (`file:${HOME}/token`), a URL carrying a credential (a user name or password, a fragment, or or any query string), and credentials sent in cleartext to another host. Such a server is reported with "request owner" and a risk naming the reason and what to change, for example: move the whole value into a variable or secret, then rescan.
- **Config reloads wait for a gateway.yaml write in progress, and a crashed write is undone.** A
  reload (the file watcher, the env-file poll, an admin reload) now takes the config lock after
  the reload lock, so it never loads bytes that a refused write is about to roll back; a lock held
  past the wait skips that reload until the next change. Where no writer can exist (a read-only
  filesystem, or a config directory this account cannot write) a reload reads without the lock,
  as before, and logs once why. A byte write that a crash interrupted leaves a journal beside
  gateway.yaml; the next writer, or the next start, puts the original back, or keeps bytes a
  reload had already accepted. A gateway refuses to start on a journal it cannot resolve, and
  says what to do.
- **A web UI save or discovery adopt that stores secrets now refuses two oversized cases before writing anything.** A secret store reference longer than 32 KiB is refused ("the secret store returned a reference longer than the writer allows"). A new gateway.yaml that could pass the loader's 16 MiB limit once its secrets are filled in is refused before any secret is stored ("the new config could grow past the largest file the loader reads once its secrets are filled in"). That check counts each secret at its longest quoted form, about 128 KiB per secret. Either way, any store entries the save created are removed and gateway.yaml is unchanged.
- **`security.sanitize_input` and `security.ssrf_protection` apply on reload.** The next request after a reload uses the new values, over HTTP, stdio, task resumes and the UI's OpenAPI import and server preview; a request already in flight keeps the values it started with. A reload that changes only these two no longer reports `security` as needing a restart, and one that changes only `idempotency`, `events` or a restart-only `server` field is now reported.
- **Per-client rate limits and breakers keep their state when the key list is rebuilt.** Each client's rate-limit bucket and circuit breaker now live in one store shared across every resolved auth config, keyed by the credential, so rebuilding the key list (a key reload, in a later release step) resets no client's usage or breaker. The per-client bucket runs the same per-minute limit as before (`rate_limit` requests a minute, burst equal to the rate) and can change its rate in place, keeping the requests already spent. No configuration change; behaviour on a running gateway is unchanged.
- **`auth.api_keys` applies on reload.** A key added, removed, edited or expired by a config reload is judged by the next request, a dashboard link or session opened with that key by its next use, and a queued or continued task created with it when it dispatches; a request in flight keeps the table it started with, and spent rate-limit usage carries over. A reload whose keys would change multi-user status, collide with the running bearer, or name an unresolvable secret reference is refused whole, on stdio too, and the running keys stay in force. Every other `auth` setting except `dashboard_session` still needs a restart.
- **Firewall rules, credential redaction and the tool policy apply on reload.** A reload that edits `security.firewall.rules`, turns `security.firewall.credential_redaction` on or off, or changes `security.tool_policy` decides the next call over HTTP, `/mcp` and stdio. A request's checks use the config it arrived under. An answer to it is judged under that config and the one in force when the answer is scanned, and the stricter result stands: refused if either refuses, redacted if either redacts. A task result as it settles, a watch poll or an event has no request behind it, so it is judged by the config in force when it is scanned. A reload that changes only these fields no longer reports `security` as needing a restart. The firewall's other settings still need one.
- **Cost-governance budgets and alert rules apply on reload.** A per-tool, per-key or daily budget, or an alert rule, changed by a config reload judges the next call. A request in flight keeps the budgets it started with, a queued task judges the budgets current when it dispatches, and today's spend and in-flight reservations carry over. The restart report no longer lists `cost_governance` for a budget- or alert-only edit. Turning governance on or off, `tool_costs`, `default_cost` and `alternatives` still need a restart.
- **A budget added by reload starts from the spend it may already have.** Past the 256 per-name rows a day keeps for unbudgeted tools and keys, later spend is kept only as one overflow total. A per-tool or per-key budget a reload adds for a name with no row of its own now starts from that overflow total (or from the overflow total when the name's row was created that day), an upper bound of its earlier spend, instead of from zero. The figure is taken once a day, kept apart from real spend in `costs.json` (`tool_estimate`, `key_estimate`) and through a restart, and `gateway_get_stats` reports it per budgeted name as `tool_estimated_start_usd` / `key_estimated_start_usd` (null when none was taken).
- **An API key's rate limit and circuit breaker follow its principal across a rotation.** A key that records an explicit `principal` keeps its rate-limit window and client breaker when its secret is rotated, so a rotation no longer hands the holder a fresh window. A key without one still starts fresh on rotation, and adopting the principal it already derives changes nothing. Dashboard sessions still end when the secret changes, and a key whose principal changes is treated as a new identity.
- **The new web UI loads each screen when you open it.** The shell page no longer carries every screen's stylesheet and script, so the first page paints with only the shell's own files and each new screen no longer slows every other page. The remaining screens load once the page has painted, so the command palette still lists every screen's actions and settings. A screen whose files fail to load shows the error with Retry, and Retry fetches only the part that failed.
- Redacting a large JSON object whose members are named like credentials (a password or token member) is faster. Near the 1 MiB cap such an answer now takes about 3 times the plain whole-text redaction, against about 18 times before. Redacted output is unchanged byte for byte.
- **Daily budgets now reset at the host's local midnight, not at UTC midnight.** The budget
  enforcer's global, per-tool and per-key daily limits count calendar days in the host's time
  zone, so a day on a clock change lasts 23 or 25 hours. A host whose zone cannot be read counts
  in UTC and logs one warning. The aggregate views of `/api/costs` and `/ui/api/costs` name the
  zone in a new `day_zone` field, and `costs.json` records `day_basis: "local"`. The rolling
  windows of per-key budgets (last 24 hours, 7 days, 30 days) are durations and keep rolling.
 
- **The capability editor saves through one locked, atomic writer that keeps the pin valid.**
  `PUT` and `DELETE /ui/api/capabilities/{name}` need `If-Match` with the file's ETag; a stale
  base answers 409 with a patch, a pinned file's pin is rewritten in place, and a save accepts
  exactly what the loader loads. `POST /ui/api/capabilities/{name}/validate` validates without
  writing (200 valid, 422 invalid, the same answer as `PUT ?validate=1`), and `cap pin` takes the same directory lock. A symlinked capability file is refused;
  on Windows a save writes the file owner-only.
- **Secret saves wait for each other only as long as the caller allows.** A save of secrets through the gateway waits for another save's vault lock only until the caller's own deadline, then refuses with nothing written. The vault lock file, `<home>/.mcp-gateway-secrets.lock`, is accepted only when it belongs to the user running the gateway, with no exception for root. A rolled-back save deletes only its own new entries, and an entry whose removal fails stays in the unused listing, now shown with when it was written.
- **Library: `mcp_gateway::Error` is `#[non_exhaustive]` and has a `GatewayRefused` variant.** A refusal that a gateway decision makes (kill switch, capability disable, attestation, spend limit) is now `Error::GatewayRefused`, with the same code and text it had as `Error::JsonRpc`. A `match` on `Error` outside the crate needs a wildcard arm.
- **Every place the gateway records a delivered refusal, and every plain-error refusal it builds, is now pinned.** Two reviewed tables list each call that marks a call's delivery as refused, and each construction under `src/gateway` of the plain errors a gateway decision returns as a refusal, each classified by what records it. Adding, removing or moving one fails the build's tests until the table is updated and reviewed. Forms the tables cannot follow (a renamed error type, a pass-through wrapper, a macro that builds a refusal) are rejected. Two refusals found unrecorded are listed for follow-up fixes. No behaviour change. Operator action: none.
- **A config write that cannot be made in place is refused, comment-free files included.** A web UI backend save, and `mcp-gateway add`, `remove`, `setup wizard` and `cap discover --write-config`, now edit an existing `gateway.yaml` in place or refuse with nothing written. Before, a comment-free file whose backends were a flow mapping, or whose edit would break an anchor and its alias, was rewritten whole, losing its key order, quoting and flow style. On the command line, `--force` still rewrites the file.
- **The gateway's own refusals now count as never sent.** A denial (`Forbidden`) and a gateway
  decision's refusal (`GatewayRefused`, such as a server switched off by the operator or a spent
  budget) are raised only before anything reaches the backend, so `Error::is_pre_dispatch()` now
  returns `true` for both, and a refused call releases its idempotency key. A playbook or chain
  that ran a step before the refusal still keeps its key, so a same-key retry is answered from the
  stored result and nothing is sent again.
- **A refusal is not retried.** A playbook step under `on_error: retry` that meets a gateway
  decision's refusal is tried once, as a denial already was.
- **A chain ended by a gateway refusal answers with the refusal's own code.** It answered -32603,
  as if the gateway had failed; it now answers with the refusal's code (for example -32000 for a
  server switched off by the operator), and its message reads "refused".
- `mcp_gateway::Error` is `#[non_exhaustive]`: a later release can add a variant without breaking a caller's `match`. A `match` on it outside this crate needs a wildcard arm. See UPGRADING.
- **A backend's own JSON-RPC error is counted as the backend's, not the gateway's.** A backend's JSON-RPC error that reaches the gateway on a non-retry HTTP status, in an in-band answer on the meta route, or on a list page now arrives as the new `mcp_gateway::Error::BackendJsonRpc` variant (same text and code as `JsonRpc`, so the wire is unchanged), and `mcp_gateway_errors_total` counts it as `backend`. A meta-route dispatch failure that the gateway answers as an `isError` tool result now counts once with its origin (it was not counted at all), and a playbook or chain that ends on, or reports, a backend step's failure counts it as the backend's; the gateway's own `isError` refusals count as the gateway's. Affects 4.0.0 pre-releases only.
- The web UI's pages and files are sent gzip-compressed when the browser asks, by the same rule as the rest of the gateway; the live stream is never compressed. The shell paints its frame from CSS inlined in the page (allowed by its hash in the Content-Security-Policy, still with no `'unsafe-inline'`), and links the rest of its stylesheet at the end of the page. Its startup reads and the live stream start after the first paint, so a signed-out user sees the sign-in prompt one paint later.
- **A same-key call while a direct-route question waits is refused instead of run again.** On the direct route (`/mcp/{name}`), when a backend answers a `tools/call` by asking the client a question, a fresh call under the same idempotency key that does not present the continuation's `requestState` no longer reaches the backend: it is answered 409 "Secured execution result is unavailable" for the key's retention (24 h), as the meta route (`/mcp`) already answers it. The continuation that presents the `requestState` still runs, once. A question the gateway refuses instead of relaying (an undeclared question, `-32021`; a continuation it cannot mint, `-32003`; a response gate or delivery refusal; a round that hands back no continuation) frees the key as before: a same-key retry runs. Affects 4.0.0 pre-releases only.
- **A direct backend request refused before its backend is found now counts as its session's activity.** On `/mcp/{name}`, the caller's own session (`mcp-session-id`, counted only for its owner) is now read right after the caller is authenticated, before the request body is read and before the backend lookup, so the call is judged and routed under that session's routing profile. A request refused at either step (a malformed or refused request body, or a backend name that is unregistered or hidden from the caller) now resets the session's idle timer and adopts a provisional session, as a request to a present backend already did; before, it was answered before the session was read and did neither. A session kept alive only by such requests is reaped later than before.
  Affects: 4.0.0 pre-release builds; 3.x never counted a `/mcp/{name}` request as session activity. Operator action: none.
- **The in-place config editor can now remove one API key entry from `auth.api_keys`.** This is the edit the web UI's key revoke makes. The entry's lines are removed with any comments on them, and those comments are reported back by original line number, never by their text. If it was the only key, the `api_keys:` line goes too, and so does an `auth:` block it leaves empty. Every other line is kept byte for byte. An entry the editor cannot remove safely (one with an anchor, tag or alias, or a list written inline) is refused, and the refusal says how to revoke the key by hand: set its `expires_at` to now and reload, or delete the named lines and reload. Each of those hand edits is offered only after it was applied to the file in memory and checked to load as the original without the key (or with only that key's expiry changed); an edit that does not check out is left out, and a shared `expires_at` is said to be shared. Removing any other list element is still refused.
  Affects: 4.0.0 pre-release builds; 3.x had no in-place editor. Operator action: none.
- **The in-place config editor can now set a whole list of strings, written as one inline list.** A list the file does not have yet is added with its key, including several lists on an API key the web UI adds; a one-line inline list such as `backends: ["*"]` is replaced in place; a block list is rewritten as one inline list in the same place, and every other line keeps its bytes. A list with an anchor, tag or alias, an inline list over several lines, or an item that is not a plain string is refused, and nothing is written. When a deletion is refused because a deleted line carries a comment, the refusal now names that line by its number.
  Affects: 4.0.0 pre-release builds; 3.x had no in-place editor. Operator action: none.
- **`VerifiedIdentity`'s fields are private.** Library code reads `key_server::oidc::VerifiedIdentity` only through its accessors (`subject()`, `email()`, `name()`, `groups()`, `issuer()`); code outside the crate can no longer build one, copy one with a field changed, or change a field of one. The gateway's own verified sources are unchanged.
- **The web UI's backend add, remove and update now write gateway.yaml through the audited config writer.** On a gateway with an audit log, each one records a `config_backend_intent` event (with `operation` and `backend`, never a value) before the file changes, and a refused append writes nothing and answers 500. A crashed write's journal found by a backend route is recovered only after its `config_recovery_intent`. With auth on and no audit log, the routes answer 503 `audit_log_required`. A reload that refuses the new bytes now puts the old file back (it used to leave the file written and answer 500 "Config written but reload failed"). An edit that changes nothing still reloads, and on an audited gateway it now records its intent first; a refused append stops that reload. With no gateway.yaml, the routes, like discovery adopt, answer 409 `no_config_file` with a message naming `mcp-gateway init --profile local`. With no config reload running they answer 503 and write nothing. A gateway.yaml deleted while the write runs also answers that 409, and any secret entry the write made is removed. A gateway.yaml, journal or staged original the config read guard refuses (writable by others, or not owned by the gateway's account) answers 503 `gateway.yaml could not be loaded`, the same answer adopt gives, and nothing is written. Write failures answer fixed text that quotes nothing from the file.
- **The older in-process write calls refuse on an audited gateway.** `ReloadContext::mutate_and_reload_outcome`, `write_and_reload_outcome` (and their `_within` forms) and `mutate_config_and_reload` with a reload context refuse before taking any lock when the gateway has an audit log or auth on, because they record no intent.
- **A crashed config write's manual recovery step no longer says to copy the staged original over gateway.yaml unconditionally.** Each case has its own step. A journal naming another file: resolve that file first, restore nothing over this gateway.yaml, and keep the journal. An unreadable journal: leave gateway.yaml as it is until you have inspected the journal; restore a staged original only if the journal names this file and the original's SHA-256 matches its `original_revision`, and for an `all_renamed` journal only delete the journal. An unreadable staged original: restore nothing, check gateway.yaml by hand, then delete the journal.
- **Both search tools declare their `limit` range.** `gateway_search_tools` and `gateway_search` now advertise `limit` as an integer from 1 to 25 (`minimum`/`maximum` in the tool schema), so a client can bound its own call. The gateway already capped both at 25. A `limit` of 0 or a negative number now returns one match instead of none (0) or the default of 10 (negative); a value above 25 still returns 25, and a missing or non-integer `limit` still means 10.
- **A stdio backend now gets to exit on its own when the gateway stops it.** The gateway used to close a stdio backend's stdin and kill its process group at once, so a backend that saves state when its input closes lost that save on every stop. That included a gateway run as another's stdio backend, which lost its final telemetry, cost, task and audit writes. It now follows the MCP stdio shutdown order: close stdin, wait for the backend to exit, send SIGTERM to its process group if it has not, wait again, then kill the group. The waits fit the stop's own budget: at shutdown, `server.shutdown_timeout` (by default 16 s after stdin closes and 8 s after SIGTERM, with 6 s kept for the kill); on an eviction or a restart, its 10 s close budget. A backend that exits when its stdin closes costs no extra time. A backend judged dead or unresponsive (a failed health probe, a failed start or handshake, a call that timed out, a revoked capability) is still killed at once. A restart's close of the old backend is now bounded at 10 s.
- **`audit verify` pairs config-write records.** Once the chain check passes, `audit verify` pairs each settle record (a `settle.`-prefixed `kind`) with its intent by token and role. The run fails with "Pairing verification FAILED", naming the rule, the counter and the token but never a payload value, in four cases: a dependent record names no intent of its token, one token and role hold two different records, a `config_write_delivery_stopped` record has no outcome, or a settle record lacks a field its role requires. An intent with no terminal record is a warning: "interrupted", or "left to recovery" after a deferral. A record naming an intent that retention deleted is an info line. When the chain check fails, pairing findings print as "unverified:" warnings and never change the verdict. Intents written before outcome records existed are counted in one info line and not paired. `VerifyResult` gains the read-only accessors `failed_check()` (which check failed) and `notes()` (the info lines).
- **A gateway started with the firewall off now says that the cross-tenant read verdict still runs.** The verdict (`security.firewall.tenant_guard.cross_tenant_reads`) runs on its own switch whenever `tenant_guard.arg_keys` is set and the mode is not `off`, on every transport, whatever `security.firewall.enabled` says; ADR-029 said it stopped with the firewall. Behaviour is unchanged. With the firewall off and the verdict on, startup now logs one notice naming the mode and `cross_tenant_reads: off` as the way to stop it: a warning under `block`, where answers can be withheld, and an info line under `observe`. ADR-029 and UPGRADING-4.0 item 130 now state this scope.
- **The capability editor refuses a literal credential in a credential header.** Saving or validating a capability through the web UI now refuses a credential-named header (`Authorization`, `Proxy-Authorization`, `Cookie`, `x-api-key` and the like) whose value is not a reference: only `{env.NAME}`, `{keychain.NAME}`, `{oauth.NAME}` or a declared input with nothing baked into the file (no `static_params` entry, no default, no enum, const or examples), optionally after one scheme word such as `Bearer`, is accepted. A literal, a duplicate or colliding key, or a text the loader cannot parse is refused with the header's field path or a fixed message with the line and column, and the answer never carries the submitted bytes. Other headers are untouched.
- Key-server audit records carry `email_hash`, a keyed hash of the verified email, instead of the email, name and groups; policy and refusal logs name the issuer and subject. The hash key lives in `key-server-email-hmac.json` in the gateway data directory, or in `key_server.audit_email_hmac_secret_ref`; back it up.
- Breaking: an enabled key server now requires the audit log (`security.transparency_log.enabled`), and a start refuses when the hash key file is missing while the audit log shows a key existed. See UPGRADING.
- Breaking (library): `AuditEvent::identity` is `Option<SafeIdentity>`; `AuditEvent::issued`, `used` and `KeyServer::new` are crate-internal; `AuditEvent::expired` is removed (the gateway never emitted it). See UPGRADING.
- **Contributors: release checks ready for a second download.** The release asset check now requires exactly the expected binaries (an unexpected `mcp-gateway-*` file fails it) and checks each product's SBOM against its own root crate (`--client-root` for the coming client-only download). The CodeQL product-file check reads dep-info rules that continue over several lines, paths with escaped spaces and Windows drive letters. The release clippy feature list leaves out product markers such as `client-cli`. No change for users of the gateway.
- **Each request's dispatch future is no longer held twice.** The wrapper that opens a request's delivery record was an `async fn` around the whole dispatch future, so the boxed future kept a second copy of it: 23,736 B per request, half of it the copy. It and 13 other wrappers of the same shape now return the scoped future directly, so a request, refused or answered, allocates about 11.8 KB less. Behaviour is unchanged.
- **One stop budget for the HTTP gateway.** `server.shutdown_timeout` is now the total of an HTTP gateway's stop, counted from the signal: the listener, the state saves, the drains and the backend stop share it instead of each starting a timeout of their own, and a stage that runs out is logged while the stop goes on. An HTTP gateway whose `server.shutdown_timeout` is below 13 s now refuses to start, naming the setting and the minimum; the 30 s default is unaffected and stdio is unchanged. [@terafin](https://github.com/terafin) found the same unbounded HTTP wait in the pre-4.0 code and fixed it there ([#5043](https://github.com/MikkoParkkola/mcp-gateway/pull/5043)); [#5099](https://github.com/MikkoParkkola/mcp-gateway/pull/5099) keeps that case covered on 4.0 with a regression test.

### Removed

- **MITRE Fight Fraud Framework mapping removed.** `docs/compliance/MITRE-F3-MAPPING.md` and its README badge and links are gone. F3 models financial-fraud actors (card schemes, payment rails, cash-out); 108 of its 123 techniques fall outside a tool-call gateway, and the controls it rated are covered by the OWASP Agentic AI self-assessment. The one open finding, failed authentication with no throttle or lockout, is now listed under OWASP ASI03. (#2191)
- Removed 18 built-in registry names that had no maintained server (list and reasons in UPGRADING-4.0 item 124); `jira` is now `atlassian`.
- **`mcp-gateway plugin` removed.** `plugin search`, `install`, `uninstall` and `list` are gone, with the marketplace module and `MarketplaceConfig`: nothing ever loaded what `install` wrote, and the default marketplace host does not resolve. A `marketplace:` block in the config now loads and warns once; delete it, and add tools as `backends:` entries or capability files instead (UPGRADING-4.0 item 145). (#2953)
- **The v1 protocol-revision window API is removed** from `mcp_gateway::protocol_revision_telemetry`: `DurableWindow`, `load_durable_window`, `production_retirement_decision`, `production_retirement_decision_at`, `DURABLE_WINDOW_SCHEMA` and `RetirementBlocked::WindowMisaligned`. Each of them failed on, or misdescribed, the v2 window this version writes. A v1 `window.json` is refused, never converted, and left untouched. (#3920)
- **The shipped examples and user docs show only the keys a normal setup needs.**
  Hidden keys left `gateway.example.yaml`, `examples/*.yaml`, README and the user docs;
  they still load and still apply, and `mcp-gateway doctor` lists any a config sets. An
  example copied afresh now takes the default for seven values it used to set; see
  upgrading.d/8044-6.md. `examples/circuit-breaker.yaml` is removed, and CI fails on any
  hidden or removed key in the docs, the examples or the Helm chart's rendered config.
 
- **`error_budget` is documented configuration again.** It had been classed as a hidden
  key, contrary to GH #475; `mcp-gateway doctor` no longer lists a set `error_budget` key
  as hidden.
- **`meta_mcp.cache_tools` is retired.** Nothing ever read it, so it never turned tool-list
  caching on or off. A config that sets it still loads and logs one warning; `mcp-gateway
  upgrade` removes the line (or, when it cannot do so safely, says to delete it by hand), and `init` no longer writes it. Use `meta_mcp.cache_ttl` to change how long tool lists are cached.
- **Three duplicate public library types removed.** `key_server::policy::MatchCriteria` and `key_server::policy::PolicyScopes` mirrored `config::PolicyMatchConfig` and `config::PolicyScopesConfig` field for field, and `config::RuntimeAvailabilityConfig` mirrored `runtime::RuntimeAvailability`. Use those types instead; config files are unchanged. Only Rust code that links the `mcp_gateway` library is affected.
- **The library's `PersistedToolUsage` row is removed.** `tool_profiles::persistence::PersistedUserProfile::tools`
  holds `tool_profiles::ToolSuggestion`, the same fields the live profile reports, so the two copies of one row
  are one; `profiles.json` keeps its bytes. The unreleased `gateway::ui::ToolCallCount` is folded into
  `stats::TopTool` the same way.
- **The library's `protocol::era::METHOD_NOT_FOUND_CODE` is removed.** It duplicated `error::rpc_codes::METHOD_NOT_FOUND` (-32601); use that instead. Every standard JSON-RPC code in the gateway now reads from `rpc_codes`, and SHA-256 hex digests come from one helper; no code or digest on the wire or on disk changes.
- Removed the severity re-exports `mcp_gateway::security::firewall::Severity`, `mcp_gateway::security::response_inspect::Severity` and `mcp_gateway::context_integrity::ContextIntegritySeverity`; use `mcp_gateway::security::Severity`.
- Removed four public paths that duplicated a live one: `mcp_gateway::attestation::Substrate` (use `mcp_gateway::runtime::Substrate`, variants `GVisor`/`AppleVm`), `mcp_gateway::security::validate_redirect_chain` (validate each hop with `validate_url_not_ssrf`), `mcp_gateway::security::resolve_and_validate_host` (check each URL with `validate_url_not_ssrf`, build the client with `.no_proxy()`, and pin DNS with `PinningResolver`), and `mcp_gateway::security::check_host_not_ssrf` (now internal; use `validate_url_not_ssrf`).
- Removed seven type paths whose names misled, each renamed: `mcp_gateway::protocol::era::Era` -> `mcp_gateway::protocol::era::PeerEra`; `mcp_gateway::protocol_revision_telemetry::CacheScope` -> `mcp_gateway::protocol_revision_telemetry::ShadowCacheScope`; `mcp_gateway::gateway::oauth::AgentIdentity` -> `mcp_gateway::gateway::oauth::OAuthAgentIdentity`; `mcp_gateway::gateway::AgentIdentity` -> `mcp_gateway::gateway::OAuthAgentIdentity`; `mcp_gateway::validator::OutputFormat` -> `mcp_gateway::validator::ValidatorOutputFormat`; `mcp_gateway::registry::server_registry::RegistryEntry` -> `mcp_gateway::registry::server_registry::ServerCatalogEntry`; `mcp_gateway::registry::server_registry::Transport` -> `mcp_gateway::registry::server_registry::CatalogTransport`.
- **Seven settings the gateway can pick itself are retired before 4.0.0 GA.** They are `capabilities.stale_check_secs` (the check runs every 60 s), `cache.enabled` (the cache is always on, for read-only annotated tools only), `failsafe.retry.enabled` (retry follows the resend annotations), `failsafe.circuit_breaker.enabled` (the breaker is always on), the nested `auth.client_circuit_breaker.enabled` (the section's presence is the switch), `security.signature_chain.max_links` (a constant 8) and `server.protocol_revision_window` (now the hidden `--protocol-revision-window` flag or `MCP_GATEWAY_PROTOCOL_REVISION_WINDOW`). A config that still sets one loads, logs one warning naming the key and what to do, and does not have the value honoured. `mcp-gateway upgrade` deletes each one. It keeps a lone `client_circuit_breaker.enabled` and says to write `client_circuit_breaker: {}`.
- **The per-key rolling budget that nothing enforced.** For library users, `cost_accounting::BudgetConfig`, `BudgetStatus`, `CostTracker::set_key_budget`, `CostTracker::check_budget`, `KeyCost::budget_status` and the `KeyCost.budget` field are removed. No config key or endpoint set a per-key rolling limit, and nothing checked one, so a key's report always read "no limit, Ok". The cost report's fields are unchanged: `hard_limit_usd` stays `null` and `budget_status` stays `"Ok"`, documented as judging no limit. The enforced per-key daily caps are the budget enforcer's.

### Fixed

- **Zed export and import use Zed's real settings file and format.** `setup export --target zed` now writes to Zed's config directory (`~/.config/zed/settings.json` on macOS, `$XDG_CONFIG_HOME/zed` on Linux, `%APPDATA%\Zed` on Windows); on macOS it previously wrote to Zed's data directory, which Zed never reads, so remove a `gateway` entry left there. Discovery now imports Zed's flat `command`/`args` and `url` entries, which it previously skipped (#1811).

- The 4.0.0 upgrade notice now includes `--config PATH` in the `accounts migrate-credentials`
  command it prints; without it the command stops unless `MCP_GATEWAY_CONFIG` is set.
- **Cost budgets survive a stdio gateway restart.** A stdio gateway loaded `costs.json` at
  startup but never wrote it, so every restart gave the daily budgets back. It now saves when
  the client closes stdin (after in-flight calls finish) and every 5 minutes while it runs, as
  the HTTP gateway does. Each save writes its own scratch file, so gateways sharing a data
  directory no longer write one scratch file between them.
- **A failed release or image-manifest job can be re-run for 30 days, not one.** The build
  binaries and image digests handed between jobs expired after a day, so a later re-run
  published a release with no binaries or failed to find the digests. They now last the
  repository's 90-day artifact retention, past GitHub's 30-day re-run limit, and a CI check
  keeps every such handoff there.
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
  with no identity.** The backend is still named, with `tools_count` null and `tools_known` false,
  matching the tool listings that omit it for that caller. (#2346)
- AX-010 no longer withholds a tool for ordinary usage guidance. "Before calling this tool" on its own now only warns, and the tool is still served. It still withholds when a read-like directive follows: read, include, copy, load, cat, fetch or open. "Encoded as base64" is a format note, not exfiltration; base64 blocks only next to send, upload, post or exfiltrate. Linear `prepare_attachment_upload` and `create_attachment`, Netdata Cloud `trigger_report` and axterminator `ax_visual_diff` are served again. (#2356)
- **Discovery responses are inspected once.** `gateway_list_tools`, `gateway_search_tools` and `gateway_search` were scanned twice by the response firewall: on their raw value, then again on the served copy, writing two audit entries. The served copy is no longer scanned again; a server-owned marker, which no backend or retried call can set, records that the raw value was inspected. (#2358)
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
- A refused cloud metadata address (169.254.169.254, fd00:ec2::254) is named as a cloud metadata address instead of a private/reserved one; a refused host name still names no address.
- A task's calls key their A/B arm and prefetch hints on the caller that created or resumed the task, as a direct call does (#2607).
- Tests: the cacheScope drift check reads whole source files and excuses only listed files, so a production writer after a test-gated item is no longer hidden. (#2616)
- Dev tooling: the MCP Events fail-fast stub refuses a malformed, negative or oversized Content-Length. (#2621)
- On stdio EOF, `run_stdio_on` returns within the 30 s drain plus a 10 s teardown window, even when a backend stop, the custody store or a task never finishes; an abandoned step is logged by name.
- stdio and WebSocket backends negotiate the protocol revision like HTTP: a selection outside the revisions the gateway speaks fails the start, the stdio fallback retry adopts the revision the backend selects, and WebSocket retries a version rejection once at the highest shared revision.
- A shutdown whose task drain runs out of time cancels the task workers still running before the task store closes, on HTTP shutdown and stdio EOF; their records are settled as interrupted on the next start, except tasks a configured upstream recovery adapter manages.
- A capability that declares `providers.fallback` now logs a CAP-011 warning at load: fallback providers are not executed, and the capability is served from its primary. A malformed fallback entry fails the load instead of being dropped silently (#2677).
- `subscriptions/listen` opens its stream with `notifications/subscriptions/acknowledged`, naming the honoured filter, instead of a JSON-RPC response, which the 2026-07-28 specification defines as the end of a subscription; a subscription the gateway ends gracefully closes with that response, and one whose reader fell behind just closes.
- **An accepted notification or client response over HTTP is answered 202 with no body.** It carried `{}` with a JSON content type, which MCP Streamable HTTP forbids; the session header is kept. Both the meta route and the direct `/mcp/{name}` route. (#2682)
- A key under a capability provider that this gateway version does not read (a misspelling, for one) now logs a CAP-012 warning naming its path instead of being dropped silently. `mcp-gateway cap validate` runs the same structural checks as the loader: warnings print and a structural error fails the command (#2683).
- `mcp-gateway add <name>` now uses a pinned package that exists, or the vendor-hosted endpoint, for every built-in server; 30 of the 45 npm packages it named did not exist and 7 were deprecated. CI checks every entry.
- **An event delivery is on the audit log before it is sent, and a retry stays inside 15 minutes.** The attributed record of each attempt is written first; if the log refuses it, nothing is POSTed and the attempt retries. `events.retry_window` above 15 minutes is refused at load. The `throttled` field of a subscribe refresh now follows the bucket and the waiting deliveries instead of a flag cleared on every send. (#2718)
- **A webhook route without a `method` accepts POST, a `transform.data` mapping without braces is a literal, and a restart drops subscriptions to routes that no longer exist.** A route that named no `method` accepted only GET, so a sender that POSTs got 405; it now accepts POST (see UPGRADING-4.0 item 131). The documented mapping grammar is a template or a literal, never a raw payload path. After the startup capability scan, subscriptions to webhook event types nothing offers are withdrawn with their pending retries. (#2732)
- Internal: a build without the dashboard feature no longer warns about an unused helper.
- **Input validation reads array limits.** The input validator now enforces `minItems` and `maxItems`; the Cloudflare WAF capability requires its ruleset phase again.
- **An event replay is audited under the admin who triggered it.** The `events.replay` audit record now carries the admin credential instead of the gateway, for a single and a bulk replay. (#2774)
- fix: the relay receipt helpers build clean without the firewall feature (#2778)
- Events: a settled task's event reaches its owner after the task expired, `capabilities.events` advertises `listChanged: false` (nothing pushes catalogue changes), and a backend removed while the gateway was down loses its event subscriptions at the next start.
- audit: the stalled-write test waits on the stall gate instead of a poll budget, so a loaded runner no longer fails it (#2787)
- gateway: the catalogue read arms of meta dispatch are boxed, so a chain step no longer overflows a 2 MiB test thread stack (#2788)
- `/.well-known/oauth-protected-resource` now lists the OIDC issuers of an enabled key server with `delegated_bearer` in `authorization_servers`, so OAuth clients such as ChatGPT can find where to sign in.
- audit: a peer's own `-32001` or `-32004` is no longer recorded as a gateway `denied`: a settled upstream task, and a replay with no stored class, record `error` with the peer's code; a refusal a gateway gate noted, and a replay of one, stay `denied` (#2803)
- capability reload: an edited capability now revokes the in-flight calls that read its earlier definition, as a removed one already did (#2811)
- A capability reload that arrives before the startup scan completes is applied when the scan completes, instead of being dropped from the webhook routes (#2818).
- **Concurrent calls can no longer overspend a budget.** With cost governance on, the budget check and the spend record were separate steps, so calls (or event deliveries) that ran at the same time could each pass the check against the same remaining allowance and overspend by up to one call's cost per extra caller. An allowed check now reserves its cost until the call settles, so later checks count it. Refusals, reasons and warnings are unchanged when calls do not overlap. (#2823)
- **`cap list` reports a config it cannot load.** A missing or malformed `--config` made `cap list` list readiness against the process environment and exit 0; it now prints the load error and exits non-zero.
- credential substitution is one pass: a secret that contains a placeholder such as `{q}` reaches the provider as written, and a caller value is never expanded. A caller can no longer supply the value of a key a credential rule owns when that credential resolves empty (#2827)
- **The lazy notification channel entry now states what a POST allocates.** Minting a session still allocates the session record; only the notification channel and its buffer wait for a stream to subscribe. A test now covers several streams subscribing to a new session at once. No behaviour change.
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
- events: a backend's resource_updated authorization is also refused when the backend leaves the registry while its catalogue lookup waits, as it already was when the backend turned ineligible
- The 4.0.0 upgrade notice (item 1) now says every OAuth backend re-authenticates once after the upgrade, and that `accounts migrate-credentials` applies only to backends bound to a personal account: it cannot keep an ordinary `backends.<name>.oauth` credential. 3.x token files are left untouched.
- `gateway_search_tools`, Code Mode search and `gateway_list_tools` now fill a backend's tool cache in the background when it was never filled, so a backend left out of a non-empty `meta_mcp.warm_start`, or one whose warm-start gave up, becomes searchable instead of staying invisible. The first search returns nothing for that backend and later ones match. A backend that is down is not asked once per search: concurrent fills share one `tools/list`, a failed fill holds further fills off for the fill cooldown, and I/O, HTTP and TLS failures, which do not start that cooldown, are bounded by the circuit breaker ([@terafin](https://github.com/terafin), [#3036](https://github.com/MikkoParkkola/mcp-gateway/pull/3036)).
- Scheduler: a weekday step `*/n` now matches only the days `n` divides; each day was also tested as its number plus 7 (meant only as Sunday's alias), so `*/2` matched every day and `*/3` to `*/13` (except `*/7`) matched extra days. Scheduled jobs and `schedule.tick` subscriptions with such a step fire on fewer days after upgrading; `*/1`, `*/7` and `*/14` or more are unchanged. (#3052)
  Affects: 3.x and 4.0.0 pre-releases. Operator action: check any scheduled job whose weekday field uses a step.
- **A grants file on a stalled network mount no longer keeps the gateway from exiting.** The `security.identity_grants` file is now read on its own thread, like the config file, so shutdown does not wait for a read that an NFS or FUSE mount never completes. (#3063)
  Affects: deployments with an identity-grants file on a network mount. Operator action: none.
- **A reserved name in a CLI or MCP capability's `env` list no longer blanks its value in results.**
  `HOME`, `PATH` and the other names the gateway sets for the child itself are never taken from
  that list, yet their operator values were still scrubbed from tool results as if they were
  injected secrets. They are now left out of the redaction list; every other declared name is
  still scrubbed, and a changed `PATH` still restarts a running MCP child. (#3064)
  Affects: 4.0.0 pre-releases only; 3.x unaffected. Operator action: none.
- fixed: the Homebrew formula caveat states the single PolyForm Noncommercial 1.0.0 licence instead of "mixed, per-file licensing"; setup docs name Rust 1.95, `mcp-gateway serve` and the meta-tool counts consistently (#3069)
- **`add --url` works against Streamable HTTP servers.** `add --url` wrote `streamable_http: false`,
  so a server that speaks only Streamable HTTP, which answers `GET` with 405, failed its first call
  with `SSE endpoint returned: 405`. That includes the CLI help's own Sentry example. An
  `http_url` backend with no `streamable_http` key now follows the MCP backwards-compatibility
  rule: it POSTs `initialize` first and falls back to the legacy SSE `GET` only when that POST is
  refused with a 4xx that is not about the credential or a retry (any 4xx but 401,
  403, 407, 408 and 429). An explicit `true` or `false` is still tried first.
  When the server refuses it with such a 4xx, the other transport is tried once and a warning
  names the backend and the value to set, so configs the old `add --url` wrote keep working. The
  transport that answered is kept for reconnects. See `docs/UPGRADING-4.0.md` item 148.
- capabilities: a hot reload that edits an `mcp` capability stops the children started under the old definition at once, as a programmatic re-registration does, instead of leaving them idle until idle eviction; a reload that leaves a capability unchanged keeps its children (#3075)
- capabilities: `mcp-gateway invoke` and `mcp-gateway cap test` check arguments against the capability's input schema before calling, as a gateway call does; a schema default now fills a placeholder in the `endpoint`, the `base_url` or the `path_selector` path the call picks (the compatibility `path` beside a selector gives none), not only in `path`; `key=value` text is typed by the tool's input schema (`count=007` is `7` for an integer, `zip=007` stays `"007"` for a string) while JSON arguments go out as written; a property whose `type` admits `"null"` accepts a null even when required or named by an `anyOf`/`oneOf` branch, checks it against its `enum`, and forwards it instead of dropping it; an unfilled placeholder whose name holds a quote (`{a"b}`) is omitted, not sent as text; `sentry_get_issue` refuses an issue ID of `0` or one with a leading zero (#3081)
- **A failed `gateway_invoke` says so in `isError`.** A failed invoke, such as an unreachable
  backend or a backend's own tool error, came back with the outer result's `isError: false`, and
  the failure was visible only inside the text payload, so a model could read it as success. The
  outer result now carries `isError: true` whenever the payload does, and the structured
  `recovery` hint is unchanged. See `docs/UPGRADING-4.0.md` item 149.
- **`init --with-examples=false` turns the examples off.** The flag defaulted to on but accepted
  no value, so `--with-examples=false`, which `init`'s own "already exists" hint suggests, was a
  parse error and the example capabilities could not be skipped. `--with-examples=false` now skips
  them. The default and a bare `--with-examples` still write them.
- **Piping CLI output into `head` no longer crashes.** `mcp-gateway list --available | head`, or
  any command whose output reader closed early, panicked with `failed printing to stdout: Broken
  pipe` and the release build dumped core. CLI output now goes through `println!`/`print!`
  replacements that exit with status 0 when the write fails with `BrokenPipe`. Any other stdout
  write failure still panics, as before.
- **`add` and `remove` keep the comments in gateway.yaml.** Both commands re-serialised the whole
  config, which dropped every comment, including the warning `init` writes next to the generated
  `bearer_token`. `add` now writes the new backend into the file's text under `backends:`,
  adding that key at the end if needed. `remove` deletes only that backend's lines. The rest of
  the file is left as it was. Each edit is used only when the edited file loads to exactly the
  old config with that one backend changed; otherwise the file is rewritten as before.
- Callers that authenticate with an API key can create tasks again when authentication is on. Task creation was refused with -32600 "task creation requires a verified caller identity" unless the caller carried an OIDC identity, which no API-key caller does. The task is now owned by the caller's proven subject when a trusted proxy, Cloudflare Access or a client certificate names one, and otherwise by its credential, the same owner `tasks/get` and `tasks/cancel` use. Two people behind one shared key therefore own separate tasks, another key is still told the task does not exist, and a caller with no credential is still refused. (#3092)
- **Recovery hints name only tools the caller can see.** With Code Mode on, a failed call's
  recovery hint (for example "Backend not found") told the caller to use `gateway_list_tools`,
  and a circuit-breaker hint named `gateway_revive_server`. Code Mode hides both. In Code Mode
  the hints now name `gateway_search`, and the circuit-breaker hint says to wait for the
  automatic recovery. Hints in standard mode are unchanged.
- **A Windows refusal for a grant journal that is not a regular file reads as two sentences.** The refusal text ended without a line break, so the journal's "Check its entries against the grant file" ran on from "replace the file." on the same line. (#3153)
- **Shipped alert rules fire on the first event.** The idle-stop and nonce capacity rules in `deploy/prometheus/mcp-gateway-alerts.yml`, and the matching rules in DEPLOYMENT.md, used `increase(...) > 0`. Each counter is created at its first increment, already at 1, so `increase` read 0 and an isolated first failure or refusal never fired. Each rule now also fires for a series new in its window. The file adds alerts for caller pool slots near their cap and for slot refusals. (#3153)
- **A recovered task result refused by the response firewall settles with the refusal error.** When a task's result is recovered from the upstream after a restart or a follow, and the response firewall refuses it, the task now fails with `-32600`, the same error a native task and a synchronous call report. It used to fail as an internal error (`-32603`). Other processing failures are unchanged. (#3156)
  Affects: clients that read the error code of a failed task in the 4.0.0 pre-releases. Operator action: none.
- **Recovery hints name only meta-tools the caller can see.** A caller that turned on Code Mode with
  `?codemode=search_and_execute` was told to use `gateway_list_tools` after a failed
  `gateway_execute`, though its tool list showed only `gateway_search` and `gateway_execute`; it is now
  pointed at `gateway_search`. A circuit-breaker hint names `gateway_revive_server` only to an admin
  caller for whom `exposed_meta_tools` does not hide it; anyone else gets the wait-only advice. A
  task created or resumed with `?codemode=` keeps that surface for its hints.
- **A retry after a lost round is told the outcome is uncertain.** When a dispatched call's request may have reached the backend and nothing that came back shows whether the work ran (a broken stream, a timeout, a config reload stopping the backend mid-call, an HTTP 5xx, or an HTTP 400, 404, 407, 408, 429 or session-expiry answer), a same-key retry was served the original error, as if the work had failed. It now gets the uncertain-outcome notice under the first caller's error code; the work still never runs twice. An answer that shows the outcome (a JSON-RPC error, a 401 or 403 credential refusal, or any other HTTP 4xx refusal) is served as before. A backend that could not take the request (`BackendUnavailable`, a tool-list timeout, a stdio backend with no writer) is now a pre-send refusal that frees the key, so the retry runs. See ADR-012 and `docs/UPGRADING-4.0.md`. (#3170)
- **A shipped first-event alert no longer re-fires after one missed scrape.** The idle-stop, nonce capacity and slot refusal rules in `deploy/prometheus/mcp-gateway-alerts.yml` and DEPLOYMENT.md read a single sample one window back to tell a new series from an old one. A failed scrape at that instant made an old series look new, and the alert fired again with no new event. They now read the highest value over five minutes at that offset. CI runs the rules' promtool cases on every pull request. (#3171)
- **A connect offer reads as its own text.** When a call needs an account the caller has not connected,
  the offer now reaches the client as its own message, without the `JSON-RPC error -32001:` prefix in
  front of it. Other errors, including a refused upstream credential, keep their text. (#3209)
- A throttle phrase alone no longer exempts a failure from the circuit breaker and the error budgets: an error worded only as a throttle, such as `request throttled: upstream out of capacity`, counts as a failure; a `429` or a rate-limit phrase still exempts. A tool result with `isError: true` worded that way counts as an answered call. See UPGRADING-4.0 item 4. (#3216)
- **A long task keeps its caller's state.** A task whose backend call ran longer than the five-minute
  idle window had its caller's per-key state (tool hints, firewall anomaly history) reclaimed while it
  ran, and what it wrote afterwards was never reclaimed. The caller key is now held for the length of
  the call and its idle window restarts when the call ends. (#3225)
- A stdio backend whose npm package cache is damaged no longer stays dead until the cache is cleared by hand. A start that fails with a missing module (`Cannot find module`, `MODULE_NOT_FOUND`) clears the cache the gateway assigned to that backend and retries once. The cache is cleared at most once per successful start, and a cache set in the backend's own `env:` is never touched ([@terafin](https://github.com/terafin), [#1759](https://github.com/MikkoParkkola/mcp-gateway/pull/1759)).
- **A session-less caller's cost report shows its own spend.** A request with no session
  (2026-07-28 era) was recorded only in the anonymous aggregate, so a non-admin caller's
  `get_cost_report` always answered `"session": null`, and a session-less call on the direct
  `/mcp/{name}` route was not recorded at all. Session-less spend is now also kept per caller key
  and reported under `"caller"`, by backend and by tool; two callers, including two subjects on
  one credential, never see each other's spend. A caller with no key (authentication off, or a
  public path) still gets `null`, and the anonymous aggregate stays admin-only. A caller's
  breakdown resets after 24 hours without a call and is reclaimed on the next eligible sweep.
  With authentication off, budgets are best-effort; turn authentication on for per-caller
  enforcement (`docs/UPGRADING-4.0.md` item 151). (#3260)
- A 2026-07-28 client over stdio now gets the result fields that revision requires: `resultType` on every result, and `ttlMs` with `cacheScope` on the lists and resource reads; `server/discover` carries `ttlMs` and `cacheScope` on every route. Without them, Claude Code loaded no gateway tools on the 2026-07-28 path. 2025 sessions are unchanged.
- MCP events: `watch.<capability>.changed` now offers only capabilities whose every provider, fallbacks included, is REST; read-only GraphQL, JSON-RPC and CLI capabilities are no longer watch types. Poll jitter only lengthens the wait, so two polls never come closer than `interval` (60 s floor).
- **A schema whose only change is the sign of a zero gets a new trust card.** `-0.0` and `0.0` compare equal in JSON values but serialise and digest apart, so the memo could list the new schema with the old card's schema digest. (#3279)
- MCP Events: a subscription's expiry is counted from when it is stored, after the callback
  challenge, so a slow challenge no longer commits an expired subscription. Zero
  `events.seen_max_per_route`, `events.dead_letter_max_records` or `events.dead_letter_max_bytes`
  now fails startup validation instead of disabling webhook dedupe or evicting every dead
  letter. A verification kept past a lowered cap is no longer reused once.
  Affects: 4.0.0 pre-releases only; 3.x has no events. Operator action: set any of the three
  caps that is 0 to a positive value.
- **A test-spawned gateway stays out of the real home on Windows.** Nine paths, among them the OAuth
  token store, the transparency log and skill and chain storage, looked up the home directory directly
  and ignored the debug-build test-home override; on Windows that reached the runner's real home. All
  of them now use the one redirectable lookup, and a lint refuses a new direct call. Release builds
  resolve the same directories as before. (#3291)
- A dead-letter replay into a suspended subscription is refused with `subscription_suspended`
  (409) and the dead letter stays; before, the replay waited unsent and was lost if the
  subscription expired unrefreshed. A replayed event keeps its original fan-out time, so a
  crash during the replay can no longer deliver it and keep it replayable.
  Affects: 4.0.0 pre-releases only; 3.x has no events. Operator action: none.
- **A backend frame carrying `"method": null` is no longer taken as a response.** JSON-RPC
  has no frame that is both a call and an answer, but a null `method` was read as absent, so
  on stdio and SSE such a frame answered the matching call, and on a listen stream it was
  projected into an event. It is now refused like any frame that carries `method`, on every
  transport; WebSocket already refused it. `"result": null` is still a valid result.
- MCP Events: a delivery whose audit record the log refused, and which therefore sent nothing,
  no longer counts toward `events.retry_max_attempts`. Before this, a long audit outage
  could bury a pending event as `exhausted` without one POST to its callback. Attempt
  numbers in the audit log stay unique, and the retry window still bounds how late an event
  can go out.
- MCP Events audit records follow the order of what they record. A dead letter's
  `events.dead_letter` record comes before any `events.dead_letter_evicted` record for it,
  including when the dead-letter caps evict it at once or when another burial evicts it.
  Racing subscribes for one subscription are audited in the order they were committed.
 
  Affects: 4.0.0 pre-releases only; 3.x has no MCP Events. Operator action: none.
- **OAuth backends keep their refresh token across a refresh.** When an authorization server answered a token refresh
  without a new refresh token (keeping the old one valid), the gateway stored no refresh token at all, so the next
  access-token expiry needed an interactive login. The refresh token that was sent is now kept. (#3313)
- **One damaged task record no longer stops the gateway.** A task record that does not parse, or
  whose task does not restore, is now skipped where it lies, and every other task loads. Previously
  one such file refused the whole task store, so the gateway did not start. A skipped record whose
  idempotency key is still readable keeps that key taken: a retry gets "task store unavailable" and
  never starts a second task. The file is never moved or deleted. It still counts against the store
  limits until an operator removes or repairs it, and a warning names it. A record written by a
  newer gateway, a record under another task's name or identity, and a foreign-moded or over-budget
  file still refuse the store as before. (#3315)
- **A bridged prompt's relay receipt commits when the prompt is written, not queued.** A prompt
  queued on a session stream could still be withheld by the stream's audit gate or dropped by a
  lagging subscriber, yet its receipt was already recorded, exempting that caller for text it never
  received. The receipt now commits once, when a stream writes the prompt.
- **The direct route `POST /mcp/{name}` speaks 2026-07-28 to a 2026-07-28 client.** A modern
  request now gets `resultType` on every result, plus `ttlMs` and `cacheScope` on the five
  cacheable lists and reads. That holds for fresh answers, sanitized calls and idempotent
  replays alike. Before, these were missing, and `tools/list` dropped them even when the backend
  sent them. The shortest backend `ttlMs` survives, capped at the gateway's own. Legacy clients
  get the same bytes as before.
- **One OAuth refresh at a time per stored credential.** Two clients holding the same stored
  OAuth credential (for example a transport a restart replaced while a call still held it, and
  its replacement) could each refresh with their own copy of the refresh token; against a server
  that rotates refresh tokens the second use could revoke the grant. Refreshes are now serialized
  per credential and always use the stored refresh token, a refresh that is cut short still
  completes and saves, and a refresh token whose exchange had an unknown outcome on a rotating
  server is never sent again. (#3333)
- MCP Events: a capability reload that could not read one of its directories no longer
  deletes the subscriptions to that directory's webhook event types. They stay, undelivered,
  until a reload reads the directory again; a complete reload that still lacks a type
  withdraws its subscriptions. At startup, a capability file loaded while the scan was
  running keeps its subscriptions instead of losing them to the startup reconcile.
 
  Affects: 4.0.0 pre-releases only; 3.x has no MCP Events. Operator action: none.
- **A damaged task record can no longer let a retried call run twice.** When a stored task's idempotency key cannot be read unambiguously, the gateway now refuses every new keyed call with code 409 and a message that says such calls are paused until the record is repaired or removed. Before, such a row released its key, so a client retry was admitted as new work and its backend ran again. Keys already held and unkeyed calls work as before. The refusal lifts on its own: the expiry sweep reads the row again and clears it without a restart. A repaired row keeps its key, so its retry never runs again, and its task reads again at the same sweep. Removing the file releases the key, so a retry of that call runs again. While it holds, the log names each file on every sweep, `mcp_task_store_skipped_records{class="sealed"}` counts the rows, `/health` reads `degraded` (`/livez` and `/readyz` are unaffected), and the admin `/health` view names each file by full path with the action that clears it. A record-named FIFO in the task store is now refused as unsafe instead of hanging startup. (#3398)
- MCP Events: at startup, a webhook subscription whose event type the first catalogue scan
  does not offer is no longer deleted straight away. The gateway waits 30 seconds for a
  capability reload that may be about to offer it, then withdraws the types still missing.
  A route that a reload removes is still withdrawn at once.
  Affects: 4.0.0 pre-releases only; 3.x has no MCP Events. Operator action: none.
- **A new tool or key keeps its own cost row when a spend straddles UTC midnight.** A spend that
  read the day just before midnight skipped the new day's sweep, so yesterday's rows could still
  fill the 256-row cap and push a new name's first spend into the overflow total. A spend that
  would overflow now sweeps stale rows first, at most once a day per map.
- **Capability OAuth refreshes no longer replay a rotated refresh token.** Two capability calls, or two
  config generations, refreshing one expired provider token at once could each send the same refresh
  token, and a server that rotates refresh tokens may then revoke the whole grant. Capability refreshes
  now share the MCP backends' refresh flight: one exchange per stored token at a time, only the stored
  refresh token is sent, a token whose exchange had an unknown outcome is not sent again (from the
  first refresh on; such a provider then needs a new authorization), a dropped call still stores the
  rotated token, and a redirect from the token endpoint is not followed.
 
- **A caller with no key gets no A/B arm and no ranking hints of its own.** Before, a keyless
  legacy HTTP or stdio session got both, keyed on its session id; now no key means no entry, as
  the upgrade guide already said.
- **A backend added or replaced by hot reload is warm-started.** Its tools reach discovery once its warm-start completes, as for a backend present at startup, instead of being missing from the first discovery calls after the reload.
- **A tool priced below one micro-USD now counts against budgets.** Spend is kept in whole
  micro-USD (millionths of a dollar), and each call's price was truncated toward zero, so a price
  under $0.000001 never moved a budget and the fraction of every other price was dropped. A
  positive price now rounds up to the next whole micro-USD in both the budget check and the
  recorded spend, so a budget may count up to one micro-USD more per call than the exact price.
  A price that is already a whole number of micro-USD is unchanged, and a zero price stays
  free.
- **A refused config reload answers 409, not 500.** `POST /ui/api/reload` returns 409 when
  the network-posture policy refuses the file (tools reachable without a credential, or
  credentials over plain HTTP), 503 when shutdown stopped the reload, and 500 otherwise.
  The `gateway_reload_config` meta-tool answers that refusal with -32600. The message text
  is unchanged.
- MCP Events: a webhook subscription whose route was removed while it stayed stored (a
  capability directory that could not be read, or a removal that failed) no longer
  silently matches nothing when the route comes back with a filter or mapped field
  dropped. Such a reload is refused, as a narrowing of a live event type already is.
  A subscribe whose route changes during its callback challenge is refused at commit.
 
  Affects: 4.0.0 pre-releases only; 3.x has no MCP Events. Operator action: none.
- On every route, a relay receipt over a 2026-07-28 answer now leaves out the members the gateway's
  response shaper writes: the `resultType` it supplies and the `ttlMs`/`cacheScope` hints on a
  cacheable method. A backend's own `resultType` stays receipted.
  Affects: 4.0.0 pre-releases only. Operator action: none.
- MCP Events: a delivery that was replayed, or that failed at least once, is no longer dropped without trace when its subscription expires. It becomes a dead letter with reason `subscription_expired`, which the admin listing shows and can replay.
  Affects: 4.0.0 pre-releases only; 3.x has no MCP Events. Operator action: none.
- MCP Events: the admin dead-letter listing now filters on every reason a dead letter can carry; `?reason=tenant` and `?reason=subscription_expired` were refused before.
  Affects: 4.0.0 pre-releases only. Operator action: none.
- **An OAuth refresh with an unknown outcome is no longer resent to a server not yet known, and no longer costs a login on one that keeps its tokens.** The gateway now records whether a server keeps or rotates refresh tokens. Until a refresh has settled it treats the server as rotating, so an MCP backend's first unsettled refresh is not sent again (a rotating server would revoke the grant). A server seen to keep its tokens, MCP backend or capability provider, keeps the token after an unsettled refresh and the next refresh reuses it, where a capability provider used to ask for a new authorization.
 
- **Shutdown no longer starts backend warm-up.** A config reload that finished just as the gateway
  began shutting down could start warming a backend it had added, and keep contacting that backend
  until the drain ended. Warm-up now refuses new work once shutdown has been announced. (#3528)
- **`tools/list_changed` arrives once per real change.** A client is told the tool list changed
  only when the tools it can discover changed, and after they can be listed: a backend added by a
  config reload is announced once its tools are known, not before. A reload or an admin revive
  that leaves the tools as they were sends nothing, and a backend whose tools disappear is
  announced. (#3528)
- **A stdio request after the backend's stdout closed fails at once.** Before, it could wait out its whole timeout. The request's write now shares that timeout too, so a backend that stops reading stdin no longer hangs a call. (#3531)
- **Stdio backends get an absolute npm cache path when `MCP_GATEWAY_CONFIG_DIR` is relative.** A backend with its own `cwd` used to get a path that pointed somewhere else, so the npm cache repair cleared the wrong directory. (#3531)
- **A relayed modern discovery carries its cache hints.** A 2026-07-28 `server/discover` sent
  to one backend through `POST /mcp/{name}` now carries `ttlMs` and `cacheScope: "private"`,
  as the other cacheable results already did. A backend's own `ttlMs` is kept up to the
  gateway's 60-second cap. Legacy discovery and the gateway's own `/mcp` discovery are
  unchanged.
- **No OAuth discovery document without a sign-in server.** `GET /.well-known/oauth-protected-resource`
  answers `404` when the gateway can name no authorization server (auth off, API keys only, or
  agent auth). It used to publish a document naming none, which steered OAuth-capable MCP
  clients into a sign-in that could not complete. With `key_server.delegated_bearer` on, the
  document is served as before. See `docs/UPGRADING-4.0.md` item 172.
- **An HTTP backend start no longer handshakes on another slot's era verdict.** The era cache is shared by every slot of a backend (the shared slot and per-user slots). A start whose own `server/discover` probe was silent could read a Modern verdict another slot installed meanwhile and skip the `initialize` handshake its peer needed, or the reverse. A start now decides its handshake from its own probe: Modern skips the handshake, anything else handshakes.
 
- **Elicitation exchanges no longer slow down as the table fills.** Every elicitation read
  (hold, retry routing, completion) used to walk all held exchanges, up to 4 096, under one lock.
  The gateway now walks only when an exchange can have expired; a full table costs about the
  same per call as an empty one. (#3573)
- **The OAuth callback redirect URI keeps the configured IPv6 loopback spelling.** With `callback_host` set to an expanded IPv6 loopback such as `0:0:0:0:0:0:0:1`, the gateway sent the redirect URI as `http://[::1]:PORT/...`, which a provider that registered the configured spelling rejects. It now sends `http://[0:0:0:0:0:0:0:1]:PORT/...` as configured.
 
- **`chrome-devtools` says it needs Chrome.** The registry entry now carries a setup note naming its prerequisite, a local Chrome install, current stable or newer, shown when you browse the registry in the web UI. Before, it read as ready to start, and the first tool call failed with no hint why.
- **A request id the gateway cannot hold is never answered as another id.** A JSON-RPC
  request whose numeric id is above `i64::MAX` was answered with that id wrapped into a
  different, negative number, so a client could match the answer to the wrong request. It is
  now answered with `id: null`, as JSON-RPC 2.0 requires for an id the server cannot
  determine.
- **One idempotency key runs one operation.** A keyed call run normally and then retried as a task under the
  same key ran a second time; it is now refused. A keyed retry of `gateway_execute` or a task that differs only
  in per-request metadata (a fresh `progressToken`, other declared capabilities) is the same call, answered
  with its stored outcome or its task, as `gateway_invoke` already was. A keyed retry after a refusal of an
  undeclared question runs again once the client declares the capability; an earlier step that ran is never
  repeated. (#3603)
  After upgrading from an earlier 4.0 beta, retrying an unfinished task with the same idempotency key is
  refused as a mismatch for up to a day; retry with a new key.
  Affects: 4.0.0 pre-releases only. Operator action: none.
- **A caller hears when its own tools change.** On a backend with identity propagation, each caller has its own tool catalogue. A change to it was never announced, so a client listening for `tools/list_changed` kept showing stale tools until it relisted on its own. Now the backend's listeners get one content-free relist hint per actual change. An identical refill, or a credential refresh with the same tools, sends nothing. The hint carries no tool data and no caller identity. Other listeners on the same backend may relist once without anything changing for them. Webhook subscribers are not told.
- **Each backend connection speaks the protocol revision of the server it reaches.** A backend with per-user sessions keeps one connection per user beside its shared one. All of them shared one protocol-era verdict, so during a rolling upgrade, one connection's server being on the 2026 revision made the gateway send 2026-shaped requests (and refuse `ping`) on another connection whose server was older, and the reverse. Each connection now probes and remembers its own server's era; health checks and `gateway_list_servers` follow the shared connection, and their era records name the slot.
 
- **A tool found by its backend's name stays in the results.** With the search ranker on, a tool that search found only through the name of the backend serving it scored zero, so it dropped out whenever more tools than the requested `limit` matched the query. It now ranks above a tool whose description merely mentions the query, and below a tool whose own name contains it.
- **`/mcp` refuses what the per-backend route refuses, and gives back what a refused call took.** Under the
  hardened posture, a modern request that declares its revision in the body but omits a required field is told
  which field it omitted (400 / -32602), as on `/mcp/{name}`, instead of being asked to declare elicitation. A
  backend result that claims `input_required` but is malformed elsewhere no longer passes a question the client
  never declared; it is refused as its well-formed twin is. A signed call refused before its backend ran (a
  refused continuation, a spend refusal) gives back its signing nonce, so re-sending the honest call is not
  refused as a replay. A chain or playbook that ran any step keeps its nonce spent, so a replay cannot repeat
  that step. (#3626)
  Affects: 4.0.0 pre-releases only. Operator action: none.
- **Change notices stay bounded under heavy catalogue traffic.** Every tool-catalogue fill and every descriptor verdict used to queue its own `tools/list_changed` notice while the gateway was busy delivering, so a burst of fills could grow memory without limit. They now share one pending notice per backend. Clients are told exactly as before.
- **Linear issue writes show the description Linear stored.** `linear_update_issue` and `linear_create_issue` now ask Linear for the issue's description in their answer, so a caller can compare the text it sent with what was saved. Before, the answer left the description out, so a write that did not apply looked the same as one that did. Two description writes to one issue in one session are covered by a regression test. The original report of a dropped second write did not reproduce on this release.
- **A backend that refuses a credential with HTTP 401 gets the managed-account refresh, whatever its body says.** A backend that answered 401 with a JSON-RPC error body was read by the body, so a managed account got neither the forced refresh nor the reconnect offer. The status now decides for 401 and 403 alike (a 403 is a refusal the gateway does not retry; only a 401 triggers the refresh); the caller sees the status rather than the backend's own error text, as for a plain-text 401 or 403. A 401 saying the session expired still re-initializes the session, and a plain-text "session expired" now does too. A backend's own JSON-RPC error that happens to use code 401 is no longer read as a credential refusal; a CLI capability's refusal still is.
 
- **The library never prints to stdout.** In stdio mode the gateway's stdout carries the JSON-RPC stream to its client, so a stray line from library code would break the session. A lint now refuses any stdout print in library code outside tests; diagnostics go to stderr or the log.
- **A malformed CLI argument template is reported when the capability loads.** The template rules (one placeholder per argument, a parameter only as the value of a fixed option before `--`, a bound `each`, one placeholder per JSON or stdin string) ran only when the tool was called, so a broken definition loaded, was listed and failed every call. Loading, the registry index and `register_capability` now refuse it, on every process provider, with the message the first call would have given.
- **The audit record of a CLI call says how its process ended.** An invocation record that ran a CLI child now carries `process`: how it ended (`exited` with `exit_code`, `signalled`, `timed_out`, `output_overflow`, `observation_failed`), `duration_ms` from spawn, and `stdout_bytes`/`stderr_bytes` (null when the output was not kept). Counts only, never output; at most 16 entries, with `process_total` when more ran. Records of calls that started no child are unchanged.
 
- **A withheld question now gives its continuation slot back on streams and stdio too.** Continuing an earlier fix: a question the gateway withheld after sealing it (a cross-tenant read blocked, a delivery record that could not be written, a failed grant-decision write) now frees its continuation slot when the client asked over `POST /mcp` with an event stream, or over stdio, not only on plain JSON and `POST /mcp/{name}`. On stdio, an answer still waiting to be written when the session ends also gives its slot back. Delivered questions keep their slot for the client's retry. Affects 4.0.0 pre-releases only.
- **A CLI write no longer reverts another writer's change to `gateway.yaml`.** `add`,
  `remove`, `setup`, `cap discover --write-config`, `init` and `upgrade` used to read the
  file before taking the config lock, so a backend the dashboard or another command
  added, removed or edited in that moment could be undone. Each now reads, edits and
  writes under one hold of the lock, `--force` included. `init` keeps a config that
  appears after its own check, and a write whose text does not parse as a config is refused instead
  of saved.
- **Config hot-reload keeps hearing edits after a broken link chain is repaired.** When the
  config's symlink chain could not be resolved at startup (a target missing mid-update) and
  the config path ran through a linked directory, the repair could drop the watch on the
  config's own directory, so later edits there were missed until a restart. The watcher now
  records that directory by its canonical name. Config hot-reload is also tested on macOS now.
 
- **A health check's rebuild no longer takes a working backend out of service.** When a health check rebuilt an HTTP backend, it removed the working connection first and then started a new one. An OAuth backend whose token had lapsed, or whose token refresh stalled until the check timed out, cannot start again without a login, so the backend was left with no connection at all. The rebuild now starts the replacement first and swaps it in only once it is up; a replacement that cannot start leaves the working connection in service, and a connection still in use is closed only after its last call. The replacement's era probe no longer disturbs the connection still serving, and a backend upgraded to the 2026 revision is detected by the rebuild. Health checks now wait a full interval after each pass, so a slow failing rebuild is not retried back to back.
 
- A test of the OAuth refresh task waited a fixed 200 ms before reading what the task had done, so it failed at random under load. It now waits for the event itself. No runtime change. (#3704)
- **A host clock set before 1970 no longer loses or wrongly ends work.** A dashboard session on such a clock is refused but kept, so the browser keeps its cookie, and a sign-in link is refused without being used up; both work once the clock is right. Task expiry pauses rather than delete what it cannot date. An input round waits for the clock instead of being abandoned or left stuck in `working`. Budget spend restored at start-up still counts once the clock is right, instead of every daily budget restarting at zero.
 
- Docs and config: the README no longer lists semantic search or tool profiles, which 4.0 does not run, and names the real client-config exporter, `mcp-gateway setup export` (there is no `config export`). `examples/gateway-full.yaml` now loads as shipped, and with any one of its commented blocks uncommented: the blocks for settings the gateway does not read are gone, and the values it refused are corrected. An empty `backends:` section now loads, and reloads, as no backends instead of failing with "invalid type: found unit"; a `backends:` that is a list or a string is still refused. (#3752)
- Tests: the rate-limit counter row counts the refusals it observes and asserts the counter equals them, instead of expecting exactly two, so a loaded host whose limiter refills mid-row no longer fails it. No runtime change. (#3757)
- **The enterprise deploy scripts no longer misread a cluster listing.** `deploy/kubernetes/enterprise-alpha/scripts/preflight.sh` could report the ServiceMonitor API as missing when it was present, or as present when `kubectl api-resources` failed; the kind smokes could try to recreate an existing cluster. Each now checks the query before matching its output. (#3767)
- **A background check no longer opens a browser login it then abandons.** When an OAuth backend's token had just lapsed, the gateway's short background requests (the protocol check after a backend starts, event-listener upkeep, and task-recovery queries) could open the browser for a login and give it up two seconds later. A backend start could then fail with "authorization cancelled". These requests now never start a login; only a request someone is waiting on asks you to sign in. (#3775)
- **A sign-in waiting on another gateway process's client-id repair can be cancelled again.** When a stored OAuth client id was unreadable and another gateway process sharing the same storage was repairing it, a sign-in that registered a client waited for that repair on a blocking lock: restarting or stopping the backend could not end it, and it held a worker thread until the other process let go. The wait now gives way to a restart or stop at once, and gives up after 30 seconds, signing in with the id it just registered. (#3782)
- **A sign-in a request started stays open after that request gives up.** When an OAuth backend's token lapsed during a request with its own short deadline (a tool-list fill, a warm start, or a task-recovery query), the browser sign-in that request opened was abandoned with it. Approving it then did nothing, and the next request opened a second browser tab. The sign-in now runs on its own: approving it stores the token, the next request uses it, and callers that retry share the same sign-in. A restart or stop still ends it at once, and every stage of the sign-in (waiting for the client, registration, the browser, the code exchange, saving the token) ends at one shared deadline, so delays can no longer add up. (#3801)
- **`docker stop` no longer waits out the grace period while a `-full` startup step runs.** The `-full` image's entrypoint ran as PID 1, and a sourced `.envsh` step ran in its own shell, so a stop during that step waited for it to return: Docker's 10 s stop timeout, then a `SIGKILL`. The image now runs `tini -g` as PID 1 in front of the entrypoint, so the stop reaches the step at once and the container exits with status 143. tini also reaps orphaned processes. The default image is unchanged. (#3812)
- A retried `gateway_execute`, `gateway_run_playbook` or `gateway_invoke` call with an idempotency key, on a capability whose account is declared `shared`, is served its stored result again instead of being refused as minting no credential.
- **`mcp-gateway add filesystem`, `add memory` and `add sequential-thinking` now write current, non-deprecated pins.** The registry pinned `@modelcontextprotocol/server-filesystem`, `-memory` and `-sequential-thinking` at the date-based `2026.8.31`, which npm now marks deprecated ("Date-based versions are no longer published. This package has resumed semantic versioning at 1.0.0"). The three entries now pin `1.0.0`, upstream's final legacy release. Existing configs keep their pins; this changes what `add` and `init` write. Three differences you can see after moving to `1.0.0`. **`sequential-thinking` is no longer marked read-only or idempotent:** a `gateway_list_tools` call that asks for the `selector` or `extractor` role no longer lists it (ask for `action`, or for no role), and its results are no longer eligible for the response cache, which is correct for a tool that keeps the thought history. `mcp-gateway init` enables it by default, so new setups see this at once. **`memory` is stricter and starts empty:** it rejects a relation that names an entity that does not exist, and an entry added on the new pin starts a fresh graph in its own `npx` cache, so set an absolute `MEMORY_FILE_PATH` first if your graph matters. **`filesystem`** waits for the client's roots before serving tool calls and fails visibly when started with no directories and no roots. Operator action: none to keep working; to move an existing entry, re-add it or edit the version in your config.
- **A re-admitted playbook task now refuses a playbook reloaded before it runs, as a synchronous call does.** A task submitted while input sanitizing was off, whose worker ran after a reload turned sanitizing on, is re-checked before it runs. For a playbook call that is not sanitize-exempt, that check recorded the playbook's definition and then dropped it, so a playbook reloaded between the check and the run ran its new definition. The run now compares against the definition the check judged and refuses a changed one, with "The playbook changed after this call was admitted; retry the call". Its arguments were sanitized either way.
  Affects: tasks running `gateway_run_playbook`. Operator action: none.
- **The protocol-revision window opens no segment after shutdown has sealed it.** When the window's first open had not succeeded by shutdown (a stalled or unwritable data directory), a checkpoint that started just before the shutdown could still open a new segment after the seal: one that was never closed and was written after shutdown began. The seal now ends the window whatever it finds, and shutdown waits for the window's writes still running, within the existing close bound; a write still running at the bound is reported as not durable, as before.
- **A refused step in a task's `gateway_execute` chain or `gateway_run_playbook` run is now tied to its task in the audit log.** When a task-augmented chain or playbook ends on a step the gateway refused, the task's settlement now writes a `task_settlement` record that says `refused`, under the gateway and the composite tool's own name. Its `error_code` is the refusing check's own code, not the plan's `-32603` wrapper. A new `joined_by` field says how the record joins the rest of the log. `step_trace` means `trace_id` is the trace of the refused step's own invocation record. `task_id` means the plan ended with no usable step trace, as when a playbook refuses a step's arguments before that step runs, so `trace_id` is the task id. Before, such a task left no record that tied the refusal to it. A playbook that carries on past a refused step and delivers writes no refused record, and single-target task records are unchanged, with no `joined_by` field.
- **A cancelled Activity read keeps its slot until it ends.** Activity reads (the list, a receipt,
  an export and the live stream's catch-up pages) run at most four at a time. A list, receipt or
  export request whose client gave up released its slot at once while its read went on in the
  background, so cancelled requests could run more than four reads together. The slot is now held
  until the read itself finishes, so the limit holds under cancellation too. (#4653)
- **A config save refuses a new bearer token when an API key cannot be compared with it.** The check that stops one secret from serving as both the bearer token and an API key used to leave out a key whose digest reference did not resolve. Such a save is now refused before any secret is stored, naming the key's field and never the token or a digest. The web UI's "audit log required" answer is now chosen by the refusal's type rather than by its wording.
  Affects: the 4.0.0 pre-releases, saving a bearer token while an API key's `key_sha256` or `previous_key_sha256` reference does not resolve. Operator action: none.
- Activity: when a line in the audit log fails its integrity check and names no usable trace, every older call without a delivery now reads an unknown effect with `answer_integrity: "indeterminate"` instead of `no_record`, in the list, the receipt and both exports; the list response and the export manifest carry `answer_integrity_unattributed` (log, segment and byte offset of the first such line, or null) (#4849)
- Fixed the email hash so it is the same on every build. Its lowercase and its trim now come from tables the crate owns (frozen at Unicode 17.0.0, reproducing the standard library's lowercase at that version, final-sigma rule included) and the NFC data crate is pinned to an exact version in `Cargo.toml`, which `cargo install` honours, so a newer compiler or a floating dependency can no longer make two builds hash one address differently and lookups miss silently. The key server also refuses to start on a build whose normalization differs from its known answers. Surrounding Unicode white space is now trimmed in the hash at issuance as well as at lookup.
- Fixed the admin email lookup so that whether an address is accepted, and which rows it finds, no longer depends on the Unicode tables of the compiler that built the gateway: the route hashes the address as typed (the hash trims it with its own frozen `White_Space` list) and refuses control characters from a fixed list.
- **The shipped templates no longer SIGKILL the gateway mid-stop.** The systemd unit, the Compose file, the launchd plist, the Helm chart, the enterprise-alpha Deployment and every `docker run` in the docs now give the gateway its stop timeout + 1 s (31 s at the default) before the kill; before, they cut it off at 30 s, 10 s or 20 s, inside its own stop. The systemd unit also sets `KillMode=mixed`, so the gateway stops its stdio backends in order instead of the service manager signalling them all at once. The Helm chart derives the grace from `config.server.shutdown_timeout` and refuses to render a value the gateway would refuse at start. A new CI check holds every shipped template and docs example to this.
- **An HTTP stop no longer lets a held restart lock eat a stdio backend's graceful stop.** The backend stage now hands every live stdio backend to the reaper at its first step, before waiting on any backend's restart or stop lock, so each child still gets its stdin close and SIGTERM waits before the kill. Each backend's plan is fitted to what is left of the stage at its own handover. The stdio stop is unchanged.
- Add tests that a modern-era backend is searchable without any request to it, and that the meta-tool band matches public_claims.json.
- Add an end-to-end test that `mcp-gateway upgrade` from 3.x emits the 4.0.0 notice once, stays silent on rerun and leaves the config untouched.
- **A stdio backend call no longer pays a thread handoff for its request frame.** Every frame
  written to a stdio backend was handed to its own task and awaited, so each `tools/call` woke a
  second worker thread and then the caller (about 1.6 extra context switches per call against
  3.5.1). The write is now attempted in place first; a frame that fits the pipe completes there,
  and only a write still pending moves, with its progress kept, to its own task. A caller dropped
  mid-write still cannot cut an admitted frame. Measured on the sequential tool-call benchmark
  over a Unix pipe (Linux, same-run paired): gateway CPU per call −9.2 µs, median latency
  −4.5 µs. A blocking-backed stdin, as on Windows, takes the task path more often.
- **Discovered-config reload tests no longer race for a port.** The tests start the gateway on `server.port: 0` and read the port it logs, and the `/livez` start-up probe has a per-request timeout. Tests only.
- **Tasks stay on in stdio mode when an auth secret cannot be resolved.** A stdio gateway no
  longer reads the HTTP auth configuration to open its task store, so an auth secret that does
  not resolve (for example an unset environment variable) no longer turns tasks off.
  Affects: 4.0.0 pre-releases. Operator action: none.
- **A cancelled call stops on the backend.** When a client cancelled a call, closed its
  connection mid-call, or the gateway gave up on it, a backend on the 2025 protocol kept running
  it, because nothing told it to stop. The gateway now sends that backend one
  `notifications/cancelled` naming the id the backend received, over HTTP (on the same session),
  WebSocket and stdio. A call that was answered, timed out inside the gateway, or never written,
  and `initialize`, are never cancelled. A 2026 HTTP backend needs no message: closing the
  request's stream already cancels it.
- A per-user slot that a grant revocation removes while a request is still running on it no
  longer decides the backend's protocol era: a re-probe answer that arrives after the removal
  is discarded, as one from a replaced connection already was. Both the revocation and the idle
  reaper mark a slot retired before it leaves the pool.
  Affects: per-user (identity-propagated) backends during a grant reload. Operator action: none.
- `POST /mcp/{name}/<sub-path>` now answers 404 instead of 500: the sub-path alias of the per-backend route never served, and is removed.
- **A task can always settle when its result is too large to store.** A result over
  `tasks.max_record_bytes` is stored as the gateway's own bounded failure. Under a small cap even
  that failure could fail to fit, and the task then stayed `working` until its TTL ran out. A task is
  now created only with room for that failure, an input round that would use up the room is refused,
  and the store refuses to open with a stored live task that has no room, naming the cap it needs, as
  it already does for a row over the cap.
  Affects: 4.0.0 pre-releases only; 3.x has no task store. Operator action: none at the default cap.
- **A task input round that fits the record size limit is no longer refused.** The check that a
  round leaves room for its shortest answer counted the answered question twice; it now measures
  the record as that answer is really written.
  Affects: 4.0.0 pre-releases, rounds close to `tasks.max_record_bytes`. Operator action: none.
- **A losing `tasks/update` no longer waits a second for its refusal.** When two updates completed
  the same input round together, the one that lost could wait the full one-second hand-over limit
  before it was told no round was outstanding, because the winner's move to `working` woke nobody.
  The winner's commit now wakes it, and it is refused at once.
- Answers on the per-backend route `/mcp/{name}` now write the `response_delivery_attempt` audit record that `POST /mcp` and stdio write. The record has the same fields, carries the read verdict, and withholds the answer under `FailClosed` when it cannot be written.
- **Release matrix citations are current.** The supported matrix cites the live lines for the modern protocol constant, the `modern_protocol` default and the default protocol version, and the MRTR.7 stdio test header names the production caller of the input bridge. Docs and comments only.
- A tool result that carries `taskId` and `result` but no task `status` is now delivered as the
  tool sent it: its nested `result.cacheScope` is no longer rewritten to `private`, because it is
  tool data rather than a task envelope. A server-to-client request on the event stream is also
  delivered unchanged. The result's own top-level `cacheScope` is still never `public`.
  Affects: 4.0.0 pre-releases only; 3.x has no `cacheScope` clamp. Operator action: none.
- A caller that made a call while the idle sweep, or a session disconnect, was reclaiming
  its expired deadline no longer has the hint and anomaly state from that call wiped by
  the cleanup.
  Affects: 4.0.0 pre-releases only; 3.x has no idle deadline sweep. Operator action: none.
- **Windows mutant rows run under pwsh.** The mutants workflow launches its Windows rows from pwsh, as the Windows check does, and a step fails the job if the shell holds an enabled backup or restore privilege, so an ACL-refusal mutant is judged in the same environment as CI. CI harness only.
- Relay detection under `block` no longer refuses a caller that forwards its own copy of a
  source's content when that copy reached it split mid-word over short fields. The caller's
  delivery receipt now also records the pieces run together, as outbound calls are read, so
  its own receipt excuses the forward. A copy it was never delivered is still refused.
 
  Affects: 4.0.0 pre-releases only; 3.x has no relay detection. Operator action: none.
- **A listen names its tasks where the tasks extension puts them.** `subscriptions/listen` reads the task filter from `notifications.taskIds` as well as the params root, as one filter. The ownership narrowing and the direct-route guard cover both placements, and the acknowledgement names the narrowed ids.
- Events: governance audit records name the real failure code of a refused verification, take the callback host stamped at fan-out, are labelled subscribe or refresh by the commit itself, and a dead letter the caps evict at once still leaves its record.
On a multi-user gateway, an API-key or admin-bearer caller can now use `mcp` capabilities: it gets its own child process, named by its credential, and a background task it starts reaches the same child. Before, every such call was refused as needing an identified caller. A single-user gateway still runs one shared child.
- **An embedded stdio gateway stops its task workers when its session is dropped.** A host that
  cancels `run_stdio` before EOF (drops its future) no longer leaves task workers running: they stop
  at once, no later task write is admitted, and the task store's lock is released. A write already
  under way when the session was dropped finishes.
  Affects: 4.0.0 pre-releases, embedders of the crate. Operator action: none.
- Events: `task.settled` is published for tasks the startup recovery settles, because the task event source is installed before recovery runs instead of after.
- Events: an attempt ending (revoked or overdue) that the audit log refuses is retried instead of being removed unrecorded; pre-upgrade records are documented as `unrecorded` and an attempt with no body as an empty body hash.
- Fixed: task shutdown bounds the expiry join and store close, keeps the store open under a task that did not stop, and refuses a task started after the drain.
- **`firecrawl_search` accepts Firecrawl's v2 search response.** Its output schema listed only
  `success` and `data` and refused anything else, so a real v2 response, which also carries `id`,
  `creditsUsed` and `warning`, failed output validation. The schema now allows extra top-level keys,
  as the Brave and Tavily schemas do.
- A backend start refused before it could connect (an OAuth and identity-propagation clash, an invalid URL or WebSocket header) no longer makes a later `hardened` registry pairing refuse that backend, and an HTTP start that read its destination policy before a pairing stamped one now refuses instead of connecting unpinned, with its OAuth client built under the same policy as its transport.
- **An OAuth capability with an expired, unrefreshable or unreadable token is not listed.** `tools/list` and search no longer offer a capability whose login cannot be used.
- A provenance receipt's `backend_ok` is now optional and an event receipt carries none, where it used to sign `true` unobserved; scoring abstains on an event receipt (UPGRADING-4.0 item 140).
- **A confirmation question that never reached the client no longer spends the signing nonce.** Under hardened signing, a destructive call refused because no session could carry its question gives its nonce back, so a retry carries the same nonce. A question that was delivered and then timed out or was cancelled keeps the nonce spent, since the operator may have seen it.
- **A server-ended listen names the server.** The terminal `subscriptions/listen` result now carries `io.modelcontextprotocol/serverInfo` in `_meta`, as every other result does.
- A startup subscription reconcile that cannot finish now logs a warning on every failed attempt and every 30 s of waiting for the capability scan, so a stalled start names its cause.
- The EVENTS.8 evidence script now fails a run whose unsubscribe named another subscription than the verified subscribe (another callback URL or arguments), or whose subscribe or unsubscribe was batched with other calls; the dev shim records a digest of each call's event, callback URL and arguments instead of the URL itself.
- events: authorization of a backend's upstream events now consults the live eligibility check, so a subscription or a queued event for a backend a reload made ineligible is refused at subscribe, fan-out and delivery alike; the delivery worker asks again after the audit waits, just before the send
- **A backend registered before the events startup check keeps its subscriptions.** At startup the events hub withdraws the subscriptions of backends removed while the gateway was down. A config reload that registered a backend in the middle of that check could have the backend's stored subscriptions withdrawn although it was registered by then. A registration now waits for the check to finish: a backend registered before the check keeps its subscriptions, and one registered after it finds the subscriptions of a backend absent at startup already withdrawn. Affects 4.0.0 pre-releases only.
- A legacy upstream peer can no longer hold more of the gateway's `resources/subscribe` subscriptions than the per-backend URI cap: a subscription the gateway cannot rule out stays counted until the backend is removed from or replaced in the config, or the gateway restarts. Updates for URIs nobody watches no longer take room from wanted ones. Affects 4.0.0 pre-releases only.
- An upstream event listener no longer reads an unresolved protocol era as legacy, replaces a modern stream before its hourly cut while the old one keeps delivering, backs off listens that are never acknowledged, and re-handshakes a session whose stream open is answered 404. Affects 4.0.0 pre-releases only.
- An upstream event listen that the backend answers with `-32601` or HTTP 405 now ends as unsupported on HTTP, stdio and WebSocket, instead of being retried fast as a failure. On a modern stream, notices that arrive before the acknowledgement, or fall outside what it honoured, are dropped; notices still being coalesced when a session ends are delivered. Affects 4.0.0 pre-releases only.
- **A call that just finished no longer counts twice against a budget.** With cost governance
  on, a budget check that ran while another call was recording its spend could see that call
  both as spent and as still reserved, and warn about or refuse a call that fit. Recording the
  spend and giving back the reservation are now one step. The gateway never admitted more
  than a budget allows, before or after.
  Affects: deployments with cost-governance budgets and concurrent calls near a limit.
  Operator action: none.
- **A reload that removes a backend stops its pending event deliveries.** A delivery
  already past its checks is held, not sent, when a config reload removes its backend
  or makes it ineligible before the send.
- **A Windows capability server sees its root and files spelled the same way.** The root and
  confined paths are handed on in the plain `C:\...` form when that names the same file, so a
  server that resolves only one side no longer refuses a file inside its root.
- A destructive-action confirmation prompt that is withheld from the event stream (every copy
  refused at write) is now treated as never delivered, like a missing session, instead of as a
  prompt the operator may have seen; a modern request refused this way keeps its confirmation
  unspent.
  Affects: 4.0.0 pre-releases only. Operator action: none.
- **A replaced `mcp` capability's processes end even when its runtime is idle.** Replacing a
  definition through `register_capability` now ends the old children's whole process trees at once,
  from any thread and without a Tokio runtime. Before, an embedder that started them inside a
  current-thread `block_on` and stopped driving that runtime left them running. A call still on a
  replaced child fails, reported as uncertain if it was already sent.
  Affects: 4.0.0 pre-releases, embedders of the crate; the gateway binary was not affected.
  Operator action: none.
- **A backend's `null` result reaches the client.** A backend that answered with `"result": null`
  over HTTP or WebSocket, or a replayed idempotent answer with a `null` result, reached the client
  as a frame with neither `result` nor `error`, which JSON-RPC 2.0 forbids. The `null` result is
  now delivered as sent; an error response still carries no `result`. Where response signing or
  signature-chain emission applies, a `null` result is refused like any other non-object result.
 
- **A call that races a reload can be retried under its idempotency key.** A backend that a reload or
  shutdown had stopped refused the call before sending anything, but the refusal settled the call's
  idempotency key as a failure, so a retry under the same key got that failure back for work that
  never ran. The refusal now frees the key, and a retry reaches the backend that replaced it. This
  refusal now answers `-32001` ("not found") instead of a backend-unavailable error, and is audited as
  `invalid` rather than `error`; it occurs only when a call races a reload or a shutdown. Warm start
  still retries such a backend after a reload.
- **A backend's slow tool list no longer delays its other event notices.** When a backend announced a
  tools change, the gateway refilled its cached tool list before handling anything else from that
  backend, so a `tools/list` that hung delayed every other notice on the session (resource and prompt
  changes, resource updates) for up to 30 seconds. The refill now runs alongside the session, which
  keeps delivering other notices; the `tools_changed` event still waits for the refreshed list.
 
- **A backend that comes back is listened to again at once.** When a backend was removed and re-added (or replaced by a config reload) just as its event listener found it gone, or while the listener was waiting to reconnect, the listener could miss the signal and wait up to 30 s, or its full reconnect backoff, before listening again. It now reconnects at once. Changes to subscriptions alone still leave a failing backend's reconnect backoff in place. Affects 4.0.0 pre-releases only.
- **An owner-scoped event is delivered after its record expires.** An owner-scoped event, such as a task's final status after the task record expired, is no longer refused and its subscription revoked by the delivery worker. Affects 4.0.0 pre-releases only.
- **Relay and cross-tenant read checks read what is delivered.** A catalogue result was
  classified before delivery stripped its signature-chain member, so text the caller never got
  could set its context-integrity verdict and audit classes; it is now classified as delivered.
  Stdio catalogue relay refusals are audited under the stdio session id. A session-stream event
  no longer rescans its `data` through the wrapper (a `data.id` equal to a tenant was
  attributed), and judging a response no longer copies its result twice.
- A `tools_changed` subscription accepted while its backend could not be listened to (refused
  by the live config or its detected transport, or not registered yet) now gets the backend's
  own `notifications/tools/list_changed` once the backend can be listened to. The same holds
  for a listener that ended because its backend turned ineligible. The listener comes back
  within 30 s of the backend becoming eligible, with no reload and no new subscription.
 
  Affects: 4.0.0 pre-releases only; 3.x has no upstream events. Operator action: none.
- While a resource URI is watched for upstream events, the gateway re-reads the backend's
  resource catalogue every `meta_mcp.cache_ttl` (at most once a second) instead of a fixed
  300 s, so a resource removed upstream stops being delivered as soon as the catalogue cache
  would notice. The default (300 s) is unchanged.
  Affects: 4.0.0 pre-releases only; 3.x has no upstream events. Operator action: none.
- **Audit records name the right outcome, correlation key and attribution.** A backend's own
  `-32602` answer settled as `invalid`, as if the gateway had refused the caller's input; it is
  now `error`, and a gateway refusal stays `invalid`. A refused call on the stateless
  2026-07-28 route with no caller trace id was keyed on an empty session, so every such refusal
  correlated as one; it now takes the minted trace id. A keyed call refused for a
  broken signature chain kept `uninspected` only on its first answer; a replay now records
  `cached_delivery_uninspected` too.
- A backend whose tool list was never fetched now gets fetched in the background when a client
  calls `tools/list` with a `query` or `gateway_list_servers`, as search already did, so its tools
  show up on a later call instead of never. A backend that propagates caller identity, one the
  multi-user guard isolates, or one the caller may not see is not fetched this way; search still
  fetches those with the caller's own credential.
  Affects: 4.0.0 pre-releases only. Operator action: none.
- **Web UI backend edits keep the comments in `gateway.yaml`.** An edit now changes only the
  keys that changed, so the entry's comments, inline comments and every other line stay, and a
  CRLF file keeps its line endings. An edit that cannot be written as a text change (a flow-style
  mapping, or a comment inside the changed value) is refused with `409` naming the lines of the
  comments a full rewrite would drop, and the file is left untouched. The CLI keeps its
  full-rewrite fallback.
- **Config errors no longer echo configured values to the web UI.** A refused edit names line
  numbers, never file text, and a load or reload failure during a web UI edit withholds the
  parser detail, which can quote a value. The CLI still shows the detail.
- **A malformed `${...}` reference is reported by field, not by name.** The message no longer
  repeats the text inside `${...}`, which could be a literal secret; the field path still
  locates it.
- **MCP Events follow the transport a backend connected with.** Since `add --url` stopped writing
  `streamable_http`, a backend reached over Streamable HTTP was refused
  `backend.<x>.resources_changed` and the other upstream events with `sse_handshake_transport`,
  because eligibility was read from config alone. A subscribe now starts an undetected backend, as
  `tools/call` would, and judges the transport it connected with; a failed start answers `-32000`.
  See `docs/UPGRADING-4.0.md` item 148.
- **A REST capability sends an explicit null the schema admits in its JSON body.** A body field
  that is a pure placeholder dropped a caller's `null`, so a backend that reads null as "clear
  this field" never saw it. A null whose property `type` admits null is now sent, even where a
  URL default fills the same parameter. Any other null is still left out, and query and path
  parameters are unchanged.
- A backend start waiting on an interactive OAuth login is now bounded: the callback wait ends
  after 300 s with `AuthorizationIncomplete`, and the callback port is free again when the
  error returns. Callers queued behind that login share its end instead of each opening a
  browser, a forced restart or a stop ends a pending login first, and the health probe never begins or
  waits on one. A login wait is not counted as a backend failure. Worst case for a start's
  OAuth phase: 420 s (two 30 s discovery steps, 30 s registration, the 300 s window, a 30 s
  token exchange). See `docs/OAUTH_CONFIG.md`.
  Affects: OAuth-protected HTTP backends whose login is never completed in the browser.
  Operator action: none.
- A response-cache hit or an idempotent replay (HTTP or stdio) now leaves out of its relay receipt
  what the gateway wrote into the original answer (cost advice, the recovery hint), as the original
  call's receipt already did, and a replayed side-effect notice, which is gateway text, leaves no
  receipt; a backend member with the same name stays receipted.
  Affects: 4.0.0 pre-releases only. Operator action: none.
- **State a call writes after its session ended is now removed, however long the call ran.**
  Before, a second cleanup pass two minutes after the end caught a call still in flight, but a
  longer call, or one that started after the end (a task worker, an input-round resume, a call
  released from a confirmation), left its profile, workflow state, cost bucket and last-tool
  entries under the dead session id for the life of the process. Each such call now holds its
  session until it finishes, and the last one to finish on an ended session runs the session's
  cleanup again. The two-minute pass stays as a backstop.
- A backend's `notifications/tools/list_changed` is no longer lost when it arrives during a
  tools refill and the upstream session then ends, or when the refill meets the backend's
  10 s list-fill cooldown (for example while a warm-start fill is on the wire). The notice
  stays owed to the backend's listener: a refill that did not fill is retried once after the
  cooldown, and subscribers hear one `tools_changed` per notice.
  Affects: 4.0.0 pre-releases only; 3.x has no upstream events. Operator action: none.
- **A writer beside the config no longer costs the config watcher CPU on Linux.** Every write in
  the config's directory, such as a profiler's output or any other file, woke the watcher, which
  then re-resolved the config's whole link chain. On Linux only an event on the config file, a
  link on its chain, or a watched directory itself now does. Edits, atomic renames, `ConfigMap`
  updates and release-link retargets reload as before, and a chain that cannot be resolved still
  wakes on every event and retries every 2 seconds. macOS and Windows, where a file can be
  reported under another spelling, keep waking on every event.
- **CLI config writes no longer drop `gateway.yaml` comments silently.** `add`, `remove`,
  `setup wizard` and `cap discover --write-config` keep comments when the change can be written
  as a text edit, one backend at a time, and the file is written once. When it cannot (a
  flow-style mapping, a comment inside a changed value, or a change outside `backends`) and the
  file has comments, the command writes nothing, exits non-zero, and names the lines of the comments a rewrite would
  drop. `--force` names the same lines, then rewrites the file without them. `remove` names the
  comment lines that went with the removed entry. The web UI's refusal message now points to
  `--force` instead of `add` / `remove`.
- **A config directory deleted and recreated in place is watched again.** The watch on the old
  directory ended with it, but the watcher kept it on record and never watched the new one, so the
  gateway kept its old config until the link chain next moved. Removing or renaming a watched
  directory now drops its record, and the next pass watches the directory found at that path and
  reloads. A link chain that heals after failing to resolve also reloads now, even when it ends at
  the same file.
- On the direct route (`POST /mcp/{backend}`), a caller's relay receipt now leaves out what the
  gateway wrote into the answer: its cost warnings (also once the response scan has redacted
  them), its signature and its signature-chain link, live and on an idempotent replay, and the
  provenance stamp on a replay. A caller passing on that gateway text is no longer refused as a
  relay; a backend member with the same name stays receipted.
  Affects: 4.0.0 pre-releases only. Operator action: none.
- **Web UI and CLI backend edits keep each line's own ending in `gateway.yaml`.** A file that
  mixes `\n` and `\r\n` line endings, or ends without a final line break, used to come back
  with every line's ending changed after one backend add, edit or delete. Lines the edit does
  not touch now keep their bytes, an edited line keeps its ending, and a new line ends like
  the line next to it.
- **Adding the first backend to a `gateway.yaml` that contains only comments now works.** The
  web UI and CLI used to refuse that edit because it would drop the comments (and `--force`
  dropped them); the backend is now added below the comments, which stay as they were.
- **A capability reload that cannot read one directory no longer deletes watch subscriptions.**
  While a reload had left a capability's directory unread, the next poll of its
  `watch.<capability>.changed` type withdrew every subscription to it, with its pending events,
  and an event already queued, or a reload landing during a poll's access check, could revoke one
  too. The source now ends a watch subscription only when a complete catalogue lacks the
  capability, or when the capability was read and is no longer watchable (including one the
  account gate refused, or an unload removed), and only when no reload landed between reading
  the catalogue and the decision.
- **Web UI backend edits now hold one config lock across loading, writing and reloading
  `gateway.yaml`.** Two such edits, from one gateway or two, can no longer overwrite each
  other's change. The lock is a hidden `.gateway.yaml.lock` file next to the config, kept
  there on purpose. CLI writes (`add`, `remove`, `setup`, `cap discover --write-config`)
  take the same lock for their write: one that meets another writer's lock says
  `Waiting for ...` and continues once it is free; if it stays held for 30 seconds the
  command writes nothing and exits non-zero, asking you to retry.
- **A plan that drops relay receipts is counted once.** The dropped-plan metric now counts
  each plan once, however many of its steps pass the staging bound.
- **A tool-list refresh waits for the pending change to be announced** before it runs, so
  a client is not told about a list the refresh already replaced.
- **A timeout on a joined tool-list fill names the backend.** A request that waited on another request's tool-list fetch reported "authorization pending" when its deadline passed while any login was pending, even though that fetch had already reached the backend and the backend was just slow. It now reports the backend's timeout once the fetch it joined has sent its request; a fetch still waiting on the login still reports "authorization pending".
- **Removing a server in the dashboard says which comment lines went with it.** A removed
  backend's own lines go with it, including any comments inside its entry; the dashboard now
  shows those comments' line numbers (never their text) after the removal.
  `DELETE /ui/api/backends/{name}` returns 200 with `{"note": "..."}` in that case, and 204
  as before when no comment was dropped.
- **Watch subscriptions poll again after a restart.** A stored `watch.<capability>.changed`
  subscription was restored before the startup capability scan finished, found nothing to watch, and
  was never retried, so it stayed silent until it was made again. The same happened when a reload
  briefly dropped the capability. The events worker now starts such a poller within 30 seconds of
  the capability being offered again.
With gateway authentication and agent authentication both on, a valid agent token can now use tasks on a public /mcp: each agent owns its tasks under its `client_id`, the same owner it has with gateway authentication off, apart from every other agent. Before, every task method answered an agent as if no task existed and task creation was refused. Event subscriptions still need a gateway credential.
- **A caller is no longer refused for relaying text it was itself delivered in a long answer.**
  A receipt keeps only the head and tail of a long delivery (and a bounded number of
  fingerprints), so text from the middle was unrecorded for its holder: relaying it was
  refused whenever another caller held it whole from the same source. The gateway now keeps a
  compact sketch of what each cut delivery carried, used only to excuse that caller. Plan
  answers over 1 MiB are covered too; see the added entry.
- **A dropped stdio request can no longer corrupt the next caller's request.** A request
  cancelled or timed out while its frame was being written to a stdio backend left half a
  frame on the shared pipe, and the next caller's frame was appended to it. Each frame is
  now written whole, and a request cancelled while waiting to write sends nothing. Closing
  a backend is no longer held up by a write stuck on a backend that stopped reading.
- **Stopping a stdio backend can no longer signal an unrelated process group.** The gateway
  ends the backend's process group before it reaps the backend's main process, so the group
  id is still the backend's own when it is signalled. A process the backend forked while
  being stopped is ended too. Two regression tests come from [#3419](https://github.com/MikkoParkkola/mcp-gateway/pull/3419) by
  [@terafin](https://github.com/terafin).
  Affects: 4.0.0 pre-releases, stdio backends on Linux and macOS. Operator action: none.
- Relay detection under `block` no longer refuses, now and then, a caller forwarding its own
  copy of a source's content when that copy reached it in a different shape (for example split
  over short fields). Fingerprints were chosen per window, so which ones a copy kept near its
  edges depended on the text around it, and the caller's own receipt could lack one that the
  forward and another caller's receipt both held. A k-gram is now kept by its own hash, so a
  shared k-gram is kept in both texts or in neither, and the caller's own copy always excuses
  its forward. A copy it was never delivered, or text beyond what it holds, is still refused;
  as a sample of its k-grams is kept, a copy of 80 chars is caught 999 times in 1,000 and one of
  100 chars all but always. About twice as many fingerprints are tracked per text; the
  tracked-state bound is unchanged, so under heavy traffic it covers about half as much
  delivered text.
  Affects: 4.0.0 pre-releases only; 3.x has no relay detection. Operator action: none.
- **An HTTP gateway no longer waits forever at exit for disk work left running.** After its shutdown
  steps finish, the process waits at most 10 more seconds for disk work still running (as `serve --stdio`
  already did), then exits and logs at ERROR that it left blocking work behind. Writes that
  finish within the 10 seconds complete as before.
  Affects: 4.0.0 pre-releases, HTTP serve with a task store or audit log on network or
  FUSE storage. Operator action: none; an ERROR at exit points at the storage to check.
- **A damaged OAuth refresh-state file no longer lets the gateway resend the stored refresh
  token.** The gateway marks a refresh token in flight in a small file beside the credential
  before sending it, so that a refresh interrupted by a stop is not repeated. When that file
  existed but could not be read or parsed, the mark was lost and the token was sent again, which
  a server that rotates refresh tokens may answer by revoking the grant. The token is now retired
  instead, and a fresh login is asked for. An absent file is unchanged.
- **A stdio request waiting for its turn holds one copy of the message.** The frame is built
  in place from the serialized request, so a backlog of large requests behind a slow backend
  uses half the memory it did.
- **A dashboard save that loses its connection still finishes.** Adding, editing or
  removing a backend in the web UI writes `gateway.yaml` and then reloads the gateway. If
  the browser disconnected between the two, the file had the change and the running
  gateway did not. The save now always runs to the end, so the gateway runs what the file
  says.
- **A repaired task record reads again without a restart.** When an operator repairs a task
  record whose key could not be read, the next expiry sweep now serves its task again: `tasks/get`
  returns it and a task retry with the same key finds it. A repaired task that was still running
  when the earlier process stopped is first settled as a restart would settle it.
  Affects: 4.0.0 pre-releases. Operator action: none; a restart is no longer part of the repair.
- **No events from a backend the gateway cannot listen to, even while it reconnects.** A backend
  whose connection uses the legacy SSE handshake cannot offer upstream events, and a delivery for
  it is refused. While the gateway swapped that backend's connection for a new one, there was a
  brief moment in which the backend read as not yet detected, and a delivery admitted in that
  moment was sent. The new connection now replaces the old one in a single step, so a delivery
  sees one or the other and a legacy backend's events stay refused throughout.
- **The SIEM file sink no longer glues a record onto a torn line.** A gateway killed or crashed
  in the middle of writing to the export file left a partial last line, and after a restart the
  same batch was appended right after it, producing one line no SIEM consumer can parse. The sink
  now cuts the file back to its last complete line before it appends, and logs how many bytes it
  dropped. A file that already ends cleanly is appended to unchanged.
- **An API-key caller can confirm and resume on every path.** A caller authenticated only by an
  API key, with no verified identity, was refused at the confirmation of a destructive task call
  (`-32003`) and at a chain resume (`-32602`), although `gateway_invoke` continuations already
  bound it by its key. Every path now binds a caller the same way: its verified identity, else
  the key it authenticated with. A chain step behind an identity-propagating or account-bound
  backend now resumes under the binding it was stopped under. The in-band confirmation on `/mcp`
  binds the key itself rather than its configured name, so a key re-issued under the same name
  must be asked again. A caller with neither an identity nor a key is still refused.
Every package manager a stdio backend runs (npm, npx, bunx, yarn, pnpm) now gets its per-backend cache from one assignment. A data directory whose path is not valid UTF-8, holds a `..` component, or holds `${`, is assigned to no runner and the backend keeps its runner's default cache, instead of a mangled path the runner would create elsewhere. An operator's cache setting is recognised in exactly the spellings that runner reads. Yarn Berry's global cache is turned off so the yarn cache folder, the gateway's or the operator's, takes effect. A non-UTF-8 `MCP_GATEWAY_CONFIG_DIR` is now used rather than silently replaced by the default.
- **A signed call refused by execution admission gives its nonce back, on `/mcp` and stdio.** A keyed call
  that admission refuses (a key reused for other arguments, a key still in flight, no execution owner) was
  refused after its signing nonce had been admitted, and kept the nonce spent: re-sending the honest call under
  that nonce was refused as a replay. Admission now gives the nonce back on both transports, since nothing has
  acted yet. A call admission answers from its stored run keeps the nonce, as a delivered call does. A relay refusal and any task call's refusal still keep the nonce for now
 .
  Affects: 4.0.0 pre-releases only. Operator action: none.
- **One `gateway.yaml` reached two ways now has one lock, and a save keeps a symlink.** A
  config named through a symlink and through its target, or by a relative and an absolute
  path, got two lock files, so two writers could both "hold" the lock and lose an edit. Both
  spellings now share one lock. A save through a symlinked config used to replace the link
  with a plain file; it now updates the file the link points to and keeps the link.
- **A keyed `/mcp/{name}` call now shares the execution lease with `/mcp`, stdio and tasks.** One idempotency key covers one backend operation, whichever route sends it. Before, the direct route checked only its idempotency cache. A direct call under the key of a task or a `gateway_invoke` still in flight could reach the backend a second time, and a retry after the cache entry expired ran the call again. Now a direct call whose key belongs to another execution or representation is refused with 409 "Idempotency key belongs to another execution or representation", and the backend runs once. A completed direct call retried after its cache entry expires replays the stored answer, signed for the retry's own nonce. A refused call gives its cache reservation back and spends no signing nonce.
  Affects: deployments whose clients send idempotency keys to `/mcp/{name}`.
  Operator action: none.
- **A stalled disk no longer holds an HTTP gateway's shutdown.** The saves an HTTP gateway makes
  as it stops (search ranking, transition tracking and, with cost governance on, today's spend) now
  run together under a 10-second deadline. A save stuck on a stalled mount is abandoned and logged
  as an error, and the process exits. The 5-minute periodic cost save no longer runs on the
  gateway's own threads, and cost writes take turns, so an older periodic snapshot cannot overwrite
  the final one.
  Affects: 4.0.0 pre-releases. Operator action: none; an abandoned save is named in the error log.
- **A question the gateway withheld no longer holds a continuation slot until it expires.** When a backend asked the client a question over `POST /mcp` (without an event stream) or `POST /mcp/{name}`, and the gateway then withheld the answer (a cross-tenant read blocked, a delivery or invocation record that could not be written, a failed grant-decision write, or a withheld confirmation challenge), the question's slot in the 4096-slot continuation table stayed taken until it expired. These slots are now given back as soon as the answer is withheld, so a burst of refusals can no longer exhaust the table. Delivered questions keep their slot for the client's retry. Affects 4.0.0 pre-releases only.
- **Every other copy of an undelivered question now gives its continuation slot back too.** A question dropped before it was written (a stdio cancel, a closed or unread event stream), a task round that was cancelled, closed at its deadline or expired, a completed task result deleted unread, and a replayed answer that never reached the client all kept their slot until it expired. The slot is now given back once the last copy of the question is dropped without being delivered, while a question delivered directly, by replay, by `tasks/get` or in a task notification keeps its slot until it is answered or expires. Affects 4.0.0 pre-releases only.
- **A refused state-only round no longer holds a continuation slot until it expires.** An `input_required` round that carries only state and asks the client nothing kept its continuation slot until expiry when the gateway refused it (the firewall, or a delivery record that could not be written), on `POST /mcp`, stdio and tasks (the initial round and a resumed one). The slot is now given back when the round is refused. Affects 4.0.0 pre-releases only.
- **Event subscriptions follow backend and catalogue changes without waiting for a sweep.** Removing a backend now withdraws all of its event subscriptions, not only `tools_changed`. A backend that becomes ineligible loses its upstream event subscriptions. A re-added backend is listened to at once. Expired and held subscriptions stop their upstream work at the next worker tick. A subscription re-made while an older withdrawal or revocation was in flight is no longer deleted by it. Affects 4.0.0 pre-releases only.
- **A renewed resource subscription is no longer revoked by an older catalogue read.** When a backend's resource list was read while a subscription to one of its resources was renewed, a delivery checked against that read could delete the renewal and its queued notifications. A catalogue read now judges only subscriptions granted before the read began. Affects 4.0.0 pre-releases only.
- **A caller who receives several long answers from one tool is no longer refused for relaying the first.**
  Each long answer keeps a compact sketch so its holder can forward the text it received. Only four were
  kept per caller and tool, so a fifth long answer within the window dropped the first, and the holder was
  then refused for text it had received. Sketches now last as long as the evidence they answer, each sized
  so the combined false-excuse rate stays under 1%, within a fixed memory budget.
- **A relay refusal now says why, and the relay detector's capacity limits are counted.** A
  refusal used to read the same whatever caused it. It now names the case: the caller holds the
  text from a different tool, another caller's copy was kept past the detector's capacity, or the
  detector ran out of room for the caller's own copy. `mcp_gateway_collusion_relay_total` gains a
  `reason` label (`relay`, `other_source`, `capacity`, `unkeyed`), and the new
  `mcp_gateway_collusion_capacity_total{bound}` counts each capacity limit when it is hit. No
  verdict changes.
- **A host clock that reads before 1970 no longer produces 1969 or 0 stamps or guessed decisions.** The gateway's remaining clock reads now refuse (new tasks, chain receipts and links, signing, provenance, subscriptions, the grant snapshot at start, the control-plane grant view), wait for the clock (a task's input round and redemption, bounded by the task's ttl), or record the event undated (delivery records). Session idle deadlines are dated at the first readable reap. Affects 4.0.0 pre-releases only. Events, OAuth and the key server follow the same rules: an expired backend token is never used, no token request or temporary token is issued, webhook signatures and deliveries are refused or held without counting an attempt, held subscriptions and dead letters are left as they are, events that cannot be dated are dropped and counted (an inbound event webhook is answered 503 with `Retry-After: 60`, so its sender retries), and audit entries are written undated.
- **Relay detection no longer refuses a caller for forwarding some of the pieces it was sent.** A
  holder who forwards a subset of a split copy (pieces 1 and 3 of a section list, say) was refused
  when the same tool had sent another caller that exact join. The seams the forward creates are now
  recorded as the holder's own excuse, never as evidence against anyone. Two new
  `mcp_gateway_collusion_capacity_total` bound values count the pass's limits: `seam_excuse_cut` and
  `seam_excuse_evicted`.
  Affects: 4.0.0 pre-releases with relay detection on.
  Operator action: none; the new `bound` values appear beside the others.
- **An oversized or zero duration in config no longer crashes the gateway.** A duration that
  passed validation could overflow the arithmetic it reached, and a release build aborts on
  that. Every duration read from input is now refused at load when it is longer than 100
  years: `5m`-style durations, whole-second and millisecond settings (per-backend ones
  included), and a capability's `timeout` and `cache.ttl`. A capability `timeout` of 0 is refused,
  and so is a 0 for `streaming.session_reaper_interval`, for
  `key_server.cleanup_interval_secs` with the key server on, and for
  `failsafe.health_check.interval` with health checks on: each of those timers panicked at
  start. A dashboard session whose
  idle timeout cannot be held as a timestamp refuses the events call instead of panicking,
  and `mcp-gateway identity grant --ttl-seconds` refuses a value too large for a timestamp.
- **Relay detection no longer refuses a caller for re-joining a copy it was sent in pieces.** A tool
  result split over content items, labelled parts or one field of an array of records is now
  recorded as the caller received it, run together per field, so the caller forwarding the pieces
  joined is excused, and another caller relaying that text is caught. Plan answers and chains read
  the same joins, including one whose pieces came from different steps, and an equal field another
  step delivered no longer crowds a step's own text out of its receipt. A receipt cut by its text
  budget is now counted as `mcp_gateway_collusion_capacity_total{bound="record_text_cut"}`.
 
  Affects: 4.0.0 pre-releases with relay detection on.
  Operator action: none; the new `bound` value appears beside the others.
- **macOS: a stdio server that keeps forking no longer leaves a process behind on close.** A child
  forked just as the gateway signalled the server's process group could finish forking after the
  signal and keep running. The gateway now repeats the signal for up to 50 ms after the server
  exits, then reaps it.
  Affects: 4.0.0 pre-releases on macOS.
  Operator action: none.
- **A request to a 2026-era backend no longer goes out in the old dialect while the gateway reads
  its era.** The outbound path read the backend's protocol era with a non-blocking lock, and any
  brief holder of that lock made it read "no verdict", so the request was sent legacy-shaped,
  without `_meta`. A strict 2026 server refuses that request. The era is now readable without the
  lock.
  Affects: 4.0.0 pre-releases.
  Operator action: none.
- **`cargo test --release` compiles again.** A debug-only test module was mounted in release test builds and failed to compile there.
- **Capability listing changes are announced when a login expires or the file watcher reloads.** A capability whose OAuth login expires is now announced with `tools/list_changed` when it stops being listed, without a reload, and the file watcher's reload announces login and key edits as the explicit reload does. Affects 4.0.0 pre-releases only.
- **Relay detection keeps a plan step's later pieces when the answer repeats one of its fields.**
  A plan step's receipt kept copies of a repeated leaf while its room lasted, so a later piece of the
  same step (a short `part`, or a long leaf after repeats) was no longer kept whole and seams through
  it went unrecorded. Late credential redaction made this reachable at scale. A leaf is now kept at
  most as often as the step staged it. The step's own delivered runs (in answer order, broken at any
  other step's field or a field the step did not stage whole) are recorded as fingerprints, so a run across a redaction marker longer than
  the credential it replaced (a 20-byte AWS key ID against the 21-byte marker) stays receipted.
 
  Affects: 4.0.0 pre-releases with relay detection on.
  Operator action: none.
- **A stdio session is told when its tool list changes.** A stdio client that connects with
  `initialize` (protocol 2025-11-25 and earlier) now advertises `tools.listChanged: true` and
  receives `notifications/tools/list_changed` after `notifications/initialized` when a watched
  capability file is added, removed or edited, a login expires, or a config reload changes what
  is listed, as an HTTP client already was. Before, stdio advertised `false` and never sent it,
  so a client kept an outdated tool list until it reconnected. A modern (2026-07-28) stdio client
  is still told `false` and sent nothing until stdio `subscriptions/listen` lands.
  Stdio sessions now also watch their capability directories for edits, as HTTP does.
  Affects: stdio deployments with capabilities enabled or a config file.
  Operator action: none.
- **Relay detection no longer refuses a holder for forwarding its own text beside a field of its
  own.** A window made of a long field's text plus the separator the gateway puts between fields,
  or the edge character of a neighbouring field (a "Fwd:" subject, a signature), matched any other
  caller who had received the same text next to any other value, and two such windows refused the
  holder at the default `min_matches`. Those windows are no longer evidence next to a field of 96 or
  more characters, which keeps all of its own windows, so a relay through it is still caught.
  Affects: 4.0.0 pre-releases with relay detection on.
  Operator action: none.
- **A confirmation that cannot be sealed gives its slot back.** When sealing a destructive
  call's confirmation failed, both confirmation paths kept the continuation slot they had taken
  until it expired. They now release it before refusing.
  Affects: 4.0.0 pre-releases. Operator action: none.
- **A playbook run under an idempotency key runs every step.** Each step reused the
  client's key for its own retry entry, so the second step to complete was refused
  409 ("Idempotency key is already in use for a different request") and a keyed
  playbook with two or more steps could not run. The key now identifies the run (a
  retry of the run replays its result), and each step's entry is scoped to that step,
  so a step retried inside the run is still served its stored outcome rather than
  repeating a side effect. A `gateway_run_playbook` call carrying `requestState` or
  `inputResponses` is refused -32602: a playbook run has no continuation to resume.
  See UPGRADING-4.0.
  Affects: 4.0.0 pre-releases only; 3.x unaffected. Operator action: none; a client
  that sends retry fields on a playbook run is refused -32602 and must omit them.
- **An owner's cancel of a recovered task reaches the upstream job even when its backend was
  briefly unavailable.** The one upstream `tasks/cancel` was sent once, and a timeout, an
  unready backend or a login still in progress meant it was never sent again while the job kept
  running. It is now kept pending and retried when that backend next starts and on the expiry
  sweep. Retries stop after 6 failed sends or 24 hours, and an ERROR log names the backend when one
  is given up.
  Affects: 4.0.0 pre-releases with upstream task recovery enabled. Operator action: none. Back up
  `tasks.store_dir` before rolling back to a pre-release: task records may now be version 8.
- **`tools/list_changed` reaches a caller only when that caller's own list changed.** Before, a change to a tool a caller could not see (a policy-denied tool, another principal's per-user slot, a backend outside its key's scope) still sent every connected stream a `tools/list_changed`, which told a probing client that something hidden had moved. Now the legacy GET stream, `subscriptions/listen` and stdio each judge the hint against the view the stream's own caller is shown, under the identities the stream was opened with (key, OAuth agent, certificate, Open WebUI end user, Cloudflare Access assertion, trusted-proxy peer). A hint that is owed is written once; a repeat of a view the caller already holds is not written.
  Affects: clients that refetch `tools/list` on every `tools/list_changed`; they now refetch less often.
  Operator action: none.
- **A stream whose caller no longer resolves when it opens is refused like an invalid credential, and one whose identity lapses while open is closed.** A GET or `subscriptions/listen` opened by a caller found dead at attach answers 401 `Invalid token`, byte for byte as an invalid credential does, with the reason only in the `mcp_view_liveness_dead_total{reason}` counter. An open stream is closed when its Open WebUI assertion expires or its held Cloudflare Access assertion stops verifying. A caller that presented no credential on a public path still opens its stream and is told nothing.
  Affects: clients that held a stream past the lifetime of the identity it was opened under.
  Operator action: none; clients reconnect with a current credential.
- **A signed task call refused before any confirmation was spent gets its nonce back, on `/mcp` and stdio.**
  A task-augmented call that execution admission refused kept its signing nonce spent, even when nothing had
  acted, so the honest call re-sent under that nonce was refused as a replay. A signed call now carries proof
  that nothing it did has acted; the confirmation step gives that proof up the moment it spends a grant, and a
  refusal gives the nonce back only with it. A task refused after its confirmation was spent keeps the nonce
  spent, and its confirmation stays used.
  Affects: 4.0.0 pre-releases only. Operator action: none.
- **On `/mcp/{name}`, a caller with no connected account can no longer tell a hidden tool from a missing one.** For a per-user backend the caller has no view of, a call to a tool its policy hides used to answer "unknown tool" at once, while a call to a missing tool got the account's connect answer; the difference showed which names exist. The hidden tool now gets the same connect answer as the missing one, and is still never sent to the backend.
  Affects: clients calling a per-user backend on `/mcp/{name}` before connecting its account.
  Operator action: none; see UPGRADING.
- **stdio no longer writes telemetry to disk on every request.** Since 4.0.0-beta.1 each stdio
  request saved the protocol-revision measurement window synchronously, with a file lock, an fsync
  and a rename, under a lock every request shared. On a real disk that cost about 7-18 ms per
  request and ran requests one at a time, capping a stdio session at roughly 60-140 requests per
  second. A request now only records its observation in memory, and the window is saved once a
  second off the request path, and again when the session stops. A hard crash or kill can lose
  the observations since the last completed save: normally at most one second plus one save's
  duration, more only while saves are slow or failing (each failure is logged and retried on the
  next tick). Regression fix; 3.x did not save per request.
- **Ctrl+C and SIGTERM now stop a stdio gateway gracefully.** Before, a signal killed it outright.
  It now stops the way end of input does: it stops reading, finishes the requests it already
  accepted within the same bound as end of input, and saves its telemetry, so a stop never waits
  on a request that does not finish.
- **CLI tables no longer crash on non-ASCII text.** A table cell or tool description cut inside a multi-byte character (an accent, CJK text, an emoji) panicked the command with "byte index is not a char boundary". It is now cut at the previous character, with the `...` as before. ASCII output is unchanged.
- **Setting `MCP_GATEWAY_CAPABILITIES` no longer breaks config loading.** The tool subcommands read it as their capabilities directory, but the config env overlay also read it as the `capabilities` key, so `serve`, `doctor` and every other command that loads the config failed. The overlay now skips the eleven `MCP_GATEWAY_*` names that CLI flags own, matching whole names only. `serve` keeps the directories in the config; nested overrides such as `MCP_GATEWAY_SERVER__PORT` and `MCP_GATEWAY_CAPABILITIES__NAME` apply as before.
- **stdio refuses the methods MCP 2026-07-28 removed, as `/mcp` does.** A stdio client that
  declared the 2026-07-28 revision was still served `ping` and `logging/setLevel`, and got a
  different `Method not found` text for `resources/subscribe` and `resources/unsubscribe`. It
  now gets `-32601 method '<method>' was removed in MCP 2026-07-28` for all four, and for
  `notifications/roots/list_changed` when that carries an id (one function builds the answer for
  both transports). A request that declares no revision, and every other notification, is
  answered exactly as before. Not shared with stdio: the checks that read an HTTP header, and
  the body-only refusals of an unserved revision (`-32022`) and an undeclared client capability
  (`-32021`), because a stdio batch runs its items with modern serving off.
  Affects: stdio clients that declare MCP 2026-07-28.
  Operator action: none.
- **`GET /api/costs` URL-decodes its `?key=` selector and answers "no data" with 404.** A key name with a space or a reserved character was never matched, because the query was compared still percent-encoded; it is now decoded the way axum decodes every other query (`+` is a space). "No data for key" and "No data for session" answer 404 Not Found instead of 200, with the same body. An escaped spelling of `session` is refused 400 like `?session=`. See upgrading.d/8369.md.
  Affects: scripts calling `/api/costs`.
  Operator action: check for 404 instead of an `error` body on 200; send a literal `+` as `%2B`.
- **The `/dashboard` tools table no longer reports every call as a success.** Its rows are
  cumulative call counts per tool, and the stats behind them count attempts with no outcome, yet
  each row carried an OK badge, so a tool whose calls all failed read as healthy. The status column
  is gone, and the table is titled "Calls per tool (cumulative since start, top 10)".
  Affects: every release with `/dashboard`. Operator action: none. Each call's outcome is recorded in
  the transparency log.
- **stdio refuses a modern request for an unserved revision or an undeclared capability, as
  `/mcp` does.** A stdio client that declared a revision this build does not serve
  (`-32022`, with the list it could retry on, empty when modern serving is off) or called a
  method whose client capability it had not declared (`-32021`, naming it) was answered as if
  nothing were wrong. Both are now refused with the same text as `/mcp`, in `/mcp`'s order
  (revision, capability, removed method). A JSON-RPC batch item is judged like any request;
  a batched `server/discover` still lists the legacy set. Only an id-bearing removed
  notification gets the revision check; every other notification stays silent.
  Affects: stdio clients that declare MCP 2026-07-28.
  Operator action: none.
- The response cache stores and serves a result only for a tool declared read-only: `readOnlyHint: true` in a backend's `tools/list`, or `read_only: true` in a capability's YAML. A capability's own `cache:` is ignored, with a warning at load, unless it is declared read-only. A repeated write within the cache's lifetime was answered from the cache and never ran, so the caller was told it succeeded. A call to a removed backend could also get its old cached answer. Reported with a fix in [#3773](https://github.com/MikkoParkkola/mcp-gateway/pull/3773) by Justin Wood ([@terafin](https://github.com/terafin)).
- A tool the backend relists as a write is no longer retried after a lost `tools/call` when the gateway saw that listing only in part: a truncated or credentialed direct `tools/list`, or a tool-list read that failed, timed out or was cancelled partway. Before, the tool kept its retry permission until the next complete listing, so a write whose first attempt had reached the backend could run twice.
Fixed a test fixture import that failed strict Clippy for the firewall-only feature combination.
- **A busy account custody just before a capability call is sent no longer locks its idempotency key.**
  A keyed call on a REST capability account whose managed account's custody was busy at
  the last credential check before the send was answered as a permanent failure, and a
  same-key retry replayed that failure until the key expired, although nothing had been
  sent. The call now answers "temporarily unavailable, retry", writes one transient
  `idp_refuse` audit record and frees the key, so the retry runs. A signed call's nonce
  stays spent, because the credential was already minted: retry it with a fresh nonce.
  A resumed `gateway_execute` chain whose pending step met a busy custody at the mint
  now reads custody and writes its `idp_refuse` record once, not twice.
- **Per-client rate limits and circuit breakers follow the authenticated key, not its
  display name.** The limiter and the client circuit breaker were stored by the key's
  `name`, so two keys sharing a name, or both omitting it, shared one bucket whose
  size the later config entry decided. They are now keyed by the key's stable
  identity, so each key gets exactly its own `rate_limit`, in either config order.
  Two key-server tokens for one OIDC identity still share one bucket. Load validation
  already refuses duplicate, empty and padded API key names. Thanks to @arpe1618 for
  the report and reproduction. (#3950)
  Affects: gateways whose `auth.api_keys` entries set `rate_limit`, or that enable
  `auth.client_circuit_breaker`.
  Operator action: none.
- **A non-ASCII `agent_id` query parameter now decodes as UTF-8.** The query-string
  label decoded each byte as a separate character, so `agent_id=caf%C3%A9`, and a
  raw `café`, became the garbled label `cafÃ©` (U+00C3 U+00A9 in place of `é`). It
  now decodes as UTF-8. A value that is not valid UTF-8 (such as `%FF`, `a%FFz`, or a
  Latin-1 escape like `%E9`) yields no label from the query, as if the query carried
  no `agent_id`. A non-blank, visible-ASCII `x-agent-id` header still supplies the
  label as before. `+` and a malformed `%` escape still stay literal.
  Affects, when agent identity is enabled and no such header is sent: clients that
  send a non-ASCII `agent_id` in the query string; and clients whose query `agent_id`
  is not valid UTF-8, which now count as sending no label. That changes the outcome
  both ways:
  - Admitted where they were refused: with `known_agents` set and `require_id` off,
    an unproven client whose garbled label was refused (it cannot satisfy
    `known_agents`, or with `allow_unverified_agent_identity` on it was not a
    `declared` entry) is now admitted as unlabelled.
  - Refused where they were admitted: with `allow_unverified_agent_identity` on, a
    label that used to be accepted (`known_agents` empty, or a matching `declared`
    entry, as `%E9` matched `é`) is now gone. An unproven client is refused when
    `require_id` is on, and a proven caller outside `known_agents` is refused,
    because the hatch admits it only on a matching label. Such a client must send
    valid UTF-8.
  - A proven caller's undecodable query label no longer counts as a contradiction,
    and no longer raises the declared-label mismatch audit record.
  Operator action: look for agent ids written in the garbled form (such as `cafÃ©`)
  and change them to the real id, in `agent_identity.principal_labels[].labels` and
  in the `declared` entries of `known_agents[].id`. A garbled `principal_labels` entry
  can now refuse a proven caller as a contradiction, whatever the other settings,
  unless the label equals the caller's proven id or `allow_unverified_agent_identity`
  admits it as a `declared` entry. The `known_agents` entries matter only when
  `allow_unverified_agent_identity` is on. If clients with the hatch on send
  Latin-1 or other non-UTF-8 ids, have them send UTF-8.
- A refused or served meta-tool call (`gateway_invoke` and other meta tools) no longer copies its whole argument tree to carry the client's `params._meta` into it: intake moves `_meta` into the arguments in place. On the router test fixture (input sanitizer off, firewall off, the body in one chunk), a refused 1 MiB call now allocates its parse plus about 47 KB, down from about 3.2 MB more; Known limit in 4.0.0: `_meta` itself is still copied once, so a client that puts its bulk in `params._meta` rather than `arguments` still costs a copy of it.
- **A sessionless legacy call no longer leaves a session behind for 30 minutes.** A
  2025-era request that is not `initialize` and carries no session id of its own was
  given a new session kept for `streaming.session_ttl`, one per call with no limit, so
  memory grew with the request rate (about 1.1 KB per call). Such a session is now
  provisional: it is reaped 60 s (or `session_ttl`, if shorter) after its last request or stream ends, it becomes an
  ordinary session when its id is presented again, and at most 10,000 are live at once.
  Past the cap a new sessionless legacy call is refused before it runs with HTTP 503,
  `Retry-After: 60` and JSON-RPC -32603 `session_capacity`. `initialize` and callers
  resuming their own session are never refused.
  Affects: gateways serving 2025-era clients that call without a session id.
  Operator action: none; see UPGRADING for who shares the cap.
- **Per-key spend and budgets follow the API key, not a display name.** Cost
  governance charged spend and checked `budgets.per_key` under the caller's display
  name for every credential, so the static bearer (named `bearer`) shared one spend
  counter and budget with an API key named `bearer`, and any identity whose display
  name matched a `per_key` entry drew on that budget. Only a configured API key is now
  charged per key; the bearer, dashboard sessions and key-server identities are not,
  as the cost record already documented. Audit records and other display uses are
  unchanged. (#3950)
  Affects: gateways with cost governance enabled and `budgets.per_key` entries.
  Operator action: a `per_key` entry meant for the static bearer, the dashboard, an OIDC
  or key-server identity or auth-off callers no longer limits them; give such a caller
  an API key, or cap it with the shared `budgets.daily` or `budgets.per_tool`
  (UPGRADING); otherwise none.
- **A replayed surfaced tool call is audited under the backend it was admitted for.** A keyed
  repeat of a surfaced tool call is answered from its stored result. Its audit record and relay
  receipt used to look the surfaced name up again, so a change to `surfaced_tools` between the
  repeat's admission and its record could name a backend the call never used. They now carry the
  backend admission resolved. Nothing changes today, since `surfaced_tools` still needs a restart;
  this is groundwork for reloading it live.
- **A fast legacy client without a session id is no longer turned away.** Since the
  provisional-session cap, a 2025-era client calling about 83 or more times
  a second without presenting a session id filled the 10,000-session cap within
  seconds, and every later call got HTTP 503 `session_capacity`. Past the cap such a
  POST is now served without a session instead: no `mcp-session-id` comes back, and
  memory stays bounded. Sessionless `GET /mcp` streams get their own share of 1,000,
  so POST traffic cannot lock streams out; a stream past it still gets the 503. At the
  POST cap the three session tools refuse with advice to send `initialize`.
 
  Affects: gateways serving 2025-era clients that call without a session id.
  Operator action: none.
- **Token refreshes give up on a busy credential lock instead of waiting forever.**
  A refresh waiting on another process's or another task's credential lock now gives up instead
  of waiting forever. Health checks, era discovery and connection close wait at most 2 seconds (a
  busy close still sends its session DELETE). Every other caller, tool calls and background upkeep
  alike, waits up to 90 seconds and then picks up the token the holder stored. A busy lock answers
  "try again later", with no login prompt and no transport rebuild. A caller timeout shorter than
  its wait (a health check of 2 seconds or less, a backend call timeout under 90 seconds) can
  still time out as before.
- **Long non-ASCII output no longer panics two text cutters.** A runtime provider command whose output passed 4096 bytes with a multi-byte character at the cut panicked in the runner, and a release build aborts on panic. A `mcp-gateway trust` table cell with a multi-byte character at its width cut crashed the command. Both now cut at the nearest character boundary. No gateway server path runs runtime commands today; the runner is library API.
- **A provider's error text can no longer pass for a busy credential lock.**
  An OAuth error whose text held the phrase "credential lock busy:" (from an authorization
  server's error description or issuer, or from protected-resource metadata) was read as a busy
  lock: the failed login was told "try again later" and was left out of the backend's failure
  counts. Only the gateway's own busy-lock error is read as busy now. A caller waiting on someone
  else's login that hits a busy lock gets the same error as the caller that ran the login: JSON-RPC
  code -32000 (was -32603), text "Backend unavailable: credential lock busy: ..." (was
  "OAuth error: Backend unavailable: credential lock busy: ..."), and it is safe to retry.
- **A rejected certificate is reported as one.** Event callbacks reported an untrusted TLS certificate as `connection_refused`, because the check looked one error layer too shallow; they now report `tls_error`. Personal-account discovery labelled a refused connection a certificate failure when its URL contained a word like `handshake`; it now decides by the error's type, not its text.
- **`stats` no longer goes through an environment proxy.** It talks only to this gateway, now with a 10-second timeout.
- **Saved state files keep the mode you set, and `~` follows one rule.** Cost totals, the skills registry, the SIEM export cursor, the upgrade stamp and protocol-import drafts are written through one atomic writer that never leaves a file wider than you set it (owner bits only where an ACL or another group could widen it); they used to reset a chmod on every save. `~` now means your home only as `~` or `~/...`: `~//x` no longer resolves to `/x` in the server and credential path settings, `~user/...` in `env_files` is no longer read under your own home, and with no home directory the transparency log is written where its exporter reads it, with a warning naming the path.
- **Warm-start retry gaps under a millisecond are no longer always zero.** Warm-start spread each retry gap over `[0, gap]` in whole milliseconds, so any gap below 1 ms drew 0 every time and the retry ran with no wait. Warm-start and chain-step retries now share one jitter helper that draws in nanoseconds. The shipped 2 s, 30 s and 60 s gaps keep the same spread.
- **A tool whose name holds a colon keeps its full name in stats and the ranking file.** The
  `server:tool` key was cut at every colon, so `gateway_get_stats` and the dashboard showed a tool
  `a:b` as `a`, and after a restart its saved usage count moved to `a`. The key now splits at its
  first colon only. Rows an earlier build already cut keep their counts.
  Affects: backends that expose tool names containing `:`. Operator action: none.
- **A cut cell in the `mcp-gateway identity` table fits its column.** A value too long for its
  column kept one character fewer than the column and gained `...`, so the cell ran two characters
  wide and pushed the rest of the row right. It now shows two fewer characters of the value and
  lines up. Affects: `identity` table output only; `--format json` is unchanged.
  Operator action: none.
- **The skills watcher no longer drops changed capability files under load.** It queued each changed `*.yaml` path in a 100-slot channel and silently dropped any path once the channel was full, so a burst of edits, or edits made while a regeneration pass was running, left those skills stale until a later edit touched the same file. Changed paths now collect in a set that never drops one; a pass that leaves changes behind logs one warning (`Skills watcher: N skill changes arrived during regeneration; deferred to the next pass`) and they are regenerated on the next pass. Paths still pending at shutdown are abandoned, and a steady stream of edits postpones the pass until it goes quiet, as before.
- **`linear_get_issue` returns the issue you asked for.** It ran a full-text search and returned
  the first hit, so an issue's UUID could come back as a different issue, with no error. It now
  looks the issue up by its UUID or its identifier, a key no issue has fails with Linear's
  "Entity not found" error, and an archived issue is returned too. The input and output are
  unchanged.
 
- **Credential redaction keeps JSON text parseable.** When a tool answer's text is a JSON document, including `gateway_invoke`'s pretty-printed answer, a database connection string in it used to be redacted together with everything after it up to the next space, so the delivered text was no longer JSON. The redactor now replaces the same characters only inside the JSON strings they cover and keeps the quotes, commas, braces, keys and numbers between them, so the text still parses and a string value hidden before stays hidden. The direct route's provenance receipt now records the row count of such an answer instead of none. Text that is not a JSON object, array or string is redacted as before. A credential that starts inside a JSON key is replaced inside that key, which takes the first free `#n` suffix in its object so no entry is lost. This holds for texts over 1 MiB too. A number after a connection string in compact JSON text is not hidden.
- **A keyed replay is never served across protocol revisions.** On `/mcp` and stdio a keyed
  call's stored answer is shaped for the revision that first sent the key, then sealed. Replaying
  that key from the other revision served the stored answer anyway: a 2026-07-28 client got a
  legacy answer reshaped after its seal, so its public receipt no longer verified, and
  a legacy client got members only the 2026-07-28 shaper writes. Such a replay is now
  refused with JSON-RPC error 409 (HTTP 409 on `/mcp`) whose `data` reads
  `{"reason": "idempotency_era_mismatch", "stored_era": "legacy", "request_era": "modern", "already_executed": true}` (the eras swapped for a legacy replay of a modern call).
  The call already ran, so the message asks for the original protocol revision, never a new key.
  The direct route (`/mcp/{name}`) stores unshaped answers and reshapes them per revision, so it
  is unchanged. See `docs/UPGRADING-4.0.md`.
- **An API key in a JSON member is redacted.** A tool answer such as `{"api_key": "<key>"}` used to be delivered unredacted. The generic API-key rule needs the name, the separator and the quoted value in one string, and a parsed JSON member keeps its key and its value apart. The redactor now pairs a member's key with its value. When the key is `api_key`, `apikey` or `secret_key` (any case, `-` or `_` as the separator, alone or ending a longer name such as `x_api_key`) and the whole value is 20 or more characters of `A-Z a-z 0-9 + / =`, the value is replaced and reported as one finding. This applies to parsed JSON and to JSON carried as text, where escaped spellings of the name count too. Values the caller exempts are kept.
- **Credential-named JSON members are redacted for every common key family.** Beyond `api_key`, a JSON member is now redacted when its key names a credential and its whole value (surrounding whitespace trimmed) looks like one for that family:
  - **Names:** private and signing keys; `Authorization` and `Proxy-Authorization`; `secret` and client, API, shared, app, consumer, webhook, signing, HMAC, JWT, session, current and previous secrets; passwords and passphrases; any key whose last word is `token` (`access_token`, `GH_TOKEN`, `accessToken`); and the API key names in camelCase (`openaiApiKey`) and `aws_secret_access_key`.
  - **Values:** a password of 4 or more characters, a secret of 16 or more, a token of 16 or more token characters, a private key of 32 or more, or an `Authorization` value with a scheme (`Basic`, `Bearer`, `Token`, `Negotiate`, `ApiKey`) and 8 or more characters.
  - **Kept:** pagination and continuation keys (`next_token`, `nextPageToken`, `continuationToken`, `cursor`, `$skipToken` and similar); whole-value placeholders such as `${DB_PASSWORD}`; masks such as `****`; words such as `none` or `N/A`; numbers; and a Stripe PaymentIntent or SetupIntent `client_secret`, which Stripe designs to be passed to the browser.
  - The rules are built in. This applies to parsed JSON and to JSON carried as text. Where an existing credential pattern already replaced the whole value, there is one finding, not two.
- A credential that starts inside a JSON key in a tool answer's JSON text is now replaced inside that key instead of redacting the rest of the text, so the answer still parses. The renamed key takes the first free `#n` suffix in its object, as credential-shaped keys in structured results already do, so two such keys never collapse into one.
- **Credential redaction keeps JSON text over 1 MiB parseable.** A tool answer's JSON text over 1 MiB that held a credential, such as a large search page with a connection string in one entry, used to be redacted from the credential to the next space, so the rest of the answer was lost and a client could no longer parse it or read its row count. It is now redacted inside the JSON strings the credential covers, as smaller texts are: keys, numbers and the rest of the document arrive as sent, and a credential-named member's value is redacted as under 1 MiB. The text is checked with the same parser rules as before, but the parsed document, whose size set the 1 MiB limit, is never built.
- **The web UI shows whether you are signed in.** It used to decide that authentication was off
  whenever the status call answered at all, so a signed-in dashboard session on a secured gateway
  was labelled "Auth disabled", and a gateway whose public paths covered `/ui/api/status` hid the
  sign-in control. `/ui/api/status` now states `auth: {enabled, signed_in, admin}` in both views,
  and the page decides from those facts. With authentication off it says so, without a green dot,
  and explains how to turn it on. A refused call shows a plain message with the sign-in action
  instead of a status line or an endless "Loading...". The redacted view still carries no backend
  names or details.
- Redacting a tool answer twice now changes nothing. Inside text that continues a connection string (`postgres://`, `mysql://`, `mongodb://`, `redis://`), a redacted span that held whitespace or was shorter than the marker is written with one leading space (` [REDACTED:credential]`), and a renamed key's collision counter is written ` #n`, so a second pass, such as a dead-letter event replay, no longer redacts the first pass's output again. All other redacted text is unchanged. A replayed event whose stored body was already redacted is recorded as `redacted`, not `pass`.
- **A network blip no longer signs you out of the web UI.** When a status poll got no answer at
  all, the page showed "Not signed in" and blanked every count until the next poll. It now keeps
  what the last answer showed. A refusal (401 or 403) or a server error still shows the signed-out
  state, and a page opened while the gateway is unreachable still offers sign-in. After Change
  key, the previous key's view is never kept or repainted.
 
- **The 4.0.0 MCP Registry listing no longer fails on the crates.io package.** The registry proves
  ownership of a crates.io package by finding the server's name in its README, and crates.io hides
  HTML comments. The README now carries a visible `mcp-name` line, and a test fails if that line
  goes missing.
 
- **A stdio backend's package cache is isolated and repaired in more cases.** A quoted or Windows
  runner path (`"/usr/bin/npx"`, `C:\nodejs\npx.cmd`) now gets the per-backend cache its plain
  spelling gets. A cache directory the gateway cannot create or write falls back to the runner's
  default instead of failing the start. `pnpm dlx` and `bunx` no longer share one install tree
  across backends. A panic while a broken cache is being moved aside no longer leaves the backend
  marked repaired, and a cache tombstone a crashed run left behind no longer blocks the next
  repair after a restart that reuses the process id.
- **Legacy SSE backends that answer on the stream now work.** A backend on the MCP 2024-11-05 HTTP+SSE transport answers each POST `202 Accepted` and sends the JSON-RPC response on its SSE stream, as the official SDKs' SSE servers do. The gateway read answers only from the POST body, so such a backend failed at `initialize` and never started. The gateway now keeps the SSE stream open and pairs each response with its request by id. A body answer is still used when a backend sends one. When the stream ends, waiting calls fail at once and the next call reconnects first; no call is sent twice.
- **A config write lands in the file it locked, or nowhere.** When gateway.yaml is a symlink,
  every writer (the CLI, the web UI, the admin API) now writes the file the link named when it
  took the config lock. If the link is re-pointed or removed, or the config is deleted, while
  the write is waiting or under way, the write is refused with "moved during the write" or
  "deleted during the write" and nothing is written. It used to write whichever file the link
  named at that moment, possibly under another file's lock. A symlink whose target is missing
  is still refused, never filled with defaults.
- **A backend edit no longer refuses a key that starts with a non-breaking space.** When a
  backend's settings in gateway.yaml held a key beginning with a non-breaking space (for
  example an `env` entry), editing that backend misread the line's indentation: the web UI
  save was refused, and the CLI fell back to rewriting the whole file, which dropped your
  comments. Only spaces and tabs now count as indentation, as in YAML, so the edit is made in
  place and every comment stays.
- **A config write the loader would refuse now creates no secret entry.** The shared gateway.yaml writer loads and checks the new file, with a stand-in for each secret, before it saves any secret to the store, so a refused save never adds store entries. A new bearer token that is already an API key's credential is refused the same way. A discovery adopt on a gateway with an audit log records its intent in the log before writing.
- **A crashed gateway.yaml write that a reload recovers is now recorded in the audit log.** On a gateway with an audit log, the reload that finds a crashed write's journal (from the file watcher, an admin reload or the meta-tool, in HTTP or stdio mode) now records a `config_recovery_intent` event before it recovers the file. It used to recover without an audit entry. With auth off and no audit log, recovery is unchanged.
- **A config write on a gateway with auth on and no audit log is refused.** Startup already refuses that state; a discovery adopt now refuses it too, before anything is written or stored, and answers 503 with `audit_log_required` and the message "auth is on but no audit log is configured; config writes are refused". An env file that assigns a reserved `MCPGW_PENDING_SLOT_` name is now refused naming the env file and the line.
- Uptime in `/ui/api/status`, `/ui/api/overview` and the dashboard now counts from when the gateway process started. It used to count from the first time any of them was requested, so a gateway that nobody had opened the UI on for a day reported an uptime of seconds.
- **A capability file changed behind its pin is acted on as the capability it was loaded as.** The gateway names the changed file's capability by the path it was loaded from, never by a name or pin the changed bytes declare, so a change that renames the capability unloads the loaded one at once rather than at the next reload, and a file declaring another capability's pin can no longer unload or relabel that capability. The warning it logs names the trusted capability and escapes the path, so the changed bytes cannot forge a log line.
- **Screen readers hear that a page is loading on its first load too.** The web UI marked its
  content busy only while a Retry ran, so a page's first load went unannounced. The content is
  now marked busy from the moment a page starts loading until it shows, fails or comes back
  empty.
 
- **The token-exchange example starts on 4.0.** `examples/token-exchange-live.yaml` declared its `mcp-gateway` issuer with an empty `audiences` list, which 4.0 refuses, so the walkthrough's command stopped at load. The issuer now lists the backend audience the gateway signs its own assertion for (`https://mail-svc.internal`), and the walkthrough says to list every token-exchange backend's audience there and to run an owner-only copy (`install -m 600`), since 4.0 refuses a config other users can read. A test now loads every shipped example config.
- **A `-full` startup step that turns off `set -e` or `set -u` no longer weakens the steps after
  it.** A sourced `.envsh` step runs in the entrypoint's own shell, so a `set +e` in one step meant
  a failing command in a later step no longer stopped the container, and the gateway started after
  a failed step. The entrypoint now restores `set -eu` after each sourced step. A step's exported
  variables still reach the gateway.
- Redacting a large tool answer is fast again. The 4.0.0 fix that keeps a second redaction pass from changing anything made redaction of a JSON array near the 1 MiB cap about three times slower than before it. That cost is gone: such an answer now takes about 2.5 times the plain whole-text redaction, against 8 to 9 times, and plain redaction is no slower than before. Redacted output is unchanged byte for byte.
- **The package-cache sweep no longer deletes a directory the gateway did not retire.** At its
  first start, the gateway deleted every entry under `pkg-cache/` whose name held `.tombstone-`,
  including an operator's own cache stored there under such a name. The gateway now marks a
  cache with a proof file before it moves the cache aside, and the sweep deletes only entries
  that carry it.
- **The classic capability editor no longer saves a file when it only validates it.** It
  validates on blur with `PUT /ui/api/capabilities/{name}?validate=1` and an `X-Validate-Only`
  header; the server read neither and wrote the text, so leaving the editor saved unreviewed
  changes, and on a pinned file broke the pin, which drops the capability on the next reload.
  Either signal now means validate only: the answer is `{"status": "valid"}` or the validation
  error, and nothing is written. Validation also stops accepting a file that does not parse as a
  capability when it has a `name:` key; the parse error is now returned.
- **A saved daily total that no run could hold restores as zero, with a warning.** On start the
  gateway puts today's spend back from `costs.json`. An infinite value, or one too large for a
  micro-USD count (only a damaged or hand-edited file holds one), used to saturate into a cap
  that refused every call until the day rolled; that row now restores as zero. Negative and NaN
  values already restored as zero, silently. Each such row now logs a warning naming
  `costs.json`, the row and its value.
- **Backend `env` and `headers` accept secret references.** An enabled backend's env or header value that is a whole `env:NAME`, `file:/abs/path` or `keychain:NAME` reference now resolves to the secret, used as stored (a `file:` value drops one trailing newline, as in every slot); before, it reached the backend as the reference text. A disabled backend keeps its text until it is enabled. Every save path (the web UI's add and edit, `mcp-gateway add`, `discover --write` and the setup import) refuses a reference that does not resolve before writing, naming the field (the web UI answers 422), and a config edited by hand with one fails to load the same way. `mcp-gateway get` and the web UI's config read show a reference as written, never its value.
- **`mcp-gateway list` and `get` report a gateway.yaml that does not load.** Both read the file
  through a loader that turned a load error into the built-in defaults, so `list` printed "No
  backends configured" and exited 0, and `get` said the backend was not found, while the real
  problem was a broken file. Both now print the load error and exit non-zero; a missing file
  still reads as an empty config. For library users, `config_persistence::load_config_or_default`
  and its `gateway::ui::backend_ops` re-export are removed; call `load_existing_or_default`,
  which returns the error instead of the defaults.
- **A delivery record now names the trace of the invocation it answers.** The
  `response_delivery_attempt` record took whatever trace was current when it was written, or a
  fresh one, so it never matched the invocation record of the same call. On `POST /mcp`
  (`gateway_invoke` and a backend tool called by its own name), on `/mcp/{name}` and on stdio,
  the delivery record now carries that invocation's `trace_id`, for a result and for an error,
  so one delivery joins exactly one invocation. Deliveries with no single invocation behind them
  (notifications, plans, code mode, a surfaced tool withheld from the caller) are traced as
  before.
- **A delivery record says `refused` wherever the gateway refused the call.** The kill switch, a
  capability disabled for its error rate, attestation, a spend limit, a relay block, an undeclared
  argument key, a rejected chain receipt, a question the caller never declared, a posture-refused
  config reload, a refused bridged round and a refused stored task read now record
  `response_effect: refused` on the answer the caller receives. A chain or playbook that ends on
  such a step records `refused` too; one that carries on past it does not. The answers themselves
  are unchanged.
- **The governance audit reads past a large record.** Reading the control-plane audit log refused any record longer than its 1 MiB read window, though the log accepts records up to 4 MiB, so one large policy change or decision made every older page an error. Such records now read back whole. A line over the 4 MiB cap, which the log never writes, is reported once and skipped: the page names it in the new `AuditPage::unreadable` field (its offset and segment), the older pages still read, the admin view marks itself degraded, and grant-change recovery refuses rather than guess past it. A page now reads at most 1 MiB plus one 4 MiB record. Both the governance reader and Activity now refuse a page whose log segment was removed by retention while it was being opened; Activity used to read the active file in its place, which holds a different segment.
- **A stdio gateway stopped during startup no longer leaves its backends running.** The gateway
  listened for SIGTERM and Ctrl+C only once it began reading requests, so a stop that arrived
  while backends were warm-starting killed it outright, and since each backend leads its own
  process group, their process trees kept running. The stop is now registered before any backend
  starts, and the session then drains and ends its backends as a later stop does. A backend's
  process group is also signalled as soon as its transport is dropped, so a gateway that exits
  right after has already sent it.
- **The classic web UI's Remove button and capability buttons work again.** They were built as inline `onclick` handlers holding the name as JSON, whose opening quote ended the HTML attribute, so a click had nothing to run; the capability page's Save and Revert were also replaced at load by an unused editor's functions. Names now travel in `data-` attributes read by one click listener, `esc()` escapes both quote characters, and the unused editor is removed.
- **Replaying a dead letter whose subscriber's identity changed is refused with its reason.** The
  replay re-checked the subscription and access, then queued the record again with the identity
  it was observed under. If the subscriber's row had since been re-granted, its lease rotated or
  its identity configuration changed, the delivery worker buried the record again as
  `observation_changed`, and the admin's replay was answered as a success. Replay now runs the
  same observation check before queuing, and answers `409` with
  `"reason": "observation_changed"` (or lists that reason per record when replaying a whole
  subscription). Nothing was ever delivered to the wrong identity.
- **The shadow scan no longer shows a command's directory path.** When a discovered command had no program name to take (for example one ending in `..`), the scan's asset id and evidence fell back to the whole command text, which named a directory on this host. The program name is now the last path segment, with either separator, and a command with no program name shows none.
- **The classic web UI's Add Server registry search lists entries.** The page read a `servers` key the registry endpoint never sends, so the search had nothing to show; it reads the endpoint's `entries` now.
- **A capability or OAuth-destination refusal of a call records `response_effect: refused`.** These refusals reached the caller as an error while the call's delivery record said `delivered`: a capability refused inside a read-only call, a CLI or MCP capability naming a network destination, a capability URL that is private, names loopback or sends a credential in cleartext (REST, GraphQL, JSON-RPC and the token endpoint), and a send the address pin refuses. Three OAuth token paths raise their refusal in a task of their own, out of reach of the call's record: a tool call's token refresh, a backend's OAuth handshake when the call starts it, and a capability's token refresh; each is now recorded where the call picks it up. Answers are unchanged. Health probes and upstream task queries still record nothing, because they turn the error into an answer of their own.
- **A delivery record no longer claims a clean or unchanged answer the gateway flagged or annotated.**
  Response inspection's findings now appear in `response_findings` (as `inspect:` kinds, never the
  matched text) beside the firewall's, so an answer inspection flagged no longer records an empty
  list. An answer the gateway adds its own verdict or advice to (`_security_findings`, a contract
  verdict, cost warnings, a recovery hint, predictions, the context-integrity verdict) records
  `annotated`, not `delivered`; context-integrity enforcement that rebuilds the answer records
  `rewritten`, and a malformed round it refuses records `refused`.
- **Audit pages no longer skip records when the log rotates mid-read.** The governance audit, Activity, the Overview's recent actions, Activity's seek and the control-plane export each worked out which log segment to read and how long it was before opening it. A rotation in between could leave a page reading a sealed segment only up to the length of the new, shorter live file, silently skipping every record above that point. Each reader now opens the segment through one shared opener and takes the page's end from the file it actually opened. A cursor into a segment no longer kept, which the governance audit used to answer as the end of the log, now restarts at the newest record with `cursor_reset` set, as Activity already did. A segment that disappears while a page reads it, or a hole between kept segments, fails the page instead of being stepped over. The check behind `audit verify`'s refusal of a hash-only pass over a signed log also re-reads the log when it rotates during the scan, so a signed segment sealed mid-scan is no longer missed.
  Affects: anyone paging the governance audit or Activity while the log rotates. Operator action: none.
- **`security.response_inspection.enabled: false` now turns response inspection off.** The setting was read only to decide whether to switch on action mode, so with `enabled: false` every answer was still inspected: findings were added to the answer as `_security_findings`, a "Response inspection finding" warning was logged for each, and the inspection ran on every call. Now nothing is inspected, annotated, logged or blocked by it, and `enabled: false` wins over `action_mode: true`. The firewall's own response scan (`security.firewall.scan_responses`) and context integrity are separate switches and are unchanged; the default (`enabled: true`, observe mode) is unchanged.
  Affects: gateways that set `security.response_inspection.enabled: false`. Operator action: none; expect no `_security_findings` and no inspection warnings while it is off.
- **A tool listing that names a backend the gateway withholds now records the refusal.** `gateway_list_tools` for one backend answers "backend not found" when the multi-user isolation guard refuses the caller or the backend requires an identity the caller does not carry. That answer is unchanged, but the delivery record now says `refused` for those two cases. A caller whose credential failed to mint gets the same answer with no refusal recorded, because that is not a decision about the caller. The all-backends listing still leaves withheld backends out silently.
- **A failed stdio start keeps its stderr on a busy host.** A stdio backend that failed to start
  was classified from the last lines it wrote to stderr (a failed install, a missing module, a
  port in use), but the gateway waited only a fixed window for its stderr reader and then gave
  up. On a loaded host the reader could miss that window, and the failure came back
  unclassified. A failed start now reads the remaining stderr itself, so the lines the backend
  wrote before it died are kept. A pipe still held open by a process outside the backend's
  group is read for the same window as before.
- **`tools/list` no longer stalls after a failed per-user credential lookup.** On a backend with per-user sessions only, a cold caller's listing claims a fill of the caller's own tool list. When that claim's credential lookup failed, its lease stayed as the retry backoff, and the caller's listings inside that backoff waited for it as if a fill were running: up to the backend's `timeout` plus a short grace (at most 30 s), and then answered without that backend's tools anyway. A listing now waits only while a lookup or fill is really running, and a listing already waiting is woken as soon as the attempt fails. The retry backoff itself is unchanged: nothing is fetched for that caller until it ends.
- **The classic web UI is easier to read and to use without a mouse.** Primary and danger buttons, the active Add Server mode and the red status badges now meet the WCAG AA contrast ratio of 4.5:1; white on the accent blue was 2.53:1. Every form control has an accessible name, so a screen reader announces the Transport choice, the tools filter, the import URL and the environment-variable rows. The Control Plane tables, which scroll sideways on a phone, now take keyboard focus and can be scrolled with the arrow keys.
- **More of the classic web UI works from the keyboard.** A tool's details now open from its name, which is a button, and a long input schema scrolls from the keyboard. So do a long OpenAPI import list and a configuration wider than the screen: each takes focus, shows a focus ring and scrolls with the arrow keys.
- **A capability redirect the gateway refuses records `response_effect: refused`.** A hop to a private address, or from a secure request down to cleartext off this machine, now records the gateway's refusal on the call's delivery record instead of `delivered`. The caller's error, and the backend's health mark, are unchanged.
- **The registry search in Add Server works from the keyboard.** It now behaves as an accessible combobox. The arrow keys move through the results, which stay in view as the list scrolls; Enter picks one, and Escape or Tab closes the list. The box, the list and the active result carry combobox and listbox roles for assistive technology. Editing the search text after a pick now clears the pick, so Add no longer adds an entry the box has stopped naming.
- **A refusal inside a task's dispatch is now tied to its task in the audit log.** When the gateway refuses a task-augmented call while its worker dispatches it (a response-contract refusal, or a refused readmission), the task's settlement now writes a `task_settlement` record that says `refused`, with the code the task settled with, joined by trace to the worker's dispatch record. Before, that dispatch record carried only an `error` outcome and no task id, so the log alone could not tell a gateway refusal from a backend failure or tie it to the task. A backend's own error with the same code is not recorded as a refusal.
- **A task's settlement record names the refusing gate's own error code.** A task whose answer a gateway gate withheld as an `isError` result was recorded on its `task_settlement` audit record with `-32600`, whatever the refusing gate decided. A malformed backend round now records `-32603`, an argument key the tool's schema does not declare `-32602`, and an absent tool `-32003` or `-32001`, matching the code the task settles with. A response-firewall refusal still records `-32600`. Task recovery, cache hits and idempotency replays are now pinned to record a context-integrity rewrite only on the call that made it.
- **A cancelled admin UI write still records who made it.** A backend add, edit or remove whose browser tab closed after the write started still changed `gateway.yaml`, but no `admin_action` naming the caller was written. The admin audit now runs the request and its record together, so the change is recorded either way. Any recorded admin UI request now runs to its answer after the client leaves, and a client that disconnects mid-upload leaves the handler's error recorded. A request refused before it runs (the audit log is down) still writes and records nothing.
- **A UI role check uses the role mapping a request arrived under.** Activity (list, export and
  receipts), the control-plane export status, and the grant, policy and decision writes judged an
  OIDC caller by the role mapping in force when the handler ran, so a reload that landed while a
  request was in flight, its body still uploading included, could admit or refuse that request by
  the new mapping. They now use the mapping pinned when the request arrived, as the control-plane
  snapshot already did, and so does the `access` report on `GET /ui/api/status`. A request that
  arrives after the reload gets the new mapping.
- **A Windows lock no longer fails with "Access is denied" while another handle releases its old file.** When a lock file that was not owner-only is replaced, and some other handle (an indexer or antivirus scan) still has the old file open, Windows keeps its name pending deletion for a moment, and a new file cannot be created under that name. The lock read that moment as a hard error and gave up. It now waits it out, within the lock's usual bound, and takes the lock once the name is free. A folder this account cannot create files in is still refused at once, as before.
  Affects: Windows only. Operator action: none.
- **A chain or playbook step that may have run is not sent again.** `ChainExecutor`'s retry policy
  and a playbook's `on_error: retry` re-sent a step after a lost connection, a timeout, an HTTP
  error, an I/O error or a backend's error answer, every one of which can follow a request the
  backend already acted on, so a payment or a message could happen twice. A step is now re-sent
  only after an error raised before its request was sent (a connection that was never made, a
  backend that was not ready); anything later ends the step, and its error text ends with "it may
  have run". A chain step reports the attempts it actually made. Under `on_error: abort` such a
  step ends the playbook with its own error, code and data unchanged, its message ending with the
  same sentence; `Error::is_pre_dispatch()` reading `false` is the check. In the gateway's own playbook
  runs, a backend's dispatch error was already final; a step failed by the gateway's own checks
  after its send (a missing signature receipt) or before it (an invalid tool name) was re-sent
  under `on_error: retry` and now runs once, and its `step_errors` reason gains the same sentence.
- **A stderr nobody reads no longer stalls requests.** Log lines go through a bounded queue to one writer thread; when stderr stops draining, lines past the queue are dropped and counted, and the gateway reports the count in a line of its own once stderr takes writes again. Log lines are moved out from under the locks other requests wait on; the few that stay are listed in the source with why, and none of them can wait on stderr. Audit records with their own file are unaffected.
- A call to a name that is both a registry backend and the capability backend is refused with `-32001` and `data.reason: "ambiguous_backend"`, before an idempotency key is reserved or a cached answer is read, instead of being judged on the backend and sent to the capability; a tool only the registry backend exposes is still refused as not found. A config reload that would register a backend under the running capability backend's name is refused. See UPGRADING.
- **More gateway refusals record `refused` on the delivery record.** A cost report's admin view
  refused to a non-admin, `gateway_list_tools` for a backend outside the key's scope, a required
  identity the call lacks, a step refused at the dispatch gate, a playbook refused before its
  first step, a resumed chain refused before its pending step, a backend redirect the SSRF
  policy refuses after the request was sent, and an authorization refusal raised at the send (a
  backend reached only with each user's own credential, called without one) now record
  `response_effect: refused`.
- **`/mcp/{name}` answers a send-time authorization refusal with 403, not 500.** On a backend
  reached only with each user's own credential, a call refused at send time was answered HTTP 500
  as if the backend had failed: one made without the user's credential, and one whose credential
  failed its per-send recheck (a revoked grant, or a credential past its expiry). It now gets the
  refusal's own status, 403, as `POST /mcp` already gave. The JSON-RPC error code (-32001) is
  unchanged.
- **The web UI preloads its other screens even on a busy device.** After the first page paints, the shell preloads the other screens when the browser is idle, so the command palette lists their actions and a later visit opens at once. It asked for idle time with no deadline, so a browser that never saw the page as idle could hold the preload back indefinitely. The preload is now queued within two seconds of the first paint either way, and runs as soon as the page's current work allows.
- **A per-user credential refusal is answered as a refusal on every route.** When a per-user backend refuses a call because the caller brought no credential, or because the credential failed its check at the send, `gateway_invoke` answered with an ordinary error result that called the problem a transient backend error and suggested retrying. It now answers with the same -32001 refusal the direct `/mcp/{name}` route gives, with no retry hint, and records the call as refused. The same refusal during the first listing of a backend's tools is no longer reported as an unreadable schema. Repeated refusals no longer count against the backend's error budget, so they can no longer trip the kill switch for every user. A client that read this refusal from an `isError` result on the meta-tools now gets a JSON-RPC error -32001 instead; see the upgrade guide. Affects gateways with per-user backends only.
- **An SSO caller's admin standing uses the role mapping a request arrived under.** A key-server
  caller (a temporary token or a delegated OIDC bearer) was made admin by the role mapping current
  at authentication, so a reload landing while a request was in flight could decide that request's
  admin standing by the new mapping and its other checks by the old one. Admin now comes from the
  mapping pinned when the request arrived, on every route; an open stream's deliveries still follow
  the current mapping, so removing an admin rule still stops a stream already open.
- **A destructive call refused for a caller the gateway cannot name is recorded as refused.** A task-augmented destructive call from a caller with no credential and no identity is answered `-32003` ("this destructive call cannot be confirmed for a caller this gateway cannot name"). Its delivery record used to say `delivered`; it now says `refused`, so refusal counts include these calls. Only HTTP reaches this answer: a stdio caller is always named by its session. Other confirmation answers keep the records they had.
- **Redacting injected values from number-heavy answers no longer slows down as the value count grows.** The echo scrub compared every JSON number in a backend's answer against every injected value, parsing each value again for every number, so a 16 MiB number-heavy answer took about 15 s to scrub against 1,024 values, and stored answers are scrubbed again on every cache hit, idempotent replay and task read. Each value is now parsed once per value set into two lookup sets (exact integers and float bits), and `null`, `true` and `false` into three flags, so a number costs one lookup: the same answer now takes about 0.13 s (median of three release runs), and doubling the values no longer changes it. What is redacted is unchanged.
- **A tools/list fill cut short no longer grants cache admission or resend.** A fill that stops early (at 32 pages, at 120 s, on a repeated cursor, on an unreadable page) may not have reached a later listing of the same tool without the hint. Such a fill now only narrows the read-only and resend sets: a tool keeps cache admission and resend only if it already held them and the pages read still declare it. A complete fill still grants both.
- **OAuth: a renewal or login that spans an issuer switch hands over nothing of the old issuer.** A background renewal whose client-credentials answer arrives after the backend was signed in again under another issuer no longer reports or logs "Token renewed via client_credentials": it is deferred, as a renewal that starts after the switch already was. `OAuthClient::authorize()` now refuses (`AuthorizationRequired`) when such a switch lands during the login, instead of returning the old issuer's token; the gateway's own callers already refused it. Library callers are unaffected: a switch exists only for a client given the gateway's sign-in status, which code outside the crate cannot attach. Nothing of the old issuer was ever cached.
- **A budget first set by a config edit applied at restart now counts that day's earlier spend.** Past the 256 per-name rows a day keeps for unbudgeted tools and keys, spend is kept as one overflow total. A reload that starts budgeting such a name already charged it an upper bound of that earlier spend; a restart did not, so the new budget started from the name's own row alone. `costs.json` now records which names were budgeted since the gateway started, and the overflow total at each row's creation, so the restart charges the same starting figure a reload would: the saved overflow when the name has no row, or the overflow when its row was created. A name budgeted before the restart is never charged again.
- **A reload that only edits API keys no longer reports a restart as needed.** Adding, removing or changing a key in `auth.api_keys` (its rotation fields included) applies on the next request, but the reload used to report `auth` as waiting for a restart and the change as "NOT YET APPLIED". It now reports the change as applied. A key edit that would switch the gateway between one user and many is still refused, as before. A change to another restart-only `auth` setting, alone or together with a key edit, still reports a restart; `dashboard_session` applies live, as before.
- **A capability changed while the gateway was down now reaches the open decisions.** A capability file whose bytes no longer match its own `sha256:` pin was skipped at startup without a record, so it never appeared as a `capability_changed` decision until it changed again while the gateway ran. Startup, on HTTP and stdio, now checks every configured capability directory for pin mismatches before it reports ready, and a directory that fails to load is still checked. While that startup check runs, a file edit's reload waits for it (logging a warning if it waits long), and the admin capability reload answers a retryable error (-32000) instead of running beside it.
- **A web UI backend edit no longer detaches a shared YAML value.** An edit that would rewrite an alias such as `env: *shared` as its keys, or drop an anchor, now writes nothing, as any edit the in-place splice cannot prove already does.
- **Admin API: a refused policy write names where policy is set.** `POST /ui/api/control-plane/policies`, and a policy decision on `/ui/api/control-plane/decisions`, still answer 409 `policies_managed_in_gateway_config`; the reason now names every gateway config key that holds policy (`security.tool_policy`, `security.firewall.rules`, `security.firewall.credential_redaction`, `security.firewall.collusion`, `security.sanitize_input`, `security.ssrf_protection`) instead of only the last two. A policy write no longer answers 503 when the control-plane store is unavailable: that store never enforces policy, so the answer is the same 409 (or 403 for a non-admin) either way. Grant writes are unchanged.
- **A call to a backend that does not exist no longer reads as allowed in the decision record.** A `gateway_invoke` (on `/mcp`, stdio or in-process) naming a backend the registry does not hold used to record `decision.kind: default_allow` and `outcome: error`. It now records `not_found` and a refusal (`denied`) with the miss's -32001 code, as a scoped key's missing name already did, so the Activity "blocked" filter shows it. The answer the caller gets is unchanged. A backend that a reload removes between the gate and the dispatch still records the plain error.
- **The dashboard's live stream no longer loses or stalls its activity and config events.** A client that reconnects right after a `reset` frame, before any replayed row, now still gets the replay instead of starting at the newest record. A replay that shows the viewer no row no longer leaves every later reconnect replaying the whole log, and a replay that meets a missing log segment now goes live from where the catch-up began instead of ending the stream on every reconnect. A credential check slower than its one-second period (a slow key server), or a status that changes faster than it can be sent, no longer holds back live events; revocation still ends the stream at the next frame.
- **A stdio gateway that is stopped by its parent no longer leaves its backends running.** When a nested gateway's own stop outlasted the parent's plan, the parent killed it before it could stop its leaves. A signal during the stop now hurries the backends so they are gone before the parent's kill.
- **A CLI write no longer recovers a pending config write unaudited.** When a gateway's audited config write fails and its rollback fails too, it leaves a replace journal beside `gateway.yaml`. A CLI command that writes the config used to recover that journal on taking the config lock, with no audit record. It now refuses, writes nothing and leaves the journal in place, and says to start or reload the gateway, which recovers it. A reload on a gateway with an audit log records the recovery there.
- **A wake from sleep no longer stops every backend for hours.** The per-backend rate limiter read a raw hardware counter, and a bucket whose stored state was ahead of that clock refused every call until the clock caught up: after one wake from hibernate on an Apple Silicon laptop, every backend answered "Rate limit exceeded" for hours, until a restart. The limiter now reads `std::time::Instant`, and a refusal that asks for a longer wait than one refill interval, which only a clock that went back produces, rebuilds the bucket and admits the call. Each reset logs a WARN `backend rate limiter clock stepped back; bucket reset` with the backend and the wait the old bucket would have imposed, and a refusing backend logs `backend rate limiter refused` with its next allowed time, at most once a minute per backend.
- **A 2026-07-28 client over `serve --stdio` no longer caches a tool list without its surfaced backends' tools.** Such a client cannot be told the list changed (stdio has no `subscriptions/listen` yet), so a first `tools/list` that landed during startup warm-up left those tools out for the whole session. Its first `tools/list` now waits, up to 30 s, for each surfaced backend's first tool fetch; if the wait runs out it answers with the tools that are ready, never an error. A session that began with `initialize`, which is told of changes, does not wait. See UPGRADING-4.0 item 52.
- **A scoped key's call to a granted backend that is not registered now records a refusal.** Its invocation record said `outcome: tool_error` (or `invalid` on a chain resume whose pending step's backend was removed), where an unscoped caller's missing backend records `not_found` and `denied` with -32001. It now records the same, on the synchronous answer, a task worker's step and a chain resume, so the Activity "blocked" filter shows every missing backend alike. The answer the caller gets is unchanged, and an out-of-scope name still records its scope refusal (-32003).
- **Relay detection tracks a plan task's stored result from the moment it is readable.** The relay replay snapshot of a completed plan or multi-target task is now written with the result itself, in the same task-store write, so a `tasks/get` or a task notification can no longer read the result before its snapshot exists. The snapshot is kept in memory only once a read delivers it: a read under `off` leaves nothing behind, any other action keeps it. A snapshot made by another gateway process cannot be matched by this one; a read of such a result is refused under `block` (`-32002`), and delivered, counted and audited under `observe`.
- **Contributors: schemata mutation batches find the gateway library.** In a workspace build the runner took the first library test executable it saw, which can be the nested `gateway-core` crate, and then refused every batch for a missing `--cfg mutants` probe. It now picks the `mcp_gateway` library by target name and refuses if that one is missing. No change for users of the gateway.
- **`x-mcp-header` mirroring covers nested and non-ASCII arguments.** An annotated property inside a nested object argument is now mirrored onto its `Mcp-Param-*` header, and a string value that is not plain visible ASCII (a space, a control character, non-ASCII text) is sent Base64-wrapped in the gateway's `=?base64?…?=` header form instead of raw or dropped; an empty value is sent as an empty header. A tool whose nested `x-mcp-header` annotations are invalid or repeat a header name is left out of `tools/list`, as a top-level one already was. A `tools/call` through the router to a backend whose tool list was never fetched still carries its mirror. The change is [@terafin](https://github.com/terafin)'s, carried over from [#4771](https://github.com/MikkoParkkola/mcp-gateway/pull/4771); a later PR of theirs, [#5052](https://github.com/MikkoParkkola/mcp-gateway/pull/5052), brought the nested-property and encoding fixes to main; its nine test rows also run on 4.0 through [#5099](https://github.com/MikkoParkkola/mcp-gateway/pull/5099).
- **Personal-account custody releases its store off the stop path.** Releasing the account store (it holds two file locks) used to run inline on the thread that stopped the gateway, so a slow unlock could hold the stop past `server.shutdown_timeout`. The HTTP and stdio stops now release it on a separate thread and wait for it only until the stop's own deadline; a release still running then finishes after the stop, and is logged once without naming an account. A gateway serve that ends early (a refused start, an error, a cancelled stdio session) hands the store to that thread too, instead of releasing it while the gateway drops. If that thread cannot be started, the store stays locked until the process exits and this is logged, rather than unlocking on the stopping thread.
- Windows: deleting a credential now confirms it is gone before reporting success. Credential Manager can briefly keep returning a credential after its delete succeeded; the gateway asks again for up to about 0.7 s, and a credential that is still readable fails the delete with `could not confirm removal` instead of being reported as removed.
- **A stopping stdio backend takes its descendants down with it.** Before the group kill, the gateway now freezes, verifies and kills every process still attached to the backend by parent pid, so a backend that is itself a gateway no longer leaves its own backends running (each sits in its own process group, which the group kill never reached). It applies to ordinary and hurried stops alike, on Linux and macOS. A helper that detaches before the stop begins (a double fork) is outside its reach; processes it could not confirm gone are logged by count and pid.
- Container image: the release image is now compiled with Rust 1.99.1, the compiler every CI test runs on. It was built with Rust 1.98, a version CI never tested, and a check now fails the build when the image's compiler and CI's differ.
- **A stopping backend keeps its SIGTERM when the gateway's reaper runs late.** A stdio backend that ignores its closed stdin gets SIGTERM, then a wait, then the kill. On a loaded host the reaper thread could wake only after the kill was due and kill at once, so the backend never got its SIGTERM or its chance to save. A late step now sends the SIGTERM first and kills it at least 100 ms later (sooner only if the gateway's stop shortens the waits again meanwhile), within the stop's existing reserve, so the stop still ends by its deadline. A SIGTERM that was already due when a gateway stop shortened the waits is still sent; a stop that leaves no room from the start still skips it, as before.

### Security

- **R2 checks a tool call even when the caller never listed the backend** (F13,
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

- **Legacy HTTP session ids are minted by the gateway and never adopted** (F9,
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
- **The OAuth authorization code is no longer logged.** The gateway wrote the authorization code it received on the OAuth callback to the debug log (`Received authorization code`). Releases since v2.0.1, v3.5.1 included, did this; anyone running with debug logging enabled may have authorization codes in stored logs. A code is single-use and short-lived, and PKCE binds it to its verifier, but it is still a credential.
  Affects: 2.0.1 through 3.5.1 and the 4.0.0 pre-releases. Operator action: delete or restrict access to stored debug logs that may contain `Received authorization code` entries.
- **OIDC refusals no longer echo the issuer.** A load-time refusal names only the issuer's
  origin, and a token refused for a cleartext issuer carries no part of it, so userinfo, a
  tenant path or a query never reaches logs or support threads. (#2615)
  Affects: no released version. Operator action: none.
- An audit replay after a failed fail-closed invocation record no longer records the withheld value as delivered.
  Affects: no released version. Operator action: none.
- A finished task polled with an unchanged grant decision writes one decision record per 10 minutes instead of one per poll, except after a restart, or for a new key once 4,096 live keys are tracked; a changed decision is written at once.
  Affects: no released version. Operator action: none.
- An audit log cut below its signed high-water mark, or interrupted between the torn-tail repair and the missing-mark marker, keeps the finding; verify checks the hash at the mark.
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
  operator included) now sees `tools_count` null and `tools_known` false instead of the shared
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
  `observe`.
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
- A capability argument such as `{env.NAME}` is no longer expanded to the gateway's own secret: references are resolved in the capability template before caller values are substituted.
  Affects: 2.0.1 up to 3.5.1 and the 4.0.0 pre-releases (`{keychain.*}` from 2.1.0). Operator action: where untrusted callers could call capabilities, rotate every secret the gateway process can read through `{env.*}` or `{keychain.*}`, including ones no capability template referenced.
- security: relay detection gains an `allowed_flows` allowlist under `security.firewall.collusion` (up to 64 `{source, egress}` `server:tool` glob pairs; a matching flow is not reported or refused) and the counters `mcp_gateway_collusion_relay_total{action}` and `mcp_gateway_collusion_unkeyed_egress_total{action}` (#2731)
  Affects: no released version. Operator action: none.
- security: verbatim relay detection records a stdio receipt only after the answer passed the cross-tenant read judge and the audit write, so a withheld read leaves no receipt (#2748)
  Affects: no released version. Operator action: none.
- Typing: every handler on an MCP path returns a sealed `OutboundReply` naming its origin (judged answer, judged stream, gateway refusal); a source test pins the registered handlers.
  Affects: no released version. Operator action: none.
- A fixture corpus of outbound frames measures the cross-tenant read verdict per principal-session (test only).
  Affects: no released version; test-only change. Operator action: none.
- security: verbatim relay detection records a direct-route receipt only after the answer passed the read judge, the fail-closed audit write and the read record, so a withheld read leaves no receipt (#2757)
  Affects: no released version. Operator action: none.
- security: verbatim relay detection records a meta HTTP receipt only after the grant slot and the read record have let the answer go out, so an answer that either one replaces leaves no receipt (#2768)
  Affects: no released version. Operator action: none.
- security: verbatim relay detection now covers `prompts/get` arguments, `resources/read` URIs and the results of both on the meta, direct and stdio routes, keyed as `tools/call` is; the stdio catalogue is the local operator (#2771)
  Affects: no released version. Operator action: none.
- The direct route decides credential resolution and the OAuth-isolation guard on the backend it captured, not a by-name lookup a reload can swap. (#2772)
  Affects: 3.0.0 up to 3.5.1 and the 4.0.0 pre-releases. Operator action: none.
- Test: a block-mode test proves the audit entries for the read and the block of a cross-tenant read.
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
- An audit-log restart now checks the record the high-water mark names even when it is the newest record, so an edit made under its stored hash or a forged signature there is recorded as a finding instead of carried forward.
  Affects: no released version. Operator action: none.
- A prompt a backend sends through the gateway to the client is delivered and recorded in the same form: a backend copy of the reserved signature-chain member is dropped from both, so the relay receipt and audit record describe the bytes sent, and the firewall judges the prompt as the client receives it.
  Affects: no released version. Operator action: none.
- relay detection: a bridged prompt is receipted only once it reached the client, so no session or a send cancelled first leaves no receipt, and an answer's receipt is built from what the caller finally receives
  Affects: no released version; relay detection first landed after v4.0.0-beta.2. Operator action: none.
- relay detection: a followed upstream task's failure is receipted at settlement only when it is the peer's own error, unchanged by every screen and by the audit; gateway errors, substitutes and errors of unknown author on older rows are never receipted
  Affects: no released version; relay detection on task routes first landed after v4.0.0-beta.2. Operator action: back up `tasks.store_dir` before upgrading if a rollback to a build that reads task records only up to version 5 may be needed (UPGRADING-4.0 item 105).
- relay detection: a change to a plan's answer keeps each step's receipt for the text the caller still got, a plan receipt is never rebuilt from engine-written text, and no receipt fingerprint crosses a cap cut or a removed leaf
  Affects: no released version; relay detection first landed after v4.0.0-beta.2. Operator action: none.
- The release procedure now cosign-signs the published Helm chart by its OCI digest and verifies the signature against a pinned signer identity and issuer before the publish counts as passed; before, the chart was pushed unsigned (RFC-0133 HELM.6).
  Affects: no released version; the chart is first published with 4.0.0. Operator action: verify the chart before installing with cosign verify against the chart digest reference, using the chart reference, signer identity and issuer published on the v4.0.0 GitHub release.
- An audit-log restart now records a finding when the active file ends on the high-water mark's own record but opens an older segment than the mark names, as a file rebuilt from an older sealed segment plus genuine later records does; before, it resumed as the older segment and the next rotation overwrote that sealed segment with nothing recorded.
  Affects: no released version. Operator action: none.
- a credential a cli or mcp capability child printed but the gateway never injected now reaches the response firewall whole, so it raises a finding, a Block and an audit entry instead of passing as a bare marker; see UPGRADING item 141 (#2993)
  Affects: no released version; 4.0 pre-release builds that include #2697 or #2819. Operator action: none with the default firewall settings; with the firewall or credential_redaction off, such a value in a cli or mcp result or error excerpt now reaches the caller unchanged, as a REST capability result already does, so turn the firewall on to have it redacted.
- the warning logged when a tool result does not match its declared output schema no longer quotes the result: it names each violation's path and its expected and actual type, and an undeclared key only as "undeclared key", since a value or key there can be a credential and the log is written before the response firewall runs (#2993)
  Affects: 3.5.1 and the 4.0 betas, for any capability with an output schema whose result breaks it. Operator action: treat gateway logs from those versions that contain "did not match its declared output schema" as possibly holding backend-returned secrets; a log pipeline that parsed the old mismatch text sees the new path-and-type form.
- An audit-log restart no longer renames an active file that ends in a seal record onto a segment that is already sealed; such a file is a copy, not an interrupted rotation, and is now recorded as a finding and sealed under a fresh name instead of replacing the genuine segment, and a restart refuses a sealed segment numbered at the last value instead of sealing onto it.
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
  Affects: 2.0.1 through 3.5.1 and the 4.0 betas, for OAuth backends whose authorization server or its advertised endpoints are `http://` off this machine, and for capabilities with `auth.required: true` whose API URL is `http://` off this machine; also any capability (with or without a credential) whose request is redirected from `https://` or loopback to `http://` off this machine, or that targets loopback with `capabilities.egress_proxy` set. Operator action: such a backend now fails at connect, and such a capability file now fails to load (the warning names `providers.<name>.config.base_url` or `endpoint`). Move it to `https://`, or serve it on a loopback host (`localhost`, `127.0.0.1`, `[::1]`; `localhost.` with a trailing dot is not loopback). `allow_cleartext_credentials` does not cover either. If one ran over cleartext before, rotate the client secrets, refresh tokens and API keys it sent. A capability that relied on such a redirect now fails the call; a loopback capability now bypasses the egress proxy. A secret in a header, query or body template of a capability with `auth.required: false` is held to the same rule (#3070). See UPGRADING-4.0 item 146.
- MCP events: an event occurrence a source ties to one lifecycle key now reaches only the subscriptions that hold that key. The core guarantees key equality; a source that polls under one principal's credential keeps principals apart by putting the principal in its key, as the credentialed REST capability watch does. No source shipped so far sets a key. (#3053)
  Affects: 4.0.0 pre-releases only. Operator action: none.
- The grant-change journal and its lock now follow the grant file's real path, so a gateway and the `identity grants` CLI that spell one grant file two ways (a symlink, relative against absolute) share them: CLI changes are recorded as `add`/`replace`/`revoke` instead of `out_of_band`, and the two sides lock each other out. A CLI change made through a symlinked grant path now edits the file it points at and keeps the link, including the first change through a link whose target does not exist yet. (#3055)
  Affects: the 4.0.0 pre-releases. Operator action: none, unless the journal warning below appears. A gateway whose grant path spelling differed from the CLI's reads the CLI's journal for the first time after upgrading, and records its earlier entries once, beside the `out_of_band` records already made for them. A journal an earlier pre-release kept beside a symlinked spelling of the grant path is renamed beside the real file on the first locked read or change. When it is on another filesystem, or a journal beside the real file already exists, it is left in place and every reload logs a warning naming both files; append its entries to the journal beside the real file, then remove it. A symlink chain that never resolves is refused instead of being replaced by a file.
- An idempotent replay's invocation record now carries the request hash its first execution recorded. A retry that sent the tool's `arguments` as the equivalent JSON string was replayed correctly, but its record hashed the retry as sent, so one operation could carry two request hashes.
  Affects: the 4.0.0 pre-releases. Operator action: none.
- **A redaction marker can no longer reproduce an injected secret, and redacted output stays bounded.**
  A secret equal to the marker text, or one formed where the marker meets the text beside it, survived
  redaction of CLI and MCP results. The executor now switches to another marker, or drops the value,
  when one would leave a secret behind. Many short matches no longer grow a redacted string past twice
  its input plus one marker: past that, the matched region collapses into one marker. (#3057)
  Affects: 4.0.0 pre-releases only; 3.x unaffected. Operator action: none.
- **Protected-resource metadata names only issuers the running gateway accepts, and never one carrying a credential.** `authorization_servers` in `GET /.well-known/oauth-protected-resource` is now read from the configuration the process started with, so a reloaded but not yet applied `key_server` or `auth` change is not advertised. It is empty while `auth.enabled` is false or `agent_auth.enabled` is true, since agent auth refuses provider tokens. An issuer that is not an http(s) URL, or that carries userinfo (even an empty `@`), a query or a fragment, is no longer published on this unauthenticated endpoint; a warning that omits the URL is logged instead. (#3058)
  Affects: the 4.0.0 pre-releases. Operator action: none, unless a client found its sign-in server through such an issuer; configure the issuer as a plain https URL.
- With relay detection on, a relay receipt rebuilt after a redaction no longer drops the numbers from a surfaced tool's text that happens to be pretty-printed JSON: only a `gateway_invoke` answer, which the gateway itself wraps, is read decoded, and the caller now says which shape it delivered. (#3059)
  Affects: the 4.0.0 pre-releases with `collusion.action` on. Operator action: none.
- **Short numeric and literal secrets are redacted from CLI and MCP results.**
  An injected secret under 4 characters that reads as a JSON number (`7`, `-5`, `1e5`), or the
  literal `true`, `false` or `null`, came back unredacted when a child returned it as a JSON
  value. A result value equal to such a secret by exact JSON equality is now redacted; text that
  is not JSON (`007`) matches nothing. An integer-valued decimal or exponent secret
  (`9007199254740992.0`) is now compared exactly against integer results, so the integer one
  past it is no longer blanked. (#3060)
  Affects: 4.0.0 pre-releases only; 3.x unaffected. Operator action: none.
- **A disabled accounts block with an adapter checks every key reference before reading any.** Such a block's `file:` keys are read at load, and a malformed sibling key surfaced only later, when the adapter was built: the gateway started, logged a warning and refused every assertion header. The load is now refused first with `accounts.keys[<id>] must be an env: or file: reference`, and no secret file is opened. (#3061)
  Affects: the 4.0.0 pre-releases. Operator action: a gateway whose disabled accounts block has an adapter and a key that is not an `env:` or `file:` reference no longer starts; make every `accounts.keys` entry such a reference.
- A direct-name call of a surfaced tool the caller may not invoke now records the identity-grant decision that refused it, from the one evaluation that refused it. A grant reload between two evaluations could leave a decision record that disagreed with the refusal served; the refusal itself always failed closed.
  Affects: the 4.0.0 pre-releases. Operator action: none.
- The attributed invocation writer now refuses a caller-supplied `tenants_total`, so a signed record's tenant overflow count is always the one the writer derived.
  Affects: no released version. Operator action: none.
- **Shadow scan no longer reports a server as unauthenticated when its client config sends an auth header.** A discovered HTTP server whose config sets `Authorization`, `Proxy-Authorization` or `X-API-Key` (matched by name, any case) now gets `auth_exposure: http_auth_header` and the reason codes `http_auth_header_configured` and `server_auth_unverified`, instead of `unauthenticated_http_endpoint`. It is not counted as network-exposed and is not proposed for quarantine; its severity is medium, or high when the server touches sensitive data. A header whose value only the client can resolve, such as `${input:token}`, counts too; since adopting the server would drop it, the scan asks the owner instead of offering an apply command. Header values are never read into the report. (#3067)
  Affects: `shadow_radar.v1` consumers. Operator action: a consumer matching `auth_exposure` exhaustively should accept the new `http_auth_header` value.
- Four limits accepted for the 4.0.0 pre-releases are closed (#3068). With the tenant guard on, a quoted, double-encoded result cut short is read as far as it goes, so a document inside it is marked uninspected. With relay detection on, each pair keeps its own delivery times, so a stale copy plus a later re-delivery no longer excuses an egress, nor makes a witness, between them. On Windows, a refused grant-journal append says to check the journal's entries before it prints the repair commands. The manual events test stub refuses a `Content-Length` padded with vertical tab or form feed.
  Affects: the 4.0.0 pre-releases with the tenant guard or relay detection on, and Windows grant-journal refusals. Operator action: none.
- **A capability secret in a template no longer goes over cleartext.** A capability with
  `auth.required: false` whose header, query parameter or body template fills in
  `{env.X}` or `{keychain.X}` sent that secret to an `http://` host off this machine. It is
  now held to the `auth.required` rule: a literal `http://` `base_url` or `endpoint` off this
  machine fails to load, with a warning that names the URL field and the template field, and a
  URL filled from a caller's parameters is refused at call time, before the secret is read.
  REST, GraphQL and JSON-RPC all apply it. See UPGRADING-4.0 item 146. (#3070)
  Affects: 3.5.1 and earlier, and the 4.0 betas, for an operator-written capability that puts a secret in a template and points at `http://` off this machine; no shipped capability does. Operator action: move the API to `https://`, or serve it on a loopback host, and rotate a secret that went over cleartext.
- A legacy client that calls without a credential (authentication off, or on with the path public, as `/mcp` is in the shipped presets) and does not resume an established session no longer gets a new identity for the per-caller controls on every request. The tenant guard, anomaly detector and call budget now count all such requests under one shared identity, so tenant breadth, anomaly history and the call budget accumulate across them instead of restarting each time.
  Affects: the 4.0.0 pre-releases. Operator action: with the tenant guard, call budget or anomaly blocking enabled, keyless session-less legacy clients now share one limit; give them a credential, raise the limit, or have them reuse their session if they are refused.
- **A stdio backend that exits before `initialize` no longer has its stderr written to the gateway log.** The record names the command, the exit status, a cause class (`missing_module`, `missing_file`, `permission_denied`, `address_in_use` or `unclassified`) and the fixed needle that matched. The start error and `doctor --start-stdio` report the same. Before, the stderr tail was logged after pattern redaction, so a credential no pattern recognised could reach the log in clear. (#3140)
  Affects: the 4.0.0 pre-releases. Operator action: none. To see a failing backend's own output, run its command directly.
- **A response delivery audit record names a certificate, OAuth-agent or trusted-header caller by its verified subject.** With auth off or on a public path, such a caller's client is `anonymous` or `public`. Its `response_delivery_attempt` record now carries `who.authority` and `who.subject` from the verified grant subject, matching the invocation record for the same call. `caller` and `who.account` are unchanged, and a record for a caller without a verified subject is identical to before. (#3146)
  Affects: audit consumers of `response_delivery_attempt` records in the 4.0.0 pre-releases. Operator action: none.
- The tenant-read principal cap is exact, and a withheld stream request fails its waiter at once (#3166). Concurrent first frames for distinct principals can no longer push the tracked-principal map past its cap. A sampling, elicitation, roots or bridged request that every SSE stream withholds because its audit record could not be written now fails at once instead of waiting out its timeout.
  Affects: deployments with the tenant guard on, and SSE sessions whose audit writes fail closed. Operator action: none.
- A `/mcp` `tools/call` refused for malformed retry fields now writes one `invalid` audit record, through the same writer and failure policy as the other meta-route refusals. A meta-route refusal with no session is keyed by its own trace id instead of the empty session every stateless call shared.
  Affects: the 4.0.0 pre-releases. Operator action: none.
- **Two credentials can no longer share one caller identity.** A configured API key or bearer token is identified by the first 48 bits of its SHA-256 digest, and sessions, grants and tasks are keyed on that identity. Two credentials whose digests share those bits were treated as one caller: each could attach to the other's sessions and, in the 4.0.0 pre-releases, read and cancel the other's tasks. The gateway now refuses such a configuration at startup and on reload, naming both credentials; the identity encoding is unchanged, so existing sessions, grants and tasks stay readable. See UPGRADING-4.0 item 153. (#3185)
  Affects: 3.5.0, 3.5.1 and the 4.0.0 pre-releases, with more than one credential configured. Operator action: none for a configuration that loads; if the gateway refuses one naming two credentials, replace one of the two credentials or remove the duplicate entry.
- **A key-server caller no longer shares its principal with a configured credential.** A caller signed in through the key server, with an `/auth/token` token or a delegated OIDC bearer, was given a principal from the same 48-bit digest space as configured API keys and the bearer token. An API key could be given an OIDC user's principal on purpose, through the key's value or, in the 4.0.0 pre-releases, its configured digest. Sessions, tasks, event subscriptions and the response cache key these callers on their verified identity, so the overlap showed where the principal itself is recorded, such as audit attribution. These callers now get `kst:` or `oidc:` followed by a full SHA-256 digest, which no configured principal can equal. See UPGRADING-4.0 item 155. (#3236)
  Affects: 3.5.0, 3.5.1 and the 4.0.0 pre-releases with the key server enabled. Operator action: update any log or audit query that matched a key-server caller's 12-hex principal.
- **A numeric secret is matched only as a whole number in CLI and MCP results.**
  A result number whose digits held an injected numeric secret of 4 or more characters was
  redacted, so secret `1234` also blanked the unrelated number `912345`. A number is now
  redacted only when it equals the secret by value; the secret inside a string is still
  removed wherever it appears. (#3238)
  Affects: 4.0.0 pre-releases only; 3.x unaffected. Operator action: none.
- **`doctor --start-stdio --show-stderr` shows a failed stdio start's stderr tail, masked.** A backend that exits before `initialize` keeps its last 20 stderr lines in memory only in sanitized form: non-UTF-8 lines dropped, control characters replaced, URL credentials, `Bearer`/`Basic` values, secret-named `key=value` pairs and known token shapes masked, each line cut at 240 characters. The doctor prints them under a banner saying they may still contain secrets. The gateway log, MCP errors and `doctor` without the flag are unchanged: they never carry the stderr text. (#3252)
  Affects: the 4.0.0 pre-releases. Operator action: none.
- Cost accounting no longer keeps one record per answered call. Per-key and per-session spend grew without limit, and a caller without a credential (authentication off, or `/mcp` public as in the shipped presets) could grow gateway memory once per request. Keys, sessions and session-less callers now keep running sums: at most 721 hourly buckets for a key's windows, and per-tool rows capped at 256 plus one `(other)` row. A key idle for 30 days with no set budget is dropped.
  Affects: the 4.0.0 pre-releases and 3.x. Operator action: none. Key cost windows (24h, 7d, 30d) are now accurate to the hour, and a per-tool breakdown past 256 distinct tools shows the rest as `(other)`.
- The cost-governance budget enforcer no longer keeps a day accumulator for every name that ever spent. Entries from earlier days without a budget are swept, and past 256 unbudgeted names per map (or a name over 256 bytes), spend goes to a separate overflow total. Before this, with a backend's input-schema check off and a non-zero `default_cost`, every tool name a caller invented added a permanent entry.
  Affects: the 4.0.0 pre-releases and 3.x. Operator action: none. Budget checks are unchanged; the admin stats and saved costs gain `tool_overflow_spend_usd`/`key_overflow_spend_usd` (stats) and `tool_overflow_usd`/`key_overflow_usd` (saved file, defaulting to 0 for older files).
- **A recovered task result no longer carries a backend's forged provenance receipt.** When an upstream task finished after its call returned, the gateway now runs the provenance step on the result, as it does for a live call. With stamping off, a `_meta.provenance` the backend supplied is removed. With stamping on, it is replaced by the gateway's own signed receipt. Before this, a stored task result could deliver a backend's receipt as if the gateway had signed it. (#3374)
  Affects: the 4.0.0 pre-releases, for upstream tasks whose result is read after the call returned. Operator action: none.
- **An ambiguous principal no longer receives another credential's operational events.** Budget,
  health and kill-switch events are offered by the principal a credential derives (the first 48
  bits of its digest). When more than one live credential derived the same principal, the first
  configured one won, so one key's holder could receive another key's budget events, or the
  bearer's admin-only events. Such a principal now gets no event standing. Configurations with
  shared principals were already refused at load and reload; this closes the gap behind that
  check.
  Affects: 4.0.0 pre-releases with operational events enabled. Operator action: none; a
  configuration with shared principals is already refused at load.
- **Everything a backend sends a client passes one response screen.** The response firewall read
  only a tool result, at several separate points, so other backend text reached the caller
  unscreened: a JSON-RPC error on the per-backend route (`/mcp/{name}`), a prompt or resource
  body (`prompts/get`, `resources/read`) and the prompt, resource and template listings on both
  routes, and a notification a backend streamed during a call (progress messages and any other
  method). The same interim question was also redacted over HTTP but refused over stdio. Every
  outgoing frame now passes one egress scan on every route: content inspection, context
  integrity and the response firewall, on every part a frame carries. A completed answer is
  redacted in place; an interim question is refused rather than rewritten, on every route. A
  replayed idempotent answer and a task notification's stored result are screened again when
  sent, and backend failure logs carry the error code instead of the backend's text.
  Affects: 4.0.0 pre-releases and 3.x, all routes (`/mcp`, `/mcp/{name}`, stdio, tasks).
  Operator action: none. A prompt, resource or listing a firewall rule refuses now arrives as the
  firewall's refusal, and a firewall `tool_match` for those answers names the method
  (`prompts/get`, `resources/read`, ...).
- **A capability can no longer set `SYSTEMROOT` or `COMSPEC` for its child.**
  The gateway sets both for a Windows capability child itself, but an `env` allowlist entry,
  `token_env` or `root_env` naming either one used to replace that value, so a capability
  could point the child's system root or command shell elsewhere. Both names are now ignored
  in those lists, on every platform, like `HOME`, `PATH` and the other names the gateway
  sets.
  Affects: 4.0.0 pre-releases. Operator action: none; a capability that listed either name
  gets the Windows platform value instead.
- **On a gateway with authentication off, a client certificate owns its own tasks.** Certificate-only callers
  shared one anonymous task owner, so any of them could read or cancel another's tasks. Each now owns its
  tasks by its certificate subject. What you lose: tasks such a caller created before upgrading are no longer
  visible to it (they expire on their TTL). What you gain: one caller cannot reach another's tasks. What to
  do: nothing; re-run a lost task under a new idempotency key. (#3603)
  Affects: 4.0.0 pre-releases only; 3.x has no task store. Operator action: none.
- **A clock that reads before 1970 never makes an expiry pass.** On a host whose clock was set
  earlier than 1970 (a dead clock battery, an unsynced VM), the gateway read "now" as 0 or as a
  1969 date, so every deadline looked still ahead: an expired API key authenticated, and expired
  key-server bearer tokens, continuations and destructive-action confirmations, identity grants,
  attestation tokens, browser and dashboard sessions, consent journeys, external credentials and
  event-subscription leases were all still accepted. A JWT decode panicked instead, which stops
  a release build. The wall clock is now read in one place; an expiry judged on a clock it
  cannot read counts as passed, a timestamp is never written from it, and a cleanup that deletes
  aged-out state skips its pass instead. The gateway refuses to start on such a clock, and a
  token exchange or refresh reads the clock before the provider is called.
  Affects: 4.0.0 pre-releases and 3.x, every route and every expiry check.
  Operator action: a gateway on a clock before 1970 now refuses to start with "system clock reads
  before 1970; set the clock and restart". Set the clock (enable NTP) and restart; nothing else
  changes.
- **A retried or repeated call is answered from its stored result only while the caller's account is live.**
  A keyed retry, or a repeated task call, to a backend that mints a per-caller credential (a
  managed account, or identity propagation with or without `account:`) was answered from the
  stored result even after the caller's account was revoked, unbound or broken. The gateway
  now resolves the account as the live call would before serving it. When it resolves, the
  stored answer goes out unchanged, with nothing sent to the backend again and the signing
  nonce kept spent. When it does not, the caller gets exactly the live call's answer: its
  refusal or connect offer, or a retryable `-32603` while custody is unavailable. A keyed
  call to a tool name the caller can no longer see now answers `-32601`, as a missing name
  does, whatever its key has stored. On an optional (`required: false`) propagation
  backend, a mint that fails now proves nothing: the static-credential fallback is not
  the caller's account. A keyed retry (on `/mcp`, stdio, or the direct `/mcp/{backend}`
  route) or a repeated task call is then not served the per-user stored result and is
  not sent again: it answers `-32603` ("identity propagation minted no credential for
  backend '<server>'; a stored result is not served without one"), not marked
  retryable, and sends nothing, unless the first call was itself unminted, whose cached
  result is served. Plan replays (`gateway_execute`, playbooks) get the same proof in
  changelog.d/3907.security.md.
  Affects: clients that retry with idempotency keys or repeat task calls on per-caller
  backends. Operator action: none; see upgrading.d/8392-2.md, upgrading.d/8392-3.md
  and upgrading.d/8392-4.md.
- **The direct `/mcp/{backend}` route no longer serves a stored per-user result to an unminted retry.**
  On an optional (`required: false`) identity-propagation backend, a keyed retry on the
  direct route whose mint failed (the IdP down, or the caller's grant revoked) reached the
  execution store under the same owner and was served the per-user output the first,
  minted call produced, under the static credential. A passthrough retry that forwarded
  no credential was served the same way. The direct route now refuses it exactly as `/mcp`
  does: HTTP 200, `-32603` "identity propagation minted no credential for backend
  '<server>'; a stored result is not served without one", nothing sent, and a signed
  call's nonce kept spent.
  Affects: clients that retry with idempotency keys on the direct route to optional
  per-caller backends. Operator action: none; see upgrading.d/8392-4.md.
- **An open `tools/list_changed` stream re-checks its agent, certificate and proxy at every notification.** A GET or `subscriptions/listen` stream held under an OAuth agent is told what that agent's current registry scopes show, not what they showed at attach. It closes when its bearer validates as another agent, when its client certificate is past `notAfter` (or the clock cannot be read), or when its trusted proxy is no longer in `trusted_proxies`. Each closure is counted once in `mcp_view_liveness_dead_total{reason}` as `agent`, `cert` or `proxy`.
  Affects: deployments with agent auth, mTLS client certificates or `trusted_proxy` identity that hold streams open.
  Operator action: none; clients reconnect. To end a revoked certificate's open stream, restart with the new CRL or issue short-lived certificates.
- **A signed call that waited on another call's tool-list fetch keeps its nonce spent if it is refused.**
  When a signed call's checks found the backend's tool list already being fetched for another call, the
  call waited for that fetch, and a refusal after it (the spend budget, relay detection, the request
  firewall) still gave the signing nonce back. The same signed request could then be sent again after it
  had waited on the backend. Waiting on a fetch already under way now counts as having acted on `/mcp`
  and the direct `/mcp/{name}` route, so the nonce stays spent. stdio runs the same route-stage check as
  `/mcp` and reads the same count, but has no test of its own for this case. An unrelated call waiting on
  a fetch at the same moment can make an honest refusal keep its nonce too; re-send it under a fresh
  nonce.
 
  Affects: 4.0.0 pre-releases only. Operator action: none.
- **On stdio with message signing, a tool hidden from the caller can no longer be told apart by its error-rate cooldown.** On a per-user backend, a signed `gateway_invoke` of a tool the caller's own list hides answered "temporarily disabled due to a high error rate" when other callers had pushed that tool into cooldown, while a missing name answered "Unknown tool"; the difference showed the hidden name exists. The hidden tool now gets the missing name's answer and is never sent. A caller who can see the tool is still refused for the cooldown, now after its nonce is checked.
  Affects: signed `gateway_invoke` calls to per-user backends, on stdio and, when the caller's own list has not shown the tool for that call, on `/mcp`.
  Operator action: none; see UPGRADING.
- **A caller with no connected account can no longer tell a per-user tool exists from its error-rate cooldown.** On a per-user backend, `gateway_invoke` of a tool other callers had pushed into error-rate cooldown answered "temporarily disabled due to a high error rate", naming the tool, while a missing name got the account's connect offer. On a per-user backend the error-rate check now runs after the caller's credential step, so a caller with no connected account gets the connect offer for both, on `/mcp` and stdio, signed or not, in a task or a `gateway_execute` chain. A caller who can see the tool is still refused for the cooldown.
  Affects: callers of per-user backends whose tools enter error-rate cooldown.
  Operator action: none; see UPGRADING.
- **A repeated plan is answered from its stored result only while every account its steps used is live.**
  A keyed code-mode (`gateway_execute`) or playbook (`gateway_run_playbook`) call, repeated
  with the same key (as a retry or as a task call) after the caller lost access to an
  account one of its executed steps used, was answered from the stored plan output. It now
  gets the live call's answer: the connect offer, or that account's resolution error, or a
  retryable `-32603` while custody is unavailable. The stored output is not served, no step
  runs again, and nothing is sent. A step the plan never ran is not judged. For chains and
  for continue/retry playbooks the answer is the first such step's own refusal, not the live
  run's wrapped or partial result (no step is re-run to build it). A repeated plan task whose
  managed account was revoked answers `-32601` for its step tool, as a missing name does,
  where a live call from an Open WebUI-bridged caller would offer a reconnect; it fails
  closed and serves nothing. Plans whose steps are themselves plans are not covered by this
  change.
  Affects: clients that repeat keyed plan calls on per-caller backends. Operator action:
  none; see upgrading.d/8406.md.
- **A scoped API key can no longer tell which backend names are registered.** A key whose
  `backends` list names backends (without `*`) now gets, for a backend outside its scope,
  the answer a backend that does not exist gets, on every route:
  - `/mcp/{name}`, any method: 404 and -32001 `Backend not found`.
  - `/mcp` `gateway_invoke` and a single-call `gateway_execute`: the `isError` result for a
    tool the backend does not list. This is the answer a registered backend outside the
    scope already got. A chain step answers that text inside its -32603 step error.
  - `prompts/get`, a chain resume and a stored task read: -32001 `Backend not found`.
  The audit record still carries the scope refusal (-32003) for a backend outside the scope.
  A backend in the key's scope that is not registered now takes the same path: it is
  answered at the gate, before signing and admission, instead of deep in dispatch. A key
  with an empty `backends` list keeps its 403 grant message.
  Affects: HTTP callers that authenticate with a scoped API key.
  Operator action: none. A client that matched 403 and -32003 for a backend outside its
  key's scope now gets the not-found answer instead.
- **A key with an empty `backends` list no longer tells registered backends from
  unregistered ones.** On `/mcp` (`gateway_invoke`, `gateway_execute`) such a key used to get
  the absent-tool answer (HTTP 200) for a registered backend, `Tool not found` for the
  capability backend, and the 403 grant refusal (-32003, "has no backends granted") for a
  name that is not registered, so the answers revealed which backends exist. Every name now
  gets the 403 grant refusal, as the direct route `/mcp/{name}` already answered. The
  refusal is decided before any backend lookup, so it says nothing about which backends
  exist. With `security.sanitize_input` on, a `passthrough: true` backend is no longer exempt
  from sanitizing for such a key, so input the sanitizer refuses (a NUL byte, say) answers 400
  for every name rather than 403 for that backend alone.
  Affects: API keys whose `backends` list is empty (docs/UPGRADING-4.0.md section 32).
  Operator action: none; grant such a key the backends it needs.
- **A keyed call from a caller with no execution principal is now refused at intake on `/mcp/{name}` and `/mcp`, before any backend connection, identity exchange or schema read, with one answer for every tool and backend name.**
  A keyed `tools/call` (one carrying `_meta["io.mcp-gateway/idempotency-key"]`, valid or
  malformed) from a caller with no verified identity, routed task owner, credential or proven
  `agent_oauth`/`mtls` subject was refused `-32003` only after the gateway had listed the
  backend, read the tool's schema and, on the direct route, possibly exchanged a token. The
  answer told a caller whether a backend was up (`500` transport error), absent (`404
  -32001`) or present (`-32003`). The refusal now comes first: `-32003` "A verified
  execution principal is required", HTTP 400, the request's own id, and the call is recorded
  as `invalid` on `/mcp` as it already was on the direct route. Protocol-field validation,
  caller authentication, the hardened identity refusal, `/mcp`'s chain-nonce refusal and a
  scoped key's backend refusal still answer first. Auth-off gateways keep pooled anonymous
  task ownership: a keyed task submit there is still admitted under the shared anonymous
  owner; sync keyed calls without a principal are refused earlier. A call answered as a
  missing name because its backend requires identity propagation and the caller has no
  principal for it keeps its `-32601` answer, and the server now logs one WARN per backend
  and caller key every 10 minutes (while fewer than 1024 backend and caller pairs are
  tracked; past that the oldest entry is dropped and a pair can be warned again sooner;
  callers with no key share one entry per backend).
  Affects: anonymous keyed calls, and keyed task submits without a principal on a gateway
  with authentication on. Operator action: none for most deployments; see
  upgrading.d/3910.md.
- **A scoped key's stored-task read no longer touches a backend outside its scope.** Reading a
  stored task whose backend the key may not see used to resolve that backend through the
  unscoped registry first, which kept its idle connection warm. The read now resolves through
  the key's scope and leaves the backend alone. Production code reaches the backend registry
  only through a scoped view or a named class, and a clippy ban in CI enforces it.
  Affects: HTTP callers that authenticate with a scoped API key.
  Operator action: none.
- **A stored task read no longer reveals a hidden per-user tool through its error-rate
  cooldown.** A caller with no view of a per-user tool (grant revoked, or the tool not
  in its catalogue) who read a stored task naming that tool while it was cooling down
  got a retryable "temporarily unavailable" error, where a missing name gets "no such
  tool". The read now judges the caller's account and catalogue first and meets the
  cooldown last, as the live call does, so both answers are the same. A caller with a
  view still gets the retryable answer while the tool cools. The read costs one
  custody (credential store) read for a cooling per-user tool. Tasks that name a
  capability-provider tool are not covered here.
  Affects: gateways with per-user (managed-account) backends and task-augmented calls.
  Operator action: none; upgrade to this release.
- **A capability tool's error-rate cooldown no longer reveals the tool to a caller whose
  account grant was revoked.** A caller with no view of a capability's personal account
  who read a stored task naming a tool in cooldown got "temporarily disabled due to a
  high error rate" (naming the tool) where the same read before the cooldown answers
  that the tool is absent. The cooldown is now checked after the account step, as it
  is on a per-user backend. A keyed replay of a finished call to a tool in cooldown is
  now refused instead of served, for account-bearing capabilities and per-user
  backends.
  Affects: gateways with capabilities on personal accounts (`auth.account`).
  Operator action: none; upgrade to this release. Clients that retry a refused signed
  call must send a fresh nonce.
- **The gateway no longer depends on `serde_yaml` or `unsafe-libyaml`.** `serde_yaml` is
  deprecated and unmaintained, and `unsafe-libyaml` is libyaml transpiled to unsafe Rust. YAML is
  now read and written by the gateway's own adapter, built on `granit-parser`, the parser the
  pre-parse guard already used. Every YAML file the gateway reads or writes behaves as before: the
  same values, refusals and error text, and byte-identical written output, so a file the new
  version writes still loads in an older one. RUSTSEC-2024-0449 (unsafe-libyaml unmaintained) no
  longer applies, and its time-boxed release-gate exception is removed. (#4138)
  Affects: every build; no YAML input or output changes. Operator action: none.
- **A firewall rule's `scan` list now limits the findings it decides.** The list was documented but never read: a rule whose `match` covered the tool decided every finding in the call. An `allow` rule written for `scan: [credentials]` therefore also allowed a shell injection or path traversal in the same call, and a `warn` rule softened a high-severity injection to a warning. Each finding is now decided by the first rule whose `match` covers the tool and whose `scan` list holds that finding's type (an empty list holds every type), or else by its severity default, and the call or answer takes the most restrictive result. A rule with no `scan` list behaves as before.
  Affects: every release since 2.6.0 with `security.firewall.enabled` on and an `allow` or `warn` rule that sets `scan`. Operator action: none for configs without `scan` lists; where a rule sets one, check that calls it used to allow or warn on for other finding types are meant to be blocked by their severity default.
- **A capability naming `localhost` no longer reaches loopback past the egress proxy.** With `capabilities.egress_proxy` set, a capability endpoint, GraphQL or JSON-RPC endpoint, OAuth token endpoint or redirect hop whose host was `localhost` skipped the proxy and was connected directly, with no address check. A host that is `localhost` or `*.localhost`, in any case and with trailing dots, is now refused before any lookup on every capability route; without a proxy it was already refused at resolution. Only loopback IP literals skip the proxy, and the address check still refuses them. A public-looking name whose DNS points at loopback goes to the proxy, which must refuse loopback and private ranges itself. See UPGRADING-4.0 item 77.
  Affects: the 4.0.0 pre-releases with `capabilities.egress_proxy` set. Operator action: none, unless a capability targets a service on this machine by name through a proxy; name it by an address the isolated runtime allows, or serve it on a host the proxy reaches.
- **A refused backend redirect fails once, without a retry.** A backend's redirect to another origin, or to an address the SSRF rule refuses, was reported as a transport error and retried, so the backend was asked again only to be refused again. The call now fails once with `-32600`: the cross-origin message (`redirect target is cross-origin to the transport base URL; ...`) or `SSRF blocked`. See UPGRADING-4.0, "A refused backend redirect fails once, without a retry".
  Affects: backends whose HTTP endpoint answers with a redirect the gateway refuses. Operator action: none; a backend whose endpoint redirects to another origin never worked through the gateway, so configure the URL it redirects to.
- **The shadow radar no longer shows URL paths or full config paths.** Its report (`cap discover --shadow`), its SIEM export and the control-plane page showed each found server's URL with its path and built the server's asset id from that URL, so a token placed in a URL path, in an MCP client's config file, an environment variable or a process argument, appeared in both. Endpoints now show the URL's origin only (scheme, host and port), the config path shows the file's name only, and an asset id carries a digest keyed by the gateway's record key instead of the URL. The same holds for client-file, environment and process finds.
  Affects: anyone who stored or shared radar reports or SIEM exports from 3.5.x or earlier. Operator action: if a URL path carried a token, rotate it, and prefer a header for credentials. Asset ids from the gateway hold across restarts; ids from the command line hold only once a gateway has created the record key (or one is configured), and until then each report says its URL ids are for that run only.
- **A subscription's stored identity is checked again when the events store reads it back.** A per-user event subscription keeps the identity its backend observes the subscriber as, and the events store reads that row back from disk on every start. It was read straight from the file, so a stored identity with an empty or blank issuer or subject loaded as an identity that names nobody. It now comes back only through the gateway's checked identity constructor: such a row observes as no one, gets no listener and no shared credential, has its queued deliveries cancelled, and is revoked at start with a warning naming its handle. `VerifiedIdentity` and `TemporaryToken` in the library's `key_server` module no longer implement `Deserialize`; nothing in the gateway reads either back (see UPGRADING-4.0, "Verified identities and gateway tokens can no longer be read from bytes"). (#4629)
  Affects: unreleased 4.0.0 code only; no released version, 3.x or a 4.0.0 pre-release, stores per-subscriber identities. Library users who deserialized `VerifiedIdentity` or `TemporaryToken`, possible since 3.x, can no longer read either from bytes; they come only from the gateway's own verification. Operator action: none. A row revoked this way is logged at warn level with its handle; its subscriber subscribes again.
- **Discovery failure lines escape client text, and a guard keeps every discovery output escaped.** The `cap discover` failure lines (writing the config, discovery, adopting shadow servers) and the config, process and environment scan-failure warnings printed their error as it was; an error can quote a server name or path from a client's MCP config, so an ANSI escape or bidi override in it reached the terminal. These lines now carry the same `\u{..}` escaping as the rest of discovery output. A new test lists every value the discovery code prints, logs or formats: each must be escaped, a literal, or a reviewed entry, so a new unescaped output fails CI.
  Affects: the 4.0.0 pre-releases and earlier, when a discovery failure's error quotes a client config value holding control or bidi characters. Operator action: none.
- **Only the outbound judge can reach the cross-tenant read history, enforced by the compiler.** Recording and checking a caller's reads across tenants now needs a token that only the judge can build, so a second path to the history, including a call a macro assembles at expansion, fails to compile instead of relying on a source scan alone. A CI check builds a probe of forged calls and passes only if each is refused for the token's privacy.
  Affects: none at runtime; this closes a code-review gap in the 4.0.0 pre-releases. Operator action: none.
- **Stored answers no longer carry a seal over bytes the gateway redacted.** A response-cache
  hit, an idempotency replay, `tasks/get` or a task notification served a stored answer with
  its provenance `public_signature`, made before the answer was scrubbed against the secret
  values held when it is served. The signature's payload carries the unsalted digest of the
  unredacted result, so a client could test guesses of a removed value offline, and the seal
  no longer covered the delivered bytes. While any secret value is held, stored answers are
  now served with no `public_signature`, steps in JSON text included; receipts stay, and fresh
  deliveries are sealed as before. See UPGRADING-4.0. (#4780)
  Affects: 4.0.0 pre-releases only; 3.x unaffected. Operator action: none.
- **The classic web UI no longer contacts a CDN.** `/ui` and `/ui/classic` loaded a script from
  unpkg.com that the page never used, so every open told a third party the operator's address
  and time of use, and the page needed the internet. The tag is gone, and both routes now send a
  Content-Security-Policy that lets the page load and connect to the gateway's own origin only,
  with `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`.
  Affects: every release with the classic UI. Operator action: none.
- **Preview install: a fetched package that is not plain registry content is refused before anything runs.** The checks sit in `src/preview_sandbox/install.rs` and are not yet reached by a route. An npm lock is refused when any entry, the root included, is a link or is not a registry tarball, or when a declared dependency is a git, file, URL, leading-dot or archive-suffixed spec, or an edge no entry satisfies. The npm run file must stay inside its package directory, which must stay under the install root; the uv console script comes from the package's own entry points (exact name first, a path-like name refused), never from a listing of `bin/`; metadata files must be regular files of at most 1 MiB.
  Affects: nobody yet: the preview sandbox is not reached by any route in this release; it applies to a later preview-install route.
  Operator action: none.
- **Preview fetch: the output a failed fetch shows never carries the fetch credential.** The output of the package fetch is read to the end (so the fetch never blocks on a full pipe), its last 64 KiB kept with any partial first line dropped, and only the last non-blank line is shown, with the credential removed raw, in base64 and in any letter case, and with every URL-like word (userinfo, query and fragment) reduced by the URL parser, failing closed. The code is not yet reached by a route.
  Affects: nobody yet: the preview sandbox is not reached by any route in this release; it applies to a later preview-install route.
  Operator action: none.
- **Chain and playbook step seals, and a stored task's own seal, are no longer served over bytes the egress firewall redacted.** A step answer is sealed when it is made; the egress firewall later redacts the delivered answer, and the step seal's readable payload carries the unsalted digest of the unredacted step, so a client could test guesses of a removed value offline. While the firewall scans responses and a redacting policy applies, every `public_signature` in the answer is now removed before the scan, at any depth and in JSON text, `tasks/get` and task notifications included; the fresh top-level seal, applied after the scan, still covers what is delivered. An answer the firewall rewrote whose text names `public_signature` without parsing as JSON is refused. See UPGRADING-4.0.
  Affects: 4.0.0 pre-releases only; 3.x unaffected. Operator action: none.
- **Dependency: `rustix` updated to 1.1.6 (RUSTSEC-2026-0486).** The advisory covers rustix's extended-attribute functions, which could mark memory as initialized when given a zero-length buffer. The gateway's one use (an access-ACL probe) was not affected; the update removes the advisory from the dependency scan.
  Affects: builds from earlier 4.0.0 pre-releases. Operator action: none.
- `serve --stdio` now exits even when its client stopped reading stdout: once the session has ended, the runtime waits at most 10 s for a stuck stdout write instead of hanging the process.
  Affects: 3.x and earlier stdio mode. Operator action: none.
- A stdio client that stops reading stdout can no longer wedge the gateway with batches or malformed lines: the reader keeps reading, so EOF and cancels are still handled and the session ends within its drain deadline.
  Affects: 3.x and earlier stdio mode. Operator action: none.
- `audit verify --anchor <file>` verifies the audit log against an off-host copy of its `.hwm`,
  so a log that was wiped, rolled back or replaced with a rewritten `.hwm` fails. A signed anchor
  refuses a verify with no secret. The oldest surviving segment must start its chain from the
  boundary it links to, and a counter of `u64::MAX` in a record is a failed verdict, never a
  panic.
  Affects: 4.0.0 pre-releases and 3.x. Operator action: keep a copy of `<log>.hwm` off the host.
- Under the `standard` posture, a `gateway_invoke` that the caller is not allowed to make now gets its policy refusal even when it carries a malformed signing nonce, and no nonce rejection is counted for it; the nonce is judged after the invocation policy, as `UPGRADING-4.0.md` now states.
  Affects: no released version. Operator action: none.
- Security: attestation tokens carry a required `audience` claim and a gateway accepts only its own; `enforce` needs `GATEWAY_ATTESTATION_AUDIENCE`.
  Affects: 3.x up to 3.5.1 and the 4.0.0 pre-releases. Operator action: set `GATEWAY_ATTESTATION_AUDIENCE` on each gateway running attestation in `enforce` mode and mint tokens with that audience.
- With agent authentication on, a stream opened with an agent token is now checked again at every delivery: once the token expires, the agent is removed or its key changes, the stream receives nothing more and ends without a closing message. A GET /mcp stream also checks each queued notification when it writes it, for every credential kind, and a prompt queued behind a dead credential fails at once instead of waiting out its timeout. With gateway authentication also on, a valid agent token can now listen on a public /mcp.
  Affects: deployments with agent authentication on, and every GET /mcp stream opened with a credential. Operator action: none; clients re-subscribe with a fresh token when a stream ends, and library users who build `AuthState` by hand set its new `agent_auth` field.
- Security: `gateway_invoke` judges and dispatches a call on the backend it captured, not a by-name lookup a reload can swap.
  Affects: 3.x up to 3.5.1 and the 4.0.0 pre-releases. Operator action: none.
- **Only the capability loader can mark a definition pinned.** A program built on the crate could
  set `ProvidersConfig::integrity` to `Verified` on a definition it built, so a `cli` or `mcp`
  process provider ran without the `sha256:` pin check. `process` and `integrity` are now
  crate-private, read through `process()` and `integrity()`, and a process runs only while the
  definition matches the fingerprint taken when its pin was checked, so a verified definition
  copied and edited is refused. The response cache of a process provider keys on that fingerprint, and replacing a
  definition through `register_capability` stops its `mcp` children. See UPGRADING-4.0 item 144.
 
  Affects: no released version. Operator action: none; an embedder that read the fields calls the getters, and one that edits a loaded definition loads the edited one through the capability loader.
- **A `message` webhook's top-level `id` is judged as content by the cross-tenant read check.** The session-stream judge skips a `message` document's top-level `id` as JSON-RPC framing, and a webhook body was judged only on its raw form, so a `data` mapping that wrote another tenant's identifier into `id` reached the caller unflagged and, under `cross_tenant_reads: block`, unwithheld. The written `id` is now judged with its member name.
  Affects: deployments with `tenant_guard.cross_tenant_reads` on, `id` listed in `tenant_guard.arg_keys`, and a webhook with `transform.event_type: message` whose `transform.data` maps a field into `id`.
  Operator action: none; upgrade. To check exposure before upgrading, look for `id` in `arg_keys` alongside such a webhook mapping.
- **A cached `mcp` capability answer is read back only by the caller whose child produced it.**
  The capability's own result cache keyed every caller without a grant subject as one, so on a
  capability with `cache:` set and identity propagation off, a second OIDC-identified caller could be served the first
  caller's cached answer from that caller's child. The cache now keys an `mcp` answer on the
  same per-caller name its child runs under.
  Affects: 4.0.0 pre-releases only; 3.x has no `mcp` capabilities. Operator action: none.
- An SSRF refusal for `::169.254.169.254` (an IPv4-compatible IPv6 spelling) names the metadata
  service, as the mapped spelling already did; the address was always refused.
  Affects: error text of that refusal only. Operator action: none.
- `mcp_gateway_collusion_relay_total` now counts an unkeyed caller's blocked relay, and the new
  `mcp_gateway_collusion_plan_receipts_dropped_total` counts plans whose step receipts were
  dropped because the answer was over the bound.
  Affects: 4.0.0 pre-releases only. Operator action: none.
- audit log: a restart no longer advances `.hwm` over a tail that contradicts it. A tail behind the mark in any segment (an older active file restored) or a record at the mark replaced by another is now recorded as a loss and the counters are never reused, in signed and unsigned logs
  Affects: no released version. Operator action: none.
- Security: a direct-route notification is charged to its credential, not its display label, so two keys with one label no longer share a notification budget.
  Affects: no released version. Operator action: none.
- relay detection: receipts follow the delivered result. A redaction rebuilds the call's receipt from what goes out and keeps its sensitivity verdict, reading a failed task receipts the backend's error, and a stdio answer whose result is null delivers a result; the known limits are stated in the design doc
  Affects: no released version. Operator action: none.
- events: a static-bearer subscription is re-checked against the full SHA-256 of the bearer, not the 12-hex log fingerprint; older rows keep the fingerprint check
  Affects: no released version. Operator action: none.
- tasks: a stored task row older than the upstream-descriptor version no longer yields backend targets from a descriptor it could not have captured
  Affects: no released version. Operator action: none.
- capabilities: an MCP capability reload revokes under the lock that admits a call, so it cannot land between the epoch check and the lease; the path-confinement swap residual is stated for every root
  Affects: no released version. Operator action: none.
- The MCP events OAuth dev shim marks its token and registration answers no-store and refuses an oversize request body before reading it, and the EVENTS.8 run script empties its directory only when that directory's state.json names the script as its owner.
  Affects: no released version. Operator action: none.
- events: a backend that becomes ineligible for upstream events after a reload stops delivering them: the listener rechecks eligibility at every delivery and reconnect, ends, and its upstream subscriptions are withdrawn; a tools notice also clears the resend-permitted set
  Affects: no released version. Operator action: none.
- The HTTP events listener no longer repeats the request URL, which can carry credentials in its query, in its error messages.
  Affects: no released version. Operator action: none.
- An event delivery whose subscription's API key lost its backend grant while the delivery was being checked
  is no longer sent: access is read again after the last source check, as eligibility already was. One
  delivery attempt also waits on an unresponsive backend's resource catalogue at most once.
  Affects: 4.0.0 pre-releases only; 3.x has no event subscriptions. Operator action: none.
- A successful `cli` or `mcp` result no longer leaks an injected all-digit credential with
  leading zeros when the child prints it as a JSON number, which drops the zeros (`012345`
  came back as `12345`): numbers are now compared to such a credential by value as well as by
  text, with the sign ignored, and a credential past u64 is parsed by the same JSON parser that
  read the result, so both sides round alike. See UPGRADING-4.0 item 141.
  Affects: 4.0.0 pre-releases only; 3.x has no injected-value scrubbing (its firewall credential redaction is pattern-based and unchanged). Operator action: none.
- audit: on stdio, the `response_delivery_attempt` record is now written after the cross-tenant read judge, over the frame the client receives. A refused read is recorded as the refusal, and its read verdict rides that one record instead of a separate `tenant_read` event, as on `POST /mcp` and `/mcp/{name}`.
  Affects: no released version; the cross-tenant read judge first landed after v4.0.0-beta.2. Operator action: none; a SIEM rule that reads stdio answers from `event: tenant_read` reads the same fields on `response_delivery_attempt` instead: `tenants` or `attribution` to count reads, `cross_tenant_read` to flag one (UPGRADING-4.0 item 130).
- **A relay receipt holds only the backend text the caller was shown.** The gateway's own members
  (recovery hints, cost advice, predictions, trace ids, provenance, signatures, response findings)
  and a task envelope's status fields were receipted as if the backend had sent them, so a caller
  could relay that text past relay detection; they are now left out, and a backend member of the
  same name stays in. A `gateway_execute` answer and a non-object `gateway_invoke` value are read
  decoded, and a task's stored result is receipted as stored.
  Affects: 4.0.0 pre-releases only; 3.x unaffected. Operator action: none.
- A successful `cli` or `mcp` result no longer leaks an injected credential written in another
  number form, such as `+12345` or `1.5e10`, when the child prints it as a JSON number
  (`12345`, `15000000000.0`): such a credential is now compared to numbers by value. Any number
  equal in value to it is redacted, even one printed for another reason.
  Affects: 4.0.0 pre-releases only; 3.x has no injected-value scrubbing. Operator action: none.
- An event subscription whose event type no source offers any more, for example after its
  source was switched off and the gateway restarted, no longer has its pending deliveries
  sent or charged. Each such delivery is held and recorded as `source_unavailable`; it is sent if
  a source offers the type again, and dead-lettered `exhausted` at its retry limit otherwise.
  The subscription itself is kept.
  Affects: 4.0.0 pre-releases only; 3.x has no event subscriptions. Operator action: none.
- Two event subscriptions whose arguments differ only in an integer beyond 2^53 (for example
  `9007199254740993` and `9007199254740992`) now get different subscription ids instead of
  sharing one id and one stored row. Every other subscription id is unchanged, so stored
  subscriptions keep theirs.
  Affects: 4.0.0 pre-releases only; 3.x has no event subscriptions. Operator action: none.
- **A plan step's relay receipt keeps the text the plan delivers.** A plan step's receipt was
  capped (a 3 KiB head and a 3 KiB tail) over the step's whole value, before the plan kept
  only some of it. A playbook that delivers one member of a step lost that member's text from
  the receipt when the backend padded the members around it, and keeping the receipt to the
  plan's answer could not bring it back. A plan step's receipt is now capped after it is kept
  to what the plan delivers, keeping no more copies of a leaf than the plan delivered, and at
  the latest when it is recorded.
  Affects: 4.0.0 pre-releases only; 3.x unaffected. Operator action: none.
- **A task result read later no longer counts the gateway's own text as the backend's.** With relay detection on, `tasks/get` now leaves out of its relay receipt the members the gateway wrote into the stored result (`trace_id`, cost advice, security findings, provenance, contract annotations), on chains and playbooks too. A backend member of the same name stays in the receipt. Task rows gain an optional `gatewayWrites` member; rows without it read as before.
  Affects: the 4.0.0 pre-releases, with relay detection on, for task results read with `tasks/get`. Operator action: none.
- **An interim answer's relay receipt keeps the backend's prompt.** The continuation the
  gateway mints in place of a backend's `requestState` (up to 8 KiB) was digested into the
  relay receipt with the backend's text, so a large one used the receipt's capped budget
  and pushed the end of the backend's prompt out of it, and relaying that text went
  undetected. The continuation is now left out of the receipt as the gateway's own text;
  every backend member stays. With relay detection on, under context integrity's `Strip`,
  the delivered text of an interim answer no longer repeats the continuation; it still
  arrives as `requestState`.
  Affects: 4.0.0 pre-releases only; 3.x unaffected. Operator action: none.
- **A redacted `gateway_invoke` answer keeps its relay receipt.** When the final firewall
  pass redacted text inside an invoke wrapper and the wrapper no longer parsed as the
  gateway printed it, the receipt was rebuilt from the escaped wrapper text (`\n` as two
  characters), so relaying the delivered text went undetected and the gateway's own members
  came back into the receipt. Such an answer now keeps the receipt staged from the
  backend's value and keeps it to the delivered text read as the caller reads it
 .
  Affects: 4.0.0 pre-releases only; 3.x unaffected. Operator action: none.
- **A webhook `base_path` may not overlap a gateway route.** With the receiver enabled,
  `webhooks.base_path` was mounted unchecked, so a path such as `/mcp/hooks` put a webhook
  handler under a gateway route and past the rule that every MCP-path handler names its
  origin, and a path such as `/mcp` or `/ui/api/backends` made startup panic. Config load and
  reload now refuse a path equal to, under or over a gateway route, and one axum cannot mount
  as written; the default `/webhooks` is unaffected.
  Affects: 4.0.0 pre-releases and 3.x. Operator action: move a receiver mounted under a gateway
  route to its own path (UPGRADING item 157).
- With gateway authentication off and agent authentication on, each validated agent now owns its own tasks; before, every agent shared one task owner, so one agent could read, cancel or replay another's task and listen to its notifications. With agent authentication off, callers still share one pool, as before.
  Affects: the 4.0.0 pre-releases, in deployments with gateway authentication off and agent authentication on. Operator action: none; tasks an agent created before the upgrade stay in the shared pool until they expire.
- **The direct route `POST /mcp/{name}` refuses what `/mcp` refuses, under every posture.**
  Outside `hardened`, the direct route skipped the `/mcp` request checks and relayed a request
  whose routing headers disagreed with its body, that named a revision the operator turned off,
  or that was malformed. It now refuses each with the same code and status as `/mcp`, before
  any backend is reached.
  Affects: 4.0.0 pre-releases only; 3.x unaffected. Operator action: none; a client that sends
  mismatched, duplicated or unserved `Mcp-*` headers to the direct route now gets the `/mcp` error.
- **Fields of a redacted `gateway_invoke` answer stay matched across each other.** When
  the final firewall pass broke an invoke wrapper's print, the receipt was kept against
  the whole wrapper text, so a relay of two short fields joined together went undetected.
  The wrapper is now read field by field, so the run across fields the caller received
  intact stays receipted.
  Affects: 4.0.0 pre-releases only; 3.x unaffected. Operator action: none.
- A successful `cli` or `mcp` result no longer leaks an injected credential of 1 to 3 characters
  written in a number form such as `012`, `+12` or `1e5` when the child prints it as a JSON number:
  such a credential is now compared to numbers by value at any length. A very short credential may
  therefore blank equal numbers in tool output, such as every `12` for the credential `012`. A
  credential with no digit before its exponent, such as `e123` or only spaces, no longer blanks
  every `0` in the result.
  Affects: 4.0.0 pre-releases only; 3.x has no injected-value scrubbing. Operator action: none.
- **A relay of the middle of a long delivery can now be caught.**
  A receipt kept only the head and tail of a delivery over 6 KiB, so text from its middle was
  never evidence and a relay of it went unseen. The gateway now records a thinned sample of the
  cut middle, under the receiving caller's own records, so that caller stays excused for its own
  copy. The sample fits the existing 4,096-fingerprints-per-delivery bound: in a 64 KiB delivery
  a 500-char middle relay is missed about 1 in 100,000 times; in a 1 MiB delivery, 78% of the
  time (before, always). Design §14.3 B1′ has the table.
  Affects: deployments with relay detection enabled (`collusion.action` observe or block) in the
  4.0.0 pre-releases. Operator action: none; a relay of a large delivery's middle that used to
  pass is now refused (403 under block), see UPGRADING.
- **The direct route no longer forwards a client's `notifications/cancelled` to the backend.**
  The cancel named the client's request id, which the backend never saw, because each backend
  connection numbers its own requests. On a shared backend it could cancel another caller's
  call that happened to hold that number, and it reached the sender's own call only by
  coincidence. The route now accepts the cancel and drops it, so the backend call it named keeps
  running to completion; sending the cancel on to the caller's own call follows in a later change.
 
  Affects: 4.0.0 pre-releases and 3.x. Operator action: none; a backend no longer receives
  client cancellations through `POST /mcp/{name}`.
- The per-backend route `POST /mcp/{name}` no longer hands a backend's `requestState` to the client.
  As on `/mcp`, the gateway seals it into a continuation bound to the caller and to the call; a retry
  must present that continuation, once, and the backend then receives its own state. A state the
  gateway did not issue, one issued to another caller or call, a spent one, or answers with no state
  are refused with -32602 before the backend is called. On both routes, a state a backend puts on a
  completed or malformed answer no longer reaches the client; a completed answer carries no
  `requestState` at all. A continuation is bound as the caller's idempotency key is: a propagated
  backend credential first, then the verified identity. A question a gateway check refuses frees
  its slot at once, and a retry refused before the backend runs consumes no signing nonce.
  Affects: 4.0.0 pre-releases only; 3.x has no multi-round tool calls. Operator action: none.
- A caller that authenticates with an API key and has no verified identity now keeps multi-round tool
  calls on both `/mcp` and `/mcp/{name}`, bound to its key; before, `/mcp` refused them with -32003.
  Everyone holding one shared key counts as one caller, as for that key's sessions and tasks.
 
  Affects: 4.0.0 pre-releases only. Operator action: none.
- The per-backend route `POST /mcp/{name}` no longer puts a question to a client that did not declare
  it can answer it. As on `/mcp`, a backend's request for an elicitation (or an elicitation mode) or a
  sampling the request did not declare is refused with -32021 before anything is minted or cached,
  and the error's `data` names the capability or mode to declare. A legacy request declares nothing,
  so on this route it is refused rather than handed a question it cannot parse.
  Affects: 4.0.0 pre-releases only; 3.x has no multi-round tool calls. Operator action: none.
- **Operator npm settings reach stdio backends, and a backend's own setting always wins.**
  Six non-secret npm settings from the gateway's environment (`npm_config_allow_git`,
  `cafile`, `prefer_offline`, `offline`, `strict_ssl`, `loglevel`) are passed to every stdio
  backend; nothing else is, so a backend never inherits the gateway's registry credentials (it
  can still name one in its own `env:`). A backend that sets
  one of these itself keeps its value in any spelling npm reads as the same setting, including
  `npm_config_strict-ssl` and `NPM_CONFIG_ALLOW-GIT`, so an operator's `strict_ssl=false` or
  `allow_git=all` cannot override a backend that requires TLS checks or refuses git
  dependencies ([@terafin](https://github.com/terafin), [#1759](https://github.com/MikkoParkkola/mcp-gateway/pull/1759)).
  Affects: every stdio backend run with npm settings in the gateway's environment. Operator action: none; a backend that needs a different value for one of the six settings names it in its own `env:`.
- **Short fields from two plan steps, delivered side by side, are matched when relayed
  together.** A playbook or chain answer could place one step's short field next to
  another's; no receipt held the text across them, so another caller relaying the pair
  went undetected. Each delivery now records that text once, under a receipt naming every
  contributing source: it is sensitive when any of them is, and it may leave only by a
  flow every one of them allows.
  Affects: 4.0.0 pre-releases only; 3.x unaffected. Operator action: none.
- **Text one caller received from many sources stays under relay detection.** A fingerprint
  stopped being judged once nine (source, caller) records held it, so one caller querying nine
  tools that returned the same sensitive text switched detection off for that text, for every
  other caller, until it expired. Records now stay exact up to 64 per caller (a shared pool of
  65,536 bounds memory at 10 MiB), and a sensitive record that does not fit still counts as
  evidence. Text five callers share stays common, as before.
  Affects: 4.0.0 pre-releases only; 3.x has no relay detection. Operator action: none.
- **stdio runs the route checks `/mcp` runs.** A stdio `tools/call` now honours
  `security.sanitize_input` at intake, in `/mcp`'s order, and passes the request firewall
  before it is admitted: the content scan refuses with HTTP's codes before any task, key or
  lease is taken, and anomaly detection, the tenant guard and the call budget apply to stdio
  where configured, with all of one process's calls counted as one caller. The verdict-to-code
  wording is now one definition shared by `/mcp`, `/mcp/{name}`, stdio and the dispatch
  rescan. See upgrading.d/8149-1.md and upgrading.d/8149-2.md.
  Affects: every stdio deployment that has not set `security.sanitize_input: false` (it is
  on by default), and stdio deployments with any of the three firewall controls configured.
  Operator action: none unless a stdio client relies on sending NUL bytes or control
  characters (encode them, or set `sanitize_input: false`), or the firewall controls'
  thresholds were tuned for HTTP traffic only.
- **Input sanitization runs once, on the whole request, before any check reads it, on every route.** Before, `/mcp` and stdio sanitized after some checks had already read the request, the direct route sanitized only the tool arguments and ignored `security.sanitize_input`, and `passthrough: true` exempted a backend on the direct route alone. Now `/mcp`, `/mcp/{name}`, stdio and task submits sanitize method, params and `_meta` at intake. The request `id` and the signing and chain nonces are validated, never rewritten. A call whose every backend target is passthrough is forwarded as sent on every route; a tool the caller cannot see is judged as absent, so a NUL probe cannot tell the two apart.
  Affects: deployments with `passthrough: true` backends, and clients of `/mcp/{name}`.
  Operator action: none, unless a passthrough backend relied on `/mcp` or stdio stripping control characters.
- **Tool arguments sent as a JSON string are sanitized too.** The step decodes them, sanitizes the object and re-encodes it, so a NUL escaped inside the string is refused instead of appearing when the call decodes it. The idempotency key and `gateway_invoke`'s argument nonce are validated like the other protocol fields: a NUL or a control character in them is refused.
  Affects: clients that send `arguments` as a JSON string.
  Operator action: none.
- **A call exempted from sanitization is refused if its passthrough backend, or its playbook, changes before it runs.** Intake records the backend instance and the playbook definition it judged the exemption on; a config reload in between answers "The backend changed after this call was admitted; retry the call" or "The playbook changed after this call was admitted; retry the call", and nothing is sent.
  Affects: deployments that reload config while passthrough calls are in flight.
  Operator action: none; clients retry.
- **A keyed `/mcp/{name}` call from a caller with no verified execution principal is refused -32003, as on `/mcp`.** Before, the direct route accepted it under its idempotency cache alone.
  Affects: clients that send idempotency keys to `/mcp/{name}` with no verified identity.
  Operator action: none.
- **A backend tool called by its own name keeps the gateway's signature-chain link.**
  A surfaced tool, or a continuation retry naming the backend tool, was answered without the
  origin link even when the client asked for one or the gateway emits `always`, so a client
  checking the chain (OWASP ASI07) lost it on that entry form. Both now carry the same link and
  verified upstream links as the `gateway_invoke` call of the tool, on HTTP and stdio.
  Affects: 4.0.0 pre-releases only; 3.x unaffected. Operator action: none.
- **stdio confirms destructive task calls.** A modern task-augmented call of a destructive
  surfaced tool over stdio was admitted as a task with no confirmation. It now gets the same
  confirmation challenge as over HTTP, before any task is made, with the grant bound to the
  stdio process that asked. See upgrading.d/8160.md.
  Affects: stdio sessions with the task store open that call destructive surfaced tools as
  tasks.
  Operator action: none.
- A question a backend asked can now be answered only to that same backend object. After a live reload
  that replaces a backend under its name, a pending answer is refused with -32602 before any backend is
  reached, on `/mcp`, `/mcp/{name}` and paused chain steps, so the old backend's state and the user's
  answers never reach the replacement; the client asks again.
  Affects: 4.0.0 pre-releases only. Operator action: none.
- **The Windows OAuth login no longer goes through cmd.exe.** The gateway opened the
  authorization URL with `cmd /c start`, which split it at the first `&`: interactive login
  opened a truncated URL, and a hostile authorization server could put `&<command>` in its
  advertised authorization endpoint to run that command as the gateway's user. Windows now opens
  the URL with `rundll32 url.dll,FileProtocolHandler`, which hands it to the browser unparsed. On
  every platform only an `https` (or loopback `http`) URL reaches a browser launcher, the launcher
  no longer shares the gateway's stdin and stdout, and the "visit this URL" prompt is always shown,
  on stderr, in case the launch was blocked.
  Affects: interactive OAuth login on Windows in 3.x and the 4.0.0 pre-releases; macOS and Linux only gain the https check. Operator action: none; upgrade.
- **A task's grant decision is now in the transparency log before the task starts.** A signed
  task's preparation decision (and any decision a resuming `tasks/update` took) used to be written
  only when the request finished, after the task's worker had started, so under load the log
  could show the worker's execution decision before the decision that caused it. Now every
  decision the request has taken is appended, and the append has finished, before a worker is
  spawned: file order is cause before effect, and the record's `timestamp` stays informational.
  What you lose: under `FailClosed`, a task submission or input-round answer whose decision cannot
  be written is refused with -32005 and nothing starts, where it used to run and then answer
  -32005; a signed task waits for one append before it starts. What you gain: under `FailClosed`,
  no task runs whose cause is not on record (under `BestEffort` a failed write is logged and the
  task still runs, as before), and log readers can trust file order for one task's decisions. What you
  do: nothing. Affects: 4.0.0 pre-releases with the transparency log enabled. Operator action:
  none; a log reader that sorted one task's decisions by `timestamp` can read them in file order.
- **A token endpoint can no longer make the gateway refresh a backend's token on every call.**
  An OAuth token answer whose `expires_in` was larger than the gateway could add to the clock
  wrapped to an expiry in the past, so the token always looked expired and every call
  refreshed it (and a debug build panicked). An `expires_in` above 100 years is now refused as
  a malformed answer, with an error naming the token endpoint. Identity-propagation token
  exchange and personal-account token refresh apply the same rule: the exchange used to keep
  such a token until the end of time, and the refresh refused only a sum that overflowed.
  Affects: 3.x and 4.0.0 pre-releases. Operator action: none.
- **Every backend send is now checked once more just before it leaves, on the bytes it carries.**
  Playbook steps, `gateway_execute` chain steps, task workers, continuation retries and bridged
  input rounds used to reach a backend without a request-firewall scan of what they sent, and a
  `gateway_invoke` whose `arguments` came as a JSON string skipped the scan entirely. Now one
  dispatch chokepoint re-checks authorization and the firewall's pattern scan on the arguments
  as dispatched (a string is judged as the object it parses to) and on a retry's answers. What
  you lose: a step argument, retry answer or string-form argument carrying a blocked pattern is
  refused (-32600, "Firewall blocked: ...") where it used to be sent; retry answers that are not
  a JSON object are refused (-32602). What you gain: the firewall covers every send, not only
  the outer call. What you do: nothing, unless a playbook or chain relied on an unscanned
  pattern; then allow its tool with a firewall rule, or add the key to the free-text skip keys.
  Affects: 4.0.0 pre-releases. Operator action: review the firewall audit log's new `dispatch`
  rows (`source`: invoke, step, retry or bridged) after upgrading.
- **The firewall audit log no longer records what a scan matched.** Every audit row used to carry
  each finding's `matched` excerpt (up to 200 characters of a request argument or a backend
  response) and a description naming the argument's key, despite the log's promise that raw values
  are never logged. A row now holds each finding as its `scan_type`, `severity` and `location`
  only, and every row carries `"schema_version": 3`. What you lose: the excerpt and the key name in
  the audit log; the client-facing refusal and in-process logs are unchanged. What you gain: an
  audit log that holds no request or response content. What you do: a log parser reading
  `findings[].matched` or `findings[].description` switches to the three kept fields.
  Affects: 3.x and 4.0.0 pre-releases with the firewall audit log enabled. Operator action: treat
  firewall audit logs written before this release as sensitive; rows without `"schema_version": 3`
  may contain request or response fragments and argument key names.
- **OIDC discovery and JWKS fetches no longer follow a redirect to another origin.** The gateway
  fetches an issuer's discovery document and its signing keys (JWKS) to verify `key_server.oidc`
  tokens and Cloudflare Access assertions. An `https://` fetch followed a redirect to any HTTPS
  host, so whoever controlled a redirect at the issuer could hand the gateway signing keys from
  anywhere. A redirect must now stay on the origin (scheme, host and port) of the URL fetched; any
  other is refused, and the token fails to verify. A same-origin redirect is still followed, and a
  loopback fetch still follows none. See upgrading.d/8281.md.
  Affects: 3.x and the 4.0.0 pre-releases with `key_server.oidc` or Cloudflare Access configured.
  Operator action: none unless a `key_server.oidc` issuer serves discovery or keys through a
  redirect to another origin; then set its `jwks_uri` to the URL the keys are served from.
- **An identity that names no one is refused, never shared.** A client certificate with neither
  a SAN URI nor a CN was served as the shared subject `mtls:<unknown>`, so every such caller
  shared idempotency keys, cached results, per-caller processes and grants. An OIDC token with
  an empty `sub` likewise made every such user at one issuer one caller. Such a certificate is
  now refused with HTTP 401 before anything runs, an empty `sub` is refused as an invalid token
  on every path including public ones, and a stored token whose identity names no one is
  refused when read back. See UPGRADING-4.0.
  Affects: 3.x and 4.0.0 pre-releases with mTLS client certificates that carry no CN or SAN URI, or an identity provider that issues an empty `sub`. Operator action: issue such clients a certificate with a CN or a SAN URI; remove any grant whose subject is `<unknown>`; otherwise none.
- **One caller can no longer fill the continuation pool.** The table of open questions and
  confirmations (4,096 per replica) was shared with no per-caller bound, so one caller could
  hold every slot for up to five minutes and refuse every other caller's questions and
  confirmations. Each caller now holds at most 64; its 65th is refused exactly as a full pool
  refuses, and nothing it already holds is evicted. A caller is its credential, verified
  identity, trusted subject or stdio process, the same whether it calls live, through a task,
  or on any backend.
  Affects: multi-user gateways on 4.0.0 pre-releases. Operator action: none.
- **A deny or allow rule its section cannot match is refused at load, not kept as a rule that
  matches nothing.** In `security.tool_policy`, `auth.api_keys[].allowed_tools`/`denied_tools`
  and `key_server.policies[].scopes.tools` only a trailing `*` is a wildcard, so a rule such as
  `*_delete` loaded and denied nothing. Backend lists and agent scope segments match an exact
  name or `*` alone. Each such entry, and a backend name containing `*`, now stops start-up and
  hot reload with a one-line error naming the entry, why it matches nothing, and what to write
  instead. No matcher matches more than before. See upgrading.d/8298.md.
  Affects: every 3.x and 4.0.0 pre-release configuration with such a pattern in those sections.
  Operator action: replace each refused entry with the exact names, or with the replacement the
  error gives.
- **A misspelt action in an agent scope no longer grants every action.** In
  `agent_auth.agents[].scopes` (`tools:<backend>:<tool>:<action>`), an action other than `read`,
  `write`, `execute` or `*` was read as `*`, so `tools:gh:search:reed` granted read, write and
  execute. The scope parser now reads it as granting nothing, and config load refuses it, along
  with a scope that lacks the `tools:` prefix (which granted nothing).
  Affects: deployments with `agent_auth` whose agent scopes carry a misspelt action, and code that
  registers agents through the library with such scopes.
  Operator action: correct the action to `read`, `write`, `execute` or `*`; the error names the
  entry.
- **A task submit is authorized like the call it would run.** A task-augmented `tools/call` of a
  personal capability the caller holds no identity grant for, or of an admin capability by a
  non-admin, used to be admitted: the caller got a task handle, the gateway stored a task record
  and took the idempotency key, and the refusal arrived only as the task's terminal error. The
  submit now runs the same authorization as the synchronous call, before any task or key exists,
  and answers with the same status, code and message. A grant revoked after submit is still
  refused when the task runs. See UPGRADING-4.0.
  Affects: 4.0.0 pre-releases with MCP tasks and personal capabilities or admin capabilities. Operator action: none.
- **A backend's OAuth discovery only uses resource metadata that names that backend.** The
  gateway took the authorization server, the scopes and the RFC 8707 token audience from the
  origin's `/.well-known/oauth-protected-resource` document without checking which resource it
  described. For an MCP endpoint at `https://host/mcp`, servers such as Linear and Notion publish
  an origin document naming `https://host`, so tokens were requested for the origin, not the
  endpoint, and on a shared origin another resource's authorization server could be adopted.
  Discovery now reads the `resource_metadata` URL a 401 names, then the RFC 9728 path-inserted
  URL, then the origin's, and refuses any document whose `resource` is not the configured backend
  URL (RFC 9728 §3.3). Every discovery URL is held to the destination policy, and the first
  request does not follow redirects. See upgrading.d/8320.md.
  Affects: deployments with gateway-level OAuth (`backends.<name>.oauth`) on a backend whose URL
  has a path.
  Operator action: none when the server publishes metadata for its endpoint (Linear, Notion, exa
  and kapa.ai do); otherwise the error names the document, the resource it names and the
  backend URL, and the backend URL should be set to the resource the server's metadata names.
- **A playbook never hands the gateway's continuation envelope to another backend.**
  A playbook step could pass an earlier step's `requestState` (the sealed envelope the gateway
  minted for its own client) to another backend, by naming it, through a whole-step reference,
  inside text, or through the caller's own inputs. That backend could keep it and return it
  later. A step argument that names a step's `requestState` now refuses the playbook (it is
  skipped when loaded from a directory), and a step whose resolved arguments carry an envelope
  this gateway sealed is refused before it is dispatched. A playbook's output still hands the
  envelope to its own client. If the clock cannot be read, a step that might carry one is
  refused rather than let through. A JSON path ending in an unclosed `[` (`a[`) in a playbook
  reference or a transform no longer panics; it reads as the key alone. See UPGRADING-4.0.
 
  Affects: 4.0.0 pre-releases only; 3.x unaffected. Operator action: rewrite any playbook whose
  step argument names `requestState`; library users implementing `ToolInvoker` add
  `sealed_state_in`.
- **A backend's follow-up question that the content gate blocks ends the call.** With context integrity enforcing, a stripped or summarized follow-up question kept a resume handle with its questions removed, and a task resumed the backend with no answer from the client. Such a question now ends the call with the gate's refusal, -32600 "Response blocked by security firewall", on every route; a playbook step is not retried after it. See UPGRADING-4.0.
  Affects: 4.0.0 pre-releases with context integrity in enforce mode and backends that ask follow-up questions. Operator action: none.
- **A withheld surfaced tool no longer reveals itself through the confirmation gate.** A
  modern task call of a destructive surfaced tool the caller may not invoke got the
  destructive-task confirmation answer, which told the caller the tool exists and is
  destructive. It now answers exactly as a name that matches no tool (`-32601`, with the same
  HTTP status), on `/mcp` and stdio, before the firewall, the confirmation gate or admission
  runs; the refusal is still logged for operators.
  Affects: deployments that surface tools and restrict who may invoke them.
  Operator action: none.
- **A surfaced tool withheld from a caller now answers as a missing name everywhere.** A
  surfaced tool the caller may not see (it may not invoke it, its input schema is invalid, or
  its description failed the tool-poisoning check) still showed through on some paths: a task
  call, a chained task, a continuation, the meta direct route, listings and search. Every path
  now answers exactly as a name that matches no tool (the same code, message and HTTP
  status), keeps no idempotency key and gives the signing nonce back, on `/mcp` and stdio.
  One record per refused call stays in the operator log. Not yet covered: a schema invalid
  only in one user's per-user catalogue is judged on the shared catalogue for calls by name
 .
  Affects: deployments that surface tools and restrict who may invoke them.
  Operator action: none; see the upgrade note on audit under `FailClosed`.
- **The per-backend route `/mcp/{name}` re-checks every `tools/call` at dispatch, as `/mcp`
  does.** Target authorization and the request firewall run again on the bytes about to be
  sent, so a retry whose answers (`inputResponses`) the firewall blocks is refused (-32600)
  instead of reaching the backend. `arguments` sent as a JSON string are scanned and sent as
  the object they parse to: string-form arguments on `/mcp/{name}` are now
  schema-validated like object arguments, closing a validation bypass, and a string that is
  not an object is refused -32602. A `tools/call`
  spelled in another letter case is refused -32601 instead of forwarded. See
  upgrading.d/8351.md.
  Affects: clients and backends using `/mcp/{name}`.
  Operator action: none, unless a backend expects string-form `arguments`, a client relied on
  string-form `arguments` skipping schema validation, or a client sends
  `tools/call` in another letter case.
- **A signed `gateway_invoke` refused after a step that may have acted keeps its nonce spent.**
  Three refusals on the invoke path (the spend budget, a refused input-required retry, and the request
  firewall on a retry's answers) gave the signing nonce back even when the refused call had already minted
  or refreshed a credential, fetched the backend's tool list, or consumed its continuation. The same signed
  request could then be sent again. A refusal now gives the nonce back only when nothing the call did can
  have acted; otherwise the nonce stays spent. A propagated or account credential counts as having acted
  whenever one is resolved, even from a cache. A tool-list fill admitted on the backend while the call's
  schema check runs counts, even one started for another call.
 
  Affects: 4.0.0 pre-releases only. Operator action: none.
- **A per-user backend answers from each caller's own catalogue.** On a backend with identity
  propagation, a tool call and the name-only listings judged a tool by the shared catalogue, so
  a call could dispatch a tool the caller's own catalogue withholds, and the answers and counts
  could confirm which tools another user's catalogue has. A call is now judged by the caller's
  own catalogue on every entry (`/mcp`, stdio, `/mcp/{name}`, `gateway_invoke` and chain steps):
  a tool it withholds or does not list answers -32601, as an unknown name, whatever
  `input_schema_enforcement` says, and confirmation, admission and task routing see that answer
  first. The disabled list, predictions, counts (the `initialize` greeting included),
  `gateway_list_servers`, spec-preview names and `tools/resolve` omit the backend's tools until
  the caller's own catalogue has been read, and re-check a rotated or revoked managed grant
  first. See `upgrading.d/8356.md`.
  Affects: the 4.0.0 pre-releases with identity propagation configured. Operator action: none.
- **A tool the caller may not see answers exactly as a tool that does not exist.** A call to a tool hidden from the caller (by its tool policy or key scope, its routing profile, an invalid input schema, a description that failed the poisoning check, or, for a capability, the admin rule or a missing grant) used to get a refusal naming why, which let a caller probe which tools exist. It now gets the answer a missing name gets, on `/mcp`, stdio and `/mcp/{name}`, and is never sent to the backend. One exception is kept: an exact replay of an idempotency key gets the step's current refusal, since its caller held the step before; a key reused with other arguments answers as for a missing step.
  Affects: clients and operators who read refusal reasons from the client's answer.
  Operator action: read refusal reasons in the audit log; see UPGRADING.
- **A playbook's steps now pass the request firewall at the route, as direct calls do.**
  `gateway_run_playbook` named no backend target before its steps ran, so the stateful
  firewall controls (call budget, anomaly scoring, tenant guard, request audit row) never saw
  them; only the stateless content rescan at dispatch did. The route now takes the playbook's
  declared steps as targets, authorizes every target before scanning any, and refuses the
  whole call before a step runs. A refused step answers `-32003 step not permitted for this
  caller` and names nothing operator-defined: authorization and content-scan refusals of a
  step are neutral, while budget, tenant and anomaly refusals keep their count-only wording. A multi-target `gateway_execute` chain whose
  last target is refused no longer charges the earlier targets. The budget counts declared
  steps, including steps a `condition` will skip, and an engine retry is not charged again.
  A call refused by a later step's budget, tenant or anomaly check has already charged the
  earlier steps' budget. A blocked pattern written into a step's own arguments is refused at
  the route with the same neutral answer.
 
  Affects: deployments that run playbooks with the request firewall enabled (content
  scanning, call budget, anomaly scoring or tenant guard).
  Operator action: none. A playbook with more declared steps than the remaining call budget is
  now refused whole instead of running until the budget is spent.
- **The transparency-log HMAC key is resolved from `${VAR}`, `env:` and `file:` references.**
  Before, a reference reached the key as its own text, so every entry was signed with a string
  anyone reading the config knows. While the log is on, a key that does not resolve, or a key under
  32 bytes or all zero bytes, literal or resolved, now refuses the load, naming the field; with the log off, `audit verify` refuses
  instead of verifying with an empty key or the reference text.
  Affects: every release with `security.transparency_log.shared_secret` written as a reference.
  Operator action: see the upgrade note; generate a key with `openssl rand -base64 48`.
- **SIEM export refuses a signed audit-log entry it holds no key for.** With
  `security.transparency_log.shared_secret` empty, export checked a signed log's hash chain only, so
  a re-chained forgery reached the SIEM while `audit verify` refused the same log. Export now halts at
  the first signed entry, with a message naming `shared_secret`; unsigned entries still export, and a
  configured key is checked as before. Both use one rule for what counts as signed.
  Affects: deployments with SIEM export on, an empty key, and a log that holds signed entries.
  Operator action: set the key the pending entries were signed with and restart; export resumes at
  the halted entry. See the upgrade note.
- **A config that will not load no longer prints the value it refused.** A wrongly typed value (a token where a number goes, `!!int` on a secret, a bad or over-long duration, an env override of the wrong type) was quoted in the load error on stderr, in `doctor`, and in the log line of a refused reload. A config that fails to parse or to match its expected types now reports the key, the file, the line and column where known, and the type expected, never the value; this covers the gateway's own field parsers (durations, `known_agents`) too. `doctor`'s suggested fix for such a config is now `mcp-gateway doctor --config <file>`; it named `validate`, which never loads the gateway config.
  Affects: anyone whose config error output reaches logs, CI or a terminal recording.
  Operator action: none.
- **A control character can no longer rename a key the gateway reads.** Input sanitizing
  stripped control characters from those keys, so `ser\u0007ver` became `server` and
  `_fu\u0007ll` became the `_full` directive. On `/mcp` and stdio such a key is now refused with
  `-32600`, and nothing is dispatched. This covers a meta tool's own argument keys (an object
  or a JSON string), each `gateway_execute` chain step's keys, `gateway_invoke`'s `_meta` keys,
  and, in every tool-arguments slot the gateway reads directives from (`gateway_invoke`'s and
  `gateway_execute`'s inner arguments, each chain step's, a surfaced tool's), a key that cleans
  to `_full` or `_claim`. Passthrough calls and resumed tasks are checked the same way. Other
  keys in tool arguments are the tool's data and keep today's stripping; `/mcp/{name}` is
  unchanged.
  Affects: clients that send control characters inside keys the gateway reads.
  Operator action: none; see the upgrade note.
- **The direct route (`/mcp/{name}`) gives a signing nonce back only when nothing the refused call did can have acted, as `/mcp` does.**
  The direct route gave the nonce back on every refusal before dispatch, including after the call had minted or
  refreshed a credential, filled the backend's tool list, or consumed its continuation, so the same signed request
  could be re-sent. It now follows `/mcp`'s rule, and on both routes a mint that was attempted and failed
  on a backend with optional identity propagation also counts as having acted.
  Affects: 4.0.0 pre-releases only. Operator action: none.
- **A stored task result is handed out only while its caller could still make the call.**
  `tasks/get`, the task-status frame and stdio `tasks/get` delivered a finished task's
  stored output after the caller lost access to its tool: a revoked or reconnect-pending
  personal account, a per-user catalogue or listing that no longer offers the tool, a
  descriptor block, or a withdrawn grant. Each read now judges every recorded target as a
  live call by the same caller would: a withheld tool or a revoked account answers `-32601`
  (as an absent tool name), a policy refusal keeps its live error, and a caller whose account
  can never bind gets the live call's own refusal. While a per-user view is being
  re-established after an idle eviction, a read answers a retryable `-32603` with
  `data.retryable` and `data.retry_after_ms`, and one reader resolves for everyone.
  A frame carries status only when the output is withheld.
  Affects: tasks API clients on per-user or managed-account backends. Operator action: none.
- **A live call whose managed account's custody is busy answers as a task read does.**
  It used to get a non-retryable answer, `-32601` by tool name or `-32603` with no
  retry data by backend name; it now gets
  JSON-RPC `-32603` with `data.retryable: true`, the same answer a task read gets in
  the same state, and one `idp_refuse` audit record per call names the transient busy
  custody, whether the busy custody is met at the view read or at the mint, on a per-user
  backend or a REST capability account. Client action: retry the `-32603` after a short
  backoff. A task-augmented
  call gets the same answer at once, with no task created and no idempotency key held;
  a kill-switched, disabled or otherwise policy-refused target keeps its refusal on a
  `gateway_invoke`, a surfaced tool name, or a keyed `gateway_execute` or playbook call
  (an unkeyed task call is refused for its missing idempotency key first).
 
  Affects: tasks API and tool-call clients of managed-account backends. Operator action:
  none; see upgrading.d/8392.md.
- **Provenance receipts can carry a publicly verifiable Ed25519 signature.**
  When `GATEWAY_PROVENANCE_SIGNING_SEED` and `GATEWAY_PROVENANCE_KEY_ID` are set, stamping adds `public_signature` beside the HMAC, exported with `mcp-gateway provenance public-key` and checked with `mcp-gateway provenance verify` without any gateway secret. Step receipts in chain and playbook answers carry the public signature. Byte-identical output holds only with provenance stamping off; with stamping on and no seed, the receipt sits in `result._meta.provenance` with no `public_signature`. See UPGRADING-4.0. (#8398)
  Affects: 4.0.0 pre-releases only; 3.x unaffected. Operator action: optional; to enable, set the seed (base64 of 32 random bytes) and key id, restart, and publish the JWK.
- **A plan's stored answer read again now renews the reader's relay receipts.**
  With relay detection on, a task re-read of a completed plan (`gateway_execute`
  chain or `gateway_run_playbook`), or a keyed synchronous replay of one over HTTP
  or stdio, delivers the stored text again but renewed no receipt. Once the
  detector's window (600 s) had passed, another principal could relay that text
  unseen, and the reader's own copy carried no excuse. Single-target re-reads
  already renewed. Now each step's receipt is renewed under its own source,
  exactly as the live delivery recorded it, and only for text the replay actually
  delivers: the gateway's own text, a redacted step and an unauthorized replay
  renew nothing.
  Limits, each failing toward a missed renewal, never an undue excuse: with no
  stored replay entry (a plan read after a gateway restart, an entry evicted
  under the 32 MiB replay budget or over the 1 MiB entry cap, a plan delivered
  while relay detection was off), nothing renews per step, and the seams of a
  plan with a nested step never renew. Without an entry, a keyed synchronous
  replay and a task re-read of a plan run on several targets renew nothing; a
  task re-read of a plan whose steps all ran on one server and tool still renews
  one receipt over the whole stored answer under that tool, as before this
  change.
  Effective ceiling: a keyed sync replay serves at most 512 KiB (fixed) and a task
  re-read at most `tasks.max_record_bytes` (default 512 KiB), so at default
  settings no replayed plan answer exceeds 512 KiB. The 1 MiB entry cap is a
  separate bound on the stored entry's counted size (fingerprint and text bytes
  plus a per-item estimate), which can exceed the answer's own size: a plan
  answer of many small segments can reach it at default settings, and its entry
  is then not stored (counted `too_large`).
  The replay budget counts fingerprint and text bytes plus a per-item estimate,
  so actual memory use can run somewhat above 32 MiB.
  Affects: deployments with relay detection on. Nothing new is stored on disk;
  the task record format is unchanged.
  Operator action: none required. With relay detection on, an operator sees
  relays of re-read plan text refused where they were let through before, and
  the new counters `mcp_gateway_collusion_plan_replay_skipped_total` (by reason)
  and `mcp_gateway_collusion_plan_replay_evicted_total` on the metrics endpoint.
- **YAML errors no longer print the value that caused them.** Outside the config
  loader (capability files, grants, skills, imports, CLI readers) a type, value or
  variant error used to quote the offending value, often a secret typed into the
  wrong field (CWE-532). It now keeps the key path, the expected type and
  line/column, as the config loader already does: a wrong enum value reads
  `unknown variant, expected ...`, and a too-long duration the gateway writes reads
  `this duration is longer than 100 years, ...`.
  Affects: anyone reading YAML errors in logs or scripts.
  Operator action: none; scripts matching the old wording see UPGRADING.
- **rustls is upgraded to 0.23.46, fixing four TLS advisories.** RUSTSEC-2026-0346
  (`Debug` output of client session values could include TLS secrets), RUSTSEC-2026-0347
  (data buffered before the handshake was sent after an Encrypted Client Hello
  rejection), RUSTSEC-2026-0348 (Brotli certificate decompression could allocate up to
  1 GiB before authentication) and RUSTSEC-2026-0349 (an unauthenticated ServerHello
  could make later connections offer only a classical key exchange). For the gateway,
  0347 and 0348 are unreachable: it configures no Encrypted Client Hello and builds
  rustls without Brotli certificate decompression. The 0346 fix is defence in depth:
  the gateway's own code does not format rustls client session values (its direct
  rustls use is the mTLS server configuration; outbound TLS runs inside reqwest and
  tokio-tungstenite, and reqwest's `Debug` output carries no TLS session data). The
  0349 fix is protective: later connections keep offering the hybrid post-quantum key
  exchange.
  Affects: every gateway build with TLS (inbound HTTPS, mTLS and outbound HTTPS).
  Operator action: none; upgrade to this release.
- **A stored result is no longer replayed when the request would dispatch under a
  different account or forwarded credential.** Every keyed call, task and plan now
  records the binding each backend call ran under: the account (its descriptor id
  with a fingerprint of the whole declared descriptor), or on the direct route
  `/mcp/{backend}` the forwarded passthrough credential. A keyed retry, a repeated
  task call or a task read is served the stored output only while each recorded
  binding is still the one the call would use now. Otherwise it is refused with
  -32603 and nothing is sent, so the key keeps its one execution. This closes two
  cases. A retry of a keyed direct-route call that forwards a different passthrough
  credential was served the output stored for the first credential; under one shared
  API key, the two credentials may belong to two people. Output produced
  under an account that was later revoked was served after the backend or capability
  was re-bound to another, live account. A task row written before this
  release carries no recorded binding, so its stored backend output is refused, with
  the row and its key kept.
  Affects: keyed calls on passthrough backends; deployments that re-bind a backend's
  `account:` (across a restart) or a capability's `auth.account` (on reload); task
  rows written by a 4.0 beta.
  Operator action: none to upgrade. Rolling back past this release requires clearing the task store first (see the upgrade note).
- **Identity grants for `api_key:<name>` now match only an authenticated API key of that name.** An identity grant written for `api_key:<name>` no longer matches the static bearer (`bearer`), the dashboard session (`dashboard`), the auth-off caller (`anonymous`) or the public-path caller (`public`), and a `key_server.oidc` provider whose `issuer` is a reserved grant authority (`mtls`, `agent_oauth` or `api_key`) is refused at load. (#3950)
  Affects: gateways with identity grants whose subject authority is `api_key`, and gateways whose `key_server.oidc` names a reserved issuer. Operator action: give each affected caller a named API key in `auth.api_keys` that the grant names, turning auth on where it is off, and point any reserved `issuer` at the provider's real https issuer URL.
- **TLS refuses the distrusted emSign intermediates.** `rustls-webpki` 0.103.16 (RUSTSEC-2026-0382) carries its own list of the distrusted emSign intermediates and refuses any chain through one of them. It checks certificate chains for WebSocket backends and, on Linux, for HTTPS backends, whatever trust store anchors them. The Mozilla root set bundled for WebSocket backends, `webpki-roots`, is updated to 1.0.10 (RUSTSEC-2026-0381), and `webpki-root-certs` to 1.0.10 (RUSTSEC-2026-0383; native builds do not link it). On macOS and Windows, HTTPS backends are verified by the operating system, which follows its own distrust list. (#8577)
  Affects: 2.0.0 up to 3.5.1 and the 4.0.0 pre-releases. Operator action: none for a backend with a publicly trusted certificate from another authority. A WebSocket backend, or an HTTPS backend on a Linux host, whose certificate chains through one of the distrusted emSign intermediates now fails its TLS handshake and needs a certificate from another authority; on macOS and Windows, an HTTPS backend with such a chain keeps connecting until the operating system's own distrust list includes it.
- **YAML text is now checked before it is parsed.** Configuration, capability,
  skill, trust-card, protocol-import, Kubernetes manifest and admin-UI YAML is
  refused in milliseconds when it nests past 128 levels, expands aliases past
  64 MiB, floods `%TAG` directives, or uses tricks the two parsers read
  differently (anchor names outside `[A-Za-z0-9_-]`, a reused anchor name, raw
  U+0085/U+2028/U+2029 line breaks, an unclosed quoted value, a quoted
  continuation indented no more than its key). Such input used to reach the
  parser, where it could take minutes or gigabytes. Behaviour change: a quoted
  continuation at its key's indent loaded before and is now refused; close the
  quote, indent the continuation lines, or use a block scalar (`|` or `>`).
  Overhead is under 0.1 ms on shipped
  configuration and capability files, linear in size (about 40 ns per byte).
  See upgrading.d/8639.md.
  Affects: every YAML read on the paths above.
  Operator action: none, unless a file uses anchors with names outside
  [A-Za-z0-9_-], reuses an anchor name within one document, contains raw
  U+0085/U+2028/U+2029, leaves a quoted value unclosed, or indents a quoted
  continuation no more than its key; then rename or remove them, or close the
  quote, indent the continuations more than their key, or use a block scalar.
- **Token exchange no longer follows a redirect from the token endpoint.** The RFC 8693 token-exchange client followed reqwest's default redirects, so a token endpoint answering 307 or 308 had the exchange form, `subject_token` included, posted again to wherever it pointed. The exchange now fails and names the redirect. Capability discovery likewise reports a redirect into a private address as an SSRF refusal instead of silently finding nothing. See UPGRADING-4.0.
  Affects: 3.1.0 and later with `identity_propagation` token exchange configured. Operator action: point `token_exchange_endpoint` at the final URL if your token endpoint redirects; otherwise none.
- **The OAuth callback checks `state` before it ends a login.** Any request that reached the
  loopback callback port during a login (another local process, or a web page that made the
  browser load `http://127.0.0.1:<port>/callback?error=x`) could end the login with an error
  and description of its choosing, because the provider-error branch ran before `state` was
  compared, and a wrong `state` also ended the login. A request whose `state` is missing or
  wrong is now refused with HTTP 400 and the login keeps waiting for the real redirect; the
  comparison is constant-time, and the mismatch log records only whether `state` was present
  and its length, never its value. (#8674)
  Affects: 3.x and 4.0.0 pre-releases, any backend that logs in through the interactive OAuth callback. Operator action: none; a provider that returns an error without `state` (against RFC 6749 §4.1.2.1) now leaves the login waiting until its 300 s window or cancellation instead of failing at once.
- **`gateway_search` glob matching is bounded.** A query with many `*` wildcards made the matcher's work grow combinatorially (40 stars against an 11-character tool name took about 250 billion steps per tool, from one request), which could hold the gateway's worker threads. The matcher also recursed once per `*`, so a long enough run of stars could overflow a worker thread's stack, which aborts the whole gateway process. The matcher is now iterative and takes at most (n+1)(m+1)+m steps for an n-character name and an m-character pattern. `gateway_search` also refuses a query longer than 256 characters with JSON-RPC error -32602, without echoing the query. (#8683)
  Affects: every release with Code Mode's `gateway_search` up to the 4.0.0 pre-releases; any caller allowed to call `gateway_search` could trigger it. Operator action: none. A client that sends a `gateway_search` query over 256 characters now gets -32602 and must shorten it.
- **The OpenAPI import preview no longer crashes the gateway on a brace-reversed line.** The UI's
  import preview sliced between the first `{` and the first `}` of a generated capability line, so a
  spec with a field or path such as `a}b{c}` (pasted, or fetched from a URL the admin gave) panicked,
  and a release build aborts on a panic: one request stopped the whole gateway. Such a line is now
  skipped. A new CI guard refuses a new `unwrap`/`expect`/panic-family call in request-path code
  unless it carries an `// invariant:` comment.
  Affects: 2.10.0 and later, including every 3.x release (an admin-authenticated UI request, or a spec URL it names). Operator action: none; until upgraded, import only specs you trust.
- **Audit, event and delivery records no longer carry a credential's stored principal.** Every record field
  that named a credential (`who.principal`, a credential `caller_key`, the events `principal` and
  `who.account` fallbacks, the settlement `who.account`, the firewall `caller` of an event payload and a
  watch poll's session name) now holds a keyed digest: 12 hex of an HMAC under a key only the gateway holds,
  or `credential:rp:<12 hex>` for an owner. Before, a record carried the same digest the credential store
  keeps, so anyone holding a leaked audit log, event stream or delivery record could match it to a
  credential. The key is created on first start as `<data dir>/record-principal.key`; with several
  replicas each pod keys its own records unless `security.record_principal_key` names a shared secret.
  Event subscriptions get the same treatment: the handle a subscriber sees (the subscribe answer, the
  `x-mcp-subscription-id` header, new `eventId`s, event records and the admin dead-letter listing's
  `subscriptionAlias`) is a keyed alias, never the stored subscription id.
  Affects: every 3.x release and the 4.0.0 betas. Operator action: update SIEM and log queries that matched
  the old principal or `credential:<p>` forms, back up `record-principal.key` with the data directory, and
  read `subscriptionAlias` in admin scripts; event subscribers learn the new handle from the next delivery
  (upgrading.d/8697.md).
- **The HMAC verifications no longer rely on a constant-time helper with a known branch.** `ctutils`, which
  `hmac` and `sha2` use for their constant-time comparisons, moves from 0.4.2 to 0.4.5 (RUSTSEC-2026-0385).
  In 0.4.2 its mask generation could compile to a branch on secret data. The gateway reaches it when it
  verifies an attestation token's signature on a boundary call, a receipt signature, and a signed
  transparency-log entry. A branch like this is a timing side channel in principle; over a network it is far
  below normal jitter, and no exploit is known. The advisory's `u128` part affects 32-bit targets only, and
  every published build is 64-bit.
  Affects: 2.10.0 and later, including every 3.x release and the 4.0.0 betas (every release whose lock
  carries `ctutils`). Operator action: none; upgrade.
- **tokio 1.53.3 (RUSTSEC-2026-0386).** The lockfile moves tokio from 1.53.1 to 1.53.3, which deprecates `AsyncFd`'s safe constructors: they accepted any raw file descriptor, which can break I/O safety. The gateway does not call them. The RUSTSEC-2026-0381 ignores are removed from `.github/osv-scanner.toml` and `.cargo/audit.toml`, because that advisory now treats the locked `webpki-roots` versions as fixed. (#8768)
  Affects: releases that lock an affected tokio, including 3.5.1 and the 4.0.0 pre-releases (tokio 1.53.1); no gateway code path calls the affected constructors. Operator action: none.
- **The `-full` image's npm carries undici 6.29.1 (CVE-2026-109869).** The image pins the packages it vendors into npm's tree, and its `undici` pin moves from 6.29.0 to 6.29.1, which fixes a denial of service via an unhandled stream error on excessive content. The copy sits inside npm's own tree (`/usr/lib/node_modules/npm/node_modules/undici`). npm reaches it for its own network traffic: registry fetches, such as `npx` fetching a stdio backend's package, and the downloads of Node headers and checksums by npm's bundled `node-gyp`. The gateway itself never loads it. The default image carries no Node.js and is not affected.
  Affects: the `-full` image of every 4.0.0 pre-release that ships one. 4.0.0-beta.2 carries the undici 6.27.0 that npm 12.0.2 bundles; 4.0.0-beta.3 and later carry the pinned 6.29.0. Both are inside the advisory's range. Operator action: pull the next `-full` image; no config change.
- **A credential beside the gateway's own continuation token is redacted again.** Inside JSON text, the egress redactor keeps a value that is the gateway's own continuation token. It did so by dropping every credential match that touched that value. A connection-string match runs to the next whitespace, so in compact JSON such as a `dsn` value followed directly by a `next` continuation, the match crossed the continuation and was dropped whole. The connection string, password included, reached the client. Now only the continuation's own bytes are left out of the match, so the credential beside it is redacted and the continuation still arrives byte for byte. A pattern is reported only where it still redacts something.
  Affects: the 4.0.0 release line since #4110; no published release, 3.x and 4.0.0-beta.1 to beta.3 unaffected. Operator action: none.
- **Backend upstream events on identity-bound backends are observed per subscriber.** A backend reached with a propagated identity (`signed_assertion`, `token_exchange`, `passthrough`) or a managed or external account used to refuse `backend.<name>` resource and prompt events (`-32014 identity_propagation`), because one shared listener would have observed under the gateway's credential and could have sent one user's changes to another. Each subscriber now gets a listener of their own: every request it sends carries that subscriber's credential (minted through the audited path, or their own passthrough token) and none of the gateway's, and each change reaches only the subscribers it was observed for. Queued deliveries made under a different grant, identity configuration or lease are buried, never sent. A passthrough token is held in memory only, zeroized on every end of its subscription, and only where core dumps can be disabled.
  Affects: 4.0.0 pre-releases with MCP Events on a backend with `identity_propagation` or a `personal_managed` / `external` account; such subscriptions were refused there, so nothing was exposed. Operator action: none for most backends; on a `passthrough` backend, subscribers send `events/lease`, and the host should run encrypted swap or none (`doctor` warns).
- **A replaced, wiped or expired passthrough lease no longer lets events read under it through.** When a subscriber replaced their `events/lease` token, for instance with one granting less, the listener kept reading on the session it had opened with the old token, and what it read was stamped and delivered as observed under the new one. A lease being wiped, and one past its deadline, also still counted as held until its drain or the next sweep finished. A replace or a wipe now ends the listener's session and reopens it under the token held then; every event carries the lease it was read under, and delivery refuses one whose lease is no longer held. A lease stops counting at its deadline.
  Affects: no released version; the passthrough lease is new in this release. Operator action: none.
- **The `-full` image trusts only the pinned NodeSource key.** The image installs Node.js from NodeSource's apt repository through a key file it downloads at build time, and checks that file against a pinned fingerprint. That check had two gaps. It matched the fingerprint against any key record, so a file whose one primary key was some other key, carrying NodeSource's key as a subkey, passed. And apt trusted every key in the file, including a primary key with no user ID, which `gpg --show-keys` does not list. The check now requires exactly one primary key whose own fingerprint is the pin, and apt's `Signed-By` names that fingerprint, so apt selects that key and its subkeys alone. Exploiting either gap needed control of the HTTPS key download at build time.
  Affects: the `-full` image of 4.0.0-beta.1, beta.2 and beta.3, as built; a published image is affected only if its build fetched a substituted key file. Operator action: none; the next `-full` image carries the fix.
- **Sign-in links and provider error text stay out of the log.** The authorization link a login logs now keeps only the provider's host and path, never its `state`, PKCE challenge or other query values. A provider's `error_description` on a refused sign-in is neither logged nor carried in the login's error; only its RFC 6749 error code is.
  Affects: every OAuth backend login.
  Operator action: none.
- **`mcp-gateway cap discover --write-config` no longer copies secrets into the config file.**
  A literal env or header value found in another app's MCP config now goes to the secret store
  (`secrets.store`), and gateway.yaml holds only its reference. A `${NAME}` template and an empty
  value are copied as written. A server the gateway could not run exactly as the client does
  (a client-only `${input:...}` value, a URL with a query or a password, a literal default) is
  skipped with its reasons and never a value; a run that writes nothing exits non-zero. Command
  arguments are still copied as written.
  Affects: 4.0.0 pre-releases and 3.x (plaintext values in a discovered config). Operator action: check `secrets.store` before running `discover --write-config`; move secrets out of a config written by an earlier version.
- **A watch opened with an API key's old secret now ends when that secret stops being valid.** An event subscription, a watch poll and a dashboard session each remember the secret they were opened with. After a rotation that drops the old secret at once (a key whose secret leaked, rotated in gateway.yaml or through the web UI, then reloaded), all three end at their next check, even though the key keeps its principal, grants and tasks. After a routine rotation they keep working until the grace for the old secret ends. Before, they were matched by the key's name and principal alone, so they outlived a leaked secret's rotation.
  Affects: 4.0.0 pre-release builds with API keys rotated while watches or dashboard sessions were open. Operator action: none; subscriptions and watches stored before the upgrade end once and are reopened by their clients.
- **A refused dashboard link no longer tells a caller whether they guessed it.** A link
  presented from another machine was refused with "this attempt has used it up" only when it was
  the live link; on a host clock before 1970 the refusal said "the link is kept" only for the live
  link; and a gateway with an HTTPS `server.public_url` on a plain-HTTP listener answered the live
  link differently from a wrong one. Each now answers every value the same, and the live link is
  spent or kept exactly as before. The link is also compared in constant time, including when no
  link is outstanding.
  Affects: 4.0.0 pre-releases. Operator action: none; the log line for a refused link still records whether it was spent.
- **The web UI's capabilities page no longer lets a capability file name inject markup.** The
  page lists capabilities by file name, with no character filter, and its escaping left quote
  characters as they were, so a name such as `x"><img src=x onerror=...>.yaml` closed an
  attribute on the capability card and ran script in the admin's browser session when an admin
  opened the page. Anyone who can place a file in a capabilities directory could trigger it. The
  page now escapes quotes wherever it writes a value into an attribute.
  Affects: 2.10.0 up to 3.5.1 and the 4.0.0 pre-releases. Operator action: none after upgrading;
  before then, keep write access to the capabilities directories limited to the accounts that
  administer the gateway.
- **Secrets saved through the gateway can go to the OS keychain, and the choice is never silent.**
  `secrets.store: keychain` now writes each saved secret to the macOS Keychain, the Linux Secret
  Service or Windows Credential Manager, and `auto` prefers the keychain wherever its read-only
  probe passes. The value reaches the store through the API or stdin, never argv or a log. A
  locked or missing keychain refuses a `keychain` save with nothing written; under `auto` the
  gateway logs a warning naming the reason and writes to owner-only files instead. A store call
  that times out keeps its entry listed rather than deleting what it cannot confirm.
  `mcp-gateway doctor` gains a `secret-store` row naming the store, the reason and the number of
  unused entries.
  Affects: 4.0.0 pre-releases only; 3.x has no secret saves. Operator action: none for `files`; on Linux, install `libsecret-tools` and `libglib2.0-bin` for the keychain, and check the doctor row after upgrading.
- **A firewall rule whose `match` glob does not parse no longer matches every tool.** The firewall compiled such a rule as `*`, so a typo like `exec_[` in an `allow` rule allowed every tool call whatever its scans found. With the firewall on, gateway.yaml now fails to load and the error names the rule's path, `security.firewall.rules[N].match`, not its text. A rule that reaches the firewall without the load (a program embedding it) blocks its finding types on every tool, whatever its action.
  Affects: every release since 2.6.0 with `security.firewall.enabled` on and a rule whose `match` is not a valid glob. Operator action: fix or remove the rule the startup error names.
- **A bad collusion glob is named by its key path, not its text.** A `security.firewall.collusion` glob that does not parse (in `sources`, `non_egress`, or an `allowed_flows` entry's `source` or `egress`) refused the config with an error that quoted the pattern. The error now names only the key path and index, such as `security.firewall.collusion.sources[1] is not a valid glob`, as the firewall rule errors already do.
  Affects: every release with `security.firewall.collusion` enabled. Operator action: none; a config that loaded before still loads.
- **Relay detection follows a reload, not the setting the gateway started with.** `security.firewall.collusion`'s `sources`, `non_egress`, `allowed_flows` and `action` now apply live: a delivery is recorded under the action in force when it is delivered, and a relay is judged against the lists and action of the request that relays it. A gateway started with relay detection `off` can switch it on by reload, provided `window_secs`, `min_matches` and `common_principals` are unchanged; otherwise `security` reports as needing a restart. Copies delivered while detection was `off` are not held, so a relay of them is not seen.
  Affects: deployments using relay detection in 4.0.0 pre-releases. Operator action: none.
- **Windows lock files are owner-only, and a lock directory open to every account is refused.** The grant journal, the audit-log segment lease, OAuth client registration and token refresh, the control-plane store and protocol telemetry took their cross-process lock on a `.lock` file that was created with its directory's inherited ACL, and an existing one was used whatever its permissions. Another local account that could open it could hold it and stall the gateway's writes (no data was exposed: a lock file is empty). Those locks now create the file owner-only and replace an existing one that is not owner-only once nothing has it open; a file still held open elsewhere (for example by an older gateway during an upgrade) is waited out up to the lock's usual deadline, then refused with the file, the rule it fails and what to do. A lock directory that Everyone, Anonymous or a specific other account may create files in is refused. One that only `BUILTIN\Users` or Authenticated Users may create files in (common outside the user profile) is used, with one warning naming the directory, the group and the repair, and `mcp-gateway doctor` reports it as a `lock-directories` warning.
  Affects: Windows only, every release with these locks; unix unchanged. Operator action: none in the usual case, since the gateway replaces such files itself. When it refuses a lock file, stop the process that holds it. When it refuses a lock directory, or warns about one, remove the other accounts' rights to create files there as the message says.
- **A save on Windows no longer widens a file to its folder's access list.**
  Rewriting an existing file (an imported capability file, the skill registry, the SIEM export
  cursor, the cost ledger, the upgrade stamp) replaced it with a file carrying the folder's
  inherited access list, so a file the operator had made owner-only became readable by every
  account the folder lets read; capability files can hold literal tokens. A save now keeps the
  file's own access list and owner, and refuses, leaving the file untouched, when they cannot be
  copied exactly: a file owned by an account the gateway cannot give a new file (it can give its
  own user, and the Administrators group when elevated), a file with an integrity label, a file
  moved in from another folder. A new file still takes the folder's list.
  Affects: Windows only, 3.x and 4.0.0 pre-releases. Operator action: none in the usual case; for a
  refused save, follow the message (give the file an owner the gateway can keep, or reset
  the file's inheritance with `icacls <file> /reset`).
- **An events subscriber on a managed-account backend no longer receives anything observed under a
  grant that has since been rotated or revoked.** A per-user listener's records carried no mark of
  the grant they were observed under, so a record queued before a re-grant, a revocation, a
  narrowing of scopes or a descriptor change was still sent after it. Each record now carries the
  grant binding of the listener run that observed it, and delivery reads the grant again just
  before the send: a record from a grant that has moved is dropped as `observation_changed`, and
  one whose grant gives no view is dropped with the outcome `grant_no_view`. An ordinary token
  refresh does not count as a change. When the account store cannot answer in time, the record
  waits unsent (`fence_unavailable`) and is dropped only once its retry window is over. The time
  from that read to the end of the request is bounded by the callback client's 10-second total.
  A listener run is fixed on the grant it started under: a later credential under another grant,
  or the run's own check every 30 seconds, ends the run before anything is sent under it.
  Affects: 4.0.0 pre-releases with per-subscriber events on a backend bound to a managed account (`account:`). Operator action: none.
- **A backend with per-user sessions only gets no gateway shared session.** A backend whose identity binding is required with `session_mode: per_user`, or one bound to a managed account or to an external account with per-user sessions, still had a shared session opened by the gateway itself: warm-start listed its tools, the health loop probed it, and a restart from the dashboard rebuilt that session. Each of these requests carried no subscriber's credential, and a cold caller's `tools/list` could show a tool list fetched under that shared session. The shared session is now refused before anything is sent, the backend's status reads `per_user`, and a cold caller's first `tools/list` waits, at most 30 s, for that caller's own list instead of the shared one. Not covered: a subscriber's own per-user session still starts (connect, discover, initialize) with only the backend's static headers, before that subscriber's credential is applied.
  Affects: every gateway with a backend whose identity binding is required with per-user sessions, or that is bound to a managed account or to an external account with per-user sessions. Operator action: none; expect `per_user` in that backend's status and no health data for it.
- relay detection: a call the gateway refuses before its backend (a withheld or absent tool name, any pre-send refusal) is no longer recorded as one a backend ran. A plan's replay entry names only the steps a backend answered, so a stored read no longer renews a receipt for a refused step; a task whose call was refused records the gateway as its answer's author, so no receipt quotes that answer as the backend's; and a plan whose replay entry is gone no longer receipts its whole stored result against its one target. A refused step stays a target, so stored reads still re-check access to it. A source scan fails the build when a new pre-send refusal exit is neither marked nor listed with a reason
  Affects: no released version. Operator action: none.
- **A required identity binding's per-user sessions send only each user's own credential.** For a backend whose identity binding is required (`identity_propagation.required: true`, any session mode), a user's own session started with only the backend's static headers: its connect, `server/discover`, `initialize` and `notifications/initialized` reached the backend with no user's credential, or with a gateway-level one if a static header carried it, and its calls carried the static headers beside the user's credential. Every request on such a session now carries only the calling user's credential, never a static header or a gateway token; a request with no user in flight is not sent (no session `DELETE` on close, no late cancel notification), and a call carrying no credential is refused. Startup warns, per backend, naming each static header these sessions now leave off. A backend with an optional binding is unchanged.
  Affects: every gateway with a backend whose identity binding is required. Operator action: none unless such a backend needs a static header on per-user requests; see the startup warning and UPGRADING.
- **A required identity binding's per-user sends recheck the user's credential each time, and A2A per-user sessions send only it.** Each send on such a per-user session (a call, a retry, a session-expiry re-handshake, a legacy SSE reopen, an era re-probe, a notification) first rechecks the dispatch's credential: a managed account's grant through its custody, any other credential against its published expiry. A grant revoked or a credential expired during a call refuses that call's next send and closes that user's session; a routine token refresh refuses only that call, and the user's next call is served. Each send uses only the credential of the call that caused it. On an A2A backend with a required binding, a user's own session sends no static header and no URL credentials, fetches the agent card under the user's credential, and sends nothing (no cancel, no poll) once the user's call has ended. Each refused send is counted in `mcp_gateway_per_user_send_refused_total`, by reason.
  Affects: gateways with a backend whose identity binding is required, managed accounts and A2A agents included. Operator action: none; see UPGRADING.
- **A rotated or revoked account grant no longer shows its old per-user tools.** When a managed account's grant rotated or was revoked, a listing could still present the catalogue fetched under the old grant: by name in `gateway_list_servers`, in `tools/list`, in HTTP `tools/resolve` or after `gateway_set_profile`. That happened when a publish of the old grant raced the gateway's account re-check, or when custody was busy. Every listing path now applies one rule: a held catalogue shows only while the request's own account read still matches it. Both writers of that index check the grant with a fresh read before they publish. A busy custody read hides per-user tools for that request; shared backends still list. After a busy read, per-user tools can stay hidden for up to the cold-fill retry backoff (60 s). Sends were never affected: each call resolves its own credential.
  Affects: per-user backends that use managed accounts, in 4.0.0 pre-releases. Operator action: none.
- **A backend can no longer forge the gateway's own answer members.** The gateway writes its
  verdicts and stamps into answers: `_security_findings`, `_contract_violation`,
  `_contract_reason`, `_context_integrity`, `_cost_warnings`, `_cost_suggestion`, `_signature`,
  `_meta.provenance`, the `_meta` interrupted-task markers and a listed tool's `trustCard`. When
  its own check wrote nothing, a backend's copy of any of them reached the client and the model
  as if the gateway had written it, for example `_security_findings: []` or an allowing
  `_context_integrity`. A planted classification also steered the relay check. The gateway now
  removes a backend's copy where every backend answer enters, before any check reads it, on
  every route, and logs a warning naming the backend and the members. A signature chain from an
  upstream gateway still verifies.
  Affects: 3.5.0 up to 3.5.1 and the 4.0.0 pre-releases. Operator action: none.
- Security: the gateway's recovery hint, call prediction and trace id are now `_recovery`, `_predicted_next` and `_trace_id`, removed from a backend's answer on the way in, so a backend can no longer forge them; the plain names pass through as backend data. Stored task results are delivered without any noted gateway-only member (the hint, prediction, trace id, findings, contract and cost members, signature and provenance) their row does not record as the gateway's own write; members the gateway writes without noting (`_context_integrity`, the task outcome and reason, `trustCard`) are delivered as stored; a result stored before 4.0 that carried backend-planted gateway members is delivered without them and without its public signature; the internal receipt remains.
  Affects: clients that read the gateway's recovery hint, call prediction or trace id from an answer, and clients that verify provenance signatures on task results stored before 4.0.
  Operator action: none; clients read the `_` names (see UPGRADING).
- **A backend's protocol directives reach the client only where the protocol lets it send
  them.** A backend could put a task handle (`taskId`), a continuation (`requestState`) or cache
  hints (`cacheScope`, `ttlMs`) on any answer, for example a cache hint on a prompt or on an
  interim answer, or a task handle on a call that asked for none, and the client or the gateway's
  caches could act on it. The gateway now removes each of them from every answer the MCP
  2026-07-28 schema and the tasks extension do not place it on, and refuses a task handle that
  answers a call which did not declare tasks: through `gateway_invoke` or a surfaced tool the
  call answers a tool error (`isError: true`, `_recovery.error_code: "INVALID_PARAM"`; through
  `gateway_invoke` inside the JSON text of `content[0].text`), where a
  signature chain in `require` mode used to answer `-32001`. It no longer adds its own cache
  hints to an interim answer either. A signature chain from an upstream gateway still verifies.
  Affects: the 4.0.0 pre-releases. Operator action: none.
- **Discovery output escapes text taken from a client's MCP config.** A client config file can come from a workspace repo the user only opened, and `cap discover`, the shadow report, `doctor` and `setup` printed its server names, keys, endpoints, paths and executables to the terminal as they were. An ANSI escape in a name could recolour or clear the terminal, a bidi override could reorder what was read, and a newline could forge a result line. Every such field is now printed with control, format and line-separator characters written as `\u{..}`; a backslash before `u{` is doubled, so an escape on screen is always one the gateway wrote. A shadow-report command that escaping would alter (Verify, Apply after review) is withheld with fixed guidance rather than shown altered. The scanner warnings and the discovery debug lines for an MCP config file name and an environment find carry the same escaping. `--format json` and `--format yaml` are unchanged: they stay lossless for machines.
  Affects: the 4.0.0 pre-releases and earlier, when a client config holds control or bidi characters in a server name, key or path. Operator action: none.
- **A backend can no longer echo a credential the gateway injected back to the client.** When a backend's `secrets:` rules inject a value into a call (as an argument, a header or a query parameter), anything that backend sends back is scrubbed of that value before the gateway parses, logs, retries, caches or stores it. That covers answers and errors, notifications, change-notice URIs, a WebSocket frame, a stdio line and an A2A reply. Each occurrence becomes `[redacted]`. Its percent-encoded form is matched too. Progress tokens, subscription tags and A2A task ids still route by what the backend sent; only the copy that leaves the gateway is scrubbed. A signed answer still verifies against the bytes the backend signed; a signed answer whose top-level key name is itself an injected value is refused, since no view of it is both scrubbed and what was signed. An answer whose `error.code` is the value, or one from a backend rotating values faster than the redaction grace allows, is replaced by a fixed refusal. Diagnostics name lengths and positions instead of quoting backend text. A rule value under 8 bytes logs one warning per rule at its first send.
  Affects: backends with `secrets:` rules. Operator action: none.
- **A backend's notifications can no longer carry members only the gateway may write.** A notification a backend sends during a call (progress, a log message, a list change) reached the client with whatever members the backend put in it, including the gateway's own (`_security_findings`, `_meta["io.mcp-gateway/..."]` and the rest of the reserved set), which an answer already loses. Every notification on its way to a client now passes one ingress, whatever transport carried it: gateway-only members are removed, a signature chain or listen subscription tag in `_meta` is removed, and an MCP notification also loses the protocol members the protocol places elsewhere (`taskId`, `ttlMs`, `requestState`, `cacheScope`). A vendor's own notification keeps its fields. A task notification a backend sends (`notifications/tasks`, `notifications/tasks/status`) is withheld, since the gateway reports tasks under its own ids. Removals are logged with the backend, the method and the member names, never the values.
  Affects: 4.0.0 pre-release builds; no released version forwards in-call notifications. Operator action: none.
- **A value in the text log can no longer forge a log line.** In the default text log format, a
  field written with `%`, an error and the event message went out with their control characters
  raw, so a client's refused tool name, a changed capability file's name or a backend's error
  text carrying a newline wrote a second, forged line, and an escape code could erase or move
  text on an operator's terminal. Every control character, line separator and bidirectional
  control in a field value, an error (with its sources) or the message is now written as an
  escape such as `\n` or `\u{1b}`, and the log writer escapes the same characters in anything
  else on the line, such as a bridged `log` record's target, keeping only the line's own final
  newline and the formatter's colour codes. A clean line is unchanged byte for byte, and the JSON
  log format was already safe and is unchanged. Not covered: a bridged
  `log` record's target can still carry one of the nine colour codes the formatter itself writes,
  also with colours off, which can recolour text but cannot break a line, conceal text or move the
  cursor.
  Affects: 2.0.0 up to 3.5.1 and the 4.0.0 pre-releases, with the text log format (the default). Operator action: none.
- **The control-plane snapshot shows a caller only its own grants and audit events.**
  Any signed-in caller, an agent's ordinary API key included, could read every user's identity
  grants and every control-plane audit event on the Control Plane page. A caller no role rule maps
  is now `viewer` instead of `auditor`, and a viewer or developer reads only its own grants and the
  audit events it performed; admin, security reviewer and auditor keep the full view. See UPGRADING-4.0.
  Affects: 4.0.0 pre-releases and 3.5.x (v3.5.1 shows every identity grant to an unmapped caller). Operator action: map an identity that must read every grant to `auditor` with a role rule; an API key that must do so is made an admin key.
- **`audit verify` without a key can no longer pass signed records written during the run.** Without a shared secret, `audit verify` refuses a signed log, so a signed log is never passed with its signatures unchecked. It decided that from a first read of the log, then verified in a second read; a signed record written between the two was checked by hash only, and the run exited 0. The verifying read now notes every signature it parses, and a keyless run that saw one is refused with the same message, whatever the first read found. A run verifies the records its read reached; a record appended after that read is for the next run. A keyless run whose chain also failed keeps its failure report, with a note that signatures went unchecked. Library callers of `verify_audit_log` get the new `VerifyResult::signed_entry_seen` field, and a keyless caller should refuse on it as the command does; hash-only verification itself is unchanged. Code that builds a `VerifyResult` with a full struct literal needs `..Default::default()`.
  Affects: keyless `audit verify` on a live, signed log. Operator action: none. A keyless run racing a signed append now exits 1 where it exited 0; the same run with the signed record written a moment earlier was already refused.
- **A backend's error no longer passes for the gateway's own.** Signals the gateway reads only from its own errors no longer take a backend's look-alike: an audit record files a backend's -32001 or -32004 as `error`, not `denied`; a backend's error no longer forwards the gateway's recovery keys, tool text or removed-method mark; and a backend's error shaped like the gateway's account refusal is answered as the backend's failure (HTTP 500 with its own text on the direct route, a tool error on the meta route), never as the account refusal.
  Affects: the 4.0.0 pre-releases. Operator action: none; an audit query that counted a backend's -32001 as a denial now sees an error.
- idempotency: a call refused inside its backend's own send, before any byte leaves (a secret rule that cannot be applied, a withheld tool, a credential the slot needs and the call lacks, a failed slot start, a managed account's backend refusing its start with 401, an open circuit, a full slot), is recorded as refused before its backend: its delivery record says refused, its idempotency key is released so a same-key retry runs, a task stores the gateway as its error's author and a plan notes no relay replay call for it. Otherwise a key is released only when the delivery provably sent nothing: a call whose earlier round or step already reached the backend keeps its key, including a bridged retry refused before its send, a bridged exchange that ends in an error or is dropped (a deadline, a spent budget, a relay refusal, a legacy call dropped while the gateway asks the client) and an HTTP resend after an expired session that never connected. A same-key retry of such a call is answered with the may-have-run notice instead of running again. One case is unchanged here: when a backend asks a modern client for input, the key is still freed for the client's continuation, so a fresh same-key call during that wait runs; a separate change keeps it reserved
  Affects: 3.x up to 3.5.1 for the HTTP resend after an expired session (3.5.1 released the key on every failed call); no released version for the other cases. Operator action: none.
- **A backend can no longer echo a credential its `headers:` or `env:` configuration gave it back to the client.** A value written as an `env:`, `file:` or `keychain:` reference, and a variable substituted into a header (`Bearer ${TOKEN}`), is removed from everything that backend sends back, at any length, the same way an injected `secrets:` value is: each occurrence becomes `[redacted]`. An `env:` value written as nothing but `${VAR}` references is treated as a secret when it is 8 bytes or longer; a shorter one is left as it is and its field is named in one warning. A literal value, a template mixed with other text (`${HOME}/bin`) and a `:-default` the gateway fell back to are never redacted. The values stay redacted for as long as they are configured; one a reload removes stays redacted for the redaction grace.
  A backend whose set filled up and refused a value now keeps refusing until that value's grace has passed, instead of serving it unredacted once older values aged out.
  Load refuses a backend with more than 64 such secret values, and a secret value containing `[redacted]`, `<removed>` or `{hidden}`; the message names the backend or field, never the value.
  Affects: backends with credentials in `headers:` or `env:`. Operator action: none for a typical config; to mark a short env value secret, write it as an `env:` reference.
- **A backend hidden from a caller now answers as an unregistered name does.** Under an mTLS policy or agent auth, a backend whose every tool the caller's policy refuses is left out of that caller's listings, but a call naming it was still refused differently from a call naming a backend that does not exist (a scope or certificate refusal against a "not found"), so a caller could probe which hidden names are registered. The caller's view now misses on a hidden backend exactly as on an unregistered one, at every stage of `/mcp`, the direct backend route, `gateway_invoke`, `gateway_execute` chains, playbooks and task runs, judged live from the caller's identity. A backend whose refusal can only be decided tool by tool, or a per-user backend whose caller has no fresh catalogue, still answers as before until its catalogue is known.
  A backend the caller's routing profile leaves out is hidden the same way: under an mTLS policy or agent auth it is left out of that caller's listings, and a call naming it answers exactly as a call naming an unregistered backend the same profile leaves out. The profile still judges every name by name, registered or not. See UPGRADING.
  Affects: 4.0.0 pre-release builds; 3.x lists every backend to every caller, refused a `POST /mcp` call naming a backend the routing profile leaves out with that routing-profile refusal under any authentication, and applied no routing profile on `/mcp/{name}`. Operator action: none.
- **A credential's backend list now bounds what it reads in the web UI's Activity and status.** A key scoped to some backends read every backend's calls in Activity (list, export and receipts) when its identity mapped to an Auditor or Admin role, or when it was an admin key, and every non-admin caller's status counts covered every backend. Activity now shows a scoped key only calls on its backends, within what its role allows, and no gateway-wide audit rows (grant and policy changes, admin actions); a receipt it may not read answers as a missing one. Status counts only its backends, and the full status view needs an unscoped admin. An admin key with a list naming some backends no longer sees every backend in the control-plane snapshot, can no longer mint a dashboard link (a session is unscoped), and a session it minted ends on the reload that narrows it. An admin key with an empty list stays a UI-wide admin that calls no backend. See UPGRADING.
  Affects: 4.0.0 pre-release builds, which judged Activity, status and dashboard links by the admin flag and role alone. Operator action: an admin key meant to administer the whole gateway sets `backends: ["*"]`; read the full audit trail with an unscoped key.
- **An admin credential scoped to some backends no longer holds gateway-wide admin powers.** An admin API key whose `backends` named only `alpha`, or an Admin-role key-server token scoped to `alpha`, could still kill, revive or reload the whole gateway, read every session's and key's spend, read `/health` detail, administer events (operator events, the dead-letter, held and lease routes) and read control-plane export status, and act as control-plane Admin. Those powers now need an admin scoped to every backend; a scoped admin keeps admin breadth inside its scope (Activity on its backends, admin-only capabilities on its backends) and is Auditor on the control plane. A queued task ends when a reload lowers its caller's admin standing. See UPGRADING.
  Affects: 4.0.0 pre-release builds. Operator action: give an admin key or Admin-role token meant for the whole gateway `backends: ["*"]`.
- **A credential's backend list now bounds the web UI's control-plane snapshot too.** A key scoped to some backends was still shown every identity grant, the local policies, the control-plane store's audit events and the shadow radar's scan of MCP servers on the gateway host, and the counts, coverage and decision queue built from them. It is now shown none of them, whatever its role, and its radar reads `scan_status: "out_of_scope"` with every count zero. Unscoped keys and an admin key with an empty list see what they saw before. See UPGRADING.
  Affects: 4.0.0 pre-release builds. Operator action: read grants, policies, the audit trail and the radar with an unscoped key (`backends: ["*"]`).
- **The web UI's live status stream follows the caller's backend scope.** A key scoped to some backends, admin or not, got status counts across every backend on `/ui/api/stream`, its event ids moved with changes outside its scope, and a reload that narrowed a plain key's backend list left its stream open under the old scope. The stream now counts only the caller's backends and never sends a scoped caller the full view; a scoped connection's status ids count the updates it was sent; and a reload that changes the key's backend list closes the stream, so the browser reconnects under the new scope. Reordering or repeating the same backends keeps it open. See UPGRADING.
  Affects: 4.0.0 pre-release builds, where a backend-scoped key or identity watching the web UI's live status saw every backend's counts. Operator action: none.
- **A grant subject that names no one cannot exist.** `GrantSubject::new` is the one constructor and returns `Result<_, EmptyIdentity>`, refusing an empty authority or subject; `GrantSubject::checked` is removed, the fields are private behind read-only accessors, and every deserialization goes through the same check, wherever the subject is nested. A grants file with a rule whose subject or owner names no one is refused at load, naming the file and every such rule; such a rule matched no caller, so it granted nothing; but the gateway kept the last rule per id, so a rule naming no one that shares its id with another rule may have been hiding it, and the refusal says so, because deleting it may make that rule active. `mcp-gateway upgrade` runs the same check on the grants file the gateway would load and fails naming the same rules; it edits nothing.
  The same check now treats a value of only whitespace as naming no one: an OIDC provider that returns a blank `sub` or `iss` is refused at sign-in as a token missing its required `sub` claim (401, no token issued), as an empty one already was.
  Affects: grants files with an empty or blank subject or owner; OIDC providers returning a blank `sub` or `iss`; library users who built `GrantSubject` with a struct literal or read its fields directly.
  Operator action: if startup or `mcp-gateway upgrade` names a grant rule naming no one, delete that rule from the grants file.
- **A client certificate that names no one is never a certificate identity.** `CertIdentity::from_der` now answers `None` for a certificate that parses but has no SAN URI and no CN; production reaches it only from the TLS acceptor's verified peer chain. `CertIdentity` fields are private (read them through the accessors) and it no longer implements `Default`. The TLS identity layer still refuses such a certificate exactly as before (401, JSON-RPC -32000, before any route runs, `/health` included); it is never treated as "no certificate".
  Affects: library users of `CertIdentity::from_der`; mTLS deployments see no behaviour change.
  Operator action: none.
- **A blank SAN URI or CN in a client certificate is skipped.** A value of only whitespace names no one, like an empty one, so the gateway takes the first SAN URI that is not blank, else a non-blank CN: a certificate whose first SAN URI is blank now presents its next SAN URI (or its CN) as its identity, for grants, the firewall key and the agent check alike, and one left with no name is refused (401, JSON-RPC -32000). Any other value is kept exactly as written.
  Affects: mTLS deployments issuing client certificates with a whitespace-only SAN URI or CN.
  Operator action: grants for such a certificate must name the value it now presents; reissue a certificate whose only names are blank.
- **A deferred upstream task no longer delivers a secret its backend echoed after the gateway lost the means to redact it.** A call the backend runs as a task records a keyed fingerprint of the secrets it was sent with. The task is polled and its result delivered only while the backend's secret rules still resolve to the same values in the same gateway process. After a rotation, a restart, or on a row stored before this change, the task ends withheld with a fixed message instead of its result.
  Affects: 4.0.0 pre-release builds that ran deferred upstream tasks on backends with `secrets:` rules. Operator action: after a restart or a secret rotation, check what a withheld task's upstream operation did before resubmitting it, and resubmit only when that is safe or the call is idempotent.
- **Relay detection records an answer when it is actually sent, under the settings in force then.** A result's relay receipts used to record when the answer was ready, before it was written. If relay detection went from `off` to `block` while an answer waited (a full stdio output queue, or an HTTP body not yet read), that answer was never recorded, and a later relay of its text by another caller was allowed. Receipts now record when stdout takes the frame (each batch item included), and on HTTP, the direct route and request-scoped streams when the server takes the body's first chunk. An answer never written records nothing. The setting at the write decides: `off` then records nothing, even for an answer prepared under `block`. A batch item is no longer excused by an earlier item of the same batch, because a client writes every item of a batch before it sees any answer. A retained answer's replay snapshot is now taken before the answer can be replayed, and it is kept or dropped by the setting at each write, so a replay delivered under `block` records even when the original was prepared under `off`. Task results are unchanged.
  Affects: an operator running relay detection who switches it from `off` to `block` (or back) while answers are in flight, and any client that sends JSON-RPC batches.
  Operator action: none.
- **The npm package checks the release binary before running it.** `npx @mikkoparkkola/mcp-gateway` and the package's postinstall downloaded the platform binary from the GitHub release and made it executable without checking it. The wrapper now also downloads `SHA256SUMS.txt` from the same release, and it installs the binary only when its SHA-256 matches the one entry for that platform. A mismatch, a missing or duplicate entry, an interrupted or stalled download, or a redirect to a non-HTTPS address fails the install with an error naming the cause, and leaves no binary behind, not even one from an earlier install. The binary is written to a temporary file and renamed into place, so an interrupted download can no longer leave a partial file that the next run would execute.
  Affects: installs through the npm package, every version up to 4.0.0-beta.3. Operator action: none; reinstall the package to replace a binary that an earlier version installed unchecked.
- **Credentials typed into the backend panel are kept out of gateway.yaml.** Adding or editing a backend in the web UI now saves a registry server's token, and each literal env value whose name ends in a credential word (`DB_PASSWORD`, `X_AUTH_TOKEN`, `GITHUB_PAT`, `OPENAI_API_KEY`; a name that only contains one, such as `TOKEN_LIMIT`, and any value shorter than 8 bytes, such as `1`, stays text), in the secret store, and writes only the store's reference to gateway.yaml; adopting a discovered server stores by the same rule. Other env values (`DEBUG=1`) are written as typed, since a stored value is redacted from tool results wherever it appears. The answer lists each stored field and its reference. A value that mixes literal text with a template, or a template with a default, is refused by field in the panel and in `mcp-gateway add`. Values saved before 4.0.0 are not moved; replace each with a reference under the same key.
  Affects: 2.10.0 up to 3.5.1 and the 4.0.0 pre-releases. Operator action: replace with an `env:` or `keychain:` reference under the same key any secret the panel saved into gateway.yaml before 4.0.0, and any secret under a name the rule does not recognise; write a value that mixes literal text with a template as a whole template or a secret reference.
- **A gateway starting after a crashed config write now records the recovery in its audit log before it recovers.** A save that crashed mid-write leaves a journal beside `gateway.yaml`, and the next start puts the right file back. Until now that recovery wrote nothing to the audit log. The start now works out which config the recovery leaves (the original for an unfinished write, the new file for one a reload accepted), loads it, and appends a `config_recovery_intent` record to that config's audit log, then recovers. If the record cannot be written, the start refuses and recovers nothing: the config has auth on and no audit log, the config does not load, or its audit log cannot be opened (with auth on or off). The message names the journal and the steps to finish the recovery by hand. A 3.x gateway would have recovered and started.
  Affects: an operator whose gateway crashed or was killed during a config save, then restarts it with a config that names an audit log or turns auth on.
  Operator action: if a start is refused with a pending journal, fix the cause it names (usually the audit log's path or permissions) and start again, or finish the recovery by hand as the message describes.
- **Every rewrite of gateway.yaml reads it through the same mode and owner check as every loader.** The web UI's config writer, the locked text editor behind `mcp-gateway init` and `mcp-gateway upgrade` (and its backend URL-key migration), the locked config writer behind the web UI and reload-API writes (which fell back to a plain read when the checked load refused the file), and the writer's crash recovery each reread gateway.yaml with a plain read, then wrote it back owner-only; crash recovery also restored a staged original, checked only against its journal's digest, as gateway.yaml. If another local account could write the file (group or world write), could read it (group or world read on a file the gateway owns), or owned it, that account's edit could be rewritten as a trusted owner-only file and loaded on the next start or reload. Each of these, and recovery's read of the journal and staged original, now refuses such a file before it records an intent, creates a secret entry or writes anything, and leaves the file's bytes and mode as they were. The discovery adopt route answers that refusal with 503 "gateway.yaml could not be loaded", naming no path, and logs the reason on the server; a gateway.yaml removed while an adopt runs answers 409 `no_config_file` instead of a 500.
  Affects: an admin using the web UI adopt route or other web UI and reload-API config writes, or an operator running `mcp-gateway upgrade` or `init`, on a gateway whose gateway.yaml another local account can write or owns.
  Operator action: none for an owner-only gateway.yaml (chmod 600); a command or write that now refuses the file names it and the fix, the same refusal the gateway gives at start, so fix the file's mode or owner and run it again.
- **The memory-poisoning scanner's `scan_tools` match is case-insensitive on both sides, as documented.** The tool name was lowercased but the configured entries were not, so an entry with an uppercase letter (`STORE`) matched no tool and the memory-poisoning scan never ran for the tools it named, with no warning. Entries are now lowercased once when the scanner is built, so `STORE` scans `store` and `Store_Memory`. An empty entry, which as a substring matched every tool, and a whitespace-only entry, which matched none, are refused at load and on reload with an error naming `security.firewall.memory_poisoning.scan_tools[i]`, whether or not the firewall or the scanner is enabled. Lowercase lists, the default included, match exactly the tools they matched before.
  Affects: an operator who sets `security.firewall.memory_poisoning.scan_tools`.
  Operator action: remove any empty or whitespace-only entry; an entry with uppercase letters needs no change, but now produces findings for the tools it names.
- **A reload or a config write can no longer put a firewall rule the firewall-on load refuses into a running firewall.** `security.firewall.enabled` and `auth.enabled` take effect only on a restart, but a reload's rules join the running firewall at once. A reload or write whose file said `enabled: false` skipped the rule checks, so it could publish a rule with an empty scope list, an exception setting no field, an invalid glob or a bad folder rule (which then blocked its scan types on every call), or a key reference no running caller could carry. While the firewall runs, such a reload or write is now refused, naming `security.firewall.rules[i]`, and the running rules stay; a key reference is also refused while the running gateway has no API-key authentication. A write that adds or changes such a rule is refused whether or not the firewall runs. `init` and `upgrade` keep an existing one byte for byte and warn. A firewall-off load warns once for each such rule, and the Policies screen's read model marks it with the load's message and how it compiles meanwhile.
  Affects: an operator whose `security.firewall.rules` hold a rule the firewall-on load refuses, or who reloads key-scoped rules before restarting with `auth.enabled`.
  Operator action: fix or remove each rule a warning names; to add a key-scoped rule while auth is off, restart with `auth.enabled` first.
- **Credentials given to `mcp-gateway add`, `setup` and `discover --write` are kept out of gateway.yaml.** `add`'s env values (`-e NAME`, `--env-file`) and a registry server's token, and the servers `setup` imports, now go through the rule the web UI backend panel uses: each literal env value whose name ends in a credential word (`DB_PASSWORD`, `OPENAI_API_KEY`) and each header value, at least 8 bytes long, is saved in the secret store (`secrets.store`) and only its reference is written. Other values (`DEBUG=1`) are written as typed. `add` prints each stored field and its reference; `--keep-as-text KEY` (or `header:NAME`) writes that value as typed instead. `discover --write` used to store every literal a client file held, so an ordinary setting such as `DEBUG=1` was redacted from tool results wherever it appeared; it now stores by the same rule, and still stores a value shaped like a secret reference (`file:/x`) under any name, so the gateway never reads it as one. Values written before 4.0.0 are not moved.
  Affects: 4.0.0 pre-releases and earlier. Operator action: replace any secret a CLI command wrote into gateway.yaml before 4.0.0 with an `env:` or `keychain:` reference under the same key, or add the backend again.
- **A credential in a backend's command or URL is refused instead of written into gateway.yaml as text.** The web UI's backend add, update and add preview answer 422 by field (`secret_in_command`, `secret_in_url`), and `mcp-gateway add` exits 2, when the command or URL that would be saved holds a credential: userinfo in the URL, a query parameter or command flag named like a credential (`token`, `api_key`, `password`, `Authorization`), a `NAME=value` argument with such a name, or an `Authorization:` header argument, with a literal value of any length. Ordinary queries (`?transport=sse`), `${VAR}` text and secret references are saved as before. Give the credential as an env value instead (`-e NAME` or `--env-file` on the CLI, an env field in the web UI), which goes to the secret store; the gateway does not expand `${VAR}` inside a command or URL. `mcp-gateway add -e` now takes an environment variable name, never a value.
  Affects: every release before 4.0.0. Operator action: replace a credential written into a backend's command or URL with an env value or a header reference, and use `-e NAME` or `--env-file` in scripts that passed `-e NAME=value`.
- **A signed audit entry stripped of its signature no longer passes as an ordinary unsigned one.** With a signing secret set, the audit log now keeps a `.sigstart` file beside it: where signing began, and a digest of the bytes written before that, under the same secret. An unsigned entry after that point, or in pre-signing bytes that changed since, reads `invalid` in the Activity list, receipts, both exports and the live stream, with the reason in a new `integrity` field; the exports' manifest reports each log's anchor state even when no row fails. A missing, edited or copied `.sigstart` is itself reported, never read as "everything unsigned".
  Affects: deployments with `security.transparency_log.shared_secret` set; on the first 4.0.0 start a log a 3.5.1 gateway signed is migrated once and records `audit_segment_sigstart_migrated`. Operator action: none for a log that starts from its first record; see the upgrading note for a 3.5.1 log an external tool trimmed, and keep `.sigstart` with the log when you move or archive it.
- **`init` no longer writes the admin token into the config.** `mcp-gateway init` now stores the generated admin token in the store chosen by `secrets.store` and writes only a reference into `auth.bearer_token`, so the config file and its samples hold no secret. See UPGRADING-4.0 and the QUICKSTART section on reading the token back.
  Affects: configs created by `init` on 4.0.0 pre-releases, which hold the token as plaintext; 3.x unaffected. Operator action: none for a new `init`; to move an existing literal `auth.bearer_token`, set it to `env:MCP_GATEWAY_TOKEN` or re-run the store step, and rotate the token if the old config was shared or committed.

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

## [3.3.1] - 2026-07-13

### Security

- **SSE transport: endpoints and redirects are checked after the URL is
  resolved (#356).** The same-origin guard for the SSE `endpoint` event checked
  only endpoints that began with a scheme, so a network-path or backslash form
  (`//169.254.169.254/...`, `\\host/x`, `/\host/x`) replaced the authority and
  went unchecked. Every endpoint is now resolved against the base URL and the
  resolved origin is checked. The SSE redirect policy enforces the same origin,
  and the SSE handshake buffer is capped at 64 KiB. An unused Tailscale
  identity-header parser, which trusted inbound headers and had no callers, is
  removed.
- **Identity propagation fails closed when its audit record cannot be written
  (#355).** A per-user credential minted for a caller is no longer returned
  when the transparency-log write fails; the call fails instead. A refusal whose
  audit write fails still refuses, and logs the failure.

### Changed

- **A lint for secrets in Debug output and logs (#354).**
  `scripts/dev/cwe532-leak-lint.py` fails a pull request that derives `Debug`
  over a secret-shaped field or logs a secret-shaped variable, and the release
  workflow runs it before publishing. Findings that predate it are listed in
  `scripts/dev/cwe532-baseline.txt`.
- **The README is restructured for first-time readers and explains the
  licensing model (#357).**
- **npm publishing runs on Node 22 (#352).** npm 12 needs Node 22 or later, so
  the 3.3.0 npm publish failed on Node 20 while the other channels published.

## [3.3.0] - 2026-07-12

### Changed

- **BREAKING: per-file licensing (#349, #350).** The repository default is now
  PolyForm Noncommercial 1.0.0; files marked `SPDX-License-Identifier: MIT` stay
  MIT. Commercial use of the noncommercial-licensed code needs a commercial
  license (`COMMERCIAL.md`). Versions 3.0.0 to 3.2.1 were published under MIT,
  and that grant stays for those exact artifacts; they are now deprecated on npm
  and yanked on crates.io, so new installs resolve to 3.3.0. `LICENSES.md` and
  `NOTICE.md` describe the model.

### Fixed

- **OAuth discovery for an authorization server whose issuer has a path (#346,
  #347).** The `.well-known` metadata URL is now built as RFC 8414 §3.1 and
  RFC 9728 §3 require, with `.well-known/<suffix>` between the host and the
  path, instead of after the path, which returned 404. Reported by @crepererum.
- **Cargo.lock carries the 3.3.0 version bump (#351).**

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
- **`docs/always-load-pins.md`** (MIK-3639): client-side pin-set rationale for Claude Code v2.1.121 `alwaysLoad` flag — recommends a small set of hot-path always-loaded MCP servers with rollback procedure.

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

## [2.0.0] - 2026-01-25

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

## [1.0.0] - 2026-01-25

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
