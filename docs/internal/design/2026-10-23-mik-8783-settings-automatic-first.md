# MIK-8782 + MIK-8783 design: retire seven settings the gateway can pick (Family-fix settings-automatic-first)

perf-8014, 2026-10-23. Base: docs/ranking-1-release-line at bc35b98df. One PR, one design.

## Problem

Seven keys reached 4.0.0 pre-releases although the gateway can pick their values itself (operator rule
2026-10-23). The keys are `capabilities.stale_check_secs`, `cache.enabled`, `failsafe.retry.enabled`,
`failsafe.circuit_breaker.enabled`, `auth.client_circuit_breaker.enabled`, `security.signature_chain.max_links`
and `server.protocol_revision_window`. Each must go before GA, in the MIK-8782 shape:
- a file that still sets the key loads;
- the loader logs exactly one warning, naming the key as ignored and the behaviour as automatic;
- the value is not honoured.

AUTO.8 also fixes two `verify` doc comments.

## Mechanism: reuse what retired `meta_mcp.cache_tools` (no new machinery)

1. **Remove the field** from its config struct (D1–D7 below).
2. **Loader:** add each path to `RETIRED_KEYS`, src/config/strict_keys.rs:68. A reason string names the
   automatic behaviour and what to do: "Delete it, or run `mcp-gateway upgrade`". The loader already
   classifies a key serde ignored and `RETIRED_KEYS` names as `Ignored::Retired`, and warns once.
3. **`upgrade`:** add each path to `REMOVED` in src/commands/retired_config_keys.rs:35 with
   `OnLoad::Warns`, so `mcp-gateway upgrade` deletes it in its single rewrite, as it does `cache_tools`.
   One exception (r1, gpt): `auth.client_circuit_breaker.enabled` is the one key whose parent section is
   itself a switch. `drop_key` removes a parent left empty (retired_config_keys.rs:229), which would turn
   the client breaker off. For that key, `upgrade` never empties the parent:
   - with siblings, it deletes the key;
   - when the key is the section's only content, it leaves the key, reports it as `Retired::Left`, and
     names it. The operator then replaces the block with `client_circuit_breaker: {}` to keep the breaker on
     (a bare `client_circuit_breaker:` is YAML null, which turns it OFF; r3, gpt), or deletes the section
     to turn it off. The report and the UPGRADING note give that exact edit, and a row loads the edited file.

   A row pins both cases. Two more rows (r2, gpt) cover a `failsafe:` section holding only `retry.enabled`,
   and one holding only `circuit_breaker.enabled`. Removing that one key would leave `failsafe:` as YAML
   null, so the rows pin the `Retired::Left` fallback, or a clean removal that still loads.
   - **Report wording (r2, gpt):** `upgrade`'s reporter says every removed key "never had an effect"
     (src/commands/upgrade_url_keys.rs:95, :98). That is false for these seven. The text becomes neutral
     ("it is ignored in 4.0; <reason>"), with the per-key reason taken from `RETIRED_KEYS`.
4. **Family test (AUTO.7, the Family-fix's table).** r1 found that today's tables are not a real
   equality check, so the design now says exactly what the test does:
   - **Equality (new, in-crate):** a `#[cfg(test)]` row compares the actual registries in three pairs
     (corrected in r2: `REMOVED` also carries two backend removals that live in `REMOVED_BACKEND_KEYS`,
     not `REMOVED_KEYS`):
     - `RETIRED_KEYS` with the `REMOVED` entries marked `OnLoad::Warns`;
     - `REMOVED_KEYS` with the non-wildcard `OnLoad::Refuses` entries;
     - `REMOVED_BACKEND_KEYS`, as `backends.*.<key>`, with the `*` `OnLoad::Refuses` entries.

     The comparison is a small pure function with test-only access to the registries. A negative control
     feeds it a list with one entry missing on each side and expects the difference to be named. A future
     retirement listed on only one side fails CI.
   - **Per key (extends the `cache_tools` tests in tests/c1_unrecognised_config_keys.rs:541 and
     tests/surf2_upgrade_removed_keys.rs), one row per key:**
     - the file loads;
     - exactly one warning names the key, counted from the captured log;
     - the loaded `Config` or the runtime shows the automatic behaviour, not the file's value (for example,
       `cache.enabled: false` and the cache is still built);
     - the compiled docs/UPGRADING-4.0.md quotes the warning's reason.

**Hazard found:** `SignatureChainConfig` is `#[serde(deny_unknown_fields)]`
(src/config/features/signature_chain.rs:38). With `max_links` gone, serde would refuse the key before
`serde_ignored` sees it, so the file would fail to load (it should warn). D6 handles this.

**Known limit:** the env layer (`MCP_GATEWAY_*`) is outside the strict check by design (strict_keys.rs:10–12),
so an env-set retired key is ignored with no warning. That is today's behaviour for `cache_tools`, and
this PR does not change it. r1 (grok) found one narrowing that D6 adds: once `deny_unknown_fields` is
dropped, a misspelled `MCP_GATEWAY_SECURITY__SIGNATURE_CHAIN__*` override of a field that remains loads
silently, where today it aborts start. The strict pass also returns Ok when there is no file
(strict_keys.rs:165). This is accepted and recorded here and in the UPGRADING note: a chain configured
only through env with a typo runs on the file's chain settings, or with no chain section.

**Behaviour for a file that set a switch to `false`:** each switch's value is ignored, so a file that set
`cache.enabled`, `failsafe.retry.enabled` or `failsafe.circuit_breaker.enabled` to `false` now runs with
the mechanism on. Each warning says that and names the hatch from the table below. For the client
breaker, `{enabled: false}` inside a present section now means on; the warning says to delete the
section to turn it off, and to write `{}` (not an empty key) to keep it on.

## Per key

| # | key | today | after | the incident hatch that remains |
|---|---|---|---|---|
| D1 | `capabilities.stale_check_secs` (8782) | `u64`, default 60, `0` = off; read at run_steps.rs:165, stdio_loop.rs:198 into `CapabilityWatcher::start(.., stale_check_secs)` | Drop the parameter and `ReloadTuning::from_config_secs`; `start` uses `ReloadTuning::default()` (already 60 s, watcher.rs:88). Tests already build their own `ReloadTuning` (watcher.rs:69 doc), so that is the test hook for AUTO.2, with no new seam. capability_stale_tests.rs is replaced by the retired-key row. | The check is a bounded fingerprint walk. A walk that stalls is already bounded and logged by MIK-8651. |
| D2 | `cache.enabled` | build_meta.rs:98 and run_wiring.rs:37 build the cache only when it is set | Always build it. What is stored stays gated by `is_read_only_for` (metadata_read_only.rs:16), and size by `max_entries`. | Entries expire on the 60 s TTL (`cache.default_ttl`), and a restart clears them. |
| D3 | `failsafe.retry.enabled` | `RetryPolicy::new` copies it (retry.rs:34) | `RetryPolicy.enabled` stays an internal field: `true` from config, `false` when `resend_permission` denies (ops.rs:176). No new gate. | `failsafe.retry.max_attempts: 1` still means one attempt (retry.rs:59), and a tool with no read-only or idempotent annotation is never retried. |
| D4 + D5 | `failsafe.circuit_breaker.enabled`, `auth.client_circuit_breaker.enabled` | one struct, `CircuitBreakerConfig` (failsafe.rs:50), serves both. `CircuitBreaker` checks `enabled` at circuit_breaker.rs:174/208/247/270, `auth_resolved.rs` at :90/:278/:313 | Remove `enabled` from `CircuitBreakerConfig` once, which retires both paths. Delete the `!enabled` branches. The client breaker stays off when its section is absent (auth_resolved.rs:275). Both paths go in both lists. | Backend: `gateway_revive_server` → `CircuitBreaker::reset` (circuit_breaker.rs:246), and the probe that bypasses the breaker (probe.rs:40). Each gets a row with the flag gone (AUTO.4). Client: remove the section and restart. |
| D6 | `security.signature_chain.max_links` | `usize`, default 8, refused at 0 | `const MAX_CHAIN_LINKS: usize = 8` in src/security/signature_chain.rs, which `ChainPolicy.max_links` keeps reading. Drop `deny_unknown_fields` from this struct only, so the strict-keys pass (which already covers every config key) refuses misspellings there as it does everywhere else. A row pins that a file with a VALID `signing_key` and `key_id` plus `key_idd: x` is refused, and the refusal names `security.signature_chain.key_idd` (r1, gpt: a fixture missing the required fields would fail extraction and prove nothing). | **Why 8, against the topology:** every hop must agree on the bound (`Forward` needs `len < max`, `Terminal` allows `len == max`; asi07 inc3 design:163). Per-deployment values make a chain one gateway builds refusable by the next, so a constant is safer than a setting. Each link is already capped at 1 KiB (signature_chain.rs:30), so 8 links fit inside the 16 KiB chain cap: the link count binds first, and the byte cap is the backstop (corrected in r1). 8 links is far above any documented deployment (client → gateway → at most a few chained gateways). |
| D7 | `server.protocol_revision_window` | `ProtocolRevisionWindow { Off, Record }` (server_config.rs:141), read at run.rs:561. Integration tests (tests/u1_window_crash.rs:37, u1_v1_window_grade.rs) set `record` in a config file. | **Lead-approved (Q1 ruling 2026-10-23), revised in r1:**<br>• **Placement (r1, grok HIGH).** Every production HTTP start omits `serve`: Helm (deploy/helm/mcp-gateway/templates/deployment.yaml:65), the container image and systemd pass top-level `--host`/`--port`, and `serve --host` exits 2. So the flag goes on the top-level `Cli` beside `--host`/`--port` (src/cli/mod.rs:133–137), not on `Commands::Serve`: `--protocol-revision-window <off\|record>`, `#[arg(long, hide = true, value_enum, env = "MCP_GATEWAY_PROTOCOL_REVISION_WINDOW")]`. It works in release builds and is hidden from `--help`.<br>• **Helm and other fixed-args deployments (r1, gpt; corrected r3, grok HIGH):** the `env` form reaches systemd (`Environment=`) and `docker -e` with no change. Helm's `envGuards` (templates/_helpers.tpl:174–180) refuses every `MCP_GATEWAY_*` name in `extraEnv`, because those override config. This one name is CLI-owned, not a config overlay, so it is allowlisted there: a single named exception in the guard and in the values.schema.json:606–620 text. A `helm template` row proves it renders while `MCP_GATEWAY_AUTH__ENABLED` is still refused. This is a guard change, and the PR brief names it.<br>• **Carrying it in:** `apply_cli_overrides` (src/main.rs:592, in the binary crate) writes it into `ServerConfig.protocol_revision_window`, which keeps its current `pub` visibility and gains `#[serde(skip)]` (r3, gpt: a `pub(crate)` field cannot be set from main.rs; keeping `pub` avoids both a visibility change and a new method). It is never deserialized, so a file key reaches `serde_ignored` and gets the retired warning. In-process tests (window_seal_http_tests.rs:39 and the saver tests) keep setting the field directly and are preserved unchanged.<br>• The `ProtocolRevisionWindow` enum stays public (the flag uses it). The public field `ServerConfig::protocol_revision_window` stays public but is no longer deserialized. The PR body lists that change beside the removed public fields.<br>• tests/u1_window_crash.rs:37 passes `--protocol-revision-window record` instead of the key. (tests/u1_v1_window_grade.rs is an ignored offline grader that never starts the gateway, so it is not a start path; r3, grok.) The argv order is the flag before any subcommand, as with `--host`.<br>• surface-4.0.md lists the flag and its env var as INTERNAL.<br>• The `RETIRED_KEYS` reason names both: "the measurement window is an operator instrument: start the gateway with `--protocol-revision-window record` or `MCP_GATEWAY_PROTOCOL_REVISION_WINDOW=record`; delete the key".<br>• Operator-facing docs change in this PR:<br>&nbsp;&nbsp;– upgrading.d/3920.md "New setting" (lines 2 and 22–24) and changelog.d/3920.added.md switch from the key to the flag, since neither has shipped in a GA release;<br>&nbsp;&nbsp;– the RFC-0060 / u1-window design notes get a one-line pointer;<br>&nbsp;&nbsp;– a comment on MIK-8442 (another owner's ticket, so a comment, not a description write) carries the runbook change: set the env var or flag on the measured deployment, for Helm through `extraEnv`. | Restarting without the flag or env var turns the window off, as `off` did. |
| D8 | `verify` doc comments (AUTO.8) | subcommands.rs:758 "verifies without its result"; :762 "result digest is absent" | :758 → "Accept a receipt that carries a result digest when no result is given (`--result` absent)"; :762 → "Accept a receipt that carries no result digest at all, so no result can ever be checked against it". A `--help` snapshot row pins the two distinct texts. | — |

## Questions: r1 answers and what is still open

- **Hot reload and the window (answered in r2, both seats).** The window saver reads the startup config
  once (run.rs:560). A hot reload does not re-apply CLI overrides, and because the field is `serde(skip)`
  it is outside the restart diff, so a reload never turns a running window off. A later reader of the
  live snapshot would see `Off`. This is recorded so no later change "fixes" a reload by stopping the
  window. The test plan adds binary-level rows: the flag and the env var each turn the window on through
  both HTTP entry paths (`serve` and no subcommand), and the window survives a hot reload.
- **Q1 (ruled; placement fixed in r1).** The flag is top-level and backed by an env var (D7). **r2 seats:**
  can every path that starts HTTP serving set it, including `run_server` under no subcommand and the
  container image's entrypoint? Does `apply_cli_overrides` run before `Gateway::run` reads the field on
  every path, including a config hot reload, which must not reset it to `off`?
- **Q2 (approved; answered in r1).** The only strict-keys call is `Config::load` (src/config/mod.rs:615).
  The env-layer gap is recorded under "Known limit". The misspelling row uses a valid fixture. **r2 seats:**
  does a hot reload go through `Config::load`?
- **Q3 (no finding in r1).** The cache is always built. Its size is bounded by `max_entries`, and only
  read-only tools are stored.
- **Q4 (answered in r1, grok).** `doctor`'s hidden-key table stays as it is: it must equal the INTERNAL
  and AUTO rows (check_surface_inventory.py:965), and these keys are REMOVE.

## Docs and inventory (AUTO.7 / 8782.AUTO.4–5)

- One upgrading.d fragment lists all seven: what was there, what happens now, and what to do. It covers:
  - the `false` cases and the env-layer limit;
  - the old overlay spelling `MCP_GATEWAY_SERVER__PROTOCOL_REVISION_WINDOW`, which is silently ignored,
    unlike the new clap env `MCP_GATEWAY_PROTOCOL_REVISION_WINDOW` (r2, grok);
  - incident guidance on the configured cache expiry (`cache.default_ttl`) and capacity (`max_entries`,
    where `0` means unlimited), not only the 60 s default (r2, gpt).
- The compiled docs/UPGRADING-4.0.md bullet at :4675 ("`0` turns it off") is rewritten to the automatic
  check (r2, grok). Each new `REMOVE` row in surface-4.0.md cites this change's fragment, and the surface
  appendix is regenerated.
- Shipped example configs, which the KEEP-only doc scanner (surface_docs.py) reads (r2, both seats):
  delete `cache.enabled`, `failsafe.retry.enabled`, `failsafe.circuit_breaker.enabled` and
  `auth.client_circuit_breaker.enabled` from gateway.example.yaml, examples/gateway-full.yaml:112,
  examples/servers.yaml:15 and examples/per-client-tool-scopes.yaml:22. Where a client breaker was on,
  leave `client_circuit_breaker: {}` so the example still turns it on. `rate_limit`, `health_check` and
  `capabilities.enabled` stay.
- `MCP_GATEWAY_PROTOCOL_REVISION_WINDOW` joins `CLI_OWNED_ENV` (src/config/mod.rs:213), so the exhaustive
  clap/env equality test (src/config/tests/env_files.rs:675) stays green (r2, gpt).
- Recorded, no edit needed (r2, grok): there is no config-schema golden; `duration_bound` needs no change
  once `stale_check_secs` is gone; Helm `values.schema.json` keeps `config` as a free-form object.
- The 4.0.0 pre-release fragments that advertise the keys switch to the automatic behaviour:
  - upgrading.d/8651.md and changelog.d/8651.added.md (`stale_check_secs: 0` as an off switch; r1, gpt);
  - upgrading.d/3920.md and changelog.d/3920.added.md (the window key, see D7).
- docs/DEPLOYMENT.md (stale check at :1492, cache, failsafe sections) describes the automatic behaviour
  first and drops the keys.
- docs/design/surface-4.0.md (r1, grok): each of the seven rows becomes class `REMOVE` (the class token
  the checker accepts, check_surface_inventory.py:30, not `REMOVED`). Each uses the `cache_tools`
  warn-and-load migration text, with defined-at `src/config/strict_keys.rs`, where the extractor anchors
  a retired key once its field is gone. The extracted id for the hidden flag (and its env var) is added
  as `INTERNAL`.
- The PR body lists every removed public field (r1, grok):
  - `CapabilityConfig.stale_check_secs`;
  - `CacheConfig.enabled`;
  - `RetryConfig.enabled`;
  - `CircuitBreakerConfig.enabled`;
  - `SignatureChainConfig.max_links`;
  - `ServerConfig.protocol_revision_window`, which stays `pub` but becomes serde-skipped.
- The tests/fixtures/mik_8425_yaml/url_render.txt golden and any config-schema golden are updated, along
  with the duration_bound pin if a duration field moves.

## Not in scope

`failsafe.rate_limit.enabled` and `failsafe.health_check.enabled` (MIK-8784/8785, v4.0.1), `max_segment_bytes` (kept;
doc note per comment 6e8a6c4d), and the firewall thresholds (kept).

## Falsifier

Stop and report if: a removed switch is the only escape from an incident; the top-level flag or env var
cannot reach the window on some serving path; or a golden that other 4.0.0 work depends on cannot be updated in this PR.
