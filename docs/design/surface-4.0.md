# 4.0 user-facing surface: inventory and classification

Ticket: MIK-8044, piece P1. Scope file: `.git/lead-decisions/scoping/surface-tightening.json`.

The operator asked for a tight public surface: anything a normal user does not need to set up or run the
gateway becomes internal, and the gateway decides what it can decide on its own. This document lists every
item on the five surfaces a user can touch, gives each one a class, and says what happens to an existing
user of anything that is not kept. Pieces P2 to P6 implement it; nothing here changes code.

`python3 scripts/release/check_surface_inventory.py` extracts the five surfaces from the source and fails
when any item is missing from the tables below, is listed twice, carries no valid class, has no migration
story, or no longer exists. `--summary` prints the counts. The check runs in CI through
`scripts/release/test_check_surface_inventory.py`.

What the check guards against: a contributor adding a config key, flag, variable, route or crate-root
item in the forms this codebase uses (serde derives, clap derives, axum `route`/`nest` calls in either
call form, `pub` items in `src/lib.rs`, `#[macro_export]` macros in any module the library compiles) without classifying it. It reads
source text, not compiled types, so it is not a proof against code written to evade it; a construct it
cannot read is added to the extractor, with a planted-source test, when the codebase first uses it.

## Classes

| Class | Meaning | What the user sees in 4.0 |
|---|---|---|
| KEEP | A normal user needs it to set up or run the gateway. | Documented in the user reference. |
| AUTO | The gateway derives or tunes it. Each row names the derivation. | Gone from the reference. Unset, the gateway derives it; a set value stays honoured as a hidden key. |
| INTERNAL | Crate-private, hidden, a fixed default, or dev/test-only. | Gone from the reference. A config key or variable becomes a hidden key: still read and validated, so nothing an operator set stops applying, and `doctor` lists it when set. A command is hidden from `--help`; a route stays mounted and leaves the reference; a lib item leaves docs.rs. |
| REMOVE | Dead or redundant. | Refused with a message naming the replacement; `upgrade` deletes it. |

So in 4.0 no config key or variable that a 3.x user set stops applying unless it already had no effect
(REMOVE). The surface shrinks where users meet it: the reference, `init`, the examples and `--help`.
A variable only a test script or an example reads is documented as such; nothing changes in the binary.

## Who is a normal user

The evidence for "needs it" is what the gateway's own setup paths write and what the user docs tell a user
to set:

- `mcp-gateway init` (src/commands/mod.rs:133): `server.host`, `server.port`, `auth.enabled`,
  `auth.bearer_token`, `auth.single_user`, `auth.public_paths`, `security.transparency_log.enabled`,
  `meta_mcp.enabled`, `meta_mcp.cache_tools`, `meta_mcp.cache_ttl`, `capabilities.enabled`,
  `capabilities.directories`, `backends`.
- QUICKSTART.md, README.md, gateway.example.yaml for the single-user path.
- TEAM_DEPLOYMENT.md, MULTI_USER.md, OAUTH_CONFIG.md, SECURITY_POSTURE.md, WEBHOOKS.md, EVENTS.md,
  CODE_MODE.md, control_plane.md and OWASP_AGENTIC_AI_COMPLIANCE.md for the documented deployment shapes.

Three of the `init` keys are not needed: `meta_mcp.enabled` and `meta_mcp.cache_ttl` restate defaults,
and `meta_mcp.cache_tools` is read by nothing (MIK-8064). In 4.0 `init` writes KEEP keys only, and only
where the value differs from the default or is a credential.

## Rules the classification follows

1. **Security controls keep their behaviour.** A control that is opt-in stays reachable, so its switch
   and its policy lists stay KEEP. Its thresholds, windows and per-principal caps become hidden keys.
   No default changes.
2. **Security opt-outs stay explicit.** `server.allow_unauthenticated_network_bind`,
   `server.cleartext_http`, `backends.<name>.passthrough`, `allow_flagged_tools`,
   `allow_cleartext_credentials` and `input_schema_enforcement` are KEEP. Hiding an opt-out would turn a
   deliberate operator decision into a silent one.
3. **Operator intent is KEEP; tuning is not.** Endpoints, credentials, identities, allow and deny lists,
   budgets, feature switches and sandbox resource limits (`runtime.profiles.<name>.resources`,
   `restart`) carry information only the operator has. Retry, breaker, cache, buffer,
   queue, TTL, poll and capacity numbers do not: they become INTERNAL (hidden keys). Retention and
   eviction policies (audit rotation, dead-letter retention) are operator intent and stay KEEP.
   "Budget" in this rule means a guard or cost budget, not store capacity. A feature switch is a key that turns a
   mechanism on or off (`enabled`, `action`, a source toggle); it is KEEP. A hidden key that refuses a
   request names itself and `mcp-gateway doctor` in the error, so it stays findable where it bites (P2).
4. **AUTO only with a concrete derivation**, each one becomes P2 work with a red-then-green test. Where
   the gateway already derives the value (transport detection, protocol negotiation) AUTO is cheap;
   elsewhere the row says what to build.
5. **State locations stay KEEP.** Deployments put state on chosen volumes; the Helm chart writes the
   audit log to its own persistent volume, apart from the ephemeral HOME.
6. **The env overlay follows the config key.** `MCP_GATEWAY_<SECTION>__<KEY>` stays as the container form
   of any KEEP key; an overlay naming a non-KEEP key gets the key's treatment.
7. **The library is not a product surface.** README documents no library use and no crate in the
   workspace depends on it. Every crate-root item becomes INTERNAL: `#[doc(hidden)] pub` where the binary
   needs it, a `#[doc(hidden)] pub mod test_support` re-export where only tests need it, and `pub(crate)`
   where nothing outside uses it.

## Decisions by area

Generated from the tables at the end; each row there carries the reason and migration.

### config

| Area | KEEP | AUTO | INTERNAL, hidden but honoured | INTERNAL | REMOVE |
|---|---|---|---|---|---|
| `_*` | 1 |  |  |  |  |
| `accounts` | 45 | `schema_version` | `adapters[].clock_skew_seconds`; `adapters[].max_lifetime_seconds`; `limits`; `limits.authority_bytes`; `limits.journeys_created_per_minute`; `limits.journeys_per_user`; `limits.journeys_total`; `limits.starts_per_minute_per_user`; `limits.store_entries` |  |  |
| `agent_auth` | 10 |  |  |  |  |
| `auth` | 17 |  | `client_circuit_breaker.failure_threshold`; `client_circuit_breaker.reset_timeout`; `client_circuit_breaker.success_threshold`; `dashboard_session`; `dashboard_session.absolute_timeout_secs`; `dashboard_session.idle_timeout_secs` |  | `api_keys[].key` |
| `backends` | 44 | `<name>.oauth.token_refresh_buffer_secs`; `<name>.protocol_version`; `<name>.streamable_http` | `<name>.a2a_agent_card_path`; `<name>.max_frame_bytes` |  | `<name>.circuit_breaker`; `<name>.idle_timeout` |
| `cache` | 2 |  | `default_ttl`; `max_entries` |  |  |
| `capabilities` | 12 |  | `files.downloads_quota_bytes`; `name` |  |  |
| `code_mode` | 2 |  |  |  |  |
| `control_plane` | 12 |  | `export.max_batch`; `export.poll_interval_secs` |  |  |
| `cost_governance` | 12 |  |  |  | `currency` |
| `default_routing_profile` | 1 |  |  |  |  |
| `env_files` | 1 |  |  |  |  |
| `error_budget` |  |  | `error_budget`; `capability`; `capability.cooldown`; `capability.min_samples`; `capability.threshold`; `capability.window_duration`; `capability.window_size`; `min_samples`; `threshold`; `window_duration`; `window_size` |  |  |
| `events` | 13 |  | `dead_letter_max_bytes`; `dead_letter_max_records`; `default_ttl`; `max_in_flight`; `max_outbox`; `max_outbox_per_subscription`; `max_subscriptions`; `max_subscriptions_per_principal`; `max_ttl`; `max_verified_tail`; `max_verified_tail_per_principal`; `min_ttl`; `queue_depth`; `rate_limit_per_subscription`; `rate_limit_per_subscription.burst`; `rate_limit_per_subscription.per_minute`; `retry_base`; `retry_max_attempts`; `retry_window`; `schedule`; `schedule.max_timers`; `schedule.max_timers_per_principal`; `secret_rotation_grace`; `seen_max_per_route`; `suspend_min_attempts`; `suspend_window`; `verification_per_host_per_minute`; `verified_tail_ttl`; `watch`; `watch.max_pollers`; `watch.max_pollers_per_principal` |  |  |
| `failsafe` | 9 |  | `circuit_breaker.failure_threshold`; `circuit_breaker.reset_timeout`; `circuit_breaker.success_threshold`; `health_check.interval`; `health_check.timeout`; `rate_limit.burst_size`; `rate_limit.requests_per_second`; `retry.initial_backoff`; `retry.max_attempts`; `retry.max_backoff`; `retry.multiplier` |  |  |
| `idempotency` | 4 |  |  |  |  |
| `key_server` | 20 | `oidc[].auto_discover` | `cleanup_interval_secs`; `max_oidc_token_age_secs`; `max_tokens_per_identity`; `token_ttl_secs` |  |  |
| `marketplace` |  |  |  |  | `marketplace` |
| `meta_mcp` | 8 | `prompts_resources_fetch_timeout` | `cache_ttl`; `projection_mode` |  | `cache_tools` |
| `mtls` | 20 |  |  |  |  |
| `playbooks` | 3 |  |  |  |  |
| `routing_profiles` | 6 |  |  |  |  |
| `runtime` | 30 |  |  |  |  |
| `security` | 120 |  | `firewall.anomaly_min_observations`; `firewall.anomaly_threshold`; `firewall.collusion.common_principals`; `firewall.collusion.min_matches`; `firewall.collusion.window_secs`; `firewall.memory_poisoning.max_entry_size_bytes`; `message_signing.replay_window` |  |  |
| `server` | 11 |  | `max_body_size`; `shutdown_timeout` |  | `request_timeout`; `ws_port` |
| `streaming` | 3 |  | `buffer_size`; `keep_alive_interval`; `session_reaper_interval`; `session_ttl` |  |  |
| `tasks` | 3 |  | `default_ttl_ms`; `expiry_interval`; `logical_budget_bytes`; `max_per_principal`; `max_record_bytes`; `max_records`; `max_workers`; `poll_interval_ms` |  |  |
| `webhooks` | 4 |  | `rate_limit` |  |  |
| `x-*` | 1 |  |  |  |  |

### cli

| Area | KEEP | AUTO | INTERNAL, hidden but honoured | INTERNAL | REMOVE |
|---|---|---|---|---|---|
| `(global)` | 11 |  |  |  |  |
| `accounts` | 6 |  |  |  |  |
| `add` | 9 |  |  |  | `mcp-gateway add --config`; `mcp-gateway add -c` |
| `audit` | 8 |  |  |  |  |
| `cap` | 50 |  |  |  |  |
| `dashboard-link` | 6 |  |  |  |  |
| `doctor` | 10 |  |  |  |  |
| `events` | 12 |  |  |  |  |
| `get` | 2 |  |  |  | `mcp-gateway get --config`; `mcp-gateway get -c` |
| `hash-key` | 2 |  |  |  |  |
| `identity` | 32 |  |  |  |  |
| `import` | 18 |  |  |  |  |
| `init` | 5 |  |  |  |  |
| `kubernetes` |  |  |  | `mcp-gateway kubernetes`; `mcp-gateway kubernetes apply-plan`; `mcp-gateway kubernetes apply-plan --approve-apply`; `mcp-gateway kubernetes apply-plan --execute`; `mcp-gateway kubernetes apply-plan --format`; `mcp-gateway kubernetes apply-plan --namespace`; `mcp-gateway kubernetes apply-plan -f`; `mcp-gateway kubernetes apply-plan -n`; `mcp-gateway kubernetes apply-plan <resources>`; `mcp-gateway kubernetes controller`; `mcp-gateway kubernetes controller --cycles`; `mcp-gateway kubernetes controller --format`; `mcp-gateway kubernetes controller --interval-seconds`; `mcp-gateway kubernetes controller --namespace`; `mcp-gateway kubernetes controller --watch`; `mcp-gateway kubernetes controller -f`; `mcp-gateway kubernetes controller -n`; `mcp-gateway kubernetes controller <resources>`; `mcp-gateway kubernetes plan`; `mcp-gateway kubernetes plan --format`; `mcp-gateway kubernetes plan --namespace`; `mcp-gateway kubernetes plan -f`; `mcp-gateway kubernetes plan -n`; `mcp-gateway kubernetes plan <resources>` |  |
| `list` | 3 |  |  |  | `mcp-gateway list --config`; `mcp-gateway list -c` |
| `ranking` |  |  |  | `mcp-gateway ranking`; `mcp-gateway ranking eval`; `mcp-gateway ranking eval --format`; `mcp-gateway ranking eval -f`; `mcp-gateway ranking eval <file>` |  |
| `remove` | 3 |  |  |  | `mcp-gateway remove --config`; `mcp-gateway remove -c` |
| `runtime` |  |  |  | `mcp-gateway runtime`; `mcp-gateway runtime compile`; `mcp-gateway runtime compile --both`; `mcp-gateway runtime compile <DESCRIPTOR>` |  |
| `serve` | 2 |  |  |  |  |
| `setup` | 20 |  |  |  |  |
| `skills` | 21 | `mcp-gateway skills generate --capabilities`; `mcp-gateway skills generate -C` |  |  |  |
| `stats` | 3 |  |  |  |  |
| `tls` | 23 |  |  |  |  |
| `tool` | 17 | `mcp-gateway tool completions --capabilities`; `mcp-gateway tool completions -C`; `mcp-gateway tool inspect --capabilities`; `mcp-gateway tool inspect -C`; `mcp-gateway tool invoke --capabilities`; `mcp-gateway tool invoke -C`; `mcp-gateway tool list --capabilities`; `mcp-gateway tool list -C` |  |  |  |
| `trust` |  |  |  | `mcp-gateway trust`; `mcp-gateway trust generate`; `mcp-gateway trust generate --capabilities`; `mcp-gateway trust generate --format`; `mcp-gateway trust generate --output`; `mcp-gateway trust generate -C`; `mcp-gateway trust generate -f`; `mcp-gateway trust generate -o`; `mcp-gateway trust inspect`; `mcp-gateway trust inspect --capabilities`; `mcp-gateway trust inspect --format`; `mcp-gateway trust inspect -C`; `mcp-gateway trust inspect -f`; `mcp-gateway trust inspect <name>`; `mcp-gateway trust lab`; `mcp-gateway trust lab evaluate`; `mcp-gateway trust lab evaluate --active-fixtures`; `mcp-gateway trust lab evaluate --baseline`; `mcp-gateway trust lab evaluate --baseline-id`; `mcp-gateway trust lab evaluate --baseline-registry`; `mcp-gateway trust lab evaluate --capabilities`; `mcp-gateway trust lab evaluate --certification-score`; `mcp-gateway trust lab evaluate --enforce`; `mcp-gateway trust lab evaluate --execute-active-fixtures`; `mcp-gateway trust lab evaluate --format`; `mcp-gateway trust lab evaluate --minimum-score`; `mcp-gateway trust lab evaluate --runtime-image`; `mcp-gateway trust lab evaluate --runtime-provider-plan`; `mcp-gateway trust lab evaluate --update-baseline-registry`; `mcp-gateway trust lab evaluate --write-baseline`; `mcp-gateway trust lab evaluate -C`; `mcp-gateway trust lab evaluate -f`; `mcp-gateway trust lab evaluate <name>`; `mcp-gateway trust validate`; `mcp-gateway trust validate --capabilities`; `mcp-gateway trust validate --file`; `mcp-gateway trust validate --format`; `mcp-gateway trust validate --strict`; `mcp-gateway trust validate -C`; `mcp-gateway trust validate -f` |  |
| `upgrade` | 5 |  |  |  |  |
| `validate` | 7 | `mcp-gateway validate --no-color` |  |  |  |

### env

| Area | KEEP | AUTO | INTERNAL, hidden but honoured | INTERNAL | REMOVE |
|---|---|---|---|---|---|
| `env` | 19 | `MCP_GATEWAY_CAPABILITIES` |  | `MCP_GATEWAY_KIND_CLUSTER`; `MCP_GATEWAY_KIND_KEEP`; `MCP_GATEWAY_KIND_NAMESPACE`; `MCP_GATEWAY_ROLLOUT_TIMEOUT`; `MCP_GATEWAY_RUNTIME_DOCKER_IMAGE`; `MCP_GATEWAY_RUNTIME_DOCKER_RESTART_IMAGE`; `MCP_GATEWAY_RUNTIME_DOCKER_SMOKE`; `MCP_GATEWAY_TEST_ERA_PROBE_CAP_MS`; `MCP_GATEWAY_TEST_HOLD_CAPABILITY_SCAN`; `MCP_GATEWAY_TEST_HOME_DIR`; `MCP_GATEWAY_TEST_PAUSE_AT_PUBLISHED` |  |

### routes

| Area | KEEP | AUTO | INTERNAL, hidden but honoured | INTERNAL | REMOVE |
|---|---|---|---|---|---|
| `/.well-known` | 2 |  |  |  |  |
| `/accounts` | 9 |  |  |  |  |
| `/api` | 1 |  |  |  |  |
| `/auth` | 3 |  |  |  |  |
| `/dashboard` | 3 |  |  |  |  |
| `/health` | 1 |  |  |  |  |
| `/livez` | 1 |  |  |  |  |
| `/mcp` | 2 |  |  |  |  |
| `/metrics` | 1 |  |  |  |  |
| `/readyz` | 1 |  |  |  |  |
| `/sse` |  |  |  | `/sse` |  |
| `/ui` | 1 |  |  | `/ui/api/backends`; `/ui/api/backends/{name}`; `/ui/api/backends/{name}/revive`; `/ui/api/capabilities`; `/ui/api/capabilities/{name}`; `/ui/api/config`; `/ui/api/control-plane`; `/ui/api/control-plane/decisions`; `/ui/api/control-plane/export-status`; `/ui/api/control-plane/grants`; `/ui/api/control-plane/policies`; `/ui/api/costs`; `/ui/api/dashboard-link`; `/ui/api/events/dead-letters`; `/ui/api/events/dead-letters/replay`; `/ui/api/events/dead-letters/{id}/replay`; `/ui/api/events/held`; `/ui/api/import/openapi`; `/ui/api/import/openapi/preview`; `/ui/api/registry`; `/ui/api/registry/search`; `/ui/api/reload`; `/ui/api/status`; `/ui/api/tools` |  |
| `config-driven` | 3 |  |  |  |  |

### lib

| Area | KEEP | AUTO | INTERNAL, hidden but honoured | INTERNAL | REMOVE |
|---|---|---|---|---|---|
| `lib` |  |  |  | 65 |  |


## Findings filed on the way (0-bug rule)

| Ticket | Finding |
|---|---|
| MIK-8063 | An `a2a_url` backend loads but can never start: nothing outside `src/a2a` builds an `A2aProvider`, and `Backend::start` returns an error (src/backend/lifecycle.rs:487). `a2a_agent_card_path` is read by nothing. |
| MIK-8064 | `meta_mcp.cache_tools` is read by nothing; `init` writes it. |

## Pending and held items

| Item | Decision |
|---|---|
| A2A | Operator decision 2026-10-07: the outbound A2A bridge is finished for 4.0 (MIK-8063). `backends.<name>.a2a_url` is KEEP; `a2a_agent_card_path` is a hidden key defaulting to the spec's well-known path; the `a2a` module and default feature stay. Inbound A2A is out of scope. |
| A2A card path default | Done in MIK-8063 PR1 (#3401): A2A 1.0 is pinned, and the card is read from `/.well-known/agent-card.json` unless `a2a_agent_card_path` is set. |
| `meta_mcp.cache_tools` | REMOVE (MIK-8064). |
| Capability `trawl_extract` and the `cisco_scanner` operation `scan_mcp_server` | Held until 4.1 (MIK-7788): the gateway cannot confine where these tools connect. Capability files are outside the five surfaces, so they have no table row. Class INTERNAL: the definitions stay in the tree, refuse to run and are not offered to clients; they leave the user docs until 4.1. |

## The minimal setup after 4.0

```yaml
server:
  port: 39400
auth:
  enabled: true
  bearer_token: "<generated by init>"
  single_user: true
  public_paths: ["/health", "/mcp"]
security:
  transparency_log:
    enabled: true   # required while auth is on
backends:
  my-server:
    command: "npx -y @my/mcp-server"
```

## Not covered here

- The MCP wire protocol and capability YAML files: defined by the MCP spec and the capability format.
- `crates/gateway-core`: a separate crate that does not depend on this one.
- Security control semantics and the web UI's look: excluded by the scope file.

## Library consumers

Every lib item becomes INTERNAL. crates.io lists no reverse dependencies for `mcp-gateway`
(checked 2026-10-07), so no published crate builds on the library.

## Surface: config

| Item | Class | Default | Reason | Migration | Defined at |
|---|---|---|---|---|---|
| `accounts` | KEEP | `type default` | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/config/mod.rs:153 |
| `accounts.adapters` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/personal_accounts/config.rs:223 |
| `accounts.adapters[].allowed_api_key_names` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/personal_accounts/config/adapters.rs:108 |
| `accounts.adapters[].clock_skew_seconds` | INTERNAL | `DEFAULT_CLOCK_SKEW_SECONDS` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/personal_accounts/config/adapters.rs:112 |
| `accounts.adapters[].header` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/personal_accounts/config/adapters.rs:100 |
| `accounts.adapters[].hmac_secret_ref` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/personal_accounts/config/adapters.rs:105 |
| `accounts.adapters[].installation_id` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/personal_accounts/config/adapters.rs:98 |
| `accounts.adapters[].issuer` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/personal_accounts/config/adapters.rs:102 |
| `accounts.adapters[].kind` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/personal_accounts/config/adapters.rs:96 |
| `accounts.adapters[].max_lifetime_seconds` | INTERNAL | `DEFAULT_MAX_LIFETIME_SECONDS` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/personal_accounts/config/adapters.rs:110 |
| `accounts.adapters[].session` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/personal_accounts/config/adapters.rs:116 |
| `accounts.adapters[].session.cookie_name` | KEEP | `"token".to_string()` | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/personal_accounts/config/journey.rs:49 |
| `accounts.adapters[].session.user_endpoint` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/personal_accounts/config/journey.rs:46 |
| `accounts.authority_dir` | KEEP | — | state location; deployments put it on a chosen volume (the Helm chart puts the audit log on its own persistent volume) | - | src/personal_accounts/config.rs:201 |
| `accounts.current_key_id` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/personal_accounts/config.rs:203 |
| `accounts.deployment` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/personal_accounts/config.rs:198 |
| `accounts.descriptors` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/personal_accounts/config.rs:212 |
| `accounts.descriptors.<name>.authorization_endpoint` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/personal_accounts/config.rs:268 |
| `accounts.descriptors.<name>.authorize_extra` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/personal_accounts/config.rs:297 |
| `accounts.descriptors.<name>.authorize_extra.access_type` | KEEP | `type default` | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/personal_accounts/config/journey.rs:63 |
| `accounts.descriptors.<name>.authorize_extra.include_granted_scopes` | KEEP | `type default` | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/personal_accounts/config/journey.rs:67 |
| `accounts.descriptors.<name>.authorize_extra.prompt` | KEEP | `type default` | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/personal_accounts/config/journey.rs:65 |
| `accounts.descriptors.<name>.client_id` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/personal_accounts/config.rs:275 |
| `accounts.descriptors.<name>.client_secret_ref` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/personal_accounts/config.rs:280 |
| `accounts.descriptors.<name>.external_strategy` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/personal_accounts/config.rs:294 |
| `accounts.descriptors.<name>.external_strategy.audience` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/identity_propagation/mod.rs:235 |
| `accounts.descriptors.<name>.external_strategy.required` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/identity_propagation/mod.rs:240 |
| `accounts.descriptors.<name>.external_strategy.session_mode` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/identity_propagation/mod.rs:242 |
| `accounts.descriptors.<name>.external_strategy.strategy` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/identity_propagation/mod.rs:233 |
| `accounts.descriptors.<name>.external_strategy.token_exchange_endpoint` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/identity_propagation/mod.rs:246 |
| `accounts.descriptors.<name>.external_strategy.token_exchange_scope` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/identity_propagation/mod.rs:249 |
| `accounts.descriptors.<name>.issuer` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/personal_accounts/config.rs:266 |
| `accounts.descriptors.<name>.mode` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/personal_accounts/config.rs:259 |
| `accounts.descriptors.<name>.provider` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/personal_accounts/config.rs:262 |
| `accounts.descriptors.<name>.redirect_uri` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/personal_accounts/config.rs:282 |
| `accounts.descriptors.<name>.resource` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/personal_accounts/config.rs:264 |
| `accounts.descriptors.<name>.revocation_endpoint` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/personal_accounts/config.rs:273 |
| `accounts.descriptors.<name>.scopes` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/personal_accounts/config.rs:284 |
| `accounts.descriptors.<name>.send_resource_parameter` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/personal_accounts/config.rs:286 |
| `accounts.descriptors.<name>.token_endpoint` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/personal_accounts/config.rs:270 |
| `accounts.enabled` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/personal_accounts/config.rs:196 |
| `accounts.hosted` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/personal_accounts/config.rs:227 |
| `accounts.hosted.public_origin` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/personal_accounts/config/journey.rs:34 |
| `accounts.hosted.return_paths` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/personal_accounts/config/journey.rs:37 |
| `accounts.instance_id` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/personal_accounts/config.rs:199 |
| `accounts.keys` | KEEP | — | managed personal-account custody (MULTI_USER.md); strict schema `accounts.v1` | - | src/personal_accounts/config.rs:205 |
| `accounts.limits` | INTERNAL | — | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/personal_accounts/config.rs:214 |
| `accounts.limits.authority_bytes` | INTERNAL | `16_777_216` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/personal_accounts/config/limits.rs:31 |
| `accounts.limits.journeys_created_per_minute` | INTERNAL | `120` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/personal_accounts/config/limits.rs:41 |
| `accounts.limits.journeys_per_user` | INTERNAL | `8` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/personal_accounts/config/limits.rs:36 |
| `accounts.limits.journeys_total` | INTERNAL | `1024` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/personal_accounts/config/limits.rs:33 |
| `accounts.limits.starts_per_minute_per_user` | INTERNAL | `10` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/personal_accounts/config/limits.rs:38 |
| `accounts.limits.store_entries` | INTERNAL | `10000` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/personal_accounts/config/limits.rs:28 |
| `accounts.schema_version` | AUTO | — | `accounts.v1` is the only accepted value; default it | accepted when it equals `accounts.v1`; `upgrade` deletes it | src/personal_accounts/config.rs:193 |
| `accounts.store_dir` | KEEP | — | state location; deployments put it on a chosen volume (the Helm chart puts the audit log on its own persistent volume) | - | src/personal_accounts/config.rs:200 |
| `agent_auth` | KEEP | `type default` | transport and token identity for team deployments (MULTI_USER.md) | - | src/config/mod.rs:135 |
| `agent_auth.agents` | KEEP | `type default` | transport and token identity for team deployments (MULTI_USER.md) | - | src/config/features/auth.rs:331 |
| `agent_auth.agents[].audience` | KEEP | — | transport and token identity for team deployments (MULTI_USER.md) | - | src/config/features/auth.rs:363 |
| `agent_auth.agents[].client_id` | KEEP | — | transport and token identity for team deployments (MULTI_USER.md) | - | src/config/features/auth.rs:338 |
| `agent_auth.agents[].hs256_secret` | KEEP | — | transport and token identity for team deployments (MULTI_USER.md) | - | src/config/features/auth.rs:343 |
| `agent_auth.agents[].issuer` | KEEP | — | transport and token identity for team deployments (MULTI_USER.md) | - | src/config/features/auth.rs:352 |
| `agent_auth.agents[].name` | KEEP | — | transport and token identity for team deployments (MULTI_USER.md) | - | src/config/features/auth.rs:340 |
| `agent_auth.agents[].rs256_public_key` | KEEP | — | transport and token identity for team deployments (MULTI_USER.md) | - | src/config/features/auth.rs:346 |
| `agent_auth.agents[].scopes` | KEEP | — | transport and token identity for team deployments (MULTI_USER.md) | - | src/config/features/auth.rs:349 |
| `agent_auth.enabled` | KEEP | `type default` | transport and token identity for team deployments (MULTI_USER.md) | - | src/config/features/auth.rs:328 |
| `auth` | KEEP | `type default` | who may call the gateway | - | src/config/mod.rs:95 |
| `auth.api_keys` | KEEP | `Vec::new()` | who may call the gateway | - | src/config/features/auth.rs:25 |
| `auth.api_keys[].admin` | KEEP | — | who may call the gateway | - | src/config/features/api_key.rs:98 |
| `auth.api_keys[].allowed_tools` | KEEP | — | who may call the gateway | - | src/config/features/api_key.rs:91 |
| `auth.api_keys[].backends` | KEEP | — | who may call the gateway | - | src/config/features/api_key.rs:87 |
| `auth.api_keys[].denied_tools` | KEEP | — | who may call the gateway | - | src/config/features/api_key.rs:95 |
| `auth.api_keys[].expires_at` | KEEP | — | who may call the gateway | - | src/config/features/api_key.rs:77 |
| `auth.api_keys[].key` | REMOVE | — | legacy plaintext key, parsed only to be refused | already refused naming `key_sha256`; `upgrade` rewrites it via `hash-key` | src/config/features/api_key.rs:70 |
| `auth.api_keys[].key_sha256` | KEEP | — | who may call the gateway | - | src/config/features/api_key.rs:74 |
| `auth.api_keys[].kind` | KEEP | — | who may call the gateway | - | src/config/features/api_key.rs:101 |
| `auth.api_keys[].name` | KEEP | — | who may call the gateway | - | src/config/features/api_key.rs:81 |
| `auth.api_keys[].rate_limit` | KEEP | — | who may call the gateway | - | src/config/features/api_key.rs:84 |
| `auth.bearer_token` | KEEP | `None` | who may call the gateway | - | src/config/features/auth.rs:22 |
| `auth.client_circuit_breaker` | KEEP | `None` | opt-in per-client circuit breaker | - | src/config/features/auth.rs:32 |
| `auth.client_circuit_breaker.enabled` | KEEP | `true` | opt-in per-client circuit breaker | - | src/config/features/failsafe.rs:52 |
| `auth.client_circuit_breaker.failure_threshold` | INTERNAL | `DEFAULT_CIRCUIT_BREAKER_FAILURE_THRESHOLD` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/failsafe.rs:54 |
| `auth.client_circuit_breaker.reset_timeout` | INTERNAL | `Duration::from_secs(DEFAULT_CIRCUIT_BREAKER_RESET_TIMEOUT_SE` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/failsafe.rs:59 |
| `auth.client_circuit_breaker.success_threshold` | INTERNAL | `DEFAULT_CIRCUIT_BREAKER_SUCCESS_THRESHOLD` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/failsafe.rs:56 |
| `auth.dashboard_session` | INTERNAL | `DashboardSessionConfig::default()` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/auth.rs:48 |
| `auth.dashboard_session.absolute_timeout_secs` | INTERNAL | `28_800` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/auth.rs:63 |
| `auth.dashboard_session.idle_timeout_secs` | INTERNAL | `1800` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/auth.rs:61 |
| `auth.enabled` | KEEP | `false` | who may call the gateway | - | src/config/features/auth.rs:18 |
| `auth.public_paths` | KEEP | `vec!["/health".to_string()]` | who may call the gateway | - | src/config/features/auth.rs:29 |
| `auth.single_user` | KEEP | `false` | who may call the gateway | - | src/config/features/auth.rs:45 |
| `backends` | KEEP | `type default` | how a user declares a backend and its credentials | - | src/config/mod.rs:105 |
| `backends.<name>.a2a_agent_card_path` | INTERNAL | `see impl Default` | unset: the A2A 1.0 well-known path `/.well-known/agent-card.json` on the origin of `a2a_url` (src/a2a/types.rs:14); an override only for a non-standard agent | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/backend_config.rs:270 |
| `backends.<name>.a2a_url` | KEEP | `see impl Default` | outbound A2A backend endpoint; operator decision 2026-10-07: the outbound bridge ships in 4.0 (MIK-8063) | - | src/config/backend_config.rs:270 |
| `backends.<name>.account` | KEEP | `None` | how a user declares a backend and its credentials | - | src/config/backend_config.rs:99 |
| `backends.<name>.allow_cleartext_credentials` | KEEP | `false` | per-backend security opt-out; stays explicit | - | src/config/backend_config.rs:83 |
| `backends.<name>.allow_flagged_tools` | KEEP | `std::collections::BTreeMap::new()` | per-backend security opt-out; stays explicit | - | src/config/backend_config.rs:70 |
| `backends.<name>.chain_origins` | KEEP | `Vec::new()` | multi-user and provenance deployments (MULTI_USER.md) | - | src/config/backend_config.rs:104 |
| `backends.<name>.chain_signer` | KEEP | `None` | multi-user and provenance deployments (MULTI_USER.md) | - | src/config/backend_config.rs:106 |
| `backends.<name>.circuit_breaker` | REMOVE | — | retired in 4.0; never had an effect | already warns once; 4.0.0 makes it a load error and `upgrade` deletes it | src/config/strict_keys.rs:33 |
| `backends.<name>.command` | KEEP | `see impl Default` | how a user declares a backend and its credentials | - | src/config/backend_config.rs:220 |
| `backends.<name>.cwd` | KEEP | `see impl Default` | how a user declares a backend and its credentials | - | src/config/backend_config.rs:220 |
| `backends.<name>.description` | KEEP | `String::new()` | how a user declares a backend and its credentials | - | src/config/backend_config.rs:16 |
| `backends.<name>.enabled` | KEEP | `true` | how a user declares a backend and its credentials | - | src/config/backend_config.rs:18 |
| `backends.<name>.env` | KEEP | `HashMap::new()` | how a user declares a backend and its credentials | - | src/config/backend_config.rs:45 |
| `backends.<name>.headers` | KEEP | `HashMap::new()` | how a user declares a backend and its credentials | - | src/config/backend_config.rs:48 |
| `backends.<name>.http_url` | KEEP | `String::new()` | how a user declares a backend and its credentials | - | src/config/backend_config.rs:231 |
| `backends.<name>.identity_propagation` | KEEP | `None` | multi-user and provenance deployments (MULTI_USER.md) | - | src/config/backend_config.rs:92 |
| `backends.<name>.identity_propagation.audience` | KEEP | — | multi-user and provenance deployments (MULTI_USER.md) | - | src/identity_propagation/mod.rs:235 |
| `backends.<name>.identity_propagation.required` | KEEP | — | multi-user and provenance deployments (MULTI_USER.md) | - | src/identity_propagation/mod.rs:240 |
| `backends.<name>.identity_propagation.session_mode` | KEEP | — | multi-user and provenance deployments (MULTI_USER.md) | - | src/identity_propagation/mod.rs:242 |
| `backends.<name>.identity_propagation.strategy` | KEEP | — | multi-user and provenance deployments (MULTI_USER.md) | - | src/identity_propagation/mod.rs:233 |
| `backends.<name>.identity_propagation.token_exchange_endpoint` | KEEP | — | multi-user and provenance deployments (MULTI_USER.md) | - | src/identity_propagation/mod.rs:246 |
| `backends.<name>.identity_propagation.token_exchange_scope` | KEEP | — | multi-user and provenance deployments (MULTI_USER.md) | - | src/identity_propagation/mod.rs:249 |
| `backends.<name>.idle_timeout` | REMOVE | — | retired in 4.0; never had an effect | already warns once; 4.0.0 makes it a load error and `upgrade` deletes it | src/config/strict_keys.rs:28 |
| `backends.<name>.input_schema_enforcement` | KEEP | `InputSchemaEnforcement::Closed` | per-backend security opt-out; stays explicit | - | src/config/backend_config.rs:72 |
| `backends.<name>.max_frame_bytes` | INTERNAL | `None` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/backend_config.rs:40 |
| `backends.<name>.oauth` | KEEP | `None` | how a user declares a backend and its credentials | - | src/config/backend_config.rs:51 |
| `backends.<name>.oauth.callback_host` | KEEP | — | a set loopback literal is what the redirect URI advertises; providers match it exactly | - | src/config/backend_config.rs:158 |
| `backends.<name>.oauth.callback_path` | KEEP | — | providers that pin an exact redirect URI (Slack, Figma) need it | - | src/config/backend_config.rs:169 |
| `backends.<name>.oauth.callback_port` | KEEP | — | providers that pin an exact redirect URI (Slack, Figma) need it | - | src/config/backend_config.rs:164 |
| `backends.<name>.oauth.client_id` | KEEP | — | how a user declares a backend and its credentials | - | src/config/backend_config.rs:147 |
| `backends.<name>.oauth.client_secret` | KEEP | — | how a user declares a backend and its credentials | - | src/config/backend_config.rs:151 |
| `backends.<name>.oauth.enabled` | KEEP | `true` | how a user declares a backend and its credentials | - | src/config/backend_config.rs:141 |
| `backends.<name>.oauth.scopes` | KEEP | — | how a user declares a backend and its credentials | - | src/config/backend_config.rs:144 |
| `backends.<name>.oauth.shared_account` | KEEP | — | how a user declares a backend and its credentials | - | src/config/backend_config.rs:183 |
| `backends.<name>.oauth.token_refresh_buffer_secs` | AUTO | `300` | unset: refresh at max(300 s, 10 % of the token lifetime) before expiry, today's 300 s as the floor | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/backend_config.rs:172 |
| `backends.<name>.passthrough` | KEEP | `false` | per-backend security opt-out; stays explicit | - | src/config/backend_config.rs:65 |
| `backends.<name>.protocol_version` | AUTO | `None` | negotiated in `initialize` | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/backend_config.rs:220 |
| `backends.<name>.runtime_profile` | KEEP | `None` | multi-user and provenance deployments (MULTI_USER.md) | - | src/config/backend_config.rs:86 |
| `backends.<name>.secrets` | KEEP | `Vec::new()` | how a user declares a backend and its credentials | - | src/config/backend_config.rs:54 |
| `backends.<name>.secrets[].credential_type` | KEEP | `CredentialType::ApiKey` | how a user declares a backend and its credentials | - | src/secret_injection.rs:63 |
| `backends.<name>.secrets[].inject_as` | KEEP | — | how a user declares a backend and its credentials | - | src/secret_injection.rs:72 |
| `backends.<name>.secrets[].inject_key` | KEEP | — | how a user declares a backend and its credentials | - | src/secret_injection.rs:78 |
| `backends.<name>.secrets[].name` | KEEP | — | how a user declares a backend and its credentials | - | src/secret_injection.rs:59 |
| `backends.<name>.secrets[].tools` | KEEP | `vec!["*".to_string()]` | how a user declares a backend and its credentials | - | src/secret_injection.rs:83 |
| `backends.<name>.secrets[].value` | KEEP | — | how a user declares a backend and its credentials | - | src/secret_injection.rs:68 |
| `backends.<name>.signature_chain` | KEEP | `ChainMode::Off` | multi-user and provenance deployments (MULTI_USER.md) | - | src/config/backend_config.rs:102 |
| `backends.<name>.stop_when_idle_for` | KEEP | `None` | operator trades memory for cold starts per backend | - | src/config/backend_config.rs:35 |
| `backends.<name>.streamable_http` | AUTO | `None` | already detected at connect (POST first, SSE on 4xx) | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/backend_config.rs:231 |
| `backends.<name>.timeout` | KEEP | `Duration::from_secs(30)` | how a user declares a backend and its credentials | - | src/config/backend_config.rs:43 |
| `backends.<name>.ws_url` | KEEP | `see impl Default` | how a user declares a backend and its credentials | - | src/config/backend_config.rs:246 |
| `cache` | KEEP | `type default` | turn response caching off for side-effecting backends | - | src/config/mod.rs:109 |
| `cache.default_ttl` | INTERNAL | `Duration::from_secs(DEFAULT_TTL_SECS)` | cache sizing with fixed defaults | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/cache.rs:24 |
| `cache.enabled` | KEEP | `true` | turn response caching off for side-effecting backends | - | src/config/features/cache.rs:21 |
| `cache.max_entries` | INTERNAL | `DEFAULT_MAX_ENTRIES` | cache sizing with fixed defaults | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/cache.rs:26 |
| `capabilities` | KEEP | `type default` | where REST capabilities come from and what they may touch | - | src/config/mod.rs:107 |
| `capabilities.directories` | KEEP | `vec!["capabilities".to_string()]` | where REST capabilities come from and what they may touch | - | src/config/features/capability.rs:20 |
| `capabilities.egress_proxy` | KEEP | `None` | where REST capabilities come from and what they may touch | - | src/config/features/capability.rs:30 |
| `capabilities.enabled` | KEEP | `true` | where REST capabilities come from and what they may touch | - | src/config/features/capability.rs:16 |
| `capabilities.files` | KEEP | `FileRoots::default()` | where REST capabilities come from and what they may touch | - | src/config/features/capability.rs:41 |
| `capabilities.files.downloads` | KEEP | `None` | where REST capabilities come from and what they may touch | - | src/config/features/capability.rs:57 |
| `capabilities.files.downloads_quota_bytes` | INTERNAL | `DEFAULT_DOWNLOADS_QUOTA_BYTES` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/capability.rs:59 |
| `capabilities.files.projects` | KEEP | `None` | where REST capabilities come from and what they may touch | - | src/config/features/capability.rs:55 |
| `capabilities.files.uploads` | KEEP | `None` | where REST capabilities come from and what they may touch | - | src/config/features/capability.rs:53 |
| `capabilities.name` | INTERNAL | `"gateway".to_string()` | display name of the built-in capability backend; always `gateway` | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/capability.rs:18 |
| `capabilities.process_commands` | KEEP | `None` | where REST capabilities come from and what they may touch | - | src/config/features/capability.rs:39 |
| `capabilities.process_commands[].args_prefix` | KEEP | — | where REST capabilities come from and what they may touch | - | src/config/features/capability.rs:110 |
| `capabilities.process_commands[].command` | KEEP | — | where REST capabilities come from and what they may touch | - | src/config/features/capability.rs:107 |
| `capabilities.process_execution` | KEEP | `ProcessExecution::Enabled` | where REST capabilities come from and what they may touch | - | src/config/features/capability.rs:34 |
| `code_mode` | KEEP | `type default` | opt-in tool surfaces (CODE_MODE.md) | - | src/config/mod.rs:126 |
| `code_mode.enabled` | KEEP | `type default` | opt-in tool surfaces (CODE_MODE.md) | - | src/config/features/code_mode.rs:24 |
| `control_plane` | KEEP | `type default` | governance roles and SIEM export (control_plane.md) | - | src/config/mod.rs:141 |
| `control_plane.export` | KEEP | `type default` | governance roles and SIEM export (control_plane.md) | - | src/control_plane/role_mapping.rs:32 |
| `control_plane.export.enabled` | KEEP | `false` | governance roles and SIEM export (control_plane.md) | - | src/control_plane/export.rs:342 |
| `control_plane.export.max_batch` | INTERNAL | `LogExporter::DEFAULT_MAX_BATCH` | exporter cadence; fixed defaults | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/control_plane/export.rs:350 |
| `control_plane.export.poll_interval_secs` | INTERNAL | `15` | exporter cadence; fixed defaults | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/control_plane/export.rs:348 |
| `control_plane.export.sink_path` | KEEP | `"~/.mcp-gateway/export/siem.ndjson".to_string()` | governance roles and SIEM export (control_plane.md) | - | src/control_plane/export.rs:346 |
| `control_plane.role_mapping` | KEEP | `type default` | governance roles and SIEM export (control_plane.md) | - | src/control_plane/role_mapping.rs:30 |
| `control_plane.role_mapping.rules` | KEEP | `type default` | governance roles and SIEM export (control_plane.md) | - | src/control_plane/role_mapping.rs:74 |
| `control_plane.role_mapping.rules[].domain` | KEEP | — | governance roles and SIEM export (control_plane.md) | - | src/control_plane/role_mapping.rs:91 |
| `control_plane.role_mapping.rules[].email` | KEEP | — | governance roles and SIEM export (control_plane.md) | - | src/control_plane/role_mapping.rs:88 |
| `control_plane.role_mapping.rules[].group` | KEEP | — | governance roles and SIEM export (control_plane.md) | - | src/control_plane/role_mapping.rs:85 |
| `control_plane.role_mapping.rules[].issuer` | KEEP | — | governance roles and SIEM export (control_plane.md) | - | src/control_plane/role_mapping.rs:82 |
| `control_plane.role_mapping.rules[].role` | KEEP | — | governance roles and SIEM export (control_plane.md) | - | src/control_plane/role_mapping.rs:93 |
| `control_plane.store_dir` | KEEP | `type default` | state location; deployments put it on a chosen volume (the Helm chart puts the audit log on its own persistent volume) | - | src/control_plane/role_mapping.rs:39 |
| `cost_governance` | KEEP | `type default` | budgets and per-tool prices are operator inputs | - | src/config/mod.rs:145 |
| `cost_governance.alerts` | KEEP | `see impl Default` | budgets and per-tool prices are operator inputs | - | src/cost_accounting/config.rs:27 |
| `cost_governance.alerts[].action` | KEEP | — | budgets and per-tool prices are operator inputs | - | src/cost_accounting/config.rs:89 |
| `cost_governance.alerts[].at_percent` | KEEP | — | budgets and per-tool prices are operator inputs | - | src/cost_accounting/config.rs:87 |
| `cost_governance.alternatives` | KEEP | `None` | budgets and per-tool prices are operator inputs | - | src/cost_accounting/config.rs:38 |
| `cost_governance.budgets` | KEEP | `BudgetLimits::default()` | budgets and per-tool prices are operator inputs | - | src/cost_accounting/config.rs:25 |
| `cost_governance.budgets.daily` | KEEP | `type default` | budgets and per-tool prices are operator inputs | - | src/cost_accounting/config.rs:75 |
| `cost_governance.budgets.per_key` | KEEP | `type default` | budgets and per-tool prices are operator inputs | - | src/cost_accounting/config.rs:79 |
| `cost_governance.budgets.per_tool` | KEEP | `type default` | budgets and per-tool prices are operator inputs | - | src/cost_accounting/config.rs:77 |
| `cost_governance.currency` | REMOVE | `"USD".to_string()` | informational only; every value is stored as USD | rejected naming USD; `upgrade` deletes it | src/cost_accounting/config.rs:23 |
| `cost_governance.default_cost` | KEEP | `0.0` | budgets and per-tool prices are operator inputs | - | src/cost_accounting/config.rs:33 |
| `cost_governance.enabled` | KEEP | `false` | budgets and per-tool prices are operator inputs | - | src/cost_accounting/config.rs:21 |
| `cost_governance.tool_costs` | KEEP | `HashMap::new()` | budgets and per-tool prices are operator inputs | - | src/cost_accounting/config.rs:30 |
| `default_routing_profile` | KEEP | `"default".to_string()` | per-session tool scoping | - | src/config/mod.rs:123 |
| `env_files` | KEEP | `type default` | loads secrets from files the user owns | - | src/config/mod.rs:91 |
| `error_budget` | INTERNAL | `type default` | kill-switch thresholds; fixed defaults (GH #475) | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/mod.rs:103 |
| `error_budget.capability` | INTERNAL | `type default` | kill-switch thresholds; fixed defaults (GH #475) | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/error_budget.rs:39 |
| `error_budget.capability.cooldown` | INTERNAL | `type default` | kill-switch thresholds; fixed defaults (GH #475) | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/error_budget.rs:57 |
| `error_budget.capability.min_samples` | INTERNAL | `type default` | kill-switch thresholds; fixed defaults (GH #475) | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/error_budget.rs:54 |
| `error_budget.capability.threshold` | INTERNAL | `type default` | kill-switch thresholds; fixed defaults (GH #475) | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/error_budget.rs:47 |
| `error_budget.capability.window_duration` | INTERNAL | `type default` | kill-switch thresholds; fixed defaults (GH #475) | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/error_budget.rs:52 |
| `error_budget.capability.window_size` | INTERNAL | `type default` | kill-switch thresholds; fixed defaults (GH #475) | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/error_budget.rs:49 |
| `error_budget.min_samples` | INTERNAL | `type default` | kill-switch thresholds; fixed defaults (GH #475) | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/error_budget.rs:37 |
| `error_budget.threshold` | INTERNAL | `type default` | kill-switch thresholds; fixed defaults (GH #475) | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/error_budget.rs:30 |
| `error_budget.window_duration` | INTERNAL | `type default` | kill-switch thresholds; fixed defaults (GH #475) | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/error_budget.rs:35 |
| `error_budget.window_size` | INTERNAL | `type default` | kill-switch thresholds; fixed defaults (GH #475) | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/error_budget.rs:32 |
| `events` | KEEP | `type default` | MCP Events opt-in and which sources publish (EVENTS.md) | - | src/config/mod.rs:150 |
| `events.allow_no_expiry` | KEEP | `false` | MCP Events opt-in and which sources publish (EVENTS.md) | - | src/config/features/events.rs:121 |
| `events.callback_allow_private` | KEEP | `Vec::new()` | SSRF exception list: operator intent | - | src/config/features/events.rs:160 |
| `events.cost_per_delivery_usd` | KEEP | `0.0` | price per delivery is an operator input to cost governance | - | src/config/features/events.rs:146 |
| `events.dead_letter_max_bytes` | INTERNAL | `256 * 1024 * 1024` | delivery, retry, TTL and capacity limits; fixed defaults | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/events.rs:156 |
| `events.dead_letter_max_records` | INTERNAL | `10_000` | delivery, retry, TTL and capacity limits; fixed defaults | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/events.rs:154 |
| `events.dead_letter_retention` | KEEP | `Duration::from_secs(7 * 24 * 3600)` | record-retention policy, like audit rotation | - | src/config/features/events.rs:152 |
| `events.default_ttl` | INTERNAL | `Duration::from_secs(3600)` | delivery, retry, TTL and capacity limits; fixed defaults | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/events.rs:113 |
| `events.enabled` | KEEP | `false` | MCP Events opt-in and which sources publish (EVENTS.md) | - | src/config/features/events.rs:108 |
| `events.max_in_flight` | INTERNAL | `32` | delivery, retry, TTL and capacity limits; fixed defaults | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/events.rs:129 |
| `events.max_outbox` | INTERNAL | `50_000` | delivery, retry, TTL and capacity limits; fixed defaults | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/events.rs:131 |
| `events.max_outbox_per_subscription` | INTERNAL | `1000` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/events.rs:133 |
| `events.max_subscriptions` | INTERNAL | `10_000` | delivery, retry, TTL and capacity limits; fixed defaults | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/events.rs:123 |
| `events.max_subscriptions_per_principal` | INTERNAL | `100` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/events.rs:125 |
| `events.max_ttl` | INTERNAL | `Duration::from_secs(24 * 3600)` | delivery, retry, TTL and capacity limits; fixed defaults | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/events.rs:119 |
| `events.max_verified_tail` | INTERNAL | `10_000` | delivery, retry, TTL and capacity limits; fixed defaults | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/events.rs:137 |
| `events.max_verified_tail_per_principal` | INTERNAL | `100` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/events.rs:139 |
| `events.min_ttl` | INTERNAL | `Duration::from_secs(60)` | delivery, retry, TTL and capacity limits; fixed defaults | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/events.rs:116 |
| `events.queue_depth` | INTERNAL | `1024` | delivery, retry, TTL and capacity limits; fixed defaults | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/events.rs:127 |
| `events.rate_limit_per_subscription` | INTERNAL | `EventsRateLimit::default()` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/events.rs:144 |
| `events.rate_limit_per_subscription.burst` | INTERNAL | `10` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/events.rs:22 |
| `events.rate_limit_per_subscription.per_minute` | INTERNAL | `60` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/events.rs:20 |
| `events.retry_base` | INTERNAL | `Duration::from_secs(10)` | delivery, retry, TTL and capacity limits; fixed defaults | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/events.rs:169 |
| `events.retry_max_attempts` | INTERNAL | `5` | delivery, retry, TTL and capacity limits; fixed defaults | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/events.rs:171 |
| `events.retry_window` | INTERNAL | `Duration::from_secs(15 * 60)` | delivery, retry, TTL and capacity limits; fixed defaults | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/events.rs:175 |
| `events.schedule` | INTERNAL | `EventsScheduleConfig::default()` | delivery, retry, TTL and capacity limits; fixed defaults | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/events.rs:166 |
| `events.schedule.max_timers` | INTERNAL | `1000` | delivery, retry, TTL and capacity limits; fixed defaults | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/events.rs:77 |
| `events.schedule.max_timers_per_principal` | INTERNAL | `20` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/events.rs:79 |
| `events.secret_rotation_grace` | INTERNAL | `Duration::from_secs(600)` | security bound, caller-input limit or switch an operator may rely on; undocumented | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/events.rs:149 |
| `events.seen_max_per_route` | INTERNAL | `100_000` | delivery, retry, TTL and capacity limits; fixed defaults | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/events.rs:135 |
| `events.sources` | KEEP | `EventsSourcesConfig::default()` | MCP Events opt-in and which sources publish (EVENTS.md) | - | src/config/features/events.rs:162 |
| `events.sources.backend_notifications` | KEEP | `true` | MCP Events opt-in and which sources publish (EVENTS.md) | - | src/config/features/events.rs:43 |
| `events.sources.operational` | KEEP | `false` | MCP Events opt-in and which sources publish (EVENTS.md) | - | src/config/features/events.rs:41 |
| `events.sources.rest_watch` | KEEP | `false` | MCP Events opt-in and which sources publish (EVENTS.md) | - | src/config/features/events.rs:48 |
| `events.sources.schedule` | KEEP | `false` | MCP Events opt-in and which sources publish (EVENTS.md) | - | src/config/features/events.rs:50 |
| `events.sources.task_settled` | KEEP | `true` | MCP Events opt-in and which sources publish (EVENTS.md) | - | src/config/features/events.rs:45 |
| `events.store_dir` | KEEP | `"~/.mcp-gateway/events".to_string()` | state location; deployments put it on a chosen volume (the Helm chart puts the audit log on its own persistent volume) | - | src/config/features/events.rs:110 |
| `events.suspend_min_attempts` | INTERNAL | `100` | delivery, retry, TTL and capacity limits; fixed defaults | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/events.rs:180 |
| `events.suspend_window` | INTERNAL | `Duration::from_secs(60 * 60)` | delivery, retry, TTL and capacity limits; fixed defaults | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/events.rs:178 |
| `events.verification_per_host_per_minute` | INTERNAL | `10` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/events.rs:158 |
| `events.verified_tail_ttl` | INTERNAL | `Duration::from_secs(24 * 3600)` | delivery, retry, TTL and capacity limits; fixed defaults | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/events.rs:142 |
| `events.watch` | INTERNAL | `EventsWatchConfig::default()` | delivery, retry, TTL and capacity limits; fixed defaults | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/events.rs:164 |
| `events.watch.max_pollers` | INTERNAL | `100` | delivery, retry, TTL and capacity limits; fixed defaults | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/events.rs:58 |
| `events.watch.max_pollers_per_principal` | INTERNAL | `10` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/events.rs:60 |
| `failsafe` | KEEP | `type default` | turn a resilience mechanism on or off (non-idempotent backends turn retries off) | - | src/config/mod.rs:101 |
| `failsafe.circuit_breaker` | KEEP | `type default` | turn a resilience mechanism on or off (non-idempotent backends turn retries off) | - | src/config/features/failsafe.rs:38 |
| `failsafe.circuit_breaker.enabled` | KEEP | `true` | turn a resilience mechanism on or off (non-idempotent backends turn retries off) | - | src/config/features/failsafe.rs:52 |
| `failsafe.circuit_breaker.failure_threshold` | INTERNAL | `DEFAULT_CIRCUIT_BREAKER_FAILURE_THRESHOLD` | breaker, retry, rate-limit and health-check tuning; fixed defaults, per-backend `timeout` stays | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/failsafe.rs:54 |
| `failsafe.circuit_breaker.reset_timeout` | INTERNAL | `Duration::from_secs(DEFAULT_CIRCUIT_BREAKER_RESET_TIMEOUT_SE` | breaker, retry, rate-limit and health-check tuning; fixed defaults, per-backend `timeout` stays | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/failsafe.rs:59 |
| `failsafe.circuit_breaker.success_threshold` | INTERNAL | `DEFAULT_CIRCUIT_BREAKER_SUCCESS_THRESHOLD` | breaker, retry, rate-limit and health-check tuning; fixed defaults, per-backend `timeout` stays | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/failsafe.rs:56 |
| `failsafe.health_check` | KEEP | `type default` | turn a resilience mechanism on or off (non-idempotent backends turn retries off) | - | src/config/features/failsafe.rs:44 |
| `failsafe.health_check.enabled` | KEEP | `true` | turn a resilience mechanism on or off (non-idempotent backends turn retries off) | - | src/config/features/failsafe.rs:138 |
| `failsafe.health_check.interval` | INTERNAL | `Duration::from_secs(DEFAULT_HEALTH_CHECK_INTERVAL_SECS)` | breaker, retry, rate-limit and health-check tuning; fixed defaults, per-backend `timeout` stays | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/failsafe.rs:141 |
| `failsafe.health_check.timeout` | INTERNAL | `Duration::from_secs(DEFAULT_HEALTH_CHECK_TIMEOUT_SECS)` | breaker, retry, rate-limit and health-check tuning; fixed defaults, per-backend `timeout` stays | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/failsafe.rs:144 |
| `failsafe.rate_limit` | KEEP | `type default` | turn a resilience mechanism on or off (non-idempotent backends turn retries off) | - | src/config/features/failsafe.rs:42 |
| `failsafe.rate_limit.burst_size` | INTERNAL | `DEFAULT_RATE_LIMIT_BURST` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/failsafe.rs:120 |
| `failsafe.rate_limit.enabled` | KEEP | `true` | turn a resilience mechanism on or off (non-idempotent backends turn retries off) | - | src/config/features/failsafe.rs:116 |
| `failsafe.rate_limit.requests_per_second` | INTERNAL | `DEFAULT_RATE_LIMIT_RPS` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/failsafe.rs:118 |
| `failsafe.retry` | KEEP | `type default` | turn a resilience mechanism on or off (non-idempotent backends turn retries off) | - | src/config/features/failsafe.rs:40 |
| `failsafe.retry.enabled` | KEEP | `true` | turn a resilience mechanism on or off (non-idempotent backends turn retries off) | - | src/config/features/failsafe.rs:78 |
| `failsafe.retry.initial_backoff` | INTERNAL | `Duration::from_millis(DEFAULT_RETRY_INITIAL_BACKOFF_MS)` | breaker, retry, rate-limit and health-check tuning; fixed defaults, per-backend `timeout` stays | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/failsafe.rs:91 |
| `failsafe.retry.max_attempts` | INTERNAL | `DEFAULT_RETRY_MAX_ATTEMPTS` | breaker, retry, rate-limit and health-check tuning; fixed defaults, per-backend `timeout` stays | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/failsafe.rs:88 |
| `failsafe.retry.max_backoff` | INTERNAL | `Duration::from_secs(DEFAULT_RETRY_MAX_BACKOFF_SECS)` | breaker, retry, rate-limit and health-check tuning; fixed defaults, per-backend `timeout` stays | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/failsafe.rs:94 |
| `failsafe.retry.multiplier` | INTERNAL | `DEFAULT_RETRY_MULTIPLIER` | breaker, retry, rate-limit and health-check tuning; fixed defaults, per-backend `timeout` stays | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/failsafe.rs:96 |
| `idempotency` | KEEP | `type default` | operator declares read-only tools the admission gate may replay (ADR-012) | - | src/config/mod.rs:111 |
| `idempotency.read_only_tools` | KEEP | `type default` | operator declares read-only tools the admission gate may replay (ADR-012) | - | src/config/features/idempotency.rs:12 |
| `idempotency.read_only_tools[].server` | KEEP | — | operator declares read-only tools the admission gate may replay (ADR-012) | - | src/config/features/idempotency.rs:20 |
| `idempotency.read_only_tools[].tool` | KEEP | — | operator declares read-only tools the admission gate may replay (ADR-012) | - | src/config/features/idempotency.rs:22 |
| `key_server` | KEEP | `type default` | transport and token identity for team deployments (MULTI_USER.md) | - | src/config/mod.rs:132 |
| `key_server.admin_token` | KEEP | `None` | transport and token identity for team deployments (MULTI_USER.md) | - | src/config/features/key_server.rs:65 |
| `key_server.cleanup_interval_secs` | INTERNAL | `DEFAULT_CLEANUP_INTERVAL_SECS` | token-store hygiene; fixed defaults | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/key_server.rs:55 |
| `key_server.delegated_bearer` | KEEP | `false` | transport and token identity for team deployments (MULTI_USER.md) | - | src/config/features/key_server.rs:73 |
| `key_server.enabled` | KEEP | `false` | transport and token identity for team deployments (MULTI_USER.md) | - | src/config/features/key_server.rs:43 |
| `key_server.max_oidc_token_age_secs` | INTERNAL | `DEFAULT_MAX_OIDC_TOKEN_AGE_SECS` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/key_server.rs:52 |
| `key_server.max_tokens_per_identity` | INTERNAL | `DEFAULT_MAX_TOKENS_PER_IDENTITY` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/key_server.rs:49 |
| `key_server.oidc` | KEEP | `Vec::new()` | transport and token identity for team deployments (MULTI_USER.md) | - | src/config/features/key_server.rs:58 |
| `key_server.oidc[].allowed_domains` | KEEP | — | transport and token identity for team deployments (MULTI_USER.md) | - | src/config/features/key_server.rs:293 |
| `key_server.oidc[].audiences` | KEEP | — | transport and token identity for team deployments (MULTI_USER.md) | - | src/config/features/key_server.rs:290 |
| `key_server.oidc[].auto_discover` | AUTO | `true` | try OIDC discovery, then `{issuer}/.well-known/jwks.json`; `jwks_uri` still overrides both | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/key_server.rs:284 |
| `key_server.oidc[].discovery_url` | KEEP | — | transport and token identity for team deployments (MULTI_USER.md) | - | src/config/features/key_server.rs:278 |
| `key_server.oidc[].issuer` | KEEP | — | transport and token identity for team deployments (MULTI_USER.md) | - | src/config/features/key_server.rs:270 |
| `key_server.oidc[].jwks_uri` | KEEP | — | transport and token identity for team deployments (MULTI_USER.md) | - | src/config/features/key_server.rs:274 |
| `key_server.policies` | KEEP | `Vec::new()` | transport and token identity for team deployments (MULTI_USER.md) | - | src/config/features/key_server.rs:61 |
| `key_server.policies[].match` | KEEP | — | transport and token identity for team deployments (MULTI_USER.md) | - | src/config/features/key_server.rs:301 |
| `key_server.policies[].match.domain` | KEEP | `type default` | transport and token identity for team deployments (MULTI_USER.md) | - | src/config/features/key_server.rs:314 |
| `key_server.policies[].match.email` | KEEP | `type default` | transport and token identity for team deployments (MULTI_USER.md) | - | src/config/features/key_server.rs:320 |
| `key_server.policies[].match.group` | KEEP | `type default` | transport and token identity for team deployments (MULTI_USER.md) | - | src/config/features/key_server.rs:323 |
| `key_server.policies[].match.issuer` | KEEP | `type default` | transport and token identity for team deployments (MULTI_USER.md) | - | src/config/features/key_server.rs:316 |
| `key_server.policies[].scopes` | KEEP | — | transport and token identity for team deployments (MULTI_USER.md) | - | src/config/features/key_server.rs:303 |
| `key_server.policies[].scopes.backends` | KEEP | `type default` | transport and token identity for team deployments (MULTI_USER.md) | - | src/config/features/key_server.rs:332 |
| `key_server.policies[].scopes.rate_limit` | KEEP | `type default` | transport and token identity for team deployments (MULTI_USER.md) | - | src/config/features/key_server.rs:338 |
| `key_server.policies[].scopes.tools` | KEEP | `type default` | transport and token identity for team deployments (MULTI_USER.md) | - | src/config/features/key_server.rs:335 |
| `key_server.token_ttl_secs` | INTERNAL | `DEFAULT_TOKEN_TTL_SECS` | lifetime of issued keys; a security window (rule 1) | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/key_server.rs:46 |
| `marketplace` | REMOVE | — | retired in 4.0; never had an effect | already warns once; 4.0.0 makes it a load error and `upgrade` deletes it | src/config/strict_keys.rs:53 |
| `meta_mcp` | KEEP | `type default` | section | - | src/config/mod.rs:97 |
| `meta_mcp.cache_tools` | REMOVE | `true` | read by nothing (MIK-8064); setting it has no effect | retired: loads and warns once with the reason (as `server.ws_port`); `init` and the examples drop it; `upgrade` deleting it waits for a comment-keeping upgrade rewrite (MIK-8064 AC2) | src/config/strict_keys.rs (RETIRED_KEYS) |
| `meta_mcp.cache_ttl` | INTERNAL | `Duration::from_secs(300)` | catalogue freshness; fixed 300 s (the `init` value) | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/meta_mcp_config.rs:43 |
| `meta_mcp.enabled` | KEEP | `true` | the durable form of `--no-meta-mcp`; `false` runs as a plain proxy | - | src/config/meta_mcp_config.rs:38 |
| `meta_mcp.expose_stats_tool` | KEEP | `false` | README documents it as the switch for `gateway_get_stats` | - | src/config/meta_mcp_config.rs:98 |
| `meta_mcp.exposed_meta_tools` | KEEP | `Vec::new()` | operator picks which tools the client sees and which backends start eagerly | - | src/config/meta_mcp_config.rs:90 |
| `meta_mcp.projection_mode` | INTERNAL | `crate::projection::ProjectionMode::default()` | rollout switch for response projection; off unless a test sets it | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/meta_mcp_config.rs:75 |
| `meta_mcp.prompts_resources_fetch_timeout` | AUTO | `Duration::from_secs(10)` | unset: min(the backend's `timeout`, 10 s), today's 10 s as the ceiling | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/meta_mcp_config.rs:56 |
| `meta_mcp.surfaced_tools` | KEEP | `Vec::new()` | operator picks which tools the client sees and which backends start eagerly | - | src/config/meta_mcp_config.rs:67 |
| `meta_mcp.surfaced_tools[].server` | KEEP | — | operator picks which tools the client sees and which backends start eagerly | - | src/config/meta_mcp_config.rs:28 |
| `meta_mcp.surfaced_tools[].tool` | KEEP | — | operator picks which tools the client sees and which backends start eagerly | - | src/config/meta_mcp_config.rs:30 |
| `meta_mcp.warm_start` | KEEP | `Vec::new()` | operator picks which tools the client sees and which backends start eagerly | - | src/config/meta_mcp_config.rs:59 |
| `mtls` | KEEP | `type default` | transport and token identity for team deployments (MULTI_USER.md) | - | src/config/mod.rs:129 |
| `mtls.ca_cert` | KEEP | `type default` | transport and token identity for team deployments (MULTI_USER.md) | - | src/mtls/config.rs:54 |
| `mtls.crl_path` | KEEP | `type default` | transport and token identity for team deployments (MULTI_USER.md) | - | src/mtls/config.rs:68 |
| `mtls.enabled` | KEEP | `type default` | transport and token identity for team deployments (MULTI_USER.md) | - | src/mtls/config.rs:45 |
| `mtls.policies` | KEEP | `type default` | transport and token identity for team deployments (MULTI_USER.md) | - | src/mtls/config.rs:75 |
| `mtls.policies[].allow` | KEEP | `type default` | transport and token identity for team deployments (MULTI_USER.md) | - | src/mtls/config.rs:100 |
| `mtls.policies[].allow.backends` | KEEP | `type default` | transport and token identity for team deployments (MULTI_USER.md) | - | src/mtls/config.rs:144 |
| `mtls.policies[].allow.tools` | KEEP | `type default` | transport and token identity for team deployments (MULTI_USER.md) | - | src/mtls/config.rs:147 |
| `mtls.policies[].deny` | KEEP | `type default` | transport and token identity for team deployments (MULTI_USER.md) | - | src/mtls/config.rs:104 |
| `mtls.policies[].deny.backends` | KEEP | `type default` | transport and token identity for team deployments (MULTI_USER.md) | - | src/mtls/config.rs:144 |
| `mtls.policies[].deny.tools` | KEEP | `type default` | transport and token identity for team deployments (MULTI_USER.md) | - | src/mtls/config.rs:147 |
| `mtls.policies[].match` | KEEP | `type default` | transport and token identity for team deployments (MULTI_USER.md) | - | src/mtls/config.rs:96 |
| `mtls.policies[].match.any` | KEEP | `type default` | transport and token identity for team deployments (MULTI_USER.md) | - | src/mtls/config.rs:136 |
| `mtls.policies[].match.cn` | KEEP | `type default` | transport and token identity for team deployments (MULTI_USER.md) | - | src/mtls/config.rs:124 |
| `mtls.policies[].match.ou` | KEEP | `type default` | transport and token identity for team deployments (MULTI_USER.md) | - | src/mtls/config.rs:127 |
| `mtls.policies[].match.san_dns` | KEEP | `type default` | transport and token identity for team deployments (MULTI_USER.md) | - | src/mtls/config.rs:133 |
| `mtls.policies[].match.san_uri` | KEEP | `type default` | transport and token identity for team deployments (MULTI_USER.md) | - | src/mtls/config.rs:130 |
| `mtls.require_client_cert` | KEEP | `true` | transport and token identity for team deployments (MULTI_USER.md) | - | src/mtls/config.rs:62 |
| `mtls.server_cert` | KEEP | `type default` | transport and token identity for team deployments (MULTI_USER.md) | - | src/mtls/config.rs:48 |
| `mtls.server_key` | KEEP | `type default` | transport and token identity for team deployments (MULTI_USER.md) | - | src/mtls/config.rs:51 |
| `playbooks` | KEEP | `type default` | opt-in tool surfaces (CODE_MODE.md) | - | src/config/mod.rs:113 |
| `playbooks.directories` | KEEP | `vec!["playbooks".to_string()]` | opt-in tool surfaces (CODE_MODE.md) | - | src/config/features/playbooks.rs:16 |
| `playbooks.enabled` | KEEP | `false` | opt-in tool surfaces (CODE_MODE.md) | - | src/config/features/playbooks.rs:14 |
| `routing_profiles` | KEEP | `type default` | per-session tool scoping | - | src/config/mod.rs:120 |
| `routing_profiles.<name>.allow_backends` | KEEP | `type default` | per-session tool scoping | - | src/routing_profile/mod.rs:58 |
| `routing_profiles.<name>.allow_tools` | KEEP | `type default` | per-session tool scoping | - | src/routing_profile/mod.rs:68 |
| `routing_profiles.<name>.deny_backends` | KEEP | `type default` | per-session tool scoping | - | src/routing_profile/mod.rs:63 |
| `routing_profiles.<name>.deny_tools` | KEEP | `type default` | per-session tool scoping | - | src/routing_profile/mod.rs:73 |
| `routing_profiles.<name>.description` | KEEP | `type default` | per-session tool scoping | - | src/routing_profile/mod.rs:53 |
| `runtime` | KEEP | `type default` | sandbox runtime profiles (opt-in) | - | src/config/mod.rs:138 |
| `runtime.availability` | KEEP | `RuntimeAvailabilityConfig::default()` | operator policy: which runtimes may run here (`local_process: false` is a sandbox opt-out no probe can infer) | - | src/config/features/runtime.rs:23 |
| `runtime.availability.docker` | KEEP | `false` | operator policy: which runtimes may run here (`local_process: false` is a sandbox opt-out no probe can infer) | - | src/config/features/runtime.rs:120 |
| `runtime.availability.kubernetes` | KEEP | `false` | operator policy: which runtimes may run here (`local_process: false` is a sandbox opt-out no probe can infer) | - | src/config/features/runtime.rs:128 |
| `runtime.availability.launchd` | KEEP | `false` | operator policy: which runtimes may run here (`local_process: false` is a sandbox opt-out no probe can infer) | - | src/config/features/runtime.rs:126 |
| `runtime.availability.local_process` | KEEP | `true` | operator policy: which runtimes may run here (`local_process: false` is a sandbox opt-out no probe can infer) | - | src/config/features/runtime.rs:118 |
| `runtime.availability.podman` | KEEP | `false` | operator policy: which runtimes may run here (`local_process: false` is a sandbox opt-out no probe can infer) | - | src/config/features/runtime.rs:122 |
| `runtime.availability.systemd` | KEEP | `false` | operator policy: which runtimes may run here (`local_process: false` is a sandbox opt-out no probe can infer) | - | src/config/features/runtime.rs:124 |
| `runtime.default_provider` | KEEP | `RuntimeProviderKind::LocalProcess` | sandbox runtime profiles (opt-in) | - | src/config/features/runtime.rs:21 |
| `runtime.profiles` | KEEP | `HashMap::new()` | sandbox runtime profiles (opt-in) | - | src/config/features/runtime.rs:25 |
| `runtime.profiles.<name>.data_class` | KEEP | `RuntimeDataClass::Internal` | sandbox runtime profiles (opt-in) | - | src/config/features/runtime.rs:170 |
| `runtime.profiles.<name>.env_keys` | KEEP | `Vec::new()` | sandbox runtime profiles (opt-in) | - | src/config/features/runtime.rs:172 |
| `runtime.profiles.<name>.executable` | KEEP | `None` | sandbox runtime profiles (opt-in) | - | src/config/features/runtime.rs:166 |
| `runtime.profiles.<name>.guarded_env_keys` | KEEP | `Vec::new()` | sandbox runtime profiles (opt-in) | - | src/config/features/runtime.rs:174 |
| `runtime.profiles.<name>.image` | KEEP | `None` | sandbox runtime profiles (opt-in) | - | src/config/features/runtime.rs:168 |
| `runtime.profiles.<name>.mounts` | KEEP | `Vec::new()` | sandbox runtime profiles (opt-in) | - | src/config/features/runtime.rs:178 |
| `runtime.profiles.<name>.mounts[].mode` | KEEP | — | sandbox runtime profiles (opt-in) | - | src/runtime/provider.rs:208 |
| `runtime.profiles.<name>.mounts[].source` | KEEP | — | sandbox runtime profiles (opt-in) | - | src/runtime/provider.rs:204 |
| `runtime.profiles.<name>.mounts[].target` | KEEP | — | sandbox runtime profiles (opt-in) | - | src/runtime/provider.rs:206 |
| `runtime.profiles.<name>.network_egress` | KEEP | `RuntimeNetworkEgress::None` | sandbox runtime profiles (opt-in) | - | src/config/features/runtime.rs:176 |
| `runtime.profiles.<name>.network_egress.allowlist` | KEEP | — | sandbox runtime profiles (opt-in) | - | src/runtime/provider.rs:231 |
| `runtime.profiles.<name>.privileged` | KEEP | `false` | sandbox runtime profiles (opt-in) | - | src/config/features/runtime.rs:184 |
| `runtime.profiles.<name>.provider` | KEEP | `None` | sandbox runtime profiles (opt-in) | - | src/config/features/runtime.rs:164 |
| `runtime.profiles.<name>.resources` | KEEP | `RuntimeResourcePolicy::default()` | sandbox runtime profiles (opt-in) | - | src/config/features/runtime.rs:180 |
| `runtime.profiles.<name>.resources.cpu_cores` | KEEP | `1` | sandbox runtime profiles (opt-in) | - | src/runtime/provider.rs:241 |
| `runtime.profiles.<name>.resources.memory_mb` | KEEP | `512` | sandbox runtime profiles (opt-in) | - | src/runtime/provider.rs:243 |
| `runtime.profiles.<name>.resources.timeout_secs` | KEEP | `60` | sandbox runtime profiles (opt-in) | - | src/runtime/provider.rs:245 |
| `runtime.profiles.<name>.restart` | KEEP | `RuntimeRestartPolicy::default()` | sandbox runtime profiles (opt-in) | - | src/config/features/runtime.rs:182 |
| `runtime.profiles.<name>.restart.backoff_secs` | KEEP | `5` | sandbox runtime profiles (opt-in) | - | src/runtime/provider.rs:276 |
| `runtime.profiles.<name>.restart.max_restarts` | KEEP | `2` | sandbox runtime profiles (opt-in) | - | src/runtime/provider.rs:274 |
| `security` | KEEP | `type default` | security posture and tool policy (SECURITY_POSTURE.md) | - | src/config/mod.rs:115 |
| `security.agent_identity` | KEEP | `AgentIdentityConfig::default()` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/config/features/security.rs:629 |
| `security.agent_identity.allow_unverified_agent_identity` | KEEP | `type default` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/security/agent_identity.rs:89 |
| `security.agent_identity.enabled` | KEEP | `type default` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/security/agent_identity.rs:63 |
| `security.agent_identity.incomparable_proof_sources` | KEEP | `type default` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/security/agent_identity.rs:132 |
| `security.agent_identity.known_agents` | KEEP | `type default` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/security/agent_identity.rs:80 |
| `security.agent_identity.principal_labels` | KEEP | `type default` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/security/agent_identity.rs:109 |
| `security.agent_identity.principal_labels[].id` | KEEP | — | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/security/agent_identity.rs:246 |
| `security.agent_identity.principal_labels[].labels` | KEEP | — | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/security/agent_identity.rs:249 |
| `security.agent_identity.principal_labels[].source` | KEEP | — | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/security/agent_identity.rs:244 |
| `security.agent_identity.require_id` | KEEP | `type default` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/security/agent_identity.rs:66 |
| `security.caller_identity` | KEEP | `crate::security::caller_identity::CallerIdentityConfig::defa` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/config/features/security.rs:644 |
| `security.caller_identity.authority` | KEEP | `type default` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/security/caller_identity.rs:47 |
| `security.caller_identity.cloudflare_access` | KEEP | `type default` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/security/caller_identity.rs:49 |
| `security.caller_identity.cloudflare_access.audiences` | KEEP | `type default` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/security/caller_identity.rs:32 |
| `security.caller_identity.cloudflare_access.team_domain` | KEEP | `type default` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/security/caller_identity.rs:30 |
| `security.caller_identity.mode` | KEEP | `type default` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/security/caller_identity.rs:43 |
| `security.caller_identity.trusted_proxies` | KEEP | `type default` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/security/caller_identity.rs:45 |
| `security.claim_capture` | KEEP | `ClaimCaptureConfig::default()` | opt-in capture switch and its file (rule 1) | - | src/config/features/security.rs:659 |
| `security.claim_capture.enabled` | KEEP | `false` | opt-in capture switch and its file (rule 1) | - | src/config/features/security.rs:571 |
| `security.claim_capture.path` | KEEP | `"~/.mcp-gateway/claim-capture/claims.jsonl".to_string()` | opt-in capture switch and its file (rule 1) | - | src/config/features/security.rs:573 |
| `security.context_integrity` | KEEP | `ContextIntegrityConfig::default()` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/config/features/security.rs:647 |
| `security.context_integrity.non_bypassable` | KEEP | `type default` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/config/features/security.rs:535 |
| `security.context_integrity.preset` | KEEP | `type default` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/config/features/security.rs:530 |
| `security.firewall` | KEEP | `crate::security::firewall::FirewallConfig::default()` | firewall switches and per-tool rules (OWASP ASI controls) | - | src/config/features/security.rs:623 |
| `security.firewall.anomaly_block_threshold` | KEEP | `see impl Default` | a switch under rule 3: setting it turns anomaly blocking on (unset warns only) | - | src/security/firewall/config.rs:78 |
| `security.firewall.anomaly_detection` | KEEP | `see impl Default` | firewall switches and per-tool rules (OWASP ASI controls) | - | src/security/firewall/config.rs:30 |
| `security.firewall.anomaly_min_observations` | INTERNAL | `fn default_anomaly_min_observations` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/security/firewall/config.rs:81 |
| `security.firewall.anomaly_threshold` | INTERNAL | `fn default_anomaly_threshold` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/security/firewall/config.rs:57 |
| `security.firewall.audit_log` | KEEP | `None` | firewall switches and per-tool rules (OWASP ASI controls) | - | src/security/firewall/config.rs:32 |
| `security.firewall.budget` | KEEP | `budget_guard::BudgetGuardConfig::default()` | opt-in OWASP ASI06/ASI10 guards: on/off and what they cover | - | src/security/firewall/config.rs:94 |
| `security.firewall.budget.enabled` | KEEP | `false` | opt-in OWASP ASI06/ASI10 guards: on/off and what they cover | - | src/security/firewall/budget_guard.rs:52 |
| `security.firewall.budget.max_calls_per_window` | KEEP | `600` | opt-in OWASP ASI06/ASI10 guards: on/off and what they cover | - | src/security/firewall/budget_guard.rs:54 |
| `security.firewall.budget.window_secs` | KEEP | `60` | opt-in OWASP ASI06/ASI10 guards: on/off and what they cover | - | src/security/firewall/budget_guard.rs:56 |
| `security.firewall.collusion` | KEEP | `see impl Default` | opt-in OWASP ASI06/ASI10 guards: on/off and what they cover | - | src/security/firewall/config.rs:108 |
| `security.firewall.collusion.action` | KEEP | `CollusionAction::Off` | opt-in OWASP ASI06/ASI10 guards: on/off and what they cover | - | src/security/firewall/collusion_gate.rs:61 |
| `security.firewall.collusion.allowed_flows` | KEEP | `Vec::new()` | opt-in OWASP ASI06/ASI10 guards: on/off and what they cover | - | src/security/firewall/collusion_gate.rs:73 |
| `security.firewall.collusion.allowed_flows[].egress` | KEEP | — | opt-in OWASP ASI06/ASI10 guards: on/off and what they cover | - | src/security/firewall/collusion_gate.rs:53 |
| `security.firewall.collusion.allowed_flows[].source` | KEEP | — | opt-in OWASP ASI06/ASI10 guards: on/off and what they cover | - | src/security/firewall/collusion_gate.rs:51 |
| `security.firewall.collusion.common_principals` | INTERNAL | `params.common_principals` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/security/firewall/collusion_gate.rs:67 |
| `security.firewall.collusion.min_matches` | INTERNAL | `params.min_matches` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/security/firewall/collusion_gate.rs:65 |
| `security.firewall.collusion.non_egress` | KEEP | `Vec::new()` | opt-in OWASP ASI06/ASI10 guards: on/off and what they cover | - | src/security/firewall/collusion_gate.rs:71 |
| `security.firewall.collusion.sources` | KEEP | `Vec::new()` | opt-in OWASP ASI06/ASI10 guards: on/off and what they cover | - | src/security/firewall/collusion_gate.rs:69 |
| `security.firewall.collusion.window_secs` | INTERNAL | `params.window.as_secs()` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/security/firewall/collusion_gate.rs:63 |
| `security.firewall.credential_redaction` | KEEP | `true` | firewall switches and per-tool rules (OWASP ASI controls) | - | src/security/firewall/config.rs:28 |
| `security.firewall.enabled` | KEEP | `true` | firewall switches and per-tool rules (OWASP ASI controls) | - | src/security/firewall/config.rs:20 |
| `security.firewall.memory_poisoning` | KEEP | `memory_scanner::MemoryPoisoningConfig::default()` | opt-in OWASP ASI06/ASI10 guards: on/off and what they cover | - | src/security/firewall/config.rs:51 |
| `security.firewall.memory_poisoning.enabled` | KEEP | `true` | opt-in OWASP ASI06/ASI10 guards: on/off and what they cover | - | src/security/firewall/memory_scanner.rs:56 |
| `security.firewall.memory_poisoning.max_entry_size_bytes` | INTERNAL | `10_240` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/security/firewall/memory_scanner.rs:60 |
| `security.firewall.memory_poisoning.scan_tools` | KEEP | `default_scan_tools()` | opt-in OWASP ASI06/ASI10 guards: on/off and what they cover | - | src/security/firewall/memory_scanner.rs:65 |
| `security.firewall.prompt_injection_detection` | KEEP | `true` | firewall switches and per-tool rules (OWASP ASI controls) | - | src/security/firewall/config.rs:26 |
| `security.firewall.rules` | KEEP | `Vec::new()` | firewall switches and per-tool rules (OWASP ASI controls) | - | src/security/firewall/config.rs:35 |
| `security.firewall.rules[].action` | KEEP | — | firewall switches and per-tool rules (OWASP ASI controls) | - | src/security/firewall/config.rs:143 |
| `security.firewall.rules[].match` | KEEP | — | firewall switches and per-tool rules (OWASP ASI controls) | - | src/security/firewall/config.rs:141 |
| `security.firewall.rules[].reason` | KEEP | — | firewall switches and per-tool rules (OWASP ASI controls) | - | src/security/firewall/config.rs:146 |
| `security.firewall.rules[].scan` | KEEP | — | firewall switches and per-tool rules (OWASP ASI controls) | - | src/security/firewall/config.rs:149 |
| `security.firewall.scan_requests` | KEEP | `true` | firewall switches and per-tool rules (OWASP ASI controls) | - | src/security/firewall/config.rs:22 |
| `security.firewall.scan_responses` | KEEP | `true` | firewall switches and per-tool rules (OWASP ASI controls) | - | src/security/firewall/config.rs:24 |
| `security.firewall.tenant_guard` | KEEP | `see impl Default` | opt-in OWASP ASI06/ASI10 guards: on/off and what they cover | - | src/security/firewall/config.rs:88 |
| `security.firewall.tenant_guard.arg_keys` | KEEP | `Vec::new()` | opt-in OWASP ASI06/ASI10 guards: on/off and what they cover | - | src/security/firewall/tenant_guard.rs:68 |
| `security.firewall.tenant_guard.cross_tenant_reads` | KEEP | `CrossTenantReads::Observe` | opt-in OWASP ASI06/ASI10 guards: on/off and what they cover | - | src/security/firewall/tenant_guard.rs:71 |
| `security.firewall.tenant_guard.enabled` | KEEP | `false` | opt-in OWASP ASI06/ASI10 guards: on/off and what they cover | - | src/security/firewall/tenant_guard.rs:60 |
| `security.firewall.tenant_guard.max_tenants_per_window` | KEEP | `3` | opt-in OWASP ASI06/ASI10 guards: on/off and what they cover | - | src/security/firewall/tenant_guard.rs:62 |
| `security.firewall.tenant_guard.window_secs` | KEEP | `300` | opt-in OWASP ASI06/ASI10 guards: on/off and what they cover | - | src/security/firewall/tenant_guard.rs:64 |
| `security.hardened` | KEEP | `crate::security::posture::HardenedConfig::default()` | security posture and tool policy (SECURITY_POSTURE.md) | - | src/config/features/security.rs:598 |
| `security.hardened.private_backends` | KEEP | `type default` | security posture and tool policy (SECURITY_POSTURE.md) | - | src/security/posture.rs:67 |
| `security.identity_grants` | KEEP | `IdentityGrantsConfig::default()` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/config/features/security.rs:641 |
| `security.identity_grants.enabled` | KEEP | `false` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/config/features/security.rs:447 |
| `security.identity_grants.fail_on_error` | KEEP | `true` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/config/features/security.rs:452 |
| `security.identity_grants.path` | KEEP | `"~/.mcp-gateway/identity-grants.yaml".to_string()` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/config/features/security.rs:449 |
| `security.message_signing` | KEEP | `MessageSigningConfig::default()` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/config/features/security.rs:626 |
| `security.message_signing.enabled` | KEEP | `false` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/config/features/security.rs:149 |
| `security.message_signing.key_id` | KEEP | `"default".to_string()` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/config/features/security.rs:164 |
| `security.message_signing.previous_secret` | KEEP | `String::new()` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/config/features/security.rs:156 |
| `security.message_signing.replay_window` | INTERNAL | `300` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/security.rs:162 |
| `security.message_signing.require_nonce` | KEEP | `false` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/config/features/security.rs:159 |
| `security.message_signing.shared_secret` | KEEP | `String::new()` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/config/features/security.rs:153 |
| `security.posture` | KEEP | `crate::security::posture::SecurityPosture::default()` | security posture and tool policy (SECURITY_POSTURE.md) | - | src/config/features/security.rs:595 |
| `security.provenance_stamping` | KEEP | `false` | opt-in provenance receipts on results (ASI04) | - | src/config/features/security.rs:655 |
| `security.remote_server_signing` | KEEP | `RemoteServerSigningConfig::default()` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/config/features/security.rs:650 |
| `security.remote_server_signing.backends` | KEEP | `type default` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/security/remote_provenance.rs:27 |
| `security.remote_server_signing.backends.<name>.issued_at` | KEEP | — | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/security/remote_provenance.rs:55 |
| `security.remote_server_signing.backends.<name>.issuer` | KEEP | — | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/security/remote_provenance.rs:53 |
| `security.remote_server_signing.backends.<name>.key_id` | KEEP | — | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/security/remote_provenance.rs:57 |
| `security.remote_server_signing.backends.<name>.signature` | KEEP | — | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/security/remote_provenance.rs:59 |
| `security.remote_server_signing.backends.<name>.subject` | KEEP | — | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/security/remote_provenance.rs:51 |
| `security.remote_server_signing.require_for_remote_backends` | KEEP | `type default` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/security/remote_provenance.rs:23 |
| `security.remote_server_signing.trusted_keys` | KEEP | `type default` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/security/remote_provenance.rs:25 |
| `security.remote_server_signing.trusted_keys.<name>.algorithm` | KEEP | — | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/security/remote_provenance.rs:34 |
| `security.remote_server_signing.trusted_keys.<name>.public_key` | KEEP | — | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/security/remote_provenance.rs:36 |
| `security.response_contract` | KEEP | `ResponseContractConfig::default()` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/config/features/security.rs:638 |
| `security.response_contract.action_mode` | KEEP | `type default` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/config/features/security.rs:422 |
| `security.response_contract.default_max_bytes` | KEEP | `type default` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/config/features/security.rs:424 |
| `security.response_contract.enabled` | KEEP | `type default` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/config/features/security.rs:420 |
| `security.response_contract.fail_closed` | KEEP | `type default` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/config/features/security.rs:427 |
| `security.response_contract.tools` | KEEP | `type default` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/config/features/security.rs:429 |
| `security.response_contract.tools.<name>.action_mode` | KEEP | `type default` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/config/features/security.rs:393 |
| `security.response_contract.tools.<name>.forbidden_patterns` | KEEP | `type default` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/config/features/security.rs:391 |
| `security.response_contract.tools.<name>.max_bytes` | KEEP | `type default` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/config/features/security.rs:389 |
| `security.response_inspection` | KEEP | `ResponseInspectionConfig::default()` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/config/features/security.rs:635 |
| `security.response_inspection.action_mode` | KEEP | `false` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/config/features/security.rs:370 |
| `security.response_inspection.enabled` | KEEP | `true` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/config/features/security.rs:366 |
| `security.sanitize_input` | KEEP | `true` | security posture and tool policy (SECURITY_POSTURE.md) | - | src/config/features/security.rs:600 |
| `security.signature_chain` | KEEP | `None` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/config/features/security.rs:661 |
| `security.signature_chain.emit` | KEEP | — | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/config/features/signature_chain.rs:46 |
| `security.signature_chain.key_id` | KEEP | — | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/config/features/signature_chain.rs:43 |
| `security.signature_chain.max_links` | KEEP | `8` | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/config/features/signature_chain.rs:49 |
| `security.signature_chain.signing_key` | KEEP | — | opt-in security control (OWASP_AGENTIC_AI_COMPLIANCE.md); behaviour unchanged | - | src/config/features/signature_chain.rs:41 |
| `security.ssrf_protection` | KEEP | `true` | security posture and tool policy (SECURITY_POSTURE.md) | - | src/config/features/security.rs:602 |
| `security.tool_policy` | KEEP | `ToolPolicyConfig::default()` | security posture and tool policy (SECURITY_POSTURE.md) | - | src/config/features/security.rs:619 |
| `security.tool_policy.allow` | KEEP | `Vec::new()` | security posture and tool policy (SECURITY_POSTURE.md) | - | src/security/policy.rs:50 |
| `security.tool_policy.default_action` | KEEP | `PolicyAction::Allow` | security posture and tool policy (SECURITY_POSTURE.md) | - | src/security/policy.rs:47 |
| `security.tool_policy.deny` | KEEP | `Vec::new()` | security posture and tool policy (SECURITY_POSTURE.md) | - | src/security/policy.rs:53 |
| `security.tool_policy.enabled` | KEEP | `true` | security posture and tool policy (SECURITY_POSTURE.md) | - | src/security/policy.rs:45 |
| `security.tool_policy.log_denied` | KEEP | `true` | security posture and tool policy (SECURITY_POSTURE.md) | - | src/security/policy.rs:57 |
| `security.tool_policy.use_default_deny` | KEEP | `true` | security posture and tool policy (SECURITY_POSTURE.md) | - | src/security/policy.rs:55 |
| `security.transparency_log` | KEEP | `TransparencyLogConfig::default()` | audit-log signing key the operator owns | - | src/config/features/security.rs:632 |
| `security.transparency_log.enabled` | KEEP | `false` | opt-in audit when auth is off; required when auth is on (src/config/features/security.rs:117) | - | src/config/features/security.rs:33 |
| `security.transparency_log.key_id` | KEEP | `"default".to_string()` | audit-log signing key the operator owns | - | src/config/features/security.rs:37 |
| `security.transparency_log.path` | KEEP | `"~/.mcp-gateway/transparency/transparency.jsonl".to_string()` | state location; deployments put it on a chosen volume (the Helm chart puts the audit log on its own persistent volume) | - | src/config/features/security.rs:35 |
| `security.transparency_log.rotation` | KEEP | `crate::security::audit_rotation_config::RotationConfig::defa` | audit retention and disk-full policy (`on_disk_full: refuse`) are compliance choices | - | src/config/features/security.rs:44 |
| `security.transparency_log.rotation.max_segment_age_secs` | KEEP | `0` | audit retention and disk-full policy (`on_disk_full: refuse`) are compliance choices | - | src/security/audit_rotation_config.rs:37 |
| `security.transparency_log.rotation.max_segment_bytes` | KEEP | `64 * 1024 * 1024` | audit retention and disk-full policy (`on_disk_full: refuse`) are compliance choices | - | src/security/audit_rotation_config.rs:35 |
| `security.transparency_log.rotation.on_disk_full` | KEEP | `OnDiskFull::ExpireOldest` | audit retention and disk-full policy (`on_disk_full: refuse`) are compliance choices | - | src/security/audit_rotation_config.rs:41 |
| `security.transparency_log.rotation.retain_segments` | KEEP | `12` | audit retention and disk-full policy (`on_disk_full: refuse`) are compliance choices | - | src/security/audit_rotation_config.rs:39 |
| `security.transparency_log.shared_secret` | KEEP | `String::new()` | audit-log signing key the operator owns | - | src/config/features/security.rs:42 |
| `security.trust_configured_backends` | KEEP | `true` | security posture and tool policy (SECURITY_POSTURE.md) | - | src/config/features/security.rs:617 |
| `server` | KEEP | `type default` | where the gateway listens and how clients reach it | - | src/config/mod.rs:93 |
| `server.allow_unauthenticated_network_bind` | KEEP | `false` | security opt-out or credential; must stay an explicit operator decision | - | src/config/server_config.rs:65 |
| `server.cleartext_http` | KEEP | `CleartextHttp::Refuse` | security opt-out or credential; must stay an explicit operator decision | - | src/config/server_config.rs:87 |
| `server.cluster_domain` | KEEP | `None` | security opt-out or credential; must stay an explicit operator decision | - | src/config/server_config.rs:91 |
| `server.host` | KEEP | `"127.0.0.1".to_string()` | where the gateway listens and how clients reach it | - | src/config/server_config.rs:32 |
| `server.idempotency_key` | KEEP | `IdempotencyKeyMode::Optional` | operator policy: whether clients must send an idempotency key (ADR-012) | - | src/config/server_config.rs:68 |
| `server.max_body_size` | INTERNAL | `10 * 1024 * 1024` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/server_config.rs:42 |
| `server.metrics_token` | KEEP | `None` | security opt-out or credential; must stay an explicit operator decision | - | src/config/server_config.rs:77 |
| `server.modern_protocol` | KEEP | `true` | multi-replica deployments turn it off (DEPLOYMENT.md:181); it is also the protocol rollback switch | - | src/config/server_config.rs:30 |
| `server.port` | KEEP | `39400` | where the gateway listens and how clients reach it | - | src/config/server_config.rs:34 |
| `server.public_url` | KEEP | `None` | where the gateway listens and how clients reach it | - | src/config/server_config.rs:52 |
| `server.replicas` | KEEP | `1` | declared, not observable from inside a pod | - | src/config/server_config.rs:83 |
| `server.request_timeout` | REMOVE | — | retired in 4.0; never had an effect | already warns once; 4.0.0 makes it a load error and `upgrade` deletes it | src/config/strict_keys.rs:48 |
| `server.shutdown_timeout` | INTERNAL | `Duration::from_secs(30)` | safety limit with a fixed default; no user story needs it | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/server_config.rs:39 |
| `server.ws_port` | REMOVE | — | retired in 4.0; never had an effect | already warns once; 4.0.0 makes it a load error and `upgrade` deletes it | src/config/strict_keys.rs:42 |
| `streaming` | KEEP | `type default` | turn server-push streams off behind proxies that break SSE | - | src/config/mod.rs:99 |
| `streaming.auto_subscribe` | KEEP | `Vec::new()` | operator picks backends to subscribe for notifications | - | src/config/features/streaming.rs:31 |
| `streaming.buffer_size` | INTERNAL | `DEFAULT_BUFFER_SIZE` | stream plumbing with fixed defaults | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/streaming.rs:25 |
| `streaming.enabled` | KEEP | `true` | turn server-push streams off behind proxies that break SSE | - | src/config/features/streaming.rs:23 |
| `streaming.keep_alive_interval` | INTERNAL | `Duration::from_secs(DEFAULT_KEEP_ALIVE_SECS)` | stream plumbing with fixed defaults | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/streaming.rs:28 |
| `streaming.session_reaper_interval` | INTERNAL | `Duration::from_secs(DEFAULT_SESSION_REAPER_INTERVAL_SECS)` | stream plumbing with fixed defaults | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/streaming.rs:38 |
| `streaming.session_ttl` | INTERNAL | `Duration::from_secs(DEFAULT_SESSION_TTL_SECS)` | stream plumbing with fixed defaults | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/streaming.rs:35 |
| `tasks` | KEEP | `type default` | trusted recovery adapters are an operator trust decision | - | src/config/mod.rs:148 |
| `tasks.default_ttl_ms` | INTERNAL | `DEFAULT_TTL_MS` | task-store capacity and cadence; fixed defaults | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/tasks.rs:37 |
| `tasks.expiry_interval` | INTERNAL | `Duration::from_secs(60)` | task-store capacity and cadence; fixed defaults | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/tasks.rs:53 |
| `tasks.logical_budget_bytes` | INTERNAL | `DEFAULT_LOGICAL_BUDGET_BYTES` | security bound, caller-input limit or switch an operator may rely on; undocumented | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/tasks.rs:49 |
| `tasks.max_per_principal` | INTERNAL | `DEFAULT_MAX_PER_PRINCIPAL` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/tasks.rs:43 |
| `tasks.max_record_bytes` | INTERNAL | `DEFAULT_MAX_RECORD_BYTES` | security bound, caller-input limit or switch an operator may rely on; undocumented | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/tasks.rs:47 |
| `tasks.max_records` | INTERNAL | `DEFAULT_MAX_RECORDS` | task-store capacity and cadence; fixed defaults | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/tasks.rs:41 |
| `tasks.max_workers` | INTERNAL | `DEFAULT_MAX_WORKERS` | task-store capacity and cadence; fixed defaults | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/tasks.rs:45 |
| `tasks.poll_interval_ms` | INTERNAL | `DEFAULT_POLL_INTERVAL_MS` | task-store capacity and cadence; fixed defaults | hidden key: a set value is still read and validated, so nothing an operator set stops applying; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/tasks.rs:39 |
| `tasks.recovery_adapters` | KEEP | `Vec::new()` | trusted recovery adapters are an operator trust decision | - | src/config/features/tasks.rs:56 |
| `tasks.store_dir` | KEEP | `"~/.mcp-gateway/tasks".to_string()` | state location; deployments put it on a chosen volume (the Helm chart puts the audit log on its own persistent volume) | - | src/config/features/tasks.rs:35 |
| `webhooks` | KEEP | `type default` | inbound webhook receiver (WEBHOOKS.md) | - | src/config/mod.rs:117 |
| `webhooks.base_path` | KEEP | `DEFAULT_BASE_PATH.to_string()` | inbound webhook receiver (WEBHOOKS.md) | - | src/config/features/webhooks.rs:21 |
| `webhooks.enabled` | KEEP | `true` | inbound webhook receiver (WEBHOOKS.md) | - | src/config/features/webhooks.rs:19 |
| `webhooks.rate_limit` | INTERNAL | `DEFAULT_RATE_LIMIT` | security or abuse bound; an operator who set it relies on it | hidden key: still read and validated, so enforcement is unchanged; left out of the reference, `init` and examples; `doctor` lists it when set | src/config/features/webhooks.rs:25 |
| `webhooks.require_signature` | KEEP | `true` | inbound webhook receiver (WEBHOOKS.md) | - | src/config/features/webhooks.rs:23 |
| `_*` | KEEP | — | operator annotation key: loads at any mapping level and is never read | - | src/config/strict_keys.rs:75 |
| `x-*` | KEEP | — | operator annotation key: loads at any mapping level and is never read | - | src/config/strict_keys.rs:75 |

## Surface: cli

| Item | Class | Reason | Migration | Defined at |
|---|---|---|---|---|
| `mcp-gateway` | KEEP | the binary | - | src/cli/mod.rs:125 |
| `mcp-gateway --version` | KEEP | clap-generated from the root command; prints the version | - | src/cli/mod.rs:125 |
| `mcp-gateway --help` | KEEP | clap-generated from the root command; prints usage | - | src/cli/mod.rs:125 |
| `mcp-gateway --config` | KEEP | where the config is and how to listen and log (env MCP_GATEWAY_CONFIG, global) | - | src/cli/mod.rs:128 |
| `mcp-gateway -c` | KEEP | short alias of `--config` | - | src/cli/mod.rs:128 |
| `mcp-gateway --host` | KEEP | where the config is and how to listen and log (env MCP_GATEWAY_HOST) | - | src/cli/mod.rs:136 |
| `mcp-gateway --log-format` | KEEP | where the config is and how to listen and log (env MCP_GATEWAY_LOG_FORMAT, global) | - | src/cli/mod.rs:149 |
| `mcp-gateway --log-level` | KEEP | where the config is and how to listen and log (env MCP_GATEWAY_LOG_LEVEL, global) | - | src/cli/mod.rs:145 |
| `mcp-gateway --no-meta-mcp` | KEEP | runs as a plain proxy for clients that want every backend tool listed | - | src/cli/mod.rs:153 |
| `mcp-gateway --port` | KEEP | where the config is and how to listen and log (env MCP_GATEWAY_PORT) | - | src/cli/mod.rs:132 |
| `mcp-gateway -p` | KEEP | short alias of `--port` | - | src/cli/mod.rs:132 |
| `mcp-gateway accounts` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:274 |
| `mcp-gateway accounts init-store` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:180 |
| `mcp-gateway accounts migrate-credentials` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:195 |
| `mcp-gateway accounts migrate-credentials --descriptor-id` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:195 |
| `mcp-gateway accounts migrate-credentials --legacy-backend-name` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:195 |
| `mcp-gateway accounts migrate-credentials --legacy-issuer` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:195 |
| `mcp-gateway add` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:401 |
| `mcp-gateway add --command` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:401 |
| `mcp-gateway add --config` | REMOVE | a second `--config` with its own `gateway.yaml` default beside the global one (and its `MCP_GATEWAY_CONFIG` form) | deduplicated: the global `--config` is `global = true`, so `<command> --config <path>` keeps parsing; only the subcommand's own `gateway.yaml` default goes (UPGRADING entry) | src/cli/mod.rs:401 |
| `mcp-gateway add -c` | REMOVE | short alias of `--config` | deduplicated: the global `--config` is `global = true`, so `<command> --config <path>` keeps parsing; only the subcommand's own `gateway.yaml` default goes (UPGRADING entry) | src/cli/mod.rs:401 |
| `mcp-gateway add --description` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:401 |
| `mcp-gateway add --env` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:401 |
| `mcp-gateway add -e` | KEEP | short alias of `--env` | - | src/cli/mod.rs:401 |
| `mcp-gateway add --force` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:401 |
| `mcp-gateway add --url` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:401 |
| `mcp-gateway add <name>` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:401 |
| `mcp-gateway add <trailing-command>` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:401 |
| `mcp-gateway audit` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:587 |
| `mcp-gateway audit show` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:723 |
| `mcp-gateway audit show --path` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:723 |
| `mcp-gateway audit show --session` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:723 |
| `mcp-gateway audit verify` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:708 |
| `mcp-gateway audit verify --anchor` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:708 |
| `mcp-gateway audit verify --archive` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:708 |
| `mcp-gateway audit verify --path` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:708 |
| `mcp-gateway cap` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:240 |
| `mcp-gateway cap discover` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:93 |
| `mcp-gateway cap discover --config-path` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:93 |
| `mcp-gateway cap discover --force` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:93 |
| `mcp-gateway cap discover --format` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:93 |
| `mcp-gateway cap discover -f` | KEEP | short alias of `--format` | - | src/cli/subcommands.rs:93 |
| `mcp-gateway cap discover --gateway-config` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:93 |
| `mcp-gateway cap discover --shadow` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:93 |
| `mcp-gateway cap discover --write-config` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:93 |
| `mcp-gateway cap import` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:52 |
| `mcp-gateway cap import --auth-key` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:52 |
| `mcp-gateway cap import --output` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:52 |
| `mcp-gateway cap import -o` | KEEP | short alias of `--output` | - | src/cli/subcommands.rs:52 |
| `mcp-gateway cap import --prefix` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:52 |
| `mcp-gateway cap import -p` | KEEP | short alias of `--prefix` | - | src/cli/subcommands.rs:52 |
| `mcp-gateway cap import <spec>` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:52 |
| `mcp-gateway cap import-url` | KEEP | user-facing command or flag for setup, operation or capability authoring (feature discovery) | - | src/cli/subcommands.rs:173 |
| `mcp-gateway cap import-url --auth` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:173 |
| `mcp-gateway cap import-url --cost-per-call` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:173 |
| `mcp-gateway cap import-url --dry-run` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:173 |
| `mcp-gateway cap import-url --max-endpoints` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:173 |
| `mcp-gateway cap import-url --output` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:173 |
| `mcp-gateway cap import-url -o` | KEEP | short alias of `--output` | - | src/cli/subcommands.rs:173 |
| `mcp-gateway cap import-url --prefix` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:173 |
| `mcp-gateway cap import-url -p` | KEEP | short alias of `--prefix` | - | src/cli/subcommands.rs:173 |
| `mcp-gateway cap import-url <url>` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:173 |
| `mcp-gateway cap install` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:124 |
| `mcp-gateway cap install --branch` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:124 |
| `mcp-gateway cap install --from-github` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:124 |
| `mcp-gateway cap install --output` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:124 |
| `mcp-gateway cap install -o` | KEEP | short alias of `--output` | - | src/cli/subcommands.rs:124 |
| `mcp-gateway cap install --repo` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:124 |
| `mcp-gateway cap install <name>` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:124 |
| `mcp-gateway cap list` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:41 |
| `mcp-gateway cap list <directory>` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:41 |
| `mcp-gateway cap pin` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:33 |
| `mcp-gateway cap pin <file>` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:33 |
| `mcp-gateway cap registry-list` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:160 |
| `mcp-gateway cap registry-list --capabilities` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:160 |
| `mcp-gateway cap registry-list -C` | KEEP | short alias of `--capabilities` | - | src/cli/subcommands.rs:160 |
| `mcp-gateway cap search` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:148 |
| `mcp-gateway cap search --capabilities` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:148 |
| `mcp-gateway cap search -C` | KEEP | short alias of `--capabilities` | - | src/cli/subcommands.rs:148 |
| `mcp-gateway cap search <query>` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:148 |
| `mcp-gateway cap test` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:72 |
| `mcp-gateway cap test --args` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:72 |
| `mcp-gateway cap test -a` | KEEP | short alias of `--args` | - | src/cli/subcommands.rs:72 |
| `mcp-gateway cap test <file>` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:72 |
| `mcp-gateway cap validate` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:20 |
| `mcp-gateway cap validate <file>` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:20 |
| `mcp-gateway dashboard-link` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:320 |
| `mcp-gateway dashboard-link --ca-cert` | KEEP | user-facing command or flag for setup, operation or capability authoring (env MCP_GATEWAY_CA_CERT) | - | src/cli/dashboard_link.rs:32 |
| `mcp-gateway dashboard-link --client-cert` | KEEP | user-facing command or flag for setup, operation or capability authoring (env MCP_GATEWAY_CLIENT_CERT) | - | src/cli/dashboard_link.rs:24 |
| `mcp-gateway dashboard-link --client-key` | KEEP | user-facing command or flag for setup, operation or capability authoring (env MCP_GATEWAY_CLIENT_KEY) | - | src/cli/dashboard_link.rs:27 |
| `mcp-gateway dashboard-link --url` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/dashboard_link.rs:12 |
| `mcp-gateway dashboard-link -u` | KEEP | short alias of `--url` | - | src/cli/dashboard_link.rs:12 |
| `mcp-gateway doctor` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:500 |
| `mcp-gateway doctor --config` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:500 |
| `mcp-gateway doctor -c` | KEEP | short alias of `--config` | - | src/cli/mod.rs:500 |
| `mcp-gateway doctor --fix` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:500 |
| `mcp-gateway doctor --format` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:500 |
| `mcp-gateway doctor -f` | KEEP | short alias of `--format` | - | src/cli/mod.rs:500 |
| `mcp-gateway doctor --shadow` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:500 |
| `mcp-gateway doctor --shadow-format` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:500 |
| `mcp-gateway doctor --show-stderr` | KEEP | diagnose a stdio backend that dies at start | - | src/cli/mod.rs:500 |
| `mcp-gateway doctor --start-stdio` | KEEP | diagnose a stdio backend that dies at start | - | src/cli/mod.rs:500 |
| `mcp-gateway events` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:322 |
| `mcp-gateway events dead-letters` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/events.rs:19 |
| `mcp-gateway events dead-letters --all` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/events.rs:42 |
| `mcp-gateway events dead-letters --ca-cert` | KEEP | user-facing command or flag for setup, operation or capability authoring (env MCP_GATEWAY_CA_CERT) | - | src/cli/dashboard_link.rs:32 |
| `mcp-gateway events dead-letters --client-cert` | KEEP | user-facing command or flag for setup, operation or capability authoring (env MCP_GATEWAY_CLIENT_CERT) | - | src/cli/dashboard_link.rs:24 |
| `mcp-gateway events dead-letters --client-key` | KEEP | user-facing command or flag for setup, operation or capability authoring (env MCP_GATEWAY_CLIENT_KEY) | - | src/cli/dashboard_link.rs:27 |
| `mcp-gateway events dead-letters --reason` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/events.rs:48 |
| `mcp-gateway events dead-letters --subscription` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/events.rs:45 |
| `mcp-gateway events dead-letters --url` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/events.rs:51 |
| `mcp-gateway events dead-letters -u` | KEEP | short alias of `--url` | - | src/cli/events.rs:51 |
| `mcp-gateway events dead-letters <action>` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/events.rs:37 |
| `mcp-gateway events dead-letters <id>` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/events.rs:39 |
| `mcp-gateway get` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:467 |
| `mcp-gateway get --config` | REMOVE | a second `--config` with its own `gateway.yaml` default beside the global one (and its `MCP_GATEWAY_CONFIG` form) | deduplicated: the global `--config` is `global = true`, so `<command> --config <path>` keeps parsing; only the subcommand's own `gateway.yaml` default goes (UPGRADING entry) | src/cli/mod.rs:467 |
| `mcp-gateway get -c` | REMOVE | short alias of `--config` | deduplicated: the global `--config` is `global = true`, so `<command> --config <path>` keeps parsing; only the subcommand's own `gateway.yaml` default goes (UPGRADING entry) | src/cli/mod.rs:467 |
| `mcp-gateway get <name>` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:467 |
| `mcp-gateway hash-key` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:282 |
| `mcp-gateway hash-key --verify` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:282 |
| `mcp-gateway identity` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:270 |
| `mcp-gateway identity grants` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/identity.rs:16 |
| `mcp-gateway identity grants grant` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/identity.rs:41 |
| `mcp-gateway identity grants grant --agent` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/identity.rs:41 |
| `mcp-gateway identity grants grant --any-agent` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/identity.rs:41 |
| `mcp-gateway identity grants grant --capability` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/identity.rs:41 |
| `mcp-gateway identity grants grant --expires-at` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/identity.rs:41 |
| `mcp-gateway identity grants grant --file` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/identity.rs:41 |
| `mcp-gateway identity grants grant --format` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/identity.rs:41 |
| `mcp-gateway identity grants grant -f` | KEEP | short alias of `--format` | - | src/cli/identity.rs:41 |
| `mcp-gateway identity grants grant --grant-id` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/identity.rs:41 |
| `mcp-gateway identity grants grant --owner` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/identity.rs:41 |
| `mcp-gateway identity grants grant --owner-label` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/identity.rs:41 |
| `mcp-gateway identity grants grant --provenance` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/identity.rs:41 |
| `mcp-gateway identity grants grant --reason` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/identity.rs:41 |
| `mcp-gateway identity grants grant --replace` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/identity.rs:41 |
| `mcp-gateway identity grants grant --scope` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/identity.rs:41 |
| `mcp-gateway identity grants grant --subject` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/identity.rs:41 |
| `mcp-gateway identity grants grant --subject-label` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/identity.rs:41 |
| `mcp-gateway identity grants grant --tool` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/identity.rs:41 |
| `mcp-gateway identity grants grant --ttl-seconds` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/identity.rs:41 |
| `mcp-gateway identity grants list` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/identity.rs:25 |
| `mcp-gateway identity grants list --active-only` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/identity.rs:25 |
| `mcp-gateway identity grants list --file` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/identity.rs:25 |
| `mcp-gateway identity grants list --format` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/identity.rs:25 |
| `mcp-gateway identity grants list -f` | KEEP | short alias of `--format` | - | src/cli/identity.rs:25 |
| `mcp-gateway identity grants revoke` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/identity.rs:114 |
| `mcp-gateway identity grants revoke --file` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/identity.rs:114 |
| `mcp-gateway identity grants revoke --format` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/identity.rs:114 |
| `mcp-gateway identity grants revoke -f` | KEEP | short alias of `--format` | - | src/cli/identity.rs:114 |
| `mcp-gateway identity grants revoke --grant-id` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/identity.rs:114 |
| `mcp-gateway identity grants revoke --revoked-at` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/identity.rs:114 |
| `mcp-gateway import` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:247 |
| `mcp-gateway import apply` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:233 |
| `mcp-gateway import apply --context-integrity-profile` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:233 |
| `mcp-gateway import apply --force` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:233 |
| `mcp-gateway import apply --format` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:233 |
| `mcp-gateway import apply -f` | KEEP | short alias of `--format` | - | src/cli/subcommands.rs:233 |
| `mcp-gateway import apply --kind` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:233 |
| `mcp-gateway import apply --output` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:233 |
| `mcp-gateway import apply -o` | KEEP | short alias of `--output` | - | src/cli/subcommands.rs:233 |
| `mcp-gateway import apply --source-name` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:233 |
| `mcp-gateway import apply <file>` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:233 |
| `mcp-gateway import preview` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:209 |
| `mcp-gateway import preview --context-integrity-profile` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:209 |
| `mcp-gateway import preview --format` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:209 |
| `mcp-gateway import preview -f` | KEEP | short alias of `--format` | - | src/cli/subcommands.rs:209 |
| `mcp-gateway import preview --kind` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:209 |
| `mcp-gateway import preview --source-name` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:209 |
| `mcp-gateway import preview <file>` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:209 |
| `mcp-gateway init` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:291 |
| `mcp-gateway init --output` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:291 |
| `mcp-gateway init -o` | KEEP | short alias of `--output` | - | src/cli/mod.rs:291 |
| `mcp-gateway init --profile` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:291 |
| `mcp-gateway init --with-examples` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:291 |
| `mcp-gateway kubernetes` | INTERNAL | enterprise-alpha controller | `#[command(hide = true)]`: still runs; the DEPLOYMENT.md section moves to deploy/kubernetes/enterprise-alpha/README.md (P6) | src/cli/mod.rs:251 |
| `mcp-gateway kubernetes apply-plan` | INTERNAL | enterprise-alpha controller | `#[command(hide = true)]`: still runs; the DEPLOYMENT.md section moves to deploy/kubernetes/enterprise-alpha/README.md (P6) | src/cli/subcommands.rs:347 |
| `mcp-gateway kubernetes apply-plan --approve-apply` | INTERNAL | enterprise-alpha controller | `#[command(hide = true)]`: still runs; the DEPLOYMENT.md section moves to deploy/kubernetes/enterprise-alpha/README.md (P6) | src/cli/subcommands.rs:347 |
| `mcp-gateway kubernetes apply-plan --execute` | INTERNAL | enterprise-alpha controller | `#[command(hide = true)]`: still runs; the DEPLOYMENT.md section moves to deploy/kubernetes/enterprise-alpha/README.md (P6) | src/cli/subcommands.rs:347 |
| `mcp-gateway kubernetes apply-plan --format` | INTERNAL | enterprise-alpha controller | `#[command(hide = true)]`: still runs; the DEPLOYMENT.md section moves to deploy/kubernetes/enterprise-alpha/README.md (P6) | src/cli/subcommands.rs:347 |
| `mcp-gateway kubernetes apply-plan -f` | INTERNAL | short alias of `--format` | `#[command(hide = true)]`: still runs; the DEPLOYMENT.md section moves to deploy/kubernetes/enterprise-alpha/README.md (P6) | src/cli/subcommands.rs:347 |
| `mcp-gateway kubernetes apply-plan --namespace` | INTERNAL | enterprise-alpha controller | `#[command(hide = true)]`: still runs; the DEPLOYMENT.md section moves to deploy/kubernetes/enterprise-alpha/README.md (P6) | src/cli/subcommands.rs:347 |
| `mcp-gateway kubernetes apply-plan -n` | INTERNAL | short alias of `--namespace` | `#[command(hide = true)]`: still runs; the DEPLOYMENT.md section moves to deploy/kubernetes/enterprise-alpha/README.md (P6) | src/cli/subcommands.rs:347 |
| `mcp-gateway kubernetes apply-plan <resources>` | INTERNAL | enterprise-alpha controller | `#[command(hide = true)]`: still runs; the DEPLOYMENT.md section moves to deploy/kubernetes/enterprise-alpha/README.md (P6) | src/cli/subcommands.rs:347 |
| `mcp-gateway kubernetes controller` | INTERNAL | enterprise-alpha controller | `#[command(hide = true)]`: still runs; the DEPLOYMENT.md section moves to deploy/kubernetes/enterprise-alpha/README.md (P6) | src/cli/subcommands.rs:316 |
| `mcp-gateway kubernetes controller --cycles` | INTERNAL | enterprise-alpha controller | `#[command(hide = true)]`: still runs; the DEPLOYMENT.md section moves to deploy/kubernetes/enterprise-alpha/README.md (P6) | src/cli/subcommands.rs:316 |
| `mcp-gateway kubernetes controller --format` | INTERNAL | enterprise-alpha controller | `#[command(hide = true)]`: still runs; the DEPLOYMENT.md section moves to deploy/kubernetes/enterprise-alpha/README.md (P6) | src/cli/subcommands.rs:316 |
| `mcp-gateway kubernetes controller -f` | INTERNAL | short alias of `--format` | `#[command(hide = true)]`: still runs; the DEPLOYMENT.md section moves to deploy/kubernetes/enterprise-alpha/README.md (P6) | src/cli/subcommands.rs:316 |
| `mcp-gateway kubernetes controller --interval-seconds` | INTERNAL | enterprise-alpha controller | `#[command(hide = true)]`: still runs; the DEPLOYMENT.md section moves to deploy/kubernetes/enterprise-alpha/README.md (P6) | src/cli/subcommands.rs:316 |
| `mcp-gateway kubernetes controller --namespace` | INTERNAL | enterprise-alpha controller | `#[command(hide = true)]`: still runs; the DEPLOYMENT.md section moves to deploy/kubernetes/enterprise-alpha/README.md (P6) | src/cli/subcommands.rs:316 |
| `mcp-gateway kubernetes controller -n` | INTERNAL | short alias of `--namespace` | `#[command(hide = true)]`: still runs; the DEPLOYMENT.md section moves to deploy/kubernetes/enterprise-alpha/README.md (P6) | src/cli/subcommands.rs:316 |
| `mcp-gateway kubernetes controller --watch` | INTERNAL | enterprise-alpha controller | `#[command(hide = true)]`: still runs; the DEPLOYMENT.md section moves to deploy/kubernetes/enterprise-alpha/README.md (P6) | src/cli/subcommands.rs:316 |
| `mcp-gateway kubernetes controller <resources>` | INTERNAL | enterprise-alpha controller | `#[command(hide = true)]`: still runs; the DEPLOYMENT.md section moves to deploy/kubernetes/enterprise-alpha/README.md (P6) | src/cli/subcommands.rs:316 |
| `mcp-gateway kubernetes plan` | INTERNAL | enterprise-alpha controller | `#[command(hide = true)]`: still runs; the DEPLOYMENT.md section moves to deploy/kubernetes/enterprise-alpha/README.md (P6) | src/cli/subcommands.rs:300 |
| `mcp-gateway kubernetes plan --format` | INTERNAL | enterprise-alpha controller | `#[command(hide = true)]`: still runs; the DEPLOYMENT.md section moves to deploy/kubernetes/enterprise-alpha/README.md (P6) | src/cli/subcommands.rs:300 |
| `mcp-gateway kubernetes plan -f` | INTERNAL | short alias of `--format` | `#[command(hide = true)]`: still runs; the DEPLOYMENT.md section moves to deploy/kubernetes/enterprise-alpha/README.md (P6) | src/cli/subcommands.rs:300 |
| `mcp-gateway kubernetes plan --namespace` | INTERNAL | enterprise-alpha controller | `#[command(hide = true)]`: still runs; the DEPLOYMENT.md section moves to deploy/kubernetes/enterprise-alpha/README.md (P6) | src/cli/subcommands.rs:300 |
| `mcp-gateway kubernetes plan -n` | INTERNAL | short alias of `--namespace` | `#[command(hide = true)]`: still runs; the DEPLOYMENT.md section moves to deploy/kubernetes/enterprise-alpha/README.md (P6) | src/cli/subcommands.rs:300 |
| `mcp-gateway kubernetes plan <resources>` | INTERNAL | enterprise-alpha controller | `#[command(hide = true)]`: still runs; the DEPLOYMENT.md section moves to deploy/kubernetes/enterprise-alpha/README.md (P6) | src/cli/subcommands.rs:300 |
| `mcp-gateway list` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:453 |
| `mcp-gateway list --available` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:453 |
| `mcp-gateway list --config` | REMOVE | a second `--config` with its own `gateway.yaml` default beside the global one (and its `MCP_GATEWAY_CONFIG` form) | deduplicated: the global `--config` is `global = true`, so `<command> --config <path>` keeps parsing; only the subcommand's own `gateway.yaml` default goes (UPGRADING entry) | src/cli/mod.rs:453 |
| `mcp-gateway list -c` | REMOVE | short alias of `--config` | deduplicated: the global `--config` is `global = true`, so `<command> --config <path>` keeps parsing; only the subcommand's own `gateway.yaml` default goes (UPGRADING entry) | src/cli/mod.rs:453 |
| `mcp-gateway list --json` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:453 |
| `mcp-gateway ranking` | INTERNAL | offline evaluation of the adaptive ranker; developer tooling | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/mod.rs:255 |
| `mcp-gateway ranking eval` | INTERNAL | offline evaluation of the adaptive ranker; developer tooling | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:269 |
| `mcp-gateway ranking eval --format` | INTERNAL | offline evaluation of the adaptive ranker; developer tooling | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:269 |
| `mcp-gateway ranking eval -f` | INTERNAL | short alias of `--format` | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:269 |
| `mcp-gateway ranking eval <file>` | INTERNAL | offline evaluation of the adaptive ranker; developer tooling | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:269 |
| `mcp-gateway remove` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:437 |
| `mcp-gateway remove --config` | REMOVE | a second `--config` with its own `gateway.yaml` default beside the global one (and its `MCP_GATEWAY_CONFIG` form) | deduplicated: the global `--config` is `global = true`, so `<command> --config <path>` keeps parsing; only the subcommand's own `gateway.yaml` default goes (UPGRADING entry) | src/cli/mod.rs:437 |
| `mcp-gateway remove -c` | REMOVE | short alias of `--config` | deduplicated: the global `--config` is `global = true`, so `<command> --config <path>` keeps parsing; only the subcommand's own `gateway.yaml` default goes (UPGRADING entry) | src/cli/mod.rs:437 |
| `mcp-gateway remove --force` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:437 |
| `mcp-gateway remove <name>` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:437 |
| `mcp-gateway runtime` | INTERNAL | sandbox substrate compiler behind the non-default `runtime-substrate` feature (feature runtime-substrate) | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/mod.rs:592 |
| `mcp-gateway runtime compile` | INTERNAL | sandbox substrate compiler behind the non-default `runtime-substrate` feature | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/mod.rs:602 |
| `mcp-gateway runtime compile --both` | INTERNAL | sandbox substrate compiler behind the non-default `runtime-substrate` feature | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/mod.rs:602 |
| `mcp-gateway runtime compile <DESCRIPTOR>` | INTERNAL | sandbox substrate compiler behind the non-default `runtime-substrate` feature | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/mod.rs:602 |
| `mcp-gateway serve` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:223 |
| `mcp-gateway serve --stdio` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:223 |
| `mcp-gateway setup` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:374 |
| `mcp-gateway setup export` | KEEP | user-facing command or flag for setup, operation or capability authoring (feature config-export) | - | src/cli/setup.rs:67 |
| `mcp-gateway setup export --config` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/setup.rs:67 |
| `mcp-gateway setup export -c` | KEEP | short alias of `--config` | - | src/cli/setup.rs:67 |
| `mcp-gateway setup export --dry-run` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/setup.rs:67 |
| `mcp-gateway setup export --mode` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/setup.rs:67 |
| `mcp-gateway setup export -m` | KEEP | short alias of `--mode` | - | src/cli/setup.rs:67 |
| `mcp-gateway setup export --name` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/setup.rs:67 |
| `mcp-gateway setup export -n` | KEEP | short alias of `--name` | - | src/cli/setup.rs:67 |
| `mcp-gateway setup export --rollback` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/setup.rs:67 |
| `mcp-gateway setup export --target` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/setup.rs:67 |
| `mcp-gateway setup export -t` | KEEP | short alias of `--target` | - | src/cli/setup.rs:67 |
| `mcp-gateway setup export --watch` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/setup.rs:67 |
| `mcp-gateway setup export -w` | KEEP | short alias of `--watch` | - | src/cli/setup.rs:67 |
| `mcp-gateway setup wizard` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/setup.rs:22 |
| `mcp-gateway setup wizard --configure-client` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/setup.rs:22 |
| `mcp-gateway setup wizard --force` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/setup.rs:22 |
| `mcp-gateway setup wizard --output` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/setup.rs:22 |
| `mcp-gateway setup wizard -o` | KEEP | short alias of `--output` | - | src/cli/setup.rs:22 |
| `mcp-gateway setup wizard --yes` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/setup.rs:22 |
| `mcp-gateway skills` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:366 |
| `mcp-gateway skills generate` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/skills.rs:47 |
| `mcp-gateway skills generate --capabilities` | AUTO | defaults to `./capabilities` and ignores the config; derive from `capabilities.directories` of the loaded config (env MCP_GATEWAY_CAPABILITIES) | flag stays as a hidden override, still honoured; `MCP_GATEWAY_CAPABILITIES` likewise | src/cli/skills.rs:47 |
| `mcp-gateway skills generate -C` | AUTO | short alias of `--capabilities` | flag stays as a hidden override, still honoured; `MCP_GATEWAY_CAPABILITIES` likewise | src/cli/skills.rs:47 |
| `mcp-gateway skills generate --category` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/skills.rs:47 |
| `mcp-gateway skills generate --dry-run` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/skills.rs:47 |
| `mcp-gateway skills generate --install` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/skills.rs:47 |
| `mcp-gateway skills generate --out-dir` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/skills.rs:47 |
| `mcp-gateway skills generate --server` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/skills.rs:47 |
| `mcp-gateway skills import` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/skills.rs:91 |
| `mcp-gateway skills import --registry` | KEEP | user-facing command or flag for setup, operation or capability authoring (env MCP_GATEWAY_SKILLS_REGISTRY) | - | src/cli/skills.rs:91 |
| `mcp-gateway skills import <source>` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/skills.rs:91 |
| `mcp-gateway skills list` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/skills.rs:103 |
| `mcp-gateway skills list --registry` | KEEP | user-facing command or flag for setup, operation or capability authoring (env MCP_GATEWAY_SKILLS_REGISTRY) | - | src/cli/skills.rs:103 |
| `mcp-gateway skills remove` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/skills.rs:135 |
| `mcp-gateway skills remove --registry` | KEEP | user-facing command or flag for setup, operation or capability authoring (env MCP_GATEWAY_SKILLS_REGISTRY) | - | src/cli/skills.rs:135 |
| `mcp-gateway skills remove <name>` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/skills.rs:135 |
| `mcp-gateway skills search` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/skills.rs:111 |
| `mcp-gateway skills search --registry` | KEEP | user-facing command or flag for setup, operation or capability authoring (env MCP_GATEWAY_SKILLS_REGISTRY) | - | src/cli/skills.rs:111 |
| `mcp-gateway skills search <query>` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/skills.rs:111 |
| `mcp-gateway skills show` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/skills.rs:123 |
| `mcp-gateway skills show --registry` | KEEP | user-facing command or flag for setup, operation or capability authoring (env MCP_GATEWAY_SKILLS_REGISTRY) | - | src/cli/skills.rs:123 |
| `mcp-gateway skills show <name>` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/skills.rs:123 |
| `mcp-gateway stats` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:309 |
| `mcp-gateway stats --url` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:309 |
| `mcp-gateway stats -u` | KEEP | short alias of `--url` | - | src/cli/mod.rs:309 |
| `mcp-gateway tls` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:262 |
| `mcp-gateway tls init-ca` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:628 |
| `mcp-gateway tls init-ca --cn` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:628 |
| `mcp-gateway tls init-ca --out` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:628 |
| `mcp-gateway tls init-ca -o` | KEEP | short alias of `--out` | - | src/cli/subcommands.rs:628 |
| `mcp-gateway tls init-ca --validity-days` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:628 |
| `mcp-gateway tls issue-client` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:672 |
| `mcp-gateway tls issue-client --ca-cert` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:672 |
| `mcp-gateway tls issue-client --ca-key` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:672 |
| `mcp-gateway tls issue-client --cn` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:672 |
| `mcp-gateway tls issue-client --ou` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:672 |
| `mcp-gateway tls issue-client --out` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:672 |
| `mcp-gateway tls issue-client -o` | KEEP | short alias of `--out` | - | src/cli/subcommands.rs:672 |
| `mcp-gateway tls issue-client --spiffe-uri` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:672 |
| `mcp-gateway tls issue-client --validity-days` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:672 |
| `mcp-gateway tls issue-server` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:644 |
| `mcp-gateway tls issue-server --ca-cert` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:644 |
| `mcp-gateway tls issue-server --ca-key` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:644 |
| `mcp-gateway tls issue-server --cn` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:644 |
| `mcp-gateway tls issue-server --out` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:644 |
| `mcp-gateway tls issue-server -o` | KEEP | short alias of `--out` | - | src/cli/subcommands.rs:644 |
| `mcp-gateway tls issue-server --san-dns` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:644 |
| `mcp-gateway tls issue-server --validity-days` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/subcommands.rs:644 |
| `mcp-gateway tool` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:359 |
| `mcp-gateway tool completions` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:717 |
| `mcp-gateway tool completions --capabilities` | AUTO | defaults to `./capabilities` and ignores the config; derive from `capabilities.directories` of the loaded config (env MCP_GATEWAY_CAPABILITIES) | flag stays as a hidden override, still honoured; `MCP_GATEWAY_CAPABILITIES` likewise | src/cli/mod.rs:717 |
| `mcp-gateway tool completions -C` | AUTO | short alias of `--capabilities` | flag stays as a hidden override, still honoured; `MCP_GATEWAY_CAPABILITIES` likewise | src/cli/mod.rs:717 |
| `mcp-gateway tool completions <shell>` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:717 |
| `mcp-gateway tool inspect` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:686 |
| `mcp-gateway tool inspect --capabilities` | AUTO | defaults to `./capabilities` and ignores the config; derive from `capabilities.directories` of the loaded config (env MCP_GATEWAY_CAPABILITIES) | flag stays as a hidden override, still honoured; `MCP_GATEWAY_CAPABILITIES` likewise | src/cli/mod.rs:686 |
| `mcp-gateway tool inspect -C` | AUTO | short alias of `--capabilities` | flag stays as a hidden override, still honoured; `MCP_GATEWAY_CAPABILITIES` likewise | src/cli/mod.rs:686 |
| `mcp-gateway tool inspect --format` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:686 |
| `mcp-gateway tool inspect -f` | KEEP | short alias of `--format` | - | src/cli/mod.rs:686 |
| `mcp-gateway tool inspect <tool>` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:686 |
| `mcp-gateway tool invoke` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:627 |
| `mcp-gateway tool invoke --args` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:627 |
| `mcp-gateway tool invoke -a` | KEEP | short alias of `--args` | - | src/cli/mod.rs:627 |
| `mcp-gateway tool invoke --capabilities` | AUTO | defaults to `./capabilities` and ignores the config; derive from `capabilities.directories` of the loaded config (env MCP_GATEWAY_CAPABILITIES) | flag stays as a hidden override, still honoured; `MCP_GATEWAY_CAPABILITIES` likewise | src/cli/mod.rs:627 |
| `mcp-gateway tool invoke -C` | AUTO | short alias of `--capabilities` | flag stays as a hidden override, still honoured; `MCP_GATEWAY_CAPABILITIES` likewise | src/cli/mod.rs:627 |
| `mcp-gateway tool invoke --format` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:627 |
| `mcp-gateway tool invoke -f` | KEEP | short alias of `--format` | - | src/cli/mod.rs:627 |
| `mcp-gateway tool invoke <KEY=VALUE>` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:627 |
| `mcp-gateway tool invoke <tool>` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:627 |
| `mcp-gateway tool list` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:666 |
| `mcp-gateway tool list --capabilities` | AUTO | defaults to `./capabilities` and ignores the config; derive from `capabilities.directories` of the loaded config (env MCP_GATEWAY_CAPABILITIES) | flag stays as a hidden override, still honoured; `MCP_GATEWAY_CAPABILITIES` likewise | src/cli/mod.rs:666 |
| `mcp-gateway tool list -C` | AUTO | short alias of `--capabilities` | flag stays as a hidden override, still honoured; `MCP_GATEWAY_CAPABILITIES` likewise | src/cli/mod.rs:666 |
| `mcp-gateway tool list --format` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:666 |
| `mcp-gateway tool list -f` | KEEP | short alias of `--format` | - | src/cli/mod.rs:666 |
| `mcp-gateway trust` | INTERNAL | TrustCard and CBOM metadata for catalogue maintainers | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/mod.rs:266 |
| `mcp-gateway trust generate` | INTERNAL | TrustCard and CBOM metadata for catalogue maintainers | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:451 |
| `mcp-gateway trust generate --capabilities` | INTERNAL | TrustCard and CBOM metadata for catalogue maintainers (env MCP_GATEWAY_CAPABILITIES) | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:451 |
| `mcp-gateway trust generate -C` | INTERNAL | short alias of `--capabilities` | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:451 |
| `mcp-gateway trust generate --format` | INTERNAL | TrustCard and CBOM metadata for catalogue maintainers | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:451 |
| `mcp-gateway trust generate -f` | INTERNAL | short alias of `--format` | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:451 |
| `mcp-gateway trust generate --output` | INTERNAL | TrustCard and CBOM metadata for catalogue maintainers | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:451 |
| `mcp-gateway trust generate -o` | INTERNAL | short alias of `--output` | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:451 |
| `mcp-gateway trust inspect` | INTERNAL | TrustCard and CBOM metadata for catalogue maintainers | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:472 |
| `mcp-gateway trust inspect --capabilities` | INTERNAL | TrustCard and CBOM metadata for catalogue maintainers (env MCP_GATEWAY_CAPABILITIES) | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:472 |
| `mcp-gateway trust inspect -C` | INTERNAL | short alias of `--capabilities` | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:472 |
| `mcp-gateway trust inspect --format` | INTERNAL | TrustCard and CBOM metadata for catalogue maintainers | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:472 |
| `mcp-gateway trust inspect -f` | INTERNAL | short alias of `--format` | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:472 |
| `mcp-gateway trust inspect <name>` | INTERNAL | TrustCard and CBOM metadata for catalogue maintainers | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:472 |
| `mcp-gateway trust lab` | INTERNAL | certification lab for catalogue maintainers and CI | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:520 |
| `mcp-gateway trust lab evaluate` | INTERNAL | certification lab for catalogue maintainers and CI | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:528 |
| `mcp-gateway trust lab evaluate --active-fixtures` | INTERNAL | certification lab for catalogue maintainers and CI | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:528 |
| `mcp-gateway trust lab evaluate --baseline` | INTERNAL | certification lab for catalogue maintainers and CI | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:528 |
| `mcp-gateway trust lab evaluate --baseline-id` | INTERNAL | certification lab for catalogue maintainers and CI | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:528 |
| `mcp-gateway trust lab evaluate --baseline-registry` | INTERNAL | certification lab for catalogue maintainers and CI | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:528 |
| `mcp-gateway trust lab evaluate --capabilities` | INTERNAL | certification lab for catalogue maintainers and CI (env MCP_GATEWAY_CAPABILITIES) | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:528 |
| `mcp-gateway trust lab evaluate -C` | INTERNAL | short alias of `--capabilities` | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:528 |
| `mcp-gateway trust lab evaluate --certification-score` | INTERNAL | certification lab for catalogue maintainers and CI | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:528 |
| `mcp-gateway trust lab evaluate --enforce` | INTERNAL | certification lab for catalogue maintainers and CI | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:528 |
| `mcp-gateway trust lab evaluate --execute-active-fixtures` | INTERNAL | certification lab for catalogue maintainers and CI | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:528 |
| `mcp-gateway trust lab evaluate --format` | INTERNAL | certification lab for catalogue maintainers and CI | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:528 |
| `mcp-gateway trust lab evaluate -f` | INTERNAL | short alias of `--format` | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:528 |
| `mcp-gateway trust lab evaluate --minimum-score` | INTERNAL | certification lab for catalogue maintainers and CI | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:528 |
| `mcp-gateway trust lab evaluate --runtime-image` | INTERNAL | certification lab for catalogue maintainers and CI | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:528 |
| `mcp-gateway trust lab evaluate --runtime-provider-plan` | INTERNAL | certification lab for catalogue maintainers and CI | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:528 |
| `mcp-gateway trust lab evaluate --update-baseline-registry` | INTERNAL | certification lab for catalogue maintainers and CI | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:528 |
| `mcp-gateway trust lab evaluate --write-baseline` | INTERNAL | certification lab for catalogue maintainers and CI | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:528 |
| `mcp-gateway trust lab evaluate <name>` | INTERNAL | certification lab for catalogue maintainers and CI | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:528 |
| `mcp-gateway trust validate` | INTERNAL | TrustCard and CBOM metadata for catalogue maintainers | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:493 |
| `mcp-gateway trust validate --capabilities` | INTERNAL | TrustCard and CBOM metadata for catalogue maintainers (env MCP_GATEWAY_CAPABILITIES) | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:493 |
| `mcp-gateway trust validate -C` | INTERNAL | short alias of `--capabilities` | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:493 |
| `mcp-gateway trust validate --file` | INTERNAL | TrustCard and CBOM metadata for catalogue maintainers | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:493 |
| `mcp-gateway trust validate --format` | INTERNAL | TrustCard and CBOM metadata for catalogue maintainers | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:493 |
| `mcp-gateway trust validate -f` | INTERNAL | short alias of `--format` | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:493 |
| `mcp-gateway trust validate --strict` | INTERNAL | TrustCard and CBOM metadata for catalogue maintainers | `#[command(hide = true)]`: still runs, gone from `--help`; UPGRADING names it | src/cli/subcommands.rs:493 |
| `mcp-gateway upgrade` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:560 |
| `mcp-gateway upgrade --data-dir` | KEEP | flag form of `MCP_GATEWAY_CONFIG_DIR` for volume-mounted deployments (env MCP_GATEWAY_CONFIG_DIR) | - | src/cli/mod.rs:560 |
| `mcp-gateway upgrade --dry-run` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:560 |
| `mcp-gateway upgrade --quiet` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:560 |
| `mcp-gateway upgrade -q` | KEEP | short alias of `--quiet` | - | src/cli/mod.rs:560 |
| `mcp-gateway validate` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:330 |
| `mcp-gateway validate --fix` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:330 |
| `mcp-gateway validate --format` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:330 |
| `mcp-gateway validate -f` | KEEP | short alias of `--format` | - | src/cli/mod.rs:330 |
| `mcp-gateway validate --no-color` | AUTO | unset: colour follows the terminal and `NO_COLOR` | hidden flag, still honoured | src/cli/mod.rs:330 |
| `mcp-gateway validate --severity` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:330 |
| `mcp-gateway validate -s` | KEEP | short alias of `--severity` | - | src/cli/mod.rs:330 |
| `mcp-gateway validate <paths>` | KEEP | user-facing command or flag for setup, operation or capability authoring | - | src/cli/mod.rs:330 |

## Surface: env

| Item | Class | Reason | Migration | Defined at |
|---|---|---|---|---|
| `MCP_GATEWAY_<SECTION>__<KEY>` | KEEP | env form of any KEEP config key (container deployments); follows the key's class | - | src/config/mod.rs:193 |
| `MCP_GATEWAY_AUTH__ENABLED` | KEEP | documented overlay spelling of `auth.enabled` (Helm chart) | - | deploy/helm/mcp-gateway/templates/_helpers.tpl:170 |
| `MCP_GATEWAY_CAPABILITIES` | AUTO | env form of `-C/--capabilities`; derive from the config's `capabilities.directories` | hidden override, still honoured; UPGRADING entry | src/cli/mod.rs:637 |
| `MCP_GATEWAY_CA_CERT` | KEEP | credentials for `dashboard-link` and `events dead-letters` against a remote gateway | - | src/cli/dashboard_link.rs:31 |
| `MCP_GATEWAY_CLIENT_CERT` | KEEP | credentials for `dashboard-link` and `events dead-letters` against a remote gateway | - | src/cli/dashboard_link.rs:23 |
| `MCP_GATEWAY_CLIENT_KEY` | KEEP | credentials for `dashboard-link` and `events dead-letters` against a remote gateway | - | src/cli/dashboard_link.rs:26 |
| `MCP_GATEWAY_CONFIG` | KEEP | container and service-manager form of the global flags | - | src/cli/mod.rs:127 |
| `MCP_GATEWAY_CONFIG_DIR` | KEEP | data directory for persisted state (src/gateway/server/persistence.rs:181); volume-mounted deployments set it | - | src/cli/mod.rs:571 |
| `MCP_GATEWAY_FIREWALL_SKIP_KEYS` | KEEP | security policy list (rule 1): replaces the argument keys the injection scan treats as free text, so it can widen or narrow the scan; an explicit operator decision (rule 2) | - | src/security/firewall/input_scanner.rs:85 |
| `MCP_GATEWAY_HOST` | KEEP | container and service-manager form of the global flags | - | src/cli/mod.rs:135 |
| `MCP_GATEWAY_KIND_CLUSTER` | INTERNAL | variable of a repository test script, not read by the binary | test-only; docs say so | deploy/kubernetes/enterprise-alpha/scripts/kind-rollback-smoke.sh:19 |
| `MCP_GATEWAY_KIND_KEEP` | INTERNAL | variable of a repository test script, not read by the binary | test-only; docs say so | deploy/kubernetes/enterprise-alpha/README.md:155 |
| `MCP_GATEWAY_KIND_NAMESPACE` | INTERNAL | variable of a repository test script, not read by the binary | test-only; docs say so | deploy/kubernetes/enterprise-alpha/scripts/kind-rollback-smoke.sh:20 |
| `MCP_GATEWAY_LOG_FORMAT` | KEEP | container and service-manager form of the global flags | - | src/cli/mod.rs:148 |
| `MCP_GATEWAY_LOG_LEVEL` | KEEP | container and service-manager form of the global flags | - | src/cli/mod.rs:142 |
| `MCP_GATEWAY_METRICS_TOKEN` | KEEP | example name the user picks for `env:` in `server.metrics_token`; not read by the binary | - | docs/DEPLOYMENT.md:678 |
| `MCP_GATEWAY_PORT` | KEEP | container and service-manager form of the global flags | - | src/cli/mod.rs:131 |
| `MCP_GATEWAY_ROLLOUT_TIMEOUT` | INTERNAL | variable of a repository test script, not read by the binary | test-only; docs say so | deploy/kubernetes/enterprise-alpha/scripts/kind-rollback-smoke.sh:25 |
| `MCP_GATEWAY_RUNTIME_DOCKER_IMAGE` | INTERNAL | variable of a repository test script, not read by the binary | test-only; docs say so | docs/runtime/provider_planner.md:193 |
| `MCP_GATEWAY_RUNTIME_DOCKER_RESTART_IMAGE` | INTERNAL | variable of a repository test script, not read by the binary | test-only; docs say so | docs/runtime/provider_planner.md:194 |
| `MCP_GATEWAY_RUNTIME_DOCKER_SMOKE` | INTERNAL | variable of a repository test script, not read by the binary | test-only; docs say so | docs/runtime/provider_planner.md:185 |
| `MCP_GATEWAY_SERVER__ALLOW_UNAUTHENTICATED_NETWORK_BIND` | KEEP | documented overlay spelling of a KEEP `server` key | - | README.md:102 |
| `MCP_GATEWAY_SERVER__CLEARTEXT_HTTP` | KEEP | documented overlay spelling of a KEEP `server` key | - | README.md:102 |
| `MCP_GATEWAY_SERVER__PORT` | KEEP | documented overlay spelling of a KEEP `server` key | - | docs/DEPLOYMENT.md:335 |
| `MCP_GATEWAY_SERVER__PUBLIC_URL` | KEEP | documented overlay spelling of a KEEP `server` key | - | deploy/single-node/docker-compose.yaml:50 |
| `MCP_GATEWAY_SKILLS_REGISTRY` | KEEP | env form of `skills --registry` | - | src/cli/skills.rs:97 |
| `MCP_GATEWAY_TEST_ERA_PROBE_CAP_MS` | INTERNAL | test hook compiled into debug builds only (`cfg(debug_assertions)`); absent from release binaries | test-only | src/backend/era.rs:311 |
| `MCP_GATEWAY_TEST_HOLD_CAPABILITY_SCAN` | INTERNAL | test hook compiled into debug builds only (`cfg(debug_assertions)`); absent from release binaries | test-only | src/capability/backend/initial_scan.rs:109 |
| `MCP_GATEWAY_TEST_HOME_DIR` | INTERNAL | test hook compiled into debug builds only (`cfg(debug_assertions)`); absent from release binaries | test-only | src/home_dir.rs:23 |
| `MCP_GATEWAY_TEST_PAUSE_AT_PUBLISHED` | INTERNAL | test hook compiled into debug builds only (`cfg(debug_assertions)`); absent from release binaries | test-only | src/gateway/task_service/execution/pause_hook.rs:16 |
| `MCP_GATEWAY_TOKEN` | KEEP | credentials for `dashboard-link` and `events dead-letters` against a remote gateway | - | src/commands/dashboard_link.rs:13 |
| `MCP_GATEWAY_TRANSPARENCY_SECRET` | KEEP | example name the user picks for `env:` in `security.transparency_log.shared_secret`; not read by the binary | - | examples/gateway-full.yaml:74 |

## Surface: routes

| Item | Class | Reason | Migration | Defined at |
|---|---|---|---|---|
| `/.well-known/jwks.json` | KEEP | OAuth discovery documents clients fetch | - | src/gateway/routes.rs:29 |
| `/.well-known/oauth-protected-resource` | KEEP | OAuth discovery documents clients fetch | - | src/gateway/routes.rs:30 |
| `/accounts/v1` | KEEP | hosted consent journey users open in a browser; mounted only with `accounts.hosted` | - | src/gateway/routes.rs:64 |
| `/accounts/v1/assets/complete.js` | KEEP | hosted consent journey users open in a browser; mounted only with `accounts.hosted` | - | src/gateway/routes.rs:73 |
| `/accounts/v1/callback` | KEEP | hosted consent journey users open in a browser; mounted only with `accounts.hosted` | - | src/gateway/routes.rs:71 |
| `/accounts/v1/complete` | KEEP | hosted consent journey users open in a browser; mounted only with `accounts.hosted` | - | src/gateway/routes.rs:72 |
| `/accounts/v1/connections/{account_id}` | KEEP | hosted consent journey users open in a browser; mounted only with `accounts.hosted` | - | src/gateway/routes.rs:70 |
| `/accounts/v1/journeys` | KEEP | hosted consent journey users open in a browser; mounted only with `accounts.hosted` | - | src/gateway/routes.rs:67 |
| `/accounts/v1/journeys/{id}` | KEEP | hosted consent journey users open in a browser; mounted only with `accounts.hosted` | - | src/gateway/routes.rs:68 |
| `/accounts/v1/journeys/{id}/start` | KEEP | hosted consent journey users open in a browser; mounted only with `accounts.hosted` | - | src/gateway/routes.rs:69 |
| `/accounts/v1/{*rest}` | KEEP | hosted consent journey users open in a browser; mounted only with `accounts.hosted` | - | src/gateway/routes.rs:66 |
| `/api/costs` | KEEP | admin cost API for scripts (raw session ids) | - | src/gateway/routes.rs:25 |
| `/auth/token` | KEEP | key-server token issue and revoke (MULTI_USER.md); mounted only with `key_server.enabled` | - | src/gateway/routes.rs:31 |
| `/auth/token/{jti}` | KEEP | key-server token issue and revoke (MULTI_USER.md); mounted only with `key_server.enabled` | - | src/gateway/routes.rs:32 |
| `/auth/tokens` | KEEP | key-server token issue and revoke (MULTI_USER.md); mounted only with `key_server.enabled` | - | src/gateway/routes.rs:33 |
| `/dashboard` | KEEP | the web dashboard and its sign-in hand-off | - | src/gateway/routes.rs:35 |
| `/dashboard/handoff` | KEEP | the web dashboard and its sign-in hand-off | - | src/gateway/routes.rs:36 |
| `/dashboard/logout` | KEEP | the web dashboard and its sign-in hand-off | - | src/gateway/routes.rs:37 |
| `/health` | KEEP | liveness and readiness probes for supervisors and Kubernetes | - | src/gateway/routes.rs:21 |
| `/livez` | KEEP | liveness and readiness probes for supervisors and Kubernetes | - | src/gateway/routes.rs:22 |
| `/mcp` | KEEP | the MCP endpoint every client uses | - | src/gateway/routes.rs:26 |
| `/mcp/{name}` | KEEP | direct endpoint for one backend | - | src/gateway/routes.rs:27 |
| `/metrics` | KEEP | Prometheus scrape, behind `server.metrics_token` | - | src/gateway/routes.rs:24 |
| `/readyz` | KEEP | liveness and readiness probes for supervisors and Kubernetes | - | src/gateway/routes.rs:23 |
| `/sse` | INTERNAL | not a transport: answers a pointer to `/mcp` for clients configured for the removed SSE endpoint; SSE-transport clients use `/mcp` (Streamable HTTP; `GET /mcp` opens the stream) | unchanged; listed as a deprecation helper | src/gateway/routes.rs:28 |
| `/ui` | KEEP | the web dashboard and its sign-in hand-off | - | src/gateway/routes.rs:34 |
| `/ui/api/backends` | INTERNAL | private JSON API of the bundled web UI | stays mounted with today's admin/redacted split; documented as the bundled UI's private API, not an integration surface | src/gateway/routes.rs:51 |
| `/ui/api/backends/{name}` | INTERNAL | private JSON API of the bundled web UI | stays mounted with today's admin/redacted split; documented as the bundled UI's private API, not an integration surface | src/gateway/routes.rs:52 |
| `/ui/api/backends/{name}/revive` | INTERNAL | private JSON API of the bundled web UI | stays mounted with today's admin/redacted split; documented as the bundled UI's private API, not an integration surface | src/gateway/routes.rs:53 |
| `/ui/api/capabilities` | INTERNAL | private JSON API of the bundled web UI | stays mounted with today's admin/redacted split; documented as the bundled UI's private API, not an integration surface | src/gateway/routes.rs:44 |
| `/ui/api/capabilities/{name}` | INTERNAL | private JSON API of the bundled web UI | stays mounted with today's admin/redacted split; documented as the bundled UI's private API, not an integration surface | src/gateway/routes.rs:45 |
| `/ui/api/config` | INTERNAL | private JSON API of the bundled web UI | stays mounted with today's admin/redacted split; documented as the bundled UI's private API, not an integration surface | src/gateway/routes.rs:40 |
| `/ui/api/control-plane` | INTERNAL | private JSON API of the bundled web UI | stays mounted with today's admin/redacted split; documented as the bundled UI's private API, not an integration surface | src/gateway/routes.rs:46 |
| `/ui/api/control-plane/decisions` | INTERNAL | private JSON API of the bundled web UI | stays mounted with today's admin/redacted split; documented as the bundled UI's private API, not an integration surface | src/gateway/routes.rs:49 |
| `/ui/api/control-plane/export-status` | INTERNAL | private JSON API of the bundled web UI | stays mounted with today's admin/redacted split; documented as the bundled UI's private API, not an integration surface | src/gateway/routes.rs:50 |
| `/ui/api/control-plane/grants` | INTERNAL | private JSON API of the bundled web UI | stays mounted with today's admin/redacted split; documented as the bundled UI's private API, not an integration surface | src/gateway/routes.rs:47 |
| `/ui/api/control-plane/policies` | INTERNAL | private JSON API of the bundled web UI | stays mounted with today's admin/redacted split; documented as the bundled UI's private API, not an integration surface | src/gateway/routes.rs:48 |
| `/ui/api/costs` | INTERNAL | private JSON API of the bundled web UI | stays mounted with today's admin/redacted split; documented as the bundled UI's private API, not an integration surface | src/gateway/routes.rs:43 |
| `/ui/api/dashboard-link` | INTERNAL | private JSON API of the bundled web UI | stays mounted with today's admin/redacted split; documented as the bundled UI's private API, not an integration surface | src/gateway/routes.rs:42 |
| `/ui/api/events/dead-letters` | INTERNAL | private JSON API of the bundled web UI | stays mounted with today's admin/redacted split; documented as the bundled UI's private API, not an integration surface | src/gateway/routes.rs:56 |
| `/ui/api/events/dead-letters/replay` | INTERNAL | private JSON API of the bundled web UI | stays mounted with today's admin/redacted split; documented as the bundled UI's private API, not an integration surface | src/gateway/routes.rs:57 |
| `/ui/api/events/dead-letters/{id}/replay` | INTERNAL | private JSON API of the bundled web UI | stays mounted with today's admin/redacted split; documented as the bundled UI's private API, not an integration surface | src/gateway/routes.rs:58 |
| `/ui/api/events/held` | INTERNAL | private JSON API of the bundled web UI | admin only, like the dead-letter listing; held webhook subscriptions per type (MIK-8057) | src/gateway/routes.rs:59 |
| `/ui/api/import/openapi` | INTERNAL | private JSON API of the bundled web UI | stays mounted with today's admin/redacted split; documented as the bundled UI's private API, not an integration surface | src/gateway/routes.rs:61 |
| `/ui/api/import/openapi/preview` | INTERNAL | private JSON API of the bundled web UI | stays mounted with today's admin/redacted split; documented as the bundled UI's private API, not an integration surface | src/gateway/routes.rs:60 |
| `/ui/api/registry` | INTERNAL | private JSON API of the bundled web UI | stays mounted with today's admin/redacted split; documented as the bundled UI's private API, not an integration surface | src/gateway/routes.rs:54 |
| `/ui/api/registry/search` | INTERNAL | private JSON API of the bundled web UI | stays mounted with today's admin/redacted split; documented as the bundled UI's private API, not an integration surface | src/gateway/routes.rs:55 |
| `/ui/api/reload` | INTERNAL | private JSON API of the bundled web UI | stays mounted with today's admin/redacted split; documented as the bundled UI's private API, not an integration surface | src/gateway/routes.rs:41 |
| `/ui/api/status` | INTERNAL | private JSON API of the bundled web UI | stays mounted with today's admin/redacted split; documented as the bundled UI's private API, not an integration surface | src/gateway/routes.rs:38 |
| `/ui/api/tools` | INTERNAL | private JSON API of the bundled web UI | stays mounted with today's admin/redacted split; documented as the bundled UI's private API, not an integration surface | src/gateway/routes.rs:39 |
| `dynamic &route (src/gateway/webhooks/mod.rs)` | KEEP | inbound webhooks under `webhooks.base_path` | - | src/gateway/webhooks/mod.rs:323 |
| `dynamic callback_path (src/oauth/callback.rs)` | KEEP | backend OAuth redirect on its own short-lived loopback listener | - | src/oauth/callback.rs:309 |
| `dynamic path (src/gateway/webhooks/mod.rs)` | KEEP | inbound webhooks under `webhooks.base_path` | - | src/gateway/webhooks/mod.rs:300 |

## Surface: lib

| Item | Class | Used by (files) | Reason | Migration | Defined at |
|---|---|---|---|---|---|
| `mcp_gateway::Error` | INTERNAL | bin 3, tests 3, benches/examples 0 | the crate ships a binary; README documents no library use (re-export from error) | `#[doc(hidden)] pub` re-export for the binary; off docs.rs | src/lib.rs:104 |
| `mcp_gateway::InitializedStore` | INTERNAL | bin 1, tests 0, benches/examples 0 | the crate ships a binary; README documents no library use (re-export from personal_accounts) | `#[doc(hidden)] pub` re-export for the binary; off docs.rs | src/lib.rs:110 |
| `mcp_gateway::MCP_PROTOCOL_VERSION` | INTERNAL | bin 2, tests 0, benches/examples 0 | the crate ships a binary; README documents no library use (const) | `#[doc(hidden)] pub` re-export for the binary; off docs.rs | src/lib.rs:118 |
| `mcp_gateway::MigratedCredential` | INTERNAL | bin 1, tests 0, benches/examples 0 | the crate ships a binary; README documents no library use (re-export from personal_accounts) | `#[doc(hidden)] pub` re-export for the binary; off docs.rs | src/lib.rs:110 |
| `mcp_gateway::OfflineInitError` | INTERNAL | bin 1, tests 0, benches/examples 0 | the crate ships a binary; README documents no library use (re-export from personal_accounts) | `#[doc(hidden)] pub` re-export for the binary; off docs.rs | src/lib.rs:110 |
| `mcp_gateway::OfflineMigrationError` | INTERNAL | bin 1, tests 0, benches/examples 0 | the crate ships a binary; README documents no library use (re-export from personal_accounts) | `#[doc(hidden)] pub` re-export for the binary; off docs.rs | src/lib.rs:110 |
| `mcp_gateway::Result` | INTERNAL | bin 1, tests 8, benches/examples 0 | the crate ships a binary; README documents no library use (re-export from error) | `#[doc(hidden)] pub` re-export for the binary; off docs.rs | src/lib.rs:104 |
| `mcp_gateway::attestation` | INTERNAL | bin 1, tests 3, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | `#[doc(hidden)] pub` re-export for the binary; off docs.rs | src/lib.rs:32 |
| `mcp_gateway::autotag` | INTERNAL | bin 0, tests 0, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | `pub(crate)`; no caller outside the crate | src/lib.rs:33 |
| `mcp_gateway::backend` | INTERNAL | bin 0, tests 52, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | reached by integration tests through `#[doc(hidden)] pub mod test_support` | src/lib.rs:34 |
| `mcp_gateway::cache` | INTERNAL | bin 0, tests 5, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | reached by integration tests through `#[doc(hidden)] pub mod test_support` | src/lib.rs:35 |
| `mcp_gateway::capability` | INTERNAL | bin 5, tests 13, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | `#[doc(hidden)] pub` re-export for the binary; off docs.rs | src/lib.rs:36 |
| `mcp_gateway::chains` | INTERNAL | bin 0, tests 0, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | `pub(crate)`; no caller outside the crate | src/lib.rs:37 |
| `mcp_gateway::cli` | INTERNAL | bin 22, tests 6, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | `#[doc(hidden)] pub` re-export for the binary; off docs.rs | src/lib.rs:38 |
| `mcp_gateway::config` | INTERNAL | bin 20, tests 90, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | `#[doc(hidden)] pub` re-export for the binary; off docs.rs | src/lib.rs:39 |
| `mcp_gateway::config_persistence` | INTERNAL | bin 6, tests 3, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | `#[doc(hidden)] pub` re-export for the binary; off docs.rs | src/lib.rs:40 |
| `mcp_gateway::config_reload` | INTERNAL | bin 0, tests 33, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | reached by integration tests through `#[doc(hidden)] pub mod test_support` | src/lib.rs:41 |
| `mcp_gateway::context_compression` | INTERNAL | bin 0, tests 0, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | `pub(crate)`; no caller outside the crate | src/lib.rs:42 |
| `mcp_gateway::context_integrity` | INTERNAL | bin 0, tests 0, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | `pub(crate)`; no caller outside the crate | src/lib.rs:43 |
| `mcp_gateway::control_plane` | INTERNAL | bin 0, tests 3, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | reached by integration tests through `#[doc(hidden)] pub mod test_support` | src/lib.rs:44 |
| `mcp_gateway::cost_accounting` | INTERNAL | bin 0, tests 4, benches/examples 1 | the crate ships a binary; README documents no library use (mod) | reached by integration tests through `#[doc(hidden)] pub mod test_support` | src/lib.rs:45 |
| `mcp_gateway::discovery` | INTERNAL | bin 4, tests 3, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | `#[doc(hidden)] pub` re-export for the binary; off docs.rs | src/lib.rs:46 |
| `mcp_gateway::error` | INTERNAL | bin 0, tests 0, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | `pub(crate)`; no caller outside the crate | src/lib.rs:47 |
| `mcp_gateway::failsafe` | INTERNAL | bin 0, tests 4, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | reached by integration tests through `#[doc(hidden)] pub mod test_support` | src/lib.rs:49 |
| `mcp_gateway::gateway` | INTERNAL | bin 5, tests 105, benches/examples 1 | the crate ships a binary; README documents no library use (mod) | `#[doc(hidden)] pub` re-export for the binary; off docs.rs | src/lib.rs:51 |
| `mcp_gateway::honest_task_tokens` | INTERNAL | bin 0, tests 2, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | reached by integration tests through `#[doc(hidden)] pub mod test_support` | src/lib.rs:54 |
| `mcp_gateway::idempotency` | INTERNAL | bin 0, tests 8, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | reached by integration tests through `#[doc(hidden)] pub mod test_support` | src/lib.rs:55 |
| `mcp_gateway::identity_grants` | INTERNAL | bin 1, tests 0, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | `#[doc(hidden)] pub` re-export for the binary; off docs.rs | src/lib.rs:56 |
| `mcp_gateway::identity_propagation` | INTERNAL | bin 0, tests 1, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | reached by integration tests through `#[doc(hidden)] pub mod test_support` | src/lib.rs:57 |
| `mcp_gateway::initialize_store_offline` | INTERNAL | bin 1, tests 0, benches/examples 0 | the crate ships a binary; README documents no library use (re-export from personal_accounts) | `#[doc(hidden)] pub` re-export for the binary; off docs.rs | src/lib.rs:110 |
| `mcp_gateway::key_server` | INTERNAL | bin 0, tests 3, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | reached by integration tests through `#[doc(hidden)] pub mod test_support` | src/lib.rs:58 |
| `mcp_gateway::kill_switch` | INTERNAL | bin 0, tests 0, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | `pub(crate)`; no caller outside the crate | src/lib.rs:59 |
| `mcp_gateway::kubernetes` | INTERNAL | bin 1, tests 1, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | `#[doc(hidden)] pub` re-export for the binary; off docs.rs | src/lib.rs:60 |
| `mcp_gateway::metrics` | INTERNAL | bin 0, tests 4, benches/examples 0 | the crate ships a binary; README documents no library use (mod feature metrics) | reached by integration tests through `#[doc(hidden)] pub mod test_support` | src/lib.rs:62 |
| `mcp_gateway::migrate_legacy_credential_offline` | INTERNAL | bin 1, tests 0, benches/examples 0 | the crate ships a binary; README documents no library use (re-export from personal_accounts) | `#[doc(hidden)] pub` re-export for the binary; off docs.rs | src/lib.rs:110 |
| `mcp_gateway::mtls` | INTERNAL | bin 2, tests 28, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | `#[doc(hidden)] pub` re-export for the binary; off docs.rs | src/lib.rs:63 |
| `mcp_gateway::oauth` | INTERNAL | bin 0, tests 1, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | reached by integration tests through `#[doc(hidden)] pub mod test_support` | src/lib.rs:64 |
| `mcp_gateway::playbook` | INTERNAL | bin 0, tests 2, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | reached by integration tests through `#[doc(hidden)] pub mod test_support` | src/lib.rs:67 |
| `mcp_gateway::projection` | INTERNAL | bin 0, tests 0, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | `pub(crate)`; no caller outside the crate | src/lib.rs:68 |
| `mcp_gateway::protocol` | INTERNAL | bin 0, tests 74, benches/examples 2 | the crate ships a binary; README documents no library use (mod) | reached by integration tests through `#[doc(hidden)] pub mod test_support` | src/lib.rs:69 |
| `mcp_gateway::protocol_imports` | INTERNAL | bin 2, tests 0, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | `#[doc(hidden)] pub` re-export for the binary; off docs.rs | src/lib.rs:70 |
| `mcp_gateway::protocol_revision_telemetry` | INTERNAL | bin 0, tests 2, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | reached by integration tests through `#[doc(hidden)] pub mod test_support` | src/lib.rs:71 |
| `mcp_gateway::provider` | INTERNAL | bin 0, tests 0, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | `pub(crate)`; no caller outside the crate | src/lib.rs:72 |
| `mcp_gateway::ranking` | INTERNAL | bin 1, tests 1, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | `#[doc(hidden)] pub` re-export for the binary; off docs.rs | src/lib.rs:73 |
| `mcp_gateway::registry` | INTERNAL | bin 4, tests 1, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | `#[doc(hidden)] pub` re-export for the binary; off docs.rs | src/lib.rs:74 |
| `mcp_gateway::routing_profile` | INTERNAL | bin 0, tests 3, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | reached by integration tests through `#[doc(hidden)] pub mod test_support` | src/lib.rs:75 |
| `mcp_gateway::runtime` | INTERNAL | bin 3, tests 1, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | `#[doc(hidden)] pub` re-export for the binary; off docs.rs | src/lib.rs:76 |
| `mcp_gateway::scheduler` | INTERNAL | bin 0, tests 0, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | `pub(crate)`; no caller outside the crate | src/lib.rs:77 |
| `mcp_gateway::secret_injection` | INTERNAL | bin 0, tests 1, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | reached by integration tests through `#[doc(hidden)] pub mod test_support` | src/lib.rs:78 |
| `mcp_gateway::secrets` | INTERNAL | bin 0, tests 0, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | `pub(crate)`; no caller outside the crate | src/lib.rs:79 |
| `mcp_gateway::security` | INTERNAL | bin 8, tests 39, benches/examples 1 | the crate ships a binary; README documents no library use (mod) | `#[doc(hidden)] pub` re-export for the binary; off docs.rs | src/lib.rs:80 |
| `mcp_gateway::semantic_search` | INTERNAL | bin 0, tests 1, benches/examples 1 | the crate ships a binary; README documents no library use (mod feature semantic-search) | reached by integration tests through `#[doc(hidden)] pub mod test_support` | src/lib.rs:82 |
| `mcp_gateway::setup_tracing` | INTERNAL | bin 1, tests 0, benches/examples 0 | the crate ships a binary; README documents no library use (fn) | `#[doc(hidden)] pub` re-export for the binary; off docs.rs | src/lib.rs:149 |
| `mcp_gateway::simhash` | INTERNAL | bin 0, tests 0, benches/examples 1 | the crate ships a binary; README documents no library use (mod) | reached by integration tests through `#[doc(hidden)] pub mod test_support` | src/lib.rs:83 |
| `mcp_gateway::skills` | INTERNAL | bin 1, tests 1, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | `#[doc(hidden)] pub` re-export for the binary; off docs.rs | src/lib.rs:84 |
| `mcp_gateway::stats` | INTERNAL | bin 0, tests 3, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | reached by integration tests through `#[doc(hidden)] pub mod test_support` | src/lib.rs:85 |
| `mcp_gateway::tool_profiles` | INTERNAL | bin 0, tests 1, benches/examples 0 | the crate ships a binary; README documents no library use (mod feature tool-profiles) | reached by integration tests through `#[doc(hidden)] pub mod test_support` | src/lib.rs:89 |
| `mcp_gateway::tool_registry` | INTERNAL | bin 0, tests 0, benches/examples 1 | the crate ships a binary; README documents no library use (mod) | reached by integration tests through `#[doc(hidden)] pub mod test_support` | src/lib.rs:90 |
| `mcp_gateway::tracing_context` | INTERNAL | bin 0, tests 0, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | `pub(crate)`; no caller outside the crate | src/lib.rs:91 |
| `mcp_gateway::transform` | INTERNAL | bin 0, tests 1, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | reached by integration tests through `#[doc(hidden)] pub mod test_support` | src/lib.rs:92 |
| `mcp_gateway::transition` | INTERNAL | bin 0, tests 2, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | reached by integration tests through `#[doc(hidden)] pub mod test_support` | src/lib.rs:93 |
| `mcp_gateway::transport` | INTERNAL | bin 2, tests 3, benches/examples 1 | the crate ships a binary; README documents no library use (mod) | `#[doc(hidden)] pub` re-export for the binary; off docs.rs | src/lib.rs:94 |
| `mcp_gateway::trust` | INTERNAL | bin 7, tests 4, benches/examples 0 | the crate ships a binary; README documents no library use (mod) | `#[doc(hidden)] pub` re-export for the binary; off docs.rs | src/lib.rs:95 |
| `mcp_gateway::validator` | INTERNAL | bin 1, tests 0, benches/examples 1 | the crate ships a binary; README documents no library use (mod) | `#[doc(hidden)] pub` re-export for the binary; off docs.rs | src/lib.rs:96 |
