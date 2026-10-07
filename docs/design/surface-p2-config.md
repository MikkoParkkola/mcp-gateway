# 4.0 config tightening (P2): tiers, derived values and the default auth posture

Ticket: MIK-8044, piece P2 (SURF.2). Builds on the inventory in `docs/design/surface-4.0.md` (P1, merged as d829176dc).
Design only; nothing here changes code.

## Problem

The operator asked for a surface where "the simpler it is to set up and configure the better". After P1 the
config still has 412 KEEP keys and the CLI 233 KEEP items. Every one is supported, but a new user reading
the reference meets all of them at once. SURF.2 asks that the config reference and schema list only KEEP
keys and that each non-KEEP key gets a red-then-green test for its new behaviour.

Target: the documented minimal setup fits on one screen, and the reference leads with what a typical
setup needs (a handful of backends, auth, the listen address).
## Tiers: ESSENTIAL and ADVANCED

KEEP splits in two. Both stay supported and validated; the split decides where a user meets an item.

| Tier | Where it appears |
|---|---|
| ESSENTIAL | The quick start, `init` output, the top of the reference, `--help` summaries. |
| ADVANCED | A later reference section per area; `init` and the quick start leave it out. |

ESSENTIAL (27 of 693 KEEP):

| Surface | Items |
|---|---|
| config (9) | `server.host`, `server.port`, `auth.enabled`, `auth.bearer_token`, `backends.<name>.command`, `backends.<name>.http_url`, `backends.<name>.env`, `backends.<name>.headers`, `backends.<name>.enabled` |
| cli (14) | the bare binary; `--config`, `--port`, `--host`; `init`; `add` with `--command`, `--url`, `--env`; `list`; `remove`; `doctor`; `validate`; `upgrade` |
| env (1) | `MCP_GATEWAY_CONFIG` |
| routes (3) | `/mcp`, `/health`, `/ui` |

Every other KEEP item is ADVANCED. Opt-in subsystems (`security`, `accounts`, `runtime`, `mtls`,
`key_server`, `agent_auth`, `control_plane`, `cost_governance`, `events`, `webhooks`) are ADVANCED as a
whole: a user who turns one on reads its own section. The inventory gains a `Tier` column for KEEP rows,
and the check rejects a KEEP row without one.
## Values the gateway sets itself (deterministic AUTO)

Each one is a pure function of the loaded config or the request, with no stored state. Where the default
already produces the derived value, the change is visibility only: the key becomes a hidden key (still
read and validated, out of the reference, listed by `doctor` when set).

| Key | Today | 4.0 | Code change |
|---|---|---|---|
| `backends.<name>.ws_url` and `http_url` | the transport is picked by which key is present (src/config/backend_config.rs:220-280) | one `url` key: `http://`/`https://` picks HTTP (with the existing SSE and Streamable HTTP detection), `ws://`/`wss://` picks WebSocket. `http_url` and `ws_url` stay as hidden aliases, still honoured | new `url` field, a scheme match, and a load error when `url` and an alias are both set. Matches the existing `add --url` flag |

With `url`, the ESSENTIAL backend keys become `command`, `url`, `env`, `headers` and `enabled`.

The 13 AUTO rows from the P1 inventory are implemented in the same increment (P2c). Each keeps an
explicit value honoured as a hidden key, and each gets a red-first test of the derived value:

| P1 AUTO row | Derivation |
|---|---|
| `accounts.schema_version` | `accounts.v1`, the only accepted value, is the default |
| `backends.<name>.oauth.token_refresh_buffer_secs` | unset: refresh at max(300 s, 10 % of the token lifetime) before expiry |
| `backends.<name>.protocol_version` | negotiated in `initialize` (already) |
| `backends.<name>.streamable_http` | detected at connect (already) |
| `key_server.oidc[].auto_discover` | OIDC discovery first, then `{issuer}/.well-known/jwks.json`; `jwks_uri` still overrides |
| `meta_mcp.prompts_resources_fetch_timeout` | unset: min(the backend's `timeout`, 10 s) |
| `--capabilities` on `skills generate` and `tool completions/inspect/invoke/list` (5 rows), `MCP_GATEWAY_CAPABILITIES` | derived from the loaded config's `capabilities.directories`; flag and variable stay as hidden overrides |
| `validate --no-color` | colour follows the terminal and `NO_COLOR`; hidden flag |
## Kept as operator decisions (challenged and rejected as AUTO)

| Key | Proposed derivation | Why it stays an operator decision |
|---|---|---|
| `server.modern_protocol` | hidden key, since the version is negotiated per client | P1 kept it KEEP: multi-replica deployments turn it off (DEPLOYMENT.md:181) and it is the protocol rollback switch. Stays KEEP, ADVANCED. |
| `failsafe.{retry,circuit_breaker,health_check,rate_limit}.enabled` | always on, hidden key turns one off | P1 kept them KEEP: a non-idempotent backend turns retries off, which is an operator decision. Each already defaults on. Stays KEEP, ADVANCED. |
| `auth.single_user` | true when there are no API keys and no key server | ADR-008 INV-2 (MIK-6752) makes it fail-closed on purpose (src/config/features/auth.rs:33-45). One bearer token can be handed to a whole team, and the gateway cannot tell from the credential count. Deriving it would switch off the per-user OAuth isolation guard without the operator saying so, which the inventory's rule 1 forbids. Stays KEEP, ADVANCED; `init` keeps writing it for the solo setup. |
| `auth.public_paths` | fixed default | Already defaults to `["/health"]` (src/config/features/auth.rs:126). Under posture A (below) `init` keeps writing `/health` and `/mcp`, so existing tokenless clients keep working. Stays KEEP, ADVANCED. |
| `security.transparency_log.enabled` | on whenever auth is on | Round 1 of the P1 review rejected full AUTO: an auth-off gateway may still want an audit log. Today an authenticated gateway fails to load without it (src/config/features/security.rs:117), so every authenticated config carries the line. 4.0 defaults it on when auth is on; an explicit `enabled: false` with auth on still fails to load, so enforcement does not change. The key stays KEEP (ADVANCED) for turning it on without auth. |
## Default auth posture

Today (`mcp-gateway init`, src/commands/mod.rs:176-202) the starter config binds `127.0.0.1`, enables auth
with a generated bearer token, sets `single_user: true`, writes the file readable only by its owner, and
lists `/health` and `/mcp` under `public_paths`. Tools stay open on loopback so an MCP client that was
already configured keeps working; the admin API and dashboard need the token. `network_bind_refusal`
(src/gateway/server/support.rs:414) already refuses to serve when the tool surface is open and the gateway
is reachable from elsewhere, through a wide bind or a declared non-loopback `public_url`, unless
`server.allow_unauthenticated_network_bind` is set.

| | A: keep today's posture | B: secure by default |
|---|---|---|
| `auth.enabled` default | `false` (`init` writes `true`) | `true` unless `auth.enabled: false` is written |
| token | `init` writes it into the config | `init` writes it into the config, or a sibling secrets file at mode 0600 that the config names |
| `/mcp` without a token | open on loopback | refused; clients send the token |
| minimal `init` config | about 12 lines: `server.port`; `auth.enabled`, `bearer_token`, `single_user`, `public_paths` (`/health`, `/mcp`); one backend | one backend plus the bearer token (or a reference to the secrets file), about 5 lines |
| who can call tools | any local process on the machine | only a caller holding the token |
| client setup | none | every MCP client config gains an `Authorization` header (or `--token`) |
| 3.x upgrade | no change | a config with no `auth` section changes behaviour: `upgrade` must write `auth.enabled: false` to keep it, or the operator adds the token to clients |

Neither option relaxes `network_bind_refusal`. B also closes the "any local process" gap for callers that cannot read the
token: other users on a shared machine and sandboxed processes. It does not stop malware running as the
config's owner, which can read a 0600 file. Its cost is one header in each MCP client
config. `setup wizard --configure-client` writes the gateway entry into each detected client
(src/commands/setup.rs:111) but no auth header today, so B also needs that writer to add the token.

**Decision for 4.0: A** (lead, 2026-10-08). B would break every existing MCP client on upgrade, since each
needs the token, and needs new client-setup work; both are wrong to land at release freeze. Today's
loopback-open posture is deliberate and documented, and `network_bind_refusal` already refuses
tools-open with remote reach. A is strengthened cheaply: `init` prints one line saying `/mcp` is open to
local processes and naming how to require the token. **B is the 4.1 direction**, together with the
client-setup writer that adds the token.

## Adaptive values (later, separate item)

`meta_mcp.warm_start` (start the backends recent sessions used) and `backends.<name>.stop_when_idle_for`
(derived from observed gaps between calls) learn from usage, so they add stored state and test surface.
They are not in P2. When proposed, each comes with a hard bound (for example at most N warm backends,
idle time clamped to a range) and a switch that turns the learning off and falls back to today's value.
## Increments

One open PR at a time, each merged and closed before the next.

| # | Increment | Product code |
|---|---|---|
| P2a | This design, reviewed | none |
| P2b | Hidden keys: one table in code of every INTERNAL and AUTO config key and variable (generated from the inventory and checked against it), `doctor` lists the ones a config sets, and the validators stay as they are | yes |
| P2c | Deterministic AUTO: backend `url` with `http_url`/`ws_url` as hidden aliases; `transparency_log.enabled` defaults on with auth; the 13 P1 AUTO rows | yes |
| P2d | REMOVE keys refused at load naming the replacement. `upgrade` deletes the dead ones; `auth.api_keys[].key` is migrated, not deleted: `upgrade` writes `key_sha256` from the plaintext (the `hash-key` path) and leaves the entry unchanged if the key cannot be resolved | yes |
| P2e | Posture A kept: `init` prints one line saying `/mcp` is open to local processes and how to require the token | yes, `init` output only |
| P2f | Docs: tier column in the inventory; the reference, `gateway.example.yaml` and QUICKSTART lead with ESSENTIAL and list no non-KEEP key; `init` writes ESSENTIAL keys plus the posture-A declarations (`single_user`, `public_paths`), which stay although ADVANCED; the minimal setup fits one screen | docs and `init` |

SURF.2 is met when P2b to P2f have merged.
## Test plan

Each test is written first and seen failing on CI at its own assertion before the change lands.

| Increment | Test | Red before |
|---|---|---|
| P2b | every INTERNAL/AUTO row in the inventory is in the code's hidden-key table and nothing else is | the table does not exist |
| P2b | a config setting a hidden key loads with the value applied, and `doctor` names the key | `doctor` does not list it |
| P2c | through the real config loader: `url` with `http://`, `https://`, `ws://` and `wss://` builds the same backend as the matching 3.x key; `url` plus `http_url` and `url` plus `ws_url` are each a load error naming both; the cleartext-credential refusal fires on `url` exactly as on the alias | `url` is an unknown key |
| P2c | each P1 AUTO row: unset gives the derived value; an explicit value is still applied | the derivations do not exist |
| P2c | a 3.x config with `http_url` or `ws_url` loads unchanged | (guard: passes before and after) |
| P2c | auth on with no `transparency_log` section loads with the log on; auth on with `enabled: false` still fails to load | the first fails to load today |
| P2d | each REMOVE key fails the load with a message naming its replacement; `upgrade` output has no dead REMOVE key | most warn once or have no effect today (inventory rows say which) |
| P2d | a config with a plaintext `auth.api_keys[].key`: after `upgrade` the entry carries `key_sha256` and the original key still authenticates; an unresolvable key leaves the entry unchanged and `upgrade` says so | `upgrade` does not migrate it |
| P2e | `init` output contains the local-exposure line naming `/mcp` and the setting that requires the token; the generated config is unchanged | the line is absent |
| P2f | the minimal config in QUICKSTART loads and serves a tool call (this also feeds SURF.7) | QUICKSTART still shows the longer config |
| P2f | `init` output: `/mcp` answers without a token on loopback, the dashboard needs it, and `single_user` grants the solo OAuth principal, as before | (guard: passes before and after) |
| P2f | the inventory check reads the reference, `gateway.example.yaml` and QUICKSTART and fails on any non-KEEP config key or variable they mention; the loader still accepts hidden keys | the check does not read the docs |
## UPGRADING impact

Each user-visible change gets one entry in `docs/UPGRADING-4.0.md`, numbered at packet time (base max + 1),
saying what the user loses, gains and does:

- Hidden keys: nothing an operator set stops applying; the keys leave the reference; `doctor` lists any set.
- `url`: new spelling; `http_url` and `ws_url` keep working. No action.
- Transparency log: an authenticated config no longer needs the line. No action.
- REMOVE keys: the load fails naming the replacement; `mcp-gateway upgrade` deletes the dead ones and
  rewrites a plaintext `auth.api_keys[].key` as `key_sha256`.
- Auth posture: unchanged in 4.0 (decision A). `init` now says that `/mcp` is open to local processes.

## Falsifiers

| Claim | Check | Fails if |
|---|---|---|
| The minimal config fits one screen | count the lines of the QUICKSTART config after P2f | more than 15 lines |
| Hidden keys change no behaviour | the P2b load test with every hidden key set to a non-default value | any value is not applied |
| `url` is a pure rename | the 3.x alias test plus the scheme tests | a 3.x backend config changes transport |
| No security control changes | `network_bind_refusal` tests and the ADR-008 single-user tests run unchanged | any of them needs editing |