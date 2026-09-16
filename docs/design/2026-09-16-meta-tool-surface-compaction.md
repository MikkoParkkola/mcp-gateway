<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# Compacting the Meta-MCP client tool surface to eleven before v4.0.0

The release owner has ruled that the Meta-MCP surface is compacted to
approximately eleven tools before v4.0.0 is tagged. Shipping seventeen and
deferring the cut to 4.1.0 was offered and declined. This document names the
cuts and the single change that lands them. It does not re-open the ruling.

Claims below are marked **verified** (read at the cited `file:line`),
**inferred** (one source, no cross-check) or **assumption** (neither).

## 1. The current surface

### The four axes

`meta_tools_for` (`src/gateway/meta_mcp/mod.rs:1596`) is the single authority
for what a caller is shown. Four filters compose there, in this order:

1. **Code Mode.** `self.code_mode_enabled` replaces the whole list with
   `build_code_mode_tools()` — `gateway_search`, `gateway_execute`
   (`src/gateway/meta_mcp_tool_defs.rs:781-786`). Verified.
2. **`MetaToolGates`.** Four booleans — `stats`, `reload`, `cost_report`,
   `webhook_status` (`src/gateway/meta_mcp_tool_defs.rs:575-583`) — each
   guarding one `tools.push(...)` inside `build_meta_tools`
   (`src/gateway/meta_mcp_tool_defs.rs:604-636`). Verified.
3. **`MetaToolExposure`.** The operator allow-list from
   `meta_mcp.exposed_meta_tools`, applied by `filter`
   (`src/gateway/meta_mcp_tool_defs.rs:913-920`). Verified.
4. **`CallerStanding`.** `tools.retain(|tool| standing.permits(&tool.name))`
   (`src/gateway/meta_mcp/mod.rs:1624`), using `permits`
   (`src/gateway/router/authorization.rs:126-129`) against `ADMIN_META_TOOLS`
   (`src/gateway/router/authorization.rs:73-78`). Verified.

### The roster

Order is the build order in `build_meta_tools`. "Axis" names what controls
the tool today; "base" means nothing does.

| # | Tool | For | Axis |
|---|---|---|---|
| 1 | `gateway_list_servers` | List connected backends and status | base (`:201`) |
| 2 | `gateway_list_tools` | List tools, optionally per backend | base (`:202`) |
| 3 | `gateway_search_tools` | Ranked keyword search over the catalog | base (`:203`) |
| 4 | `gateway_invoke` | Call any backend tool through the gateway | base (`:204`) |
| 5 | `gateway_get_stats` | Invocations, cache hits, top tools | gate `stats` (`:609`) |
| 6 | `gateway_cost_report` | Session and API-key spend | gate `cost_report` (`:612`) |
| 7 | `gateway_run_playbook` | Collapse a multi-step playbook into one call | base (`:616`) |
| 8 | `gateway_kill_server` | Operator kill switch for a backend | admin (`authorization.rs:74`) |
| 9 | `gateway_revive_server` | Re-enable a killed backend | admin (`authorization.rs:75`) |
| 10 | `gateway_set_profile` | Switch this session's routing profile | base (`:619`) |
| 11 | `gateway_get_profile` | Show the active routing profile | base (`:620`) |
| 12 | `gateway_list_disabled_capabilities` | Capabilities auto-disabled on error rate | base (`:621`) |
| 13 | `gateway_list_profiles` | Enumerate configured routing profiles | base (`:622`) |
| 14 | `gateway_set_state` | Transition the session's workflow state | base (`:623`) |
| 15 | `gateway_reload_config` | Re-read `config.yaml` without restart | gate `reload` (`:625`) + admin (`authorization.rs:76`) |
| 16 | `gateway_reload_capabilities` | Re-read capability YAML without restart | admin (`authorization.rs:77`) |
| 17 | `gateway_webhook_status` | Whether webhook events still arrive | gate `webhook_status` (`:634`) |

Line numbers in the Axis column are `src/gateway/meta_mcp_tool_defs.rs` unless
stated. All verified.

### What a default deployment actually sees

Gate values on the served path, all verified:

- `stats` — `self.stats.is_some()` (`mod.rs:1603`). `serve` always passes
  `Some(Arc::new(UsageStats::new()))` (`src/gateway/server/mod.rs:948`, used at
  `:1007`), so this gate is **always on**.
- `cost_report` — hardcoded `true` (`mod.rs:1606`). Always on.
- `reload` — `self.get_reload_context().is_some()` (`mod.rs:1604`), set only
  when a config path exists (`server/mod.rs:1584-1596` for HTTP,
  `:2305-2317` for stdio). On for any `serve -c config.yaml`.
- `webhook_status` — `self.get_webhook_registry().is_some()` (`mod.rs:1610`),
  wired only on the HTTP path and only when `config.webhooks.enabled`
  (`server/mod.rs:1559-1561`), which defaults to `true`
  (`src/config/features/webhooks.rs:28-36`).

Exposure is a no-op by default: `exposed_meta_tools` defaults to an empty
`Vec` (`src/config/mod.rs:1497`) and `from_names` returns `expose_all()` for an
empty slice (`meta_mcp_tool_defs.rs:865-868`). Verified.

Standing is the axis that moves the number, and it is not what the published
figure assumes. `AuthConfig::default().enabled` is `false`
(`src/config/features/auth.rs:72`); with auth off the middleware inserts
`anonymous_client()`, whose `admin` field is `false`
(`src/gateway/auth.rs:908-912`, `:867-879`), so `CallerStanding::of_client`
(`handlers.rs:1245`, `:1780`) yields `Standard` and the four admin names are
retained out. Stdio is the opposite: `const STDIO: CallerStanding =
CallerStanding::Admin` (`src/gateway/server/mod.rs:149`). Verified.

So the number depends on who asks:

| Deployment | Built | Listed |
|---|---|---|
| HTTP, auth off (the shipped default), config file | 17 | **13** |
| HTTP, admin API key, config file | 17 | **17** |
| stdio, config file (always admin, never a webhook registry) | 16 | **16** |
| Minimum stripped surface (all gates off) | 13 | 13 admin / 9 standard |

**A default HTTP deployment lists 13, not 17.** The 17 in
`benchmarks/public_claims.json:5` and README:267 counts the built ceiling for
an admin-authenticated HTTP caller with a config file and webhooks enabled —
the only configuration that reaches it. Established by reading the four gate
sources and the standing derivation above, not by running the gateway; no
build or test was run for this document.

The "14 minimum" is `build_meta_tools` with every gate off, which is 13
(`src/gateway/meta_mcp_tool_defs_tests.rs:26`, `:601`), plus `cost_report`,
which the served path hardcodes on. Verified.

## 2. The cut

Six tools leave the default listing. None is removed. All six move to a gate,
because a gate is the axis the requirement already blesses: `NFR.PERF.4` states
that "the cap governs what `tools/list` advertises, not what is dispatchable: a
name absent from the listing is not thereby uncallable"
(`docs/requirements/RELEASE-4.0.0-requirements.md:295`). Verified.

That is not aspirational. Dispatch is a flat name match
(`src/gateway/meta_mcp/mod.rs:2094-2106`) that consults `MetaToolExposure`
(`mod.rs:1894`) and `CallerStanding` (`mod.rs:1909` onward) and never consults
`MetaToolGates`. `gateway_webhook_status` is already the shipped precedent: it
is dispatchable by name over stdio on a surface that does not enumerate it —
stated at `meta_mcp_tool_defs.rs:810-816` and confirmed by the dispatch arm at
`mod.rs:2096`. Verified.

| Tool | Mechanism | Why not removal |
|---|---|---|
| `gateway_get_stats` | Gate `stats` re-sourced from "a collector is attached" (always true) to an explicit `meta_mcp.expose_stats_tool` opt-in, default `false` | The handler is the only stats view a stdio client has; `/metrics` covers HTTP operators |
| `gateway_cost_report` | Gate `cost_report` re-sourced from the hardcoded `true` at `mod.rs:1606` to "a cost registry is attached", which already follows `cost_governance.enabled` (`server/mod.rs:985`) | Cost accounting is a shipped feature; hiding it where it cannot answer is the same rule webhook status already follows |
| `gateway_set_profile` | New gate `profiles` — at least one configured routing profile | Routing profiles are a shipped feature, off by default |
| `gateway_get_profile` | Same gate | Same |
| `gateway_list_profiles` | Same gate | Same |
| `gateway_run_playbook` | New gate `playbooks` — `PlaybookEngine` is non-empty | Playbooks are a shipped feature, loaded only from configured directories |

Gate sources for the two new gates, both reading state the process already
holds:

- `profiles` — `routing_profiles` defaults to an empty `HashMap`
  (`src/config/mod.rs:89`) and `ProfileRegistry::from_config` maps it one to one
  (`src/routing_profile/mod.rs:343-356`), so an unconfigured gateway has no
  profiles. With none configured, `get` returns an allow-all fallback for every
  name (`src/routing_profile/mod.rs:367-374`) — the three tools describe and
  switch between profiles that do not exist. Verified. The registry's `profiles`
  field is private, so this needs one accessor (`has_configured_profiles`).
- `playbooks` — `PlaybookEngine::new()` starts empty (`mod.rs:558`,
  `src/playbook/engine/mod.rs:25-30`) and `set_playbook_engine` is called only
  after loading from configured directories (`server/mod.rs:1520-1542`).
  `PlaybookEngine::is_empty()` already exists
  (`src/playbook/engine/mod.rs:99`). Verified.

### Resulting counts

| Deployment | Listed after the cut |
|---|---|
| HTTP, admin API key, config file, webhooks on (the ceiling) | **11** |
| HTTP, auth off (the shipped default) | **7** |
| stdio, config file | **10** |
| Minimum stripped surface, every gate off | 9 admin / 5 standard |
| Maximum, every gate configured on (unchanged by this cut) | **17** |

The eleven at the ceiling: `gateway_list_servers`, `gateway_list_tools`,
`gateway_search_tools`, `gateway_invoke`, `gateway_list_disabled_capabilities`,
`gateway_set_state`, `gateway_webhook_status`, `gateway_kill_server`,
`gateway_revive_server`, `gateway_reload_config`, `gateway_reload_capabilities`.
Arithmetic over the verified roster above.

`NFR.PERF.4` is restated as **11 meta-tools at the admin ceiling in the
shipped default gate configuration**, with the band at **9-17** over every gate
combination and the 7 / 10 figures published beside it. §7 rules on why these
are two figures rather than one range; the earlier `5-11` conflated them, and
five is a standard-standing number that no admin caller ever sees.

Two tools were considered and kept. `gateway_set_state` and
`gateway_list_disabled_capabilities` both read capability-backend state
(`mod.rs:2229-2231` for the former), and the shipped catalog attaches a
capability backend, so a capability-attachment gate would not fire on a default
deployment and would buy nothing.

## 3. What a caller who needs a cut tool does instead

No cut tool becomes unreachable. Three routes, in order of directness:

1. **Call it by name.** All six remain dispatchable through `tools/call`, for
   the reason set out above. A client that knows the name gets the same answer
   it gets today. This is the primary answer for every one of the six.
2. **Turn the gate on.** Each gate is an operator switch that is already the
   truthful description of the deployment: configure a routing profile and the
   three profile tools appear; enable `cost_governance` and the cost report
   appears; load a playbook directory and the playbook runner appears; set
   `meta_mcp.expose_stats_tool` and statistics appear. A deployment that uses a
   feature lists that feature's tool.
3. **Use the HTTP surface.** `/metrics` (`src/gateway/router/mod.rs:321`) and
   `/api/costs` (`src/gateway/router/mod.rs:249`) already serve the two
   operator-facing cuts without any meta-tool. Verified.

One projection follows the listing automatically and needs no separate work:
the gateway-owned guides build their served set from `meta_tools_for`
(`src/gateway/meta_mcp/resources.rs:348-352`), so a gated-off tool drops out of
the quickstart and routing guides with no edit. Verified.

One projection does not read the gates — `build_discovery_preamble`
(`src/gateway/meta_mcp_helpers.rs:258`) takes only the exposure filter. It names
`gateway_search_tools`, `gateway_invoke`, `gateway_list_tools` and
`gateway_list_servers` and nothing else
(`src/gateway/meta_mcp_helpers.rs:270-277`), none of which is cut, so the
initialize preamble stays correct. Verified.

## 4. Blast radius

This is the part that decides whether the change is small. It is: nine test
sites and one derived constant, all of them numeric or name-list assertions
with no structural coupling to the gates.

### Count assertions

| Site | Asserts | After the cut |
|---|---|---|
| `tests/nfr_perf_4_meta_tool_band.rs:25` | `const BAND: RangeInclusive<usize> = 14..=17` | **not a one-line edit — see §4.1** |
| `tests/nfr_perf_4_meta_tool_band.rs:82` | presence tracks the webhook registry in both directions | unchanged — `webhook_status` is not cut |
| `src/gateway/meta_mcp_tool_defs_tests.rs:26` | `build_meta_tools` with all gates off is 13 | becomes 9 |
| `src/gateway/meta_mcp_tool_defs_tests.rs:601` | same, as an exposure-work regression pin | becomes 9 |
| `src/gateway/meta_mcp_helpers_tests.rs:516` | 13 with all gates off | becomes 9 |
| `src/gateway/meta_mcp_helpers_tests.rs:551` | 14 with `stats` on | becomes 10, and the inline arithmetic comment at `:550` with it |
| `src/gateway/meta_mcp_helpers_tests.rs:581` | 14 with `reload` on | becomes 10, comment at `:580` with it |
| `src/gateway/meta_mcp_helpers_tests.rs:604` | 15 with `stats` and `reload` on | becomes 11 |

### Name-list fixtures

| Site | Holds | After the cut |
|---|---|---|
| `src/gateway/meta_mcp/tests.rs:4707` | `B10_EXPECTED_TOOLS`, 14 names pinned for a modern sessionless connection | drops `gateway_cost_report`, `gateway_run_playbook`, `gateway_set_profile`, `gateway_get_profile`, `gateway_list_profiles` → 9 names |
| `src/gateway/meta_mcp/tests.rs:5399` | `B01_EXPECTED_TOOLS`, the same 14 plus two surfaced backend tools | same five drop → 11 entries |
| `benchmarks/token_savings.py:162` | `GATEWAY_TOOLS`, the canonical README-benchmark definitions, length-checked against `public_claims.json` at `:322` | the same five definitions are deleted |

### Derived constant and its cross-checks

`src/honest_task_tokens.rs:22` — `pub const README_META_TOOLS: u64 = 17`
becomes 11. It feeds the token arithmetic at `:104`, `:123` and `:172`, and
`tests/public_claims_validation.rs:418` asserts it equals
`readme_token_savings.gateway_tools`. Verified.

`tests/public_claims_validation.rs` is the enforcement that makes this a
single change rather than a sweep: it derives both published figures from a
live `MetaMcp` — `minimum` from a bare handler and `readme_benchmark` from
`operational_meta_mcp()` (`:106-107`, `:84-102`) — and then asserts README
(`:351-352`) and `docs/BENCHMARKS.md` (`:447-448`) contain the matching prose.
Docs that do not move with the code fail this test. Verified.

Both figures are taken at `CallerStanding::Admin`: `meta_tool_count` calls
`handle_tools_list` (`:68-72`), which hardcodes admin standing
(`src/gateway/meta_mcp/mod.rs:1547-1555`). This is why the published 17 never
described the default HTTP caller. Verified.

### Not blast radius

`tests/mik_7218_acs.rs:318` asserts `window.tools_list_shadow.len() == 16`.
That is the telemetry map of filter combinations
(`src/protocol_revision_telemetry.rs:222`, `:232`), 2^4 keys, not a tool count.
Verified — it does not move.

Code Mode assertions are untouched: `src/gateway/meta_mcp/tests.rs:367`,
`src/gateway/meta_mcp_tool_defs_tests.rs:426-438` and
`src/gateway/meta_mcp_helpers_chain_tests.rs:451-468, 562` all pin the two-tool
schema, which this change does not touch.

`governed_meta_tool_names()` (`src/gateway/meta_mcp_tool_defs.rs:806-832`)
builds its set with every gate forced on and chains the Code Mode builder, so
the operator allow-list and the `-32601` non-disclosure behaviour
(`src/gateway/meta_mcp/mod.rs:1894-1907`) are unaffected by any gate change.
Verified — no allow-list test moves.

### Searches run for this section

`rg -n --hidden --no-ignore "len\(\), *1[0-9]|META_TOOL_COUNT|EXPECTED_TOOL"
--glob '!target/**' -g '*.rs'`; `rg -ln --hidden --no-ignore "14-17|14 to
17|14–17|NFR.PERF.4" --glob '!target/**'`; `rg -n "README_META_TOOLS" src/
tests/`. No fixture file holds a golden `tools/list` response: `rg -n --hidden
--no-ignore "gateway_list_disabled_capabilities|gateway_cost_report" --glob
'!target/**' --glob '!*.rs' --glob '!*.md' -l` returned
`benchmarks/token_savings.py` and nothing else — no `.json`, `.yaml` or `.snap`
golden file.

### 4.1 The band test must loop every gate axis before `BAND` moves

`nfr_perf_4_1_every_feature_combination_serves_a_surface_inside_the_band`
(`:64`) is universally quantified, but only over three axes — `stats`,
`webhooks`, `reload` — and it counts through the caller-less
`handle_tools_list`, which applies no standing filter. Today that is complete:
those are the only gates the served path varies, because `cost_report` is
hardcoded `true` at `mod.rs:1606`. The helper's doc comment says so in as many
words: "Every gate the served path actually reads, at both settings"
(`tests/nfr_perf_4_meta_tool_band.rs:41`).

After the cut it is no longer complete. Six gate fields control eight tools
(`stats`, `reload`, `cost_report`, `webhook_status`, `playbooks`, and one
`profiles` gate carrying three tools). Looping three of six leaves the two new
gates never exercised, so a `BAND` edit would pass **vacuously** — green
without evaluating what it claims to. That is worse than a red test.

**The loop takes all six axes before `BAND` is touched.** Six booleans is 64
combinations, not 256: the axis count is gate *fields*, not gated tools. Each
iteration builds an in-process `MetaMcp` and serialises one `tools/list`, so 64
is not a CI cost worth sampling around, and no sampling rule is proposed.

`meta_mcp_with` needs three more wirings, all of which already exist:

| Axis | Wiring | Where |
|---|---|---|
| `cost_report` | `with_cost_governance(enforcer, registry)` | `src/gateway/meta_mcp/mod.rs:1189` (consuming builder, `cost-governance` feature) |
| `playbooks` | `set_playbook_engine(engine)` | `src/gateway/meta_mcp/invoke.rs:3898` |
| `profiles` | `with_profile_registry(registry)` | `src/gateway/meta_mcp/mod.rs:696` (consuming builder) |

`cost_report`'s gate source is `self.cost_registry.is_some()`
(`Option<Arc<CostRegistry>>` at `mod.rs:384`, `None` at `:580`), which the
server sets only when `cost_governance.enabled` (`server/mod.rs:983`). Verified.
Note this is `cost_registry`, not `cost_tracker` — the tracker at `:370` is
unconditional and cannot serve as a gate.

With all six looped, the true range at the ceiling standing is **`9..=17`**:
seventeen with every gate on, nine with every gate off. Write that. A band
topping out at eleven is false for an operator who configures playbooks,
profiles, cost governance and `expose_stats_tool`, and the band is the one
claim in this document that is universally quantified.

The two `#[cfg(feature = "cost-governance")]` wirings mean the `cost_report`
axis is only exercisable in a build with that feature. Gate the axis on the
`cfg` rather than dropping it, or the default-feature CI run silently drops
back to a partial loop — the same vacuous-pass failure in a new costume.

## 5. The one-change checklist

The repository's own guidance names the tool count as a known drift source and
requires README, badges, `benchmarks/public_claims.json` and docs to move in
the same change as the code (`CLAUDE.md:162`). Every site that states a count
or lists the tools, found with `rg -n --hidden --no-ignore "14-17|14–17|14 to
17|NFR.PERF.4|17 meta|17 tools" --glob '!target/**'` plus the name searches in
§4:

### Code

- `src/gateway/meta_mcp_tool_defs.rs:575-583` — `MetaToolGates`: two new fields.
- `src/gateway/meta_mcp_tool_defs.rs:596-603` — the doc comment stating the
  `14-17` band and its webhook rationale; becomes `9-17`.
- `src/gateway/meta_mcp_tool_defs.rs:604-636` — `build_meta_tools`: five pushes
  move behind gates.
- `src/gateway/meta_mcp/mod.rs:1600-1615` — the gate sources.
- `src/routing_profile/mod.rs:331-334` — one accessor for the private
  `profiles` map.
- `src/config/mod.rs:1484-1497` — the `expose_stats_tool` flag on
  `MetaMcpConfig`.
- `src/honest_task_tokens.rs:22` — `README_META_TOOLS`, 17 → 11.
- `src/gateway/meta_mcp_tool_defs.rs:817-826` (`governed_meta_tool_names`) and
  `src/gateway/destructive_confirmation.rs:231-238` (`DESTRUCTIVE_META_TOOLS`)
  — both construct `MetaToolGates` as **exhaustive** struct literals with every
  flag `true`, so both stop compiling (`E0063`) until the two new fields are
  added. Add `playbooks: true, profiles: true`. Do **not** silence the error
  with `..Default::default()`: the derive at `:574` makes that compile and
  quietly drops five tools out of the operator allow-list's governed set and
  out of the destructive-confirmation set at once. Per §7, remove the
  `Default` derive at `:574` in the same change so that door stays shut.
- `tests/nfr_perf_4_meta_tool_band.rs` — see §4.1. Three new loop axes in
  `meta_mcp_with` (`:41`) and the loop nest (`:64`) **first**, then `BAND` at
  `:25` becomes `9..=17`, and the doc comment at `:20-24` restates what the
  band now quantifies over. Not a one-line constant edit.

### Machine-readable claims

- `benchmarks/public_claims.json:4` — `meta_tools.minimum`, 14 → 9 (the
  every-gate-off count at the ceiling standing, matching the band's floor; not
  5, which is a standard-standing figure — see §7).
- `benchmarks/public_claims.json:5` — `meta_tools.readme_benchmark`, 17 → 11.
- `benchmarks/public_claims.json:18` — `readme_token_savings.gateway_tools`,
  17 → 11.
- `benchmarks/token_savings.py:19-21` — the docstring restating the band.
- `benchmarks/token_savings.py:162` — the `GATEWAY_TOOLS` definitions.

### Prose

Which figure replaces which, per §7: a site stating the **band** (`14-17`)
takes `9-17`; a site stating the **benchmark or headline count** (`17`) takes
`11` and gains the words "at the admin ceiling"; a site describing what a
*user* sees takes `7` (HTTP) or `10` (stdio) with the standing named. A site
that states a bare number with no standing is the drift this list exists to
stop — give it one or delete the number.

- `README.md:21` — "a compact meta-surface of 14 to 17 tools".
- `README.md:37`, `README.md:46`, `README.md:308` — the three Mermaid diagram
  labels carrying `14-17`.
- `README.md:259` — the comparison-table cell "17 meta-tools in the README
  benchmark (~1,700 tokens)"; the token figure moves with the count.
- `README.md:267` — the paragraph enumerating which tools are conditional.
- `README.md:411`, `README.md:568` — two positioning lines quoting `14-17`.
- `docs/BENCHMARKS.md:17`, `:65`, `:90` — the claims table row, the Code Mode
  contrast and the token derivation.
- `ARCHITECTURE.md:42` and the derivation table at `:44-60` — one row per tool,
  with an `Always` column that the two new gates change.
- `docs/ARCHITECTURE.md:13` — the ASCII diagram label.
- `docs/DEPLOYMENT.md:938` — the meta-tool-narrowing section.
- `docs/show-hn.md:33` — the launch summary.
- `gateway.example.yaml:23` — the `exposed_meta_tools` comment stating the band.
- `CLAUDE.md:111`, `:121`, `:139`, `:193` — vision, status, the locked-decision
  row and the architecture summary.
- `CHANGELOG.md` — a new `[Unreleased]` entry. This is operator-visible: a
  deployment that lists `gateway_run_playbook` today will stop listing it until
  a playbook directory is configured.

### Release governance

- `docs/requirements/RELEASE-4.0.0-requirements.md:295` — `NFR.PERF.4`, the
  band itself.
- `docs/requirements/RELEASE-4.0.0-criteria-status.md:418` — the `NFR.PERF.4`
  evidence row, which quotes the 14/16/17 spread and the test that pins it.
- `docs/requirements/RELEASE-4.0.0-plan.md:64`, `:71`, `:288`, `:430` — the
  band and the 2026-09-08 webhook ruling that set it.
- `docs/requirements/RELEASE-4.0.0-blocking-rollup.md:270` — the rollup line.
- `docs/requirements/RELEASE-4.0.0-gap-plan.md:833` — "1-3 tools off a 14-17
  tool surface".
- `docs/release/v4.0.0-release-notes-DRAFT.md:213` — the carried-forward band
  evidence row.

The README's badge block is `README.md:3-17`. Fifteen badges, none of
which encodes a tool count — the closest is the capability badge at `:10`
("REST capabilities 110+"), which counts capability YAML files, not meta-tools.
No badge needs editing. Verified by reading the block.

One document is already untrue and should be corrected in the same change
rather than merely renumbered: `ARCHITECTURE.md:42` says fourteen tools are
unconditional, which describes the built list and not the served one — the
admin axis (`src/gateway/meta_mcp/mod.rs:1624`) removes four of them from every
non-admin caller today, and the table's `Always` column has no column for it.

## 6. Risks and falsifiers

Each risk carries a check that can be run in minutes and a threshold that
decides it. None requires a benchmark.

### R1 — a gated-off tool turns out to be unreachable

The whole design rests on gates governing listing only. **Falsifier:** `rg -n
"MetaToolGates" --type rust src/ tests/` and read every consumer.
**Pass:** the only consumers are `build_meta_tools`
(`src/gateway/meta_mcp_tool_defs.rs:604`), `build_meta_tools_filtered`
(`:926`), `governed_meta_tool_names` (`:817`), `DESTRUCTIVE_META_TOOLS`
(`src/gateway/destructive_confirmation.rs:231`) and the one call in
`meta_tools_for` (`src/gateway/meta_mcp/mod.rs:1602`). **Fail:** any
authorization, dispatch or routing path reads the struct.
**Already run for this document: pass** — those five and nothing else.

### R2 — a compile error gets silenced instead of fixed

Both `governed_meta_tool_names()`
(`src/gateway/meta_mcp_tool_defs.rs:817-826`) and `DESTRUCTIVE_META_TOOLS`
(`src/gateway/destructive_confirmation.rs:231-238`) construct `MetaToolGates`
as exhaustive struct literals with every flag `true` and no `..`. Adding two
fields breaks both with `E0063`, so the compiler does raise the alarm — the
hazard is how it gets answered. `MetaToolGates` derives `Default` (`:574`), so
`..Default::default()` compiles, reads like a tidy fix, and silently drops five
tools out of the operator allow-list's governed set and out of the
destructive-confirmation set, because `is_exposed` admits anything ungoverned.
**Falsifier:** `every_builder_contributes_to_the_governed_set`
(`src/gateway/meta_mcp_tool_defs_tests.rs:639`), with
`conditionally_enumerated_webhook_status_is_still_governed_by_an_allow_list`
(`:626`) as the companion. **Pass:** the governed set still contains all
nineteen names — seventeen built plus the two Code Mode tools. **Fail:** any
count below nineteen.

### R3 — a shipped artifact calls a cut tool by name and stops working

**Falsifier:** `rg -n --hidden --no-ignore
"gateway_run_playbook|gateway_set_profile|gateway_get_profile|gateway_list_profiles"
--glob '!target/**' --glob '!*.md' --glob '!*.rs' -l`. **Pass:** hits are
`benchmarks/token_savings.py` (the benchmark definitions, edited by this
change), `examples/playbook-morning-briefing.yaml` (a playbook *definition*,
not a caller — and a deployment that loads it turns the playbook gate on) and
`scripts/release/extract-operator-decisions.py` (a text scanner over release
documents). **Fail:** any capability YAML, skill or shipped script invoking one.
**Already run for this document: pass** — those three files only.

### R4 — published claims drift, which this repository has done before

**Falsifier:** `tests/public_claims_validation.rs`. It derives both figures
from a live handler (`:106-107`) and asserts the README (`:351-352`) and
`docs/BENCHMARKS.md` (`:447-448`) prose matches. **Pass:** the test passes
after every §5 edit. **Fail:** any mismatch. The threshold is the test result,
not a reading of the diff.

### R5 — the band passes vacuously

The band figures are counted off the roster by hand, and §4.1 shows the
existing test cannot check them: three loop axes against six gates means the
two new gates are never exercised, so a `BAND` edit goes green without
evaluating anything it claims to.
**Falsifier:** add the three missing axes first, then run the test **before**
editing `BAND` and read the failure message — it prints the served count and
the gate values for the combination that fell outside.
**Pass:** the failures it prints bracket exactly `9..=17`, one combination at
nine and one at seventeen. **Fail:** anything else, or a green run, which means
an axis is not wired to a gate and the loop is still decorative. Do not edit
`BAND` and the loop in the same step: the whole value of this check is seeing
the old band break where the arithmetic says it should.

### R6 — stdio operators lose their only stats view

Stdio has no `/metrics` endpoint, so an opt-in `expose_stats_tool` defaulting
to `false` takes `gateway_get_stats` off every stdio listing.
**Falsifier:** confirm the dispatch arm at `src/gateway/meta_mcp/mod.rs:2094`
is reached with the gate off, which R1 establishes structurally; then call
`gateway_get_stats` by name over stdio against a build with the gate off.
**Pass:** a normal stats payload. **Fail:** `-32601`, which would mean a gate
leaked into dispatch and the whole design is void.

### R7 — the ruling's baseline is a number no default deployment ever served

This is the largest risk and it is not technical. "Seventeen" is the admin
ceiling (§1), reached only by an admin-authenticated HTTP caller. A default
HTTP deployment lists thirteen today and would list seven after this change —
past the target, because the standing axis compounds with the gates. A stdio
client, always admin, goes from sixteen to ten.
**Falsifier:** put all four numbers — admin ceiling 17→11, default HTTP 13→7,
stdio 16→10 — in front of the release owner before merge and record which one
the ruling governs. **Pass:** a recorded answer. **Fail:** merging with the
question open, which would let the release close against a criterion whose
number means something different from what was ruled. The cheapest form of
this check is one line in the `NFR.PERF.4` restatement naming the standing the
band is measured at. `tests/public_claims_validation.rs:68-72` counts through
the caller-less `handle_tools_list`, which applies no standing filter, so the
ceiling is the number the tests enforce whatever the prose says.

**Settled — see §7.** The release owner has ruled that the criterion is
measured at the admin ceiling. The consequence for the band's figures is
recorded below.

## 7. Ruling on R7: which number the criterion governs

`NFR.PERF.4` is measured at the **admin ceiling** — the count a caller with
every standing sees. Three facts settle it.

The test already measures that number and cannot measure another one.
`meta_tool_count` calls `handle_tools_list(RequestId::Number(1))` with no
caller at all (`tests/public_claims_validation.rs:68-72`), so it counts the
undropped surface. A criterion restated against the default HTTP band would be
enforced by a test that never evaluates it.

The ceiling is the honest worst case for the claim the criterion exists to
protect. The surface-size claim is about context cost, and an admin stdio
caller pays the ceiling on every request. Quoting the smaller default-HTTP
number would advertise a cost no privileged session actually incurs, which is
the drift `benchmarks/public_claims.json` was introduced to stop.

The smaller numbers are real and must be published, not hidden. The
restatement names its standing explicitly — *N meta-tools at the admin
ceiling* — and records the default HTTP and stdio bands beside it, so the
figure cannot be read as a per-caller promise. After the cut that is 11 for an
admin caller in the shipped default gate configuration, 7 for a default HTTP
caller, 10 for stdio. Eleven is the top of the shipped-gate band, not a ceiling
over gate configurations — see the two axes below.

### The gate struct loses its `Default`

R2 is a live hazard, not a note: `MetaToolGates` derives `Default`
(`src/gateway/meta_mcp_tool_defs.rs:574`), and both `governed_meta_tool_names()`
and `DESTRUCTIVE_META_TOOLS` set every flag to `true` by hand. A later field
added with `..Default::default()` drops tools out of the allow-list and the
destructive-confirmation set with no compiler error.

Remove the `Default` derive as part of this change. Every construction site
then lists every field, and the silent allow-list hole becomes a build
failure. This is cheaper than the guard test it replaces, because it cannot be
forgotten.

### The two axes are different kinds of thing

Caller standing is not the operator's to choose: on any deployment an admin
caller sees the undropped surface whether the operator likes it or not. Gate
configuration *is* their choice — enabling cost governance is opting into those
tools. Collapsing both into one range is what produced a number false for
somebody whichever value was picked. So the document publishes two figures, of
two different kinds:

| | Figure | Quantification |
|---|---|---|
| **The band** | **9-17** | Universal, over both axes: every gate combination at the ceiling standing. Nine with every gate off, seventeen with every gate on. This is what `tests/nfr_perf_4_meta_tool_band.rs` asserts (§4.1). |
| **The headline** | **11** | The admin ceiling in the **shipped default gate configuration** — no playbooks, no profiles, cost governance off, `expose_stats_tool` off. This is where the cut's value shows up, and it is the number the `NFR.PERF.4` restatement names. |
| Beside it | **7** | Default HTTP caller (auth off, standard standing), same gate configuration. |
| Beside it | **10** | Stdio caller (always admin, never a webhook registry), same gate configuration. |

Each of the last three is labelled with its standing wherever it is published.
None of them is presented as the range.

### The cut does not lower the maximum

State this plainly wherever the new figure appears, because the first reader of
"surface compacted to 11" will otherwise believe something false: **nothing is
deleted by this change.** All seventeen tools remain built, dispatchable and
listable. An operator who configures playbooks, routing profiles, cost
governance and `expose_stats_tool` is served all seventeen, exactly as today.

The value of the cut is entirely in the default. It moves five tools from
"listed for everyone" to "listed for the operators who asked for them", which
is why the band's top does not move and the headline's does.

### Follow-through on removing the `Default` derive

Removing the derive is right, and it is cheaper than the paragraph above
suggests, because the two sites named there are **exhaustive** struct literals
with no `..`: `governed_meta_tool_names()`
(`src/gateway/meta_mcp_tool_defs.rs:817-826`) and `DESTRUCTIVE_META_TOOLS`
(`src/gateway/destructive_confirmation.rs:231-238`) already fail to compile
(`E0063`) when a field is added. The derive is what would let a future author
answer that error with `..Default::default()` instead of the two new fields.
Dropping it closes that door permanently. Check first that nothing else relies
on it: `rg -n "MetaToolGates::default|MetaToolGates \{ *\.\." --type rust`.
