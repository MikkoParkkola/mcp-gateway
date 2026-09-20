<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# Test plan: compacting the Meta-MCP client tool surface

Test plan for `docs/design/2026-09-16-meta-tool-surface-compaction.md`. The
design is the specification; this document does not re-open it.

## 0. The premise changed: the design is already implemented

The design was written against a 17-tool surface. It has since landed on this
branch (`37bd9121 feat(meta-mcp): compact the meta-tool surface and relocate
internal docs`). Read at source on HEAD:

| Design requirement | State on HEAD |
|---|---|
| Two new gate fields | `playbooks` (`src/gateway/meta_mcp_tool_defs.rs:599`), `profiles` (`:604`) |
| `Default` derive removed | `src/gateway/meta_mcp_tool_defs.rs:583` derives `Clone, Copy, Debug, PartialEq, Eq` only; the doc comment above says "Deliberately has **no `Default`**" |
| `stats` re-sourced to an opt-in | `stats: self.expose_stats_tool` (`src/gateway/meta_mcp/mod.rs:1668`); flag at `:452`, builder `with_expose_stats_tool` at `:778`, config default `false` at `src/config/mod.rs:1524` |
| `cost_report` re-sourced to registry attachment | `cost_report: self.cost_registry.is_some()` (`mod.rs:1674`) |
| New gate sources | `playbooks: !self.playbook_engine.read().is_empty()` (`:1681`), `profiles: self.profile_registry.has_configured_profiles()` (`:1682`) |
| Band `9..=17` | `tests/nfr_perf_4_meta_tool_band.rs:33` |
| Band loops all six axes | `tests/nfr_perf_4_meta_tool_band.rs:156-170` |
| `README_META_TOOLS` 17 → 11 | `src/honest_task_tokens.rs`, constant and its doc comment both read eleven |
| `public_claims.json` 14/17 → 9/11 | `benchmarks/public_claims.json`, plus a new `"standing": "admin"` field |
| A dedicated test module | `src/gateway/meta_mcp/surface_compaction_tests.rs`, 152 lines, wired at `src/gateway/meta_mcp/mod.rs:2804-2805` |

So this plan is **coverage mapping plus a short list of seams**, not a
greenfield suite. The seam list is short because the implementation landed
with its fixtures: `with_expose_stats_tool` (`mod.rs:778`),
`with_profile_registry` (`:749`), `set_playbook_engine`
(`src/gateway/meta_mcp/invoke.rs:3904`), `handle_tools_list_for_session`
(`mod.rs:1700`), `one_playbook()` / `one_profile()`
(`tests/nfr_perf_4_meta_tool_band.rs:51-66`), `shipped_default()`
(`src/gateway/meta_mcp/surface_compaction_tests.rs:71`).

### Honesty constraint on every "green" in this document

No `cargo` command was run for this plan. Every "lands GREEN" is **inferred**
from reading the asserted constant against current source, not from an
executed run. Every `file:line` is **verified** — opened and read on HEAD.
Anything marked **assumption** was neither.

## 1. Scope table

"Compiles today" means: the symbols, signatures and fixtures the body needs
exist on HEAD as written.

| Test | Target file | Design section | Compiles today |
|---|---|---|---|
| `shipped_default_gate_configuration_lists_eleven_to_an_admin_caller` | `src/gateway/meta_mcp/surface_compaction_tests.rs:98` | §2 "Resulting counts", §7 headline | **Exists.** Yes |
| `every_tool_the_cut_stops_listing_is_still_callable_by_name` | `src/gateway/meta_mcp/surface_compaction_tests.rs:123` | §3, R1, R6 | **Exists.** Yes — see §4.3 for a tightening |
| `nfr_perf_4_1_every_feature_combination_serves_a_surface_inside_the_band` | `tests/nfr_perf_4_meta_tool_band.rs:155` | §4.1, R5 | **Exists.** Yes |
| `build_meta_tools_spans_the_documented_band` | `src/gateway/meta_mcp_tool_defs_tests.rs:141` | §4 count assertions | **Exists.** Yes |
| `every_builder_contributes_to_the_governed_set` | `src/gateway/meta_mcp_tool_defs_tests.rs:664` | R2 | **Exists.** Yes |
| `canonical_meta_tool_counts_match_live_runtime` | `tests/public_claims_validation.rs:336` | §4 derived constant, R4 | **Exists.** Yes |
| `readme_benchmark_surface_shrinks_by_the_admin_set_for_a_standard_caller` | `tests/public_claims_validation.rs:356` | §7 the 7 figure | **Exists.** Yes |
| `a_stdio_shaped_deployment_serves_the_published_ten` | `tests/public_claims_validation.rs` (new) | §7 the 10 figure, R4, R7 | **Yes** — needs no new seam |
| `the_band_sweep_covers_every_gate_field` | `src/gateway/meta_mcp_tool_defs_tests.rs` (new) | §4.1, R5 | **Yes** — `MetaToolGates` is `pub(crate)`, this module is inside the crate |
| `a_cut_tool_answers_tools_call_with_its_own_payload` | `src/gateway/meta_mcp/surface_compaction_tests.rs` (amend `:143-150`) | R6 pass criterion | **Yes** |
| `the_routing_guide_gains_a_tool_when_its_gate_opens` | `src/gateway/meta_mcp/search_disclosure_e2e.rs` (new) | §3 projection | **Yes** — `guide_tool_names` (`:932`), `routing_guide_text` (`:940`) exist |
| `the_discovery_preamble_never_names_a_cut_tool` | `src/gateway/meta_mcp_helpers_tests.rs` (new) | §3 "One projection does not read the gates" | **Yes** |
| `no_shipped_artifact_invokes_a_cut_meta_tool_by_name` | `tests/public_claims_validation.rs` (new) | R3 | **Yes** — `walkdir` already a dev-dependency, used at `tests/public_claims_validation.rs:21` |
| `release_criterion_states_the_band_the_band_test_enforces` | `tests/public_claims_validation.rs` (new) | §8.3, R4 | **Yes** — re-derives the bounds the way `live_meta_tool_counts` (`:114-124`) already does |

Nothing in this plan needs a `#[cfg(test)]` addition to production code. That
is a consequence of the implementation having landed with its builders public;
had it not, `has_configured_profiles` would have been the one seam, and it is
already `pub` (called from `mod.rs:1682`, reachable from the crate).

## 2. Naming

The repo's test modules use snake_case sentences, not `test_` prefixes:
`webhook_status_is_enumerated_exactly_when_its_registry_is_attached`
(`src/gateway/meta_mcp_tool_defs_tests.rs:69`),
`conditionally_enumerated_webhook_status_is_still_governed_by_an_allow_list`
(`:651`), `every_tool_the_cut_stops_listing_is_still_callable_by_name`
(`src/gateway/meta_mcp/surface_compaction_tests.rs:123`). Requirement-tagged
tests carry the tag first: `nfr_perf_4_1_...`,
`mik_7332_discovery_1_routing_guide_agrees_with_served_list`. New names below
follow both patterns.

## 3. Existing coverage, and which of it lands GREEN on an unchanged tree

Every row here is a **regression guard**. It passes on HEAD today. A green
result from any of them means "the compaction has not been undone", never
"this plan's new work is done". Read the column literally.

| Test | What it would catch | Result on an unchanged tree |
|---|---|---|
| `shipped_default_gate_configuration_lists_eleven_to_an_admin_caller` (`surface_compaction_tests.rs:98`) | A tool re-added to the base pushes, or one of the eleven lost. Asserts the sorted name list, not only the count | GREEN |
| `every_tool_the_cut_stops_listing_is_still_callable_by_name` (`:123`) | A gate leaking into dispatch — the design's void condition | GREEN |
| `nfr_perf_4_1_every_feature_combination_serves_a_surface_inside_the_band` (`nfr_perf_4_meta_tool_band.rs:155`) | Any of the 64 gate combinations serving outside `9..=17`; the webhook diagnostic decoupling from its registry; either end of the band going unattained | GREEN |
| `build_meta_tools_spans_the_documented_band` (`meta_mcp_tool_defs_tests.rs:141`) | Builder arithmetic drifting from 9 / 17 without the served path moving | GREEN |
| `every_builder_contributes_to_the_governed_set` (`:664`) | R2 exactly: a builder whose tool no allow-list can restrict | GREEN |
| `conditionally_enumerated_webhook_status_is_still_governed_by_an_allow_list` (`:651`) | Governance following listing rather than dispatchability | GREEN |
| `canonical_meta_tool_counts_match_live_runtime` (`public_claims_validation.rs:336`) | `public_claims.json` drifting from a live `MetaMcp`; `readme_token_savings.gateway_tools` drifting from `readme_benchmark` | GREEN |
| `readme_benchmark_surface_shrinks_by_the_admin_set_for_a_standard_caller` (`:356`) | The 7 figure drifting, and the admin set being disclosed to a caller who cannot dispatch it | GREEN |
| `honest_model_constants_match_canonical_claims` (`:467`) | `README_META_TOOLS` drifting from the claims file | GREEN |
| `token_savings_benchmark_tracks_readme_meta_tool_surface` (`:569`) | `benchmarks/token_savings.py`'s `GATEWAY_TOOLS` drifting from the published count | GREEN |
| `public_surfaces_do_not_retain_obsolete_meta_mcp_claims` (`:603`) | A retired phrase such as the old band surviving in a public surface | GREEN |
| `mik_7332_discovery_1_routing_guide_agrees_with_served_list` (`search_disclosure_e2e.rs:973`) | The routing guide naming a tool the caller's own listing withholds, on the standing and allow-list axes | GREEN — but see §4.4: it is built on `MetaMcp::new`, so the **gate** axis is never exercised |

### The band test is not vacuous today

§4.1 of the design warned that a three-axis loop against six gates passes
vacuously. That warning was answered. The shipped loop sweeps all six
(`nfr_perf_4_meta_tool_band.rs:156-170`) and, more importantly, pins that both
ends are reached:

- `seen.iter().min() == Some(*BAND.start())` (`:206-210`) — some configuration
  must attain nine.
- `seen.iter().max() == Some(ATTAINABLE_CEILING)` (`:215-220`) — some
  configuration must attain the highest count this build's features allow.
- `ATTAINABLE_CEILING` is 17 with `cost-governance` and 16 without
  (`:149-152`), and `COST_AXIS` is `[false, true]` or `[false]` to match
  (`:139-142`). `cost-governance` is in `default` (`Cargo.toml:179`), so the
  repo's own gate command `cargo test --quiet` sweeps both settings and
  enforces the published 17.

A band nothing reaches the ends of fits anything, so do not describe this one
as vacuous. **But the earlier claim here — that it cannot be widened for free
— was wrong at the top end, and §6.1 records why.** The floor is pinned to
`BAND`; the ceiling is pinned to a constant that `BAND` does not constrain.

## 4. New tests

### 4.1 The stdio figure is published and nothing derives it

`NFR.PERF.4` states "the shipped default HTTP deployment serves 11 and stdio
10" (`docs/requirements/RELEASE-4.0.0-requirements.md:295`), repeated at
`docs/DEPLOYMENT.md:951`. The 11 is derived from a live handler
(`public_claims_validation.rs:336`). The 7 is derived as
`readme_benchmark - 4` (`:356`). **The 10 is derived nowhere and carried in no
structured field.** That is the drift class `benchmarks/public_claims.json`
exists to stop, and R4's own falsifier does not reach it.

A stdio deployment is the operational fixture minus the webhook registry:
`run_stdio` never calls `set_webhook_registry`
(`src/gateway/meta_mcp_tool_defs.rs:615-620`, the `build_meta_tools` doc
comment), and stdio is always admin (`const STDIO: CallerStanding =
CallerStanding::Admin`, `src/gateway/server/mod.rs`). So the count is the
published 11 minus one.

Add to `tests/public_claims_validation.rs`:

```rust
/// The stdio figure `NFR.PERF.4` publishes
/// (`docs/requirements/RELEASE-4.0.0-requirements.md:295`,
/// `docs/DEPLOYMENT.md:951`), derived rather than asserted flat: it is the
/// admin benchmark minus `gateway_webhook_status`, because `run_stdio` never
/// attaches a webhook registry and stdio callers are always admin.
///
/// Written against a live handler for the same reason the other figures are:
/// a number in prose that no test evaluates is the drift this file exists to
/// stop.
#[test]
fn a_stdio_shaped_deployment_serves_the_published_ten() {
    let claims = load_claims();
    let backends = Arc::new(BackendRegistry::new());
    let meta_mcp = MetaMcp::with_features(
        Arc::clone(&backends),
        None,
        Some(Arc::new(UsageStats::new())),
        None,
        Duration::from_secs(60),
    );
    meta_mcp.set_reload_context(make_reload_context(Arc::clone(&backends)));
    // Deliberately no webhook registry: that is what makes this stdio.

    let served = decode_tools_list(meta_mcp.handle_tools_list(RequestId::Number(1))).tools;
    let names: Vec<&str> = served.iter().map(|t| t.name.as_str()).collect();

    assert!(
        !names.contains(&"gateway_webhook_status"),
        "stdio attaches no webhook registry, so the diagnostic must not be listed: {names:?}"
    );
    assert_eq!(
        served.len(),
        claims.meta_tools.readme_benchmark - 1,
        "the stdio surface is the published admin benchmark of {} minus the \
         webhook diagnostic; NFR.PERF.4 publishes 10, served {names:?}",
        claims.meta_tools.readme_benchmark
    );
}
```

Compiles today: `load_claims`, `make_reload_context`, `decode_tools_list`,
`MetaMcp::with_features` and `RequestId` are all already imported in that file
(`:3-19`, `:68-92`). `handle_tools_list` lists at admin standing
(`src/gateway/meta_mcp/mod.rs:1610-1613`), which is the stdio standing, so no
`CallerStanding` argument is needed.

Result on an unchanged tree: **GREEN** (inferred: 11 − 1 = 10, matching the
published figure). It is a guard against the published 10 drifting, not a
discovery of a defect.

**Divergence from §5, not a bug.** §5 asked for the three standing-labelled
figures as *structured fields* in `public_claims.json`. The implementation
published one (`"standing": "admin"`) and recorded the others as tests. The
doc comment at `public_claims_validation.rs:356` states the reasoning: the
standard figure is "recorded as a test rather than a published claim because
no prose quotes it". That reasoning does not extend to the stdio 10, because
prose *does* quote it — twice. Whether the 10 also earns a JSON field is a
reviewer call, not this plan's.

### 4.2 Nothing keeps the band sweep in step with the gate struct

R5's defect is a loop that has stopped selecting anything. The shipped loop
sweeps all six fields today (§3), but `tests/nfr_perf_4_meta_tool_band.rs`
declares its own private `Gates` struct (`:75-85`) and `MetaToolGates` is
`pub(crate)` (`src/gateway/meta_mcp_tool_defs.rs:583`), so the integration
test cannot see the type it is meant to be sweeping. A seventh gate field
added later compiles, the loop keeps sweeping six, and the band goes green
without evaluating the new axis — R5 verbatim, one field later.

The guard has to live inside the crate. A struct pattern that omits a field is
`E0027`, so exhaustive destructuring is the seam:

```rust
/// `tests/nfr_perf_4_meta_tool_band.rs` sweeps a private mirror of this
/// struct, and cannot see this type to check the mirror is complete. This is
/// that check, from the side that can.
///
/// The destructuring is the mechanism, not decoration: a seventh field added
/// to `MetaToolGates` makes this pattern `E0027`, and the author who fixes it
/// is standing in the one place that names the band sweep. Without it the
/// sweep silently covers six of seven axes and reports green for an axis it
/// never set — the failure mode §4.1 of the design named, one field later.
///
/// Each flag is also asserted to move the built count on its own. A field
/// that is swept but gates nothing is the quieter half of the same defect.
#[test]
fn the_band_sweep_covers_every_gate_field() {
    let all_off = MetaToolGates {
        stats: false,
        reload: false,
        cost_report: false,
        webhook_status: false,
        playbooks: false,
        profiles: false,
    };
    // E0027 here when a field is added. Do not answer it with `..`.
    let MetaToolGates {
        stats: _,
        reload: _,
        cost_report: _,
        webhook_status: _,
        playbooks: _,
        profiles: _,
    } = all_off;

    let floor = build_meta_tools(all_off, 0, 0).len();
    assert_eq!(floor, 9, "every gate off is the band floor");

    let axes: [(&str, fn(&mut MetaToolGates)); 6] = [
        ("stats", |g| g.stats = true),
        ("reload", |g| g.reload = true),
        ("cost_report", |g| g.cost_report = true),
        ("webhook_status", |g| g.webhook_status = true),
        ("playbooks", |g| g.playbooks = true),
        ("profiles", |g| g.profiles = true),
    ];
    let mut total_added = 0;
    for (name, set) in axes {
        let mut gates = all_off;
        set(&mut gates);
        let count = build_meta_tools(gates, 0, 0).len();
        assert!(
            count > floor,
            "the {name} axis must add at least one tool on its own, \
             or sweeping it is decorative: {floor} -> {count}"
        );
        total_added += count - floor;
    }
    assert_eq!(
        floor + total_added,
        17,
        "the six axes must account for every tool between the band's ends; \
         a tool reachable only through two gates at once would break this"
    );
}
```

Compiles today: `MetaToolGates` and `build_meta_tools` are already imported in
`src/gateway/meta_mcp_tool_defs_tests.rs` (used at `:17`, `:141`). The six
field names are verified at `src/gateway/meta_mcp_tool_defs.rs:589-604`. The
counts 9 and 17 are verified against `build_meta_tools_spans_the_documented_band`
(`:141-175`). Each gate adds exactly one tool except `profiles`, which adds
three (`build_meta_tools` pushes `set_profile` and `get_profile` at one site
and `list_profiles` at another, `src/gateway/meta_mcp_tool_defs.rs:628-667`),
so 9 + (1+1+1+1+1+3) = 17.

Result on an unchanged tree: **GREEN**. This test exists to fail on the
*next* gate field, not on this one. That is the whole of its value, and a
reviewer should read its green as "the tripwire is armed".

Note the `assert!(count > floor)` per axis is the part that catches the design
document's own worst case — the `stats` axis that kept looping over a boolean
after it stopped selecting anything (§4.1's fourth instance).

### 4.3 The R6 assertion passes for the wrong reasons

`every_tool_the_cut_stops_listing_is_still_callable_by_name`
(`src/gateway/meta_mcp/surface_compaction_tests.rs:123-152`) asserts
`assert_ne!(error.code, -32601)` (`:144-149`). R6's stated pass criterion is
"a normal stats payload"; its fail is `-32601`. The gap between those is every
other error code. A tool half-wired into dispatch that answers `-32602`
invalid-params, or an authorization refusal, satisfies the current assertion
while failing the risk it was written for.

Transport is not the gap. Dispatch is a flat name match
(`src/gateway/meta_mcp/mod.rs:2094-2106`), so stdio and HTTP get the same
answer and an HTTP-shaped fixture is the right one.

Tighten in place rather than adding a test:

```rust
        let response = meta_mcp
            .handle_tools_call(
                RequestId::Number(2),
                tool,
                json!({}),
                None,
                super::authz_tests::ctx(&authorizer),
            )
            .await;

        // R6's pass criterion is a payload, not merely "some error other than
        // -32601". A tool half-wired into dispatch answers -32602 and would
        // satisfy `assert_ne!(code, -32601)` while failing the risk.
        assert!(
            response.error.is_none(),
            "{tool} is gated off the listing, not removed: tools/call answered \
             error {:?}",
            response.error
        );
        assert!(
            response.result.is_some(),
            "{tool} must answer tools/call with a result even though {gate} is off"
        );
```

Compiles today: same bindings, no new imports.

Result on an unchanged tree: **this is the one row in this plan that may land
red.** Three of the six cut tools take required arguments
(`gateway_set_profile` needs a profile name, `gateway_run_playbook` a playbook
name), and `json!({})` may be rejected as invalid params before the handler
runs. If so the fix is to give each entry in `CUT`
(`surface_compaction_tests.rs:29-36`) a minimal valid argument object and keep
the strict assertion, not to relax the assertion back. Stated as
**inferred** — the argument schemas were not read for this plan, and a
reviewer should treat this row as work with an undetermined result rather
than a guard.

### 4.4 The guide projection is never exercised on the gate axis

§3 of the design claims a gated-off tool drops out of the quickstart and
routing guides with no edit, because the guides project through
`meta_tools_for` (`src/gateway/meta_mcp/resources.rs:348-352`).
`mik_7332_discovery_1_routing_guide_agrees_with_served_list`
(`src/gateway/meta_mcp/search_disclosure_e2e.rs:973`) checks that agreement on
the **standing** and **allow-list** axes only: it builds `MetaMcp::new`
(`:975`), where every gate is already off, so no gated tool is ever present to
drop. The subset assertion holds trivially for the gate axis.

```rust
/// §3 of the compaction design: a gated-off tool drops out of the guides with
/// no edit, because they project through the same `meta_tools_for` the
/// listing answers from.
///
/// The gate axis, which `mik_7332_discovery_1_routing_guide_agrees_with_served_list`
/// does not reach: that test builds `MetaMcp::new`, where every gate is
/// already off, so a subset assertion cannot distinguish "correctly withheld"
/// from "never built". This one opens a gate and requires the guide to move.
#[tokio::test]
async fn the_routing_guide_gains_a_tool_when_its_gate_opens() {
    let closed = MetaMcp::new(Arc::new(BackendRegistry::new()));
    let closed_named = guide_tool_names(&routing_guide_text(&closed, CallerStanding::Admin).await);
    assert!(
        !closed_named.contains("gateway_get_stats"),
        "with the stats opt-in off the guide must not document the tool: {closed_named:?}"
    );

    let open = MetaMcp::new(Arc::new(BackendRegistry::new())).with_expose_stats_tool(true);
    let open_named = guide_tool_names(&routing_guide_text(&open, CallerStanding::Admin).await);
    assert!(
        open_named.contains("gateway_get_stats"),
        "with the opt-in on the guide must document the tool it now lists: {open_named:?}"
    );

    let listed = listed_names(&open.handle_tools_list_for_session(
        RequestId::Number(2),
        None,
        CallerStanding::Admin,
    ));
    for name in &open_named {
        assert!(
            listed.contains(name),
            "the routing guide names {name} but the served list withholds it: {listed:?}"
        );
    }
}
```

Compiles today: `guide_tool_names` (`search_disclosure_e2e.rs:932`),
`routing_guide_text` (`:940`), `listed_names` (`:756`),
`with_expose_stats_tool` (`src/gateway/meta_mcp/mod.rs:778`, a consuming
builder returning `Self`) and `handle_tools_list_for_session` (`:1700`,
taking `RequestId`, `Option<&str>`, `CallerStanding`) all exist. Two
registries rather than one, because `with_expose_stats_tool` consumes the
handler and `closed` is still needed for the negative half.

Result on an unchanged tree: **settled by review — the test above fails, and
the fix is to change the tool, not the guide.** `routing_content()`
(`src/gateway/meta_mcp/resources.rs:135-181`) never names `gateway_get_stats`.
The only guide that does is `quickstart_content()`, at `:123`. So the positive
half asserts something the routing guide cannot say under any gate setting.

The tool is wrong; the guide is right. `routing_content()` names six
meta-tools, and three of them — `gateway_set_profile`, `gateway_get_profile`,
`gateway_list_profiles` — sit behind the `profiles` gate
(`profiles: self.profile_registry.has_configured_profiles()`,
`meta_mcp_tool_defs.rs:1682`). Opening that gate through `with_profile_registry`
(`mod.rs:749`) moves exactly the tools the routing guide already documents.

**Revised assertion:** keep the shape above; open `profiles` rather than the
stats opt-in, and assert on `gateway_set_profile`. The negative half still
starts from `MetaMcp::new`, where the gate is off because the registry is
empty.

Two things this resolution also establishes, both checked at source rather
than assumed:

* §3's projection claim holds for **both** guides, not just the routing one:
  `try_serve_guide` (`resources.rs:226-240`) runs `retain_served_sections`
  over `quickstart_content()` and `routing_content()` alike. A guide test on
  either is a test of the same mechanism.
* The test remains worth writing. It was never the tool name that made it
  load-bearing — it is the gate axis, which
  `mik_7332_discovery_1_routing_guide_agrees_with_served_list` cannot reach.
  That gap is unchanged by this correction.

### 4.5 The discovery preamble, as a cheap green guard

§3 notes `build_discovery_preamble` (`src/gateway/meta_mcp_helpers.rs:259`)
reads only the exposure filter and names four tools — `gateway_search_tools`,
`gateway_invoke`, `gateway_list_tools`, `gateway_list_servers`
(`:271-275`) — none of which is cut, so the initialize preamble stays correct.
Nothing pins that.

```rust
/// The initialize preamble does not read the gates
/// (`build_discovery_preamble` takes only the exposure filter), so it is
/// correct only as long as it names nothing the gates can withhold. A tool
/// named here but gated off would be announced to every client before any
/// `tools/list` and then be absent from it.
#[test]
fn the_discovery_preamble_never_names_a_cut_tool() {
    let preamble = build_discovery_preamble(42, 3, &MetaToolExposure::from_names(&[]));
    for cut in [
        "gateway_get_stats",
        "gateway_cost_report",
        "gateway_run_playbook",
        "gateway_set_profile",
        "gateway_get_profile",
        "gateway_list_profiles",
    ] {
        assert!(
            !preamble.contains(cut),
            "the preamble reads no gate, so naming {cut} would announce a tool \
             the served list may withhold: {preamble}"
        );
    }
}
```

`MetaToolExposure::from_names(&[])` returns the expose-all filter for an empty
slice, which is the widest input and therefore the strictest test; that branch
is the one `config_default_exposes_every_meta_tool`
(`src/gateway/meta_mcp_tool_defs_tests.rs:632-643`) already exercises.

Result on an unchanged tree: **GREEN**, trivially. Listed because a future
author extending the preamble to name a fifth tool has no other warning.

#### 4.6a The allow-list above is corrected, and the walker root is a defect

The three-entry allow-list this plan first carried was wrong in both
directions, and the error is recorded here rather than silently patched
because it is the kind a reader will otherwise reintroduce.

| Entry | Status | Evidence |
|---|---|---|
| `benchmarks/token_savings.py` | **Stale — removed.** Names no cut tool. It uses `gateway_cost` and `gateway_cost_usd`, which are not `gateway_cost_report`. | `rg -c` over the six names exits 1 |
| `examples/playbook-morning-briefing.yaml` | Real hit, kept | scan |
| `scripts/release/extract-operator-decisions.py` | Real hit, kept | scan |
| `scripts/release/demo/5-error-budget.sh` | **Was missing — added.** Not Rust, not Markdown, so the exclusions never covered it. | `:9`, `:105`, `:106` |
| `docs/release/demo/5-error-budget-transcript.txt` | **Was missing — added.** Same reason. | `:28` |

So the test as first written failed on an unchanged tree for two shipped
artifacts, while carrying a dead entry that would have silently permitted a
future cut-tool reference in the benchmark script.

**The walker root is the more serious of the two.** `WalkDir::new(repo_file("."))`
descends into `.claude/worktrees/`, which holds agent checkouts of this same
repository — four of them at the time of writing, each a full copy carrying its
own hits — and into `.archive/`, which holds a `.patch`. A test whose verdict
depends on which checkouts happen to exist on the machine running it is green
in CI and red on a developer's box, which is the failure mode least likely to
be believed when it appears. Scope the walk to tracked files, or exclude both
directories explicitly.

### 4.6 R3 has no standing check

R3's falsifier is an `rg` the design ran once. Nothing re-runs it. A capability
YAML, skill or shipped script that calls a cut tool by name keeps working
today — that is the design's whole point — but its deployment no longer lists
the tool it depends on, and the operator gets no signal.

```rust
/// R3: a shipped artifact that calls a cut meta-tool by name still works, but
/// its deployment no longer lists the tool it depends on. Scanned rather than
/// reasoned about, because the set of shipped artifacts grows.
///
/// Rust and Markdown are excluded: the test modules and the design documents
/// name all six on purpose. The three known hits are allowed by name, and a
/// fourth is what this test is for.
#[test]
fn no_shipped_artifact_invokes_a_cut_meta_tool_by_name() {
    const CUT: [&str; 6] = [
        "gateway_get_stats",
        "gateway_cost_report",
        "gateway_run_playbook",
        "gateway_set_profile",
        "gateway_get_profile",
        "gateway_list_profiles",
    ];
    // A playbook *definition* (whose deployment turns the playbook gate on), a
    // text scanner over release documents, and the error-budget demo, which
    // calls the stats tool as the subject of the demo rather than as a
    // dependency. Corrected against the tree: see the note below.
    const ALLOWED: [&str; 4] = [
        "examples/playbook-morning-briefing.yaml",
        "scripts/release/extract-operator-decisions.py",
        "scripts/release/demo/5-error-budget.sh",
        "docs/release/demo/5-error-budget-transcript.txt",
    ];

    // Walk the tracked tree only. Rooting at the repo directory descends into
    // agent checkouts under `.claude/worktrees/` and into `.archive/`, which
    // would make the result depend on what happens to be checked out locally.
    let root = repo_file(".");
    for entry in WalkDir::new(&root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        let rel = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .to_string_lossy()
            .into_owned();
        if rel.starts_with("target/")
            || rel.starts_with(".git/")
            || rel.ends_with(".rs")
            || rel.ends_with(".md")
            || ALLOWED.contains(&rel.as_str())
        {
            continue;
        }
        let Ok(contents) = fs::read_to_string(path) else {
            continue;
        };
        for cut in CUT {
            assert!(
                !contents.contains(cut),
                "{rel} names {cut}, which the shipped default no longer lists; \
                 either it is a caller whose gate must be turned on, or add it \
                 to ALLOWED with the reason"
            );
        }
    }
}
```

Compiles today: `WalkDir`, `fs` and `repo_file` are already imported and used
in `tests/public_claims_validation.rs` (`:3`, `:21`, `:60`).

Result on an unchanged tree: **inferred GREEN**, on the design's own R3 run,
which found exactly those three files. This is the most brittle test in the
plan — see §6.

## 5. Design §4 "Blast radius" coverage

### 5.1 Count assertions

Each was a numeric edit. Each now has a test standing over it. Verified by
reading the asserted constant on HEAD.

| §4 site | Design said | On HEAD | Guarded by |
|---|---|---|---|
| `tests/nfr_perf_4_meta_tool_band.rs` `BAND` | not a one-line edit; `9..=17` | `const BAND: std::ops::RangeInclusive<usize> = 9..=17` (`:33`) | the sweep itself, plus §4.2's field guard |
| same file, webhook presence | unchanged | `assert_eq!(names.contains(&"gateway_webhook_status"), webhooks, ...)` (`:188-194`) | itself, inside all 64 combinations |
| `src/gateway/meta_mcp_tool_defs_tests.rs:26` | 13 → 9 | `assert_eq!(tools.len(), 9)` (`:28`) | `build_meta_tools_base_count_without_optional_features` (`:11`) |
| `meta_mcp_tool_defs_tests.rs:601` | 13 → 9 | `assert_eq!(tools.len(), 9)` (`:626`) | the exposure-work regression pin |
| `meta_mcp_helpers_tests.rs:516` | 13 → 9 | `assert_eq!(tools.len(), 9)` (`:528`) | itself |
| `meta_mcp_helpers_tests.rs:551` | 14 → 10 | `assert_eq!(tools.len(), 10)` (`:565`) | itself |
| `meta_mcp_helpers_tests.rs:581` | 14 → 10 | `assert_eq!(tools.len(), 10)` (`:593`) | itself |
| `meta_mcp_helpers_tests.rs:604` | 15 → 11 | `assert_eq!(tools.len(), 11)` (`:615`) | itself |

No new test is proposed for this table. Eight count assertions that agree with
each other and with a 64-combination sweep is enough; a ninth would only
restate the arithmetic.

### 5.2 Name-list fixtures

| §4 site | Design said | On HEAD |
|---|---|---|
| `B10_EXPECTED_TOOLS` | drops five names → 9 | 9 names (`src/gateway/meta_mcp/tests.rs:4720-4730`); the five cut names absent, and `gateway_webhook_status` / `gateway_reload_config` absent because the fixture attaches neither registry |
| `B01_EXPECTED_TOOLS` | same five drop → 11 entries | declared at `src/gateway/meta_mcp/tests.rs:5407` |
| `benchmarks/token_savings.py` `GATEWAY_TOOLS` | six definitions deleted; 17 − 6 = 11 | length-checked against `public_claims.json` by `token_savings_benchmark_tracks_readme_meta_tool_surface` (`tests/public_claims_validation.rs:569`) |

`CEILING` in `src/gateway/meta_mcp/surface_compaction_tests.rs:39-51` is the fourth name list, and
the only one asserted as a *set equality* rather than a subset. That is the
assertion that would fail a deletion, which is why the design's §7 insists the
cut deletes nothing.

### 5.3 The derived constant and its cross-checks

| Claim | On HEAD | Test |
|---|---|---|
| `README_META_TOOLS` 17 → 11 | `pub const README_META_TOOLS: u64 = 11` (`src/honest_task_tokens.rs:24`), and the doc comment above it (`:19`) reads "Eleven, not nine" — the stale-comment defect §5 named did not happen | `honest_model_constants_match_canonical_claims` (`tests/public_claims_validation.rs:467`) |
| `public_claims.json` minimum 9, benchmark 11 | both present, plus `"standing": "admin"` | `canonical_meta_tool_counts_match_live_runtime` (`:336`), which compares a whole `MetaToolClaims` struct against a live derivation (`:114-124`) — including the standing string |
| Both figures measured at admin standing | `handle_tools_list` passes `CallerStanding::Admin` (`src/gateway/meta_mcp/mod.rs:1617`, reasoned at `:1611-1616`) | the standing string is itself derived (`:120`), so editing the file to say "standard" without moving the derivation fails |

### 5.4 §4.1 — the band test loops every gate axis

Requirement met on HEAD: six axes (`tests/nfr_perf_4_meta_tool_band.rs:156-161`),
the `stats` axis re-wired to `with_expose_stats_tool` (`:102`) rather than to
collector attachment, and the `cost_report` axis gated on its `cfg` rather
than dropped (`:79-82`, `:138-141`, `:148-151`). Every wiring the design's
table asked for is present.

The one thing §4.1 asked for that has no enforcement is that the loop stay
complete as `MetaToolGates` grows. §4.2 of this plan is that enforcement.

### 5.5 "Not blast radius" — confirmed still out

`tests/mik_7218_acs.rs` `tools_list_shadow.len() == 16` is a 2^4 telemetry map,
not a tool count; Code Mode's two-tool schema assertions are untouched;
`governed_meta_tool_names` forces every gate on so the allow-list set is
gate-independent (`src/gateway/meta_mcp_tool_defs.rs:838`). No test is proposed
for any of these — a test asserting that something did not change, where
nothing connects the two, is noise.

## 6. Requirement trace R1-R7

Each risk from §2 of this plan, the test that answers it, and whether that
test exists on HEAD or is proposed here.

| Risk | Answered by | Status |
|---|---|---|
| R1 — a cut tool stops being dispatchable | `every_tool_the_cut_stops_listing_is_still_callable_by_name` (`src/gateway/meta_mcp/surface_compaction_tests.rs:123`) | GREEN on HEAD; §4.3 tightens what "callable" means |
| R2 — a new gate field is added and never read | `every_builder_contributes_to_the_governed_set` (`src/gateway/meta_mcp_tool_defs_tests.rs:664`); `MetaToolGates` has no `Default` derive (`meta_mcp_tool_defs.rs:583`), so a new field breaks every literal | GREEN on HEAD; §4.2 extends it from the builder set to the band sweep |
| R3 — prose keeps naming a tool the default no longer lists | §4.6, new | proposed |
| R4 — a published figure drifts from the runtime | `canonical_meta_tool_counts_match_live_runtime` (`tests/public_claims_validation.rs:336`); `public_surfaces_do_not_retain_obsolete_meta_mcp_claims` (`:603`) | GREEN on HEAD for the 11 and the 9; §4.1 adds the stdio 10, which is published and underived |
| R5 — the band is widened instead of the regression being fixed | attainment asserts at `tests/nfr_perf_4_meta_tool_band.rs:205-219` — both ends must be reached by some configuration | GREEN on HEAD; §4.2 arms the tripwire for a 7th gate |
| R6 — a cut tool is reachable only by an error message | §4.3, new | proposed |
| R7 — standing and gating are conflated into one range | settled in prose by design §7, and enforced by the `"standing": "admin"` field inside the derived claims struct | GREEN on HEAD for the standing *string*; the size of `ADMIN_META_TOOLS` is unpinned — see §7 item 6 |

`NFR.PERF.4` itself (`docs/requirements/RELEASE-4.0.0-requirements.md:295`)
now names the admin ceiling explicitly and carries the 11 / 10 figures, so
the requirement text and the band test quantify over the same thing.

## 7. What a reviewer should push back on

Written before any of this ran. Nothing below was cleared by a test run.

1. **§4.4 rests on an unread function.** `routing_content()` was not read.
   The negative half of that test — cut tool names absent from the guide on a
   default deployment — follows from the guide building its set from
   `meta_tools_for`. The positive half assumes the guide names tools at all in
   a form a substring search finds. If the guide describes categories rather
   than tool names, that assertion fails for a reason that is not a defect.
   Read `routing_content()` before writing it.
2. **§4.3 may land red on required arguments.** `gateway_set_profile` and
   `gateway_run_playbook` schemas were not read. Calling them with `{}` to
   prove they dispatch could return an argument error that the test then has
   to distinguish from a routing error. That is listed as work in §4.3, not
   as a guard that passes today.
3. **§4.6 is a brittle repo scan.** Its ALLOWED list is maintenance, and a new
   capability YAML that legitimately names a cut tool fails it. It is a doc
   test wearing a unit test's clothes. Worth keeping only while the published
   numbers are fresh; delete it if it starts costing more than it catches.
4. **§4.2 asserts a compile-time mechanism.** What it really guards is that
   adding a 7th `MetaToolGates` field breaks the build until the sweep covers
   it. That cannot be demonstrated without adding a field and compiling, which
   this plan did not do.
5. **The stdio 10 is arithmetic, not a transport fixture.** §4.1 derives it as
   `readme_benchmark - 1` on the ground that stdio never attaches a webhook
   registry. That is a true statement about `server/mod.rs`, and it is still a
   proxy: nothing here drives a real `run_stdio`. A reviewer who wants the
   figure proven rather than derived should ask for the transport fixture.
6. **Nothing pins `ADMIN_META_TOOLS` at four.** The 11 at the ceiling minus
   the four admin names is the 7 published for the default HTTP deployment.
   Add a fifth admin name and the 7 becomes 6 with no test objecting.
7. **Structured-field divergence in §5.1 is left open.** Eight count
   assertions across three files agree today by arithmetic, not by
   construction. Consolidating them is a refactor this plan did not propose.

## 8. Coupling to the release criterion `NFR.PERF.4`

Raised by the team lead against the pre-implementation tree. Every citation in
the brief was re-checked against HEAD; three of the four points are already
satisfied by the shipped change, and the fourth is a **live defect**.

### 8.1 Which assertion moved, and how each bound derives

The brief expected the band assertion to be the thing this plan schedules. It
already moved: `BAND` is `9..=17` (`tests/nfr_perf_4_meta_tool_band.rs:33`),
and the four-gate sweep the brief describes is now six
(`Gates`, `:75-85`). The brief's `:60` for the test function is `:154` on HEAD.

Each bound, derived rather than observed — the R5 vacuity answer:

| Bound | Derivation | Enforced by |
|---|---|---|
| Floor 9 | `build_meta_tools` with every gate off returns 9, asserted directly (`meta_mcp_tool_defs_tests.rs:11`, `:28`). The old floor of 14 rested on `cost_report` being hardcoded `true` on the served path; the compaction re-sourced that gate to registry attachment, so the hardcode that lifted the floor is gone | `assert_eq!(seen.iter().min(), Some(*BAND.start()))` (`:205-209`) — some configuration must *reach* the floor |
| Ceiling 17 | Unchanged by the cut: every gate on is the pre-compaction surface. `webhooks.enabled` defaults true (`src/config/features/webhooks.rs`), so an HTTP deployment reaching it is shipped, not exotic | `ATTAINABLE_CEILING` (`:148-151`), which steps to 16 where `cost-governance` is compiled out, so the assert fails for a regression rather than for a build configuration |
| 11 at the admin ceiling | `CEILING` names the eleven and the test asserts set equality, not a count (`src/gateway/meta_mcp/surface_compaction_tests.rs:39-51`) | `shipped_default_gate_configuration_lists_eleven_to_an_admin_caller` (`:98`) |
| 10 over stdio | `run_stdio` never calls `set_webhook_registry`, so stdio is the ceiling minus that one name | **Nothing.** This is the §4.1 gap, and §7 item 5 is honest that the proposed fix derives it arithmetically rather than through a transport fixture |
| 7 at the shipped HTTP default | 11 minus the four `ADMIN_META_TOOLS` names | **Nothing pins the four.** §7 item 6 |

### 8.2 The criterion text did not move with the test — open defect

The brief's point 2 is the right worry and it already happened.

- `docs/requirements/RELEASE-4.0.0-requirements.md:295` **moved**: it states 9-17 at admin standing, names all six gated tools, and publishes 11 / 10.
- `docs/requirements/RELEASE-4.0.0-criteria-status.md:418` **did not**. It still reads "Meta-MCP surface remains 14-17 tools", still grades `MET`, and every citation inside it describes the pre-compaction tree: the test at `:60` (now `:154`), "the four gates" (now six), the floor derived from a hardcoded `cost_report_enabled` (re-sourced), `readme_benchmark` 17 (the file says 11), `README_META_TOOLS` at `honest_task_tokens.rs:20` (now `:24`, value 11), the live cross-check at `public_claims_validation.rs:257` (now `:336`), and the governance pins at `meta_mcp_tool_defs_tests.rs:496,509` (now `:651`, `:664`).

So a criterion graded `MET` asserts a band that the code it cites no longer
holds to, and a reader checking the grade lands on line numbers that moved.
Nine is outside `14..=17`: the row is not merely stale, it is **wrong in the
direction that matters**, because it would grade the shipped floor as a
violation.

Why no test caught it: `public_surfaces_do_not_retain_obsolete_meta_mcp_claims`
scans `PUBLIC_CLAIM_SURFACES` (`tests/public_claims_validation.rs:147-159`),
which lists README, BENCHMARKS, QUICKSTART, ARCHITECTURE and the binaries —
**no file under `docs/requirements/`** — and `BANNED_PUBLIC_PHRASES` (`:175`)
has no entry for the old band.

This is a fix, not a test-plan item. The test seam below is what keeps it
fixed; the row itself has to be rewritten by whoever owns the grade.

### 8.3 New test — §4.7, the criterion row states the live band

**Name.** `release_criterion_states_the_band_the_band_test_enforces`
**Where.** `tests/public_claims_validation.rs`, beside the other surface scans.
**Asserts.** Read `docs/requirements/RELEASE-4.0.0-criteria-status.md`, take
the `NFR.PERF.4` row, and require it to contain the band rendered from the
same source the band test uses. Adding the file to `PUBLIC_CLAIM_SURFACES`
instead was considered and rejected: that row legitimately narrates the
2026-09-02 and 2026-09-08 history, so a banned-phrase scan over the whole file
fails on correct prose about the past.

**Cost.** The band constant lives in a `tests/` binary, so it is not importable
from another integration test. Either it moves to the library beside
`README_META_TOOLS`, or the new test re-derives the floor and ceiling the way
`live_meta_tool_counts` already does (`tests/public_claims_validation.rs:114-124`).
The second needs no production change and is the lazier of the two.

**Compiles today.** Yes, on the re-derivation route.

### 8.4 Governance is separate from enumeration, and did not narrow

The brief's point 4. Verified: `governed_meta_tool_names()` builds its set from
`build_meta_tools` with **all six gates forced on**, chained with
`build_code_mode_tools()` (`src/gateway/meta_mcp_tool_defs.rs:838-865`), with
the comment stating that membership follows what is *callable*, never what any
deployment lists.

So every cut tool lands in the same state, and it is the state the brief asks
the plan to name:

| State | Which tools | Consequence |
|---|---|---|
| Enumerated, governed | the eleven in `CEILING` | listed and allow-list-checked |
| **Not enumerated by default, still governed** | all six cut tools, plus `gateway_webhook_status` off the HTTP path | dispatchable by name; an operator allow-list that omits the name still blocks it |
| Ungoverned | none | `is_exposed` admits anything ungoverned, which is the escape hatch the forced-on set exists to close |

No cut tool moved to "gone", and none moved to "ungoverned". The two pins the
brief names are on HEAD at `meta_mcp_tool_defs_tests.rs:651` and `:664` —
renumbered from the brief's `:496,509`, unchanged in substance.

### 8.5 The published-claims chain, as its own row

The brief's point 3. Already covered by §5.3; restated here as the scope row
it asked for, with HEAD line numbers rather than the brief's:

| Link | HEAD | Moves with the band? |
|---|---|---|
| `benchmarks/public_claims.json` | `{"standing":"admin","minimum":9,"readme_benchmark":11}` | Yes — already 11, not 17 |
| `src/honest_task_tokens.rs:24` | `README_META_TOOLS = 11` | Yes |
| `tests/public_claims_validation.rs:336` | `canonical_meta_tool_counts_match_live_runtime`, comparing the whole struct against a live `MetaMcp` | Yes, and it pins the `"admin"` standing string too |
| `benchmarks/token_savings.py` `GATEWAY_TOOLS` | 11 entries | Yes, via `:569` |
| `docs/requirements/RELEASE-4.0.0-criteria-status.md:418` | **17, stale** | **No — §8.2** |

### 8.6 Q4 still scopes out, and the compaction narrowed it

The brief asks whether the `surfaced_tools` / spec-preview scoping survives.
It does, and it got stronger rather than weaker: the band governs the
meta-tool population, a surfaced backend tool is not one, and `surfaced_tools`
defaults empty. The compaction lowered the meta-tool floor without touching
that boundary, so the headroom between the enumerated meta surface and any
configured surfaced list *grew* by six.

One honest caveat for a reviewer: the band test measures through
`handle_tools_list`, which the module doc says appends surfaced tools. The
sweep attaches no surfaced tools, so it never exercises the appended path.
Q4 remains scoped out of the criterion — and the test that enforces the
criterion would not notice if it stopped being.

---

## 6. Review round two

One seat returned `SHIP-WITH-FIXES` with four findings, all rated MEDIUM. The
other seat produced no verdict on three consecutive attempts, so this plan
carries **one** recorded review verdict, not two. Each finding below was
re-checked at source before being accepted; none was taken on the reviewer's
word.

### 6.1 The band's upper end can be widened for free — CONFIRMED

`nfr_perf_4_1_every_feature_combination_serves_a_surface_inside_the_band`
makes three assertions. Two reference `BAND`; the decisive one does not.

| Assertion | Anchored to | Survives `BAND` widened to `9..=18`? |
|---|---|---|
| `seen.iter().min() == Some(*BAND.start())` | `BAND` | No — this one is genuinely pinned |
| `BAND.contains(&ATTAINABLE_CEILING)` | `BAND`, but only as containment | Yes — `9..=18` contains 17 |
| `seen.iter().max() == Some(ATTAINABLE_CEILING)` | the constant, **not** `BAND` | Yes — still 17 |

So the floor is pinned and the ceiling is not. Widening the published band by
one at the top passes the suite untouched, which is precisely the drift this
criterion exists to catch.

The test is not careless about it. `nfr_perf_4_meta_tool_band.rs:145-147`
states the reason in a comment: asserting against `BAND.end()` in a build that
compiled the cost tool out would fail for the *configuration* rather than for
a regression. That reasoning is sound and the fix must preserve it.

**Fix:** under `cost-governance` — which is in `default` (`Cargo.toml:179`), so
the repo's own `cargo test` runs it — require `ATTAINABLE_CEILING ==
*BAND.end()`. Keep the existing containment form for builds without the
feature. The published ceiling then cannot move without the test moving.

### 6.2 The remaining three findings

| # | Where | Finding | Fix |
|---|---|---|---|
| 1 | `:331` | The dispatch tightening requires success from tools whose default fixtures cannot succeed, even given valid arguments. An implementer meets failures that are not dispatch regressions. | Require a decoded stats payload for R6, supply sessions for the profile calls, and assert the specific configuration error for an unavailable profile or playbook rather than success. |
| 2 | `:177` | The published-number checks can pass while the prose they protect is wrong. | Compare the actual HTTP and stdio claim values in both documents against measured counts, and read the criterion's current requirement cell rather than searching its historical narrative for a band that matches. |
| 3 | `:243` | Exhaustively destructuring `MetaToolGates` proves the unit fixture is complete, not that the integration sweep is. Updating one can leave an axis of the other untested. | Share one exhaustive gate matrix between the coverage guard and the served-path sweep, so satisfying the guard cannot be done by touching an unrelated pattern. |

Finding 2 is the sharper restatement of a round-one observation that the
published-number checks were loosely coupled to the claims they protect. It is
the same defect class as §6.1: a check anchored to something other than the
thing it is meant to hold still.

### 6.3 One claim withdrawn

The plan asserted at `:705` that a fifth admin-only tool would escape the
existing tests. It would not — the existing Standard-caller test already
asserts the benchmark count minus four. The claim is withdrawn and no test is
owed for it.

### 6.4 Where this leaves the plan

Recorded verdict: **SHIP-WITH-FIXES**, one seat. The four findings are
specified above but **not yet written into the cases they correct**; §6 is the
work list for the next revision, not a record that the work is done. No
implementation has started.
