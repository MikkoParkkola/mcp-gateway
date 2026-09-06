<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# NFR.PERF.4 — holding the Meta-MCP surface inside 14..=16

Status: **revision 2**, awaiting dual review. Revision 1's selected option is
WITHDRAWN — see §0. No code written.

## 0. What revision 1 got wrong

Revision 1 selected a three-tool breaking fold. Dual review returned
DO-NOT-SHIP with two HIGH findings, both verified at source against clean HEAD
`5d359559` before being accepted:

| # | finding | verified at |
|---|---|---|
| 1 | Supported configurations serve fewer than 14 tools, so "every configuration lands in 14..=16" is unachievable by any rearrangement of the surface | `src/gateway/meta_mcp/mod.rs:1265` (Code Mode serves 2), `:1297` and `:1307` (`meta_tool_exposure.filter` applies to both branches) |
| 2 | The 13-tool floor was read from a builder combination the served path never produces | `src/gateway/meta_mcp/mod.rs:1304`, verbatim: `true, // cost_report always enabled (tracker is always present)` |

Finding 2 inverts the diagnosis. The served floor is **14**, not 13, so the
constraint revision 1 derived — "at least one non-base tool must become
unconditional" — was already satisfied before the change. Only the ceiling is
out of band. That makes the three-tool fold a breaking rename bought for
nothing, and it is withdrawn rather than patched: the finding it answered does
not exist.

It also falsifies revision 1's own correction of the operator. Revision 1
claimed removing `gateway_webhook_status` would drop the floor to 13 and break
the `minimum: 14` claim. It would not — the floor is held by
`gateway_cost_report`, unconditionally. **The 2026-09-02 prescription was
correct as given.**

## 1. Problem, measured

| fact | evidence |
|---|---|
| `cost_report` is unconditional on every served list | `src/gateway/meta_mcp/mod.rs:1304` |
| three conditional tools remain: stats, webhooks, reload | `src/gateway/meta_mcp/mod.rs:1301-1303` |
| 13 base tools with all four builder flags off | `src/gateway/meta_mcp_tool_defs_tests.rs:16-17` — a builder-level assertion, NOT a served surface |
| webhooks default on | `src/config/features/webhooks.rs:28-36`, `enabled: true` |
| claimed band | `benchmarks/public_claims.json:4-6` — `minimum: 14`, `readme_benchmark: 16`, `with_webhook_status: 17` |

Served band today: **14..=17**. `13 base + cost_report` = 14 floor; all three
conditionals on = 17 ceiling. The criterion is violated at the ceiling only.

## 2. Constraint

14 floor with 13 base and one unconditional extra is fixed. A ceiling of 16
permits **at most two conditional tools** in the all-enabled enumeration.
There are three. So at least one conditional entry must be absent from that
enumeration. Which entry, and whether it is deleted or merged into another, is
the selection in section 3 — the arithmetic forces the count, not the choice.

## 3. Options

| # | option | band after | verdict |
|---|---|---|---|
| a | clamp the count at startup, error outside the band | 14..=17 | **rejected** — turns a configuration an operator may set into a startup failure and does not change the surface |
| b | exclude gated tools from "the counted surface" | 14..=17 | **rejected** — the count stops describing what the client sees, which is the drift `public_claims.json` exists to catch |
| c | widen the requirement to 14..=17 | — | **rejected** — reverses the 2026-09-02 ruling |
| d | fold three status tools into one `gateway_status(scope)` | 14..=15 | **withdrawn** — see §0; answers a floor problem that does not exist, at the cost of three breaking renames |
| e | remove `gateway_webhook_status` from the enumeration | 14..=16 | **selected** |

## 4. Selected: remove `gateway_webhook_status`

```
13 base
+ 1 gateway_cost_report   (unconditional today)
+ 1 gateway_get_stats     (stats_enabled)
+ 1 gateway_reload_config (reload_enabled)
= 14..=16
```

This is the 2026-09-02 prescription, unmodified. It matches
`public_claims.json` exactly: `minimum: 14` is the floor, `readme_benchmark: 16`
is the ceiling, and `with_webhook_status: 17` is the row that goes away.

Why elimination rather than a patch: afterwards "the unfiltered surface can
leave 14..=16" cannot be restated — no combination of the remaining gates
produces 17. Clamping or reclassifying leaves the defect describable and merely
unreachable.

One tool changes, not three. Nothing is renamed, so no client contract moves.

### 4.1 Deleting the entry alone is a security regression

Review finding, verified at source. `MetaToolExposure::is_exposed`
(`src/gateway/meta_mcp_tool_defs.rs:823`) reads:

```rust
Some(allowed) => allowed.contains(name) || !governed_meta_tool_names().contains(name),
```

`governed_meta_tool_names()` is **derived from the builder** with all flags on.
The right-hand disjunct therefore fails open for any name outside that set, and
the same predicate gates `tools/call` as well as `tools/list`. Removing
`gateway_webhook_status` from the builder drops it out of the governed set, so
`is_exposed` begins returning `true` for it under *every* operator allow-list —
while the dispatch arm at `src/gateway/meta_mcp/invoke.rs:2879` still serves
endpoint paths and delivery counts.

A change made to shrink the surface would widen what a restricted client can
reach. The comment at `meta_mcp_tool_defs.rs:747` records this same escape
hatch being closed once already for Code Mode's `gateway_execute`; this design
would reopen it under a different name.

Binding consequence: **the enumeration entry and its dispatch arm leave
together**, so the name becomes unrecognised rather than merely unlisted. Any
resolution of question 5 that keeps the handler alive must instead keep the
name in the governed set. NFR.PERF.4.6 pins the property either way.

## 5. Out of scope

- The README badge and the prose around the token-savings headline.
- Any change to the 13 base tools, or to `gateway_reload_capabilities`
  (already unconditional and inside the base count).
- The `handle_tools_list` filtering machinery itself (`meta_tool_exposure`,
  Code Mode). Question 4 decides whether it is in scope at all; until it is
  answered nothing here touches it.
- **In scope, contrary to the first draft:** the benchmark figures.
  `tests/public_claims_validation.rs:269` asserts
  `readme_token_savings.gateway_tools == meta_tools.readme_benchmark`, so the
  surface count and the savings denominator move together and ship in one
  commit. Under option (e) `minimum` and `readme_benchmark` are unchanged and
  the `with_webhook_status: 17` row is deleted — a smaller claims delta than
  revision 1, which moved all three.

## 6. Open questions — scheduled, not assumed

| # | question | form | state |
|---|---|---|---|
| 1 | Do published clients call `gateway_webhook_status` by name? | checkable | **resolved**, see 6.1 |
| 2 | Is `readme_benchmark: 16` measured or a target? | checkable | **resolved**, see 6.2 |
| 4 | Does the 14..=16 band govern only the unfiltered traditional surface, or every served list including Code Mode and `exposed_meta_tools`? | askable — operator | **open**, blocks the acceptance criterion's wording, not the implementation |
| 5 | When the tool goes, where does webhook status become observable? | askable — operator | **open**, blocks implementation |

### 6.1 Answer to question 1

18 tracked files name `gateway_webhook_status`; none is a published client, a
capability definition, or `README.md`. Removal is not externally breaking, and
`src/commands/upgrade.rs` — whose migration framework handles configuration
keys only — needs no new migration.

`src/gateway/meta_mcp/resources.rs` — model-facing guidance shipped as an MCP
resource, and the closest thing to a published client this change has — names
`gateway_cost_report` and `gateway_get_stats` but **not**
`gateway_webhook_status`. Verified, not assumed: that file was the single site
that would have made revision 1's fold user-visible, and option (e) does not
touch it. NFR.PERF.4.4 pins the property rather than the current absence, so a
later addition cannot reintroduce the hazard silently.

### 6.2 Answer to question 2

**Measured, not a target.** `tests/public_claims_validation.rs:105-106`
computes the figures at test time from `MetaMcp::new(...)` and
`operational_meta_mcp(false)` and asserts them against the JSON. The JSON is a
pinned expectation of a measurement, so it moves whenever the surface does.
`:265`, `:269` and `:359` spell the same number three ways; all three are
checked by CI.

### 6.3 Questions 4 and 5 are deferred, and both block

An earlier draft argued implementation could proceed with question 4 open.
Both reviewers rejected that, correctly: if the band governs every served
list, the frozen scope — which puts the filtering machinery out — *cannot*
satisfy the criterion, and the change would be built against an acceptance
criterion its own scope forecloses. A residual-risk paragraph is not a
resolution.

Both unknowns therefore carry the four deferral fields, and nothing depending
on them is implemented:

| field | Q4 — which surfaces the band governs | Q5 — where webhook status goes |
|---|---|---|
| owner | operator | operator |
| what resolves it | a ruling on whether Code Mode and `exposed_meta_tools` surfaces are in the acceptance population | a ruling among fold into `gateway_get_stats`, a new CLI subcommand, or removal with no replacement |
| when | before implementation; asked 2026-09-06, unanswered | before implementation; asked 2026-09-06, unanswered |
| if it resolves badly | "every served list" makes the criterion unsatisfiable inside the frozen scope — §P0 reopens and option (e) is insufficient, not merely incomplete | "no replacement" makes this a breaking capability removal under DoR C5, needing recorded approval rather than an inference from a repository search |

Q5's fallback is the sharper one. Section 6.1 establishes that removal is not
breaking *as a name*; it does not establish that removing the only path to a
diagnostic is non-breaking *as a capability*. The first draft ran those two
claims together.

**NFR.PERF.4 is blocked on the operator.** No code is written until both
rulings land.

## 7. Assumptions and reversibility (DoR G10, G17)

| # | assumption | impact if wrong | uncertainty | check |
|---|---|---|---|---|
| 1 | no consumer outside the tree calls `gateway_webhook_status` | a client breaks silently | low | 6.1, done |
| 2 | webhook status has another observable path, or none is required | operators lose a diagnostic | **high** | question 5, open |
| 3 | tool count is an adequate proxy for context cost | the band passes while tokens rise | medium | NFR.PERF.4.5 below |

Reversibility: **two-way door.** Re-adding a tool definition behind its
existing `webhooks_enabled` gate restores the prior surface and moves the
claims figures back. No data migration, no persisted state, no renamed
contract. No ADR required.

## 8. Test obligations (plan, not tests)

| AC | case | level |
|---|---|---|
| NFR.PERF.4.1 | every combination of the remaining gates yields a served count in `14..=16` | unit, exhaustive over the gate powerset |
| NFR.PERF.4.2 | the count is measured through `handle_tools_list`, not by re-deriving builder arithmetic | unit |
| NFR.PERF.4.3 | `public_claims.json` agrees with the measured band and no longer carries `with_webhook_status` | CI drift check |
| NFR.PERF.4.4 | no model-facing resource text names the removed tool | unit |
| NFR.PERF.4.5 | serialized schema token count of the surface does not rise, measured with the serializer and tokenizer pinned in the test, against the pre-change surface as baseline | bench assertion |
| NFR.PERF.4.6 | an operator allow-list omitting the removed name **refuses a direct `tools/call`** to it — absence from `tools/list` is not sufficient | unit, the §4.1 regression |

NFR.PERF.4.1 is the case that makes the criterion decidable: it can fail, and
today it fails at the ceiling. NFR.PERF.4.2 exists because revision 1's whole
error was trusting a builder-level count that the served path contradicts —
`tests/public_claims_validation.rs:103` duplicates that arithmetic and is the
line that let a 13 through. NFR.PERF.4.5 answers the review's improvement note:
a count can satisfy the band while the surface costs more context.
