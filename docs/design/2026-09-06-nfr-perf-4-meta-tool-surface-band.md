<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# NFR.PERF.4 — holding the Meta-MCP surface inside 14..=16

Status: proposed, awaiting dual review. No code written.

## 1. Problem, measured

`NFR.PERF.4` requires the Meta-MCP surface to stay within **14..=16** tools. The
shipped surface is a band of **13..=17** and nothing clamps either end.

| fact | evidence |
|---|---|
| 13 tools with all four flag gates off | `src/gateway/meta_mcp_tool_defs_tests.rs:16-17`, asserts `== 13` |
| four independent flag gates | `src/gateway/meta_mcp_tool_defs.rs:544-573` — `stats_enabled`, `cost_report_enabled`, `webhooks_enabled`, `reload_enabled` |
| webhooks default on | `src/config/features/webhooks.rs:28-36`, `enabled: true` |
| claimed band | `benchmarks/public_claims.json:4-6` — `minimum: 14`, `readme_benchmark: 16`, `with_webhook_status: 17` |

Two consequences the earlier diagnosis missed:

- **`gateway_webhook_status` is the 14th tool, not the 17th.** It is on by default, so
  it is exactly the tool the `minimum: 14` claim counts. The 2026-09-02 prescription —
  remove it — would have dropped the default floor to 13, breaking the floor claim while
  leaving the ceiling reachable.
- **The band is violated at both ends.** 13 when an operator disables webhooks; 17 when
  all four gates are on. A ceiling-only fix leaves the criterion false.

## 2. Constraint every option must satisfy

A floor of 14 over 13 base tools means **at least one non-base tool must be
unconditional**. A ceiling of 16 means **at most two more may be conditional**. So any
solution reduces four independent gates to at most two and makes at least one of the
removed ones unconditional. That is arithmetic, not preference, and it rules out every
option that edits only the ceiling.

## 3. Options

| # | option | floor | ceiling | verdict |
|---|---|---|---|---|
| a | clamp the count at startup, error outside the band | 13 | 17 | **rejected** — turns a configuration an operator is entitled to set into a startup failure, and does not change the surface |
| b | exclude flag-gated tools from "the counted surface" | 13 | 17 | **rejected** — the count stops describing what the client sees. That drift is precisely what `public_claims.json` and its CI check exist to catch |
| c | widen the requirement to 13..=17 | — | — | **rejected** — reverses the operator ruling of 2026-09-02 and raises the ceiling to match whatever shipped |
| d | fold the three status/report tools into one unconditional `gateway_status` with a `scope` argument; leave `reload_config` gated | 14 | 15 | **selected** |

## 4. Selected: fold the status surface

`gateway_get_stats`, `gateway_cost_report` and `gateway_webhook_status` are three
read-only status queries over three registries. They differ in which registry they read,
which is an argument, not a tool.

```
13 base
+ 1 gateway_status            (unconditional)
+ 1 gateway_reload_config     (reload_enabled)
= 14..=15
```

`14..=15` sits inside `14..=16` with one tool of headroom, so the next unconditional
meta-tool does not immediately re-break the criterion.

`scope` is an enum, not a bool — `stats | cost | webhooks` — per the boolean-trap rule in
the codegen-craft block. A scope whose feature is disabled is refused with a typed error
naming the disabled feature, so an operator can tell "not built" from "no data".

Why this is an elimination rather than a patch: afterwards the finding "the surface can
leave 14..=16" cannot be restated — no configuration produces 13 or 17. Clamping or
reclassifying leaves the defect describable and merely unreachable.

## 5. Out of scope

- The README badge and the prose around the token-savings headline.
- **Correction, after answering question 2 (see 6.2): the `readme_benchmark` figure is NOT
  separable and is IN scope.** `tests/public_claims_validation.rs:269` asserts
  `readme_token_savings.gateway_tools == meta_tools.readme_benchmark`, so changing the surface
  count necessarily changes the token-savings denominator in the same commit. The first draft
  of this section put it out of scope; that was wrong.
- Any change to the 13 base tools.
- `gateway_reload_capabilities`, already unconditional and inside the base count.

## 6. Open questions — scheduled, not assumed

| # | question | form | state |
|---|---|---|---|
| 1 | Do any published clients call `gateway_get_stats` / `gateway_cost_report` / `gateway_webhook_status` by name? | checkable — searched the repo, the capability catalogue and the docs | **resolved**, see 6.1 |
| 2 | Is the 16 in `readme_benchmark` a measured scenario or a target? | checkable — read `tests/public_claims_validation.rs` | **resolved**, see 6.2 |
| 3 | Does the operator accept a breaking rename of three meta-tools in 4.0.0, or must the old names alias for one release? | askable — operator | **open**, blocks implementation |

### 6.1 Answer to question 1

Searched every tracked file for the three names (`rg --hidden --no-ignore`, `target/` excluded):
21 files name `gateway_get_stats`, 14 name `gateway_cost_report`, 18 name `gateway_webhook_status`.
**No published client and no capability definition is among them, and `README.md` names none of
the three.** So the rename is not externally breaking, and `src/commands/upgrade.rs` — whose
migration framework only handles configuration keys, with no tool-rename precedent — does not
need a new migration.

It is, however, load-bearing in three in-tree places the design did not list, all of which must
change in the same PR:

| site | what it is | consequence if missed |
|---|---|---|
| `src/gateway/meta_mcp/resources.rs:117,121` | model-facing guidance shipped as an MCP resource, telling the model to call `gateway_cost_report()` and `gateway_get_stats()` | the gateway would instruct the model to call tools that no longer exist — the closest thing to a published client this change has |
| `src/commands/stats.rs:51` | CLI JSON output with a literal `"name": "gateway_get_stats"` field | an operator's parser sees a name the surface no longer offers |
| `src/gateway/destructive_confirmation.rs:336` | test asserting `gateway_get_stats` is **not** destructive | the fold must carry the non-destructive classification to `gateway_status`, or a read-only query starts demanding confirmation |

The third is the one worth stating as a requirement rather than a chore: `gateway_status` is
read-only for every `scope`, so it must be classified non-destructive, and the test that pins
that must name the new tool.

### 6.2 Answer to question 2

**Measured, not a target.** `tests/public_claims_validation.rs:105-106` computes both figures at
test time and asserts them against the JSON: `minimum` from a bare `MetaMcp::new(...)`,
`readme_benchmark` from `operational_meta_mcp(false)`. The JSON is a pinned expectation of a
measurement, so it moves whenever the surface does — it cannot be left alone.

The same file couples the surface count to the headline savings claim:

| line | assertion | consequence for this design |
|---|---|---|
| `:265` | the measured triple equals `claims.meta_tools` | all three of `minimum` / `readme_benchmark` / `with_webhook_status` must be restated |
| `:269` | `readme_token_savings.gateway_tools == meta_tools.readme_benchmark` | the token-savings denominator is pinned to the surface count and changes with it |
| `:359` | a `README_META_TOOLS` constant equals that same denominator | a third spelling of the same number, also to be updated |

So the fold moves the savings arithmetic: the denominator goes 16 -> 15, which *raises* the
computed saving rather than lowering it (fewer gateway tokens against the same 100-tool
baseline). That is a claim moving in our favour, which is exactly the direction that most needs
stating out loud rather than being allowed to drift upward unremarked.

Consequence for the plan: `NFR.PERF.4.4` is not an afterthought CI check, it is the case that
fails first, and the claims update ships in the same commit as the fold.

Question 3 is load-bearing: an alias period keeps the old names in the surface and puts
the count straight back to 17, defeating the design. Nothing is implemented until it is
answered.

## 7. Test obligations (plan, not tests)

| AC | case | level |
|---|---|---|
| NFR.PERF.4.1 | every combination of the remaining gates yields a count in `14..=16` | unit, exhaustive over the gate powerset |
| NFR.PERF.4.2 | `gateway_status` is present with all gates off | unit |
| NFR.PERF.4.3 | a `scope` whose feature is disabled returns the typed refusal, not an empty success | unit |
| NFR.PERF.4.4 | `public_claims.json` agrees with the measured band | CI drift check |

NFR.PERF.4.1 is the case that makes the criterion decidable: it can fail, and today it
fails at both ends.
