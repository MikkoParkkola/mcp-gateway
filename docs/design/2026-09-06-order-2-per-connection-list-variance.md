# ORDER.2 — list results must not vary per connection, nor as a side effect

MIK-7272.ORDER.2a, MIK-7272.ORDER.2b. Design only. No code, no tests.

## What this note is, and is not

This is a **delta** on `docs/design/2026-08-31-cluster-b-connection-invariance.md`
(Part I of that note *is* ORDER.2) and its sibling test plan. It does not restate
the option analysis, the blast radius, or the cases already written there. It
records two things that note could not: that the profile leg has since been
**closed in code**, and that the one remaining leg is the `spec-preview`
promotion store, which cluster-b classified in its §I.2 and explicitly left to
"whichever ORDER.2 option is chosen".

## §P0 SCOPE

**FOR:** deciding what remains to be done so that `tools/list` results neither
vary per connection (2a) nor vary as a side effect of other requests on the same
connection (2b), on a connection declaring MCP 2026-07-28.

**OUT:**
- Legacy (pre-2026-07-28) connections. The criterion is about the modern era;
  legacy sessions keep per-session profiles by design.
- Whether the `spec-preview` promotion feature should exist at all
  (cluster-b left this open; it is still not this note's question).
- Backend cache hot-reload / `tools/list_changed`, deferred by cluster-b Part III
  item 1 and unchanged here.
- Variation by **authorization**, which the criterion explicitly permits.
- stdio and A2A transport parity (cluster-g owns it; see §4).

## 1. The audit premise is stale — measured at source

The ORDER.2 audit row states the guard is absent and cites `surfaced.rs:106-108`
and `mod.rs:944-954`. Both line references have drifted, and the behavioural
claim is false as of 682a709a. A guard exists and it names ORDER.2 as its reason.

| # | fact | source |
|---|---|---|
| 1 | A request declaring the modern era by header gets **no session and none is minted**: `session_id` is the empty string. | `src/gateway/router/handlers.rs:574-589` |
| 2 | `fn session_key(session_id: Option<&str>) -> Option<&str>` filters the empty string to `None`. Its doc comment states the ORDER.2 rationale verbatim: "the empty key is shared by *every* sessionless caller, so a profile stored under it does not merely vary the tool set per connection, it varies it across connections." | `src/gateway/meta_mcp/mod.rs:1075-1090` |
| 3 | `active_profile` routes through `session_key`, so a sessionless caller resolves to the registry **default** profile. | `mod.rs:1062-1072` |
| 4 | `gateway_set_profile` and `gateway_get_profile` both **refuse** on a sessionless caller with `NO_SESSION_FOR_PROFILE`. | `mod.rs:1725-1728`, `mod.rs:1737-1739`; const at `mod.rs:1096-1099` |
| 5 | The `X-MCP-Profile` initialize-time binding is gated by the same `session_key`. | `mod.rs:1186` |
| 6 | `resolve_surfaced_tool` filters every surfaced tool through `active_profile` first, so the whole surfaced-tool leg inherits (3). | `src/gateway/meta_mcp/surfaced.rs:101-115` |

**Consequence:** the routing-profile leg of ORDER.2 is closed, and it is closed
in the shape of cluster-b's **option (b)** (profiles do not exist in modern mode),
not the option (a) that note recommended. The mechanism is elimination, not a
check: with no non-empty key there is no per-connection profile state to vary.

## 2. What remains: the spec-preview promotion store

`spec-preview` dynamic promotion (SEP-1862) is the one list-shaping input that
does **not** pass through `session_key`.

| # | fact | source |
|---|---|---|
| 7 | After a successful `gateway_invoke`, the tool is promoted for the session: `if let Some(sid) = session_id { self.promote_tool_for_session(sid, &tool_key); }`. `Some("")` satisfies this. | `src/gateway/meta_mcp/invoke.rs:1826-1828` |
| 8 | `promote_tool_for_session` writes `session_promoted.entry(session_id.to_string()).or_default()`. The empty string is a valid `DashMap` key. | `src/gateway/meta_mcp/spec_preview.rs:228-245`; store at `mod.rs:312`, init `mod.rs:467`, cleared `mod.rs:1048-1049` |
| 9 | `promoted_tools_for_session(session_id)` reads the raw id, no `session_key`. | `mod.rs:1021-1030` |
| 10 | The router passes `Some(session_id.as_str())` on both the list and the call path, i.e. `Some("")` for a modern connection. | `handlers.rs:971` (`tools/list`), `handlers.rs:1162` (`tools/call`) |
| 11 | Promoted tools are appended to the assembled list inside `handle_tools_list_for_session`, immediately after the surfaced-tool loop. | `mod.rs:1284-1330`, surfaced loop at `mod.rs:1310` |

**Both clauses fail on this leg.** 2b: a successful `gateway_invoke` changes the
next `tools/list` on the same connection. 2a: because the key is `""` and every
sessionless modern caller shares it, the change is visible to *other*
connections too — a strictly worse failure than the one the criterion names.

**Materiality, stated honestly.** `spec-preview` is not in the default feature
set: `Cargo.toml:179` lists `default = ["a2a","webui","config-export",
"cost-governance","firewall","discovery","semantic-search","tool-profiles",
"metrics"]`, and `Cargo.toml:193` declares `spec-preview = []`. A default build
does not compile this path. It is a real defect in the builds that enable the
feature, and the feature is the one this whole protocol effort exists to
prepare. This is a severity input for the requester (§6), not a reason to leave
it.

**Not a discovery.** cluster-b's test plan already specifies this case as
**B-07** ("a promoted tool must not appear in session A's modern list, nor make
it differ from B") and **B-06** (B-01 re-run under `--features spec-preview`).
What is new here is the measurement that the production path is still open and
that the profile leg around it has closed, which changes which option is cheap.

## 2b. A second store with the same defect — the FSM workflow state

Review found a second store keyed by the raw session id. It is the same defect
as §2, in a different place, and unlike §2 it is in the **default build**.

| # | fact | source |
|---|---|---|
| 12 | `gateway_set_state` guards with `let Some(sid) = session_id else { ... }`, **not** with `session_key`. `Some("")` passes, and the FSM workflow state is written under the empty key. | `src/gateway/meta_mcp/mod.rs:1688-1696` |
| 13 | `current_search_state` reads it the same way: `session_id.map_or_else(|| DEFAULT_STATE, |sid| self.session_state.get_state(sid))`. `Some("")` reads the shared entry rather than falling back to the default. | `src/gateway/meta_mcp/search.rs:161-165` |
| 14 | That state filters the tools returned by the discovery surface: `search_tools` and the code-mode search both derive `current_state` from it, and the capability branch returns `cap.get_tools_for_state(&current_state)`. | `search.rs:378`, `search.rs:586`, `search.rs:653`, `search.rs:730` |
| 15 | The store is `session_state: SessionStateStore` at `mod.rs:319`, initialised at `mod.rs:468`. Nothing in it is feature-gated. | `mod.rs:319,468` |

So on a modern connection, `gateway_set_state` mutates state under the key `""`,
and every subsequent `gateway_search` / capability tool listing on **every**
sessionless modern connection sees the changed tool set. Mechanically identical
to §2; materially worse, because it ships by default.

**What it does not touch.** `handle_tools_list_for_session` does not consult
`session_state`; the filtering is confined to the discovery surface. Whether the
discovery surface's output is a "list result" for the purposes of ORDER.2 is a
question for the requester (Q3, §6) — but the defect is the same shared key, and
recommendation (c) closes it with the same one-line change applied at
`mod.rs:1689` and `search.rs:163`. No separate option analysis is needed.

**Provenance.** This was not in the first draft of this note. The review leg
raised it, and it was confirmed at source before being written down. The §3
sweep below is corrected accordingly — its earlier claim that `search.rs:376,
629,728` were "not list-shaping for ORDER.2" was right about `tools/list` and
wrong about the criterion, because it read the criterion as being about one
method name rather than about list results.

## 3. The negative sweep — what else shapes a list, and why each is not a violation

A "nothing else found" claim is only worth what it enumerates. Every input that
reaches list assembly was read:

| input | source | verdict |
|---|---|---|
| routing profile | `mod.rs:1062-1072` via `surfaced.rs:101` | closed, §1 |
| OAuth / route isolation omission | `mod.rs:870-873` `meta_route_isolation_refused` -> `enforce_oauth_isolation_for` | **not a violation** — derived from authorization, which the criterion explicitly permits to vary |
| Code Mode | `handlers.rs:497` `code_mode_url_active` | **not a violation** — read from the request's own URL query, per-request input, not connection state |
| meta-tool set | global configuration | invariant across connections by construction |
| backend tool cache contents | shared, time-varying | out of scope; cluster-b Part III item 1 |
| spec-preview promotion | §2 | **a remaining violation** |
| FSM workflow state, via the discovery surface | §2b, `mod.rs:1688-1696` and `search.rs:161-165` | **a remaining violation**, in the default build |

Other `active_profile` call sites were checked. `invoke.rs:1065` is dispatch.
`mod.rs:1263` (`shadow_tools_list_assembly`) is telemetry only, as is
`mod.rs:1758`. `spec_preview.rs:47` shapes the preview list and is covered by
B-06. `search.rs:376,629,728` shape the discovery surface, and that surface is
where §2b's defect lands — the first draft of this note wrote them off as "not
list-shaping" and was wrong to.

One protocol check worth recording because it could have made §1 moot:
`REMOVED_IN_2026_07_28` at `src/protocol/meta.rs:221-229` is
`["ping","logging/setLevel","notifications/roots/list_changed",
"resources/subscribe","resources/unsubscribe"]`. `initialize` is **not** removed,
so a modern client can still call it and still send `X-MCP-Profile`; fact 5 is
load-bearing, not vestigial.

## 4. Options

Cluster-b's four options stand; this note re-prices them against what is now
true, and adds the one that was not available when that note was written.

**(a) Profile as a per-request input.** Restores profile selection for modern
clients without connection state. Unchanged in cost from cluster-b's assessment:
a schema change on every list and invoke path. Does **not** address §2 by itself —
promotion would still need its own answer. Now strictly more expensive than it
was, because it means *undoing* the shipped behaviour in fact 4 and then
rebuilding the capability in a new shape.

**(b) No profiles in modern mode.** This is what shipped (§1). Nothing to design;
the remaining work is to decide whether the resulting refusal is intended (§6).

**(c) Extend the `session_key` discipline to the promotion store — RECOMMENDED.**
Route `invoke.rs:1826` and `promoted_tools_for_session` through `session_key`, so
a sessionless caller neither writes to nor reads from `session_promoted`. A
modern connection then sees the unpromoted list, always, and an invoke has no
effect on it.

**(d) Disable spec-preview promotion entirely in modern mode.** Rejected as
written: it is (c) with a coarser blade, adds a second modern-mode branch where
one already exists, and it would also disable the query-driven preview list that
`spec_preview.rs:43-47` serves and that ORDER.2 does not object to (that list is
a function of per-request `params.query`, not of connection state).

**(e) Keep promotion, key it by something invariant across connections.**
Rejected: any key that is invariant across connections makes promotion a global
mutation, which converts a 2a violation into a worse one — every caller's list
changes because one caller invoked something.

### Recommendation

Take **(c)**. Three reasons, in order of weight. It **eliminates** rather than
patches: after it, the shared `""` key does not exist, so the finding cannot be
restated — the test in the repair protocol's elimination table. It reuses a
mechanism that already exists, is already reviewed, and already carries the
ORDER.2 rationale in its own doc comment, so it adds no new concept to the
codebase. And it needs no new per-request input and no change to the
`gateway_set_profile` product surface, which means it can land without waiting on
the open question in §6.

The consequence to state plainly: with (b) already shipped and (c) applied, a
modern connection has **no per-connection list state at all**. That is the
strongest form of the criterion, and it is reached by removing state rather than
by adding checks.

## 5. Unknowns

Every unknown is resolved with a recorded answer or deferred with four fields.

**RESOLVED**

| question | how | what came back | what it changed |
|---|---|---|---|
| Is the profile leg actually unguarded, as the audit row says? | read `handlers.rs:574-589`, `mod.rs:1062-1099`, `mod.rs:1186`, `mod.rs:1725-1739` | a guard exists, and its doc comment names ORDER.2 as its reason | Inverted the note. Scope shrank from "design the ORDER.2 fix" to "close the one remaining leg". |
| Does any modern-declaring path reach list assembly with a **non-empty** session id, which would put a hole in fact 1? | `rg` for every caller of `handle_tools_list_for_session` and `promoted_tools_for_session` outside `mod.rs`; read `handlers.rs:971,1162`; read the stdio transport module | Only `spec_preview.rs:43` and `mod.rs:1247`, which passes `None`. The stdio transport carries no session id at all. HTTP is the only path that supplies one, and it supplies the empty string for modern. | Nothing. Fact 1 holds, so the recommendation stands as written. Had it come back otherwise, §1 would have been the design and §2 a footnote. |
| Is `initialize` removed in 2026-07-28, which would make the `X-MCP-Profile` guard dead code? | read `REMOVED_IN_2026_07_28` at `meta.rs:221-229` | Not in the removal list. | Nothing, but it makes fact 5 load-bearing rather than defensive. |
| Is `spec-preview` in the default build? | read `Cargo.toml:179,193` | No; `spec-preview = []`, and it is not in `default`. | A severity input for §6. Does not change the recommendation — the option is cheap enough that non-default status is not a reason to skip it. |
| Does prior art already cover this, making a new note a duplication? | read the cluster-b connection-invariance note, Part I and its residue list, and its sibling test plan | Part I *is* ORDER.2; its residue list explicitly leaves the promotion store "to be closed by whichever ORDER.2 option is chosen"; B-06 and B-07 already specify the cases. | Made this a delta note rather than a design. No option analysis, blast radius, or test case is restated here. |

**DEFERRED**

| unknown | owner | what would resolve it | when | if it resolves badly |
|---|---|---|---|---|
| Whether the stdio and A2A transports can present a modern-era connection carrying a non-empty session id, which would reopen fact 1 on a path this note did not price | cluster-g, the stdio dispatch parity note dated 2026-09-02 | Reading that dispatch path for a session id that reaches `handle_tools_list_for_session` | Before any ORDER.2 implementation merges | The `session_key` discipline still applies unchanged, but it would have to be applied at that transport's boundary too, and the cases would need a stdio variant. Recommendation (c) is unaffected in shape, only in coverage. |
| Whether `session_promoted` should exist at all once modern is the only era | cluster-b, its "the `spec-preview` promotion feature itself" residue item | A product decision, not a check | When the legacy era is dropped | (c) becomes dead code to delete, which is the cheap direction. |

Nothing in this note's recommendation depends on either deferred item.

## 6. Open questions for the requester

Neither is answerable from inside the codebase.

**Q1 — Is the shipped refusal of `gateway_set_profile` on modern connections
intended?** `mod.rs:1725-1728` and `mod.rs:1737-1739` return
`NO_SESSION_FOR_PROFILE` for any caller declaring MCP 2026-07-28. That is a
user-visible behaviour change: a modern client gets the default profile and no
profile control at all. Two readings. (1) Accept it — this is cluster-b option
(b), it is shipped today, and it costs nothing. (2) Modern clients should get
profile selection back as a per-request input — cluster-b option (a), which costs
a schema change on every list and invoke path. Recommendation: (1), on the
grounds that it is already shipped and that ORDER.2 is a *harder* guarantee
under it. The cluster-b note poses a version of this question at its line 462 and
records it as one that cannot be answered internally; it appears to still be
unanswered, and two differently-worded copies of one question is how a question
never gets answered — so answer it against that line, not beside it.

**Q2 — Does `spec-preview` being a non-default feature lower ORDER.2's
severity?** The remaining violation compiles only under `--features spec-preview`
(`Cargo.toml:193`). If the ledger's severity describes a default build, ORDER.2's
status arguably differs between the two build configurations, and the ledger has
one cell. Recommendation: hold the criterion at its stated severity regardless,
because the feature is the one the 2026-07-28 work exists to prepare, and because
option (c) is cheap enough that the distinction does not buy anything.

## 7. Test plan — one row per clause

The cases live in `docs/design/2026-08-31-cluster-b-connection-invariance-test-plan.md`
and are **not** restated here. This table maps each clause to the case that
proves it and, per §P2's second question, states how each case can FAIL — a case
that cannot fail proves nothing.

| clause | leg | case | level | how it can FAIL |
|---|---|---|---|---|
| 2a — must not vary per connection | routing profile | **B-01**: two modern connections, one binds `X-MCP-Profile`, both tool-name sets compared against the same pinned literal | integration | The binding connection's list differs from the other's, or either differs from the pinned literal. Because the expectation is a pinned literal rather than a comparison of the two lists, a regression that changes *both* connections identically also fails, which a two-way equality assertion would miss. |
| 2a | spec-preview promotion | **B-07**: a tool promoted in session A must not appear in a modern connection's list, nor make two modern connections differ | integration | The promoted tool name appears in the modern list, or the two lists differ. Fails today against the code in §2 if the fixture drives promotion through the real invoke path — it must not stub `promote_tool_for_session`, or the case asserts against its own fixture rather than production. |
| 2a | spec-preview preview list | **B-06**: B-01 re-run under `--features spec-preview` with a pinned match-all `params.query` | integration | The feature-gated build's list differs from the default build's, or between connections. Covers `spec_preview.rs:46`. Runs only in a job that enables the feature; a suite that never enables it reports green while proving nothing, so the feature-enabled job is part of the case, not an optional extra. |
| 2b — must not vary as a side effect of other requests on the connection | routing profile | **B-02**: `tools/list`, then `gateway_set_profile`, then `tools/list`; both lists compared to the same pinned literal | integration | Either list differs from the literal. Note the case must assert on the *lists*, not on the `gateway_set_profile` response: that call now returns `NO_SESSION_FOR_PROFILE` (§1 fact 4), and a case that asserts only the refusal would pass even if the lists diverged. |
| 2b | spec-preview promotion | **B-07** covers the cross-connection half; the same-connection half needs the sequence `tools/list` → successful `gateway_invoke` → `tools/list`, both lists equal | integration | The second list contains the promoted tool. This sequence is the direct statement of 2b and is the case that fails against §2 today. It is the one addition this note asks of the existing plan. |

Two properties the plan should keep visible. Every case pins a **literal**
expected tool-name set rather than comparing two observed lists, so a change
that moves both connections in step is still caught. And the promotion cases
must drive the real `gateway_invoke` path — the defect in §2 lives in the
argument passed at `invoke.rs:1826`, and a fixture that calls
`promote_tool_for_session` directly bypasses exactly the line under test.

## 8. What this note does not close

ORDER.2a and ORDER.2b are **not** satisfied by this note. It is design only: no
code changed, no test was added, and the promotion leg in §2 is open in the
source as of 682a709a. The ledger rows stay blocking. What has changed is what
the evidence cell can now say: the profile leg is closed in code and measured
here, the remaining defect is one call site and one accessor, and the option to
close it is chosen and priced.
