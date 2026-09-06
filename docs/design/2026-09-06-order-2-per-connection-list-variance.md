# ORDER.2 — list results must not vary per connection, nor as a side effect

MIK-7272.ORDER.2a, MIK-7272.ORDER.2b. This note adds no code and no tests. It is not, however, a design written ahead of all of its subject: two of the three legs below had already landed when it was written (`eb9e537a`, `76b8536c` and the five profile cases are ancestors of the revision under review). For those two legs this note is a POST-HOC RECORD and should be read as one; only the third leg, the FSM workflow-state store, is designed here before it is built. A reviewer judging the closed legs is judging a decision already constrained by its implementation, and saying so is cheaper than implying otherwise.

## What this note is, and is not

This is a **delta** on `docs/design/2026-08-31-cluster-b-connection-invariance.md`
(Part I of that note *is* ORDER.2) and its sibling test plan. It does not restate
the option analysis, the blast radius, or the cases already written there. It
records what that note could not: which legs have since **closed in code** and which
have not. Three legs; the prerequisite checkpoint below measures the committed integration base `0d4df3c0`. Historical citations remain evidence of the original investigation.
The routing profile is closed and carried by five cases. The `spec-preview`
promotion store — which cluster-b classified in its §I.2 and explicitly left to
"whichever ORDER.2 option is chosen" — is closed in code at `eb9e537a`. The sessionless regression in `0527aacc` is external history, not an ancestor or a test present in this isolated base. B-10 is the in-tree promotion regression. The **FSM workflow-state store is the one leg still open
in committed code**: `76b8536c` converged four discovery entry points onto one
accessor, which is the precondition for a filter and is not the filter. An earlier
revision of this paragraph named `spec-preview` as the sole remainder; that was
written before `eb9e537a` landed and is corrected here rather than left to mislead
an implementer into repairing the leg that is already done.

## §P0 SCOPE

**FOR:** deciding what remains to be done so that list results neither vary per
connection (2a) nor vary as a side effect of other requests on the same
connection (2b), on a connection declaring MCP 2026-07-28. **List results** here
means `tools/list` *and* the tool listings the discovery surface returns. The
second half is in scope because that is where §2b's defect lands; that ORDER.2's
own wording reaches it was Q3, answered by the team lead on 2026-09-06 (§6). This is wider
than the first draft's `tools/list`, deliberately and before any dual review
completed, so the scope freeze has not been moved — it has not yet been set.

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
| 4 | `gateway_set_profile` and `gateway_get_profile` both **refuse** on a sessionless caller with `NO_SESSION_FOR_PROFILE`. | `mod.rs:1726-1727`, `mod.rs:1755-1756`; const at `mod.rs:1096` |
| 5 | The `X-MCP-Profile` initialize-time binding is gated by the same `session_key`. | `mod.rs:1186` |
| 6 | `resolve_surfaced_tool` filters every surfaced tool through `active_profile` first, so the whole surfaced-tool leg inherits (3). | `src/gateway/meta_mcp/surfaced.rs:101-115` |

**Consequence:** the routing-profile leg of ORDER.2 is closed, and it is closed
in the shape of cluster-b's **option (b)** (profiles do not exist in modern mode),
not the option (a) that note recommended. The mechanism is elimination, not a
check: with no non-empty key there is no per-connection profile state to vary.

## 2. The spec-preview promotion store — closed in code, and now tested

`spec-preview` dynamic promotion (SEP-1862) was the one list-shaping input that
did **not** pass through `session_key`. It does now: `promote_tool_for_session`
takes `Option<&str>` and returns early when `session_key` rejects the caller
(`src/gateway/meta_mcp/spec_preview.rs:238-241`, landed in `eb9e537a`), and a
sessionless test was later added in `0527aacc` on another branch. That test has not been replayed into base `0d4df3c0`, so it is not counted here.
The facts below record the defect as it stood, because the option analysis in
§4 was written against it.

| # | fact | source |
|---|---|---|
| 7 | After a successful `gateway_invoke`, the tool is promoted for the session: `if let Some(sid) = session_id { self.promote_tool_for_session(sid, &tool_key); }`. `Some("")` satisfies this. | `src/gateway/meta_mcp/invoke.rs:1826-1828` |
| 8 | `promote_tool_for_session` writes `session_promoted.entry(session_id.to_string()).or_default()`. The empty string is a valid `DashMap` key. | `src/gateway/meta_mcp/spec_preview.rs:228-245`; store at `mod.rs:312`, init `mod.rs:467`, cleared `mod.rs:1048-1049` |
| 9 | `promoted_tools_for_session(session_id)` reads the raw id, no `session_key`. | `mod.rs:1021-1030` |
| 10 | The router passes `Some(session_id.as_str())` on both the list and the call path, i.e. `Some("")` for a modern connection. | `handlers.rs:971` (`tools/list`), `handlers.rs:1162` (`tools/call`) |
| 11 | Promoted tools are appended to the assembled list inside `handle_tools_list_for_session`, immediately after the surfaced-tool loop. | `mod.rs:1284-1330`, surfaced loop at `mod.rs:1310` |

**Before `eb9e537a`, both clauses failed on this leg.** 2b: a successful `gateway_invoke` changes the
next `tools/list` on the same connection. 2a: because the key is `""` and every
sessionless modern caller shares it, the change is visible to *other*
connections too — a strictly worse failure than the one the criterion names.

**Materiality, stated honestly.** `spec-preview` is not in the default feature
set: `Cargo.toml:179` lists `default = ["a2a","webui","config-export",
"cost-governance","firewall","discovery","semantic-search","tool-profiles",
"metrics"]`, and `Cargo.toml:193` declares `spec-preview = []`. A default build
does not compile this path. It was a defect in the builds that enabled the
feature, and the feature is the one this whole protocol effort exists to
prepare. Whether that lowers the criterion's severity was Q2, answered on
2026-09-06: it does not (§6). Not a reason to leave it.

**Not a discovery.** cluster-b's test plan already specifies this case as
**B-07** ("a promoted tool must not appear in session A's modern list, nor make
it differ from B") and **B-06** (B-01 re-run under `--features spec-preview`).
This historical measurement motivated the now-landed promotion guards. The FSM leg below is the remaining prerequisite.

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
discovery surface's output is a "list result" for the purposes of ORDER.2 was Q3,
answered yes on 2026-09-06 (§6) — and the defect is the same shared key either
way, so recommendation (c) closes it with the same one-line change applied at
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
| spec-preview promotion | §2 | closed in code, `eb9e537a`; in-tree B-10 regression; `0527aacc` is external/unreplayed |
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

**The letters below are this note's own.** They are *not* cluster-b's, and the
two sets do not line up — cluster-b's (c) is "re-key the profile on the
authenticated principal", which is this note's (e), not this note's (c). An
implementer who carries the parent note's lettering across builds the expensive
principal-mapping option nobody chose here. The mapping, once:

| this note | cluster-b §I.4 |
|---|---|
| (a) profile as a per-request input | (a), threaded differently |
| (b) no profiles in modern mode | (b) |
| (c) `session_key` on the raw-id stores | **no equivalent** — the leg it closes was not open when that note was written |
| (d) disable spec-preview promotion in modern mode | no equivalent |
| (e) key promotion by something connection-invariant | (c) re-key on the authenticated principal |
| — | (d) `notifications/tools/list_changed`, out of scope here per §P0 |

**(a) Profile as a per-request input.** Restores profile selection for modern
clients without connection state. Unchanged in cost from cluster-b's assessment:
a schema change on every list and invoke path. Does **not** address §2 by itself —
promotion would still need its own answer. Now strictly more expensive than it
was, because it means *undoing* the shipped behaviour in fact 4 and then
rebuilding the capability in a new shape.

**(b) No profiles in modern mode.** This is what shipped (§1). Nothing to design;
and the operator ratified it on 2026-08-31 (cluster-b §4.1, recorded in §5), so
there is nothing left to decide here — (a) is dead rather than merely expensive.

**(c) Extend the `session_key` discipline to the two raw-id stores — RECOMMENDED.**
**Historical implementation sequence.** Promotion guards (`eb9e537a`) and the FSM reader consolidation (`76b8536c`) are already in integration base `0d4df3c0`. The only remaining production edits are the FSM write guard and the one consolidated read guard. The following inventory explains why the original design required consolidation; it does not prescribe repeating that completed work:

| Remaining FSM owner | Required change | Existing consumers |
|---|---|---|
| `MetaMcp::set_state` | reject missing/empty session key with the ratified protocol error | real `handle_tools_call` dispatch |
| `MetaMcp::current_search_state` | normalize missing/empty key to the default state | code-mode search, search_tools, list_tools, list_tools_single_server |

The promotion guards and FSM reader fold have already landed. They are not work
for this increment. Both remaining guards reuse `session_key`, so future callers
inherit the invariant at its existing owner rather than repeating call-site checks.

One deliberate exception, because it is the kind that gets "corrected" later: the
FSM **write** is filtered at the `gateway_set_state` handler (`mod.rs:1689`), not
inside `SessionStateStore`. A sessionless caller must receive a protocol error,
and a store setter has no way to return one — pushing the filter down into the
store would turn the refusal into a silent no-op, which is a worse defect than
the one being fixed. The profile stores already sit this way, for the same
reason.

A modern connection then sees the unpromoted list and the default workflow state,
always, and an invoke has no effect on either.

**The cost, stated rather than implied.** On the `session_state` half this is not
free: `gateway_set_state` currently *succeeds* on a modern connection, and after
(c) it must refuse — the same shape as the `NO_SESSION_FOR_PROFILE` refusal in
fact 4, on a tool that works today, in the **default build** rather than behind a
feature flag. That refusal is a user-visible behaviour change and it is the
substantive price of (c). It is the right price: the alternative is a tool whose
effect leaks to every other sessionless connection. But it is a product surface
moving, so it is named here rather than discovered at implementation.

**(d) Disable spec-preview promotion entirely in modern mode.** Rejected as
written: it is (c) with a coarser blade, and it adds a second modern-mode branch
where one already exists. (Two earlier drafts got its side effect wrong in opposite
directions. The first charged it with disabling the query-driven preview list at
`spec_preview.rs:43-47` — overstated. The second said the filtered path does not
read `session_promoted` at all — false: `collect_filtered_backend_tools` merges
promoted tools at `spec_preview.rs:111-112`, which is the same reader the §7
matrix already cites. What (d) actually costs there is that merge and nothing
else: the query-and-profile list keeps working, and promoted tools stop joining
it on a modern connection. The rejection stands on the other two reasons.)

**(e) Keep promotion, key it by something invariant across connections** — this
is cluster-b's (c), principal re-keying, in the promotion store's clothes.
Rejected **on 2b, not on 2a** — an earlier draft rejected it as "a global
mutation", which is a caricature of principal re-keying and would not survive an
implementer reading it. A principal key is authorization-derived: two connections
of the same principal agree, and two principals differ, which is precisely the
variation ORDER.2's third clause *permits*. So (e) satisfies 2a. It fails the
half this note is also FOR: the principal is the same before and after an
invoke, so a successful `gateway_invoke` still changes that connection's next
list — 2b, untouched, which is the leg (c) closes. Its second cost is the one
cluster-b priced: an unauthenticated modern connection has no principal to key
on, so it needs a fallback, and the only fallback available is the shared key
this note exists to remove.

### Recommendation

Take **(c)**. Three reasons, in order of weight. It **eliminates** rather than
patches: after it, the shared `""` key does not exist, so the finding cannot be
restated — the test in the repair protocol's elimination table. It reuses a
mechanism that already exists, is already reviewed, and already carries the
ORDER.2 rationale in its own doc comment, so it adds no new concept to the
codebase. And it needs no new per-request input, and no change to the
`gateway_set_profile` surface beyond what already shipped. It does change one
surface: `gateway_set_state` starts refusing on **sessionless** callers — the
empty-id condition, which is what a modern connection over HTTP presents — priced
in (c) above. Not "on modern connections": the refusal fires on what `session_key`
filters, and stdio's fixed `"stdio-session"` is not filtered, so a modern stdio
caller keeps `gateway_set_state`. The cases must pin the empty id rather than the
era, or B-09 goes red against a correct fix.

The consequence to state plainly: with (b) already shipped and (c) applied, a
modern connection **over HTTP** has **no per-connection list state at all**.
That is the strongest form of the criterion, and it is reached by removing state
rather than by adding checks. The qualifier is load-bearing and it is not a
hedge: stdio dispatches under the fixed non-empty id `"stdio-session"`
(`server/mod.rs:1604,1822-1824`), which `session_key` passes untouched, so (c)
closes both legs on modern HTTP and neither on stdio. Fact 1 in §1 is an HTTP
fact — it cites the router — and it should be read as one. §8 carries the limit;
transport parity is cluster-g's per §P0.

## 5. Unknowns

Every unknown is resolved with a recorded answer or deferred with four fields.

**RESOLVED**

| question | how | what came back | what it changed |
|---|---|---|---|
| Is the profile leg actually unguarded, as the audit row says? | read `handlers.rs:574-589`, `mod.rs:1062-1099`, `mod.rs:1186`, `mod.rs:1725-1739` | a guard exists, and its doc comment names ORDER.2 as its reason | Inverted the note. Scope shrank from "design the ORDER.2 fix" to "close the one remaining leg". |
| Does any path reach list assembly with a **non-empty** session id, which would put a hole in fact 1? | `rg` for every caller of `handle_tools_list_for_session` and `promoted_tools_for_session` outside `mod.rs`; read `handlers.rs:971,1162`; read the **stdio dispatch in `src/gateway/server/mod.rs`** — the first pass read `src/transport/stdio.rs`, which is the wrong file, and returned a false negative | On **HTTP**, no: only `spec_preview.rs:43` and `mod.rs:1247` (which passes `None`), and modern HTTP supplies the empty string. On **stdio**, yes: `server/mod.rs:1604` sets `let session_id = "stdio-session";` and `:1822-1824` passes `Some(session_id)` into `tools/list`, as `:1826-1828` does into `tools/call`. A fixed, non-empty id. | A great deal, and it is the repair this review earned. `session_key` filters the *empty* string, so `"stdio-session"` passes it: **(c) does not close the 2b sequence on stdio**, where an invoke can still promote into the same connection's next list. It does close both legs on modern HTTP, which is what §P0 declares this note FOR. The stdio gap is recorded in §8 and belongs to cluster-g by §P0, not to this note — but it is now a measured fact rather than an open question. |
| Is `initialize` removed in 2026-07-28, which would make the `X-MCP-Profile` guard dead code? | read `REMOVED_IN_2026_07_28` at `meta.rs:221-229` | Not in the removal list. | Nothing, but it makes fact 5 load-bearing rather than defensive. |
| Is `spec-preview` in the default build? | read `Cargo.toml:179,193` | No; `spec-preview = []`, and it is not in `default`. | A severity input for §6. Does not change the recommendation — the option is cheap enough that non-default status is not a reason to skip it. |
| Is the shipped refusal of `gateway_set_profile` on modern connections **intended**, or is fact 4 an unratified behaviour change? (askable, not checkable) | asked of the operator on 2026-08-31 via the cluster-b note's Part IV; answer recorded at `docs/design/2026-08-31-cluster-b-connection-invariance.md:453-458` | "RESOLVED 2026-08-31, by the operator, asked and answered: remove them outright (option b)." The break is recorded as knowingly accepted. | A great deal. §1 is a **ratified** closure, not a shipped surprise, so cluster-b option (b) is settled and option (a) is dead rather than merely expensive. This note's first draft re-asked it as an open Q1; that was wrong, and asking a closed question twice is how an answer gets lost. Q1 is struck from §6. |
| Does `spec-preview` being a non-default feature lower ORDER.2's severity? (askable, not checkable) | asked of the team lead in this note's deliverable, answered 2026-09-06 | Hold the severity. Splitting the row by build configuration buys a distinction that (c) makes moot, and the §2b leg ships in `default` regardless, so the row is earned either way. | Nothing in the design; it closes the severity question so the ORDER.2 evidence cell can be written against one reading. Recommendation confirmed rather than overturned. |
| Does the discovery surface's output count as a "list result" under ORDER.2? (askable, not checkable) | asked of the team lead in this note's deliverable, answered 2026-09-06 | The second reading: ORDER.2 is about *what tool set a connection is shown*, not about one method name. Both readings leave the defect identical — which is what made this the lead's call and not the operator's. | Fixes the §2b leg's label: the `session_state` half of (c) belongs to ORDER.2 itself, not to a sibling criterion, so implementation lands under one ticket. The defect, its four call sites and the cases were the same under either reading. |
| Does prior art already cover this, making a new note a duplication? | read the cluster-b connection-invariance note, Part I and its residue list, and its sibling test plan | Part I *is* ORDER.2; its residue list explicitly leaves the promotion store "to be closed by whichever ORDER.2 option is chosen"; B-06 and B-07 already specify the cases. | Made this a delta note rather than a design. No option analysis, blast radius, or test case is restated here. |

**DEFERRED**

| unknown | owner | what would resolve it | when | if it resolves badly |
|---|---|---|---|---|
| ~~Whether stdio can present a connection carrying a non-empty session id~~ — **answered, and badly**: it does (`server/mod.rs:1604,1822-1824`, §5 above). What remains deferred is what cluster-g does about it: A2A's equivalent, and whether stdio should key these stores at all given one client per process | cluster-g, the stdio dispatch parity note dated 2026-09-02 | Reading the A2A dispatch for the same pattern, and a product call on stdio's fixed id | Before any ORDER.2 implementation claims transport-wide coverage | Already realised. The fallback named here is now the live path: `session_key` alone does not cover stdio, so cluster-g must either drop the fixed id, or key the two stores by something that is per-*connection* rather than per-*process*, and the cases need a stdio variant. (c)'s shape is unchanged; its **coverage** is HTTP-modern only, and §8 says so. |
| Whether `session_promoted` should exist at all once modern is the only era | cluster-b, its "the `spec-preview` promotion feature itself" residue item | A product decision, not a check | When the legacy era is dropped | (c) becomes dead code to delete, which is the cheap direction. |

Nothing in this note's recommendation depends on either deferred item.

## 6. Questions put to the requester — decisions recorded

Recorded here because a question that was asked and answered is evidence; a
question that quietly stopped being asked is not. Q4 was answered by the operator;
the recovered answer below removes the decision dependency. Implementation and
acceptance validation remain separate and pending.

**Q1 is struck.** It asked whether the `gateway_set_profile` refusal was
intended. The operator answered that on 2026-08-31 in cluster-b Part IV §4.1 —
"remove them outright (option b)" — and the answer is recorded in §5 above. The
number is retired rather than reused, so citations to it stay unambiguous.

**Q2 — does `spec-preview` being a non-default feature lower ORDER.2's
severity? Answered 2026-09-06 by the team lead: no, hold it.** The remaining
promotion violation compiles only under `--features spec-preview`
(`Cargo.toml:193`), so the question was whether one ledger cell can describe two
build configurations. It does not have to: the §2b FSM leg ships in `default`,
so the row is earned by the default build alone, and (c) closes both legs at a
price low enough that the distinction would buy nothing. Recorded in §5.

**Q3 — does the discovery surface's output count as a "list result" under
ORDER.2? Answered 2026-09-06 by the team lead: yes — read the criterion as *what
tool set a connection is shown*.** The criterion's text says `tools/list`, while
§2b's defect filters `gateway_search` and the capability listings
(`search.rs:378,586,653,730`). The harm ORDER.2 names is a client seeing a tool
set that another connection silently changed; which surface reveals it is a
label, not a defect. **Both readings leave the defect, its four call sites and
its cases identical** — that is precisely why this was the lead's call to settle
and not an escalation to the operator, and it is why nothing in §7 moves. What it
fixes is where the work lands: the `session_state` half of (c) belongs to ORDER.2
itself rather than to a sibling criterion, so implementation is one ticket.

**Q4 — RESOLVED: the operator ratified the refusal on 2026-09-06.** After
(c), `gateway_set_state` **refuses** on a modern HTTP connection, in the
**default build**, on a tool that previously succeeded. The question explicitly
named that compatibility cost. Its recorded answer was **"Ratify the refusal
(recommended)"** at `2026-09-06T11:19:59.466Z`, through `AskUserQuestion`, tool-use
ID `toolu_01SKMFrjNivV7VaHyKzwEt4c`, session
`be5177ff-7fa6-4b0c-9c6c-fecc3f7548e1`. The answer was recovered from the actual
tool result during release takeover, rather than inferred from the implementation
comment. The design's former OPEN status had not been updated after that answer.

This selects option (c)'s refusal branch and B-08/B-09's refusal-plus-unchanged-list
assertions. It does not establish that those tests compile or pass, or that the
implementation is reviewed or delivered.

| answer | what it buys | what it costs |
|---|---|---|
| **ratify the refusal** (selected) | 2a and 2b can close on modern HTTP by removing state rather than adding checks; `gateway_set_state` follows `gateway_set_profile`'s session rule | a modern client calling `gateway_set_state` starts getting a protocol error where it got a success; if any client depends on it, that client breaks at upgrade |
| keep it succeeding, close 2a only | no client-visible break | the tool's effect still leaks to every other sessionless connection, which is the defect — a per-connection tool that is not per-connection |

The selected refusal prevents a modern caller from writing state that every other
sessionless connection can read. Existing session-bearing callers retain their
stateful behavior; the acceptance tests must verify both populations.

## 7. Test plan — moved to its own document

`docs/design/2026-09-06-order-2-per-connection-list-variance-test-plan.md`.

It carries what stood here: the case-per-clause table with the how-it-can-FAIL
column, the six-cell criteria x surface matrix and the reasons three of its cells
are empty, the `B-07` repair without which that case covers nothing, and the full
specifications of the three new cases `B-08`, `B-09` and `B-10`. It adds what a
plan owes and a design note does not — the two implementation shapes the cases
depend on, stated as plan-blocking preconditions rather than advice.

Moved rather than copied: §P2 asks for a plan reviewed **as a plan**, and this
note's review was scoped design-only. A table living in both files drifts, and the
copy nobody reads is the one that goes stale.

## 8. What this note does not close

ORDER.2a and ORDER.2b are **not** satisfied by this note. The promotion leg of §2 has since closed —
guarded in `eb9e537a`, with B-10 as an in-tree regression — and the FSM
state store of §2b is the one leg still open in isolated base `0d4df3c0`. The additional sessionless test in `0527aacc` is unreplayed external history, not current coverage. The ledger rows stay blocking. What has changed is what
the evidence cell can now say: the profile leg is closed in code and measured
here, the remaining defect is **one store** — the
default-build FSM state store of §2b; the feature-gated promotion store of §2 is
closed — and the option to close both is chosen, priced, and ratified by the operator
on 2026-09-06 (§6 Q4). §2b belongs to ORDER.2
itself, per Q3's answer of 2026-09-06; it would have been the same defect under
either reading.

**Disposal of that limit, named rather than defaulted (§P0).** Of the four
disposals, the one that holds is *write it into the design* — cluster-g's, not this
note's, because the finding changes what that cluster's convergence point should be
and its owner is who acts on it. Done on 2026-09-06: a section at the end of
`docs/design/2026-09-02-cluster-g-stdio-dispatch-parity.md` records the non-empty
`"stdio-session"` id, the two stores that would have to be re-keyed, and the fact
that the settlement is a product call rather than a repair. It was **not** filed as a
ticket: filing is the most expensive disposal, cluster-g already owns a design note
and a board row, and a new ticket would have added a queue entry without adding a
decision. What the disposal does not do is build the watcher — that stays cluster-g's
implementation step and is named as missing there.

One coverage limit, found by review and worth more than the rest of this note:
**(c) closes both legs on modern HTTP and neither of them on stdio.** stdio
dispatches under the fixed non-empty id `"stdio-session"`
(`server/mod.rs:1604,1822-1824`), which passes `session_key` untouched, so an
invoke on a stdio connection can still promote into that connection's next list —
2b, live, after the recommended fix. §P0 puts transport parity with cluster-g and
this note does not price it; what this note owes cluster-g is the measurement,
which is now in §5 rather than sitting in the deferred column as a question.


## 9. FSM prerequisite delivery checkpoint — 2026-09-07

**Current increment status:** the two FSM guards are implemented; eight focused
acceptance/caller cases pass after compiled assertion RED and test-finder closure.
Formatting passes. Draft publication starts CI in parallel with remaining final
code review, quantitative checks and independent functional acceptance. No merge
or complete release acceptance is claimed.

**FOR:** unblocking the 4.0 integration base and configuration PR #483 by closing
only the sessionless FSM write/read invariant already selected in option (c).
**OUT:** profile/promotion redesign, stdio/A2A transport policy, notifications,
cache behavior, unrelated release implementations, and merging or release closure.
This is the remaining FSM increment of the original ORDER.2 change, not a new
requirement or a reset of its review history. Historical ledgers stored
`change_id: null`; the original frozen design receipt remains material
`5f262fb547766dfac8835f691fe481ff017fdbea709008f78f9bc40522ee3a14`
(31,167 bytes, Grok `grok-20260906T064155Z-129`). Preserve that lineage rather
than inventing a previous passing gate. This prerequisite is two steps from the
configuration implementation (CI selection, then its failing integration base);
it still serves the user's original 4.0 release delivery objective.

A prepared repair exists in the separate delivery worktree, but its required
gates are missing. The authoritative later GPT/Grok design/plan findings are
`gpt-20260906T153954Z-80665` and `grok-20260906T154615Z-96685`, both
SHIP-WITH-FIXES. They require the ratified refusal assertions, modern-aware error
text, and an honest distinction between completed promotion work and the two
remaining FSM guards. Their original differing material hashes are retained;
they do not constitute a matching final approval. The historical Kimi plan leg
`synthetic-20260906T080350Z-26796` also returned SHIP-WITH-FIXES, despite the
older record saying pending. No FSM tests-as-tests closure, final code pair,
independent functional drive, or quantitative receipt was found in the inherited
OUT/ledger audit. None is claimed as passed.

### Definition of Ready and validation boundary

- Value/priority: mandated `MIK-7272.ORDER.2a/.2b` release invariance; CI run
  34062367993 on config SHA `bfa16dc3` compiled 4,058 library cases and returned
  4,052 passed, two B08/B09 assertion failures, four ignored, exit 101. The same
  relevant production blobs and test bodies are present in base `0d4df3c0`.
  The private Spark rebuild now independently confirms B08/B09 assertion RED and one staging control PASS (exit 101); see `order2-prerequisite-base-red-r2.log`.
- Scope/dependencies: only `MetaMcp::set_state`, its refusal text, and
  `MetaMcp::current_search_state`; the existing `session_key` helper and four
  discovery consumers already exist. Tests and these two design files accompany
  the patch. No new public API, dependency, storage format, crypto, service, or
  deployment topology. Parent owns TLS; config PR #483 stays separate.
- Alternatives: reuse the selected owner-level guards; reject a silent store
  no-op because it hides the refusal, and reject principal re-keying because a
  caller could still change its own subsequent list. The existing operator Q4
  answer settles the only product compatibility decision: refuse sessionless
  state changes; non-empty legacy/stdio session keys retain their behavior.
- Risks: write-only repair misses already contaminated empty-key state; read-only
  repair makes the refused mutation appear successful. Separate write/read tests
  and their falsifiers cover both. Exact error assertions prevent advice to send
  a session header that modern HTTP ignores. Unchanged non-empty controls detect
  overbroad normalization.
- Applicable DoR: CODE/security mandate and existing ticket/criteria; G0-G12,
  C1-C15 and rollback/test/CI requirements apply. Novelty/NPV/emerging-tech
  benchmark, new-service SLO, crypto/PQC, AI/ML, residency, device and new-license
  conditions are N/A because no such surface changes. The existing Rust helper
  avoids introducing a new abstraction or technology. No new telemetry event is
  needed for an existing protocol refusal. STRIDE: eliminate shared-state
  tampering/information influence; no new identity or credential is trusted.
- Unknowns: Q4 is resolved by the recorded operator answer. Compiled repaired
  assertions, read-guard falsification, critical coverage/mutation, final review
  and independent public HTTP behavior are **pending results**, owned by this
  increment before merge; any failure blocks that gate and is repaired within
  this same invariant. A full release/transport-wide claim remains out of scope.
- Quantitative plan: exercise >=95% of changed critical executable lines and
  catch >=85% of viable focused mutations, including each omitted guard and a
  silent-success fault. Run default and all-feature affected tests, formatter,
  Clippy and same-SHA CI. Use a pinned actual CLI HTTP drive with modern and
  session-bearing controls; the independent driver gets ACs and launch details,
  no source/diff. No passing score is inferred from old unrelated reviews.
- Rollback: revert this isolated prerequisite commit; this restores the known
  shared-state defect, so it is an operational rollback rather than a release
  acceptance outcome. No migration or data rewrite is required.

The isolated branch starts at `0d4df3c0bd4e3b3ca5afa3f2d63bdb3261b118cf`:
`codex/v4-order2-prerequisite`. Gate receipts and full command logs are retained
under the external release evidence directory as `order2-prerequisite-*`.


### Complete named DoR gate inventory (finder repair)

This is the security-mandate path, with no claim of financial NPV or novelty.
The canonical file's enumerated IDs total **72**, although its heading says 84:
22 G + 5 B + 9 T + 17 C + 8 P + 7 L + 4 O. All 72 named IDs are accounted for
below; no twelve invented gates are marked complete. Of these, 50 apply and 22
are N/A. Pending DoD execution is not represented as a passing DoR result.

| IDs | Applicability and readiness evidence |
|---|---|
| G0–G5 | Apply: release mandate and CI dependency demonstrated by run 34062367993; Q4 approved. Fixed planning estimate for gate recovery: 220,000 input tokens and 16,000 output tokens, including reviews and validation interpretation; at the canonical $15/M input + $75/M output rates, $3.30 + $1.20 = **$4.50**. Allow 1–2 hours including approximately 15 minutes of context restoration and review handoffs. These are estimates, not measured billing or a claim about actual vendor rates. NPV/ROI dollar calculation is N/A under the security mandate. Minimum repair is two owner guards; no optional redesign. |
| G6–G12 | Apply: owner guards versus silent no-op/principal re-keying already compared in §4; same-session and cross-session impact plus overbroad legacy refusal identified; the cheapest high-risk assumption is now tested on a rebuilt base: B08/B09 assertion RED, one staging control green, actual exit101 in `order2-prerequisite-base-red-r2.log`. Required runtime dependencies are in base. |
| G13, G14, G15, G18, G20, G21 | N/A: no novel technology, optimization, emerging-tech bet or moat claim; bounded security repair estimated below four hours, so G15's hotfix exception applies. |
| G16, G17, G19 | Apply: four primary prior-art sources and the NIH decision are cited in the focused evidence below; reproduce the observed failure rather than invent a new mechanism. Revert is possible without migration. User outcome is stable tool membership and explicit refusal for sessionless clients, measured by all four discovery surfaces. |
| B1–B5 | Apply: existing MIK-7272, High, 8 points, mcp-gateway project, Mikko team, v4.0.0 milestone, In Progress, prioritized prerequisite for PR483. Coordinator completed and read back Mikko as owner, Bug+mcp-gateway labels, and all five stable FSM criteria in the existing description; `order2-linear-prerequisite-readback.json` retains the full receipt. Original scope and relations are preserved. B2/B4 metadata readiness is verified. This is an increment of that ticket, not a new orphan issue. |
| T0, T1, T2, T4, T5 | Apply: reliability/security fix in the existing Rust gateway; reuse the proven helper and protocol error type. No technology switch is warranted at a two-guard boundary; it would add deployment/review cost without improving this invariant. Direct callers verified by GitNexus and static source: one write handler and four discovery readers. |
| T1b, T1c, T3, T6 | N/A: no emerging-tech claim, crypto, framework selection, numeric/collective processing. |
| C1–C12, C14–C16 | Apply: one existing helper per invariant, no new API/schema/dependency/cycle; the reviewed plan has red drivers and independent read/write falsifiers. Trust boundary is the unauthenticated/sessionless request context; no user label becomes identity. Existing locked session store retains strong per-key ownership for non-empty callers. The compatibility refusal is Q4-approved. Existing protocol envelopes and version routing remain intact; memory/state capacity decreases for forbidden keys. Source delta target is under 400 lines. Pre-existing large parent modules are not expanded with a new production abstraction. |
| C13, C17 | N/A as readiness gates: C13 explicitly moved to DoD mutation evidence (planned, not passed); no new cross-service failure mechanism or resilience policy. |
| P1, P2, P4, P6, P7 | Apply: existing observable JSON-RPC refusal/trace path; tested binary rollback planned; no additional stored state, data migration, or capacity dependency; reuse the exact already-reviewed integration-branch CI selector from bfa16dc3 and obtain this PR's own head-bound run. |
| P3, P5, P8 | N/A: no feature flag or new service/SLO/alert threshold is introduced; this is the operator-ratified invariant at existing endpoints. |
| L1 | Apply: owned source is PolyForm-Noncommercial-1.0.0, not MIT; preserve each header. Actual header check, current 453-package license inventory, CycloneDX 1.5 SBOM, AGPL scan and identical-lock CI vulnerability audit are recorded below. No new dependency, algorithm or license/patent claim. |
| L2–L7 | N/A: no new personal data, AI feature, transfer/residency flow, license set, device contribution, or crypto/ML distribution. |
| O1–O3 | Apply: separate owned worktree, scoped changes, existing design/test-plan SSOT, evidence outside source; owned build artifacts cleaned after handoff. |
| O4 | N/A: no one-way architectural decision requiring a new ADR; existing option (c) and Q4 decision are retained. |

**DoR summary:** mandate-justified NPV/ROI N/A; estimated recovery cost above;
72/72 named IDs assessed (50 applicable, 22 N/A; canonical heading says 84).
Readiness remains **pending GPT finder confirmation** of the remaining G16 arXiv citation and L1 scoped patent-search record; G2/C6 and the other G16/L1 audit items closed in r3; Grok r2 closed its NOW findings with SHIP, actual exit 0. Evidence counts: E1 four declarations (scope, AC contract, rollback, fixed effort/cost estimate); E2 eight citation groups (four prior-art sources, original decisions, reviewer ledgers, live tracker, source owners/callers); E3 nine output groups (four symbol impacts, rebuilt baseline RED, license-header check, current metadata/AGPL inventory, CycloneDX output, identical-lock CI audit); E4 three records (existing design, existing test plan, focused STRIDE/auth/input record below).
No DoD final approval or functional pass is implied by this readiness inventory.


### Focused readiness evidence: G16, C6 and L1

**G16 — prior art and NIH decision (checked 2026-09-07).**

1. [Rust `Option::filter`](https://doc.rust-lang.org/std/option/enum.Option.html#method.filter)
   specifies preservation of `None` and predicate-based removal of `Some`. This
   is the existing `session_key` mechanism; no replacement abstraction is needed.
2. [MCP 2025-11-25 session management](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#session-management)
   specifies server-assigned session identifiers and subsequent client use. It
   grounds the non-empty legacy compatibility control; it does not establish the
   newer HTTP decision, which is the separately ratified Q4 contract.
3. [Pinned gateway prior art at base 0d4df3c0](https://github.com/MikkoParkkola/mcp-gateway/blob/0d4df3c0bd4e3b3ca5afa3f2d63bdb3261b118cf/src/gateway/meta_mcp/mod.rs#L1095)
   already filters empty keys for neighboring per-session behavior. Reuse that
   helper in the two FSM owners; existing profile refusal demonstrates the same
   explicit error boundary. Local pinned source was inspected.
4. [Calzavara et al., Language-Based Web Session Integrity, arXiv:2001.10405v2](https://arxiv.org/abs/2001.10405v2)
   studies server-side session integrity with a security type system and real
   application analyses. It motivates checking both the mutation boundary and
   discovery observations. The application to these guards is an engineering
   inference; this increment does not adopt that type system or claim a formal
   proof. The existing predicate remains the smallest mechanism.

**C6 — security record.** Trust domain: unauthenticated or authenticated request
contexts may be sessionless; session identifiers are state keys, not principals.
Existing router authentication/authorization remains authoritative. Inputs are
optional internal session IDs, the state argument, and protocol/session headers
already normalized by transport handling. State is local in-process, partition
handling is unchanged, and the locked per-key store retains strong ownership.
No crypto algorithm, signature, key exchange, randomness or credential generation
changes; crypto/PQC applicability is N/A.

| STRIDE concern | Mitigation in this bounded change |
|---|---|
| Spoofing | An empty key cannot create a session identity; existing authentication remains unchanged. |
| Tampering | Reject unkeyed FSM writes and ignore a pre-existing empty-key state on every reader. |
| Repudiation | Preserve the JSON-RPC request ID and explicit protocol error; never acknowledge a refused state mutation as success. |
| Information disclosure | Prevent one sessionless caller from changing another caller's discoverable membership; refusal adds no secret data. |
| Denial of service | Rejected empty-key writes allocate no persistent entry; normalization is one constant-time empty-string check. Existing request limits remain. |
| Elevation of privilege | Refusal grants no permissions; non-empty state ownership and existing authorization continue unchanged. |

These are design mitigations; their behavioral tests and fault checks are pending,
not represented as completed security testing.

**L1 — actual audit evidence.** `order2-prerequisite-license-audit.json` binds the
following artifacts to base `0d4df3c0` and the identical lockfile used in the
passing CI audit. `bash scripts/ci/check-license-headers.sh` passed (exit 0): all
first-party headers match the existing per-file license boundary. The affected
meta-MCP files carry PolyForm-Noncommercial-1.0.0; new tests must preserve it.
Current `cargo metadata --locked --all-features` succeeded and enumerates 453
packages: no AGPL expression and no missing dependency license; the only package
using a license file is this workspace's `LICENSES.md`. The snapshot includes
existing MPL and optional LGPL alternatives; this increment adds no dependency
or distribution. `cargo cyclonedx` 0.5.9 with `--all-features --target all --all
--format json --spec-version 1.5` passed (exit 0), producing a 399-component
runtime/build dependency SBOM in `order2-prerequisite-bom.json`; the broader
metadata inventory also covers development dependencies.

[CI audit job 101565032105](https://github.com/MikkoParkkola/mcp-gateway/actions/runs/34062367993/job/101565032105)
passed against byte-identical Cargo.toml/Cargo.lock, scanning 453 crates using
1,239 advisories. It reported one allowed, pre-existing warning: **chacha20 0.10.0
is yanked**. The warning and full log are retained, with no policy change or
claim of a warning-free audit. A scoped patent search is recorded in `order2-prerequisite-prior-art-search.json`:
query `site:patents.google.com "session identifier" "empty" session state`.
[US9058214B2](https://patents.google.com/patent/US9058214B2/en) describes pooling,
checking out and returning session tokens to reuse established sessions.
[CN103095859B](https://patents.google.com/patent/CN103095859B/en) describes sharing
session information across domain names through a synchronization system. These
technical features are outside the proposed delta: two calls to an existing
empty-key predicate, a protocol refusal and default reads. No token pool,
credential exchange, synchronization system or cross-domain session sharing is
added. This is a scoped technical comparison of the retrieved publications,
not a conclusion that patents do not exist or a freedom-to-operate opinion.
No new algorithm or patent/license claim is introduced. The unavailable
`cargo license` attempt and incomplete offline metadata attempt are superseded
by the successful current metadata and installed CycloneDX tool, with failures
retained in the audit receipt. This PR still requires its own CI run before merge.

Evidence locator for this increment: `/Users/mikko/Documents/Codex/2026-09-06/mcp-gateway-v4-scope-review/order2-prerequisite-evidence-index.json`. It names exact artifact paths and SHA-256 values; each review manifest also binds its own immutable material.


Readiness closure: GPT r4 SHIP (actual exit 0, material
`a447e2ffa0668d1464ff3db148cec39fc97b0830afc0b6c52271f50414d2b16b`,
12,264 bytes) closes the remaining arXiv/patent findings; Grok r2 SHIP is retained.
`order2-prerequisite-plan-closure.json` preserves each finder and original lineage.
Test r1 compiled with four assertion failures and two controls passing. Grok
reviewed those tests SHIP; GPT requested two caller regressions. This adjusts
only test coverage of the existing FSM.3/.5 contract, with the coordinator's
approval; the two-owner production repair and all OUT boundaries stay fixed.
