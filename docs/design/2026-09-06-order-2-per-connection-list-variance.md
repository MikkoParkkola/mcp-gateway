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
prepare. Whether that lowers the criterion's severity was Q2, answered on
2026-09-06: it does not (§6). Not a reason to leave it.

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
Two writes and two reads — but only **after** a duplication is removed, and that
removal is part of (c) rather than a tidy-up beside it:

| store | write | read |
|---|---|---|
| `session_promoted` (§2, feature-gated) | `invoke.rs:1826-1828` | `promoted_tools_for_session`, `mod.rs:1021-1030` — the only reader of the map; `mod.rs:1266`, `mod.rs:1330` and `spec_preview.rs:112` all go through it |
| `session_state` (§2b, **default build**) | `mod.rs:1689` | `current_search_state`, `search.rs:161-165` — **plus two inlined copies of its body**, `search.rs:581-584` in `list_tools_single_server` and `search.rs:647-650` in `list_tools`, which call `self.session_state.get_state(sid)` directly |

The promotion store already has one owner per direction. The FSM store does not:
the same `map_or_else(DEFAULT_STATE, get_state)` expression is written out three
times, and `session_key` applied only to `current_search_state` would leave
`gateway_list_tools` reading the shared entry on both of its paths while
`gateway_search_tools` and code-mode search were fixed — a guard that holds on
some surfaces and not others, which is the defect this note is about, one level
down. So (c) folds `search.rs:581-584` and `search.rs:647-650` into
`current_search_state` first, and then filters inside it. Three sites become one,
and the finding stops being restatable rather than being patched three times.

Each store is then routed through `session_key` at one read and one write, so a
sessionless caller neither writes to nor reads from either. A modern connection then sees the unpromoted list
and the default workflow state, always, and an invoke has no effect on either.

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

## 6. Questions put to the requester — all three settled

None remain open. Recorded here because a question that was asked and answered is
evidence; a question that quietly stopped being asked is not.

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

## 7. Test plan — one row per clause

The cases live in `docs/design/2026-08-31-cluster-b-connection-invariance-test-plan.md`
and are **not** restated here. This table maps each clause to the case that
proves it and, per §P2's second question, states how each case can FAIL — a case
that cannot fail proves nothing.

**New cases continue the `B-` series** (`B-08`, `B-09`, `B-10`). An earlier draft
called the two FSM cases `S-01` and `S-02`; those ids are already taken in that
plan by the `SUB.2` cases — `S-01` is POST content negotiation, `S-02` is
notification forwarding (`:57-58`, `:206-223`) — and an implementer following the
collision would have overwritten or split existing coverage.

| clause | leg | case | level | how it can FAIL |
|---|---|---|---|---|
| 2a — must not vary per connection | routing profile | **B-01**: two modern connections, one binds `X-MCP-Profile`, both tool-name sets compared against the same pinned literal | integration | The binding connection's list differs from the other's, or either differs from the pinned literal. Because the expectation is a pinned literal rather than a comparison of the two lists, a regression that changes *both* connections identically also fails, which a two-way equality assertion would miss. |
| 2a | spec-preview promotion | **B-07, and it must be repaired before it covers this**: as written in the sibling plan (`:187-204`) the case cannot fail against the defect §2 describes. Its premise promotes tool `T` for a **legacy-era** session A and observes it in A's legacy list; the two modern lists it then pins are read under the key `""`, which that promotion never touched, so the case stays green whether or not modern connections share promotions. The repair: drive the promotion through **a modern connection's own successful `gateway_invoke`** (`invoke.rs:1826-1828` writes under `Some("")`), drop the reverse-A5 legacy premise, and pin both modern lists to a literal that excludes `T` | integration | After the repair: `T` appears in the other modern connection's list — which is what happens today, because both read `""`. Before the repair it can fail on nothing, which is the finding. The fixture must not stub `promote_tool_for_session`, or the case asserts against its own fixture rather than production. |
| 2a | spec-preview preview list | **B-06**: B-01 re-run under `--features spec-preview` with a pinned match-all `params.query` | integration | The two modern connections' filtered lists differ from each other or from one pinned **filtered** literal. Not "differs from the default build's list" — an earlier draft said that, and it cannot hold: `handle_tools_list_filtered` deliberately omits the meta-tools from a filtered response (`spec_preview.rs:28-29`), so the two builds are *expected* to differ and a case asserting otherwise stays red after a correct fix. Covers `spec_preview.rs:46`. Runs only in a job that enables the feature; a suite that never enables it reports green while proving nothing, so the feature-enabled job is part of the case, not an optional extra. |
| 2b — must not vary as a side effect of other requests on the connection | routing profile | **B-02**: `tools/list`, then `gateway_set_profile`, then `tools/list`; both lists compared to the same pinned literal | integration | Either list differs from the literal. Note the case must assert on the *lists*, not on the `gateway_set_profile` response: that call now returns `NO_SESSION_FOR_PROFILE` (§1 fact 4), and a case that asserts only the refusal would pass even if the lists diverged. |
| 2b | spec-preview promotion | **new — B-10**: repaired B-07 covers the cross-connection half; the same-connection half is its own case, the sequence `tools/list` → successful `gateway_invoke` → `tools/list` on one modern connection, with **both** lists asserted against the same pinned literal and the invoke asserted to have succeeded. Feature-gated: it runs only in the `--features spec-preview` job, on the same terms as B-06 | integration | Either list differs from the literal, or the invoke did not succeed. Asserting the two observed lists against each other would pass both when the invoke silently failed (nothing was promoted, so nothing changed) and when a regression moved both lists in step; the pinned literal and the invoke assertion are what remove those two green-while-broken paths. This is the direct statement of 2b and fails against §2 today. |
| 2a | FSM workflow state (§2b) | **new — B-08**: connection A calls `gateway_set_state` to a non-default state; connection B, opened independently, calls **`gateway_list_tools` and `gateway_search_tools`** — both, and not `tools/list`, which reads this store on no path (§7 matrix) — and each result is compared against the pinned default-state literal | integration | B's set differs from the literal — which is what happens today, because A wrote under the key `""` and B reads the same entry. Fails in the **default build**, no feature flag needed. It cannot pass by construction: the fixture must drive the real `gateway_set_state` meta-tool, since the defect is the argument at `mod.rs:1689`, and a fixture calling `SessionStateStore::set_state` directly bypasses the line under test. |
| 2b | FSM workflow state (§2b) | **new — B-09**: on one modern connection, `gateway_list_tools` → `gateway_set_state` → `gateway_list_tools`, and the same sequence again through `gateway_search_tools`, each list compared against the same pinned literal | integration | Either list differs from the literal. Note this case's expected behaviour changes under (c): today the second list differs; after (c) the `gateway_set_state` call is *refused*, and the case must assert the refusal **and** the unchanged lists, exactly as B-02 does for `gateway_set_profile` — asserting only the refusal would pass while the lists diverged. |

**Does every criterion have a case, or a stated reason it has none?** The
criteria are two, `MIK-7272.ORDER.2a` and `.2b`, and since Q3 reads them as *what
tool set a connection is shown*, each has to be answered on both surfaces that
show one: `tools/list` and the discovery surface. That is six cells rather than
three legs, and the legs do not each reach both surfaces — which is why some
cells are empty on purpose:

| leg | reaches `tools/list` | reaches the discovery surface | cases |
|---|---|---|---|
| routing profile | yes — `mod.rs:1263`, `spec_preview.rs:47` | yes — `search.rs:376,629,728`, `surfaced.rs:107` | B-01 (2a), B-02 (2b), on `tools/list` |
| spec-preview promotion | yes — `mod.rs:1330`, `spec_preview.rs:112` | **no reader**: `promoted_tools_for_session` is not called from `search.rs` or `surfaced.rs` at all | B-07, B-06 (2a), the 2b sequence |
| FSM workflow state | **no reader**: nothing on the `tools/list` path reads it | yes, and only here — four entry points: `code_mode_search` (`search.rs:378`), `search_tools` (`:730`), and `list_tools` / `list_tools_single_server`, which today read the store directly (`:647-650`, `:581-584`) | B-08 (2a), B-09 (2b) |

Two of the empty cells need no case, because there is no behaviour in them to
assert: promotion has no discovery-surface reader, and the FSM state has no
`tools/list` reader. The third is a judgment and is recorded as one — the
profile leg **on the discovery surface** has no case of its own. The reason is
that the guard is inside `active_profile` (`mod.rs:1062-1099`), one owner for all
eight of its call sites, so a discovery duplicate of B-01 would drive the same
line B-01 already drives and could not fail independently of it. That reason is
conditional on where (c) puts its filter: if the implementation guards at the
call sites rather than inside the accessor, the cell stops being empty and the
two cases are owed.

The same condition binds B-08 and B-09, and more sharply, because the FSM store
is **not** single-owner today. Each drives one discovery entry point, and that is
sufficient only because (c) folds `list_tools` and `list_tools_single_server`
back into `current_search_state` before guarding it. If that fold is skipped and
`session_key` is applied to the accessor alone, B-08 and B-09 go green while
`gateway_list_tools` still reads the shared entry — a case passing over a live
defect, which is precisely what §P2's second question exists to prevent. Written
as a rule for whoever implements it: **the fold is load-bearing for the tests,
not cosmetic.**

Three additions to the existing plan, then: B-10, B-08 and B-09. Two properties the plan should keep visible. Every case pins a **literal**
expected tool-name set rather than comparing two observed lists, so a change
that moves both connections in step is still caught. And every case must drive
the real meta-tool path — the defects live in the arguments passed at
`invoke.rs:1826` and `mod.rs:1689`, and a fixture that calls
`promote_tool_for_session` or `SessionStateStore::set_state` directly bypasses
exactly the line under test.

## 8. What this note does not close

ORDER.2a and ORDER.2b are **not** satisfied by this note. It is design only: no
code changed, no test was added, and the promotion leg in §2 is open in the
source as of 682a709a. The ledger rows stay blocking. What has changed is what
the evidence cell can now say: the profile leg is closed in code and measured
here, the remaining defect is **two stores and four call sites** — the
feature-gated promotion store of §2 and the default-build FSM state store of §2b
— and the option to close both is chosen and priced. §2b belongs to ORDER.2
itself, per Q3's answer of 2026-09-06; it would have been the same defect under
either reading.

One coverage limit, found by review and worth more than the rest of this note:
**(c) closes both legs on modern HTTP and neither of them on stdio.** stdio
dispatches under the fixed non-empty id `"stdio-session"`
(`server/mod.rs:1604,1822-1824`), which passes `session_key` untouched, so an
invoke on a stdio connection can still promote into that connection's next list —
2b, live, after the recommended fix. §P0 puts transport parity with cluster-g and
this note does not price it; what this note owes cluster-g is the measurement,
which is now in §5 rather than sitting in the deferred column as a question.
