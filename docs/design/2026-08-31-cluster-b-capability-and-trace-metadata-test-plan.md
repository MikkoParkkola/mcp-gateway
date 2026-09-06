# Cluster B — test plan (MIK-7272 EXT.1, OTEL.1)

Status: §P2 test plan, awaiting dual-vendor review. No test code. Design:
`docs/design/2026-08-31-cluster-b-capability-and-trace-metadata.md` (§P1, reviewed,
SHIP-WITH-FIXES from both vendors, findings disposed in that document).

Two decisions are settled upstream and are premises here, not questions this plan re-opens:
the `extensions` map is populated from **implemented** extensions only — today the empty set —
and `gateway_declares()` stays TASK.1's payload. A row asserting a populated `extensions` would
assert something this release does not ship.

## 0. What this plan is for, and what it is not

FOR: one case per acceptance-criterion clause of EXT.1 and OTEL.1, each with a V-model level, a
test type, and a statement of what makes it able to fail.

OUT: test code (§P2 writes it after this plan is reviewed); any criterion outside EXT.1/OTEL.1;
the operator questions at design §4.4 — a plan cannot answer them and does not pretend to.

## 1. Criterion decomposition, and why rows are clauses

The requirements file carries two rows — `MIK-7272.EXT.1` and `MIK-7272.OTEL.1`
(`docs/requirements/RELEASE-4.0.0-requirements.md:196-197`). Both are compound MUSTs: EXT.1 says
*declare* **and** *honour a non-supporting client*; OTEL.1 names three fields and, through design
§3.4, four rules about them. A two-row plan would let a case prove one clause and score the
whole criterion, which is the coverage-map failure this step exists to prevent.

So each criterion is decomposed into clauses with stable IDs. Every clause traces to a sentence
in design §7 ("What closing these criteria requires") or to a MUST in the criterion text. The
parent criterion closes only when **all** its clause rows are green.

| clause | the obligation, in one line | source |
|---|---|---|
| EXT.1.a | `ServerCapabilities` carries an `extensions` field and it reaches the wire on both entry points | design §2.3, §7 |
| EXT.1.b | the map is populated from implemented extensions only; today it is empty, and an empty map serialises to an ABSENT key, not to `{}` | design §3.1a, §3.1b |
| EXT.1.c | the client's `ExtensionSet` is recovered from the **raw** `_meta[KEY_CLIENT_CAPABILITIES]` object, not from `declared_capabilities` | design §2.4, §3.2.A |
| EXT.1.d | absent extension ⇒ revert to core behaviour; never refuse the request | criterion text; design §3.2 |
| OTEL.1.a | the three W3C fields are read from the inbound **params-level** `_meta` — the carrier `CallToolRequestParams` specifies — on every route that can carry one | criterion text; design §3.4, corrected by §2.7 and §7 |
| OTEL.1.b | they are written into the outbound `_meta` at `dispatch_to_backend` **unconditionally**, merged with the cache key when one exists | design §3.4a |
| OTEL.1.c | never minted — absent or rejected inbound context yields no outbound field | design §3.4; `trace.rs:12-13` |
| OTEL.1.d | `baggage` propagates independently of `traceparent` | design §3.4 |
| OTEL.1.e | each field is bounded and charset-checked; a failing field is dropped, never repaired, and never fails the request | design §3.4, §4.2 |
| OTEL.1.f | the `traceparent` predicate matches the W3C grammar in the four places §3.4b names | design §3.4b, F7 |
| OTEL.1.g | no trace value reaches routing, backend selection, authorisation, policy, cache keys or budget | design §3.4 |
| OTEL.1.h | the three fields survive one real gateway→backend hop end to end | criterion text ("across the gateway hop") |

## 2. The assertion rules this plan was swept against

A1 pinned number asserts both sides · A2 pinned shape asserts the exact key set · A3 a set
assertion says what DID arrive · A4 a count also names identities · A5 the fixture lets the rule
under test be the thing that decides · A6 a relative rule needs a relative fixture · A7 a named
constant is proven only by changing it · A8 never assert a value against the expression that
produces it · A9 a fixture breaks one thing at a time.

Sweep performed before this document's first review; the violations it found are recorded at §6,
not silently fixed, because two of them changed what a case must do.

## 3. EXT.1 — the coverage map

| clause | case | level | type | red on HEAD? |
|---|---|---|---|---|
| EXT.1.a | **E1** `build_initialize_result` is called with a **non-empty** implemented-extension source and its result serialised to `serde_json::Value`; assert its **`capabilities`** member's key set contains `extensions` and that the value is a JSON **object** (not null, not a string). Repeated against `discover_document`'s `capabilities` member so both entry points are named, not inferred from the shared builder. The source must be non-empty: the field is `skip_serializing_if = "HashMap::is_empty"`, so an empty source emits no key and the presence assertion would fail against correct code. | unit | contract / serialisation | **No — green at 10a61c21.** `ServerCapabilities.extensions` exists (`types.rs:256`), `build_server_capabilities` is fed from `implemented_extensions()` (`meta_mcp_helpers.rs:147,158,190`), and `discover_document` (`meta_mcp/mod.rs::discover_document`) reuses those capabilities verbatim. **Retrofit — falsifier probe required (§3.1).** |
| EXT.1.b | **E2** with the gateway's implemented-extension source empty, assert the serialised `capabilities` object does **not** contain an `extensions` key at all, and that a 2025-era client's initialize result is byte-identical to the pre-field result. The field carries `#[serde(default, skip_serializing_if = "HashMap::is_empty")]` (`types.rs:255`) deliberately: MIK-7217 AC discover-3 requires a byte-identical initialize result for an already-supported protocol version, so an always-present key is a breaking handshake change however empty it is. **An earlier revision of this row demanded the opposite — key present, value exactly `{}`, no `skip_serializing_if`. Written that way the case asserts a regression.** | unit | contract / serialisation | **No — green at 10a61c21**, and green for a second reason: absence is also what an unwired field emits. **See §4.1 — on its own this case cannot distinguish a wired populate from a defaulted field. Retrofit — falsifier probe required.** |
| EXT.1.b | **E3 (the discriminator)** call the builder with an implemented-extension source containing one synthetic identifier `example.test/probe`, and assert the wire carries `{"example.test/probe": {}}` — key identity asserted as a literal (A4, A8). Then the empty-source case E2 is meaningful, because the same code path demonstrably varies with its input. | unit | contract, A7 constant-perturbation | **No — green at 10a61c21.** `build_server_capabilities` already takes the map as an **argument** (`meta_mcp_helpers.rs:158`), which is exactly what §5.1 demands, so the perturbation is writable as specified. The source must be a **map of identifier strings**, not an `ExtensionSet`: `ExtensionSet` can only hold `Extension` variants, so a probe identifier is unrepresentable in it and the perturbation collapses. Substituting `Extension::Tasks` here is forbidden — it makes the case pass against an implementation that simply wired `gateway_declares()`, which is the wiring §0 puts out of scope. **Retrofit — falsifier probe required, and it is the one probe that carries the section: mutate the builder to ignore its argument and E3 must fail on the literal-identity assertion.** |
| EXT.1.c | **E4** drive a **production entry point** — a `tools/call` request through the router, not a direct call to `from_capabilities()` — whose params-level `_meta["io.modelcontextprotocol/clientCapabilities"]` is `{"extensions": {"io.modelcontextprotocol/tasks": {}}}`; assert at the invoke funnel that the recovered extension set contains `Extension::Tasks`. The identifier must be a **recognised** one: `from_capabilities()` filters through `Extension::from_id` (`extensions.rs:71-90`), so a synthetic identifier is discarded **by a correct implementation** and a case asserting its recovery could never go green. Assert against the literal identifier, never against `from_capabilities()`'s own output on the same input (A8). **The entry point is the whole point of this row: a unit case calling `from_capabilities()` directly stays green while the function has zero production callers, which is exactly the state HEAD is in.** | integration | parsing, production-path | Yes — `from_capabilities()`/`negotiate()` have zero callers outside `extensions.rs` (V 2026-09-07, `rg -n 'from_capabilities\|negotiate\(' src/`). |
| EXT.1.c | **E5 (the anti-`declared_capabilities` case)** same production entry point, same identifier, **non-object settings**: `{"extensions": {"io.modelcontextprotocol/tasks": 3}}`. Assert the set recovered **at the invoke funnel** is empty. A correct implementation drops it on the `settings.is_object()` filter (`extensions.rs:78`); an implementation that reached the same answer through `declared_capabilities` keeps it, because that path discards values and filters only nulls (`meta.rs:186-190`) — `3` is not null. Paired with E4, which must stay non-empty. This is the pair that distinguishes the two implementations; E4 alone does not, and the value must be non-null or both paths drop it and the discriminator collapses. | integration | negative / discrimination | Yes. |
| EXT.1.d | ~~**E6** behavioural revert~~ — **withdrawn at review.** With no extension-gated behaviour shipped, "reverted to core" and "never consulted the client" are output-identical: ordinary `tools/call` already succeeds. The case was marked red on HEAD and is not. **No case. See §6.5.** | — | — | **No.** |
| EXT.1.d | **E7** the refusal-shape negative: same request, assert the response is **not** a JSON-RPC error and no error code is emitted. Paired with E6 because "revert" and "reject" are the two spec-permitted answers and the design chose revert; a case asserting only success would also pass a build that never consulted the client at all. E7's value is bounded — see §4.2. | integration | negative | No, on its own. Recorded as such rather than counted. |

### 3.1 E1/E2/E3 are retrofits, and a retrofit owes a falsifier probe

E1, E2 and E3 assert against code that already shipped (`ServerCapabilities.extensions` landed before this plan was written). A test written after the code cannot borrow the free failure a test-first case gets, so each one owes the probe `development-process.md` §P2 prescribes: restore the **pre-field content** of the file under test, run the case, and read the **assertion** that fails — not the exit code, because a missing-import error is not a caught defect. Then restore the repair and re-run to confirm it goes green.

The restore must be of content, not of working-tree state. `git stash` around a committed change removes only later edits; `git checkout -- <path>` discards an uncommitted repair. Use `git show <pre-fix-ref>:<path>`, under a `trap` that copies a `mktemp` backup back on `EXIT INT TERM`.

**`<pre-fix-ref>` is pinned, not left to the runner.** A recipe naming no ref is decorative — it
cannot be run as written, which is the empty cell this section exists to forbid. The two refs, both
found with `git log -S` against the file under test rather than assumed:

| what the probe restores | ref | why that one |
| --- | --- | --- |
| `src/protocol/types.rs` without `ServerCapabilities.extensions` | `6daf020f^` (parent of `feat(capabilities): declare the extensions map in server capabilities`) | `6daf020f` is the commit that added the field; its parent is the last tree in which the field does not exist. Verified: `git show 6daf020f^:src/protocol/types.rs` contains no `pub extensions`. |
| `src/gateway/meta_mcp_helpers.rs` with the builder unwired | `6daf020f^` | the same commit rewrote `build_server_capabilities` to take the map as an argument, so one ref restores both halves of the retrofit. |

Do **not** reach for `f8fcbcb1` (`fix(protocol): omit empty extensions from server capabilities`)
as the pre-fix ref. It added `skip_serializing_if = "HashMap::is_empty"` a day after the field
landed; restoring its parent gives a tree where the field exists and always serialises, which is
the state E2 was inverted to reject (§3, E2) — a probe against it would show E2 failing for the
right reason on the wrong question. `f8fcbcb1` is the ref for a probe of the **omission** rule
itself, and nothing in E1-E3 asserts that rule directly.

E3 is the probe that carries the section. E1 and E2 both survive a builder that ignores its argument — E1 because a hardcoded non-empty map still emits the key, E2 because absence is also what an unwired field emits (§4.1). Only E3 pins identity: mutate `build_server_capabilities` to ignore the map it is handed, and E3 must fail on the literal `example.test/probe` assertion. A probe run on E1 or E2 alone is evidence of nothing.

Needing this section at all means §P2 was skipped for EXT.1.a-b. It is a recovery mechanism, recorded as one.

## 4. Where a case cannot distinguish two implementations — said plainly

### 4.1 The empty-set trap: an absent `extensions` key proves less than it looks

`implemented_extensions()` returns an empty map today (`meta_mcp_helpers.rs`), and the field
carries `skip_serializing_if = "HashMap::is_empty"` (`types.rs`), so the wire currently shows **no
`extensions` key at all**. That absence is what a correctly wired populate emits, and it is
**also** what a field that was declared and never populated emits. Design §3.1b names this a
silent-success shape. Restated as a test fact:

- E2, asserting the key is **absent** from `capabilities`, passes against the wired
  implementation.
- E2 also passes against a one-line struct addition with no builder assignment at all.
- E2 therefore proves the **field exists and stays quiet while empty**, not that the **wiring
  exists**. It is a real case for EXT.1.a and a vacuous one for EXT.1.b.

An earlier revision of this section asserted the shape was `extensions: {}` and blamed
`..Default::default()`. Both were wrong at source and are corrected here: `extensions` is
**explicitly assigned** in `build_server_capabilities`, so `Default` never reaches it, and the
serde attribute means an empty map produces silence rather than `{}`. The trap survives the
correction unchanged — it never depended on which empty shape reached the wire, only on wired and
unwired producing the *same* one.

The only honest discriminator is E3: perturb the input, require the output to change (A7). It
converts E2 from "the key is absent" into "the key is absent **because the source is empty**",
which is the clause's actual claim. If the implementation makes the source non-injectable, E3
becomes impossible and **EXT.1.b has no honest case** — the plan would then carry an empty cell,
not a weaker assertion. §5.1 states the requirement that keeps that from happening. That
requirement is currently met: `build_server_capabilities` takes the map as a parameter, and its
own doc comment names this section as the reason.

A second thing E2/E3 cannot see: whether the empty declaration is *correct*. It is honest only
because no extension is implemented today. Nothing in this suite would catch a future change that
implements an extension and forgets to register it — the key would still be absent and every case
would stay green. That guard belongs to TASK.1, which adds the first entry, and this plan records
it as inherited rather than claiming coverage it does not have.

### 4.2 E7 is a weak case and is labelled one

E7 asserts an absence (no error). An implementation that never reads client capabilities and
always runs core behaviour satisfies it. It was drafted as the paired half of E6, and **E6 has
since been withdrawn** (§6.5), so E7 now stands alone and its weakness is worse, not better: on
its own it says only "not a refusal", and it cannot say "reverted", because there is nothing to
revert from. It is kept because the revert-versus-reject choice is a real one the design made and
the spec permits both — but it is recorded as non-discriminating so a later reader does not
mistake it for evidence of negotiation. Nothing else in this suite discriminates EXT.1.d: E5 is
EXT.1.c's case (the set is recovered from the raw object) and must not be counted here as well,
which is exactly what §6.5 refuses. The behavioural half has **no case at all** until TASK.1 gates
something on an extension.

## 5. OTEL.1 — the coverage map

Every row below states its fixture direction explicitly, because the propagation trap is a
fixture trap: a case that seeds the **outbound** `_meta` and then asserts the value survives has
verified serde, not the hop. In every case **in this section's table** the trace values are placed
**only** on the inbound request body. The *observation* point is not uniform and the earlier
version of this sentence said it was: T1-T9 assert on the **outbound** params object
`dispatch_to_backend` produces; **T0 asserts on the production extractor's recovered values**,
which is the read side and the whole reason the .a/.b split exists; and **T10 asserts on the
cache key and the resolved backend and tool**, because non-interpretation is observable there and
nowhere in the outbound object. Fixture direction is what this paragraph fixes for the whole
table; observation point is stated per row. §5.2 keeps the fixture direction and moves the observation
point; it says so there, because a preamble that claimed to cover it would be false.

The red/green column below rests on one verified statement of HEAD, re-checked at source on
2026-09-06 rather than carried forward. `src/protocol/trace.rs` carries both halves of the
mechanism and carries them **whole**: the struct has a field for each of `traceparent`,
`tracestate` and `baggage` (`:19-24`), `TraceContext::from_meta` (`:33`) parses all three, and
`to_meta` (`:75`) writes all three back out. The `baggage` half landed in `baa318b2` ("carry
baggage across the gateway hop"), an ancestor of HEAD. The extractor is also **called**: the one
production call site is `invoke.rs:1845-1847`, and it reads `args.get("_meta")` — the arguments
map, one level below where the protocol puts `_meta`.

So the gap is neither a missing field nor an unwired function. It is a **carrier and a reach**:
`extract_tools_call_params` (`helpers.rs`) returns `(tool_name, arguments)` and discards the rest
of `params`, and both route call sites destructure exactly that pair — the `tools/call` arm in
`handlers.rs` and `dispatch_single_with_sink` in `server/mod.rs`, so nothing a client puts in `params._meta` reaches
`from_meta` on any path. Rows are red when they assert a params-level read, assert propagation,
or assert a grammar predicate HEAD gets wrong. A row that hands a `_meta` object straight to
`from_meta` and asserts only that its fields parse — `baggage` included — would be **green
today**, and none is written as if it were not.

An earlier revision of this section said the opposite: that `baggage` was absent from the struct
and that `TraceContext` was called nowhere. **Both were true at `5c7e64f4`** — the commit the
companion design pins and evidences every `file:line` against — and both were false by 21:33 the
same evening, when `baa318b2` added the `baggage` field and `d4874a25` wired `from_meta` into
`invoke.rs`. Neither document was careless with its sources. This plan inherited claims that were
correctly evidenced against a commit and then wrote them as statements about **HEAD**, a moving
reference it never pinned, so the tree drifted out from under grades that read as timeless.

Hence the pin, which this plan should have carried from the first draft: **every red/green grade
below is asserted against `b8cfc7e4`, and every check in §12 was run against that
tree on 2026-09-06 — evidenced, not asserted, by §12 check 7.** A later reader re-derives, and does not assume. The corrections above are
recorded in the open rather than quietly overwritten, because what exposed them was running the
checks in §12 — checks a reviewer demanded and this plan had until then only asserted.

| clause | case | level | type | red on HEAD? |
|---|---|---|---|---|
| OTEL.1.a | **T0 (the read case)** feed a whole JSON-RPC request body whose `params._meta` carries the three fields to the **production extractor** the request path uses (`TraceContext::from_meta`, `trace.rs:32`), reached the way the dispatch path reaches it — not by handing the fields in as a separate argument. Assert all three recovered values against the literals. Without this row, .a can be satisfied by an implementation that never reads the request body at all. **The carrier this row reaches, and the two routes that must deliver a body to it, are covered by T11-T15 in §5.2.** | unit | parsing | Yes, on the **reach**, and on no field. Re-verified at source 2026-09-06 (§12): `TraceContext` (`trace.rs:19-24`) has a field for all three and `from_meta` (`:33`) parses all three, so a three-field assertion compiles and the parse itself is green. What is red is the delivery this row's fixture requires — *reached the way the dispatch path reaches it*: `extract_tools_call_params` keeps only `(tool_name, arguments)` (`helpers.rs:190-195`) on both routes (`handlers.rs`, the HTTP `tools/call` arm, `server/mod.rs::dispatch_single_with_sink`), and the one production call site reads `args.get("_meta")` (`invoke.rs:1845-1847`), so no `params._meta` ever arrives. Hand the same three fields directly to `from_meta` and the row goes green while the gap stays open — which is why the fixture is a whole request body, and why .a still needs the route coverage T11-T15 carry in §5.2 and not just this row. |
| OTEL.1.b | **T1 (the hop case)** inbound `_meta` carries `traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"`, `tracestate = "vendor=abc"`, `baggage = "k=v"`, and **no prompt-cache key**. Inbound `_meta` **also** carries an unrelated sentinel key `example.test/poison`. Assert the outbound `_meta` by **exact key set** — the three trace keys with those exact literal strings, and **no** `example.test/poison`. A contains-check passes an implementation that clones inbound `_meta` wholesale, which would relay attacker-controlled metadata to the backend; the exact key set refuses it (A2, and the provenance-strip rule at `invoke.rs:472`). Expected side is a literal, never `TraceContext::from_meta(inbound).to_meta()` (A8). | unit | propagation, positive | **Yes.** The `None` cache-key arm passes `base_params` through with no `_meta` at all (`invoke.rs:1934-1938`). |
| OTEL.1.b | **T2 (the merge case)** same inbound, **with** a prompt-cache key. Assert the outbound `_meta` contains the three trace keys **and** the cache key, by exact key set (A2) — not by "contains traceparent". A merge that overwrites `_meta` wholesale passes a contains-check and fails this. | unit | propagation, regression | Yes. |
| OTEL.1.c | **T3 (not-minted)** inbound `_meta` with **no** trace keys; assert the outbound `_meta` has **no** `traceparent`, `tracestate` or `baggage` key. Asserted as key-absence, not as "value is empty" — a minted root is a non-empty value and would be caught; an empty-string value would not be, so the absence form is the one that discriminates. | unit | negative | Partially. Today no `_meta` is written on the no-cache-key arm, so T3 passes vacuously against HEAD. **See §6.2** — this case is honest only when run beside T1, and the plan records that dependency rather than claiming an independent red. |
| OTEL.1.c | **T4 (rejected ⇒ dropped, not minted)** inbound `traceparent` malformed in exactly one way (A9: `"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7"` — three parts, everything else valid); assert no `traceparent` on the outbound, **and** assert the request still succeeds. Distinguishes drop from both mint and reject. | unit | negative | **Partially — same vacuity as T3.** HEAD writes no `traceparent` on this arm, so both halves are already true. Evidence only beside a green T1. §6.2 governs. |
| OTEL.1.d | **T5 (baggage independence)** inbound carries a valid `baggage` and **no** `traceparent` at all; assert the outbound `_meta` carries the `baggage` literal. This is the case option 3.4.E would fail. | unit | negative-space, discrimination | Yes — re-derived (§12, check 7). Not because `baggage` is absent (check 4 refuted that): outbound `_meta` is written **only** when a cache key is present (`invoke.rs:2545`) and the inbound read is at the arguments level (`invoke.rs:1844`), so the no-`traceparent` arm produces no outbound `baggage` today. |
| OTEL.1.d | **T6** inbound carries a **malformed** `traceparent` and a valid `baggage`; assert `baggage` survives and `traceparent` does not. Separates "baggage independent of *absent* traceparent" (T5) from "independent of *rejected* traceparent", which is a different code path. | unit | negative | Yes. |
| OTEL.1.c | **T5b / T6b (tracestate is *not* independent)** the inverse pair, and the design makes it load-bearing: inbound carries a valid `tracestate` with **no** `traceparent` (T5b), then with a **malformed** `traceparent` (T6b). Assert `tracestate` is **absent** outbound in both, and the request still succeeds. `tracestate` is meaningless without the parent it annotates, so relaying it orphaned would send vendor trace state to a backend with nothing to correlate it to. Without these rows the plan asserts independence for `baggage` and says nothing about the field that must *not* be independent. Filed under **.c, not .d** — .c is the never-minted/nothing-survives-a-rejected-context clause, and these rows are that clause read on `tracestate`; .d is specifically `baggage`'s independence, which these rows do not exercise. | unit | negative, discrimination | **Partially — same vacuity as T3/T4.** HEAD writes no `_meta` on this arm, so "no outbound `tracestate`, request succeeds" is already true. Not an independent red; evidence only in a suite where T1 is green. §6.2 governs. |
| OTEL.1.f | **T7 (the grammar rows)** one row per predicate §3.4b names, each breaking exactly one thing (A9): uppercase hex ⇒ rejected; version `ff` ⇒ rejected; all-zero `parent-id` ⇒ rejected; a five-field `traceparent` with a valid first four ⇒ **accepted**, and the outbound carries the **whole five-field input** as a literal. Reading the first four is a *parse* rule (design §3.4b); the emit rule is byte-for-byte as received (design L238, L464). Asserting a four-field outbound would fail a correct hop and, if "fixed", would silently truncate valid future context. Each row asserts both sides — the input refused and a neighbouring input permitted (A1). | unit | parameterised, boundary | Yes, all four. Verified against `TraceContext::from_meta` (`trace.rs:32`): it accepts uppercase hex (`is_ascii_hexdigit` is case-insensitive), accepts version `ff`, checks the all-zero rule on `trace_id` only and not on the span id, and rejects any `traceparent` with other than exactly four parts. Each of the four rows asserts the opposite of what HEAD does. |
| OTEL.1.e | **T8a (charset)** one row per field, each breaking exactly one character class against the W3C grammar (A9), with the permitted neighbour asserted alongside (A1). Literal valid and invalid values pinned per field at writing time. | unit | boundary | Yes — no charset check exists today. **Not blocked**: charset is independent of the length numbers. |
| OTEL.1.e | **T8b (length bounds)** per bounded field: at the limit ⇒ propagated; one byte over ⇒ dropped, request still succeeds. Both sides pinned (A1). | unit | boundary | Yes — no bound exists today (F4). **Blocked on a number: see §6.1.** |
| OTEL.1.e | **T9 (constant perturbation)** a stated **mutation procedure**, not a unit case: patch the named bound constant in source, re-run T8b unchanged, require the verdict on the same input to flip. A runtime-injected bound would not prove the same thing — the point is that no hardcoded length sits beside the constant (A7). | procedure | A7 mutation | Same block as T8b. |
| OTEL.1.g | **T10 (non-interpretation)** two requests identical except for their trace values; assert the **cache key is byte-identical** across both, and that the resolved backend and tool name are identical. The cache key is the one interpretation channel that is mechanically checkable in-process. | integration | negative, security | No — but not for the reason first written here. HEAD **does** read a trace value: `invoke.rs:1845-1847` parses `_meta.traceparent` and uses the trace id as the transparency-log correlation key (`d4874a25`, check 6). That read is outside the clause's interpretation channels — it sets no cache key, resolves no backend, decides no route, auth, policy or budget — and T10 asserts on exactly those, so the case still passes on HEAD. Recorded as a **regression guard**, not as evidence the clause was newly met. |
| OTEL.1.g | routing, authorisation, policy and budget non-interpretation | — | — | **No case.** See §6.3. |
| OTEL.1.h | end-to-end across a real backend hop | — | — | **No case.** See §6.4. |

### 5.1 A testability requirement this plan places on the implementation

Four constraints, stated here because discovering them during implementation is what turns them
into "we asserted the empty value instead". The first two are what E3 and T9 need; the second two
are what §5.2's rows and §8's ERROR-is-not-FAILURE rule need, and they were cited from §8 and §11
before this section contained them — a defect both review legs raised independently:

1. `build_initialize_result` must take the implemented-extension set as a **parameter or
   injectable source**. A module-level constant read internally makes E3 unwritable, and EXT.1.b
   then loses its only honest case.
2. The bounded-read limits (design §4.2) must be **named constants**, so T9 can perturb them.
3. The outbound `_meta` construction must be reachable as `build_outbound_meta(inbound_meta,
   cache_key_opt)` — a seam a test can call without standing up `dispatch_to_backend`. Without
   it T1 and T2 go red on harness setup, and §8 already says an ERROR is not a FAILURE and buys
   the red suite nothing.
4. The invoke funnel's **resolved `TraceContext`** must be observable to a test entering at a
   route — an assertion hook, a returned value, or a recorded field. T11-T14 are specified to
   observe there and forbidden from naming `extract_tools_call_params` or reading the outbound
   object; with no probe, those two rules leave the rows unwritable, which is the same
   empty-cell defect one level down.

The first two are not design changes — §3.1a already says the map is populated from a set, and
§4.2 already says each bound is a named constant carrying its provenance. The last two are: they
name shapes the design left to the implementer. They are recorded here as **testability
requirements**, not as chosen seams — any construction satisfying them serves.

### 5.2 The carrier and the two routes — the rows §6.6 was holding open

§6.6 recorded route-level ingestion as an empty cell. It is no longer empty: the design's §2.7
and §7 turned "a route never calls the extractor" from a hypothesis into a statement about the
tree, and a close condition without cases is a close condition nobody can fail. These five rows
are those cases. §6.6 now points here rather than standing beside them as a second live close
condition.

**Four of the five rows below observe at the invoke funnel, not at the outbound `_meta`.** T15
is the exception and says so in its own cell: it keeps the transparency-log assertions of the
test it realigns, which observe downstream of the funnel. That is the
point the design's own close condition names — *"reaching the invoke funnel on both transports"*
(§7) — and it is not a stylistic choice: the read is upstream of the write, so a row that observed
the outbound object would go red when the unconditional write of clause .b is missing — .b's defect reddening a .a row, which is
exactly the conflation these rows are built to avoid. Fixture direction is unchanged from §5: values are
placed only on the inbound body, never on the outbound one.

An earlier revision of this section restricted T11-T14 to `traceparent` and `tracestate`, on the
reasoning that a `baggage` assertion would go red on a missing struct field and so redden four
rows for a reason that had nothing to do with the carrier they exist to observe. **That
restriction is removed, not relaxed.** Its premise died at source on 2026-09-06 (§12, check 4):
`baggage` is a field on `TraceContext` and `from_meta` parses it, so asserting it introduces no
second cause of redness — these rows are red on the carrier, and on the carrier alone, whichever
of the three fields they name. T11-T14 therefore assert all three, as T0 does. The finding that
produced the restriction can no longer be stated, which is the test for an elimination rather
than a hedge.

| clause | case | level | type | red on HEAD? |
|---|---|---|---|---|
| OTEL.1.a | **T11 (the carrier)** build the params object a `tools/call` arrives with — `{"name": ..., "arguments": {...}, "_meta": {"traceparent": ..., "tracestate": ..., "baggage": ...}}` — and drive the invoke funnel with it. Assert the funnel sees all three values. The read under test is at the **params** level, which is where the protocol puts `_meta` (`CallToolRequestParams`, design §1); the one production read site today is a level below it, in `arguments` (`invoke.rs:1845-1847`). This row is what says the carrier is the params object and not the arguments map. | integration | contract | Yes, and for the carrier and not for the field: `extract_tools_call_params` returns `(tool_name, arguments)` and discards the rest of `params` (`helpers.rs:190-195`), so no params-level `_meta` reaches the funnel on any path. Populating `arguments._meta` instead would make this row green today — that is exactly the wrong-shaped fixture T15 exists to correct, and the reason this row states its carrier in its fixture rather than in its name. |
| OTEL.1.a | **T12 (HTTP ingestion)** post a whole JSON-RPC `tools/call` body over the HTTP route with all three `params._meta` fields populated, and assert the invoke funnel sees all three values. Nothing is handed in at a seam; the body enters where a client's body enters, and the observation is the same one T11 makes — what changes is who delivered the params object. | integration | contract | Yes. The HTTP handler destructures exactly the pair `extract_tools_call_params` returns (`handlers.rs`, the HTTP `tools/call` arm), so the trace fields are dropped before any dispatch. Note what this row buys over T11: T11 can pass against an implementation that reads `params._meta` at the funnel while the HTTP route still never delivers a params object that has it. That is the gap §6.6 named, and it is why the carrier row does not subsume the route rows. |
| OTEL.1.a | **T13 (stdio ingestion)** the same body over the stdio route, same assertion at the funnel (`server/mod.rs::dispatch_single_with_sink`). | integration | contract | Yes, same cause, independently: stdio destructures the same pair at its own call site. **This row asserts the trace read and nothing else.** It does not touch `stdio_should_present_a_retry_when_the_context_declares_one` (`server/mod.rs:3599-3611`), does not un-ignore it, and does not assert anything about `retry`: that watcher observes cluster-G's MRTR stdio `RetryFields` seam, and coupling OTEL.1's close to a criterion another cluster owns is the defect that removed disposition 3 from the design. |
| OTEL.1.a | **T14 (precedence)** populate **both** carriers in one request with **different** trace ids — `params._meta.traceparent` = A, `arguments._meta.traceparent` = B — and assert the funnel resolves to A. Then assert B is not reachable at all: no field carries it, no fallback restores it. | integration | contract | Yes, on the second assertion at minimum. This row is the one in this set most likely to be born unable to fail, and the failure mode is in the fixture, not the coverage: **a fixture carrying only `params._meta` passes under both implementations** — the one that prefers params and the one that never reads params but finds nothing at the args level either. Both carriers, different values, is what makes the row discriminating. The second assertion is what makes it observe disposition 1 of design §2.7 (the args-level read is REMOVED, not demoted to a fallback) rather than merely observe an ordering. |
| OTEL.1.a | **T15 (the realigned fixture)** `trace_correlation_tests.rs:104-130` today passes because it drives `meta.invoke_tool(&args, ..)` directly with `{"server", "tool", "arguments", "_meta"}` — the meta-tool's own argument object, which is `params.arguments` once a real `tools/call` arrives, and exactly what `invoke.rs:1845` reads. **Re-pointing it needs the call site moved first**: `invoke_tool` takes that argument object and never sees a `CallToolRequestParams`, so moving `_meta` up to `params._meta` while leaving the test where it is gives the value no recipient — the case would ERROR on a missing `server`/`tool`, not fail on its assertion. So: enter at the same production `tools/call` entry T11 and T12 use, put `_meta` at the params level, and keep the three transparency-log assertions unchanged. | integration | contract | **Grade pending.** It must go red before it is repaired, and the redness is T11's cause: no params-level `_meta` survives `extract_tools_call_params`. The cell is not filled because this test is one of the two cited as evidence for **CONTROL.3b = MET** (`docs/requirements/RELEASE-4.0.0-criteria-status.md:175`), and criteria-ledger has not yet answered whether that grade survives the finding that it rests on a read of the wrong carrier. If 3b stays MET, this row is a regression test for a criterion already graded met; if 3b moves, it is a missing specification. Those are different rows, and which one it is is not this plan's call. |

## 6. The empty cells, each with its reason

An empty evidence cell is the finding. Four were opened here; **three are still empty**, and
§6.6 is retained as a closed entry rather than deleted, because a gap that was answered is worth
more as a record of how than as a silence. None is tidied away, and none is downgraded into a
weaker case that would look green.

### 6.1 T8b/T9 are blocked on a number, not on a design question

Design §4.2 defers the `tracestate` and `baggage` size limits to the implementer, "with the test
plan, so the boundary rows assert a real number rather than a placeholder". That trigger has now
fired: **this is the test plan, and the number is not yet pinned.** T8b and T9 are specified in
shape and blocked in value. T8a is **not** blocked: the charset half of OTEL.1.e is decided by the
W3C character classes, which are already pinned by a published specification, so it is written now
and only the length half waits.

- owner: this ticket's implementer, before the first bounded-read constant is written
- resolving action: take the limits from the W3C specs SEP-414 defers to and pin each as a named
  constant carrying its provenance
- trigger: the first bounded-read constant; the boundary rows are written against it in the same
  commit
- if it resolves badly: too low drops valid context, too high relays more attacker-influenced
  bytes than needed. Both are one constant, and the drop-not-repair rule means neither can fail
  a request — so a wrong number is a tuning defect, not a correctness one

A boundary row written now would assert a placeholder against itself, which is A8 in its purest
form. Blocked is the honest state.

### 6.2 T3 cannot fail on its own, and is honest only beside T1

T3 asserts that no `traceparent` appears on the outbound when none arrived. Against HEAD the
outbound carries **no `_meta` at all** on the no-cache-key arm, so T3 is green today for a reason
that has nothing to do with minting — A5, exactly: the condition it claims to observe is removed
before the rule under test is consulted.

It is kept, because deleting it would leave the never-mint invariant — the design's security
property — with no case at all. It is kept **with its dependency stated**: T3 is evidence only in
a suite where T1 is also green. T1 green proves the write site now emits trace `_meta`
unconditionally; T3 green **then** proves the emission is conditional on inbound presence rather
than minted. Separately, T4 carries the same invariant on a path where the fixture does supply an
inbound value, so the not-minted claim is not resting on T3 alone.

The plan does not claim T3 is red on HEAD, and a reader must not count it as an independent
proof.

### 6.3 Three of the four non-interpretation channels have no case

OTEL.1.g forbids trace values reaching routing, backend selection, authorisation, policy, cache
keys and budget. T10 covers cache key, backend and tool resolution because those are observable
from an in-process call. **Authorisation, policy evaluation and budget accounting have no case
in this plan.**

The honest reason, and it is not "we ran out of time": a negative over an unbounded surface is
not testable by example. A passing case would show that *these particular* trace values did not
influence *these particular* decisions — it would not show that no value can. The property is
enforced by construction (the trace values are carried as opaque strings and never passed to
those subsystems) and by review, not by a test.

What could be built and is not proposed here: a taint-style assertion that no trace-derived value
appears in the authorisation or budget inputs. That is a mechanism, not a case, and it is larger
than this criterion. Recorded as a gap with a named shape so the next reader does not mistake
T10's scope for the whole clause.

### 6.4 OTEL.1.h — no end-to-end case exists, and this is a shared cost

The criterion says "across the gateway hop". Every case above stops at the outbound params object
`dispatch_to_backend` builds; **none observes a real backend receiving the fields over the wire.**
No backend-capture harness exists in this tree.

Design §3.4a already records this and records why it is not priced here alone: cluster B1's
stream-isolation work reaches the same missing harness. Two designs naming it makes it an item
with an owner rather than a per-cluster cost.

Stated at its true strength: the unit cases prove the gateway *emits* the three fields into the
params it sends. They do not prove a backend *receives* them. For a JSON body serialised by the
same client that carries the cache key today, the gap between those two claims is small — but it
is not zero, and a plan that called T1 an end-to-end case would be overstating it.

- owner: unassigned — needs the operator, because it is shared with cluster B1
- resolving action: one backend-capture harness (a local HTTP backend recording received bodies)
- trigger: whichever of B1 or this cluster reaches implementation first
- if it resolves badly (no harness): OTEL.1 closes on emission evidence, **and closure is
  conditional on that limit being written into the closing evidence comment** — a criterion whose
  wording says "across the gateway hop" may not be signed off against emission-only cases while
  the shortfall lives in a design document nobody reads at closing time

### 6.5 EXT.1.d has no behavioural case, and E6 was withdrawn to say so

EXT.1.d is the honour clause: an extension the client did not declare must not change behaviour,
and a request depending on one must be answered as if the extension were absent.

E6 was drafted as the red behavioural case — send an extension-dependent request without declaring
the extension, assert the core answer. Review killed it, correctly. **There is no extension to
revert from.** `Extension::from_id` recognises exactly one identifier, `io.modelcontextprotocol/tasks`,
and nothing in 4.0.0 is gated on it, so a core `tools/call` already succeeds. "Reverted to core
behaviour" and "never consulted an extension at all" produce byte-identical outputs, and no
assertion can separate them. A case that cannot fail the wrong implementation is A5, and the
earlier "red on HEAD" label on E6 is **retracted**, not softened.

E7 stays, labelled weak as it already was: it separates revert from *reject*, which is a real
distinction the honour clause makes, but it does so on the reject side only.

**EXT.1.d must not be counted as evidenced by this plan.** It gets a case when TASK.1 ships
behaviour actually gated on `Extension::Tasks` — at that point the undeclared-extension request has
something to be reverted from, and the same row becomes writable and red.

- owner: the TASK.1 implementer
- resolving action: once one behaviour is extension-gated, write E6 against it
- trigger: the first `if extensions.contains(Extension::Tasks)` on a request path
- if it resolves badly (TASK.1 ships no gated behaviour in this release): EXT.1.d closes on
  construction and review, recorded as such, never on E7 alone

### 6.6 Route-level ingestion — no longer an empty cell; the cases are §5.2

**This entry is closed. Its cell was filled on 2026-09-06 by T11-T15 in §5.2, and the four
deferral fields it used to carry are struck rather than annotated.** A §6 entry exists to record
a gap nobody has cases for; leaving one standing next to the cases that close it gives the
document two live close conditions for one criterion, and a later reader takes whichever they
open first.

What the gap was, in one sentence, so a reader who remembers it can see it was answered rather
than lost: T0 proves the parse is real and proves nothing about either transport handing the
extractor a body to parse, so if a route never calls the extractor every row in §5 still passes.
The earlier argument that the split was deliberate — that the transports were moving under other
tickets and extractor evidence would therefore do — was WITHDRAWN before that, by the design's
§2.7 and §7.

What replaced it: **route-level ingestion per transport is a case, not a waiver.** §5.2's T12
(HTTP) and T13 (stdio) are those cases, T11 asserts the carrier they must deliver to, and OTEL.1.a
does not close while any of the three is unwritten or green-on-HEAD. The capture harness §6.4
names may supply the evidence; it may not substitute for the rows. The one field still genuinely
open is T15's grade, and it is recorded in that row's own cell, where the case it qualifies is —
not here, as a fifth deferral for someone to find.

## 7. The A1-A9 sweep, and what it changed

Run before this document's first review. Recorded rather than silently fixed, because two
findings changed what a case does.

**Limit, stated:** this table is the *pre-review* sweep. The rows added or re-keyed during
disposal — T0, T5b/T6b, the T8a/T8b split, and the E1/E3/E4/E5 repairs — were written against
A1-A9 but are **not** swept as a set here; §8 step 2's post-write sweep is where they get the
same treatment as the rest, and it has not been run.

| rule | what the sweep found | what changed |
|---|---|---|
| A8 | An earlier draft of T1 asserted the outbound `_meta` equalled `TraceContext::from_meta(inbound).to_meta()`. That is the module under test on the expected side: it stays true after every predicate in `trace.rs` is deleted. | T1 now asserts literal strings. The round-trip identity, if wanted, becomes a separate assertion. |
| A5 | An earlier draft of T1 supplied a prompt-cache key "so the fixture is realistic". The cache-key arm already writes `_meta`, so the case would have passed against the unfixed conditional write — the exact defect F8 names. | T1 runs with **no** cache key. T2 was added to cover the merge. |
| A5 | T3 examined and found vacuous on HEAD. | Kept, with §6.2 stating the dependency instead of claiming a red. |
| A7 | E2 asserted an empty map — the empty-set trap. | E3 added as the discriminator, plus the §5.1 injectability requirement that makes it writable. |
| A9 | An earlier T4 broke two things at once (short `traceparent` **and** uppercase hex), so whichever check ran first decided. | One defect per fixture; T7 splits the grammar into four single-defect rows. |
| A4 / A2 | T2 asserted "contains traceparent". | Exact key set, so a wholesale `_meta` overwrite is caught. |
| A3 | E4 asserted the recovered set contained no forbidden identifier. True of an empty set. | Asserts the identifier that **did** arrive, and E5 supplies the negative. |
| A1 | T7's future-version row asserted only that a five-field input is accepted. | Also asserts the propagated value — as the whole five-field literal, after review corrected the first draft's truncation to four (§11 item 5). |
| A6 | No relative rule in this cluster — no time, freshness or ordering predicate. | N/A, stated. |

### 7.1 The same sweep over T11-T15, and the two questions a plan review asks

Run 2026-09-06, when §5.2 was written, against the same A1-A9 rules. Recorded here rather than in
a table row of its own: a sweep is a pass over cases, not a case.

**Q1 — does every clause these rows touch have a case, or a stated reason it has none?**
OTEL.1.a now has six (T0, T11, T12, T13, T14 after the re-key below, T15) where it had one, and
its route-level cell is filled rather than deferred. **Two** claims the design's §2.7 makes have **no case,
deliberately**, and the empty cell is the finding rather than an oversight; a **third** has a
case but only one, and is listed after them so the count stays checkable:

- *"the constraint is the reduction, not the function"* — no row asserts anything about
  `extract_tools_call_params` by name, and none should. T12 and T13 enter at the route and assert
  at the invoke funnel; they hold across a rename, a rewrite, or a different reduction entirely. A row naming the function would convert the implementation choice §2.7 explicitly
  left open into an acceptance criterion.
- *"the watcher stays ignored and stays cluster-G's"* — a scope statement, not a behaviour. It is
  asserted by no case because there is nothing to observe: it is a decision about which cluster
  owns a test, and a test asserting it would be this plan reaching into cluster G's.
The third, which does have a case:

- *"the args-level read is REMOVED rather than kept as a fallback"* — asserted **behaviourally**
  by T14's second assertion and by nothing else. No case asserts the source line is gone; that is
  a grep, not a test, and a plan that promises one is promising something a suite cannot deliver.

| rule | what the sweep found | what changed |
|---|---|---|
| A4 / A2 | T14 was keyed to OTEL.1.b. Precedence decides **which source the read takes**, which is clause .a; .b is the unconditional write. This is a trace, not a judgement call: design §7's close condition puts *"never from the tool argument object (§2.7)"* **inside the read clause**, so the carrier choice is part of what .a obliges. Keyed to .b, the row would have been counted as evidence for a clause it does not touch, and .a's count would have been one short. | Re-keyed to OTEL.1.a. |
| A5 | **Withdrawn 2026-09-06.** This sweep restricted T11-T14 to `traceparent` and `tracestate`, on the premise that `baggage` was absent from `TraceContext` (`trace.rs:19`) and a three-field assertion could not compile. That premise was **true at `5c7e64f4`, the commit the design pins, and false four and a half hours later**: `baa318b2` added the field and the parse (§12, checks 4-6). The sweep was sound when run and is void now. A sweep is a claim about a tree, and this plan never said which tree. | No restriction. All four rows assert the three fields T0 asserts; their one cause of redness is the carrier, which is the thing they exist to discriminate. |
| A7 | T14's second assertion — "B is not reachable" — is a negative, and a negative is true of an implementation that dropped **both** values. | Paired with the first assertion (the resolved value **is** A). An implementation that loses both fails assertion one; an implementation with a fallback fails assertion two. Neither passes alone. |
| A9 | T14 varies two inputs in one fixture, which reads like the "two defects at once" rule. Examined: it varies one **dimension** — which carrier holds the value — and both arms are required for the row to discriminate at all. A single-carrier fixture passes under both implementations. | Kept as written, with the reason stated in the row rather than left for a reviewer to re-derive. |
| A5 | T15 is a case whose current fixture makes its own assertion true: it seeds `arguments._meta`, which the one production read site reads, so it passes against the shape no client sends. This is the §P2 Q2 failure mode in the tree, not a hypothetical. | Kept as a row, and its purpose stated as the repair — the fixture moves to the carrier the protocol specifies, and must go red before it goes green. |
| A1, A3, A6, A8 | No relative, temporal or self-referential predicate in these five rows; no expected-side value computed by the module under test (each asserts against literals placed in the fixture). | N/A, stated. |

**Q2 — can each row actually fail?** T11-T13 fail on HEAD because no params-level `_meta` survives
the reduction, and the redness is checked at source rather than assumed (`helpers.rs:190-195` and
its two callers). T14 fails on HEAD for the same reason, and would still fail against a *fallback*
implementation that the other four rows would pass — that is its whole job. T15 is the one row
whose grade is not filled in, and §5.2 says which answer fills it. A row that cannot fail is worth
less than no row, because it is counted.

## 8. Execution order, before this suite is trusted

The two steps that get skipped, per the honesty protocol, are the two that collapse round count.

1. Write the cases.
2. Sweep A1-A9 again after writing — §7 is the pre-write sweep; the post-write one finds
   different things.
3. **Run the red suite and read the failure REASON of every case, not the count.** An assertion
   failure is the free proof that a case can fail. An `ERROR` — a panic, a missing fixture, a
   compile failure in the test module — means the harness is broken and the case would have
   failed against a *correct* implementation too. For this suite the distinction matters most in
   T1/T2: run them against the `build_outbound_meta(inbound_meta, cache_key_opt)` seam §5.1
   requires, **not** through `dispatch_to_backend`, whose backend stub will `ERROR` rather than
   `FAILURE` when incomplete — an ERROR is not the free proof, it is a broken harness.
   **§5.2's route rows carry the same hazard one level up, and it is likelier there.** T12 and
   T13 drive whole transports; a route that will not start, or a stdio harness that never reads a
   line, produces a red T12/T13 that says nothing about whether the trace read exists. Their red
   must be an assertion failure **at the funnel**, on the values the funnel was expected to see.
   Observing there is what removes the third source of false red — no backend stub is needed to
   reach the observation point, so an absent or incomplete one cannot ERROR the row. A route row
   that has never once been seen to fail on its own assertion is an untested test.
4. Then implement.

## 9. Readiness gates — applicable ones, checked

Against `rules-source/workflows/quality-gates-dor.md`. "Not applicable" carries its reason.

| gate | verdict |
|---|---|
| B4 acceptance criteria, stable IDs | Met. `MIK-7272.EXT.1` and `MIK-7272.OTEL.1` exist upstream; §1 decomposes them into clause IDs and traces each to a design sentence. |
| C3 test strategy | This document. |
| C11 contract tests | E1, E2, E3, T2 are contract/serialisation cases on the wire shape; T11-T15 add the carrier and the two routes. |
| G6 alternatives | Held at design §3; a test plan does not re-open them. |
| G0 biggest ROI, G4 requirements clear, G5 minimum scope | Met upstream. The criteria are release-blocking and already worded; §1 decomposes them without widening them, and §0 states what is out. |
| O1-O3 structure, clutter, naming | Met. One document, in `docs/design/`, named for its cluster and dated like its sibling design. |
| G8 risks | Met: §6 opened four gaps, three still open and one (§6.6) closed into cases at §5.2; §10 hands the open ones forward with owners. |
| G10-G12 fail-fast | **Partially — planned, not executed.** A test plan cannot produce execution evidence; nothing has been run. What this step can do is order the work so the riskiest assumption is tested first, and it does: §6 names four gaps, and the two cheapest discriminators (E3, T5) are the first cases to write — E3 decides whether EXT.1.b is provable at all, T5 whether `baggage` was built. The gates close at §P3, not here. |
| T0 contribution class | infrastructure/compliance — closing two spec MUSTs. |
| L2 data protection | **Applicable and UNRESOLVED — corrected at review.** `baggage` is arbitrary caller-supplied key/value text and may carry personal data; propagating it moves that data across a backend boundary. The W3C baggage specification's own privacy considerations say as much. This plan does not decide it: design §4.4.4 is the operator question, and until it is answered OTEL.1.d ships a data flow nobody has reviewed. Recorded as an open item (§10), not as N/A. |
| L1, L3-L7 legal | N/A. No new dependency, no crypto primitive, no AI classification, no device contribution, no export-controlled distribution. |
| T1c PQC | N/A. No key agreement, no signature. |
| T6 numerical discipline | N/A. No quantisation, parallelism or collective. |
| G20 profiling-first | N/A. Not a performance change. |
| G13-G14 moat, T1b beyond-SOTA | N/A per the DoR's own auto-skip for infrastructure/compliance work. |
| B1-B5 backlog health | Inherited from MIK-7272, which carries the ticket, the criteria and their stable identifiers. Not re-litigated here, and not claimed as evidence produced by this document. |

Applicability class: this document is **DOCS** work that plans **CODE** work. The DOCS gate set is checked above and is met. The CODE gate set (C1-C17, D-gates, §1-§13) is **not** evaluated here and is not claimed — it closes against the implementation, not against its plan. |

## 10. Open items this plan hands forward

| # | item | to whom |
|---|---|---|
| 1 | The `tracestate` and `baggage` bounds (§6.1). T8b/T9 cannot be written until the numbers are pinned; T8a is not blocked. | this ticket's implementer |
| 2 | The backend-capture harness (§6.4). Shared with cluster B1. | operator — it is a cross-cluster cost, not a per-cluster one |
| 3 | The injectable extension source and named bound constants (§5.1). | this ticket's implementer, at implementation time |
| 4 | Non-interpretation over authorisation, policy and budget (§6.3) is enforced by construction and review, with no case. | recorded as a limit against OTEL.1 |
| 5 | EXT.1.d has no behavioural case until an extension gates behaviour (§6.5). | the TASK.1 implementer |
| 6 | ~~Route-level ingestion of trace `_meta` on HTTP and stdio (§6.6).~~ **Closed 2026-09-06** — it is §5.2's T11-T13, not a handed-forward item. What remains open from it is narrower and belongs to someone else: T15's grade cell, which turns on whether CONTROL.3b's MET survives resting on a read of the wrong carrier. | criteria-ledger, on CONTROL.3b (`docs/requirements/RELEASE-4.0.0-criteria-status.md:175`) |
| 7 | **Data protection on `baggage` (§9, gate L2).** Caller-supplied `baggage` may carry personal data, and propagating it moves that data to a backend. The W3C baggage specification says so in its own privacy considerations (https://www.w3.org/TR/baggage/#privacy-considerations). Design §4.4.4 is the question; it is unanswered, and OTEL.1.d cannot honestly be called reviewed until it is. | operator — it is a policy decision, not an engineering one |

The design's operator questions (§4.4) are unchanged by this plan and are not restated. One of
them bears on coverage: if §4.4.3 is answered "both routes", OTEL.1 gains the direct route
`POST /mcp/{name}`, which carries no `_meta` at all — and this plan gains a row it does not
currently have.

## 11. Review round 1 — findings and their disposal

Two vendors, identical material (this document at `41ef8347`, 27,888 bytes, submitted as the plan
alone rather than a tree diff). Both returned **SHIP-WITH-FIXES**. A third leg, `kimi-review`,
returned COULD NOT REVIEW (exit 65) and produced no verdict; it is recorded as absent, not as
agreement.

A banner declared the round VOID because the tree moved between submission and reading
(`41ef8347` → `832ef3d9`). It moved because **another agent committed on this shared branch**; the
material was pinned by object id at submission, so both verdicts describe the document as reviewed.
The banner is noted and rebutted rather than deleted.

Disposal follows development-process §P0: fix it here, write it into the design, record it as an
observation, or file a ticket — first one that holds. Nine findings were repairs to this plan,
which is what a plan review is for. Nothing was filed: no finding needed a human to decide
something that this document could not answer, and filing is the most expensive disposal.

| # | finding | raised by | disposal |
|---|---|---|---|
| 1 | E1 asserts `extensions` in the initialize result's own key set, but the field lives on `capabilities` — never green against a correct payload. | grok (HIGH) | **Fixed here.** E1 now asserts on the serialised `capabilities` member, matching the discover half of the same row. |
| 2 | E4/E5 use the synthetic id `example.test/probe`, which `from_capabilities()` correctly discards — the case fails a correct implementation. | grok (HIGH), gpt (MEDIUM) | **Fixed here**, and it was the sharpest catch of the round. E4 uses `io.modelcontextprotocol/tasks` and asserts `Extension::Tasks`; E5 keeps a real identifier with a non-object value `3`, which survives `declared_capabilities`' null filter and dies on `is_object()` — that is the honest discriminator against a name-list implementation. The row states why a synthetic id can never go green. |
| 3 | E3's discriminator needs an injectable probe id, but §5.1 permitted an `ExtensionSet` source that cannot hold one. | grok (HIGH) | **Fixed here.** §5.1 now requires a map of identifier strings, and substituting `Extension::Tasks` in E3 is forbidden in the row itself. |
| 4 | E6 is not red on HEAD: with no extension-gated behaviour, revert and never-consult are output-identical, so EXT.1.d is counted evidenced on a vacuous case. | grok (HIGH), gpt (MEDIUM) | **Fixed by removal**, per the repair protocol's elimination default. E6 is withdrawn, the red-on-HEAD label is retracted, and §6.5 records EXT.1.d as an empty cell with the trigger that fills it. Patching E6 would have left the defect describable; deleting it does not. |
| 5 | T7's accept-row demands the outbound `traceparent` be truncated to four fields, contradicting byte-for-byte emission. | grok (HIGH), gpt (MEDIUM) | **Fixed here.** The row asserts the whole five-field literal outbound; "read the first four" stays a parse predicate. Verified at source: design L238 and L464 say forwarded unchanged, L321 governs parsing only. |
| 6 | Legal gate L2 marked N/A although caller-supplied `baggage` may carry personal data. | gpt (HIGH) | **Fixed here and handed forward.** §9 now marks L2 applicable and unresolved, citing the W3C baggage privacy considerations; §10 item 7 hands the decision to the operator, where design §4.4.4 already put it. Correct catch — this plan had no standing to call it N/A. |
| 7 | T1 carries no sentinel, so a copy-all-inbound implementation passes. | gpt (HIGH), grok (IMPROVEMENT) | **Fixed here.** T1 injects `example.test/poison` inbound and T2 asserts the outbound by exact key set excluding it, which is what A2 and the provenance strip at `invoke.rs:472` actually require. |
| 8 | OTEL.1.a folded into T1 at `dispatch_to_backend`, which never receives request `_meta` — no discriminating seam for the read clause. | grok (MEDIUM), gpt (MEDIUM) | **Split here, with the residue named.** New T0 exercises the production extractor over a request body for .a; T1 keeps the dispatch write for .b. The route-level gap this does not close is §6.6, not a silent omission. |
| 9 | No case proves `tracestate` is dropped when `traceparent` is absent or malformed. | gpt (MEDIUM), grok (IMPROVEMENT) | **Fixed here.** T5b/T6b mirror T5/T6 on the inverse coupling design §3.4 makes load-bearing, filed under **OTEL.1.c** (the never-minted clause read on `tracestate`) rather than .d (`baggage`'s independence), and carrying the same T1-dependency honesty as T3/T4 — they are vacuous on HEAD and say so. |
| 10 | T8 blocks charset rows on an unpinned length bound, though charset is independent. | gpt (MEDIUM), grok (IMPROVEMENT) | **Fixed here.** T8a (charset, against the W3C character classes, not blocked) is separated from T8b (length bounds, blocked on §6.1). |
| 11 | T4 marked red on HEAD although HEAD already satisfies both its assertions. | grok (MEDIUM), gpt (LOW) | **Fixed here.** T4 now carries the same T1-dependent form as T3, and §6.2 governs both. The plan had already caught this vacuity for T3 and missed the identical case one row down. |
| 12 | §9 evaluates neither the CODE gates nor the minimal DOCS set, and claims G10-G12 met without execution evidence. | gpt (MEDIUM), grok (IMPROVEMENT) | **Fixed here.** §9 declares its applicability class, adds G0/G4/G5/O1-O3, states that the CODE set closes against the implementation and is not claimed here, and downgrades G10-G12 to planned-not-executed. |
| 13 | Recast T9 as an explicit mutation procedure. | gpt (IMPROVEMENT) | **Fixed here.** T9 is a stated source-mutation procedure with level `procedure`, not a unit case. |
| 14 | Give the backend-capture harness a named owner and make it an explicit OTEL.1 closure gate. | gpt (IMPROVEMENT) | **Half fixed, half declined.** The closure gate is now explicit in §6.4: emission-only closure must carry the recorded limit into the closing comment. The owner is *not* invented — it is shared with cluster B1 and stays an operator item (§10 item 2). Naming a fake owner would satisfy the reviewer and not the problem. |
| 15 | T1/T2 should target an extractable seam rather than `dispatch_to_backend`, so a red suite fails on the assertion rather than on harness setup. | grok (IMPROVEMENT) | **Fixed here.** §5.1 adds the `build_outbound_meta(inbound_meta, cache_key_opt)` seam as a testability requirement, which is what §8's ERROR-is-not-FAILURE warning needs to hold. |

One correction came from the verification rather than from either reviewer. Checking finding 8 at
source turned up `src/protocol/trace.rs`: a correct `from_meta`/`to_meta` pair that **nothing
calls**, with no `baggage` field. The first draft's blanket "nothing is propagated today" was
therefore true of the request path and false of the module, and several red-on-HEAD claims rested
on it. §5's preamble now states the verified position, and T0 and T7 carry the specific source
facts that make them red. This is what the repair protocol's source-verification step is for:
the reviewers were right about the seam and, in chasing their finding, the plan's own background
claim turned out to need narrowing.

Nothing was accepted as residual risk and nothing was disputed at source: every finding survived
verification against the implementation. Four of them — 2, 4, 5 and 11 — were cases this plan
claimed could fail an incorrect implementation and could not, which is precisely the class §P2's
plan review exists to catch and which no later code review would have recovered.


### 11.1 Review round 2 — findings and their disposal

Both legs reviewed the plan as it stood **before** the §12 checks were run, so their findings are
independent of the baggage correction and none was closed by it. Two were raised by both vendors.

**Who actually reviewed — corrected.** The `raised by` column below first named `gpt` and
`claude`. That was false, and the correction is the same defect class as §12's: a claim written
from what the author believed had run rather than from the record. The two legs were
`grok-review` (`grok-default`) and `kimi-review` (`synthetic:hf:moonshotai/Kimi-K3`) — ledger rows
of 2026-09-06 08:20:14Z and 08:13:09Z, run files `grok-20260906T081029Z-66301.md` and
`synthetic-20260906T081025Z-65532.md`, both `process_status: ok`, both SHIP-WITH-FIXES. Neither
named vendor could have raised anything here: `gpt-review` has returned `process_status: error,
exit 1` on every invocation since 05:41:45Z that day (usage limit), and the only `claude-review`
row against this repo that day is the confirmation pass recorded in §11.2. Both launchers labelled
their scope string `round 1`; the round numbering in this document is the plan's own and is
unchanged.

| # | finding | raised by | disposal |
|---|---|---|---|
| 16 | §8 step 3 and §11 #15 both cite a `build_outbound_meta` seam "§5.1 requires", and §5.1 contained two constraints, neither of them that. #15 recorded it as fixed and it was not. | kimi (MEDIUM/CERTAIN), grok (MEDIUM/CERTAIN) | **Fixed here.** §5.1 carries it as constraint 3. The two citations are now true; before this they pointed at nothing, and T1/T2 would have gone red on harness ERROR — which §8 itself says buys the red suite nothing. |
| 17 | T11-T14 are told to observe at the invoke funnel and forbidden to name `extract_tools_call_params` or read the outbound object, and §5.1 named no funnel probe — so the rows are unwritable without breaking one of the plan's own rules. | grok (HIGH/LIKELY) | **Fixed here** as §5.1 constraint 4, stated as an observability requirement rather than a chosen seam. Same defect class as #16, one level down: the plan specified an assertion and not the surface it asserts against. |
| 18 | T15 re-points `trace_correlation_tests.rs:104-130` at `params._meta` while leaving it on `meta.invoke_tool`, which takes the meta-tool argument object and never sees a `CallToolRequestParams` — the case would ERROR on a missing `server`/`tool`, not fail. | grok (HIGH/LIKELY) | **Fixed here**, and the finding was sharper than stated. Verified at source: the test seeds `_meta` at the top of the gateway-invoke argument object — a sibling of `arguments`, not inside it — which is `params.arguments._meta` once a real `tools/call` arrives, and exactly what `invoke.rs:1845` reads. The row now moves the call site to the production `tools/call` entry first, then re-points the carrier. |
| 19 | §5's preamble claims every case in its table asserts on the outbound params object. False of T0 (asserts the extractor) and T10 (asserts the cache key and resolved backend). | kimi (MEDIUM/CERTAIN) | **Fixed here.** The preamble now fixes fixture direction for the whole table and states that observation point is per-row, naming T0 and T10 as the two that observe elsewhere. Following the old sentence would have made T0 a duplicate of T1 and destroyed the .a/.b split round 1 was spent creating. |
| 20 | §5.2's preamble says all five rows observe at the invoke funnel; T15 keeps assertions that observe the transparency log, downstream of it. | grok (MEDIUM/CERTAIN), kimi (LOW/POSSIBLE) | **Fixed here** — four of five, with T15 excepted by name. Confirmed at source while checking #18. |
| 21 | §7.1 says "Two claims ... have no case" and lists three bullets, the third of which does have a case (T14). | kimi (LOW/CERTAIN), grok (improvement) | **Fixed here.** Two are listed as having no case; the third is listed separately as having exactly one. The count was the whole point of the device, and a reader who miscounts it re-raises a closed row. |

Two round-2 improvements were **already closed** by the pin repair that preceded this disposal:
pin the SHA every red-on-HEAD grade is asserted against (§5), and retarget T11-T14's `baggage`
exclusion because the field has existed since `baa318b2` (§5.2, and the elimination recorded
there). Both were raised against the pre-repair text and both are moot against this one.

### 11.2 Confirmation pass — round 2's closure re-check

Two legs on the repaired plan and design. Verdicts read from the ledger row and the process exit
status only, never scraped from the body text (§PA).

| leg | ledger row | verdict |
|---|---|---|
| `gpt-review` (codex-default) | 08:28:17Z — `process_status: error`, `exit_code: 1`, verdict field empty, no run file written | **ERROR** — usage limit. Not a refusal, not a SHIP, and not evidence of closure. |
| `claude-review` (claude-opus-5) | 08:32:37Z — `process_status: ok`, `exit_code: 0` | **SHIP-WITH-FIXES** |

**The re-check went to the wrong pair, and that is a finding about this pass, not about the
repairs.** Repair-protocol step 6 returns a closure re-check to the vendor that *raised* the
finding; the delegated path opens only on finder unavailability, after a 12h clock, under the
narrower mandate of confirming or refusing the finding's own text. The six findings' finders were
`grok-default` and `synthetic:hf:moonshotai/Kimi-K3`, and both were reachable minutes before this
pass launched — grok wrote an `ok` verdict-bearing row at 08:25:19Z, three minutes before the
08:28 launch, and the kimi wrapper served a row at 08:15:06Z. Neither was asked. Routing to
`gpt-review` and `claude-review` instead was a **mis-route, not a delegation**: no clock started
and no narrower mandate travelled in the material. The consequence is exactly what the rule
predicts of a stranger vendor — the surviving leg re-opened three things it never raised. Those
three are therefore **new material disposed under §P0**, not confirmation-pass output, which is
why each was eliminated on its own merits and verified at source rather than accepted as closure.
What still has no finder re-check is the closure of findings 16-21.

The surviving leg confirmed all six round-2 findings closed **by changed specification rather
than by words**, and raised three new ones against the repair itself. Every one is a claim the
repair made about its own closure — the same shape as the defect §12 exposed, one level up.

| finding | disposal |
|---|---|
| §5's repaired preamble lists T14 among the rows asserting on the outbound params object, while §5.2 puts T14 at the funnel and §5's own table contains no T14 row. | **Eliminated.** "and T14" struck. T0 and T10 remain the section's two named exceptions, and the sentence can no longer be read against a row that is not there. |
| T5's red-on-HEAD cell still cited the premise check 4 refuted — "`baggage` appears nowhere in `src`". | **Eliminated.** The cell carries the surviving cause, verified at source: outbound `_meta` is written only when a cache key is present (`invoke.rs:2545`), and the inbound read is at the arguments level (`invoke.rs:1844`). The grade stands; its stated reason no longer contradicts §12. |
| §5's pin was asserted, not evidenced, and check 6 reasoned against unpinned `HEAD` inside the section whose purpose is to ban unpinned references. | **Eliminated.** Check 6 now runs against `b8cfc7e4`; check 7 evidences the pin itself against a *named* tree, `f2cf01b9` — ancestor, zero `src/` drift, and the five cited files unmodified in the shared checkout. Naming the tree is the point: this branch is shared and HEAD moved three times while this pass ran, so a check written against `HEAD` reads false to the next reader even when it was true when run. |

Three improvements are recorded as observations rather than actioned (§P0, third disposal): name a
checkable shape for §5.1's constraint 4 the way constraint 3 names a signature; add a
claimed-versus-verified column to §11's disposal tables; and re-derive §6's "Four were opened
here" against its six subsections. None blocks the red suite, and each is a plan-level tidy that
the next verdict-bearing round can take.

## 12. Evidence — the checks, run on 2026-09-06, with their output

A reviewer's HIGH finding on this plan was that its citations shipped as *measured* while nothing
recorded that any had been run. The answer to that finding is this section, and running it is what
falsified §5's baggage premise (§5 preamble, §5.2, sweep A5). The commands and their output are
reproduced verbatim; a claim in this plan that a check contradicts is corrected in place and the
correction says so.

```
### check 1 — extract_tools_call_params returns (tool_name, arguments)
$ sed -n 190,195p src/gateway/router/helpers.rs
    let arguments = params
        .and_then(|p| p.get("arguments"))
        .cloned()
        .unwrap_or(json!({}));
    (tool_name, arguments)
}

### check 2 — the two callers destructure exactly that pair
$ sed -n 976p src/gateway/router/handlers.rs; sed -n 1827p src/gateway/server/mod.rs
            let (tool_name, arguments) = extract_tools_call_params(params.as_ref());
                let (tool_name, arguments) = extract_tools_call_params(params.as_ref());

### check 3 — the one production from_meta call reads args._meta
$ rg -n "from_meta" src/ --glob "!*tests*"
src/gateway/meta_mcp/invoke.rs:1845:                .and_then(crate::protocol::trace::TraceContext::from_meta)
src/protocol/trace.rs:33:    pub fn from_meta(meta: &Value) -> Option<Self> {
src/protocol/trace.rs:109:        let onward = TraceContext::from_meta(&inbound)
src/protocol/trace.rs:122:        let onward = TraceContext::from_meta(&json!({ "traceparent": TRACEPARENT }))
src/protocol/trace.rs:135:            TraceContext::from_meta(&json!({ "baggage": "userId=alice" })),

### check 4 — REFUTED: `TraceContext` HAS a `baggage` field, and `invoke.rs` reaches it
via `TraceContext::from_meta` (`invoke.rs:1845`). The string `baggage` itself appears in exactly
one file, `src/protocol/trace.rs` — an earlier heading here claimed `invoke.rs` referenced the
field directly, which this check's own output refutes.
(the heading this check was written under asserted the opposite; its own output is below,
and it is what falsified the premise §5 was built on)
$ sed -n 12,25p src/protocol/trace.rs
//! Propagated, never re-minted. A gateway that started a fresh trace would make
//! its own hop the root and hide the caller that caused it.

use serde_json::{Value, json};

/// A `traceparent`, and whatever vendor state travelled with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceContext {
    traceparent: String,
    trace_id: String,
    tracestate: Option<String>,
    baggage: Option<String>,
}

$ rg -l "TraceContext" src/
src/gateway/meta_mcp/trace_correlation_tests.rs
src/gateway/meta_mcp/invoke.rs
src/protocol/trace.rs
$ rg -c "baggage" src/ | wc -l
       1
```

Two further checks were run after the four above, and they are the pair that moved the plan:

```
### check 5 — from_meta parses all three fields, to_meta writes all three back
$ sed -n 53,88p src/protocol/trace.rs
        let passthrough = |key: &str| meta.get(key).and_then(Value::as_str).map(str::to_string);
        Some(Self {
            traceparent: traceparent.to_string(),
            trace_id: trace_id.to_string(),
            tracestate: passthrough("tracestate"),
            baggage: passthrough("baggage"),
        })
    ...
    pub fn to_meta(&self) -> Value {
        let mut meta = json!({ "traceparent": self.traceparent });
        ... for (key, value) in [("tracestate", ...), ("baggage", ...)]

### check 6 — when the baggage field landed, and that it is behind the pin `b8cfc7e4`
$ git log -1 --format='%h %ad %s' --date=short baa318b2
baa318b2 2026-08-31 feat(trace): carry baggage across the gateway hop
$ git merge-base --is-ancestor baa318b2 b8cfc7e4 && echo "IS ANCESTOR of b8cfc7e4"
IS ANCESTOR of b8cfc7e4

### check 7 — the pin itself, which every other check was asserted against
$ git rev-parse --short HEAD
f2cf01b9
$ git merge-base --is-ancestor b8cfc7e4 f2cf01b9 && echo "IS ANCESTOR of f2cf01b9"
IS ANCESTOR of f2cf01b9
$ git diff --stat b8cfc7e4..f2cf01b9 -- src/ | wc -l
       0
$ git status --porcelain -- src/protocol/trace.rs src/gateway/router/helpers.rs \
    src/gateway/router/handlers.rs src/gateway/server/mod.rs src/gateway/meta_mcp/invoke.rs | wc -l
       0
```

**What this changed, and why it was not carelessness.** Checks 4, 5 and 6 falsify a statement
this plan carried in three places — that `baggage` was absent from `TraceContext` and that a
three-field assertion could not compile. Check 3 falsifies a fourth — that `TraceContext` was
called nowhere; `invoke.rs:1845-1847` calls it, at the arguments level.

Both statements were **true at `5c7e64f4`**, the commit the companion design pins and reads every
`file:line` from. `baa318b2` (21:23) added the `baggage` field and its parse; `d4874a25` (21:33)
wired `from_meta` into the invoke path as a transparency-log correlation key. Both landed roughly
four and a half hours after that pin, and neither is an ancestor of it. The design's evidence is
sound; this plan's error was to inherit commit-pinned facts and restate them as facts about
**HEAD** without pinning HEAD — a reference that moves while the sentence does not. §5 now carries
the pin that would have caught it, which is the durable half of this repair. Every red/green grade
that rested on the falsified statements is re-derived from the carrier and the reach, which checks
1, 2 and 3 do support.

**What it did not change.** Checks 1, 2 and 3 confirm the plan's core claim unchanged:
`extract_tools_call_params` discards everything but `(tool_name, arguments)`, both routes
destructure exactly that pair, and the one production read is at the args level. The gap OTEL.1.a
exists to close is real. It is a different gap from the one this plan first described, and a
narrower one.

**Honest limit.** These are source reads, not test runs. This document is a test plan: no test it
specifies has been written, so it produces no execution evidence and §9's G10-G12 remain
"partially — planned, not executed". A source read proves what HEAD says; only a run proves what
HEAD does.
