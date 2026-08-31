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
| EXT.1.b | the map is populated from implemented extensions only; today `{}`, and `{}` is not the same wire value as an absent key | design §3.1a, §3.1b |
| EXT.1.c | the client's `ExtensionSet` is recovered from the **raw** `_meta[KEY_CLIENT_CAPABILITIES]` object, not from `declared_capabilities` | design §2.4, §3.2.A |
| EXT.1.d | absent extension ⇒ revert to core behaviour; never refuse the request | criterion text; design §3.2 |
| OTEL.1.a | the three W3C fields are read from the inbound `_meta` | criterion text; design §3.4 |
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
| EXT.1.a | **E1** `build_initialize_result` is called and its result serialised to `serde_json::Value`; assert the object's key set contains `extensions` and that the value is a JSON **object** (not null, not a string). Repeated against `discover_document`'s `capabilities` member so both entry points are named, not inferred from the shared builder. | unit | contract / serialisation | **Yes.** `ServerCapabilities` (`types.rs:232-254`) has no such field, so the key cannot appear. |
| EXT.1.b | **E2** with the gateway's implemented-extension source empty, assert the serialised value is exactly `{}` — key present, zero members — and separately assert the key is **not** omitted (i.e. the field carries no `skip_serializing_if` that would collapse empty to absent). | unit | contract / serialisation | Yes, for the same reason as E1. **But see §4 — on its own this case cannot distinguish a wired populate from a defaulted field.** |
| EXT.1.b | **E3 (the discriminator)** call the builder with an implemented-extension source containing one synthetic identifier `example.test/probe`, and assert the wire carries `{"example.test/probe": {}}` — key identity asserted as a literal (A4, A8). Then the empty-source case E2 is meaningful, because the same code path demonstrably varies with its input. | unit | contract, A7 constant-perturbation | Yes. Requires the builder to take the set as an **argument or injectable source**, not to read a module-level constant — see §5.1, a testability requirement this plan places on the implementation. |
| EXT.1.c | **E4** construct a request body whose `_meta["io.modelcontextprotocol/clientCapabilities"]` is `{"extensions": {"example.test/probe": {}}}`; assert the negotiation input parsed by `from_capabilities()` contains that identifier. Assert against the literal identifier, never against `from_capabilities()`'s own output on the same input (A8). | unit | parsing | Yes — nothing calls `from_capabilities()` from the request path (`rg gateway_declares/ExtensionSet:: src` matches only the module). |
| EXT.1.c | **E5 (the anti-`declared_capabilities` case)** same body, but assert the recovered set is empty when the capabilities object is `{"extensions": {}}` **and** non-empty for E4's body. `declared_capabilities` reduces both to the same one-element name list `["extensions"]` (`meta.rs:186-190`), so an implementation that reads the name list passes E4 and **fails E5**. This is the case that distinguishes the two implementations; E4 alone does not. | unit | negative / discrimination | Yes. |
| EXT.1.d | **E6** a request that uses an extension-gated behaviour while the client declared no extensions: assert the response is a **successful core-behaviour response**, and assert on its identity (the ordinary `tools/call` result shape), not merely on "not an error" (A3). | integration | behavioural | Yes — no negotiation exists on the request path today, so there is no branch to take. |
| EXT.1.d | **E7** the refusal-shape negative: same request, assert the response is **not** a JSON-RPC error and no error code is emitted. Paired with E6 because "revert" and "reject" are the two spec-permitted answers and the design chose revert; a case asserting only success would also pass a build that never consulted the client at all. E7's value is bounded — see §4.2. | integration | negative | No, on its own. Recorded as such rather than counted. |

## 4. Where a case cannot distinguish two implementations — said plainly

### 4.1 The empty-set trap: `extensions: {}` proves less than it looks

`{}` is what a correctly wired populate emits today, and it is **also** what a struct field
added and never assigned emits, because `build_initialize_result` ends in
`..Default::default()` (`meta_mcp_helpers.rs:164`). Design §3.1b names this a silent-success
shape. Restated as a test fact:

- E2 asserting `extensions == {}` passes against the wired implementation.
- E2 also passes against a one-line struct change with no builder assignment at all.
- E2 therefore proves the **field exists**, not that the **wiring exists**. It is a real case
  for EXT.1.a and a vacuous one for EXT.1.b.

The only honest discriminator is E3: perturb the input, require the output to change (A7). It
converts E2 from "the value is empty" into "the value is empty **because the source is empty**",
which is the clause's actual claim. If the implementation makes the source non-injectable, E3
becomes impossible and **EXT.1.b has no honest case** — the plan would then carry an empty cell,
not a weaker assertion. §5.1 states the requirement that keeps that from happening.

A second thing E2/E3 cannot see: whether `{}` is *correct*. The declaration is honest only
because no extension is implemented today. Nothing in this suite would catch a future change
that implements an extension and forgets to register it — the map would still read `{}` and
every case would stay green. That guard belongs to TASK.1, which adds the first entry, and this
plan records it as inherited rather than claiming coverage it does not have.

### 4.2 E7 is a weak case and is labelled one

E7 asserts an absence (no error). An implementation that never reads client capabilities and
always runs core behaviour satisfies it. It earns its row only as the paired half of E6 —
together they say "core behaviour, and specifically not a refusal" — and it is recorded here as
non-discriminating so a later reader does not mistake it for evidence of negotiation. The
discrimination for EXT.1.d lives in E5 (the set is recovered correctly) plus E6 (core behaviour
runs). E7 covers the one thing those two do not: that the chosen branch is revert, not reject.

## 5. OTEL.1 — the coverage map

Every row below states its fixture direction explicitly, because the propagation trap is a
fixture trap: a case that seeds the **outbound** `_meta` and then asserts the value survives has
verified serde, not the hop. In every case here the trace values are placed **only** on the
inbound request body, and the assertion is made on the **outbound** params object that
`dispatch_to_backend` produces.

| clause | case | level | type | red on HEAD? |
|---|---|---|---|---|
| OTEL.1.a + .b | **T1 (the hop case)** inbound `_meta` carries `traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"`, `tracestate = "vendor=abc"`, `baggage = "k=v"`, and **no prompt-cache key**. Call `dispatch_to_backend`; assert the outbound params' `_meta` contains all three keys with those exact literal strings. Expected side is a literal, never `TraceContext::from_meta(inbound).to_meta()` (A8). | unit | propagation, positive | **Yes.** The `None` cache-key arm passes `base_params` through with no `_meta` at all (`invoke.rs:1934-1938`). |
| OTEL.1.b | **T2 (the merge case)** same inbound, **with** a prompt-cache key. Assert the outbound `_meta` contains the three trace keys **and** the cache key, by exact key set (A2) — not by "contains traceparent". A merge that overwrites `_meta` wholesale passes a contains-check and fails this. | unit | propagation, regression | Yes. |
| OTEL.1.c | **T3 (not-minted)** inbound `_meta` with **no** trace keys; assert the outbound `_meta` has **no** `traceparent`, `tracestate` or `baggage` key. Asserted as key-absence, not as "value is empty" — a minted root is a non-empty value and would be caught; an empty-string value would not be, so the absence form is the one that discriminates. | unit | negative | Partially. Today no `_meta` is written on the no-cache-key arm, so T3 passes vacuously against HEAD. **See §6.2** — this case is honest only when run beside T1, and the plan records that dependency rather than claiming an independent red. |
| OTEL.1.c | **T4 (rejected ⇒ dropped, not minted)** inbound `traceparent` malformed in exactly one way (A9: `"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7"` — three parts, everything else valid); assert no `traceparent` on the outbound, **and** assert the request still succeeds. Distinguishes drop from both mint and reject. | unit | negative | Yes. |
| OTEL.1.d | **T5 (baggage independence)** inbound carries a valid `baggage` and **no** `traceparent` at all; assert the outbound `_meta` carries the `baggage` literal. This is the case option 3.4.E would fail. | unit | negative-space, discrimination | Yes — `baggage` appears nowhere in `src` (`rg -i baggage src` = 0). |
| OTEL.1.d | **T6** inbound carries a **malformed** `traceparent` and a valid `baggage`; assert `baggage` survives and `traceparent` does not. Separates "baggage independent of *absent* traceparent" (T5) from "independent of *rejected* traceparent", which is a different code path. | unit | negative | Yes. |
| OTEL.1.f | **T7 (the grammar rows)** one row per predicate §3.4b names, each breaking exactly one thing (A9): uppercase hex ⇒ rejected; version `ff` ⇒ rejected; all-zero `parent-id` ⇒ rejected; a five-field `traceparent` with a valid first four ⇒ **accepted**, and the outbound carries the first four fields as a literal. Each row asserts both sides — the input refused and a neighbouring input permitted (A1). | unit | parameterised, boundary | Yes, all four — the current predicate has the opposite behaviour in each. |
| OTEL.1.e | **T8 (bounds)** one row per bounded field: at the limit ⇒ propagated; one byte over ⇒ dropped, request still succeeds. Plus a charset row per field. Both sides pinned (A1). | unit | boundary | Yes — no bound exists today (F4). **Blocked on a number: see §6.1.** |
| OTEL.1.e | **T9 (constant perturbation)** change the bound constant and assert the same input changes outcome, so a hardcoded length beside the constant cannot pass (A7). | unit | A7 | Same block as T8. |
| OTEL.1.g | **T10 (non-interpretation)** two requests identical except for their trace values; assert the **cache key is byte-identical** across both, and that the resolved backend and tool name are identical. The cache key is the one interpretation channel that is mechanically checkable in-process. | integration | negative, security | No — nothing reads trace values today, so this passes on HEAD. Recorded as a **regression guard**, not as evidence the clause was newly met. |
| OTEL.1.g | routing, authorisation, policy and budget non-interpretation | — | — | **No case.** See §6.3. |
| OTEL.1.h | end-to-end across a real backend hop | — | — | **No case.** See §6.4. |

### 5.1 A testability requirement this plan places on the implementation

E3 and T9 both need an input the test can vary. Two constraints, stated here because discovering
them during implementation is what turns them into "we asserted the empty value instead":

1. `build_initialize_result` must take the implemented-extension set as a **parameter or
   injectable source**. A module-level constant read internally makes E3 unwritable, and EXT.1.b
   then loses its only honest case.
2. The bounded-read limits (design §4.2) must be **named constants**, so T9 can perturb them.

Neither is a design change — §3.1a already says the map is populated from a set, and §4.2
already says each bound is a named constant carrying its provenance. They are recorded as
test-visible consequences of decisions already taken.

## 6. The empty cells, each with its reason

An empty evidence cell is the finding. Four exist. None is tidied away, and none is downgraded
into a weaker case that would look green.

### 6.1 T8/T9 are blocked on a number, not on a design question

Design §4.2 defers the `tracestate` and `baggage` size limits to the implementer, "with the test
plan, so the boundary rows assert a real number rather than a placeholder". That trigger has now
fired: **this is the test plan, and the number is not yet pinned.** T8 and T9 are specified in
shape and blocked in value.

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
- if it resolves badly (no harness): OTEL.1 closes on emission evidence, and that limit is
  recorded against the criterion rather than left implicit

## 7. The A1-A9 sweep, and what it changed

Run before this document's first review. Recorded rather than silently fixed, because two
findings changed what a case does.

| rule | what the sweep found | what changed |
|---|---|---|
| A8 | An earlier draft of T1 asserted the outbound `_meta` equalled `TraceContext::from_meta(inbound).to_meta()`. That is the module under test on the expected side: it stays true after every predicate in `trace.rs` is deleted. | T1 now asserts literal strings. The round-trip identity, if wanted, becomes a separate assertion. |
| A5 | An earlier draft of T1 supplied a prompt-cache key "so the fixture is realistic". The cache-key arm already writes `_meta`, so the case would have passed against the unfixed conditional write — the exact defect F8 names. | T1 runs with **no** cache key. T2 was added to cover the merge. |
| A5 | T3 examined and found vacuous on HEAD. | Kept, with §6.2 stating the dependency instead of claiming a red. |
| A7 | E2 asserted an empty map — the empty-set trap. | E3 added as the discriminator, plus the §5.1 injectability requirement that makes it writable. |
| A9 | An earlier T4 broke two things at once (short `traceparent` **and** uppercase hex), so whichever check ran first decided. | One defect per fixture; T7 splits the grammar into four single-defect rows. |
| A4 / A2 | T2 asserted "contains traceparent". | Exact key set, so a wholesale `_meta` overwrite is caught. |
| A3 | E4 asserted the recovered set contained no forbidden identifier. True of an empty set. | Asserts the identifier that **did** arrive, and E5 supplies the negative. |
| A1 | T7's future-version row asserted only that a five-field input is accepted. | Also asserts the propagated value is the first four fields, as a literal. |
| A6 | No relative rule in this cluster — no time, freshness or ordering predicate. | N/A, stated. |

## 8. Execution order, before this suite is trusted

The two steps that get skipped, per the honesty protocol, are the two that collapse round count.

1. Write the cases.
2. Sweep A1-A9 again after writing — §7 is the pre-write sweep; the post-write one finds
   different things.
3. **Run the red suite and read the failure REASON of every case, not the count.** An assertion
   failure is the free proof that a case can fail. An `ERROR` — a panic, a missing fixture, a
   compile failure in the test module — means the harness is broken and the case would have
   failed against a *correct* implementation too. For this suite the distinction matters most in
   T1/T2, which call `dispatch_to_backend` and will `ERROR` rather than `FAILURE` if the backend
   stub is incomplete.
4. Then implement.

## 9. Readiness gates — applicable ones, checked

Against `rules-source/workflows/quality-gates-dor.md`. "Not applicable" carries its reason.

| gate | verdict |
|---|---|
| B4 acceptance criteria, stable IDs | Met. `MIK-7272.EXT.1` and `MIK-7272.OTEL.1` exist upstream; §1 decomposes them into clause IDs and traces each to a design sentence. |
| C3 test strategy | This document. |
| C11 contract tests | E1, E2, E3, T2 are contract/serialisation cases on the wire shape. |
| G6 alternatives | Held at design §3; a test plan does not re-open them. |
| G8 risks, G10-G12 fail-fast | Met in the form this step can meet them: §6 names four gaps, and the two cheapest discriminators (E3, T5) are the first cases to write — E3 decides whether EXT.1.b is provable at all, T5 whether `baggage` was built. |
| T0 contribution class | infrastructure/compliance — closing two spec MUSTs. |
| L1-L7 legal | N/A. No new dependency, no personal data, no crypto primitive, no cross-border flow. `baggage` may carry caller-supplied key/value pairs, which is why it is propagated opaque and never interpreted (design §3.4); operator question §4.4.4 owns whether relaying it is acceptable at all, and that is not a plan decision. |
| T1c PQC | N/A. No key agreement, no signature. |
| T6 numerical discipline | N/A. No quantisation, parallelism or collective. |
| G20 profiling-first | N/A. Not a performance change. |
| G13-G14 moat, T1b beyond-SOTA | N/A per the DoR's own auto-skip for infrastructure/compliance work. |
| B1-B5 backlog health | Inherited from MIK-7272; not re-litigated here. |

## 10. Open items this plan hands forward

| # | item | to whom |
|---|---|---|
| 1 | The `tracestate` and `baggage` bounds (§6.1). T8/T9 cannot be written until the numbers are pinned. | this ticket's implementer |
| 2 | The backend-capture harness (§6.4). Shared with cluster B1. | operator — it is a cross-cluster cost, not a per-cluster one |
| 3 | The injectable extension source and named bound constants (§5.1). | this ticket's implementer, at implementation time |
| 4 | Non-interpretation over authorisation, policy and budget (§6.3) is enforced by construction and review, with no case. | recorded as a limit against OTEL.1 |

The design's operator questions (§4.4) are unchanged by this plan and are not restated. One of
them bears on coverage: if §4.4.3 is answered "both routes", OTEL.1 gains the direct route
`POST /mcp/{name}`, which carries no `_meta` at all — and this plan gains a row it does not
currently have.
