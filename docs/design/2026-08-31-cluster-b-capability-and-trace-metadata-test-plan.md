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
| EXT.1.a | **E1** `build_initialize_result` is called and its result serialised to `serde_json::Value`; assert its **`capabilities`** member's key set contains `extensions` and that the value is a JSON **object** (not null, not a string). Repeated against `discover_document`'s `capabilities` member so both entry points are named, not inferred from the shared builder. | unit | contract / serialisation | **Yes.** `ServerCapabilities` (`types.rs:232-254`) has no such field, so the key cannot appear. |
| EXT.1.b | **E2** with the gateway's implemented-extension source empty, assert the serialised value is exactly `{}` — key present, zero members — and separately assert the key is **not** omitted (i.e. the field carries no `skip_serializing_if` that would collapse empty to absent). | unit | contract / serialisation | Yes, for the same reason as E1. **But see §4 — on its own this case cannot distinguish a wired populate from a defaulted field.** |
| EXT.1.b | **E3 (the discriminator)** call the builder with an implemented-extension source containing one synthetic identifier `example.test/probe`, and assert the wire carries `{"example.test/probe": {}}` — key identity asserted as a literal (A4, A8). Then the empty-source case E2 is meaningful, because the same code path demonstrably varies with its input. | unit | contract, A7 constant-perturbation | Yes. Requires the builder to take the set as an **argument or injectable source**, not to read a module-level constant — see §5.1. The source must be a **map of identifier strings**, not an `ExtensionSet`: `ExtensionSet` can only hold `Extension` variants, so a probe identifier is unrepresentable in it and the perturbation collapses. Substituting `Extension::Tasks` here is forbidden — it makes the case pass against an implementation that simply wired `gateway_declares()`, which is the wiring §0 puts out of scope. |
| EXT.1.c | **E4** construct a request body whose `_meta["io.modelcontextprotocol/clientCapabilities"]` is `{"extensions": {"io.modelcontextprotocol/tasks": {}}}`; assert the negotiation input parsed by `from_capabilities()` contains `Extension::Tasks`. The identifier must be a **recognised** one: `from_capabilities()` filters through `Extension::from_id` (`extensions.rs:71-90`), so a synthetic identifier is discarded **by a correct implementation** and a case asserting its recovery could never go green. Assert against the literal identifier, never against `from_capabilities()`'s own output on the same input (A8). | unit | parsing | Yes — nothing calls `from_capabilities()` from the request path (`rg gateway_declares/ExtensionSet:: src` matches only the module). |
| EXT.1.c | **E5 (the anti-`declared_capabilities` case)** same identifier, **non-object settings**: `{"extensions": {"io.modelcontextprotocol/tasks": 3}}`. Assert the recovered set is **empty**. A correct implementation drops it on the `settings.is_object()` filter (`extensions.rs:78`); an implementation that reached the same answer through `declared_capabilities` keeps it, because that path discards values and filters only nulls (`meta.rs:186-190`) — `3` is not null. Paired with E4, which must stay non-empty. This is the pair that distinguishes the two implementations; E4 alone does not, and the value must be non-null or both paths drop it and the discriminator collapses. | unit | negative / discrimination | Yes. |
| EXT.1.d | ~~**E6** behavioural revert~~ — **withdrawn at review.** With no extension-gated behaviour shipped, "reverted to core" and "never consulted the client" are output-identical: ordinary `tools/call` already succeeds. The case was marked red on HEAD and is not. **No case. See §6.5.** | — | — | **No.** |
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
verified serde, not the hop. In every case here the trace values are placed **only** on the
inbound request body, and the assertion is made on the **outbound** params object that
`dispatch_to_backend` produces.

The red/green column below rests on one verified statement of HEAD, checked at review rather than
assumed. `src/protocol/trace.rs` already carries both halves of the mechanism —
`TraceContext::from_meta` (`:32`) reads a `traceparent` and an optional `tracestate`, `to_meta`
(`:71`) writes them back out — and **neither is called anywhere**: `rg` finds no `TraceContext`
outside that module. `rg baggage src/` returns nothing at all. So the shape of the gap is not
"nothing exists" but "a correct, unwired, two-thirds-complete extractor exists": the
`traceparent`/`tracestate` parse is already right, `baggage` is absent from the struct, and no
request path reaches either function. Rows that assert `baggage`, that assert propagation, or
that assert a grammar predicate HEAD gets wrong are red. A row asserting only that a valid
`traceparent` parses would be **green today**, and none is written as if it were not.

| clause | case | level | type | red on HEAD? |
|---|---|---|---|---|
| OTEL.1.a | **T0 (the read case)** feed a whole JSON-RPC request body whose `params._meta` carries the three fields to the **production extractor** the request path uses (`TraceContext::from_meta`, `trace.rs:32`), reached the way the dispatch path reaches it — not by handing the fields in as a separate argument. Assert all three recovered values against the literals. Without this row, .a can be satisfied by an implementation that never reads the request body at all. **Route-level ingestion (HTTP, stdio) is still uncovered — see §6.6.** | unit | parsing | Yes, on the `baggage` half — verified at source: `TraceContext` (`trace.rs:19`) has fields for `traceparent`, `trace_id` and `tracestate` and **none for `baggage`**, so a three-field assertion cannot compile against HEAD, let alone pass. The `traceparent`/`tracestate` half is already green: the extractor exists and is correct. It is also **uncalled** — `rg` finds no `TraceContext` reference outside its own module — which is why .a needs §6.6's route coverage and not just this row. |
| OTEL.1.b | **T1 (the hop case)** inbound `_meta` carries `traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"`, `tracestate = "vendor=abc"`, `baggage = "k=v"`, and **no prompt-cache key**. Inbound `_meta` **also** carries an unrelated sentinel key `example.test/poison`. Assert the outbound `_meta` by **exact key set** — the three trace keys with those exact literal strings, and **no** `example.test/poison`. A contains-check passes an implementation that clones inbound `_meta` wholesale, which would relay attacker-controlled metadata to the backend; the exact key set refuses it (A2, and the provenance-strip rule at `invoke.rs:472`). Expected side is a literal, never `TraceContext::from_meta(inbound).to_meta()` (A8). | unit | propagation, positive | **Yes.** The `None` cache-key arm passes `base_params` through with no `_meta` at all (`invoke.rs:1934-1938`). |
| OTEL.1.b | **T2 (the merge case)** same inbound, **with** a prompt-cache key. Assert the outbound `_meta` contains the three trace keys **and** the cache key, by exact key set (A2) — not by "contains traceparent". A merge that overwrites `_meta` wholesale passes a contains-check and fails this. | unit | propagation, regression | Yes. |
| OTEL.1.c | **T3 (not-minted)** inbound `_meta` with **no** trace keys; assert the outbound `_meta` has **no** `traceparent`, `tracestate` or `baggage` key. Asserted as key-absence, not as "value is empty" — a minted root is a non-empty value and would be caught; an empty-string value would not be, so the absence form is the one that discriminates. | unit | negative | Partially. Today no `_meta` is written on the no-cache-key arm, so T3 passes vacuously against HEAD. **See §6.2** — this case is honest only when run beside T1, and the plan records that dependency rather than claiming an independent red. |
| OTEL.1.c | **T4 (rejected ⇒ dropped, not minted)** inbound `traceparent` malformed in exactly one way (A9: `"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7"` — three parts, everything else valid); assert no `traceparent` on the outbound, **and** assert the request still succeeds. Distinguishes drop from both mint and reject. | unit | negative | **Partially — same vacuity as T3.** HEAD writes no `traceparent` on this arm, so both halves are already true. Evidence only beside a green T1. §6.2 governs. |
| OTEL.1.d | **T5 (baggage independence)** inbound carries a valid `baggage` and **no** `traceparent` at all; assert the outbound `_meta` carries the `baggage` literal. This is the case option 3.4.E would fail. | unit | negative-space, discrimination | Yes — `baggage` appears nowhere in `src` (`rg -i baggage src` = 0). |
| OTEL.1.d | **T6** inbound carries a **malformed** `traceparent` and a valid `baggage`; assert `baggage` survives and `traceparent` does not. Separates "baggage independent of *absent* traceparent" (T5) from "independent of *rejected* traceparent", which is a different code path. | unit | negative | Yes. |
| OTEL.1.c | **T5b / T6b (tracestate is *not* independent)** the inverse pair, and the design makes it load-bearing: inbound carries a valid `tracestate` with **no** `traceparent` (T5b), then with a **malformed** `traceparent` (T6b). Assert `tracestate` is **absent** outbound in both, and the request still succeeds. `tracestate` is meaningless without the parent it annotates, so relaying it orphaned would send vendor trace state to a backend with nothing to correlate it to. Without these rows the plan asserts independence for `baggage` and says nothing about the field that must *not* be independent. Filed under **.c, not .d** — .c is the never-minted/nothing-survives-a-rejected-context clause, and these rows are that clause read on `tracestate`; .d is specifically `baggage`'s independence, which these rows do not exercise. | unit | negative, discrimination | **Partially — same vacuity as T3/T4.** HEAD writes no `_meta` on this arm, so "no outbound `tracestate`, request succeeds" is already true. Not an independent red; evidence only in a suite where T1 is green. §6.2 governs. |
| OTEL.1.f | **T7 (the grammar rows)** one row per predicate §3.4b names, each breaking exactly one thing (A9): uppercase hex ⇒ rejected; version `ff` ⇒ rejected; all-zero `parent-id` ⇒ rejected; a five-field `traceparent` with a valid first four ⇒ **accepted**, and the outbound carries the **whole five-field input** as a literal. Reading the first four is a *parse* rule (design §3.4b); the emit rule is byte-for-byte as received (design L238, L464). Asserting a four-field outbound would fail a correct hop and, if "fixed", would silently truncate valid future context. Each row asserts both sides — the input refused and a neighbouring input permitted (A1). | unit | parameterised, boundary | Yes, all four. Verified against `TraceContext::from_meta` (`trace.rs:32`): it accepts uppercase hex (`is_ascii_hexdigit` is case-insensitive), accepts version `ff`, checks the all-zero rule on `trace_id` only and not on the span id, and rejects any `traceparent` with other than exactly four parts. Each of the four rows asserts the opposite of what HEAD does. |
| OTEL.1.e | **T8a (charset)** one row per field, each breaking exactly one character class against the W3C grammar (A9), with the permitted neighbour asserted alongside (A1). Literal valid and invalid values pinned per field at writing time. | unit | boundary | Yes — no charset check exists today. **Not blocked**: charset is independent of the length numbers. |
| OTEL.1.e | **T8b (length bounds)** per bounded field: at the limit ⇒ propagated; one byte over ⇒ dropped, request still succeeds. Both sides pinned (A1). | unit | boundary | Yes — no bound exists today (F4). **Blocked on a number: see §6.1.** |
| OTEL.1.e | **T9 (constant perturbation)** a stated **mutation procedure**, not a unit case: patch the named bound constant in source, re-run T8b unchanged, require the verdict on the same input to flip. A runtime-injected bound would not prove the same thing — the point is that no hardcoded length sits beside the constant (A7). | procedure | A7 mutation | Same block as T8b. |
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

### 6.6 OTEL.1.a is covered at the extractor, not at the route

T0 feeds a request body to the production extractor and asserts the recovered context. That proves
the *parse* is real. It does not prove either transport hands the extractor a body to parse:
neither the HTTP nor the stdio route is exercised by any row here.

The split is deliberate — the transports are being edited concurrently under other tickets in this
cluster, and a row asserting their internals would be written against a moving target. The
consequence is stated instead of hidden: **if a route never calls the extractor, every row in §5
still passes.** T0 and T1 together bound the defect to "the fields are parsed and emitted
correctly once something on the request path reads them"; wiring that read is checked by the same
backend-capture harness §6.4 waits on, which observes the whole route rather than a seam inside it.

- owner: shared with §6.4 — the same harness answers both
- resolving action: one route-level case per transport, or the capture harness
- trigger: whichever lands first
- if it resolves badly: OTEL.1.a closes on extractor evidence with the route gap named in the
  closing comment, exactly as §6.4 requires for .h

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
4. Then implement.

## 9. Readiness gates — applicable ones, checked

Against `rules-source/workflows/quality-gates-dor.md`. "Not applicable" carries its reason.

| gate | verdict |
|---|---|
| B4 acceptance criteria, stable IDs | Met. `MIK-7272.EXT.1` and `MIK-7272.OTEL.1` exist upstream; §1 decomposes them into clause IDs and traces each to a design sentence. |
| C3 test strategy | This document. |
| C11 contract tests | E1, E2, E3, T2 are contract/serialisation cases on the wire shape. |
| G6 alternatives | Held at design §3; a test plan does not re-open them. |
| G0 biggest ROI, G4 requirements clear, G5 minimum scope | Met upstream. The criteria are release-blocking and already worded; §1 decomposes them without widening them, and §0 states what is out. |
| O1-O3 structure, clutter, naming | Met. One document, in `docs/design/`, named for its cluster and dated like its sibling design. |
| G8 risks | Met: §6 names four gaps and §10 hands them forward with owners. |
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
| 6 | Route-level ingestion of trace `_meta` on HTTP and stdio (§6.6). | shared with item 2 |
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
