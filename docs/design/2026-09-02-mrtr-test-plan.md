# Cluster A test plan — one case per MRTR acceptance criterion

Status: **plan, submitted for review as a plan.** No test code exists for the nine blocking rows.
Scope (§P0) — FOR: naming, for every MRTR criterion, the case that proves it, the level it belongs
at, and what makes that case able to fail. OUT: implementation, and any criterion outside
`MIK-7212.MRTR.*` (clusters B–F have their own rows and are not covered here).

Why a plan and not tests first: tests written straight from a design inherit the design's happy
path. The empty cell in the evidence column below is the finding — three rows have one, and they
are named as findings rather than filled with a case that would not have caught anything.

## Levels

`unit` = a function against constructed values, no transport. `component` = the gateway's own
request path with a stubbed backend, no network peer. `integration` = two processes, or two
gateway replicas sharing a store. The level is chosen by what the criterion asserts, not by what
is convenient: a criterion about *what crosses the wire* cannot be proved at `unit`, and a
criterion about *a value's shape* does not need a second process.

## The matrix

| criterion | the case that proves it | level | type | can it fail? |
|---|---|---|---|---|
| MRTR.1 carry `inputResponses`/`requestState` on a retry | a `tools/call` carrying both fields reaches the backend with both fields intact, and one carrying neither is unchanged | component | positive + control | today it fails at the router refusal, which is the free failure §P2 wants |
| MRTR.2 mint our own envelope, never forward the backend's | backend returns a `requestState` string; the value the client receives is not that string and verifies under our key | component | negative (anti-passthrough) | **not held — see "What self-QA found" below.** `ac_mrtr_2_*` asserts confidentiality against a hand-built `Keyring` token at `unit` level; no case drives the gateway path with a backend-supplied state |
| MRTR.3 client-presented state is attacker-controlled | four presentations — unsigned, signed by a foreign key, truncated, and tampered-payload-with-valid-tag — each refused with a distinct reason | unit + component | negative, table-driven | each row constructs a value the verifier must reject; a verifier that returns `true` unconditionally fails all four |
| MRTR.4 bound to principal + original request | a continuation minted for principal A and tool T is refused when presented by principal B, and when presented by A against tool U | component | negative pair | the two negatives differ in exactly one field from a positive that must still pass — the positive is what stops a blanket-refusal implementation passing |
| MRTR.5 single-use + expiry, atomic, across replicas | (a) second redemption of the same handle is refused; (b) a handle past its deadline is refused; (c) two concurrent redemptions of one handle yield exactly one success | (a),(b) component; (c) integration | negative + concurrency | (c) is the only one that can fail on a non-atomic store, and it needs two replicas against one store — a single-process test passes on a broken implementation |
| MRTR.6 retry reaches the replica holding the exchange, or fails explicitly | a retry presented to a replica that does not hold the exchange either routes to the holder or returns a named error — never a silent new exchange | integration | negative | the failure mode is *silently starting over*, which looks like success to any assertion that only checks for a 200 |
| MRTR.7 modern result bridged to a legacy client | a backend `InputRequiredResult` reaches a client that declared no round support as a server-initiated prompt, and the client's answer returns to the backend as `inputResponses` | component | end-to-end within the gateway | the bridge design is written (`2026-09-01-mrtr7-legacy-client-bridge.md`); the case asserts on both directions, so a bridge that prompts and drops the answer fails |
| MRTR.8 in-flight state bounded and reclaimed | count bound: N+1 concurrent exchanges evicts or refuses, never grows; lifetime bound: an abandoned exchange is gone after its deadline | component | resource | the reclamation design (`2026-09-01-nfr-perf3-reclamation.md`) names the observation point; a test asserting only "memory did not grow" cannot fail deterministically and is not the case |
| MRTR.9 never send an undeclared *type* | a client declaring only `elicitation` receives a refusal, not a `sampling` request | component | negative | held today by `ac_mrtr_9_*` |
| MRTR.9a never send an undeclared **mode** | **no case — this is the finding.** The criterion is ABSENT, not merely untested: the declaration type carries no mode field, so there is nothing a test could read. The work is three files (declaration type, per-method capability answer, the comparison), tracked as DE-9, and the test cannot be written before the field exists | — | — | a case written today would assert against a value that does not exist and would pass vacuously |
| MRTR.10a idempotency key includes the continuation inputs | two calls identical but for `inputResponses` produce different keys; two identical calls produce the same key | unit | positive + negative pair | held today by `ac_mrtr_10_*`; the pair is what makes it fail — a key ignoring the field passes the sameness half alone |
| MRTR.10b an InputRequired result is never cached as completed | a backend returning `input_required` leaves the cache untouched, and a subsequent identical call reaches the backend again | component | negative | held, and by more than this plan first credited: `tests/mik_7216_mrtr_10_acs.rs` covers both caches, the refusal, the control that final results still cache, and malformed result types — seven cases, not the one classifier assertion in `mik_7212_acs.rs` |

## What self-QA found

Four rows were submitted claiming an existing `ac_mrtr_*` test already held them. Checking that
claim before a reviewer was asked to — §P3a — broke two of the four, in opposite directions.

**MRTR.2 was overstated.** Both `ac_mrtr_2_*` tests construct a `Keyring` directly and assert on
the minted token: one round-trips it, the other checks the token contains neither the backend's
state nor its name. That is confidentiality at `unit` level against a value the test built itself.
The criterion is about what the *gateway* does when a *backend* hands it a state, and no test drives
that path — searching every test for a backend-supplied state returns only JSON-shape fixtures. A
passthrough regression in the gateway would leave all of `ac_mrtr_2_*` green. The row moves from
held to a case still to write, which makes the cluster ten cases rather than nine.

**MRTR.10b was understated.** The cited test asserts only that a classifier tells `input_required`
from `complete` — true, and not the criterion. The criterion is held elsewhere and better:
`tests/mik_7216_mrtr_10_acs.rs` asserts the idempotency cache does not serve an interim result, the
response cache does not store one, both still store final and legacy results, and neither stores a
malformed type. The plan cited the wrong file.

Worth stating plainly: the overstatement is the dangerous one. A row marked held is a row nobody
writes, and MRTR.2 is recorded `MET` in the release ledger on the strength of code wiring. The code
may well be right; the *test evidence* for it is thinner than the ledger's citation implies, and
that gap is now named rather than inherited.

## What the matrix says about order

Six rows are `component`, two are `integration`, one is `unit`, one has no case. The two
`integration` rows (MRTR.5c, MRTR.6) are the only ones needing a shared store and a second
replica, so they are the fixture cost of the cluster; every other row runs in-process. Writing the
in-process rows first is not a scheduling preference — MRTR.5a/5b and MRTR.4 exercise the same
mint-and-verify surface the integration rows depend on, so a defect there is cheaper to find
before two processes are involved.

## Two failure modes this plan is written against

**A fixture that replaces the code under test.** Every row above asserts against the gateway's own
mint/verify functions, not against a helper that re-derives what they should have produced. A test
whose fixture computes the expected envelope by the same rule as the implementation passes
whatever the implementation does.

**A case that cannot go red.** MRTR.8's lifetime bound is the one at risk: "state is reclaimed" is
easy to write as an assertion that never fails. The row names the reclamation design's observation
point precisely because a memory-shaped assertion would be theatre.

## The open question this plan does not answer

MRTR.6's "or fails explicitly" leaves the error's shape undecided — a named JSON-RPC code, or a
refusal reusing the MRTR.3 reason set. It is a design question, not a test question, and the case
above is written to accept either as long as the failure is *named*. Recorded here rather than
assumed: if the answer is a new code, this row's assertion tightens to that code.
