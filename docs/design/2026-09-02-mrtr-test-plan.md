# Cluster A test plan — one case per MRTR acceptance criterion

Status: **plan, submitted for review as a plan.** No test code exists for the nine blocking rows.
Scope (§P0) — FOR: naming, for every MRTR criterion, the case that proves it, the level it belongs
at, and what makes that case able to fail. OUT: implementation, and any criterion outside
`MIK-7212.MRTR.*` (clusters B–F have their own rows and are not covered here).

Why a plan and not tests first: tests written straight from a design inherit the design's happy
path. The plan's first draft left one row with no case at all and called that empty cell the
finding; review disagreed, and was right — see "What review changed" below. No row is empty now.

## Levels

`unit` = a function against constructed values, no transport. `component` = the gateway's own
request path with a stubbed backend, no network peer. `integration` = two gateway processes with
*independent* key material — not two replicas over a shared store, which is the arrangement the
accepted design rejects (`2026-08-30-shared-continuation-state.md:107`). The level is chosen by what the criterion asserts, not by what
is convenient: a criterion about *what crosses the wire* cannot be proved at `unit`, and a
criterion about *a value's shape* does not need a second process.

## The matrix

| criterion | the case that proves it | level | type | can it fail? |
|---|---|---|---|---|
| MRTR.1 carry `inputResponses`/`requestState` on a retry | four shapes through the component path — both fields, responses-only, state-only, neither — each reaching the backend with exactly what it carried | component | table-driven positive + control | today it fails at the router refusal, which is the free failure §P2 wants |
| MRTR.2 mint our own envelope, never forward the backend's | backend returns a `requestState` string; the value the client receives is not that string and verifies under our key | component | negative (anti-passthrough) | **not held — see "What self-QA found" below.** `ac_mrtr_2_*` asserts confidentiality against a hand-built `Keyring` token at `unit` level; no case drives the gateway path with a backend-supplied state |
| MRTR.3 client-presented state is attacker-controlled | four presentations — unsigned, signed by a foreign key, truncated, and tampered-payload-with-valid-tag — each refused with a distinct reason | unit + component | negative, table-driven | each row constructs a value the verifier must reject; a verifier that returns `true` unconditionally fails all four |
| MRTR.4 bound to principal + original request | a continuation minted for principal A and tool T is refused when presented by principal B, and when presented by A against tool U | component | negative pair | the two negatives differ in exactly one field from a positive that must still pass — the positive is what stops a blanket-refusal implementation passing |
| MRTR.5 single-use + expiry, atomic, across replicas | (a) second redemption of the same handle is refused; (b) a handle past its deadline is refused; (c) two concurrent redemptions on the minting process yield exactly one success; (d) a handle minted by one process is refused by a second process with independent key material | (a)-(c) component; (d) integration | negative + concurrency | (c) fails on a non-atomic ledger; (d) fails if key material is ever shared or if refusal is silent rather than explicit |
| MRTR.6 retry reaches the replica holding the exchange, or fails explicitly | a retry presented to a process that does not hold the exchange returns a named error and starts nothing — the accepted design refuses rather than routes, because the second process cannot open the envelope at all | integration | negative | the failure mode is *silently starting over*, which looks like success to any assertion that only checks for a 200 |
| MRTR.7 modern result bridged to a legacy client | a backend `InputRequiredResult` reaches a client that declared no round support as a server-initiated prompt, and the client's answer returns to the backend as `inputResponses` | component | end-to-end within the gateway | the bridge design is written (`2026-09-01-mrtr7-legacy-client-bridge.md`); the case asserts on both directions, so a bridge that prompts and drops the answer fails |
| MRTR.8 in-flight state bounded and reclaimed | count bound: N+1 concurrent exchanges evicts or refuses, never grows; lifetime bound: an abandoned exchange is gone after its deadline | component | resource | the reclamation design (`2026-09-01-nfr-perf3-reclamation.md`) names the observation point; a test asserting only "memory did not grow" cannot fail deterministically and is not the case |
| MRTR.9 never send an undeclared *type* | every supported request type, plus an unrecognised one and one carrying no method, against a client that declared only `elicitation`; one declared-type positive control | component | table-driven negative + control | partly held: `ac_mrtr_9_*` already covers the unrecognised type, the missing method, and per-entry judgement. What a single `sampling` row could not do is fail when a *different* undeclared type is relayed, so the row is a table rather than one case |
| MRTR.9a never send an undeclared **mode** | a client declares `elicitation` in form mode only; the gateway is driven to relay a URL-mode elicitation and must refuse. Plus an empty declaration (what the default is) and a declared-mode positive | component, at the wire | table-driven negative + control | fails today, on a criterion nothing enforces — the free failure §P2 asks for |
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

Most rows are `component`, two are `integration`, one is `unit`, and none is empty. The two
`integration` rows (MRTR.5d, MRTR.6) are the only ones needing a second process, so they are the
fixture cost of the cluster; every other row runs in-process. Writing the
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

## What review changed

`gpt-review` returned **SHIP-WITH-FIXES** on the first draft. `grok-review` could not run —
`API error (status 402 Payment Required): Grok Build usage balance exhausted` — so this plan carries
one vendor's verdict, not two, and the dual gate stays open. The wrapper exited 0 with an error in
its body; per §PA the ledger row for that leg is an error, not a verdict, and nothing is scraped
from the text.

Four findings, all accepted, one of them structural:

**The MRTR.9a exemption did not survive.** The draft argued no test could be written because the
declaration type carries no mode field. That confuses the Rust type with the wire: a client can
declare form mode in raw JSON and the gateway can be driven to relay a URL-mode elicitation, today,
with no new field anywhere. The case fails now, which is exactly the free failure the criterion was
being excused from. The excuse was more comfortable than the test — that is what made it worth
checking.

**The MRTR.5 fixture tested a mechanism we do not deploy.** The draft assumed two replicas over a
shared store. The accepted design says the opposite in terms: *key material is per process and is
never shared* (`2026-08-30-shared-continuation-state.md:107-120`), and cross-replica single-use is
satisfied by refusal — a second process cannot open the envelope, so it never reaches a ledger. The
row now mints on one process and asserts explicit refusal on another. Left as drafted, this test
would have passed against a design nobody agreed to build, and its passing would have been evidence
of nothing. MRTR.6 carried the same assumption and is corrected the same way.

**Two rows were single cases where the criterion is plural.** MRTR.1 tested both-fields-present when
a retry may legitimately carry one; MRTR.9 tested `sampling` when the criterion covers every
undeclared type. Both are now tables. Neither single case could fail on the shapes it omitted.

One reviewer remark is recorded without action: the verdict line refers to an invalid oracle in
MRTR.3, but no finding block was filed for it and the row's four presentations each construct a
value a correct verifier must reject. Unverified at source, so it is neither fixed nor dismissed —
it goes to the second leg when a second leg is available.
