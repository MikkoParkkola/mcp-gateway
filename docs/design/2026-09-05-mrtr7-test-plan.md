# MRTR.7 wiring — test plan

Companion to `docs/design/2026-09-05-mrtr7-bridge-wiring.md`. Written before any
test code, to be reviewed **as a plan**: every acceptance criterion gets a case
or a stated reason it has none, and every named case must be able to fail.

## What the existing 21 rows already cover, and what they cannot

`tests/mik_7212_mrtr7_bridge_acs.rs` drives `InputBridge::run` through trait
fakes and receives the capability value as a **parameter**. That is the right
shape — no fixture reimplements a capability store, so none of those rows can
pass by testing its own scaffolding. It is also the limit: every one of them
begins after the decision the wiring change actually makes. Nothing in that file
observes which value the caller passed, where it came from, or whether the caller
exists at all. The 21 rows stay green whether or not this change ships.

So the delta below is entirely at the **call site**, and one row is end-to-end.

## Rows

| AC | criterion | case | level | type | how it can fail |
|---|---|---|---|---|---|
| `MIK-7212.WIRE.1` | A modern request that declared at `initialize` and sent no `_meta` is still refused | drive `invoke` with a modern-shaped request, session declaration present, `_meta` absent; assert MRTR.9 refuses and nothing is asked | integration | negative | an unconditional merge makes it bridge; the assertion is on the refusal AND on zero client frames |
| `MIK-7212.WIRE.2` | A legacy request with a session declaration is bridged | same call site, legacy shape, session declaration present; assert the client is asked | integration | positive | a shape check inverted, or the session store never read, leaves the client unasked |
| `MIK-7212.WIRE.3` | A legacy request with no session declaration is refused | legacy shape, empty session; assert refusal | integration | negative | fail-open on an absent declaration bridges instead of refusing |
| `MIK-7212.WIRE.4` | A modern request reads only its own `_meta` | modern shape, `_meta` declares sampling, session declares elicitation; stage one sampling request (permitted) and one elicitation request (refused) and assert each outcome, rather than inspecting the merged value | integration | boundary | the merge leaking into the modern path admits elicitation |
| `MIK-7212.WIRE.5` | Every backend attempt is accounted exactly once, including bridge retries | one call that bridges and retries twice; assert the backend was invoked three times and that each sink — invocation metrics, error budget, cost tracker, spend record — carries three, not one | integration | positive | the pre-factoring code counts only the first attempt — this row fails against today's tree, which is what makes it load-bearing |
| `MIK-7212.WIRE.6` | The retry bound is enforced against the accounted attempts, not a separate counter | drive past the bound; assert refusal and that accounting agrees with the attempt count | integration | boundary | two counters drifting apart passes a bound check while over-billing |
| `MIK-7212.WIRE.7` | A declaration dies with its session | capture at `initialize`, then DELETE the session; assert a later request under a reused identifier is refused | integration | negative | a declaration outliving its session grants inherited permissions — assert on the **refusal**, not on a map being empty, or the row passes against a store nobody reads |
| `MIK-7212.WIRE.8` | The whole path composes over real HTTP | one test: `initialize` declaring a capability, a backend that asks, delivery over live SSE, the answer POSTed back and correlated, the backend retried with it, then session cleanup | system | end-to-end | every fake in rows 1-7 is replaced by the production transport; this is the only row that can fail because an adapter was never constructed |
| `MIK-7212.WIRE.9` | A successful bridge retry is judged on its own result | a backend that asks once and then succeeds; assert the idempotency key is settled as completed, the response is returned, and the settled result is cached — an equivalent follow-up call is served without a further backend invocation, since the cache gate at `invoke.rs:1769` is the second consumer of the same verdict | integration | regression | `invoke.rs:1475` computes `stopped_to_ask` from the *first* result, so a passing test here proves the verdict is re-derived after the retry — against today's tree the key stays unsettled and the row fails |

`WIRE.8` is the row the reviewers asked for and the only one that proves the new
call site exists. Rows 1-7 would all pass against a well-tested function nobody
calls; `WIRE.8` would not.
| `MIK-7212.WIRE.10` | An initialized stdio caller is still refused | stdio session declares elicitation at `initialize`, backend asks; assert the MRTR.9 refusal is returned immediately, no client request is sent, and no retry occurs | integration | regression | this row is not `#[ignore]`d: the refusal is stdio's behaviour until MIK-7387 lands, and a transport-scope regression would turn it into a 30–120s stall |

## The two questions a plan review answers

**Does every acceptance criterion have a case, or a stated reason it has none?**
Yes, with one qualifier. The ten `MIK-7212.WIRE.*` rows above each carry a case.
The criteria this change does not add a case for are named in the section below,
each with its reason, not skipped. The qualifier is the twenty-one existing
MRTR.7 rows in `tests/mik_7212_mrtr7_bridge_acs.rs`: today they are accounted
for by count, not by name, so a duplicate or an omission inside that set would
not show. Mapping each row to its test name is scheduled before implementation
handoff; until that lands this answer rests on an aggregate, and an aggregate
cannot show a gap.

**Can each named case actually fail?** Yes — the rightmost column of the table
is that answer, per row, and it is the reason the column exists. Five rows fail
against today's tree for a reason stated at source (`WIRE.5`, `WIRE.6`,
`WIRE.9`, and the two halves of the gate in `WIRE.1`/`WIRE.3`), which is the
strongest form of the answer: the case fails now and passing it is what the
change buys. No row's fixture constructs the condition it then asserts, and no
row is staged so that its assertion is true before the production code runs —
the failure mode `test-plan-honesty` exists to catch. `WIRE.8` is the one row
whose failure would be an environment failure as easily as a defect, because it
drives real HTTP; it is kept because nothing else proves the path composes, and
its diagnosis cost is the price of that proof.

## Criteria with no case, and why

- **MRTR.7a/7b on legacy stdio** — no drivable surface in this change. The three
  rows exist in `tests/mik_7212_mrtr7_stdio_acs.rs`, are `#[ignore]`d against
  MIK-7387, and become that package's acceptance evidence.
- **The two `input_bridge.rs` defects** (discarded timeout at `:433`, pending-map
  growth at `:430`) — confirmed, out of scope for a wiring change, and disposed
  in the design's finding table. They get cases when they get a change.

## What this plan does not claim

That rows 1-7 prove the feature works. They prove the **decision** is right at
the call site. `WIRE.8` is the only row that proves the wiring, and a plan that
shipped rows 1-7 alone would report full coverage of a disconnected bridge.
