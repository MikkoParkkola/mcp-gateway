# CONFIRM.2 / Option I — test plan

Companion to `docs/design/2026-09-06-confirm-2-destructive-confirmation.md`. Written before any
test code, per `development-process.md` §P2: one row per acceptance criterion, the case that
proves it, its V-model level, its type. An empty evidence cell is the finding, not a gap to be
filled quietly.

Scope (§P0). **FOR**: the cases that would prove Option I's seven items meet the acceptance
criteria they answer to. **OUT**: Option R's cases (the branch was not taken), the legacy
elicitation path beyond one regression row, and anything the criteria do not name.

## The one thing every reader gets wrong here

**"At the gate" is load-bearing in every MRTR row below.** MRTR.8a/8b, 9/9a and 10a/10b already
have passing tests on the *invoke* path, and those tests are **not evidence for this change**.
`gateway_kill_server` never enters the funnel that calls `enforce` — the design measures this,
sole production call at `invoke.rs:1177` — so the gate is a new call site with none of the
invoke path's bounds, capability checks or idempotency entry. A reviewer ticking "does MRTR.8a
have a test?" will find the invoke-path one and close a cell that is empty. Each row below
states the call site it observes; a case that exercises `enforce` satisfies none of them.

## The table

| AC | the case that proves it | level | type | branch |
|---|---|---|---|---|
| `MIK-7246.CONFIRM.2` | modern caller, no session, destructive call → `input_required` result carrying the question → retry with `inputResponses` + `requestState` → continuation redeemed, kill proceeds. End to end over the transport, not against the gate function | system | functional | Option I |
| `MIK-7246.CONFIRM.1a` | modern caller that declared **no** input capabilities is still refused, `-32001`, message still containing `none could be obtained` (see the string collision below) | integration | negative | either |
| `MIK-7246.CONFIRM.1b` | legacy path still warns and proceeds; Option I changed the modern branch and must not have moved this one | integration | regression | either |
| `MIK-7212.MRTR.9` / `.9a` | **at the gate**: with `caller.input_capabilities` absent the gate refuses rather than asking; with the mode declared it asks, in the declared mode. Two cases, one per direction — the refusing half alone cannot distinguish "checks the declaration" from "never asks anyone" | unit + integration | negative | Option I (item 5) |
| `MIK-7212.MRTR.8a` / `.8b` | **at the gate**: a client that mints a confirmation continuation and never retries. Bound observed as a **count of live continuations** under an injectable clock, not a sleep | unit | resource | Option I (item 6) |
| `MIK-7212.MRTR.10a` / `.10b` | **at the gate**: duplicate delivery of a call whose confirmation was redeemed and whose kill succeeded returns the **recorded result**. This is the floor's `retry_after_redeemed_confirmation_returns_recorded_result` | integration | idempotency | Option I (item 7) |
| item 4 — gate precedence | a valid retry is redeemed **before** gate re-entry: assert the gate was **not entered** (refusal absent, gate counter unmoved), not merely that the retry succeeded | integration | ordering | Option I (item 4) |
| item 3 — typed origin | a gateway-authored continuation is **not** routed as a backend by `retry_origin_backend` (`invoke.rs:497-513`) | unit | correctness | Option I (item 3) |
| U2 record | a record is emitted for a **refused** kill — **CONDITIONAL, and U2 is open.** U2's bad-resolution field accepts "4.0.0 needs no record" as a recorded residual, so this row exists only if the ruling owes a record. Listed rather than dropped so its absence is visible | integration | audit | either, conditional |

Items 1 and 2 (emit-side constructor/serializer; mint-and-redeem reachable from the gate) get **no
row of their own, and that is the answer, not an omission**: they are mechanism serving CONFIRM.2,
and the CONFIRM.2 system case fails if either is wrong. Seven design items are not seven criteria.

`modern_path_refuses_unconfirmable_destructive_call` is **absent on purpose**. It is the floor's
Option R test, asserting a wire string stating that this request's declared protocol version has
no confirmation channel. Under Option I that sentence is false by construction. Spent, like the
time-box clause — marked, not deleted.

## The string collision — read before writing CONFIRM.1a's row

`tests/mik_7215_acs.rs:743` and `:990` assert the refusal message contains `none could be
obtained`, and both fixtures send `"clientCapabilities": {}` — precisely the caller Option I's
item 5 must refuse for a *different* reason (C3: the client never declared it could answer). If
the C3 refusal replaces that wording, two committed assertions die when item 5 lands.

**The repair is not to loosen them.** CONFIRM.1a is closed with a falsifier on record; weakening
its string check re-opens the criterion silently, which is worse than a red test. The C3 refusal
must be a **superset**: keep the existing sentence and name the missing capability in addition.
That constraint is a plan row because it is a decision about what the code must say, and the
plan is where a reviewer can still argue with it.

## §P2 plan-review questions, answered

**Q1 — does every acceptance criterion have a case, or a stated reason it has none?** Yes. Nine
rows above; items 1-2 carry their stated reason; the U2 row carries its condition. No empty cell
is left unexplained.

**Q2 — can each named case actually FAIL?** Two rows could not, as first drafted, and are written
above in the form that can:

- **Item 4 (precedence).** "The retry succeeds" passes under a wrong order that happens to
  terminate. Falsifiable only by asserting the gate was *not entered*.
- **Item 6 (bounds).** "State does not leak" is unobservable without a count of live
  continuations. A sleep-based version is the timing class `development-process.md` sends to a
  deterministic harness — hence the injectable clock.

Item 7's falsifier is free: the design states the wrong behaviour outright (gate-first → the
second delivery is refused), so the case asserts the **recorded result comes back**, not merely
that no error occurred. No case above stages its own assertion true; no fixture replaces the
production code it observes.

## What this plan does NOT prove — U1

The CONFIRM.2 and item-7 cases drive a **synthetic** client that retries. U1 asks whether a real
modern client, having declared in-band `elicitation`, actually does. Nothing here answers that,
and a green table is not U1 closed. U1 was re-pointed onto items 4, 6 and 7 by the standing
ruling; if no real client retries, that is a finding carried to the operator with the measurement
attached, never a fallback the slice elects.
