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
| `MIK-7246.CONFIRM.2` (also `MIK-7212.MRTR.1a` / `.1b`) | modern caller, no session, destructive call → `input_required` result carrying the question → retry with `inputResponses` + `requestState` → continuation redeemed, kill proceeds. End to end over the transport, not against the gate function. **This is also MRTR.1a/1b's case**: both fields are dropped today by `extract_tools_call_params` (`helpers.rs:178`), so nothing reaches the gate to redeem unless they survive the extractor — they need no row of their own, and a unit test on the extractor would prove less | system | functional | Option I |
| `MIK-7246.CONFIRM.1a` | modern caller that declared **no** input capabilities is still refused, `-32001`, message still containing `none could be obtained` (see the string collision below) | integration | negative | either |
| `MIK-7246.CONFIRM.1b` | legacy path still warns and proceeds; Option I changed the modern branch and must not have moved this one | integration | regression | either |
| `MIK-7212.MRTR.9` / `.9a` | **at the gate**: with `caller.input_capabilities` absent the gate refuses rather than asking; with the mode declared it asks, in the declared mode. Two cases, one per direction — the refusing half alone cannot distinguish "checks the declaration" from "never asks anyone" | unit + integration | negative | Option I (item 5) |
| `MIK-7212.MRTR.8a` / `.8b` | **at the gate**: a client that mints a confirmation continuation and never retries. Bound observed as a **count of live continuations** under an injectable clock, not a sleep | unit | resource | Option I (item 6) |
| `MIK-7212.MRTR.10a` / `.10b` | **at the gate**: duplicate delivery of a call whose confirmation was redeemed and whose kill succeeded returns the **recorded result**. This is the floor's `retry_after_redeemed_confirmation_returns_recorded_result` | integration | idempotency | Option I (item 7) |
| item 4 — gate precedence | a valid retry is redeemed **before** gate re-entry: assert the gate was **not entered** (refusal absent, gate counter unmoved), not merely that the retry succeeded | integration | ordering | Option I (item 4) |
| item 3 — typed origin | a gateway-authored continuation is **not** routed as a backend by `retry_origin_backend` (`invoke.rs:497-513`) | unit | correctness | Option I (item 3) |
| `MIK-7212.MRTR.3a` / `.3b`, `.4a` / `.4b` | **at the gate**: a continuation minted for one caller confirming one kill, presented (i) by a different principal and (ii) against a different server, is refused at redemption. The design's own S and T rows say this binding is inherited from `redeemable_by` (`continuation.rs:202-224`, live at `invoke.rs:556-570`) and that what Option I owes is **that the gate sits on that path rather than beside it** — an obligation the design names in prose and no row carried. Two negative cases; the valid retry in the CONFIRM.2 row cannot tell "verifies the binding" from "verifies nothing" | integration | negative | Option I (items 1-2) |
| `MIK-7246.CONFIRM.3` (dependency, not derivation) | every tool in the governed set is also admin-gated — `is_destructive_meta_tool` ⊆ `is_admin_meta_tool` (`src/gateway/destructive_confirmation.rs:218`, `src/gateway/router/authorization.rs:80`; the gate that consumes it, `src/gateway/meta_mcp/mod.rs:1585`). Option I does not change how the set derives; it **leans** on the snapshot, and this pins it. **In-crate `#[cfg(test)]`, not `tests/`** — `is_admin_meta_tool` is `pub(crate)` | unit | invariant | Option I (mitigation E) |
| U2 record | a record is emitted for a **refused** kill — **CONDITIONAL, and U2 is open.** U2's bad-resolution field accepts "4.0.0 needs no record" as a recorded residual, so this row exists only if the ruling owes a record. Listed rather than dropped so its absence is visible | integration | audit | either, conditional |

Items 1 and 2 (emit-side constructor/serializer; mint-and-redeem reachable from the gate) get **no
row of their own, and that is the answer, not an omission**: they are mechanism serving CONFIRM.2,
and the CONFIRM.2 system case fails if either is wrong. Seven design items are not seven criteria.

**`MIK-7212.MRTR.7a` / `.7b` get no row, and the reason is the design's own scope line.** They
are the *other* direction — a modern **backend** returning `InputRequiredResult` to a legacy
client. Option I makes the gateway the **author** of the question, never a relay for a backend's,
so no item in it touches the bridge. Both were scored unwired in `f2bcbd1d`, and the design lists
the InputBridge under what it does not touch: "not unblocked, not partially wired, not worked
around by this design" (blocked by MIK-7388). A case here would be a case for a different change.

**`MIK-7246.CONFIRM.3` gets a row, but not the row it looks like it wants.** Its derivation
requirement is already met and is declared OUT — "the set is what `is_destructive_meta_tool` says
it is". What Option I adds is a *dependency* on it: mitigation E (a confirmation must not widen
what the caller may do) rests on C4, the admin gate running first, and C4 is a **snapshot**, not
an invariant. If the derived governed set ever stops being a subset of the admin-gated set, E
lapses silently. Option R does not carry this — it refuses, so nothing widens. The row pins the
subset relation and nothing else; the meta-tools-only question stays the requester's.

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

**Q1 — does every acceptance criterion have a case, or a stated reason it has none?** Yes, and
the check is not a count of the rows above. Counting one's own table cannot find a criterion
nobody thought of: an empty cell is visible, an **absent row is not** — the same defect as the
"at the gate" warning, one level higher. So the criteria register was enumerated independently
and diffed against the table:

```
rg -o 'MIK-7212\.MRTR\.[0-9]+[a-z]?|MIK-7246\.CONFIRM\.[0-9]+[a-z]?' \
   docs/requirements/RELEASE-4.0.0-requirements.md | sort -u
```

**The register is the requirements file, and getting that wrong cost a row.** The first run of
this check enumerated the *design* instead. A design yields only the IDs it happens to discuss, so
it can no more show an unmentioned criterion than the table can — the same defect one level up
again. That run found `MRTR.7a/7b` and `CONFIRM.3`, both dispositioned above. Re-run against the
register — 26 IDs — it found what the design mentions nowhere as a criterion: the **redemption
bindings**, `MRTR.3a/3b` and `4a/4b`, which the design's own STRIDE S and T rows say Option I owes
at the gate, and which no row carried. That row exists now. A method whose second run finds more
than its first is the argument for publishing the method rather than the count.

The remaining ten register IDs are all `MRTR`, and get a clause each rather than ten rows:
`1a`/`1b` (the retry must carry `inputResponses` / `requestState`) are proved by the CONFIRM.2
row and are named on it; `5a` (single-use) is the 10a/10b row seen from the other side — a
redeemed continuation that mints a second kill fails that case; `5b` (expiry) is what makes item
6's count fall, under the same injectable clock; `2a`/`2b` are vacuous under Option I, which
authors the question rather than relaying a backend's, so there is no backend `requestState` to
forward or to wrap; `5c`/`5d`, `6` and `7` are multi-replica and bridge criteria the design lists
under what it does not touch.

Standing: eleven rows. **Eight carry a criterion ID** (CONFIRM.2, 1a, 1b, 3; MRTR.9/9a, 8a/8b,
10a/10b, 3a/3b+4a/4b). **Three are not criteria** and say so — items 4 and 3 are design items
whose failure is invisible in the CONFIRM.2 case, and the U2 row carries its condition. Items 1-2
carry their stated reason. MRTR.7a/7b carry theirs. Ten more carry a clause above. No cell is
empty and unexplained.

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

One row is green before a line of Option I exists, and that is not a Q2 failure. `CONFIRM.3` pins
an **invariant** — governed = {`gateway_kill_server`} ⊆ the four admin meta-tools, verified true
today at source. Q2 asks whether a case *can* fail, not whether it fails now: this one's falsifier
is the first destructive tool added outside the admin set, which is precisely what C4's snapshot
warning predicts and why the row earns its line. Reading Q2 as "every case must be red today"
would delete exactly the rows that catch a future change.

## What this plan does NOT prove — U1

The CONFIRM.2 and item-7 cases drive a **synthetic** client that retries. U1 asks whether a real
modern client, having declared in-band `elicitation`, actually does. Nothing here answers that,
and a green table is not U1 closed. U1 was re-pointed onto items 4, 6 and 7 by the standing
ruling; if no real client retries, that is a finding carried to the operator with the measurement
attached, never a fallback the slice elects.
