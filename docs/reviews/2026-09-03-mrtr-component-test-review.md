# Test review — the three MRTR component cases (cluster A)

Material: `tests/mik_7212_mrtr_component_acs.rs` as of `4cdf6958`, reviewed **as tests**
per development-process §P2.

## Verdicts

| leg | vendor | verdict |
|---|---|---|
| 1 | Codex/GPT (`gpt-review`) | **SHIP-WITH-FIXES** — 4 findings, 3 HIGH |
| 2 | Kimi (`kimi-review`) | **MISSING** — wrapper emitted a malformed tool call and exited "no valid final verdict" |

Leg 2 produced no ledger row. Per §PA the answer is `MISSING`, not a verdict scraped
from the body. The dual gate on this batch is **open**, and re-running leg 2 against
material already known to be defective would spend a run to learn nothing.

## The four findings, all CONFIRMED at source

**1 (HIGH) — the tests cannot pass after correct wiring, and cannot say which guard refused.**
Worse than reported. `ContinuationError::client_message()`
(`src/protocol/continuation.rs:234-236`) returns `"continuation rejected"` for *all seven*
variants, so `assert_refused_by_the_continuation_guard`
(`tests/mik_7212_mrtr_component_acs.rs:196-204`) cannot distinguish `NotAuthentic` from the
mechanism each case names. Independently: `post` (`:164-181`) sends no credential while
`mint_for` (`:132`) mints for a synthetic principal, and `session_owner_key`
(`src/gateway/router/handlers.rs:154-161`) resolves an unauthenticated caller to the **empty
string** — "that is not an identity, and the controls that key on this refuse". So the
MRTR.5d case, which expects a successful dispatch, can never go green however correct the
wiring is.

**2 (HIGH) — the gone-exchange case tests the wrong state.**
`ac_mrtr_6_a_retry_whose_exchange_the_origin_no_longer_holds_is_refused` (`:1031`) asserts
`in_flight().len() == 0` without ever staging a hold. An empty table is the *never existed*
state; the criterion is about an exchange the origin **no longer** holds. The comment at
`:1028-1030` defends the shortcut ("would test the same state by a longer route") and is
wrong on exactly that distinction.

**3 (MEDIUM) — the foreign-replica case observes nothing it claims.**
`ac_mrtr_6_a_retry_at_another_replica_is_refused_and_opens_no_exchange` (`:981`) mints on
`origin` and posts to `neighbour`, but never opens a hold on `origin`. Its own doc comment
(`:977-979`) promises the origin is left "holding the handle unspent" — there is nothing
there to hold or to spend.

**4 (HIGH) — the recorder control is on the wrong route.**
`fixture_control_a_fresh_call_reaches_the_backend` (`:540`) drives `fresh_body`, a
`gateway_invoke` shape (`:527-531`), not the retry route. A retry route incapable of *any*
dispatch satisfies every "the backend received nothing" assertion in the file.

## Disposal — elimination, not patching

Per the repair protocol, a test-plan finding is eliminated by default. After the repair the
findings must not be restatable.

The synthetic principal goes away entirely: the handle is obtained from the **production
mint path**. `mint_continuation` (`src/gateway/meta_mcp/invoke.rs:372-394`) binds
`principal_fingerprint(caller.verified_identity)` and returns `None` for a caller it cannot
identify, so an authenticated `gateway_invoke` against a fixture backend that returns an
interim exchange yields a real handle bound to the real principal. Recomputing the digest in
the fixture is refused for the reason the file already states at `:125-131`, and
`principal_of` (`src/gateway/auth.rs:38`) is `pub(crate)` and unreachable from an integration
test in any case. The auth fixture to copy is `tests/nfr_sec1_controls.rs:175-195`.

Findings 2 and 3 are eliminated by staging real holds. Finding 4 is eliminated by a
same-route positive control.

Finding 1's second half — one client sentence for seven causes — cannot be eliminated from
the test side. It collides with **DE-9**, the deferred decision on which error code a refusal
answers under (`docs/design/2026-08-30-mrtr-wiring.md` DE-8), which already has an owner.
Recorded there rather than resolved here.
