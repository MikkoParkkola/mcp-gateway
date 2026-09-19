<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# The four residue rows — what each one actually needs

`RELEASE-4.0.0-blocking-rollup.md` groups thirty-six blocking criteria into six
clusters and a five-row residue. This covers four of that five:
`MIK-7215.CONTROL.4`, `MIK-7246.CONFIRM.2`, `NFR.SEC.1`, `NFR.SEC.6`.
`MIK-7214.HEADER.9` belongs to the header increment and is not touched here.

No code is proposed below. Two of the four are settled by a test, one by an
operator decision, and one by a decision the design has to make first — and
they sort by that, not by size.

## The sort

| row | what it needs | who can do it |
|---|---|---|
| `NFR.SEC.1` | one test (row 2) and one reclassification (row 5) | the test is engineering; the reclassification is the operator's |
| `NFR.SEC.6` | one test on an existing fix, and a traceability call | the test is engineering; the call is the operator's |
| `CONTROL.4` | a design decision, then wiring | the decision is nobody's yet — see below |
| `CONFIRM.2` | a spec answer | the operator's alone |

## `NFR.SEC.1` — twelve of fourteen, and the two that are left

Eight refusal tests now run through the modern route in
`tests/nfr_sec1_controls.rs` (`cargo test --test nfr_sec1_controls`, 8 passed).
`docs/requirements/nfr-sec1-control-inventory.md` carries the set and the
per-row citations. What is left:

- **Row 2, agent JWT validity.** A genuine gap. Driving it needs an agent
  registry and a signed token — `AgentAuthState::new(true, registry)` with a
  populated `AgentRegistry`, which is a fixture, not a decision. Estimate one
  test; the falsifier is the same frame with a valid token.
- **Row 5, client circuit breaker.** *Probably not a gap.* The criterion says
  "refusal when its **input is absent**". A circuit breaker refuses on a trip
  count; it has no input to remove. Under the derivation rule that is
  N/A-with-reason. But the derivation rule is this document's, and narrowing
  what a criterion covers is a scope change in engineering's clothes — so it
  stays counted as a gap until the operator says otherwise. **Question:** does
  a control with no absent input count against `each`?

The firewall is the 15th gate and stays out: every test of it needs
`src/security/firewall/**`, which another session owns and is editing.

## `NFR.SEC.6` — the search was for the wrong thing

The row read "MIK-7249 and MIK-7262 have ZERO references in `src/` or
`tests/`". True, and it does not mean what it was read to mean: the tree was
searched for the ticket string rather than the behaviour. Both fixes are in the
tree, unlabelled.

| ticket | the fix | asserted by |
|---|---|---|
| MIK-7249 | a restart-only config edit kept reporting instead of being silently absorbed — `LiveConfig::restart_required` (`src/config_reload/mod.rs:279`), `pending_restart_fields` (`:285`) | `a_restart_only_change_keeps_reporting_until_a_restart` (`:346`) |
| MIK-7262 | a declared `registers_external_callback` beats name inference — the early return at `src/capability/definition/mod.rs:1150` | **nothing** |

So 7249 is evidenced and 7262 is not. Reading the early return and concluding
the ticket is closed is inference from source, not verification, and the
criterion says *closed in this release*.

- **Engineering:** one unit test that a definition declaring
  `registers_external_callback: false` is NOT treated as registering one, even
  when its name matches the inference list (`watch`, `subscribe`, …). That name
  collision is the exact case the comment says motivated the fix, so it is also
  the case that falsifies the test.
- **Question for the operator:** does an unlabelled fix satisfy "closed in this
  release"? If traceability requires the ticket ID to appear, the answer is a
  comment on each site, not more code.

## `CONTROL.4` — the ledger understates this one

The ledger says "no production caller registers with it". The stronger fact:
`SessionLifecycle` has **zero** production references of any kind. Searching
`src/` outside `session_lifecycle.rs` returns three doc comments in
`src/security/firewall/**` and the `pub mod` line. Nothing constructs one,
nothing holds one, and `reap` is called only from the module's own tests.

Ownership is **not** the blocker, and that was worth checking before designing
around it. `register` takes a closure (`impl Fn(&str) + Send + Sync + 'static`),
so registration happens wherever the gateway starts up and the firewall is only
*called* from inside the closure. No edit to another owner's file is required.

What blocks it is a decision the design has not made. `session_lifecycle.rs:26`
states the problem against itself:

> MCP 2026-07-28 removed protocol sessions, so `on_disconnect` has nothing left
> to fire on: there is no session to DELETE, and the stream whose close drove
> the other trigger is replaced by `subscriptions/listen`.

The module's own answer is `track`/`reap` — a deadline instead of a trigger.
That answer is unfinished in two places, and both are design questions, not
typing:

1. **What calls `reap`, and how often?** A deadline with no clock is the same
   leak the module was written to close, one indirection further along. The
   candidates are the notification multiplexer's existing timer and a
   purpose-built interval task; neither is chosen.
2. **What is the key, and what sets the deadline?** The doc comment says "a
   principal after the migration, a session before it" and leaves it there. A
   TTL policy is an operator-visible number — it decides how long a departed
   caller's per-session state is retained — so it is not a value to pick while
   wiring.

Until both are answered, wiring `register` alone produces handlers that are
registered and never fire, which is indistinguishable from today except that
the criterion would appear to be met.

There is also a residual the module already names honestly at
`session_lifecycle.rs:76`: a key re-tracked between reaping's removal and
`fire_cleanup` still has its handlers fired. Closing that needs an ownership
model the module does not have. It should be decided **with** the wiring, not
after — a leak reintroduced by the fix for a leak is the shape this whole row
is about.

**What the test must do, once the decision exists:** drive the production call
site, not the type. `SessionLifecycle`'s own unit tests already assert the type
thoroughly (five tests, including the double-fire and refreshed-deadline
cases). A sixth would add nothing the criterion asks for: `CONTROL.4` is about
a *production caller*, so the test has to reach the registry the way production
does — construct the gateway, let the deadline pass, and observe the handler
ran. A test that calls `reap` directly re-proves what the unit tests already
prove and leaves the criterion exactly as unmet.

## `CONFIRM.2` — a question, not a patch

The criterion names a confirmation mechanism. The path that exists is
`elicitation/create` over SSE — a different mechanism reaching the same
outcome. Two halves, and only one of them is mine to answer:

- **Mechanism.** Is the criterion satisfied by an equivalent mechanism, or does
  it name `elicitation/create` because that specific one was intended? This
  cannot be settled by reading code: both readings are consistent with
  everything in the tree. **It is an operator call, and it is being asked here
  rather than assumed.** Implementing a second confirmation path to match the
  criterion's wording would be building a mechanism nobody wants in order to
  make a sentence true.
- **Reachability.** Even under the generous reading, the row does not close on
  my side alone: whether a modern caller can reach the confirmation path at all
  depends on the continuation-envelope wiring a concurrent session owns.

So `CONFIRM.2` stays blocking, and it stays blocking for a reason that is
written down rather than for a reason nobody looked up.

## What this leaves

Two tests (`NFR.SEC.1` row 2; `NFR.SEC.6`/MIK-7262), three operator questions
(row 5's scope, 7262's traceability, `CONFIRM.2`'s mechanism), and one design
decision that has no owner (`CONTROL.4`'s clock and key). None of the four
rows is blocked on code that is hard to write.
