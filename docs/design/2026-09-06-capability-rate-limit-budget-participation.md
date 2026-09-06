# Design — capability execution and the rate-limit error budget (GH475.RL.10)

Status: proposed · 2026-09-06 · GH [#475](https://github.com/MikkoParkkola/mcp-gateway/issues/475), [#481](https://github.com/MikkoParkkola/mcp-gateway/issues/481)
No code in this document (§P1).

## §P0 Scope

FOR: deciding whether capability execution participates in the error-budget
system, and what GH475.RL.10 requires of it.

OUT: the MCP-backend recording path (`src/backend/ops.rs`, `src/failsafe/`) —
unchanged by anything here; RL.9 and RL.11 (separate rows, separate criteria);
retry policy for a `429`; any change to `is_rate_limited`'s predicate text.

## 1. The premise the brief carried is false

The criteria ledger (`docs/requirements/RELEASE-4.0.0-criteria-status.md:393`)
records RL.10 as ABSENT because "`src/capability/executor/` contains no call to
`is_rate_limited` and no rate-limit classification of any kind". That sentence
is true of the executor directory and false as a statement about capability
execution, which is the thing the criterion is about.

What the tree actually does, on the path by which a capability tool is
executed as agent traffic — the meta-MCP invoke path. (There is a second,
non-agent path, a CLI diagnostic; it is disclosed and dispositioned below,
not folded into this table.)

| step | site | what happens to a capability `429` |
|---|---|---|
| HTTP send | `src/capability/executor/mod.rs:124`, `:138` | transport health records **success** — any HTTP status is a live backend (`mod.rs:95`) |
| status check | `executor/jsonrpc.rs:204`, `params.rs:50`, `graphql.rs:260` | `Err(Error::Protocol("… returned {status}: {body[..500]}"))` |
| backend | `src/capability/backend.rs:441` | `?` — propagated unchanged |
| dispatch | `src/gateway/meta_mcp/invoke.rs:2447-2458` | `call_capability_tool_with_identity`, inside `dispatch_to_backend` |
| classify | `invoke.rs:1384` → `BudgetOutcome::of` `:3006` | `is_rate_limited(&error.to_string())` → `IgnoredRateLimit` |
| record | `invoke.rs:1896-1913` | returns before both budgets; emits `mcp_error_budget_suppressed_total{reason=rate_limited}` |

So a capability `429` is **already excluded** from the server error budget, from
the per-capability budget (`kill_switch.record_capability_failure`, `:1929`), and
from the kill switch. It is excluded because `reqwest::StatusCode`'s `Display` is
`429 Too Many Requests` and sits at the FRONT of the message, ahead of the
500-character body truncation, and `is_rate_limited` (`src/gateway/recovery.rs:286-307`)
matches both the `429` token and `too many requests`.

Two further facts that bound the problem:

- **There is no second *agent-facing* execution path.**
  `call_capability_tool_with_identity` has exactly one caller (`invoke.rs:2458`),
  and `src/gateway/router/backend_handlers.rs` contains no capability route
  (`rg capabilit` → no match). Every other `get_capabilities()` site is
  listing, search, policy or status. Nothing an agent can drive reaches a
  capability tool while bypassing `record_error_budget`.

  **One path does bypass it, and is excluded here on purpose, not missed.**
  `cap_test` (`src/commands/cap.rs:220-256`) constructs its own
  `CapabilityExecutor` (`:241`) and calls `.execute()` directly — an
  operator-invoked, one-shot CLI diagnostic (`mcp-gateway cap test`). It is
  never agent traffic and never reaches `MetaMcp::dispatch_to_backend`.
  Routing a CLI subcommand through the meta-MCP invoke path to buy it budget
  participation is a real architectural change for a manual diagnostic tool,
  for no agent-facing benefit — rejected on that basis, not overlooked.
  Residual, stated rather than silently absorbed: an operator running
  `cap test` against a throttled capability spends the same upstream provider
  quota a real invocation would, and the error budget never records it — no
  auto-disable, no counter, nothing. Acceptable for a tool an operator runs
  by hand; it would not be if `cap_test` were ever wired into unattended
  tooling. That premise is checked, not assumed: a whole-tree search
  (`rg --hidden --no-ignore 'cap_test|cap test'`, excluding `target/`) finds
  exactly two hits — the dispatch arm and the definition, both in
  `src/commands/cap.rs` — and no CI job, script, or workflow invokes it as of
  this revision.
- **There is no capability circuit breaker to protect.** `Failsafe` lives on
  `PooledEntry` (`src/backend/pool.rs:78`), the MCP-backend pool. `CapabilityExecutor`
  owns a bare `HealthTracker` (`executor/mod.rs:65`) and nothing else. "A 429 must
  not trip the capability breaker" is vacuous, and the health tracker cannot be
  fooled by a `429` because it never reads the status.

The correct statement of the gap is therefore not *capability execution records
nothing*. It is: **the exclusion is delivered, unpinned, and carried by a string.**

## 2. The two real gaps

**G1 — the classification is text-dependent.** Nothing in the executor knows it
observed a `429`. The status is destroyed into prose at `jsonrpc.rs:204` and
reconstructed by substring match 2,800 lines away. Three independent formatting
sites must all keep the status *in* the message for the exclusion to hold.
Order is not the hazard: `is_rate_limited` lowercases the whole string, matches
its phrases anywhere in it, and accepts `429` as a standalone token
(`recovery.rs:286`), so moving the status after the body survives, and so does
wrapping the error ("upstream request failed: …") or replacing `{status}` with
`{status.as_u16()}`, which keeps the bare token even when it drops "Too Many
Requests". What breaks it, and looks harmless in review: dropping the status
altogether, gluing the digits into a longer token (`HTTP429` lowercases to
`http429`, which is not the token `429`), or adding a fourth protocol executor
that formats its own message without a status. The predicate is also fooled in the other direction
by a body that merely contains the word "throttled".

**G2 — nothing pins it.** No test drives a capability `429` through
`dispatch_to_backend` into `BudgetOutcome`. The existing budget tests
(`invoke.rs:4412`, `:4433`, `:4451`, `:4465`) construct `BudgetOutcome` values or
synthetic strings directly; the capability executors' tests stop at the
`Error::Protocol` boundary. Delete the status from all three format strings and
the whole suite stays green while every throttled capability starts consuming its
own budget and auto-disabling itself under load — which is precisely the failure
GH #475 exists to prevent, arriving silently.

A third candidate gap does not exist and is recorded here so it is not
rediscovered: capability transport health is already status-blind by construction
(`executor/mod.rs:124`), not by text, so a `429` cannot mark a capability backend
unhealthy in `/health`.

## 3. What RL.10 actually demands — an ambiguity, resolved

The test-plan row (`docs/design/2026-09-05-error-budget-test-plan.md:36`) reads:

> `| GH475.RL.10 | a typed rate-limit outcome needs no text | a capability 429 observed at jsonrpc.rs is excluded with the error text scrubbed to an unrelated string | integration | behaviour | src/capability/executor/ tests |`

Two readings:

- **weak** — scrub the *body*, keep the status. Passes today, unmodified, because
  the status precedes the 500-char body truncation.
- **strict** — scrub the *whole message*, status included. Fails today, because
  with the status gone there is nothing left to classify from.

Strict is the face-value reading of both columns, and weak is the strained one.
"observed at `jsonrpc.rs`" places the observation at the status check, and "the
error text" means the text, not a half of it that the row never names. The weak
reading needs "the error text" silently narrowed to "the body portion", and it
makes the headline — *"a typed rate-limit outcome needs no text"* — false, since
under it the outcome needs exactly one piece of text and always has. A later
reader should not be able to take weak as the reasonable default: it is not the
plain reading, it is the reading that survives the tree as it stands.

Adopting it would also let the criterion be closed by a test whose subject is the
formatting of an error message — a test that passes for a reason unrelated to what
the row is named after. **Strict reading adopted.** Under it,
RL.10's behaviour is delivered and its property is genuinely absent, and those
have different fates (§5).

## 4. Options

### O0 — capability execution should not participate in the budget system at all

Argued, not assumed away, because it is the option that would delete the
criterion rather than satisfy it.

The case for it: error budgets and the kill switch exist to stop routing to a
backend that has stopped working. A capability backend is not a process the
gateway owns — it is somebody's REST API reached over HTTP, already covered by
transport health, and per-capability auto-disable is a blunt instrument to point
at a third party's endpoint. If capabilities did not participate, `is_rate_limited`
would have nothing to exclude them from, G1 and G2 would evaporate, and RL.10
would be deleted as a criterion about a system capability execution is not in.

Rejected, three reasons, any one sufficient:

1. **It is a removal, not an omission.** `record_capability_failure`
   (`invoke.rs:1929`) and the per-capability budget config exist and are wired;
   auto-disable of a single capability is a shipped 4.0.0 feature. Non-participation
   means deleting that, which is a scope change requiring the requester's recorded
   agreement, not an engineering simplification.
2. **The budget is measuring the right thing.** A capability that returns 500s
   for ten minutes should stop being routed to, for exactly the reason an MCP
   backend should. The `429` carve-out is the whole point of GH #475: distinguish
   *throttled* from *broken*. Dropping participation to avoid the distinction
   throws out the measurement to avoid one classification.
3. **It makes the failure mode worse, silently.** Without the budget the only
   remaining signal is transport health, which records a `429` and a `500`
   identically — as a success. A capability answering `500` to everything would
   read as perfectly healthy forever.

### O1 — typed rate-limit error from the executor (RECOMMENDED)

The executor classifies at the point it holds the `StatusCode`
(`jsonrpc.rs:204`, `params.rs:50`, `graphql.rs:260`) and returns a *typed*
rate-limit error rather than a formatted one. `BudgetOutcome::of` matches on the
type; `is_rate_limited` stays where it is for the MCP-backend path, which has no
typed status to match on.

Eliminates rather than patches: after it, the finding "the exclusion depends on
message text" cannot be stated of the capability path. It also gives
`Retry-After` a place to live if anything later wants it.

Cost, stated plainly and checked rather than assumed (section 6): `crate::Error`
is exported at the crate root (`src/lib.rs:94`), is **not** `#[non_exhaustive]`
(`src/error.rs:14-15`), and carries **no** rate-limit-shaped variant today — the
nearest precedent is `Forbidden`, which does carry a typed HTTP `status`. So O1
adds a public symbol and breaks any downstream exhaustive `match`. That is D28
(API surface counted) plus D2 (breaking → approved and migrated); it is **not**
`VISIBILITY-IS-DESIGN`, which governs widening a field or a function, not adding
a variant to an already-public enum. Citing the wrong gate matters here, because
one is an ask and the other is a review.

Two things make the cost smaller than it reads. `to_rpc_code` already ends in a
`_ =>` arm, so the crate's own match sites do not all need touching. And 4.0.0 is
a major release in preparation — a breaking enum change is never cheaper than
during one. Neither disposes of the question of whether 4.0.0's public surface is
still open to additions; only the requester can answer that, so it stays an open
question in section 6.

### O1b — the same classification, carried crate-internally (rejected)

Named because O1's whole cost is the public enum, and both ends of the wire are
in-crate: the status is known at `executor/jsonrpc.rs:204` and consumed at
`invoke.rs:1384`. If the classification could ride a crate-internal carrier, the
open question in section 6 would not exist. It cannot, for a language reason and
a signature reason.

Rust has no per-variant visibility: a variant of a `pub` enum, and its fields, are
as public as the enum. There is no `pub(crate)` variant of `crate::Error` to add.

The alternative is a capability-layer error type carried up to the dispatch site
instead. The carrier between the two ends is the return type of
`CapabilityBackend::call_tool_with_context` (`src/capability/backend.rs:390`) —
`pub`, on a `pub` type, in a `pub` module (`src/lib.rs:36`). Changing it is the
same public-API gate as O1, applied to a signature every external caller uses
rather than to one added variant, and a converting boundary that flattens the type
back to `crate::Error` before `BudgetOutcome::of` sees it puts the information
loss back exactly where it is today. Same gate, worse shape.

This is not O3. O3's defect is two representations that can disagree; O1b is one
representation in the wrong place.

### O2 — one shared error constructor plus a format-contract test

Keep the string, but funnel all three executors through a single constructor that
guarantees the status token leads, and test that constructor.

Rejected as the primary: the defect stays describable. A fourth executor that does
not use the constructor, or a caller that wraps the error, re-arms it, and the
contract test cannot see either. This is the patch the repair protocol says to
take only when the root cause is out of scope — it is not.

### O3 — classify at `dispatch_to_backend` from a side channel

Have the dispatch site ask the capability layer "was that a rate limit?" via
per-call state set during execution.

Rejected: two representations of one outcome that can disagree — the caller sees
one error, the budget sees another — and the side channel has to be per-call state
threaded through an `async` boundary that currently threads none.

### O4 — do nothing; record RL.10 as ABSENT

Rejected. The behaviour is present and correct; recording it as absent is a false
negative in the ledger, and leaving it unpinned (G2) is the actual risk.

## 5. Verdict

**Capability execution participates in the budget system, and already does.**
O1 is the change; O0 is rejected on the record above.

### What records what, and where

| recorder | owner | point | a `429` counts as |
|---|---|---|---|
| transport health | `HealthTracker` on `CapabilityExecutor` (`executor/mod.rs:65`) | inside `send_with_retry`, at the HTTP send (`:124`, `:138`) — before any status is read | **success** (unchanged; status-blind by construction) |
| server error budget + kill switch | `MetaMcp` (`invoke.rs:1896`) | after `dispatch_to_backend` returns (`:1384`) | **excluded** — no sample recorded either way |
| per-capability budget / auto-disable | same (`:1929`) | same call | **excluded** |
| circuit breaker | none exists for capabilities | — | n/a |

`execute_with_context` itself records nothing new. That is deliberate and is the
answer to "at which point in `execute_with_context`": the classification is
produced there (the executor is the only place holding a `StatusCode`) and
*consumed* at `invoke.rs:1384`, where the recording already happens for every
backend kind. Adding a recorder inside the executor would build a second
accounting surface beside a working one and give a capability `429` two chances
to be counted.

### How it composes with the MCP-backend path

It does not compose — it runs *beside* it, and that is correct. The MCP-backend
path records at `src/backend/ops.rs:254` via `Failsafe::record_dispatch_failure`
(`src/failsafe/mod.rs:88`), which owns a circuit breaker and a per-slot health
tracker. The capability path records at `invoke.rs:1384` via `BudgetOutcome`,
which owns budgets and the kill switch. They share exactly one thing: the
predicate `is_rate_limited` (`recovery.rs:286`) — the single signal table RL.11
is about. O1 does not change that predicate, does not add a second one, and does
not move either recorder; it changes only what the capability path *feeds* into
the decision, from a formatted string to a type. An MCP backend keeps using the
text predicate because a transport error there genuinely has no typed status.

### Fate of the criterion

- **RL.10 — behaviour:** MET, one leg pinned. The exclusion works today. The
  test this section originally named — drive a capability `429` through invoke,
  assert `IgnoredRateLimit` and no budget sample — is **not** the test that
  landed: `BudgetOutcome::of`'s recorder is private to `invoke.rs`, so the pin
  enters at the shared predicate instead (§7, item 1). What is asserted is therefore
  the predicate leg; the `BudgetOutcome` leg of the trace stays read off the
  source. This is the part that must land regardless of O1.
- **RL.10 — property ("needs no text"):** ABSENT until O1 lands. It is a breaking
  public API change (D2, D28), gated on an ask (section 6) — and O1b establishes
  there is no crate-internal way around that gate.
- If the ask is refused, RL.10's property half is recorded as OUT-OF-SCOPE-FOR-4.0.0
  with its reason — public error-enum widening declined — and G1 becomes a named
  residual risk carrying O2 as its mitigation. It is not silently downgraded to
  the weak reading, and the ledger row says which half is met.

## 6. Open questions — scheduled, per §P1

### Resolved (checked)

| question | check run | result | what it changed |
|---|---|---|---|
| Does any *agent-facing* path reach a capability tool without `record_error_budget`? | `rg call_capability_tool`, `rg capabilit src/gateway/router/backend_handlers.rs`, read of every `get_capabilities()` site — scoped to the meta-MCP invoke surface, the only surface an agent drives | one execution caller, `invoke.rs:2458`, inside the recorded window; no route in `backend_handlers.rs` | killed a suspected third gap **on the invoke surface**; the design does not add a recorder for an agent-facing path that does not exist. This search was scoped to that surface and could not see, and does not claim to see, the CLI (`src/commands/cap.rs`), which never routes through `invoke.rs` — see §1's disposition of `cap_test` for that separate, non-agent path |
| Does the 500-char body truncation break the exclusion? | read `jsonrpc.rs:204-207`, `params.rs:50-54`, `graphql.rs:260-263` | status precedes the truncated body in all three | RL.10 under the *weak* reading passes today — which is why section 3 had to settle the reading rather than assume it |
| Is there a capability circuit breaker a `429` could trip? | `rg failsafe\|Failsafe src/capability/`, read `executor/mod.rs:65` | none; bare `HealthTracker` only | removed "must not trip the breaker" from the design as vacuous, in one line rather than a section |
| Does capability transport health mis-count a `429`? | read `send_with_retry` `executor/mod.rs:112-158` | any HTTP status records success | no change needed at the transport layer |
| Is `crate::Error` `#[non_exhaustive]`? If it were, O1 would add no breaking change and need no ask. | read `src/error.rs:14-15`, `rg non_exhaustive src/error.rs src/lib.rs` | no attribute; the enum is plain `pub enum Error` | the ask in the deferred row survives — but it is D2/D28, not `VISIBILITY-IS-DESIGN`, and the wrong citation is corrected in O1 |
| Does a rate-limit-shaped variant already exist, so that O1 would only construct an existing symbol differently? | read all 22 variants of `src/error.rs:15-179` | none; the nearest precedent is `Forbidden`, which does carry a typed HTTP `status` | O1 genuinely adds a public symbol — and `Forbidden` shows the enum already accepts a typed-status variant, so the shape is not novel |
| Can the classification avoid the public enum entirely by staying crate-internal? | read `CapabilityBackend::call_tool_with_context` `src/capability/backend.rs:390`, `pub mod capability` `src/lib.rs:36`, plus the Rust rule that variants inherit enum visibility | no: no `pub(crate)` variant exists as a language feature, and the alternative carrier is an equally public signature | added O1b, rejected on the record, so the ask cannot be dodged by a route nobody had checked |

### Deferred (must be asked before O1 is implemented)

| field | value |
|---|---|
| question | Is 4.0.0's public API still open to a breaking addition — specifically, may `crate::Error` gain a typed rate-limit variant? It is a public enum without `#[non_exhaustive]`, so a new variant breaks downstream exhaustive matches: D2 (breaking → approved and migrated) and D28 (surface counted). Not `VISIBILITY-IS-DESIGN`, which governs fields and functions. |
| owner | GH [#475](https://github.com/MikkoParkkola/mcp-gateway/issues/475) / [#481](https://github.com/MikkoParkkola/mcp-gateway/issues/481) — the operator decides, tracked on these tickets, not a bare role reference |
| what resolves it | a yes/no on the enum widening, recorded in this document. The counter-argument to record with it: a major release is the cheapest moment such a change ever gets, and `to_rpc_code`'s `_ =>` arm means the crate's own match sites mostly do not move |
| migration path (D2) | if approved: downstream exhaustive `match crate::Error` sites gain one new arm, or already fall through a `_` wildcard — no behavioural change, since the new variant is only ever constructed by O1's own code path. Called out explicitly in the 4.0.0 release notes alongside the enum addition, so a consumer's own CI catches it at compile time rather than at runtime |
| when | before any implementation of O1 begins; the RL.10 behavioural pin does not wait on it |
| if it resolves badly | O2 as mitigation, RL.10's property half recorded OUT-OF-SCOPE-FOR-4.0.0 with the reason, G1 as named residual risk (section 5) |

Nothing depending on this answer is implemented. The behavioural pin closing G2
does not depend on it.

## 7. What lands next, in order

1. **(item 1)** The RL.10 behavioural pin (G2) — **LANDED 2026-09-06, at a different seam
   than this section named, and the difference matters.**

   The seam named above — a capability `429` driven through the invoke path from
   a mock upstream, asserting `mcp_error_budget_suppressed_total` and two
   untouched budgets — **is not reachable, by design of the security layer, not
   by any shortcoming of the fixture.** `CapabilityExecutor::execute_jsonrpc`
   calls `validate_url_not_ssrf` (`capability/executor/jsonrpc.rs:153`), which
   rejects an IP literal in a private or reserved range before the HTTP call; a
   domain-named loopback host passes that sync check and is then stopped by
   `PinningResolver` (`capability/executor/mod.rs:176-184`) at DNS. There is no
   env or test escape hatch and none should be added: a fixture that opens an
   SSRF hole to prove a rate-limit property is a bad trade. The named counter is
   also not observable in-process — no metrics recorder is installed in the test
   harness — so the two-budget effect was the only half of that observable that
   could have been asserted anyway. Nor is there an alternative route around the
   probe: `CapabilityBackend` (`capability/backend.rs:122`) and
   `CapabilityExecutor` carry no trait or DI seam a test could substitute
   instead — the only trait in the chain, `ProtocolExecutor` (`executor/rest.rs:48`),
   abstracts response *formatting* (REST/JSON-RPC/GraphQL), not transport
   substitution, and has no injection point today: `dispatch_protocol`
   (`executor/mod.rs:361`) is private and selects concretely, and the
   `HashMap<&'static str, Arc<dyn ProtocolExecutor>>` that would make it
   injectable is documented at `mod.rs:356-360` as future work, not present
   code. So the only way to drive a real `429` through the full invoke path
   today is the SSRF-blocked loopback probe; a mockable substitute is not a
   route nobody tried, it is a route that does not exist yet to try.

   What landed instead: `a_real_capability_429_is_excluded_by_the_shared_rate_limit_predicate`
   (`src/capability/executor_tests.rs:993`). It drives a real loopback `429` and
   a real `500` whose bodies are **identical** — the status line is the only
   difference — through the production formatter `handle_response`
   (`capability/executor/params.rs:38`, format site `:51`) and hands each
   resulting `Error::Protocol` message to `Failsafe::record_dispatch_failure`
   (`failsafe/mod.rs:88`), which runs the same `is_rate_limited` predicate
   (`gateway/recovery.rs:286`) that `BudgetOutcome::of` runs. `Failsafe` is
   **not on the capability path** — only `backend/ops.rs:271` and `:409` reach
   it, and capability errors go to `BudgetOutcome::of` instead — it is the only
   *public* consumer of that predicate, which is why the pin enters there. What
   the pin therefore establishes is the classification of a real capability
   error string, not the capability path's own budget bookkeeping. The observable is
   the **effect** — the throttled response leaves the circuit breaker closed,
   the control opens it — never `BudgetOutcome`'s return value. The control is
   what proves the path ran and discriminated.

   What that pin does and does not close, stated plainly so no reader has to
   infer it:
   - it closes G2 **for the predicate leg of the REST capability path only** —
     that a real `params.rs:51` error string is classified as rate-limited.
     It does not assert the `BudgetOutcome` leg, which stays read off the
     source. `jsonrpc.rs:205` and `graphql.rs:261` format their own status
     text, are driven by no test, and stay exactly as exposed as this document
     found them.
   - it closes nothing of G1 at any of the three sites. Detection is not
     prevention; only O1 is.
   - it does not pin that `execute()` calls `handle_response` — the test enters
     at `handle_response`, as the executor's existing response tests do
     (`executor_tests.rs:695`, `:738`, `:787`). The production call site is
     `executor/mod.rs:494`.
   - the meta-MCP recorder half was already pinned, and is not re-pinned here:
     `error_budget_tests` (`gateway/meta_mcp/invoke.rs:4396`) asserts the
     two-budget effect for `IgnoredRateLimit`, `Failure` and `Success`. Those
     tests construct the outcome directly — the shape objection above stands
     against them — but with this pin the two halves meet at the shared
     predicate rather than at a string a test wrote for itself.

   Falsifier: a **mutation** probe, per §P2's retrofitting note — no pre-fix ref
   exists, because the behaviour was never broken. Run 2026-09-06 against
   `params.rs:51` with the status dropped from the `"API returned {}: {}"`
   literal: the throttled case tripped the breaker and the test failed on its
   first assertion (`a real 429 must not trip the breaker`), not on a compile
   error. Restore verified by re-running the test to PASS, not by `git status`.
2. The ledger correction at `RELEASE-4.0.0-criteria-status.md:393` — the ABSENT
   line's stated reason is false and the row splits into behaviour and property.
3. O1, gated on section 6.

## 8. Reviews

§12 dual-vendor review of this document: NOT YET RUN.
