# 4.0.0 release readiness: what is left, and the order to do it

Assessed 2026-09-09 against branch `fix/mrtr2-continuation-handle`, remote tip
`5dfbed58`, PR #473.

## Where the release stands

`scripts/release/count-release-criteria.py --check` is the authority on totals.
Run against the ledger as it exists at the remote tip `5dfbed58` -- not the local
worktree, which is 39 commits behind and carries a peer's uncommitted edits to
that file -- it reports: **146 criteria, 183 rows, 180 met or non-blocking, 3
blocking**, and `--blocking` names the same three rows covered below. The header
line in `docs/requirements/RELEASE-4.0.0-criteria-status.md` matches, so the
ledger's arithmetic is not drifting.

This document is not itself on the branch. It sits on two local-only commits
(`62570a22`, `0122ee40`) in a worktree nobody may fast-forward from, so it needs
the same delivery path as item 0 below: rebuilt on `5dfbed58` and pushed as an
explicit ref.

Three criteria block the release. One thing outside the ledger also blocks it —
the branch does not build green — and that is the first item below because none
of the other work can be verified while the suite is red.

## 0. The branch is red, and the cause is a lost implementation

Run 34361905129 is against `5dfbed58`, the current PR head, so the red verdict
is current rather than stale. Two tests fail out of 4157:
`block_1_gateway_invoke_interim_fields_reach_the_result` and
`block_1_gateway_execute_interim_fields_reach_the_result`.

The head carries the call site (`src/gateway/meta_mcp/mod.rs:1811`) and all four
fixtures, but carries the function as its red-stage placeholder:

    fn promote_interim_envelope(tool_name: &str, content: &Value, response: &mut JsonRpcResponse) {
        let _ = (tool_name, content, response);
    }

The implemented body did not survive the merges that landed the working tree
onto the release branch. `47dd46a9` ("wip: uncommitted working-tree state on the
stale base") introduced the placeholder and is an ancestor of `5dfbed58`, so this
is a merge artifact rather than a deliberate revert. Both failures are explained
by this one placeholder.

That is the whole of the *measured* red, and the measurement is narrower than the
count suggests. CI runs `cargo test --all-features` with no `--no-fail-fast`
(`.github/workflows/ci.yml:198` at `5dfbed58`), so cargo aborts after the first
failing target. Both failures are lib tests
(`src/gateway/meta_mcp/tests.rs:5872`, `:5900`), so the run stopped at the lib
target and no `tests/*.rs` integration target executed. The 4157 figure is
essentially the lib target alone: a filtered lib run at this tree reports 4116 to
4120 tests filtered out of the same population.

The consequence is a structural gap in the evidence chain, not just a caveat on
one number: **while any lib test is red, the CI test job cannot report the
integration suite's status at all**, and a green rollup on the other 26 jobs does
not compensate -- none of them run `tests/*.rs`. Every acceptance criterion
evidenced by an integration test is therefore currently unmeasured, whatever its
ledger row says. Restoring the item 0 body is what makes the rest of the suite
observable, which is a second and stronger reason to do it first.

Restoring the body turns the lib target green; it is verified green locally with that
body (`cargo test --lib block_1_`, 4 passed). The repair must be built on top of
`5dfbed58` and pushed as an explicit ref. It must not be delivered by pushing a
local tip: the worktree at `/Users/mikko/github/.worktrees/mcp-2026-protocol` is
39 commits behind the remote and 16 ahead, and pushing its tip would drop the
peer commits in between.

Owner: the lane driving PR #473 to green, which holds the push.

## 1. `MIK-7272.SUB.2b` — the capture half exists, the emit half does not

The ledger row still reads "ABSENT on both legs, and the client leg DISCARDS".
That reason is now stale on both counts, and the criterion still blocks — for a
different reason, which changes what is left to build.

Both capture legs have landed. Over SSE, `parse_sse_response` returns an
`SseExchange` whose `notifications` field holds the frames that preceded the
response on the request's own stream (`src/transport/http/mod.rs:283-298`). Over
stdio, `take_captured_notifications` and `capture_notification`
(`src/transport/stdio.rs:448,463`) route a notification to the call that supplied
its token, with three tests covering the routed, the isolated and the unclaimed
case (`:1116,:1131,:1148`).

What is missing is the consumer. The `notifications` field carries
`#[allow(dead_code)]` and a comment naming its own state: no production path
reads it, `send_request_with_headers` maps it away, and the reader that will
close the criterion is the `Accept`-negotiated event-stream body in
`gateway::router::handlers::meta_mcp_handler`. The attribute is the evidence that
the criterion is half-built, and it lifts when the consumer lands.

So the remaining work is one named thing rather than a whole mechanism: make the
event-stream response body emit the captured notifications on the request's own
stream, ahead of the final response, and delete the `allow(dead_code)`. The row's
evidence text needs rewriting at the same time, because a reader who trusts it
today would go looking for a capture path that already exists.

## 2. `MIK-7272.SUB.4` — covered on two routes of three, not one

A side-effecting call re-issued after a broken stream with a new request id must
be protected by an idempotency key or the tasks extension. The row records
UNWIRED "because the criterion needs all three routes and only one is covered".
Read at the tip rather than taken from the row: two of the three are covered, and
the row's stdio evidence is stale.

The generic `tools/call` route is live. `idempotency_key_for` has exactly one
production call site (`src/gateway/meta_mcp/invoke.rs:1344`; every other hit is
its definition in `meta_mcp/support.rs:48` or that module's tests), and
`enable_idempotency` is wired unconditionally at the sole production `MetaMcp`
construction site (`src/gateway/server/mod.rs:747`).

Stdio's dispatch is wired too. The row says stdio "hardcodes `retry: &NO_RETRY` at the two
sites that build its dispatch context (`server/mod.rs:2200`, `:2703`)" and that
`RetryFields::from_params` at `handlers.rs:1220` "is the only production site
that ever constructs a real `RetryFields`, and stdio never calls it". At
`5dfbed58` stdio's own dispatch does call it: `dispatch_single_with_sink` builds
real `RetryFields` and passes them into `handle_tools_call`
(`src/gateway/server/mod.rs:1886`). The one surviving `retry: &NO_RETRY` in that
file sits inside a test (`:2730`), and the regression test the row calls
`#[ignore]`d is not ignored -- `server/mod.rs` carries no `#[ignore]` anywhere,
so `stdio_caller_context_carries_the_clients_idempotency_key` runs in CI, where
the only failures are the two from item 0.

What that evidence covers, precisely: real `RetryFields` reach
`handle_tools_call` on the stdio path, and the watching test is live and green.
It is a unit test over a constructed caller context, so the last step -- a
retried side-effecting call over stdio actually reaching the guard at
`invoke.rs:1344` -- is inferred from those two facts rather than separately
exercised. The owning lane should decide whether that inference is enough to
close the route or whether it wants an end-to-end case.

The uncovered route is `POST /mcp/{name}` (`backend_handler`,
`src/gateway/router/backend_handlers.rs:434`), which bypasses `invoke_tool_traced`
and never calls `idempotency_key_for` -- which the single-call-site search above
independently confirms.

So the remaining work is one route, not two. The stdio wiring arrived in
`47dd46a9`, the same WIP commit that dropped the item 0 body, which is why the
row was accurate when written and is not now. Re-evidencing it is deferred: the
ledger shows uncommitted peer edits, so this text goes to the owning lane rather
than into the row.

## 3. `MIK-7246.CONFIRM.2` — the gate is unreachable through the MRTR path

The confirmation mechanism is `elicitation/create` over an SSE session
(`ProxyManager::forward_elicitation_with_response`), and a modern client cannot
reach it through the MRTR path. Checked at the tip rather than quoted: that
forwarder is at `src/gateway/proxy.rs:274` exactly as the row cites, and the
module comment the row quotes -- "sessions, so *every* modern destructive call
would take that branch" -- is at `src/gateway/destructive_confirmation.rs:96`,
not the `:83-84` the row gives. The substance holds; only the line anchor drifted. There is a second, related defect recorded in
`docs/release/verify/metamcp-blockers-fixes.md`: `for_modern()` selects a policy
that no live branch reads, its sole consumer sits inside the `Era::Legacy` arm
(`src/gateway/router/handlers.rs:1378-1382,1449`), and the doc comment on
`src/gateway/destructive_confirmation.rs:31` still states modern clients are
refused, which contradicts the in-band ask this criterion requires.

Whether that is repaired by deleting the branch, deleting the constant or
rewriting the doc is the owning lane's call, because all three are consistent
with the criterion and they differ in what they claim about intent.

## What is NOT a gap

`MIK-7212.WIRE.1` through `.13` do not appear in the ledger, and that is correct
rather than an oversight. `docs/release/2026-09-08-team-lead-rulings.md` rules on
them as live work owned by the `bridge-mrtr7` lane (R1, R8, R8a, R22), and R8
records a design event that moves what `WIRE.5` asserts and reopens the earlier
review phases. Criteria whose design is still moving are not promoted. The five
`ROOTS` criteria in the same design are implemented and covered — 26 and 5 tests
green in `tests/mrtr7_roots_acs.rs` and `tests/mik_7212_mrtr7_bridge_acs.rs` —
and are the rows the ledger can carry once the owning lane confirms the mapping.

The tasks-extension TTL gap recorded in the blockers file is real but is not a
4.0.0 blocker: no criterion in the ledger asserts it. It belongs in the follow-up
that closes `docs/design/2026-08-31-task-1-tasks-extension.md`, which requires a
finite default TTL, a global cap counting every unreaped record, and reaping as a
store-level compare-and-delete against the record's current `ttlMs`.

## Order of work

Item 0 first and alone: while the suite is red, no other criterion can be shown
green, and a second push racing the repair risks dropping it the way the merges
already dropped it once. Items 1 to 3 are independent of each other and can run
in parallel across their owning lanes once the branch builds. Item 1 is the
cheapest of the three — one consumer against two landed capture paths — and it
is the one whose ledger row most misleads a reader today, so it should be
re-evidenced even before it is built.

## Addendum, same day: gaps the ledger does not carry

Each surfaced from another lane and was re-verified here at source before being
recorded, because a lane's report is corroboration, not proof.

### A. `MIK-7246.CONFIRM.1a` is not a blocker, and is not measured either

The row at `docs/requirements/RELEASE-4.0.0-criteria-status.md:247` rests on
`ConfirmationPolicy::for_modern()`'s `REFUSE` being "consulted rather than merely
defined". It is not consulted, and the reason is structural rather than a missing
call.

`is_modern` is *defined* as `era == Era::Modern` on the line after `era` is read
(`src/gateway/router/handlers.rs:826-827`). The policy is chosen from that same
predicate: `for_modern()` when `is_modern`, `for_legacy()` otherwise (`:1359-1363`).
`ConfirmationChannel::Elicit` -- the only channel variant that carries a policy at
all -- is constructed at `:1468` and `:1596`, and both sites sit in the
`Era::Legacy` arm of a match on that same `era`. The `Era::Modern` arm builds
`InBand`, which carries a continuation and no policy.

So the only policy value that can reach `policy.on_unconfirmable()` at
`src/gateway/meta_mcp/mod.rs:2226` is `for_legacy()` = `PROCEED_WITH_WARNING`, and
the comparison against `REFUSE` there can never be true. `for_modern()`'s value is
constructed on the modern path and then never placed in a channel. `REFUSE` is a
string constant with no runtime producer on any transport, stdio included.

The requirement text settles what that costs, and it is not a blocker.
`RELEASE-4.0.0-requirements.md:204-205` demands an outcome -- the gate MUST refuse
when it cannot obtain confirmation -- and names no mechanism, so a refusal
delivered by a failed in-band mint satisfies it exactly as a policy-driven one
would. `CONFIRM.1b` states in writing that the legacy path keeps
`PROCEED_WITH_WARNING` deliberately and that the asymmetry "is not a defect of
this criterion". So the dead `for_modern()` is dead code, not a violation, and the
blocking count stays at three.

What remains is worse than a stale citation and is the reason the row still cannot
be called met. `CONFIRM.1a`'s PASS rests on
`ac_confirm_1_a_modern_destructive_call_with_nobody_to_ask_is_refused`
(`tests/mik_7215_acs.rs:684`), whose own doc comment gives its premise: "a modern
request cannot carry a session -- this revision deleted them -- so there is nobody
to elicit over and `Unsupported` is the outcome every time". The era split removed
that premise: a modern request now takes `InBand`, `state.continuation` is an
`Arc` rather than an `Option` so the channel always carries one,
`ContinuationState::new()` configures a working keyring, and
`confirmation_principal` falls back to the api-key name, which makes the test's
`admin-client` nameable. Live channel, working keyring, nameable principal: the
mint succeeds and the modern caller is asked rather than refused.

That prediction cannot be checked against the last CI run, because the era split
was already present at `5dfbed58` (`handlers.rs:1441-1447` there) and the run
still stopped at the lib target -- see item 0 -- so this test did not execute. The
honest grade is neither PASS nor FAIL but unmeasured-and-at-risk, and it is an
instance of the general gap recorded in item 0 rather than a separate defect. The
ledger cell keeps PASS with a CONTESTED note carrying these anchors: a prediction
from source is not a measurement, and the measurement is available the moment the
lib target goes green.

Cite `on_unconfirmable` by symbol, not by line: that comparison has been cited at
`:2201-2204`, `:1967` and `:2223` in three different documents and is at `:2226`
now.

### B. `gateway_invoke` reports a failed backend call as `isError: false`

On the not-found path, the wire response carries top-level `"isError": false` and
`"resultType": "complete"` while the real `"isError": true` sits one JSON string
deep inside `content[0].text`. A client that branches on the top-level field --
which is the field the specification puts there for that branch -- records a
failed call as a success.

Not house style: the same file produces a top-level `isError: true` at
`src/gateway/meta_mcp/invoke.rs:1659`, `:1701`, `:2371` and `:2439`, so the
not-found path is inconsistent with its own neighbours.

No criterion in the ledger asserts this, so it does not change the blocking count.
It is a wire-contract defect on a shipped surface and should be filed and fixed
before 4.0.0 rather than deferred: the cost of shipping it is that every client
integrating against the not-found path builds on the inverted value.

### C. The two clippy gates do not cover their union

CI's Clippy job runs `cargo clippy --all-features` -- lib and bins, no test
targets. The gate this repository states in `CLAUDE.md` is
`cargo clippy --all-targets -- -D warnings` -- test targets, default features.
Neither is a superset of the other, so a lint inside a *feature-gated test*
escapes both.

One does today. `src/gateway/meta_mcp/tests.rs:5518` tripped
`clippy::similar_names`, and the case that holds it (`:5494`) is
`#[cfg(feature = "spec-preview")]`. Two independent clippy runs disagreed about
the same tree for exactly this reason -- `--all-targets` alone did not compile the
case, `--all-targets --all-features` did -- and both runs were correct. The fix
was to carry the `#[allow(clippy::similar_names)]` its sibling case at `:5361`
already carries for the identical pair of bindings; the sibling had it and the
copy did not.

That makes three ways this branch has hidden a break from a green rollup in one
day: a staged-but-undeclared module (absent from the committed tree, so CI
compiles what local builds cannot), a red lib target (aborts the run before any
integration test, see item 0), and a feature-gated test lint (outside both clippy
gates). The pattern is the same each time -- the rollup measures a tree or a
target set that is not the one the gate claims to cover -- and it is worth one
decision before release rather than three more discoveries. Adding
`--no-fail-fast` to the test job and `--all-targets` to the clippy job closes the
second and third; both are changes to the release branch's CI configuration and
belong to whoever owns it.

### D. A legacy caller with a session id but no usable channel is refused outright

The three red tests in `src/gateway/meta_mcp/tests.rs` --
`a_declared_input_request_passes_the_gateway_gate` (line 3486),
`a_continuation_that_is_never_retried_stores_nothing_gateway_side` (line 3552)
and `an_enforced_transform_preserves_the_continuation_handle` (line 2977) -- do
not fail in the continuation mint. They fail one branch earlier, and the error
string is what separates the two. Two `-32003` sites exist and they say
different things: `unbindable_continuation`, at line 459 of
`src/gateway/meta_mcp/invoke.rs`, says "cannot be continued for this caller",
while the legacy-bridge branch at line 1801 of the same file -- the only site
producing that wording -- says "the bridged exchange could not be completed".
All three failures carry the second. The mint at line 1822 is never reached, so
every hypothesis about the keyring, the principal or the slot table is about a
function these tests do not enter.

The branch guard at lines 1745 to 1747 is
`caller.era == Era::Legacy && interim.is_some() && session_id.is_some()`. The
shared fixture `allow_all_ctx_named`, at line 27 of the test module, sets
`era: Era::Legacy` on line 43 and `channel: &NoClientChannel` on line 44; the
tests pass `Some("session-1")` and declare elicitation. So `InputBridge::run`
reaches `NoClientChannel::send_request`, at line 328 of
`src/gateway/input_bridge.rs`, which returns `Err(DeliveryError::NoSession)`
unconditionally on line 335, and the branch converts any bridge error into a
hard refusal at lines 1798 to 1805.

The defect is in the guard, not the fixture. It tests `session_id.is_some()` --
a session *identifier* -- but what decides whether a bridge can run is whether
the *channel* can deliver, and those are different facts. A legacy client whose
session id is known while its channel cannot deliver -- a disconnected SSE
stream, stdio with no client half -- now receives a hard refusal where the
pre-split code minted a redeemable continuation. `DeliveryError::NoSession` is a
distinguishable variant, so the fall-through is available: on `NoSession`
specifically, leave `interim` set and drop through to the mint, which is the
case that path exists to serve. `Declined`, `UnknownAction` and `ClientRefused`
are real answers from a reachable client and must keep failing hard.

This belongs to the era-split lane. The branch and its guard arrived with the
split, and it shares a root with section A above: the split changed which
callers reach which path, and the fixtures encoding the old routing were not
re-read. It does not change the blocking count -- the tests are red today and
already counted under item 0 -- but the production behaviour behind them is a
wire regression, not a test-fixture artefact, and shipping it would refuse a
class of legacy client the gateway previously served.
