# 4.0.0 release readiness: what is left, and the order to do it

Assessed 2026-09-09 against PR #473, branch `fix/mrtr2-continuation-handle`.
The remote tip has moved twice during this assessment and is now `cbd224f0`;
sections written earlier cite `5dfbed58` and are left as written, because the
line numbers in them were read against that tip.

**Read this first: two trees.** This document was written from a worktree that is
now 47 commits behind `origin/fix/mrtr2-continuation-handle` and 31 ahead of it.
Local and remote have diverged far enough that "the branch" is not a well-formed
subject here, and several findings below turned on which one was being measured.
Every claim states its tree. Integration is deliberately held: `git merge-tree`
reports roughly ten conflicting regions, and two source files
(`src/gateway/router/backend_handlers.rs`, `src/gateway/server/mod.rs`) hold
another session's uncommitted edits, so merging now would destroy work no commit
is holding.

## Where the release stands

`scripts/release/count-release-criteria.py --check` is the authority on totals.
Against the ledger at the remote tip it reports **146 criteria, 183 rows, 180 met
or non-blocking, 3 blocking**, and `--blocking` names the same three rows covered
below. The header line in `docs/requirements/RELEASE-4.0.0-criteria-status.md`
matches, so the ledger's arithmetic is not drifting. That count has not moved
today; what moved is how much of it is measured.

Item 0 -- the branch not building green -- is **closed**. The lib target is
`4157 passed; 0 failed; 3 ignored` at the remote tip, so `cargo test` reaches the
integration binaries for the first time on this branch, and 25 of 26 CI checks
pass. The Tests job is still red, on sixteen component acceptance criteria with a
single root cause; see section D and its two continuations.

Three criteria block the release by the ledger's own count. Four further gaps the
ledger does not carry are recorded in the addendum: `CONFIRM.1a` unmeasured (A), a
wire-contract inversion in `gateway_invoke` (B), the clippy gates' uncovered union
(C), and the legacy-bridge refusal behind the sixteen (D). None of the four
changes the blocking count; all four are things a reader of the count alone would
not see.

This document is not itself on the branch. It sits on local-only commits in a
worktree nobody may fast-forward from, so it needs the same delivery path as the
code: rebuilt on the remote tip and pushed as an explicit ref.

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

**Superseded on 2026-09-11 — read the `2026-09-11` section below before acting
on this one.** Two findings above are no longer true. The HTTP consumer has
since landed: `decode_sse_exchange` publishes each notification as it decodes
(`src/transport/http/sse_decoder.rs:264`), reached from the incremental arm in
`src/transport/http/mod.rs:1305-1317`, so "no production path reads it" holds
for stdio only. And the stdio line numbers here are the worktree's, not
`HEAD`'s; at `HEAD` the pair sits at `src/transport/stdio.rs:445,460`. The
later section splits the verdict by tree, which is the one to act on.

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

### D-continued, after the first observable CI run (`cbd224f0`)

Item 0 is closed. The lib target is `4157 passed; 0 failed; 3 ignored`, so
`cargo test` now reaches the integration binaries for the first time on this
branch. What it found is one root cause, not a spread: 16 of the 19 cases in
`tests/mik_7212_mrtr_component_acs.rs` fail inside a single shared *arrange*
helper, `mint_for` at line 189, which panics with "the gateway must mint a
continuation for an interim exchange" against the same legacy-bridge `-32003`
recorded above. Those 16 are the written specification for the fall-through
section D proposes; the file does not exist on `main`, so they arrived with this
branch as its own acceptance criteria and have never been measurable until now.

The blast radius is wider than the fixtures suggested, and the reason is in
`src/gateway/router/handlers.rs`. At lines 704 to 719 a caller that does *not*
declare the modern revision by header is given a session id unconditionally --
`get_or_create_session_for(None, owner)` mints one when the request carried no
`Mcp-Session-Id` at all. The test harness posts to `/mcp` with no session header
and no `Accept: text/event-stream`, and still satisfies `session_id.is_some()`.
So the bridge branch fires on *every* legacy interim exchange over
`POST /mcp`, and succeeds only where a live SSE stream happens to be attached.

The invariant this violates is stated in that same file, six lines below the
mint, at lines 720 to 725, as the reason the subscription is dropped:

> This handler is not a stream reader. Holding the subscription would make a
> server-to-client prompt look deliverable to a caller with no live SSE stream:
> the send succeeds into a receiver nobody polls, and the caller waits out the
> 120-second response timeout instead of being told there is nobody to ask.

The handler drops the receiver precisely so that a session id is not read as a
delivery channel. The bridge guard then reads it as one. This is not a design
judgment to be weighed -- the file argues the point in prose and the downstream
guard contradicts it, which makes section D a defect against a stated invariant
rather than a preference about error shape.

Two consequences for the release. First, the 16 failures are one fix, not
sixteen, and that fix is the fall-through already described. Second, the Tests
job still cannot measure everything after it: `mik_7212_mrtr_component_acs`
sorts before `mik_7272_task_1_acs`, and with no `--no-fail-fast` the run aborts
before the dispatcher binary executes. The `--no-fail-fast` change recorded in
section C is therefore not housekeeping; without it, one lane's red spec keeps a
second lane's evidence unobtainable.

### D-corrected: the three lib tests were staleness; the sixteen were not

The three red lib tests are withdrawn as evidence for section D, and section D
survives on different evidence.

`ci-green` is right about them and I was wrong. This worktree is 47 commits
behind `origin/fix/mrtr2-continuation-handle` and 31 ahead of it. `91b58974`
("fix(meta-mcp): match fixture era to the capabilities the fixture declares") is
on origin and not on local `HEAD`, and origin's `allow_all_ctx_declaring` sets
`era: Era::Modern` with a comment that predicts the failure I diagnosed: "Pinning
`Legacy` here claimed a wire shape the fixture never sent -- a 2025 client that
somehow declared 2026 input capabilities -- and took the legacy input bridge,
which this context's `NoClientChannel` then refuses." Read from origin, not
relayed. A fixture that declares 2026 input capabilities is a modern caller, the
legacy branch should never have been reachable from it, and the fix for those
three is to stop measuring a stale tree.

That withdrawal does not reach the sixteen. Those failed on
`tests/mik_7212_mrtr_component_acs.rs` in CI, at origin's own tip `cbd224f0`,
which contains `91b58974`. They are not a staleness artefact and no fixture-era
correction is available to them, because their era is not a fixture choice at
all: `fresh_body` (origin, line 689) sends a bare `tools/call` with no `_meta`
block, no protocol-version header, no session header and no
`Accept: text/event-stream`. `classify_request` reads that as `Legacy` because it
*is* legacy -- a genuine 2025-shaped request. The caller then receives a minted
session id from `handlers.rs:704-719`, satisfies `session_id.is_some()`, takes
the bridge, and is refused.

So the distinction that matters is between two callers that both reach the
legacy branch for opposite reasons. One declared 2026 capabilities and was
mislabelled; origin fixed that. The other is honestly legacy, has no stream, and
is refused a continuation the sixteen acceptance criteria require it to be
given. Only the second is section D, and it is unaffected by the rebase.

One thing the withdrawal does change: the fall-through on
`DeliveryError::NoSession` should be proposed on the strength of the sixteen and
of the invariant quoted above from `handlers.rs:720-725`, not on the three. A
production behaviour change argued from a local staleness artefact would be
exactly the error this document keeps recording in other lanes.

Integration is deliberately not being done right now. A merge of origin into this
worktree reports roughly ten conflicting regions, and two source files
(`src/gateway/router/backend_handlers.rs`, `src/gateway/server/mod.rs`) currently
hold another session's uncommitted edits. Rebasing or merging under that would
destroy work no commit is holding. The integration waits for those edits to land.

### D-owner: the fall-through belongs to the MRTR.7a/7b bridge lane

Section D closes its open question. It asked who signs off on changing a
production refusal into a fall-through; the answer was already recorded in the
shared coordination file and had not been read into this document.

The bridge runtime is owned by the `MRTR.7a/7b` lane, that lane's ACK states the
work is assigned and in flight, and it asks explicitly that no second lane open
work on it. So the fall-through described above is handed over as a finding, not
implemented here. What was handed over is the guard's third conjunct, the
invariant it contradicts in its own file, the `DeliveryError::NoSession`
discrimination that makes the fall-through available, and the measured blast
radius of sixteen cases against one shared arrange helper.

Two consequences for the plan. This removes section D from the list of things
this document is waiting on an owner for — it is scheduled work in another lane
now, not an unowned defect. And it leaves exactly one item in that state: the
two workflow changes in section C, which belong to whoever owns the release
branch's CI configuration and are still unmade.

### Count re-derived on both trees

The coverage headline above was re-derived today rather than carried forward,
because the shared coordination file contained a second Claude lane quoting
`174 met or non-blocking, 9 blocking` from a receipt this morning, against this
document's `180 / 3`. Running
`scripts/release/count-release-criteria.py --check` against the local worktree
ledger and against the committed ledger at the pushed tip returns the same line
from both: `146 criteria, 183 rows, 180 met or non-blocking, 3 blocking`.

The other figure was accurate when it was written and is superseded; the
blocking column moved `21 -> 20 -> 9 -> 7 -> 5 -> 4 -> 3` across today's ledger
commits. A third figure in circulation, PR496's `182 / 157 / 25`, is older than
both. None of the three is wrong for its own tree, which is the whole hazard:
every one of them reads like a fact about the release rather than about a
commit. The script is the authority and costs a second to run.

### E. The ledger counts 55 unmeasured test binaries as passing surface

This is the largest finding of the day and it is not about any one criterion.

At origin's own tip, the Tests job ran **33 of 88 integration binaries. 55 never
executed.** The run stops at `error: test failed, to rerun pass --test
mik_7212_mrtr_component_acs`, that binary reports `FAILED. 3 passed; 16 failed`,
and no `Running tests/...` line appears after it. Read from the job log, not
inferred.

Cargo runs targets in byte order, confirmed against the same log:
`mik_7212_acs` then `mrtr7_bridge` then `mrtr7_stdio` then `mrtr_component`,
because `'7'` is `0x37` and sorts before `'_'` at `0x5F`. Every `mik_7215`
through `mik_7272` target sorts after the aborting one, which is why
`mik_7272_task_1_acs` and seven sibling dispatcher binaries are in the unrun 55,
along with every `mik_7215`, `mik_7216`, `mik_7217`, `mik_7218`, `mik_7222` and
`mik_7246` target.

The distinction that matters for a release decision: those 55 are **unmeasured
surface, not passing surface.** Nothing in the run says they are green. The
ledger's met count has been reading them as though it did. That does not make
any individual row wrong — most rows carry their own named test evidence — but
it does mean the suite-level assurance behind the count is thinner than the
count implies, and no amount of re-reading the ledger would reveal it.

There is a second-order trap here worth stating plainly. Fail-fast reveals
exactly one failing target per run, so the question "would the run still abort
before the dispatcher binary once the sixteen clear" **cannot be answered by the
gate as configured.** You cannot learn whether a 34th-to-88th binary is red
without first adding the flag. This is why `--no-fail-fast` on the Tests job is
required rather than prudent: it is not tidying, it is the only way to observe
the two-thirds of the suite that currently reports nothing.

The clippy half of the same gap is now empirical rather than structural. The
`Clippy (pedantic)` job **passed** at the same tip whose test module holds a
genuine `items_after_statements` error, because the job omits `--all-targets`
and so never compiles test code. A real `-D warnings` error sat on the pushed
branch under a green lint badge.

So origin is simultaneously green on a lint gate that does not compile the code
holding the error, and red on a test gate that stops before two-thirds of its
own suite. Both are one flag.

### D-implemented: the fall-through landed while this section was being written

The previous subsection routed the fall-through to another lane as a finding
rather than a patch. That routing is superseded: the fix is committed as
`3227c985`, `+18/-0`, confined to `src/gateway/meta_mcp/invoke.rs`.

`Delivery { error: NoSession, .. }` gets its own arm and falls through with
`interim` still set, so the ask goes out as a continuation. Every other
`BridgeError` keeps the `-32003`, because those are exchanges that were
attempted and failed by a reachable client. The fixture was left untouched,
which is the right call: the guard was the defect.

The evidence base is deliberately labelled weak by the lane that produced it. A
full target check exits 0, and the three named lib tests report 3 passed. But
the pre-fix RED baseline was not captured, and **the sixteen cases in
`tests/mik_7212_mrtr_component_acs.rs` have not been run** — and those sixteen
are the only tests that are this change's actual specification. The static case
is strong and the measurement does not exist yet. Until it does, this is a fix
believed correct, not a fix shown correct.

One correction of record from that lane, kept here because it changed routing:
two earlier commit messages state a build was unavailable to it. That was false
and self-reported as false. The lane had a working toolchain throughout, so the
arity repair it claimed on enumeration alone is now also settled empirically.

### E-corrected: the 55 are newly dark, and six criteria rest on evidence CI has never run

Two corrections to section E, both sharpening it rather than withdrawing it.

**First, the darkness is 31 hours old, not the life of the branch.** At the last
green CI run — `5cb4f4e9`, 2026-09-08 04:36 — **75 integration binaries ran and
passed**, and `mik_7272_task_1_acs` was among them. The tree held exactly 75
targets at that commit and holds 88 now, verified by listing `tests/` at both
revisions. So most of the 55 currently-unrun binaries are not unknown: they hold
green evidence that is roughly 31 hours stale, from the last green run to the
first red one on 2026-09-09 11:20. That is a materially smaller hole than
"55 unmeasured" implies, and section E should be read with this correction
attached.

**Second, and this is the part that touches the count.** Thirteen test binaries
were added after that last green run, so **none of them has ever executed in a
green CI run on this branch.** Twelve of the thirteen also sort after the
current abort point, so they did not execute in the red run either — only
`continuation_expiry_metric_test` sorts ahead of `mik_7212_mrtr_component_acs`.
The thirteen:

```
continuation_expiry_metric_test          mik_7246_confirm2_acs
mik_7213_7214_negotiated_revision_wiring mik_7246_confirm_1a_unconfirmable_producers
mik_7215_control3b_acs                   mik_7272_sub4_three_routes
mik_7215_control4_reap_count_acs         nfr_perf3_soak
mik_7215_control4_sweep_log              nfr_sec1_envelope_shape
mik_7215_control4_track_acs              nfr_sec3_key_rotation
mik_7215_control4_wiring_acs
```

Seven of the thirteen are cited as evidence in the criteria ledger, and the
cells quote pass counts — `6 passed, 0 failed` for `nfr_sec3_key_rotation`,
`1 passed, 0 failed, 5.05s` for `nfr_perf3_soak`. Those numbers are real, and
they can only have come from a local run by the lane that wrote the row, because
CI has never executed those binaries. The affected rows:

| criterion | status in ledger | cited binary |
| --- | --- | --- |
| `MIK-7214.HEADER.9a` | MET, not blocking | `mik_7213_7214_negotiated_revision_wiring` |
| `MIK-7215.CONTROL.3b` | MET, not blocking | `mik_7215_control3b_acs` |
| `MIK-7215.CONTROL.4` | MET, not blocking | `mik_7215_control4_track_acs` |
| `MIK-7246.CONFIRM.1a` | PASS, not blocking | `mik_7246_confirm_1a_unconfirmable_producers` |
| `NFR.OBS.4` | closed 2026-09-08 | `continuation_expiry_metric_test` |
| `NFR.PERF.3` | blocking moved to no | `nfr_perf3_soak` |
| `NFR.SEC.3` | all three clauses hold | `nfr_sec3_key_rotation` |

At least two of these rows record a blocking flag *moving* on that evidence:
`CONFIRM.1a` was regraded `PARTIAL -> PASS` on 2026-09-09 on the strength of its
new binary, and `NFR.PERF.3` states in the cell that blocking goes to no once the
soak landed.

**What this does and does not mean.** It does not make any row wrong. A local
run is real evidence and these rows are unusually well argued — several name
their own RED-then-GREEN capture. What it means is narrower and still material:
the headline `180 met or non-blocking, 3 blocking` is not a number the gate has
ever reproduced. Part of it rests on runs that exist only in the lanes that
performed them, and the gate that would independently confirm them has not
executed those binaries once. For a release decision the distinction is between
"we tested it" and "the pipeline shows it tested", and the ledger currently reads
as the second while being, for these seven, the first.

The remedy is the same single flag as everything else in section E. With
`--no-fail-fast` on the Tests job, one run reproduces or refutes all seven at
once, and the same run tells us whether any of the other 42 stale-green binaries
regressed during the 31 dark hours. Until then the honest statement of release
readiness is that three criteria block by the ledger's count, and seven more are
graded on evidence the pipeline has never seen.

### G. The bridge acquired a production call site today, and two lanes are reasoning from before that

`b7a4a768`, "feat(mrtr): wire the input bridge into the invoke path", landed on
origin at 2026-09-09 11:26. `InputBridge` is constructed at
`src/gateway/meta_mcp/invoke.rs:1733` on origin's own tip and `:1765` locally.
Verified on both trees rather than one.

Three statements in circulation predate it and are now false:

- The coordination file states `InputBridge` "has zero production call sites —
  `rg -n --hidden --no-ignore "InputBridge" src/` returns three hits, all inside
  its own file". There is a fourth hit, in `invoke.rs`, on origin. The three
  prerequisites that note lists as gating the call site are gating a call site
  that already exists.
- The MRTR.7a/7b acknowledgement describes `Bridge::retry_params` as having "one
  non-test caller, inside the `run` nothing calls". `run` is called now.
- The module doc of `tests/mik_7212_mrtr7_stdio_acs.rs` says its rows "cannot be
  shown to work while `InputBridge::run` has no production caller ... nothing on
  a transport calls it, so no bridged request is written to the pipe at all".
  That justification for an unobservable test row has expired.

The narrow claim in that same acknowledgement survives and should not be
disturbed: `Bridge::to_legacy_client` genuinely has no caller at origin, in
`src/` or in `tests/` — the only surviving mention is a doc comment recording
that a property was *previously* pinned against it. So that lane's scope is
right and its premise is stale, which is the more awkward combination: the
conclusion holds while the reasoning behind it needs re-deriving against a tree
where the wiring exists.

Two consequences. The legacy-bridge fall-through committed as `3227c985` is on a
live production path, not a latent one, which strengthens it. And the stdio test
row may now be observable; nobody has re-read it since the wiring landed.

**The stdio invariant holds, and its proof has a named untested seam.** The
fall-through could in principle have shipped MIK-7387's future behaviour early,
because `input_bridge.rs` documents the stdio refusal as deliberate "until
MIK-7387 lands". It does not, and the reason is structural: `stdio_caller_context`
sets `input_capabilities: Declared::NONE` (`server/mod.rs:2236`), and `run`
calls `plan` at `:404` before `ask` at `:410`, so an undeclared caller is refused
with `BridgeError::Refused` one step before any delivery attempt — an arm the
fall-through does not touch. Verified at source on this tree.

Worth recording the seam the same file names in its own comment: the two halves
of that invariant are "proven separately ... No test joins the two end to end
yet; that row is `MIK-7212.WIRE.10`". So the safety argument for `3227c985` rests
on a structural fact whose end-to-end proof is an open test-plan row. That is not
an objection to the fix — the structure is real and checkable by reading — but it
belongs in the record, because a future edit to either half would break the
invariant with no test to catch it.

### E-upgraded: the stale green is real green, and the six-versus-seven seam

Two things, one from a second lane's follow-up and one against this document.

**The last green run was a genuine full pass, not a fail-fast illusion.** This
matters because a fail-fast run can look green simply by stopping early, which
is the whole failure mode section E describes — so "it was green 31 hours ago"
would be worth very little if that run had also aborted somewhere in the suite.
It did not. Four independent checks agree: the tree at `5cb4f4e9` held 75 test
files, that run executed 75 binaries, the log carries zero `test result: FAILED`
lines, and the last `Running tests/...` line is `wolfram_llm_tests` — last in
byte order, so the run reached the end of the suite rather than stopping inside
it.

So the roughly 42 binaries carrying older evidence hold **real green from a
complete, unaborted run on a named commit**, not merely green-before-things-went-
red. They deserve more weight than a stale-green label usually earns. The hole is
correspondingly narrower than section E first drew it: the release's exposure is
the 13 never-green targets and whatever regressed in the 31 dark hours, not 55
unknowns.

**A seam in this document, corrected against itself.** The heading of the
previous subsection says six criteria rest on evidence CI has never run, while
its body says seven are cited and its table lists seven rows. Both numbers are
defensible and neither was explained, which is the defect. The reconciliation:
seven ledger rows cite binaries added after the last green run, and **six of the
seven have executed in no CI run of any colour.** The seventh,
`continuation_expiry_metric_test` behind `NFR.OBS.4`, sorts ahead of the aborting
component binary in byte order, so it does run in the current red runs — it has
simply never appeared in a green one. Seven rows are graded on evidence the
pipeline has never confirmed; six of those seven are backed by binaries the
pipeline has never executed at all. Use seven for the release question and six
for the never-executed question, and say which is which.

**One number withdrawn before it reached this document.** A first pass at the
run-history archaeology reported that 88 of 88 targets had never run, and exited
0. It was false — a dropped path prefix made every fetch 404, the error payload's
first line was captured as a job id, and every run recorded a clean zero. No
figure from that pass is used here; this document's `33 of 88`, `75` and the
13-target list were each read from a job log or derived from `git ls-tree` and
`git diff` directly, and the `75` is now confirmed twice by different routes.

The generalisable point belongs in the record next to the other five reporting
failures catalogued today, because it is the first one that was worn rather than
caught: every ingredient tested clean in isolation, only the composition was
broken, and the exit status said 0 over a confident and complete wrong answer.
What caught it was the answer contradicting data read twenty minutes earlier —
suspicion, not a control. The control is the guard that followed: **an empty
result and a failed fetch must not be able to look alike.** A zero that can be
produced by a broken fetch is not a measurement.

### H. The disk blocker is not ours, and it is getting worse

Every plan item below the documentation layer is gated on one environmental
fact: the repository's disk-pressure hook refuses any command containing
`cargo` while free space on `/` is under 5G, and free space is **3.9G**. No
lane can build, test, or reproduce a single criterion until that clears. This
is upstream of every remaining verification in this document, including the
`--no-fail-fast` re-run that would settle the seven rows in section E and the
component-AC run that would move `MIK-7246.CONFIRM.2`.

Three measurements taken an hour apart change what the blocker is:

- Free space fell from **4.2G to 3.9G with no build running**. `procs` matched
  no `rustc` and no `cargo` process anywhere on the machine.
- Exactly **one** worktree holds a `target/` directory at all — this one, at
  10.0Gi, and it is static. The other lanes have never built here.
- Its largest reclaimable component is `target/debug/incremental` at 7.2Gi,
  whose last write was several minutes before the first measurement.

So the drain is somewhere else on the system entirely. Reclaiming inside this
repository would buy roughly 7Gi of headroom and unblock the lanes, but it
would not touch the cause, and at the observed rate the same wall returns. The
useful framing for whoever picks this up is that there are two separate jobs —
**headroom now** (delete `target/debug/incremental`; `deps/` survives, so no
lane pays a cold rebuild) and **the actual leak**, which nobody has located and
which is not in this repository.

**Why this is recorded rather than fixed.** The disk-pressure hook reserves
reclamation to the operator. The decision was put to the operator three times
and went unanswered each time. Three unanswered asks are an absent operator,
not consent, so nothing was deleted — and the other two lanes were told not to
take it either, because routing the reserved action to a peer defeats the
reservation rather than satisfying it. The same reasoning holds the two CI
workflow flags in section E: `--no-fail-fast` at `ci.yml:198` and
`--all-targets` at `ci.yml:180` are one-line edits with a lane volunteering to
make them, and both remain unowned by decision, not by difficulty.

## I. The path to release-ready, in dependency order

Sections 0–3 order the three blocking criteria against each other. The addenda
added gaps those items do not cover, and several of them are blocked on the same
two things. This section is the whole scope in one list, ordered by what unblocks
what rather than by severity, because severity is not what decides what to do
first here.

**Two unlocks sit above everything, and neither is a technical problem.**

*Unlock 1 — push authority.* This branch is 47 commits behind its own remote and
about 35 ahead, and nothing local has ever been pushed. Every commit in this
document, including this document, is invisible to PR #473 and to CI. A `ci.yml`
edit on an unpushable branch is inert: the workflow that runs is the one at
origin. So the two CI flags are not a live decision yet — they are downstream of
push. This is the single unlock with the most behind it.

*Unlock 2 — disk headroom.* 3.9G free against a 5G hook threshold halts every
build in every lane, including the local runs that would settle the local-side
gaps. Section H holds the detail and the ownership.

**The ordered path.** Each row names what closes it, not merely what is wrong.

| # | Gap | Action | Blocked on | Observable that closes it |
| --- | --- | --- | --- | --- |
| 1 | Nothing local is visible to CI or the PR | Push the branch | operator: push authority | `origin/fix/mrtr2-continuation-handle` contains `d053bc7e` |
| 2 | Tests job aborts at the first failing binary | `--no-fail-fast` at `ci.yml:198` | #1 | a run whose log lists all 88 `Running tests/…` lines |
| 3 | Clippy does not lint test targets | `--all-targets` at `ci.yml:180` | #1 | the `items_after_statements` error at `tests.rs:4840` appears in CI, not only locally |
| 4 | 16 component ACs fail; branch is red | Section 0's lost implementation | #1, #2 for confirmation | `mik_7212_mrtr_component_acs` green in CI |
| 5 | 7 rows graded on evidence CI never ran | No code change — re-run under #2 | #2, #4 | those 7 binaries appear with pass lines in one CI run |
| 6 | 42 binaries hold green from 31 hours ago | No code change — same run as #5 | #2, #4 | the same run covers them; regressions surface or do not |
| 7 | `MIK-7246.CONFIRM.2` unreachable | Peer fix `3227c985` needs its RED baseline and the 16 ACs | disk, then #4 | pre-fix red, post-fix green, both recorded |
| 8 | `MIK-7272.SUB.2b` emit half missing | Build it (section 1) | #4 clears the tree | a consumer test over the two landed capture paths |
| 9 | `MIK-7272.SUB.4` covered on 2 routes of 3 | Third route (section 2) | #4 | `mik_7272_sub4_three_routes` green on all three |
| 10 | `gateway_invoke` reports backend failure as `isError: false` | Section B | #4 | a test asserting `isError: true` on a failed backend call |
| 11 | `MIK-7212.WIRE.10` — stdio invariant unproven end to end | One joining test | none technical; owned by `bridge-mrtr7` | a test that drives a stdio caller to `BridgeError::Refused` |
| 12 | Local tree cannot merge | Merge, never rebase | two peers' uncommitted `backend_handlers.rs` and `server/mod.rs` | a clean merge commit with both lanes' work intact |

**What the ordering says that a severity list would not.** Items 5 and 6 need no
engineering at all — one flag and one run resolve ten rows between them, and that
run is worth more than any single fix in the table because it is the only step
that converts "we tested it" into "the pipeline shows it tested" across the whole
suite at once. Items 8, 9 and 10 are real build work and are the only rows that
are. Items 1, 2 and 3 are decisions rather than work, and they gate almost
everything else.

**What release-ready means concretely, when this list is done:** one CI run at a
named commit, with `--no-fail-fast` on, in which all 88 binaries execute, none
fails, and `scripts/release/count-release-criteria.py --check` reports zero
blocking against a ledger whose cited evidence that run reproduced. Today none of
those four conditions is met, and the ledger's `180 met or non-blocking, 3
blocking` is a count the pipeline has never once reproduced end to end.

## J. `ran=0` has three causes, and only two of them are a flag

A second lane closed the run-history question and reported a union across "all 34
CI runs" on this branch: 76 distinct binaries ever executed against 88 in the
tree, so twelve have never run in CI of any colour. That twelve matches the list
this document derived from ledger citations, name for name, by an independent
route — log lines rather than criteria rows. Two legs, one answer.

**The conclusion survives; the denominator does not.** `gh run list --workflow CI`
returns **90 CI runs** on this branch, `46 success, 44 failure`, back to
2026-09-01. Thirty-four is what a 100-run page yields once `Docker` and
`Dependabot auto-merge` are interleaved with `CI` at roughly one apiece — a
window over the last four days, not the branch's history. It is worth being
precise about why the twelve are unaffected by that: the twelve test files were
added after `5cb4f4e9` on 2026-09-08, and every run since that commit falls
inside the sampled window, so no unsampled run could have executed a file that
did not exist when it ran. The sample happens to cover the whole lifetime of the
things being counted. That is what makes the union safe to use, and it is a
different argument from "we looked at every run".

**The `ran=0` finding is real and its cause is not single.** The same report
notes that most sampled runs executed no integration binary at all, and reads
that as this branch dying before integration testing. Three job logs, read
directly, show three distinct shapes behind that one number:

| Shape | Evidence | Does `--no-fail-fast` fix it? |
| --- | --- | --- |
| The lib does not compile | `error: could not compile 'mcp-gateway' (lib) due to 1 previous error`, `exit code 101`, run `34345016352` @ 11:20 | **No.** Nothing is built, so nothing can run. |
| Lib unit tests fail | `test result: FAILED. 4155 passed; 2 failed`, zero `Running tests/` lines, run `34361905129` @ 14:10 | Yes. The abort is one stage earlier than the one section E describes. |
| An integration binary fails | abort at `mik_7212_mrtr_component_acs`, `ran=33`, runs `cbd224f0` and `9ff75b16` | Yes. This is the shape already tracked. |

The two lib tests that abort the middle shape are
`block_1_gateway_execute_interim_fields_reach_the_result` and
`block_1_gateway_invoke_interim_fields_reach_the_result` — the same pair a peer
lane measured as stale rather than substantive, which is consistent with them
being fixed already, but nothing in CI has yet shown that.

**What this changes in section I.** Item 2 is worth more than it was written to
be: one flag converts two of the three red shapes into full coverage, not one.
It also cannot stand alone — a run in the first shape produces zero binaries with
the flag on, so item 4 (a tree that compiles) genuinely precedes it rather than
merely accompanying it. The observable for item 2 is unchanged but its
precondition is sharper: all 88 `Running tests/…` lines are only reachable from a
commit whose lib compiles and whose lib tests pass, because both stages sit ahead
of the first integration binary in the same test invocation.

### H-update, 2026-09-10: the headroom came back, from outside this session

Free space on `/` went 3.9G → 2G → **18.2G** within the same evening, and a
`cargo --version` probe now passes the MIK-4777 guard instead of being refused.
Nothing in this session deleted anything; the recovery freeze held throughout, and
the operator question in section H was never answered. So roughly 14G was
reclaimed by something outside this lane.

Two things follow, and only one of them is good news. Builds are legal again, so
the local-side work that was frozen — the sixteen component ACs, the RED baseline,
the two `MIK-7246.CONFIRM.2` rows — can run, and the owning lane has been told the
slot is theirs. But the underlying question section H raised is still open and is
now better evidenced rather than closed: a machine that can lose 2G with no build
running and regain 14G with no build finishing is not a machine whose free space
is a stable input. Treat the headroom as borrowed. `target/debug/incremental` was
7.2Gi at last measurement and an incremental run spends back into exactly this
budget.

### J-update: the twelve rest on tree membership, not on dates

The lane that produced the union re-derived its own denominator and confirmed 90
CI runs, 46 success and 44 failure, earliest 2026-09-01 09:02 — its sample ran
09-05 23:15 to 09-09 18:27 and missed 56 runs.

More usefully, it replaced the survival argument above with a stronger one. This
document justified the twelve by *when* the files were added, which is an
inference: a file can be added, deleted and re-added, and the dates would still
read the same. The lane instead asked the tree directly at the last green commit:

```
git cat-file -e 5cb4f4e9:tests/<f>.rs   ->   present=0  absent=12
```

None of the twelve existed at `5cb4f4e9`, and the check discriminates rather than
always answering absent — `mik_7272_task_1_acs` comes back present. So the twelve
stand on all 90 runs, not on the sampled 34, and they stand on membership rather
than on chronology. Prefer that formulation to the dated one.

**Two claims withdrawn by their author, recorded here because both appear above.**
"No red run has ever executed more than 33 targets" and "25 of 34 runs scored
`ran=0`" are sound about the four-day sample and unverified about the branch: in
the unsampled 09-01 to 09-05 stretch the tree held roughly 66 targets and a red
run there could have aborted later than 33. Neither claim can touch the twelve.
Both are being closed rather than scoped — a full 90-run scan is in flight,
classifying every run by the three shapes in the table above, which will replace
the sampled counts with branch-complete ones and answer the question section J
leaves open: whether the compile-failure shape, the one no flag rescues, is rare
or routine.

## 2026-09-11: where the release stands now, and the ordered path out

Re-derived today against the worktree, not against the sections above. The count
moved and the red set shrank; both are recorded here rather than edited into the
09-09 prose, so the earlier state stays readable.

**Ledger.** `scripts/release/count-release-criteria.py --check` exits 0 and reports
**146 criteria, 186 rows, 184 met or non-blocking, 2 blocking**. `--blocking` names
them: `MIK-7272.SUB.2b` and `GH475.RL.5`. Of the three that blocked on 09-09,
`MIK-7272.SUB.4` is MET (corrected 2026-09-10 from a flip two reviewers had rejected)
and `MIK-7246.CONFIRM.2` no longer carries a blocking flag. `GH475.RL.5` is new to the
blocking set and is not code: the predicate's `throttled` arm is deliberate and
recorded, and whether the criterion text or the predicate moves is a question already
with the requester at [#482](https://github.com/MikkoParkkola/mcp-gateway/issues/482).

**CI.** The last run on `fix/gh517-protocol-negotiation` (`34541872175`, 2026-09-11
01:26Z) is red on the Tests job with **three** rows, not sixteen: `s02_stdio_progress_*`,
`s02_stdio_message_*` and `s03_progress_stdio_*` — `1 passed; 3 failed` in that binary.
All three are the stdio outbound leg of `SUB.2b`. Section D's sixteen are therefore
closed. Twenty commits are unpushed, so CI has not seen the newest work at all.

**Correction: the emitter is not missing — it is uncommitted.** The `SUB.2b` row has
described the stdio outbound emitter as unbuilt, and against `HEAD` that is still exactly
true. Against the *worktree* it is not: a peer lane holds 682 uncommitted insertions
across `src/transport/stdio.rs`, `src/gateway/server/mod.rs` and `src/gateway/streaming.rs`
that build it. Both readings are correct about different trees, and conflating them is how
this section nearly recorded the opposite verdict. Split by tree:

At `HEAD` — the tree CI measured when it produced the three red rows:

- `take_captured_notifications` (`src/transport/stdio.rs:445`) is still present and still
  the end-of-call drain, published at `:621`. ADR-014 §3 requires it deleted.
- `dispatch_with_notifications` does not exist in `src/gateway/server/mod.rs` at all. The
  client-facing stdio leg — the task that writes notifications to stdout while the call is
  still running — is absent. That single absence explains all three red rows.

In the worktree, uncommitted, owned by another lane:

- `take_captured_notifications` is gone, definition and call sites both.
- `register_progress_token` (`:451`) takes the request's sender from the ambient sink and
  `capture_notification` (`:474`) sends per notification (`:487`) — the per-request channel
  §3 asks for, not a `Vec`.
- `dispatch_with_notifications` (`src/gateway/server/mod.rs:1970`) scopes the sink around
  dispatch and runs a concurrent stdout writer, established *inside* the per-request spawn
  (`:1806-1838`), so the `tokio::task_local!` at `src/transport/notification_sink.rs:34` is
  live where the transport reads it.

The HTTP half is committed and needs no such split: `decode_sse_exchange` publishes each
notification as its chunk decodes (`src/transport/http/sse_decoder.rs:264`), reached from
the incremental arm at `src/transport/http/mod.rs:1305-1317`, and `first_event_wins_stream`
(`src/gateway/streaming.rs:705`) forwards before the result. The caller's `progressToken`
is relayed outbound rather than dropped (`src/gateway/meta_mcp/prompt_cache.rs:246-249`).

The consequence for the plan is that nobody should build this emitter. It exists; it is
unlanded. The blocker is a commit, not a design.

**And one of the three rows is not in scope either way.** ADR-014 §2 states that
`notifications/message` *from a backend* stays unattributable over stdio, because it
carries no progress token and therefore has no key. `s02_stdio_message_*` asserts exactly
that case, so it tests something the ADR declined to build. That reading predicted an
`#[ignore]`; the measurement says otherwise — see the correction below, and do not act
on the `#[ignore]` suggestion. §3's outbound emitter carries "the backend's
`notifications/progress` and, over HTTP, its `notifications/message`" — so
`s02_stdio_progress_*` and `s03_progress_stdio_*` are the real two. This reading is a
property of the ADR and holds against both trees.

**A gap the machine check cannot see.** The ledger's own rule is "a criterion is
BLOCKING unless it is MET or N/A", and the counter enforces vocabulary on the blocking
column only — `MET`, `PARTIAL`, `ABSENT` and the rest are never matched against a
pattern. Two rows exploit that without meaning to: `MIK-7246.CONFIRM.1a:247` and
`MIK-7246.CONFIRM.2:249` both read status `PASS`, a token the vocabulary block does not
define, and both are flagged `no`. Under the stated rule neither is MET and neither is
N/A, so both should be blocking; under the script both are silently fine. The evidence
in those two cells is substantive — the risk is the token, not the criterion. The repair
is a status-column regex in `count-release-criteria.py` beside the existing blocking-column
guard, and a restatement of the two rows by whoever owns their evidence. Until that runs,
"2 blocking" is a count over rows whose status words were never checked.

**The HTTP half of `SUB.2b` has an open defect with no measurement.** Recorded in
`docs/design/2026-09-11-sub2b-http-liveness.md`: a fixture whose second notification
exists only after an intervening client call yields one notification and stalls, while
the same row with the second notification on a timer passes. The stream leg therefore
forwards two notifications and the layer that drops the gated one is unidentified. The
two reproduction rows in `tests/mik_7272_sub2b_acs.rs` are `#[ignore]`d and unrun; their
`PROBE-A`/`PROBE-B` labels separate "the intervening call was never serviced" from "it
was serviced and no frame followed", which is the measurement that names the layer.

**Order of work, from here.**

1. Land the stdio outbound emitter that already exists uncommitted. This is the whole of
   the stdio blocker and it needs no design: the peer lane holding those 682 insertions
   commits them, with pathspec, and CI measures the result. Nothing else in this plan can
   turn `s02_stdio_progress_*` or `s03_progress_stdio_*` green, and no other lane should
   write into those three files while they are dirty.
2. Measure, then fix, whatever survives that commit. The HTTP half's defect is unlocalised
   and stays that way until the discriminating rows run: the `#[ignore]`d PROBE rows, plus
   `s02_stdio_progress_*` once step 1 lands. **The lane that wrote this section cannot run
   the `mik_7272_sub2b_acs` integration binary** — it is denied there — so the measurement
   has to come from elsewhere. Whoever picks it up runs that binary twice, once with the
   ignored rows enabled and once filtered to the stdio progress row, both with captured
   output, and reads which `PROBE` label fires. Until then every claim about *which* layer
   drops the frame is unevidenced. (The `s02_stdio_message_*` sentence that stood here
   recommended an `#[ignore]`; it is withdrawn — the row passes. See the correction
   below.)
3. Add the status-column guard to the counter and restate `CONFIRM.1a` and `CONFIRM.2` in
   the ledger's own vocabulary. Cheap, and it is what makes step 5's number mean anything.
4. Close `GH475.RL.5` by decision at [#482](https://github.com/MikkoParkkola/mcp-gateway/issues/482).
   No code moves until the requester answers which side gives.
5. Push and let CI run. Twenty unpushed commits are twenty commits of unmeasured surface;
   a green local suite on a shared, dirty worktree is not the same observation.
6. Cluster F last: `NFR.COMPAT.1` is a default change the board sequences behind clusters
   A and C, and `NFR.PERF.1`'s residual stands — no P50 or P99 may be quoted publicly for
   this release until an end-to-end harness produces one.

Steps 3 and 4 are independent of 1 and 2 and are the only ones this lane can advance;
step 1 belongs to the lane holding the uncommitted emitter, and step 2 needs a lane where
the integration binary runs. Nothing
here reopens a decision the release owner has made; the `NFR.PERF.1` headroom ruling and
the ADR-014 narrowing both stand as recorded.

### 2026-09-11, later: landing the emitter does not close `SUB.2b`, and the last red row is faithful

Step 1 above says the stdio work is a commit rather than a build. Half of that
survives and half does not. The emitter half is real and uncommitted, as recorded.
The *correlation* half is neither built nor merely uncommitted — what sits in the
worktree implements the design ADR-014 §2 explicitly retired.

Read at source, in the peer-held worktree copy of `src/transport/stdio.rs:602-607`:

> Register before the write: the reader task can route a notification back before
> `write_message` returns. **Never minted here** — only a token the caller supplied
> is honoured (MIK-7272.SUB.2b, option (i)).

ADR-014 §2 heads the paragraph that overturns exactly that rule —
*"**Superseded: "the gateway never mints a token."**"* — and gives three reasons,
each cited to the map it guards: the key space collapses `Number` and `String` into
one entry, `register_progress_token` is a bare `insert` that overwrites a live
owner, and a caller reusing its token on a later call inherits the earlier call's
late notifications. The decision it records is a minted `gw-<uuid>` registered as
`minted → (the caller's token, the request's bounded sender)`, translated back on
capture so the client still sees its own token byte-identically, with a drop guard
removing the entry on every exit path.

No minted token reaches the registration map. The claim is made at the map's only
entrance rather than by pattern-matching a name: `register_progress_token` has one
production call site, `src/transport/stdio.rs:607`, and it passes
`request_progress_token(...)`, which reads `_meta.progressToken` off the outbound
request and substitutes nothing (`stdio.rs:584-589` in the worktree, `:570-575` at
`HEAD` — identical on both). Whatever a mint were called, it could not be registered
without going through that line. (A repo-wide search for the `gw-` prefix finds only
session ids at `src/gateway/streaming.rs:193,203` and trace ids at
`src/gateway/meta_mcp/tests.rs:78`, but a prefix search cannot carry this claim: a
mint spelled any other way would be invisible to it.)

That is why `s02_stdio_progress_reaches_its_own_call_before_the_result` is red, and
it is red for the right reason. Its final assertion
(`tests/mik_7272_sub2b_acs.rs:515-520`) requires the token the backend sees to
differ from the client's, citing this ADR section by name. The row is a faithful
acceptance test for a decision the code has not caught up with — not a row to
amend, and not a row an `#[ignore]` may cover.

Commit `aaad0281` ("relay the caller progress token to the backend", 2026-09-11
04:09) is adjacent but not the cause. It supplies an outbound token where a backend
previously received `null`, which the HTTP leg needs and correlates structurally
anyway. On the stdio leg the ADR's mint would overwrite that value before the write.
The conflict is not between the commit and the ADR; it is that the mint step, which
both would sit under, is absent.

**So step 1 becomes two.** Landing the emitter (still the peer lane's commit) clears
delivery. Correlation is a second, smaller change in the same file: mint per outbound
request that carries progress, register the minted key against the caller's token and
sender, translate back at `capture_notification`, guard the removal, and rewrite the
`:602-607` comment that still cites option (i) as live. Until it lands, `SUB.2b`
stays blocking on both trees, and no count that assumes otherwise is safe.

**And step 2's two parked rows have an answer, from a lane where the binary runs.**
Both `#[ignore]`d PROBE rows were measured on 2026-09-11 by the lane holding
`src/gateway/streaming.rs`. The timer row passes. The two-gate row fails, and not on
the notification path: its debug log shows both notifications decoded and published,
then the *second* `release` call answered from the response cache with no backend
request behind it, so the fixture's second permit is never added and the result frame
never comes. Giving that call a distinguishing argument makes the row pass in full.
The mechanism is corroborated here at source rather than taken on report:
`response_cache_key_for` takes `&arguments` (`src/gateway/meta_mcp/invoke.rs:1453-1468`),
so two byte-identical calls are one cache entry. The row asks one cached call to have a
side effect twice, which no gateway change can satisfy. A second defect in the same row:
its PROBE labels can never fire, because the helper bounds its own read with the same
duration the row wraps around it and always wins the race. Both are test defects; the
rows stay parked until they are fixed, and neither is evidence about the product.

### 2026-09-11, correction: the stdio message row passes, and the absence claim is narrower than it read

Two claims in the sections above were stated more widely than what was checked. Both are
corrected here rather than edited away, because the wider versions were relayed to another
lane and someone may be acting on them.

**The `#[ignore]` recommendation for `s02_stdio_message_*` is withdrawn.** Two sections
above told whoever picks up the stdio work that the row "needs an `#[ignore]` carrying the
ADR reference, not an implementation". The ADR reasoning behind that is sound — ADR-014 §2
does leave a backend `notifications/message` unattributable over stdio, and the row's own
doc comment says it tests exactly that case — but the conclusion was never measured against
the suite. It has been now. The HTTP lane ran the whole binary at `6fc9471b`, unfiltered:
`7 passed; 1 failed; 2 ignored`, the sole failure being
`s02_stdio_progress_reaches_its_own_call_before_the_result` and the two ignored being the
parked PROBE rows. `s02_stdio_message_reaches_its_own_call_before_the_result` is listed
`ok`. It is out of
scope for the criterion *and* green, which owes no test edit at all. An `#[ignore]` applied
to it would have parked a passing row on the strength of a document.

**"No minted progress token exists anywhere in `src/`" overstated its own evidence.** The
search behind it matched the literal `gw-` prefix. A mint assembled any other way — a
`const` prefix, a bare `Uuid::new_v4()`, a helper in a module the search did not name —
would not appear in it, so the sentence claimed more than a prefix search can carry. The
claim is now made at the registration map's only entrance instead:
`register_progress_token` has one production call site, `src/transport/stdio.rs:607`, and
what it passes is `request_progress_token(...)`, which reads `_meta.progressToken` off the
outbound request and substitutes nothing — `stdio.rs:584-589` in the worktree and
`:570-575` at `HEAD`, byte-identical. However a mint were spelled, it could not reach the
map without going through that line. The conclusion is unchanged and the correlation half
of SUB.2b stays unbuilt; only the reach of the evidence changes.

The pattern in both is the same: a document was read correctly and then allowed to answer a
question only a measurement can answer.

### 2026-09-11, ruling: who owns the correlation half, and what the worktree now says about step 5

**The correlation half of SUB.2b belongs to the stdio lane, not to the lane that fixed the
HTTP leg.** The mint, the `minted → (caller token, sender)` registration, the translate-back
and the drop guard all land in `src/transport/stdio.rs`, which carries 153 changed lines of
that lane's uncommitted emitter — the same seam, not an adjacent one. A second session
editing into it is how work gets swept. The HTTP lane asked rather than assumed, which was
right; the answer is no, and the reason is the file, not the competence.

What that lane does instead is the design for the half, now, while the file is dirty: it
touches nothing, it is step 1 of this plan's own order, and it converts a wait into
progress. Two constraints the design has to satisfy rather than caveat. The drop guard's
"every exit path" includes the transport error paths and a panic in the reader task — a
guard that leaks one entry per panicked reader is unattributable map growth later. And the
translate-back has to survive ADR-014 §2 reason (1): `capture_notification` collapses
`Number(n).to_string()` and `String(s)` into one `String` key, so byte-identical return of
the client's own token is a property to prove, not to assume. If the stdio lane turns out
parked, the half moves with its design already reviewed and nothing is wasted.

**Step 5 got harder while nobody was looking.** Earlier in the day this worktree carried
three modified files. It now carries fifteen modified and five untracked, spanning at least
MIK-6744 identity plumbing, MIK-7116, MIK-7406 signing validation and the sub4 resend
design — several lanes, all mid-flight. A push or a review payload taken from here would
carry all of it, so "push and read CI" is not a step someone can take unilaterally when
they judge their own work ready; it needs the tree, not just one lane, to be quiet. Anyone
reaching step 5 should re-count before assuming the earlier three-file picture still holds.

One worktree-specific trap, found while checking that: `git status --porcelain` reported
` M src/gateway/streaming.rs` for a file whose `git diff` is empty and whose content is
fully committed in `d6087aca`. That is a stale stat entry in the shared index, not content.
In a worktree this busy, confirm a reported modification with `git diff` on the path before
treating it as somebody's in-flight work.

### 2026-09-11, correction: the run quoted above was a stale capture

The `6 passed; 2 failed; 0 ignored` cited in the correction section — and repeated in the
`SUB.2b` ledger row — was read out of a captured run file from earlier in the day, before
the HTTP leg was measured clean. It was quoted as if current. It is not, and it named
`s02_progress_http_reaches_its_own_call_before_the_result` as a failure. That row passes,
and has passed in every run the HTTP lane has recorded; a reader taking the number at face
value would have gone hunting an HTTP defect that three independent measurements say does
not exist.

The current figure, whole binary at `6fc9471b`, unfiltered: `7 passed; 1 failed; 2 ignored`.
The sole failure is `s02_stdio_progress_reaches_its_own_call_before_the_result`, the
correlation row this plan documents as genuinely unbuilt. The two ignored are the parked
PROBE rows. Every HTTP row is green, and so is
`s02_stdio_message_reaches_its_own_call_before_the_result` — which is the row the
withdrawal above turns on, so that conclusion is unaffected and now rests on a current
measurement rather than an old one.

The failure mode is worth naming, because it is the same one the correction section was
written to fix, one level down. That section faulted a document for answering a question
only a measurement can answer; the fix then reached for a measurement that had gone stale
and used it the same way. A captured run file is evidence about the tree it ran against. It
carries a commit, and if the quote does not carry one too, it is not yet evidence about
now.

### 2026-09-11, ruling: ADR-014 governs the correlation half, and its owner just died

`b9e1fb95` ("docs(adr): mint stdio progress tokens instead of the caller's", +181/-55) is
the design of record for the correlation half. It decides the mint, the
`minted → (caller token, sender)` entry and the translate-back, and at `:158` it already
requires the drop guard to cover "cancellation alike", for the stated reason that the
registration would otherwise outlive the sink. A second design document written today
(`docs/design/2026-09-11-sub2b-stdio-minted-progress-token.md`) is **subordinate**: it is an
implementation plan, not a competing design, and it is deliberately not going through an
independent design review. One criterion carrying two separately-reviewed documents is
several rounds spent reconciling two texts that are each individually correct.

Two things in it are worth keeping, because the ADR does not decide them at that
granularity. Store the caller's original `Value` rather than its string form — that is what
makes the translate-back byte-identical across the `Number`/`String` collapse the ADR names
as reason (1). And generalise the existing `PendingRequestGuard` over its value type instead
of adding a second near-identical guard. Both are implementation choices and belong at the
call site, not in a document.

The subordinate doc's drop-guard section is worth reading as what it actually found: not a
gap in the ADR, but a gap in *today's code* against what the ADR already demands. The
release after `outcome` is a plain statement, so it covers `Ok`, transport error and
timeout, and does not cover the future being dropped mid-await. That path leaks one entry
and holds the caller's sink open. A panicked reader task costs one `request_timeout` per
in-flight call and no map growth, because the guard still drops on that path.

**Ownership is now uncertain.** `row6-mint-2` answered that it was working the row and that
no new design was needed — correct — and then failed on the 32000-token output ceiling,
which lands no writes. `row6-mint` has not answered. The half may be unowned; a status
request is out to `row6-mint`, and the lane that wrote the subordinate doc is next in line
with the analysis already done. Whoever takes it cannot start until `stdio-concurrent`
commits the emitter, because the work lands in the same file.

One operational note, since it cost an owner: an agent killed by the output ceiling
persists nothing. On a criterion this long-running, commit each piece as it works rather
than reporting a large result at the end.

### 2026-09-11, amendment: the guard change is two files, and two doc comments ride on it

The ruling above called the `PendingRequestGuard` generalisation an implementation choice
that "belongs at the call site". That understated where it lands, and the corrected scope is
verified here at `HEAD`. The guard is declared at `src/transport/mod.rs:180` with `Drop` at
`:199`, and it has two existing construction sites: `src/transport/stdio.rs:619` and
`src/transport/websocket.rs:515`. Adding a value-type parameter edits the declaration in
`transport/mod.rs`; the websocket site infers it and compiles unchanged. Both of those files
are clean in this worktree — only `stdio.rs` is dirty — so the change crosses no other
lane's in-flight work.

Two doc comments describe that guard from outside the transport module and must be re-read
rather than assumed: `src/gateway/proxy.rs:96` and `src/gateway/input_bridge.rs:291`, the
first of which says in as many words that the guard "is typed to the …". A generic parameter
is exactly the kind of change that leaves such a sentence quietly false, and a stale comment
is model input for the next agent to read the file.

The generalisation is still the right call rather than a second near-identical struct, and
the codebase says so itself: the comment at `websocket.rs:511-514` already gives the guard's
purpose as keeping "a request future dropped by an OUTER timeout or task abort" from
stranding its entry — the same cancellation case the correlation half needs. The motivation
is not new; only the second map is.

Related correction from the same lane, recorded because the earlier reasoning is quoted
above: the reader-panic path is bounded by the existing release statement after `outcome`
and needs no guard. RAII is for cancellation alone — the future dropped mid-await, where
that statement is never reached.
