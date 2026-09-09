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
is a merge artifact rather than a deliberate revert. Two tests fail out of 4157
and both are explained by this one placeholder -- that is what makes it the whole
of the red, not a claim that nothing else was dropped.

Restoring the body turns the suite green; it is verified green locally with that
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
