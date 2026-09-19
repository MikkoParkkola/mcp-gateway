# SUB.2b outbound leg — implementation brief

Criterion `MIK-7272.SUB.2b`, outbound half. Graded `ABSENT` in
`docs/requirements/RELEASE-4.0.0-criteria-status.md`. This brief states what closing
it requires; it is not a record that it is closed.

## Do not commit the parked diff

129 uncommitted insertions in `src/transport/stdio.rs` and
`src/transport/notification_sink.rs` implement the rule
`docs/adr/ADR-014-request-scoped-notifications.md:116-132` retires, under the heading
*"Superseded: the gateway never mints a token"*. The diff also deletes
`stdio_drains_a_captured_notification_into_the_callers_sink`, which passes at HEAD.
Committing it would land a rework that removes passing coverage on a superseded
scheme. It is snapshotted at
`~/github/.agent-snapshots/2026-09-11-sub2b-outbound-uncommitted.patch`
and the grading is committed in `42f1f7de`.

## What ADR-014 requires

The gateway mints its own token per outgoing request, `gw-<uuid>`, substitutes it for
the caller's token on the wire, and translates it back on the way out. Three defects
in the superseded scheme, each cited at source in the ADR:

1. `capture_notification` folds `Value::Number(n)` through `n.to_string()` into the
   same `String` key as `Value::String(s)`, so tokens `7` and `"7"` alias.
2. `register_progress_token` is a bare `insert`: two in-flight calls supplying the
   same token overwrite one another's owner.
3. A reused token outlives its request — release happens only on the explicit path
   at `src/transport/stdio.rs:637`, not on cancellation.

## The constraint that decides the map type

The caller's token must come back byte-identical **and JSON-type-identical**: a
caller sending `7` gets `7`, not `"7"`. `request_progress_token`
(`src/transport/stdio.rs:584`) currently returns `Option<String>` because it funnels
through `progress_token_string` (`:570`), which collapses `Number` into `String`.
That return type cannot carry the requirement. The map value must hold the original
`Value`, and `request_progress_token` must return `Value`.

`progress_token_string` stays correct for the inbound capture lookup, where the
minted key is a `String` by construction — and the inbound side can require
`Value::String` outright, which expresses the ADR's "a minted key is never numeric"
closure in code rather than relying on it.

Defect 3 wants an RAII release rather than another explicit call site;
`PendingRequestGuard` in the same file is the in-repo idiom to match.

## Tests that discriminate

Unit tests in `src/transport/stdio.rs`; the integration binary is hook-denied.
All three fail on HEAD's scheme and pass on the minted one:

1. Two calls with tokens `7` and `"7"` — each receives only its own notification.
2. Two live calls supplying the *same* token — no cross-delivery.
3. Token reused across sequential calls — a late notification from the first does
   not land in the second.

Cases 1 and 3 are unreachable for the parked diff's tests: every token literal in it
is distinct (`tok-a`, `tok-b`, `tok-stray`), so a green run there is evidence about
the cases chosen, not about the criterion.

Write them RED first and read the failure messages. A test that passes at HEAD is
testing something else.

## HTTP needs a mint too

An earlier revision of this brief said HTTP needed nothing, quoting `ADR-014:113`
("none needed — the connection is the key"). That quotation is accurate and the
conclusion drawn from it was not.

`ADR-014` §2's table is headed *"Correlation, per transport"*. It answers **attribution**
— which in-flight call a notification belongs to — and for HTTP the answer really is
structural: a notification on a response body belongs to the request that opened it.
Minting answers a different question: **do not hand a backend the client's own token**.

The acceptance test settles it at source. `write_config`
(`tests/mik_7272_sub2b_acs.rs:271`) gives the backend `http_url` and
`streamable_http: true`, so gateway-to-backend is HTTP; stdio is client-to-gateway only
(`:287-292`). `minted_token` (`:90-95`) reads `/params/_meta/progressToken` off the
frames that HTTP backend received, and `:515-520` asserts it differs from the client's.
A stdio-only mint cannot satisfy that assertion, because no stdio backend is on the path.

So the correlation half is not confined to `src/transport/stdio.rs`. The mint belongs at
the single transport-independent outbound `_meta` writer
(`src/gateway/meta_mcp/invoke.rs:3018-3024`), where both backend transports converge.
`docs/design/2026-09-11-sub2b-progress-token-mint.md` carries the reviewed design.

## Order

Detached worktree at HEAD, so the shared tree's dirty files stay untouched. RED
tests, implementation, `cargo test --lib` under `~/.claude/bin/lowload`, clippy, then
two non-Claude reviewers in parallel. The ledger row moves only after that.
