# PR #473 meta-mcp blockers — fix log

Source report: `docs/release/verify/pr473-metamcp.md`, `## Blocking a 4.0.0 release`
(BLOCK-1..BLOCK-5). Working sequentially, one commit per finding. This file is
appended to after each finding so partial progress survives a kill.

Method per finding: re-verify at source -> failing test first -> smallest fix
at root cause -> re-run test -> clippy/fmt clean -> commit paths named
explicitly.

## Status

| finding | verdict | commit |
|---|---|---|
| BLOCK-1 | pending | |
| BLOCK-2 | pending | |
| BLOCK-3 | fixed, uncommittable (shared file) | |
| BLOCK-4 | fixed, independently verified SOUND | `7abb3514` |
| BLOCK-5 | pending | |

---
## BLOCK-3 — `_meta` injected into direct-route backend payloads

Root cause: `MetaMcp::exposes_meta_tool` delegated straight to
`MetaToolExposure::is_exposed`, which returns `true` for every ungoverned name
by design (`src/gateway/meta_mcp_tool_defs.rs:867-872`). The router feeds that
predicate to `merge_client_meta` as `is_meta_tool`
(`src/gateway/router/handlers.rs:1186`), so a surfaced backend tool answered
`true` and the client's `_meta` was merged into arguments the backend never
asked for.

Fix: a roster predicate, `is_governed_meta_tool`, ANDed into
`exposes_meta_tool` (`src/gateway/meta_mcp/mod.rs:607-609`). Exposure and
ownership are now separate questions, which is what the two call sites needed.

Test: `block3_a_surfaced_backend_tool_does_not_take_the_clients_meta`
(`src/gateway/router/tests.rs`).

**Not yet committable.** The one-line behaviour change lives in
`src/gateway/meta_mcp/mod.rs`, which currently also carries a concurrent
session's edits, including a `promote_interim_envelope` stub whose body is
`let _ = (tool_name, content, response);` — a no-op standing where BLOCK-1's
repair would go. Committing the file would publish that stub as if BLOCK-1 were
addressed. Splitting the commit is also not available: `is_governed_meta_tool`
has no other consumer, so `mod.rs`-less staging fails `-D warnings` on
`dead_code`. Operator decision required on how the shared file is divided.

## BLOCK-4 — a released reservation stored a result bound to no request

Root cause: `IdempotencyReservation::complete` routed through
`IdempotencyCache::mark_completed`, which recovers the admitting request's
fingerprint by looking the entry up. After a `release` — or an
`IN_FLIGHT_TIMEOUT` sweep — the entry is gone, the lookup yields the empty
string, and an empty fingerprint matches every later request, so the stored
result answered any call reusing the key for the whole TTL.

Fix: the reservation carries the fingerprint it was admitted for and passes it
to a new `mark_completed_bound` (`src/idempotency.rs:368`). The lookup path
remains for callers that hold no reservation.

Test: `released_then_completed_entry_stays_bound_to_its_own_request`
(`src/idempotency.rs`), asserting the fingerprint-mismatch refusal by message
rather than by `is_err` — the in-flight and at-capacity refusals are errors too
and neither would prove the binding held.

## Branch clippy gate — `tests/common/mod.rs`

`cargo clippy --all-targets -- -D warnings` failed on the
`nfr_compat1_revisions` target with three errors, all in `tests/common/mod.rs`
and all in content that predates the file's current uncommitted edits: two
`unused_imports` at the re-export block, and `clippy::struct_excessive_bools`
on `Fixture` at :38. The uncommitted change to that file is a 26-line append
at :207, so it cannot be the cause of an error at :23.

Root cause of the imports: the module already carries `#![allow(dead_code)]`
with a doc comment explaining exactly this — Cargo compiles the module once
per test binary, so an item one suite uses is dead in the others. The
mitigation was written for the right reason and does not reach re-exports,
which lint as `unused_imports` rather than `dead_code`. `Duration` is consumed
by `nfr_sec1_controls` alone; the other two binaries that include the module
never touch it.

Fix: widen the existing allow to `#![allow(dead_code, unused_imports)]` and
extend its comment to say which import the split affects. `Fixture` takes
`#[allow(clippy::struct_excessive_bools)]` — its fields are independent
switches each suite flips on its own, and folding them into enums would couple
settings that vary independently.

**Not committed.** `tests/common/mod.rs` also carries another session's
`SPEC_ENCODING_TABLE`, consumed by their uncommitted `tests/mik_7214_acs.rs`
and destined for `tests/mik_7214_header_9_acs.rs`. Committing the file would
publish their in-flight work under this session's authorisation. The repair
sits in the worktree, so whichever session commits that file next carries it
and the gate goes green either way.

## BLOCK-4 — independent verification

A second session re-checked the commit against source rather than against the
fixing session's report. Verdict: **SOUND**. Four questions, all answered from
the tree.

The defect is real and reaches production by two routes, not one. The error
path releases at `src/gateway/meta_mcp/invoke.rs:1481` and still stores the
structured error at `:1836`; the sweep route is live independently, since
`evict_expired` (`src/idempotency.rs:385`) runs from `spawn_cleanup_task`,
wired at `src/gateway/meta_mcp/mod.rs:691`. Either way the entry is gone by
the time the result is written, `Entry::new(Completed, "")` is stored, and
`Entry::matches` (`:150`) treats an empty fingerprint as matching everything.

**The fixing session predicted the wrong assertion, and the verification is
better for having said so.** Its recorded RED came from a superseded revision
of the test, and the fingerprint-mismatch message check it named sits
downstream of an `Err` — on the defect path `enforce` returns
`Ok(CachedResult)`, so that assertion is unreachable by construction. The
load-bearing assertion is the `let Err(err) = outcome else` panic at `:1065`.

Because "failed, but not on the predicted assertion" is exactly how a bad
falsifier probe hides, the verifier ran a second probe with a diagnostic test
against the same pre-fix code, and named what the second request actually
received:

```
LEAK: fp-B served A's body: {"isError":true,"who":"A"}
```

Not a re-admission and not a different error — a verbatim cross-request result
leak. Restore was verified by re-running the test, and `git diff --stat HEAD`
left empty; no `git status`, no `git checkout`.

Regressions: `cargo test --lib idempotency` 28 passed. The reorder of the
`is_final` check is exercised only by integration binaries `--lib` does not
build, so those were run too — `idem_p1_p3_p6_acs` 5, `mik_7216_mrtr_10_acs`
7, `mik_7272_result_2` 2, all passing.

### Residual — the unbound entry point is the public one

Confirmed at source, not taken on the verifier's word:

- `pub fn mark_completed` — `src/idempotency.rs:347`
- `pub(crate) fn mark_completed_bound` — `src/idempotency.rs:368`
- `pub mod idempotency;` — `src/lib.rs:53`
- `matches` still treats `""` as a wildcard — `src/idempotency.rs:150`

The fix removed the internal path to the unbound primitive; it did not remove
the primitive. Every in-tree production caller now goes through the bound
form, so BLOCK-4 is closed for this binary. But the module is published API,
and the only completion entry point an external consumer of the crate can
reach is the unbound one — calling it mints exactly the wildcard entry this
blocker was about.

That is an API-surface question for 4.0.0 rather than a defect in this commit,
and it is recorded here rather than filed: the decision is whether
`mark_completed_bound` becomes public, `mark_completed` takes a fingerprint as
a breaking change, or the wildcard in `matches` goes away entirely. All three
are release-scope calls for the operator.

### Gate re-run — the three errors are gone, one different failure is not

`cargo clippy --all-targets` after the repair: no `tests/common/mod.rs`
diagnostic survives, and the `nfr_compat1_revisions` target compiles. The run
still exits 101, on a different target and a different file:

```
tests/mik_7215_control4_reap_count_acs.rs:29:20: error[E0308]: mismatched types: expected `()`, found integer
tests/mik_7215_control4_reap_count_acs.rs:51:27: error[E0308]: mismatched types: expected `()`, found integer
```

Not this session's, and not a defect. The file is committed as `09735d32`,
"test(control4): T3 — reap reports what it reclaimed, **red by signature**".
It asserts `lifecycle.reap(300)` returns a count; `reap` currently returns
`()`. That is a test written before its implementation, doing exactly what the
process asks of it, and it will compile when the owning session lands the
signature change.

It is nonetheless the branch's current gate failure, so `-D warnings` cannot
go green until that increment lands. Left alone deliberately: implementing
another session's `reap` mid-increment would collide with the work its RED
test was written to drive.

Recording the exit code separately mattered here. The background task reported
`exited with code 0` — that is the trailing `echo`, not the compiler.
`CLIPPY_EXIT=101` came from capturing `$?` before anything else ran.
