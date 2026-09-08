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
| BLOCK-2 | fixed | `1e8d6967` |
| BLOCK-3 | fixed, independently verified SOUND | `73cf8117` |
| BLOCK-4 | fixed, independently verified SOUND | `7abb3514` |
| BLOCK-5 | fixed | `c169bfc7` |

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

## BLOCK-3 — independent verification

A second session re-checked the repair against source. Verdict: **SOUND**.

The defect reaches the wire, which the fixing session inferred and the verifier
proved: pre-fix, `merge_client_meta` (`src/gateway/router/helpers.rs:236`)
injected the client's `params._meta` into `arguments`, and `arguments.clone()`
(`src/gateway/meta_mcp/mod.rs:1503`) hands that to the backend. Consumption,
not just construction.

Falsifier probe: the pre-fix predicate restored behaviourally, the new test
re-run, failing on the intended assertion — `_meta` present against
`{"city":"Oslo"}` — rather than on a compile error. Restore verified by
re-running the test. The verifier stated a fidelity limit rather than burying
it: the probe carried one extra `let _ = …is_governed_meta_tool;` statement, so
it was behaviourally the pre-fix predicate and not a byte-level revert.

Consumer analysis found the one place where narrowing a predicate could have
removed a security check — the admin pre-check at
`src/gateway/router/handlers.rs:1242` — and showed it is a no-op: all four
`ADMIN_META_TOOLS` names are built under all-true gates, so
`is_governed_meta_tool` already answers true for each.

`cargo test --lib`: 4091 passed, 3 failed. None attributable. One is a
base-branch red under `src/capability/` with no working-tree diff; the other
two are another session's RED-phase tests driving `promote_interim_envelope`,
the stub named earlier in this document. Triaging those as regressions would be
a mistake, and the verifier said so explicitly.

### Residual — the stdio entry point has no test of its own

`src/gateway/server/mod.rs:1856` carries the identical merge and is repaired
only because the predicate is shared. Nothing drives it end-to-end, and nothing
drives `handlers.rs:1186` end-to-end either; the new test pins the
predicate-plus-merge composition. That is a coverage gap rather than a defect
in this fix, and it is the strongest thing standing against the repair.

Also unexercised: the allow-list arm of `is_exposed`, `Some(allowed)` with
`|| !governed.contains(name)`.

---
## BLOCK-5 — the backend's raw `requestState` leaked in `structuredContent`

Root cause: `enforce_output_schema` fell back to the whole MCP envelope when
`extract_output_validation_target` found no inner payload
(`unwrap_or_else(|| result.clone())`). The envelope then failed validation
against a schema that describes the tool's *payload*, took the advisory
pass-through branch, and `apply_validated_output` republished the entire
envelope under `structuredContent` — backend `requestState`, `resultType` and
`inputRequests` included. The mint at `invoke.rs:1602` replaces only the
top-level field, so the copy inside `structuredContent` kept the backend's own
string, breaking the invariant the PR states for itself at `:1574-1580`.

The same fallback had a second face: for a schema-bearing tool returning one
plain-text item, `apply_validated_output` overwrote that human-readable text
with a pretty-printed dump of its own wrapper.

Fix: an envelope with nothing extractable has nothing the schema describes, so
`enforce_output_schema` returns it untouched. Not a new judgement — the
projection path next door already refuses this exact case as bug #167, with the
note that "re-wrapping it would clobber a non-JSON `content` text". The schema
path now agrees with its sibling.

The refusal is narrowed to envelopes. A **bare payload** — a result carrying
neither `content` nor `structuredContent` — legitimately reached the fallback
and was validated and coerced in place, and an unconditional early return would
have silently dropped that coercion. `is_mcp_envelope` keys on the same two
fields `apply_validated_output` keys its re-wrap on, so both functions answer
the question the same way.

Tests, written first and failing on the intended assertions:
`block5_an_unextractable_result_is_not_republished_as_structured_content` and
`block5_a_single_non_json_text_item_keeps_its_human_readable_text`. The second
RED is the defect stated in one line:

```
left:  "{\n  \"content\": [\n    {\n      \"text\": \"no such issue\", …
right: "no such issue"
```

Ownership nuance from the source report, unchanged by this repair: the three
functions involved produce zero changed lines in the PR. This is pre-existing
behaviour that the PR's new interim path made reachable.

### BLOCK-3 addendum — the fixing session's own report

Two things it recorded that the verification did not, both worth keeping.

A second test ships alongside the red-to-green one:
`block3_a_governed_meta_tool_still_takes_the_clients_meta`. It has **no RED by
design** — pre-fix it passed too, because `is_exposed` answered true for
everything — and it exists to prove the narrowing did not overshoot and strip
`_meta` from `gateway_invoke` or the admin `gateway_kill_server`. A guard
against the fix, not against the defect. `--lib gateway::router::tests`: 105
passed.

**The finding's severity claim is unverified.** The source report said the
injected field "can shift the continuation digest, so a legitimate continuation
fails its own integrity check". The injection is proven; that consequence was
never traced. The fix stands on the proven half — a backend receiving a field
the client never addressed to it — and the digest claim should not be repeated
as established.

### The tree cannot currently produce a complete clippy run

Both routes die on peer-owned files, neither modified by these fixes:

| invocation | dies on |
|---|---|
| `--all-targets` | `tests/mik_7214_acs.rs` |
| `--lib --tests` | `tests/mik_7215_control4_reap_count_acs.rs` |

So "clippy clean" is not provable for this branch as a whole by anyone right
now, and a claim of it should be read as scoped to a target. For BLOCK-3 the
lib target is proven clean; `router/tests.rs` compiles (105 tests ran) but was
never linted. `cargo fmt --check` returns 0.

## BLOCK-2 — every step of a chain shared one idempotency key

Root cause: `idempotency_key_for` derived its key from the caller's own
`client_key` and the projection/identity suffixes alone. `execute_chain` calls
`invoke_tool` once per step under a single caller context, so all steps of a
chain hashed to the same key. The second step then matched the first step's
cached entry and returned its result — a chain of N tools could answer with the
first tool's output N times.

Fix: `idempotency_key_for` takes a trailing `step: Option<usize>` and appends
`|step:{idx}` **after** `identity_suffix`. Placement is the whole decision. The
alternative — folding the index into the client segment — would have falsified
the length-prefix comment the MIK-7408 fix relies on, because `{len}:{key}` is
reserved for bytes the client supplied. Appending outside that segment keeps the
prefix honest, and a client key that itself contains `|step:1` cannot forge a
step suffix, since its own length prefix still counts its real bytes.

`execute_chain` passes `Some(idx)`; `code_mode_execute` and every single
invocation pass `None`, so a single invocation's key is byte-identical to the
one this branch already shipped and no cached entry is stranded.

`MetaMcpInvoker` implements `ToolInvoker` and cannot take an extra parameter, so
it counts steps itself through an `AtomicUsize`. That is sound because the
invoker is constructed once per playbook run (`invoke.rs:3105`), not shared
across runs.

Tests, written first and failing on the intended assertions:
`block2_two_chain_steps_under_one_client_key_derive_distinct_keys`,
`block2_a_client_key_cannot_forge_a_step_suffix`, and
`block2_a_single_invocation_key_is_unchanged`. The third pins the
no-stranded-entry property to a literal key, so a future change to the suffix
order fails rather than silently re-keying every stored single invocation.

Evidence: `test result: ok. 3 passed; 0 failed` (filter `block2_`, exit 0).
`cargo fmt --check` returns 0. Commit `1e8d6967`.

Scope of that evidence, stated rather than implied. Both runs were measured in
a shared worktree that also carries another session's uncommitted BLOCK-1 work,
so the tree tested is not the tree committed. The committed revision was checked
for the one way that could matter — neither `mod.rs` nor `tests.rs` at
`1e8d6967` references `promote_interim_envelope`, the symbol whose hunks were
deliberately left out of the split — so the green transfers to the commit.

Branch-wide `cargo clippy --all-targets -- -D warnings` is NOT provable here and
is not claimed. It exits 101 on `tests/mik_7215_control4_reap_count_acs.rs`
(`E0308` at lines 29 and 51), a file introduced whole by commit `09735d32`
("red by signature"): a failing test written before the `reap` return-type
change it specifies. That is another session's test-first step doing its job,
not a lint regression. It is absent from the base revision and from all seven
files this fix touches, so it is reported, not repaired.

## A local clippy pass over `tests/common/mod.rs` does not mean CI has one

Measured 2026-09-08. `RELEASE-4.0.0-CLOSE-PLAN.md` records the branch clippy red
as three errors in `tests/common/mod.rs`. A clippy run in this worktree no longer
reports them, and it would be easy to read that as the red having been closed. It
has not been. The repair exists only as an uncommitted working-tree edit: the
committed file at `HEAD` carries `#![allow(dead_code)]` alone (line 8), while the
worktree carries `#![allow(dead_code, unused_imports)]` and
`#[allow(clippy::struct_excessive_bools)]` on `Fixture`. CI builds the committed
tree, so `-D warnings` still fails there on exactly the errors the plan names.

Two consequences worth separating. The red is real and still blocks the release
until that edit is committed by whoever owns it — it is another session's file and
not this one's to commit. And any local clippy result read off this worktree is
evidence about the worktree, not about the branch; the same caveat applies to the
green reported above.
