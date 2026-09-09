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
| BLOCK-1 | implemented, unverified locally | `promote_interim_envelope` (`src/gateway/meta_mcp/mod.rs:1933`) is no longer a no-op. It promotes `resultType`, `inputRequests` and `requestState` onto the JSON-RPC result for `gateway_invoke` and `gateway_execute` when `resultType` is `input_required`, and returns early otherwise. Written to the four tests that specify it (`tests.rs:5842-5915`): the two failing CI cases plus `block_1_promotion_leaves_a_completed_call_alone` and `block_1_promotion_ignores_tools_that_cannot_produce_a_round`, which together pin the tool-name scope that was previously called an open design question. The two-name set matches the existing idiom at `mod.rs:1589`. The disk floor (MIK-4777, 5 GB) that previously blocked cargo no longer binds; the tree has 36.9 GB free as of 2026-09-09, and the remaining wait is the shared build lock. `mod.rs` also carries a concurrent session's extract-function refactor of `destructive_confirmation_gate` into `redeem_carried_confirmation` and `unconfirmable_refusal`, so any commit of this file publishes that too. |
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

## Three tests cited by ORDER.2a's MET verdict are in an undeclared module

Measured 2026-09-09. `src/gateway/meta_mcp/order2_fsm_tests.rs` is staged as a new
file (`A` in `git status`) and is declared by no module file. `mod.rs`'s module
block lists `invoke`, `policy_epoch_tests`, `prompt_cache`, `protocol`,
`resources`, `search`, `spec_preview`, `support` and `surfaced`; `order2_fsm_tests`
is not among them and appears nowhere else in the crate. The file is therefore not
part of the build: its contents never compile and its tests never run.

The MIK-7272.ORDER.2a row in `RELEASE-4.0.0-criteria-status.md:215` is `MET`, and
its evidence names three cases in that file —
`missing_and_empty_keys_are_explicitly_refused` (`:51`),
`old_empty_key_state_cannot_influence_any_discovery_reader` (`:70`) and
`nonempty_legacy_and_stdio_keys_retain_isolated_state_changes` (`:86`). None of the
three has ever executed. A file-and-line citation reads as proof that a case ran;
here it only proves the text exists on disk.

The rest of the row's evidence does execute and was checked separately:
`src/gateway/router/tests/order2_fsm.rs` is declared at
`src/gateway/router/tests.rs:35`, and `src/gateway/server/tests/order2_fsm.rs` at
`src/gateway/server/mod.rs:2285`. Both are inside the build. So ORDER.2a is not
unsupported — it is supported by fewer cases than it claims, and the refusal path
and the contaminated-old-state path are among the ones with no live coverage.

This is the second instance of the same defect on this branch. `direct_route.rs`
sat on disk outside the crate the same way while `backend_handlers.rs:781` called
into it; that one surfaced as a build error only because production code depended
on it. A test module fails silently instead, which is why it survived a MET
verdict. Before a criterion's evidence is read as executed, the file it names has
to be traceable to a `mod` declaration.

### Fixed — the three cases now compile and run

The declaration belongs in `tests.rs`, not `mod.rs`. Declaring it as a sibling in
`mod.rs` compiles the file but fails it 18 times: the cases call
`assert_membership` and read `STAGED_DEFAULT_TOOLS`
(`src/gateway/meta_mcp/tests.rs:4944`), which are private to the `tests` module and
unreachable from a sibling. The file was written as a child of `tests` — its own
`pub(super) fn assert_refusal` is scoped for that parent — so the fix is
`#[path = "order2_fsm_tests.rs"] mod order2_fsm;` in `tests.rs`
(`src/gateway/meta_mcp/tests.rs:17`). The path is not `../order2_fsm_tests.rs`:
`tests.rs` is itself loaded through a `#[path]` attribute, so a nested `#[path]`
resolves against `src/gateway/meta_mcp/` rather than a `tests/` subdirectory.

A second declaration of the same file under a different module name compiles and
is not a name collision — it includes the file twice and runs every case twice
under two module paths. One include per file.

`cargo test --lib order2_fsm`, exit status 0: 5 passed, 0 failed, each case once
— the router and server cases the row also cites, plus the three that had never
run:
`missing_and_empty_keys_are_explicitly_refused`,
`old_empty_key_state_cannot_influence_any_discovery_reader` and
`nonempty_legacy_and_stdio_keys_retain_isolated_state_changes`. ORDER.2a's evidence
now matches what executes.

Two intermediate runs of this fix reported success while the crate did not compile.
Piping cargo into `tail` reports the pipe's exit status, so `[exited with code 0]`
accompanied `could not compile ... due to 18 previous errors`. Redirect to a file
and read `$?` when the exit status is the thing being trusted.

## The two `Era` enums do not meet, and merging them would add a defect

Measured 2026-09-09. The premise that `protocol::meta::Era` and
`protocol::era::Era` meet in `src/gateway/router/handlers.rs` does not hold.
`handlers.rs` names only `meta::Era` (`:827`, `:1462`, `:1467`, `:1590`, `:1595`);
its two `protocol::era::` references are the error-code constants
`UNSUPPORTED_PROTOCOL_VERSION` (`:287`) and `MISSING_REQUIRED_CLIENT_CAPABILITY`
(`:992`), not the enum.

The two answer different questions and their consumer sets are disjoint. `meta::Era`
(`src/protocol/meta.rs:106`) is what one inbound request declared, derived from
`RequestShape::era` and never computed independently; its consumers are the gateway
inbound path — `router/handlers.rs`, `meta_mcp/*`, `server/mod.rs`. `era::Era`
(`src/protocol/era.rs:25`) is what a backend peer speaks, established by probing and
carried with `EraEvidence` and `EraSource`; its consumers are `backend/lifecycle.rs`,
`backend/mod.rs` and `transport/http/mod.rs`. No file in `src/` names both, and no
`From` impl or function converts between them.

Unifying them would give the inbound path a type that also carries probe-derived
backend state, which is the second era predicate the doc comment at
`src/protocol/meta.rs:104` exists to forbid. Closed as no change required.

## `ConfirmationPolicy::for_modern()` is built on every modern call and discarded

Measured 2026-09-09. `src/gateway/router/handlers.rs:1378` selects a
`confirmation_policy`, taking `for_modern()` when `is_modern` and `for_legacy()`
otherwise. That value reaches exactly one consumer, at `:1449`, inside the
`Era::Legacy` arm of the `confirmation` match. The `Era::Modern` arm at `:1441`
builds `ConfirmationChannel::InBand` and never reads it.

`is_modern` is not an independent input: `handlers.rs:826-827` derives it as
`era == Era::Modern` from the same `shape.era()` the match switches on. The two
cannot disagree, so the `Elicit` arm is reached only when `era` is `Legacy`, which
is exactly when `confirmation_policy` holds `for_legacy()`. The `for_modern()`
branch therefore has no consumer on any path: its value is constructed and
dropped on every modern destructive call.

`for_modern()` has one call site in the crate (`rg 'for_modern\(\)' src/`,
2026-09-09): that one. Stdio does not consult it and says so —
`src/gateway/server/mod.rs:2711-2716` records that stdio refuses unconditionally
because no asker can exist, rather than by asking about the revision.

Nothing computes a wrong answer today, so this is not a correctness defect. What
it costs is read: the module doc at `src/gateway/destructive_confirmation.rs:31`
introduces `for_modern()` as the policy for modern requests and states that it is
`REFUSE`, which invites the conclusion that a modern HTTP destructive call is
refused. CONFIRM.2 replaced that behaviour with the in-band ask, and the constant
was left standing. A future reader reconciling the doc against the wire will find
they disagree.

Left unpatched deliberately. Deleting the branch, deleting the constant, or
rewriting the doc are three different decisions about what the modern policy is
supposed to mean, and that belongs with CONFIRM.2's owner rather than in a
blocker-fix pass.

## The tasks extension's TTL and admission rules are designed and unbuilt

Measured 2026-09-09. `docs/design/2026-08-31-task-1-tasks-extension.md` settles four
requirements about task lifetime, three in §3 and one in the amendment §10.3 closed
on 2026-09-06:

- a finite default TTL and a global cap, because `ttlMs: null` with no admission
  bound lets a caller hold memory indefinitely (§3, `:118`);
- a cap that counts every **unreaped** record rather than active ones, because a
  terminal record is retained until its TTL expires and a flood of fast-finishing
  tasks exhausts memory while an active-only counter reads zero (`:927`);
- a reap that is a single store-level compare-and-delete against the record's
  **current** `ttlMs`, never a read followed by an unconditional delete (§3,
  `:103-104`, `:159`);
- `ttlMs` and `pollIntervalMs` both mutable over a task's life, one rule for both,
  because a reaper pinning the TTL it read at creation reaps a task the server has
  since extended (§10.3 amendment, `:126`, `:676-677`).

None of the four exists in the code. `rg 'ttl' src/protocol/task_store.rs
src/protocol/tasks.rs` (2026-09-09) matches only two prose comments about settled
tasks; there is no TTL field, no cap, and no function named for reaping, sweeping,
expiring or pruning. The design records the same absence itself at `:140`.

`Task` at `src/protocol/tasks.rs` also still carries neither `createdAt` nor
`lastUpdatedAt` (design `:57`), which the reap would need to compute an expiry
against.

Recorded here because this file is the one this pass owns. The row belongs in
`RELEASE-4.0.0-gap-plan.md` under the tasks-extension work, and needs its acceptance
criteria written against the four bullets above rather than against "TTL is
implemented" — a default TTL with a read-then-delete reap satisfies the sentence and
not the requirement.

### Swept for the same defect: `order2_fsm_tests.rs` is the only one

Every `.rs` file this branch adds under `src/` was checked against a `mod <name>;`
declaration somewhere in the tree (2026-09-09, 29 files). All are declared except
`src/gateway/meta_mcp/order2_fsm_tests.rs`. The files directly under `tests/` are
not part of this check and need no declaration: cargo discovers each as its own
integration target, and `tests/common/mod.rs` is pulled in by `mod common;` inside
the targets that use it.
