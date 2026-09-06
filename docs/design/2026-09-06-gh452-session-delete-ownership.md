<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# GH452: apply session ownership to legacy DELETE

Status: design/test-plan, separate tests-as-tests and final code reviews returned
SHIP from both vendors. The repair passes all eleven focused acceptance tests,
fourteen existing streaming regressions and the independent seven-criterion
endpoint drive. Changed functions have 56/56 source regions covered; critical
mutation score is 10/11 (90.9%). CI/integration/release gates remain pending;
this component evidence does not constitute a published release.
Tracking: [GitHub #452](https://github.com/MikkoParkkola/mcp-gateway/issues/452).
Release criterion: `GH452.SESSION.1`; the detailed clauses below expand this
aggregate and preserve the original GitHub issue's acceptance mapping.

## Isolated delivery checkpoint — 2026-09-07

[Machine-readable delivery evidence](../release/gh452-session-ownership-evidence.json)
records source bindings, commands, review provenance and remaining gates.

The original two-file runtime patch was extracted into
`codex/v4-session-owner-increment`, based on
`0d4df3c0bd4e3b3ca5afa3f2d63bdb3261b118cf`. Both runtime files are byte-identical
to their approved code-review inputs. A fresh isolated build passes all eleven
acceptance cases and fourteen existing streaming/ownership controls. The test
fixture now initializes `Config.auth` directly to satisfy Clippy; the existing
assertions and configured values are unchanged. All-feature/all-target Clippy
with warnings denied passes after that mechanical correction.

Repository formatting also exposed an existing method-chain layout issue in
`discovery_names`. The formatter-only correction is byte-identical to the
already reviewed configuration increment. The CI selector is likewise the exact
approved integration-branch selector; no job or permission changes are made.
Formatting, actionlint and diff checks pass. The original failed Clippy run is
preserved. Prior runtime reviews, critical coverage, mutation and independent
acceptance evidence remain valid for the unchanged runtime patch.

CI on the eventual PR revision, integration and release closure remain pending.
The integration base's two ORDER.2 failures are a separate prerequisite; they
must be resolved before this increment can pass the complete CI suite.

**FOR:** closing the 4.0 release gap where a caller who knows another caller's
legacy session ID can terminate that session through `DELETE /mcp`.

**OUT:**

- Changing modern protocol version negotiation or adding modern sessions.
- Changing authentication configuration or middleware, principal derivation,
  credential rotation, or GET/POST session creation/resumption policy. The DELETE
  handler's credential requirement on auth-enabled deployments is in scope.
- Redesigning the legacy stream, session expiry, task recovery, or subscriptions.
- Removing the existing public unconditional multiplexer removal API.

## Readiness and current caller proof

The operator approved #452 for 4.0 and then authorized delivery of all release
gaps on 2026-09-06. This supplies the product decision; owner-check placement and
atomic removal are engineering decisions. This is a security/reliability increment
with mandatory tenant isolation, not a new product capability or technology bet.
Value is eliminating successful cross-caller termination while preserving owner
termination; the falsifier below measures that result without inventing a monetary
return. No dependency, storage migration, configuration key, or cryptography is added.

Evidence inspected in the delivery worktree before edits:

| Question | Current source / result | Consequence |
|---|---|---|
| Does this issue still exist? | `gh issue view 452 --json number,title,body,state,url`: OPEN; `src/gateway/router/handlers.rs:346-367` uses `has_session` then unconditional `remove_session` without caller extraction. | This is a live teardown bypass, not duplicate implementation. |
| Is there an owner already? | `ClientSession.owner`, `src/gateway/streaming.rs:45-67`; `get_or_create_session_for`, `:169-215`, checks and stores it under `sessions.write()`. | Reuse the recorded owner; do not infer it from the session ID. |
| Which identity is authoritative? | `session_owner`, `src/gateway/router/handlers.rs:132-147`, uses the validated credential principal, with an unauthenticated namespace. GET calls it at `:300-306`, legacy POST at `:590-596`. | DELETE must call the same helper. Same display names are not ownership. |
| Is the caller available? | `create_router`, `src/gateway/router/mod.rs:229-260`, registers DELETE on `/mcp` inside `auth_middleware`; validated API keys receive `principal_of(key)` in `src/gateway/auth.rs:220-235`. | Extract the existing optional `AuthenticatedClient` extension, matching GET/POST. |
| Can auth-enabled DELETE reach the handler anonymously? | `src/gateway/auth.rs:856-880` validates a presented static credential on a public route, but otherwise inserts an unauthenticated `public` client with an empty principal and continues. | The handler must require an authenticated, nonempty principal whenever auth is enabled, including a public `/mcp`. |
| What currently calls unconditional removal? | Scoped `rg` finds the DELETE handler and the existing multiplexer test at `src/gateway/streaming.rs:578`. | Switch the HTTP caller only; preserve the public API for trusted existing consumers. |
| Is there duplicate/in-flight work in these files? | `git diff -- src/gateway/router/handlers.rs src/gateway/streaming.rs` was empty at inspection. The delivery coordinator assigned this increment exclusive ownership of DELETE and owner-aware removal. | Do not modify unrelated handlers or other agents' files; recheck the narrow diff before source edits. |
| Can GitNexus prove the graph? | Query and upstream impact for `mcp_delete_handler` and `remove_session` returned `Repository "mcp-gateway" not found. Available: hebb`. | Graph analysis is unavailable, not a zero-risk result. The static route/middleware/caller trace above is the fallback; no index mutation in a shared tree. |

The inspected impact is the authenticated legacy DELETE route and its shared
multiplexer; existing GET/POST ownership must remain unchanged. Security impact is
material, though the implementation surface is small. The HTTP handler already
exceeds the repository's 800-line guideline (1,644 lines); this increment changes
only its existing function and does not undertake a router split. `streaming.rs`
is 788 lines before this increment; if the new operation crosses 800 lines,
extract the existing inline session-ownership tests unchanged to a sibling test
module during implementation. New acceptance tests use the dedicated integration
file. This is focused test organization, not a broader streaming refactor.
The coordinator owns review receipts, tracker metadata and final delivery gates.

## Chosen behavior

Add a crate-visible `NotificationMultiplexer::remove_session_for` operation taking
a session ID and the resolved owner key. Acquire the sessions write lock once,
use `HashMap::entry` to obtain one occupied entry, compare its stored owner, and
remove only the matching entry while that same guard is held. Return one boolean:
a matching entry was removed, or it was not. Do not expose separate unknown/foreign
states and do not compose a read check with a later
unconditional delete. This serializes deletion against session creation, expiry,
and another deletion without a new lock or an await while holding the guard.

`mcp_delete_handler` extracts the same optional authenticated-client extension used
by GET. Before reading the session ID or looking up a session, if
`state.auth_config.enabled` is true, it requires a client with `authenticated=true`
and a nonempty principal. Otherwise it returns the existing
`bearer_unauthorized_response` (HTTP 401 with the standard bearer challenge),
independent of the supplied session ID. This applies when `/mcp` is configured as
a public path too. It then derives `session_owner` and calls the owner-aware
operation. A successful removal remains HTTP 204. Unknown and foreign IDs both return HTTP 404 with the
same empty body and response headers. Neither refusal changes session state nor
creates a replacement session. After the authentication precondition, missing or
non-text session headers remain HTTP 400; an empty text ID follows the existing
unknown-ID behavior. With authentication
disabled, HTTP sessions share the same existing unauthenticated owner and can
still be deleted. Public anonymous sessions on an auth-enabled deployment remain
usable according to the unchanged GET/POST policy, but cannot be terminated by
anonymous DELETE; existing expiry remains their cleanup path. Valid credentials
on that same public route retain ordinary owner deletion.

Retain the existing successful termination log. Refusals share one message and
must not log a stored owner or validated credential. The existing public
`remove_session` remains a trusted in-process cleanup API and is no longer reached
from HTTP DELETE. The new operation is crate-visible, so there is no added public
library API. No automatic retry or resurrection is introduced.

| Alternative | Reason not selected |
|---|---|
| Check owner via a getter, then call `remove_session` | Ownership and mutation would occur under different lock acquisitions; a replacement entry could be removed after the check. |
| Bind DELETE to display name | Distinct configured credentials may share a name; GET/POST already reject that identity model. |
| Return 403 for foreign IDs and 404 for unknown IDs | Discloses whether a session exists; contradicts issue and release acceptance. |
| Reject all DELETE requests | Avoids the bypass but breaks supported legacy owner termination. |
| Change the public `remove_session` signature | Needlessly breaks library callers for an HTTP authorization repair. |

## Acceptance criteria and discriminating test plan

Tests live in `tests/gh452_session_owner.rs`, following the real `create_router`
and `AppState` fixture used in `tests/nfr_sec1_controls.rs`. Configure actual test
API keys and pass them through authentication middleware. Obtain IDs through
legacy GET/POST requests; do not seed an owner string or fabricate an authenticated
extension. Use the legacy protocol version explicitly so the modern stateless
path cannot make an ownership assertion vacuously pass. Do not depend on live
backends, account credentials, or Spark for this increment.

The issue's original `MIK.SESSION.1-4` identifiers map respectively to the foreign,
owner, indistinguishability and router coverage rows below. The release's single
`GH452.SESSION.1` row is the aggregate requirement; `.2-.7` are its detailed cases.

| Stable ID | Given / action / required result | V-model level; type | Discriminating assertion / expected red evidence |
|---|---|---|---|
| `GH452.SESSION.1` | A and B create distinct sessions. B DELETEs A's ID. A's session remains usable, B's remains untouched, DELETE is 404. | Integration; authorization regression | Check original session presence/count before resuming, then POST ping as A with the original ID and verify response ID. Retain A's original SSE response and deliver a tagged notification after refusal to prove the original stream survived, rather than a new session being created with the old ID. Pre-fix DELETE returns 204 and removes A. |
| `GH452.SESSION.2` | A DELETEs its own ID; response is 204, original entry disappears, a second DELETE is 404, B still works. | Integration; positive lifecycle/control | Assert both HTTP status and absence before any request that might recreate an entry; stream delivery to the removed ID fails. Prevents a deny-all implementation from passing. |
| `GH452.SESSION.3` | B DELETEs a never-created ID and A's live ID. | Integration; privacy/negative | Compare 404 status, empty bodies and response headers; verify neither request changes count or the live entry. Pre-fix status differs. Compare semantic response metadata, excluding any generic per-request trace header if added independently. |
| `GH452.SESSION.4` | Missing and non-text session header, auth disabled owner session, and missing credentials with auth enabled. | Integration; boundary/compatibility | After the auth gate has passed, missing/non-text ID is 400 and empty text ID is 404. Auth-disabled anonymous owner DELETE is 204, never 401; unauthenticated requests with auth enabled are refused before session lookup. These controls prevent replacing the targeted fix with a blanket refusal or bypass. |
| `GH452.SESSION.5` | Two valid API keys share the same configured display name and have distinct secrets; one tries to delete the other's session. | Integration; identity collision regression | Through real auth and DELETE, assert 404 and original stream/session survival. A display-name-only owner mutant would incorrectly return 204. Include the name `anonymous` to cover the reserved-label namespace. |
| `GH452.SESSION.6` | Two owner DELETE requests contend for one entry; foreign callers also attempt removal. | Integration plus source review; concurrency/lifecycle | Exactly one owner request returns 204, later requests are 404, foreign calls never remove it, and unrelated sessions survive. The interleaving test supplements rather than proves atomicity: review confirms a single write guard and occupied entry cover lookup, comparison and removal with no unlock/await. |
| `GH452.SESSION.7` | Auth is enabled and `/mcp` is an actual configured public path. Anonymous callers create sessions through the real router, then issue DELETE for a known public session and an unknown ID. A valid credential tries deleting that public anonymous session and also creates and deletes its own session on that public path. | Integration; public-route bypass regression | Both anonymous DELETEs receive identical 401 bearer-challenge responses and leave original streams and counts intact. A valid authenticated nonowner DELETE of the public session is 404 and preserves both original streams; valid authenticated owner DELETE remains 204. Include a request with no ID and with an invalid credential to prove refusal occurs before lookup and that a presented-but-unvalidated credential cannot bypass it. Pre-fix known public session deletion returns 204. |

## Contract event and review receipt, 2026-09-06

The first review found a missing authorization precondition: an auth-enabled
deployment can expose `/mcp` as public, and its anonymous sessions share the
`unauthenticated:public` owner. Comparing owners alone would continue to permit
cross-caller teardown in that configuration. Verified against
`src/gateway/auth.rs:856-880`; disposition: **fix it in this change**. The scope
now explicitly includes a DELETE-only credential gate when authentication is
enabled, while auth-disabled deployments retain their shared-owner compatibility.
This changes the first draft's public anonymous DELETE contract and adds
`GH452.SESSION.7`; design and test-plan confirmation are required before tests.
No authentication middleware behavior or GET/POST contract is changed.

The coordinator reports the following receipts as SHIP-WITH-FIXES on the same
original material:

- GPT: `gpt-20260906T125419Z-64997`, evidence at
  `/Users/mikko/.claude/data/reviews/runs/gpt-20260906T125419Z-64997.md`.
- Grok: `grok-20260906T125419Z-64996`, evidence at
  `/Users/mikko/.claude/data/reviews/runs/grok-20260906T125419Z-64996.md`.

Both found the public-route gap; `src/commands/mod.rs:176-180` confirms that the
init template lists `/mcp` publicly. Disposition for both findings: **fix it in
this change** with the credential precondition and `.7` route cases. The chosen
401 challenge applies to every request without a validated principal, whether
its ID is known, unknown or absent; it reveals no session existence. Authenticated
foreign and unknown IDs remain identical 404s. The coordinator confirmed this
contract after considering Grok's suggested anonymous 404. Current middleware
does validate a presented static key before public fallback
(`src/gateway/auth.rs:856-863`), so the public valid-key positive control remains.

GPT's occupied-entry improvement is incorporated. Grok's same-thread atomicity
test suggestion is disposed as an **observation**: a synchronous function with no
injected pause cannot be forced to interleave by running it on one thread. The
plan retains real competing requests plus source review of the single write
guard, and does not claim a scheduler-dependent test proves atomicity. No new
test-only production synchronization hook is warranted for this small operation.
At the first-review stage these findings were addressed in the proposed design
but not yet independently confirmed or implemented; subsequent confirmation is
recorded below. Review prose alone does not establish acceptance.

Confirmation receipts reported by the coordinator: GPT
`gpt-20260906T130728Z-98459` and Grok `grok-20260906T130729Z-98458`, both SHIP with
successful process exits. Both reviewed material SHA-256
`5de39d7d1ceab1bf1749971626438c2f351ce0660a158233a14cb965c765d1fa` (49,074 bytes).
Evidence files are under `/Users/mikko/.claude/data/reviews/runs/` with those names
and `.md` suffixes. Grok's requested wording clarifications are incorporated:
`.4`'s status matrix follows the auth gate, auth-disabled callers do not receive
401, and file size may require focused extraction of existing tests.

GitNexus is now available as `mcp-gateway-v4-delivery`. Upstream impact for
`mcp_delete_handler` returned LOW with zero graph callers on 2026-09-06; this does
not supersede the static `/mcp` route registration proof because that Rust route
edge is absent from the graph. No behavior edit is authorized by this test stage.

## Tests-as-tests review and red evidence

The coordinator ran `cargo test --all-features --test gh452_session_owner --jobs 6
-- --nocapture` on Spark before any production repair. Compilation succeeded;
exit 101 reported five passing controls and five assertion failures. The failing
cases observed cross-owner 204 versus required 404, foreign versus unknown
response differences, same-name credential confusion, foreign termination among
competing requests, and anonymous public 404 versus required 401. This is intended
pre-fix evidence, not release acceptance. Exact log:
`/Users/mikko/Documents/Codex/2026-09-06/mcp-gateway-v4-scope-review/gh452-red.log`.

The separate test review used run ID `mcp-v4-session-tests-20260906-r1`. Both
authoritative ledger rows and actual wrapper exits were checked: process status
`ok`, exit 0, identical 304,897-byte material with SHA-256
`f78959a99c8befa953907831de461a123583517c5ca0e5ee5f3f648d659edf0a`.
Receipts: GPT `gpt-20260906T133105Z-54875` (SHIP-WITH-FIXES), Grok
`grok-20260906T133105Z-54870` (SHIP); full outputs are in
`/Users/mikko/.claude/data/reviews/runs/` with `.md` suffixes.

| Review finding or improvement | Source check and disposition |
|---|---|
| Valid credential deleting someone else's public anonymous session is not covered (GPT finding; Grok improvement). | **Fix it in this change.** Public fallback has owner `unauthenticated:public`; validated credentials have their own owner. Add `gh452_session_7_public_session_rejects_authenticated_nonowner`, asserting 404, both original streams survive, and the credential holder's ping succeeds. `.7` now explicitly names this case. |
| SESSION.5 should prove Bob's stream and calls after Alice deletes her own session (Grok). | **Fix it in this change.** Replace presence-only evidence with tagged delivery through Bob's original stream, successful ping, and unchanged remaining count. |
| Cross-product both creation routes with every owner/foreign test (GPT). | **Observation.** Current `.1` drives GET creation plus foreign refusal; `.2` drives POST creation, GET resumption and owner deletion with the same ID. Both creation branches use the same `session_owner` helper. The existing coverage is retained; no complete cross-product is claimed. |
| Compare only status/challenge/body rather than the whole header map (both). | **Observation.** The recorded responses contain stable `content-length` headers and no per-request trace header. Keep the stronger comparison so an added session-existence header cannot silently escape the assertion. If a generic per-request header is introduced, exclude only that named non-semantic header, as the plan already permits. |
| Remove Bob's in-race 404 assertion (Grok). | **Observation.** Bob must receive 404 whether his request precedes or follows owner deletion. The invariant does not depend on winning a race; the test still makes no claim to prove atomicity. Retain it alongside deterministic `.1`. |
| Share the state constructor with `nfr_sec1_controls.rs` (Grok). | **Observation.** That constructor is private to another test binary and configures a modern-protocol fixture. There is no reusable public fixture today. This increment follows the established `AppState` pattern; extracting a shared constructor would change another test suite and is not necessary to close the authorization gap. |

The repaired file contains eleven tests; its source has been formatted and its
diff checked. The coordinator's second Spark run compiled and exited 101 with
six passes and five assertion failures, including the new authenticated nonowner
of a public session (actual 204, required 404). Exact evidence:
`/Users/mikko/Documents/Codex/2026-09-06/mcp-gateway-v4-scope-review/gh452-red-r2.log`.
The contention case passed this run and failed the first, which confirms its
classification as a concurrency regression/control, not a deterministic pre-fix
falsifier or proof of atomicity. The owner-check and public-identity cases provide
the deterministic reds. Focused confirmation reviewed these repaired tests.
GitNexus does not yet index the new test symbol; the required impact query
for the `.5` test returned UNKNOWN/not found. Static scope is that test alone and
the new `.7` case; no production source has changed.

Focused confirmation used `mcp-v4-session-tests-20260906-r2`. Authoritative GPT
`gpt-20260906T134554Z-91005` and Grok `grok-20260906T134554Z-91000` rows both say
SHIP, both process statuses are `ok`, and both actual wrapper exits are 0. The
exact submitted material is 107,360 bytes, SHA-256
`144eaa8ba1339e7e535ebcaa4e6ed0b645e1246f92201f6d64b652f6abe1d1b7`.
The current test-file hash was checked against that frozen material after both
reviews returned. Complete receipts are under
`/Users/mikko/.claude/data/reviews/runs/` with the named `.md` files.

Neither confirmation returned a blocking finding. The remaining suggestions are
recorded as observations: direct unit cases for the future removal helper repeat
the matching/foreign/unknown branches already reached by the route tests; shared
fixture extraction has the disposition above. A full public-path response
comparison and anonymous POST ping would broaden the matrix; `.3` already checks
the shared DELETE response producer's privacy semantics, and `.7` directly proves
the public original stream survives. The auth layer resolves identity before the
same handler, and both legacy GET/POST use `session_owner`. No full cross-product
of middleware configuration and operation is claimed. These suggestions do not
change the approved acceptance contract or justify another test-review round.

## Sequence and validation

1. Coordinator obtains design and test-plan reviews before any test/source edit.
2. Write the router tests; run `cargo test --test gh452_session_owner`. Record the
   foreign-delete and privacy assertions failing against unchanged production
   code. A compiler failure or a refusal from unrelated middleware is not the
   required red evidence. Coordinator schedules the shared Rust build.
3. Obtain the separate tests-as-tests review, then implement the narrow fix and
   rerun that same command. Every case must pass, with no ignored/flaky tests.
4. Run the existing `gateway::streaming` and session/router regression tests,
   formatting, targeted Clippy and the coordinator's release gates. Review the
   changed diff for one production caller and no credential-bearing logs.
5. Measure changed-line coverage and mutation for this critical authorization
   branch (target 100% changed-line coverage and at least 85% mutation score).
   Explicitly falsify unconditional deletion, deny-all, display-name ownership,
   and foreign/unknown response distinction; record surviving mutants as gaps.
6. A fresh non-author driver uses a binary built from the reviewed revision and
   exercises the endpoint's owner/foreign/unknown cases. Coordinator records the
   revision, AC results, dual code review, CI, deployment and rollback evidence;
   tests alone do not close #452.

No unresolved product decision blocks this design. Incomplete Rust route edges
in the available graph remain a tooling limitation; static impact and real-route tests are required
compensating evidence. Build availability and independent review are execution
gates owned by the delivery coordinator; if either fails, this increment remains
unaccepted. Rollback is the previous reviewed binary/config with no data migration,
but rolling back restores the known teardown bypass and must be recorded as such.

## Local implementation handoff

The coordinator authorized production implementation after the test-review gates
closed. `mcp_delete_handler` now extracts the existing authenticated client,
requires a validated principal when auth is enabled before inspecting the session
header, derives the unchanged `session_owner`, and calls
`NotificationMultiplexer::remove_session_for`. The new crate-visible operation
uses one occupied map entry under one write guard; foreign and absent entries
return the same false result. Only these two production symbols changed. No
response-finalizer, authentication middleware or legacy creation path changed.

Pre-edit GitNexus checks for the handler and multiplexer impl both returned LOW;
the initially ambiguous impl/struct target was resolved with the explicit impl
UID. Static checks supplement the missing Rust route edge and confirm the real
`/mcp` DELETE registration reaches this operation. `streaming.rs` is exactly 800
lines after normal formatting, so no test extraction was needed.

Local `rustfmt --edition 2024 --check` for the two source files and acceptance test
passes; `git diff --check` passes. The inspected diff is 18 added / 3 removed lines
in the DELETE handler and 12 added lines in the multiplexer. Static AC checks
confirm `.7`'s credential gate precedes header lookup, `.1`'s shared owner reaches
the new removal operation, and `.6`'s lookup/comparison/removal hold the same guard
without an await. These source checks do not replace runtime acceptance.

The synchronized Spark green run passed all eleven cases under
`cargo test --all-features --test gh452_session_owner --jobs 6 -- --nocapture`.
The fourteen existing owner, streaming and reaper regressions also passed under
`cargo test --all-features --lib gateway::streaming --jobs 6 -- --nocapture`.
Logs are `mcp-gateway-v4-gh452-green.log` and
`mcp-gateway-v4-gh452-streaming-green.log` under
`/Users/mikko/Documents/Codex/2026-09-06/mcp-gateway-v4-scope-review/`.
Read-only SHA-256 checks confirmed both modified source files and the acceptance
test on Spark match the local review input. The real-route failures recorded
before implementation now pass, including the public-session nonowner case.

Self-QA inspected the final diff, checked formatting/wiring and read both runtime
logs. The improvement pass retained the existing owner/auth response helpers and
single occupied entry; no duplicate owner store, getter/check/remove sequence,
extra public API, or test-only synchronization hook was introduced. No further
behavior change was necessary after green.

### Final code reviews and dispositions

Final code review run `mcp-v4-session-code-20260906-r1` returned SHIP from both
vendors. Authoritative receipts are `gpt-20260906T141238Z-56965` and
`grok-20260906T141238Z-56960` under
`/Users/mikko/.claude/data/reviews/runs/`, with `.md` suffixes. Both ledger rows
have process status `ok`, both actual wrapper exits are 0, and their material
SHA-256 and byte count match:
`a17a0e734df4de71159ca47cff63d88b7e7d3eeecf1fc9294fabc636e9362c1c`,
193,501 bytes. The frozen packet, manifest and process receipts are
`gh452-code-review-r1.*` in the local scope-review evidence directory.

Neither code review returned a blocking finding. Their optional improvements
have these dispositions:

| Suggestion | Disposition |
|---|---|
| Avoid the owned-key allocation by borrowed lookup followed by removal under the same write guard (both). | **Observation.** The accepted design chose one occupied entry for an explicit atomic compare-and-remove. The current bounded allocation has no measured regression; retain the reviewed implementation rather than change it solely for an unmeasured micro-optimization. A future measured optimization must retain the same guard throughout. |
| Derive the credential gate from `session_owner_key` (Grok). | **Observation.** Both predicates currently require authenticated and nonempty principal, which source review confirms. Calling the string-producing helper would allocate an owner key just to test its emptiness, before producing the actual legacy owner again. This increment preserves both existing helpers and explicitly tests the public anonymous boundary. |
| Replace the side-effecting match guard with an explicit if/else (Grok). | **Observation.** The guard calls the atomic operation exactly once; the remaining arms only choose 404 or 400. Current code follows the existing handler structure. No ambiguity or failing behavior warrants another production change. |

### Mutation evidence

The first copied-tree mutation attempt failed during its unmutated baseline:
Spark's `/tmp` tmpfs ran out of space. Cargo exited 101 and cargo-mutants exited
4; **no mutants were tested and no score is attributed to that attempt**. It also
revealed that trailing libtest arguments did not select the baseline build
target. The retry set a task-specific `TMPDIR` on the spacious `/home` disk and
passed target selection to every Cargo invocation. The failed scratch directory
was automatically removed by cargo-mutants; its full logs remain preserved.

The retry command was:

```text
TMPDIR=/home/mikko/codex/mcp-gateway-v4-gh452-mutation-r2/tmp cargo mutants --all-features --file src/gateway/router/handlers.rs --file src/gateway/streaming.rs --re 'mcp_delete_handler|remove_session_for' --jobs 1 --jobserver-tasks 6 --copy-target true --output /home/mikko/codex/mcp-gateway-v4-gh452-mutation-r2 --cargo-arg=--test --cargo-arg=gh452_session_owner
```

With cargo-mutants 27.1.0, the unmutated baseline passed and all eleven mutants
completed: **10 caught, 1 missed, 0 unviable, 0 timeout**. The raw score is
**10/11 = 90.9%**, exceeding the planned 85% threshold without excluding the
survivor. The actual cargo-mutants exit is **2**, because a mutant survived; it is
not reported as a zero-exit run. Baseline build and run arguments both selected
only `gh452_session_owner`, so unrelated in-progress lib tests were excluded.

The survivor changes the inner `authenticated && !principal.is_empty()` to `||`
at `handlers.rs:358`. A source scan of every production `AuthenticatedClient`
constructor found only true/nonempty or false/empty states: validated static
credentials in `gateway/auth.rs:207,222`, dashboard identity at `:735`, temporary
and delegated tokens in `key_server/mod.rs:96,152`, and anonymous/public fallback
at `gateway/auth.rs:797,867`. Credential principals use a nonempty digest.
Consequently that mutant is equivalent for the current production-reachable
identity states. This is a bounded invariant argument, not a claim that arbitrary
fabricated extensions are equivalent. Retain the survivor in the denominator and
retain the defensive conjunction in production; no artificial client fixture was
added to inflate the score. The ten caught mutations cover unconditional success,
deny-all, bypassed/reversed owner comparison, incorrect outer auth gating, removed
negations and bypassed/reversed removal result handling.

Complete logs, per-mutant diffs, `mutants.json`, `outcomes.json` and actual process
receipts are preserved outside the repository in:

- `/Users/mikko/Documents/Codex/2026-09-06/mcp-gateway-v4-scope-review/gh452-mutation-r1-infrastructure-failure/`
- `/Users/mikko/Documents/Codex/2026-09-06/mcp-gateway-v4-scope-review/gh452-mutation-r2/`

### Coverage, independent functional drive and remaining release gates

The coordinator installed and verified cargo-llvm-cov 0.9.0 on Spark and ran
`cargo llvm-cov --all-features --test gh452_session_owner --jobs 4 --json`.
Both changed functions have all 56 source regions covered (56/56, 100%),
excluding dependency tracing-macro regions. This is source-region coverage,
not a branch-coverage claim. Exact summary is `gh452-critical-coverage-summary.json`,
with full JSON and log alongside it in the local scope-review evidence directory.
The coordinator supplied a separate AC-only brief and an immutable binary to a
fresh non-author driver; the author did not launch or exercise that service.
Binary SHA-256 was independently checked and matched:
`6d128266e994d460cc5cec8d0c7d141bf93f034e04ee65f423061b667a826530`.
The brief is `gh452-functional-driver-brief.md` in the local scope-review evidence
directory and supplies every `GH452.SESSION.*` criterion without implementation
or author-test material.

The first independent-driver attempt failed at environment setup before any AC
execution because of its nested sandbox. It supplies no functional pass. The
corrected isolated run `20260906T145616Z-independent-r2` completed **7 PASS,
0 FAIL, 0 INVESTIGATE**, with no skipped criteria. The author inspected its final
report, machine-readable outcomes and cleanup verification. It drove authenticated,
auth-disabled and public-MCP instances through actual HTTP, retained original SSE
streams, and exercised missing/non-text/empty session headers, credential-identity
separation, foreign/unknown equivalence and an observed concurrent delete schedule.

Every required retained stream produced new keep-alive bytes within 1.2 seconds;
owner teardown reached EOF within 0.05 seconds (6-second observation limit).
Foreign and unknown response metadata matched with only Date normalized. The
concurrency result covers one observed barrier-released schedule, not every
interleaving. Initial raw requests that half-closed the socket produced no HTTP
response; those inconclusive artifacts remain retained, and corrected requests
established the reported 400/404 results. No inconclusive request is counted as a
pass. The intentionally retained public stream kept graceful shutdown draining;
only that recorded driver PID required forced cleanup after the acceptance checks.
Final verification found all driver PIDs absent and all temporary ports bindable.

Local driver evidence is under
`gh452-independent-driver-r2/gh452-functional-evidence-20260906T145616Z/` in the
scope-review directory: `report.md`, `outcomes.json`, `facts.json`, raw request and
stream artifacts, and `cleanup-verification.json`. The concise final result is
`gh452-independent-driver-r2/result.md`. Remote originals remain at
`/home/mikko/codex/mcp-gateway-v4-gh452-functional/driver/20260906T145616Z-independent-r2`.

Full Clippy, dependency/security scanning, integrated CI and deployment acceptance
remain release gates owned by the delivery coordinator. This local implementation
is uncommitted and has not been published or deployed; passing this increment's
focused gates does not establish release completion.
