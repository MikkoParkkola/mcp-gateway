<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# MIK-6744.STORE.2 — the three tests the re-grade specified

Design for the test work that moves `STORE.2` off PARTIAL. Input is
`docs/internal/requirements/scope-grading-2026-09-16-store-2.md`, whose review section
left the criterion needing three specified tests rather than one.

**Scope.** Three new tests, plus one oracle tightened in place. Test-only: no production
change is planned, and none is expected. Explicitly out of scope — if a new test goes red,
the fix is a separate ticket, not a widening of this one; the `gating-2026-09-20c`
gate-design observation; anything in `NFR.WORKLOAD.1`.

## Where the criterion stands

| Conjunct | State | Test |
|---|---|---|
| 1. Revoke during refresh | covered | `fence_tests.rs:105` |
| 2. Restart during token replacement | covered at one boundary, loose oracle | `crash_tests.rs:144` |
| 3. Old task / cache / connection cannot restore a revoked grant | uncovered | — |
| 4. Re-consent yields a usable new grant | covered | `fence_tests.rs:132` |

## D1 — drive every commit boundary, do not argue an equivalence class

The review offered two ways to close conjunct 2's coverage gap: drive the crash harness at
each named commit point, or record an argument that the manifest move is the sole commit
point and one crash point therefore stands for all of them.

**Decision: drive every boundary.** Three reasons, all from the source rather than from
preference.

There is exactly one `CommitCheckpoint`, so "each named `CommitCheckpoint`" has no plural
to iterate. The real population is `faults::ALL` — nine boundaries in commit order
(`faults.rs:66-76`). `s10` drives boundary 5 of 9. The window the review actually asked
about, *after* the manifest move, is boundary 9 alone — every earlier boundary fires
before its own step, so at boundary 8 the rename has not yet happened.

The array exists for this. Its own comment states the reason: "A case that iterates this
cannot miss a boundary by forgetting to list it" (`faults.rs:64-65`). An equivalence-class
argument is an assertion about the commit path; iterating the array is a proof of it, at
the cost of nine child processes instead of one in a test that already spawns them.

The equivalence class is not uniform, which is the substantive reason. Each
`boundary!(X)` fires *before* step X (`commit.rs:216-223`), so an abort at `ManifestRename`
means the rename has not happened. `ParentSync` is the exception: it fires *after*
`fs::rename` returned and *before* `sync_directory` (`commit.rs:231-241`). That single
boundary is the only one where the post-restart state must be the **new** generation, and
folding it into a class with the other eight would hide exactly the window the review
asked about.

### The oracle, by band

The harness kills a process, not a machine: `reached` calls `std::process::abort()`
(`faults.rs:134`). The kernel's page cache survives that, so a `fs::rename` that already
returned is visible to every later process whether or not the parent directory was
synced. Both bands are therefore deterministic, and neither oracle is a disjunction.

| Band | Boundaries | Required after restart | Never |
|---|---|---|---|
| Pre-replacement | 1-8 (`RecordWrite`..`ManifestRename`) | the prior generation | the uncommitted candidate, an unexplained failure |
| Replacement returned | 9 (`ParentSync`) | the new generation | the prior generation |
| Healthy | no abort | the new generation | anything else |

The unsynced rename at boundary 9 *could* be lost to a power cut, and under that model
either generation would be admissible. This harness does not simulate power loss, so
importing its ambiguity here would only buy a rollback regression a free pass. If a
power-loss model is ever wanted it is a separate harness, not a looser oracle in this one.

## D2 — conjunct 3 names three holders; this module owns one and guards the others

The conjunct names "an old task, cache or connection". Searching `src/personal_accounts/`
for a credential cache finds none: `worker.rs:22-23` states the wrapper "owns no store
logic, no cache and no second single-flight", and the only cache in the module's
vocabulary belongs to the REST account registry, outside it (`mod.rs:586-590`). Writing a
test that drains a cache this module does not own would test a fixture.

What the module does own is the guard in front of that cache. `VaultStrategy::recheck`
runs "before a cache entry may be selected and before anything reaches the wire"
(`vault.rs:180-183`), and `cache_binding` (`vault.rs:144,169`) is what keys the entry. So
the three holders map onto three things that exist here:

| Holder named | What it is here | Boundary that must refuse |
|---|---|---|
| Old task | the in-flight single-flight refresh | its completion cannot land post-revoke |
| Cache | an entry keyed by `cache_binding` | `recheck` refuses before selection; a re-consent changes the binding |
| Connection | a `CredentialLease` taken before the revoke | `custody.release(&lease)` refuses |

The second row is the sharper half of the conjunct: the criterion asks not only that a
stale entry go unused, but that it cannot be revived under the new grant. A binding that
changes across re-consent is what makes that structural rather than incidental, so the
test asserts the binding changed, not merely that a lookup missed.

**What this does not establish, and the grade must say so.** T1 proves the guard refuses.
It does not prove that the REST account registry actually calls the guard before selecting
a cache entry, or that an open connection re-enters it — those consumers live outside this
module and outside this scope. Conjunct 3 is therefore closed at the module boundary only,
and the external-consumer obligation stays open against an integration test. A grade that
reads T1 as closing conjunct 3 outright would overstate it.

The revoke these tests drive is itself off the production call graph. `AccountService::
invalidate` carries `#[cfg_attr(all(not(test), not(kani)), expect(dead_code, …))]`
(`service.rs:318-327`), and an `expect` that compiles without firing is the compiler
certifying no non-test caller reaches it. So T1 and T3 prove the store refuses correctly
when revoked; they do not prove a shipped code path ever calls revoke. That is the same
deferral the attribute already names (MIK-6744/6745/6746) rather than a new gap, but the
grade must state it, because "revocation works" and "revocation is reachable" are
different claims and only the first is under test here.

## The three tests

**T1 — live holders across a revoke and a re-consent** (new, service layer). Call
`prepare` (`vault.rs:113`) twice against the connected generation, keeping the lease and
the returned `cache_binding` from the first. Assert the two bindings are **equal** — a
binding that varies per call is a nonce, and a nonce would satisfy the change-across-
re-consent assertion below without isolating anything. Revoke durably. Assert `recheck`
on the retained pre-revoke lease refuses. Re-consent. Assert: a fresh `prepare` succeeds,
its `cache_binding` differs from the pre-revoke one, and the pre-revoke lease is still
refused.
No in-flight refresh is held across the revoke. `prepare` calls `refresh_if_expired` and
then `release` inline (`vault.rs:138-150`), and refreshes serialize on the per-account
single-flight lock (`service.rs:220,378-382`), so a suspended refresh and a *completed*
`prepare` lease cannot coexist on one account — the composition is unwritable, not merely
awkward. That conjunct is already covered at `service_refresh_tests.rs:102` and `:277`.
*Falsifier:* return `Ok` from `recheck` after a revoke and confirm T1's refusal assertion
goes red.
*Positive control:* every refusal above is asserted to succeed before the revoke, and the
fresh lease is asserted to recheck *successfully* after re-consent, so a permanently
refusing store cannot pass. Release-observer counts
(`CredentialReleaseObserver`, `service.rs:99`) are asserted unchanged across every
refusal, so a credential that is published and only then errored cannot pass either.
*Existing coverage not duplicated:* `service_release_tests.rs:235` already covers lease
retirement and `service_refresh_tests.rs:277` a held refresh completing after a newer
grant. T1's new evidence is the vault binding and the recheck across re-consent.

**T2 — tighten `s10`'s oracle** (in place, `crash_tests.rs:144`). Replace
`observed == answered("connected") || explicit_failure(&observed)` with a requirement for
the prior generation, full stop. The failure arm is not tightened, it is deleted: there is
no candidate-specific recovery error to pin it to — `AccountError` carries six broad
variants and none of them means "an uncommitted candidate was found" (`mod.rs:84-102`) —
and recovery never looks at candidates at all, reading only the record the manifest entry
names (`storage.rs:594-600`). Inventing such an error would be a production change, which
this scope excludes. Under process-abort the outcome is deterministic anyway, so the
disjunction was buying nothing.
*Falsifier:* remove the authority file so startup fails with `StorageUnavailable`, which
the current oracle accepts and a prior-generation-only oracle must reject.

**T3 — every boundary, banded** (new, `crash_tests.rs`). Iterate `faults::ALL`; for each
boundary, drive the child to die there, assert it announced that checkpoint before dying
(the existing `Outcome::Died { checkpoint }` evidence, so a process that merely ended does
not count), restart, and apply the band oracle above. Includes the healthy no-abort row.
The generation is named by **record equality** against the expected `GrantRecord`, not by
a fieldless `GrantRecord { .. }` pattern match (`crash_tests.rs:49`) — a fieldless match
admits any connected record, so band 2 and the healthy row would pass on the wrong one.
*Falsifiers, one per band because no single mutation reaches every row:*
- rows 4-8 — make recovery prefer the newest candidate over the manifest-named record;
  the candidate is only in `store_dir` from boundary 4 onward, so this is the range where
  a selectable wrong answer exists at all;
- row 9 — make recovery fall back to the prior manifest; this is the rollback regression
  the corrected band-2 oracle exists to catch, and the old "either generation" oracle
  would have passed it;
- rows 1-3 — no mutation of recovery can distinguish these, because nothing durable has
  moved: no candidate is selectable, so recovery has no wrong answer available to it.
  The disk is not byte-identical to a commit that never started — `process::abort()`
  skips `persist_record`'s cleanup, so temporary debris survives — but debris the
  manifest does not name is unreadable by recovery, which is why no mutation reaches
  these rows. Their evidence is therefore the band-1 prior-generation oracle plus the
  announcement assertion: a child that dies without naming its boundary fails the row.
  Stated here rather than discovered later, because a row whose oracle cannot fail is
  worth knowing about before it is written.

T2 and T3 overlap at boundary 5. That is deliberate: T2 is the oracle fix that must land
even if T3 is deferred, and T3 subsumes it only once green.

## Sequence

Design reviewed → the three tests written and reviewed as tests → red for the right reason
(each falsifier above run once) → green. The re-grade is amended only after that, and the
amendment cites test bodies, not test names — which is the rule the original grade broke.

## Review

Reviewed before any test code existed, which is the only point at which changing the
oracle costs a paragraph. The first review verified the commit path, the abort mechanism
and the recovery read path at source, and three of its findings changed the design:

- **Band 2 was inverted.** The first draft admitted either generation at `ParentSync` on
  the reasoning that the directory was unsynced. But `reached` calls
  `std::process::abort()` (`faults.rs:134`), which ends a process and leaves the page
  cache intact, so a `fs::rename` that already returned is visible to the next process.
  The new generation is required there, and the draft's disjunction would have passed a
  rollback regression — the single most valuable thing this test can catch.
- **T2's failure branch had no type to pin it to.** `AccountError` has no
  candidate-specific variant (`mod.rs:84-102`) and recovery never enumerates candidates
  (`storage.rs:594-600`). The branch is dropped rather than tightened, which makes the
  oracle a single required value and is strictly stronger than what was asked for.
- **T3's falsifier could not reach every row.** No candidate is selectable before
  `RecordRename` completes, so one mutation cannot redden all eight pre-replacement rows.
  The falsifiers are now per-band, and rows 1-3 are recorded as resting on the
  announcement assertion instead of a recovery mutation.

Two smaller findings are folded in: T1 is specified against the existing lease interfaces
rather than a binding string, and the external cache and connection consumers are recorded
as an obligation this test-only change does not discharge.

A second review, run against the corrected text rather than the draft, found T1 itself
unbuildable and three sharper oracles:

- **T1 could not hold an in-flight refresh and a completed lease at once.** `prepare`
  calls `refresh_if_expired` and then `release` inline (`vault.rs:138-150`), and refreshes
  serialize on the per-account single-flight lock (`service.rs:220,378-382`), so the two
  states are mutually exclusive on one account. T1 drops the refresh — already covered at
  `service_refresh_tests.rs:102` and `:277` — and is driven from `prepare` / `recheck` /
  binding / re-consent alone.
- **A changing binding was not enough.** Asserting only that `cache_binding` differs after
  re-consent would be satisfied by a per-call nonce, which isolates nothing. T1 now
  asserts the binding is *stable* across two pre-revoke `prepare` calls first.
- **T3 named the generation too loosely.** A fieldless `GrantRecord { .. }` match
  (`crash_tests.rs:49`) admits any connected record; band 2 and the healthy row require
  record equality against the expected generation.

The claim that boundaries 1-3 leave the disk byte-identical to a commit that never started
is withdrawn: `process::abort()` skips `persist_record`'s cleanup and temporary debris
survives. The conclusion is unchanged — debris the manifest does not name is unreadable by
recovery — but the reason is now the right one.

A separate seam audit established that the revoke path these tests drive is dead code
outside test and kani builds (`service.rs:318-327`), verified at source. That limitation
is recorded in D2 and belongs in the grade.
