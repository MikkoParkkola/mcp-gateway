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

The equivalence class is not even uniform, which is the substantive reason. Each
`boundary!(X)` fires *before* step X (`commit.rs:216-223`), so an abort at `ManifestRename`
means the rename has not happened. `ParentSync` is the exception: it fires *after*
`fs::rename` returned and *before* `sync_directory` (`commit.rs:231-241`). That single
boundary is the only one where the new manifest is on disk but unsynced, and it is the
only one where both generations are legitimately admissible after restart. Folding it into
one class with the other eight would hide exactly the window the review asked about.

### The oracle, by band

| Band | Boundaries | Admissible after restart | Never |
|---|---|---|---|
| Pre-replacement | 1-8 (`RecordWrite`..`ManifestRename`) | prior generation, or the typed recovery failure | the uncommitted candidate |
| Unsynced replacement | 9 (`ParentSync`) | prior **or** new generation | the uncommitted candidate |
| Healthy | no abort | new generation only | anything else |

Band 2 is one boundary wide and is named as ambiguous on purpose. A disjunction that is
stated and justified is evidence; the same disjunction left implicit is what made `s10`'s
oracle weak.

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

## The three tests

**T1 — live holders across a revoke and a re-consent** (new, service layer). Start an
in-flight refresh and take a `CredentialLease`, both against the connected generation.
Revoke durably. Assert: the in-flight refresh resolves to a rejection and does not commit;
`custody.release` on the held lease refuses; `recheck` on the pre-revoke binding refuses.
Re-consent. Assert: a fresh lease releases successfully, the new `cache_binding` differs
from the pre-revoke one, and the pre-revoke lease and binding are still refused.
*Falsifier:* make the post-revoke refusal in `recheck` a no-op and confirm T1 goes red.
*Positive control:* every refusal above is asserted to succeed before the revoke, so a
uniformly refusing store cannot pass.

**T2 — tighten `s10`'s oracle** (in place, `crash_tests.rs:144`). Replace
`explicit_failure(&observed)` with the specific typed recovery failure for an uncommitted
candidate. Keep the disjunction — isolation, not availability, is what the criterion
demands — but pin the failure arm so an unrelated startup fault can no longer satisfy it.
*Falsifier:* inject an unrelated startup failure and confirm the tightened oracle rejects
it where the current one accepts.

**T3 — every boundary, banded** (new, `crash_tests.rs`). Iterate `faults::ALL`; for each
boundary, drive the child to die there, assert it announced that checkpoint before dying
(the existing `Outcome::Died { checkpoint }` evidence, so a process that merely ended does
not count), restart, and apply the band oracle above. Includes the healthy no-abort row.
*Falsifier:* make recovery prefer the newest candidate over the manifest and confirm every
pre-replacement row goes red.

T2 and T3 overlap at boundary 5. That is deliberate: T2 is the oracle fix that must land
even if T3 is deferred, and T3 subsumes it only once green.

## Sequence

Design reviewed → the three tests written and reviewed as tests → red for the right reason
(each falsifier above run once) → green. The re-grade is amended only after that, and the
amendment cites test bodies, not test names — which is the rule the original grade broke.
