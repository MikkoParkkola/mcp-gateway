# Re-grade: MIK-6744.STORE.2

Criterion (`RELEASE-4.0.0-scope-update.md:43`): *revocation and restart preserve
credential isolation and cannot leave an old refresh job or cached credential
usable under a new grant.*

The 2026-09-12 grade was PARTIAL, with the note "no test asserts the specific
failure the criterion names". That note names the files it searched:
`service_release_tests.rs` and `service_refresh_tests.rs`. The covering tests are
in neither. They are at the store boundary, where revocation and restart are
actually decided, and they were not in the search scope.

The test spec at `RELEASE-4.0.0-scope-tests.md:42` names four conjuncts. Each is
graded below against a test body that was read, not against a test name:

| Conjunct | Covering test | Evidence |
|---|---|---|
| Revoke during refresh | `s08_a_stale_snapshot_cannot_land_after_a_durable_revoke` | `src/personal_accounts/fence_tests.rs:105` — the snapshot is taken before the provider call "exactly as a refresh would"; after a durable revoke the response returns `RefreshOutcome::Rejected`, and `reopen` still reports `Revoked` |
| Restart during token replacement | `s10_a_crash_between_candidate_sync_and_manifest_replacement_keeps_the_prior_grant` | `src/personal_accounts/crash_tests.rs:144` — a real child process dies at the named `CommitCheckpoint`, between candidate sync and authority move; the test first proves the window was real (candidate count rose), then requires the prior generation or an explicit failure, never the uncommitted candidate |
| Old task, cache or connection cannot restore a revoked grant | **uncovered** — nearest is `s13_restored_pre_revoke_ciphertext_stays_refused_across_restart` | `src/personal_accounts/crash_tests.rs:182` — proves restored *ciphertext at rest* is refused. The conjunct names three live holders, and a byte sequence on disk is none of them. No test retires a running refresh task, an in-memory cache entry or an open connection and then asserts it cannot use or reinstate the grant |
| Re-consent yields a usable new grant without reviving the old one | `s09_a_late_refresh_cannot_overwrite_a_newer_generation` | `src/personal_accounts/fence_tests.rs:132` — re-consent mints a new generation over the tombstone and is `Connected`; the refresh staged against the retired generation is `Rejected`; `reopen` returns the new generation unchanged |

Two of the four carry their own positive control, which is what makes them
evidence rather than a green that proves nothing. `s13` asserts `connected`
before the revoke, so its later refusal is a decision about the revoked
generation and not a store that refuses everything. `s10` asserts the candidate
count rose before asserting the outcome, so the crash window is demonstrated
rather than assumed.

Grade: **PARTIAL**, unchanged — but for a different and much smaller reason than
the one on record. Three of four conjuncts are covered by test bodies at cited
lines. The fourth is genuinely open.

What remains is now one specified test rather than four open questions: at the
service or lease-runtime layer, hold a live refresh task and a populated
credential cache across a revoke, then assert both are retired and that neither
can use nor reinstate the grant under the re-consented generation. The cheapest
falsifier is the usual one — make the retirement path a no-op and confirm the new
test goes red.

That distinction came from an independent reviewer and it is the finding of this
re-grade. The persistence layer refuses a revoked grant four ways; the question
the criterion actually asks is about holders that are still running, and the
store boundary cannot answer it.

The transferable finding is about the earlier grade, not this one. A criterion
was graded absent from a search scoped to the two files whose names matched the
criterion's vocabulary. The behaviour lived one layer down, under the vocabulary
of the layer that implements it — `commit`, `fence`, `candidate`, `manifest` —
and a search built from the requirement's words cannot reach it. Grade against
the layer that decides the behaviour, and record the scope any absence claim was
made under, because that scope is the claim's real content.
