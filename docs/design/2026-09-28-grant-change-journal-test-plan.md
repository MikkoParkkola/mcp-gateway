# Test plan: grant-change journal (MIK-7570.AUDIT.4, #1869)

Design: `docs/design/2026-09-28-grant-change-journal.md` (rev 4). Cells are the design's section 10
table; this plan fixes where each lives, how it is driven and the exact assertion.

## Harness

- `JournalFixture` (test-only, `src/identity_grants/journal_tests.rs`): temp dir, grant file path, helpers
  `cli_add`, `cli_replace`, `cli_revoke` calling the library change function the CLI calls, `direct_write`
  (writes the grant file with `write_identity_grants_file`, no journal), `journal_lines`.
- `AuditFixture` (test-only, `src/config_reload/grant_audit_tests.rs`): an `InMemoryControlPlaneStore`
  wrapped by `FlakyStore`, whose `append_audit` fails on chosen call numbers; `records()` returns the
  `grant_change` events oldest first; `restart()` builds a fresh `GrantAuditor` over the same store and
  state dir, dropping all in-memory state (a crash).
- Crash points: `GrantAuditFault::{AfterPlanWrite, AfterAppend(k), BeforeCommit}` (test-only field on
  `GrantAuditor`, `#[cfg(test)]`); the fault returns an error from `reconcile` at that point and the test
  then calls `restart()`.
- Every assertion compares verbs, grant ids and digests in order, and counts event ids for uniqueness.

## Cells

| Cell | File | Drive | Assert |
|---|---|---|---|
| T1a | journal_tests | `cli_add` g1, `cli_replace` g1, `cli_revoke` g1 | 3 lines; verbs add, replace, revoke; `prev_digest` null, d1, d2; `digest` equals `grant_digest(row)`; actor `unknown` |
| T1b | journal_tests | add g1 twice without replace; revoke g9 | both return Err; journal has exactly 1 line |
| T1c | journal_tests | `grant_digest` of a fixed row | equals a pinned `sha256:` literal |
| T1d | journal_tests (unix) | first append | journal mode `0o600` |
| T2a | grant_audit_tests | add then revoke, one reconcile | records: add, revoke (2) |
| T2b | grant_audit_tests | reconcile twice, no change | second adds 0 records |
| T2c | grant_reload_trigger_tests-style, new file `grant_audit_watch_tests.rs` | sink with auditor, `ConfigWatcher::spawn_reload_task`, CLI add, touch config | one `add` record within the bounded wait |
| T2d | grant_audit_tests via `reload_identity_grants` | identical-content `--replace` | one `replace` record although rows are unchanged |
| T3a | server startup test `grant_audit_startup_tests.rs` | 2 active, 1 revoked, 1 expired | `loaded` x2 (active ids), `loaded_complete` count 2, same run id |
| T3b | same | empty grants | only `loaded_complete` count 0 |
| T3c, T3d | same | `FlakyStore` fails a `loaded` / the closing append | served grant set empty |
| T3e | grant_audit_tests | plan append fails at startup; restart with store healthy | first run: no snapshot, served empty; second: each planned id once, then snapshot |
| T4a | grant_audit_tests | baseline, `direct_write` changes g1 | one `out_of_band` g1 with new digest |
| T4b | same | delete g1 row; then `grants: []` | `out_of_band` per missing id, digest None |
| T4c | same | stopped: `direct_write`; `restart()` + reconcile | `out_of_band` |
| T4d | same | `direct_write` g1, then `cli_revoke` g1, one reconcile | `out_of_band` g1, then `revoke` g1 |
| T4e | same | A->B, reconcile, B->A, reconcile, A->B, reconcile | 3 `out_of_band` with 3 distinct ids |
| T4f | same | no state file; journal entry digest D; file row differs | `out_of_band` |
| T4g | same | torn line then a valid entry; separately a mode 0o666 journal | one `indeterminate` each; a second reconcile adds 0; no `out_of_band` for the valid entry |
| T4h | same | replace journal with a shorter one holding a new entry | one `indeterminate`, then the new entry's record |
| T4i | same | direct edit g1, CLI replace g1, direct edit g1; fault `AfterAppend(1)`; restart | two `out_of_band` ids distinct; each record once |
| T4j | same | no baseline; first entry `revoke` of a pre-existing grant | no `out_of_band` |
| T5a | startup tests | auth on, grants on, store dir unopenable (file in the way), HTTP and stdio | start returns Err naming the governance audit log |
| T5b | startup tests | auth off, grants on | starts; no state file created |
| T6 | grant_audit_tests via `reload_identity_grants` | append fails after publish | live store holds the new rows; outcome contains `UNRECORDED` |
| T6b | same | state dir read-only before plan write | outcome is a refusal; live store unchanged |
| T7a | same | append fails; restart; `direct_write`; reconcile | gap `indeterminate`, then `indeterminate` (not `out_of_band`) for the edit |
| T7b | same | append fails; restart; no edit | gap `indeterminate` record present |
| T7c | same | append fails; next reconcile recovers old plan | state `gap` stays true until a plan with the gap record commits |
| T8 | same | faults AfterPlanWrite, AfterAppend(1 of 3), AfterAppend(300 of 301), BeforeCommit; restart | every planned id exactly once, plan order kept |
| T8b | same | commit write fails; CLI add; reload; restart | reload refused; no record appended while pending; each id once after restart |
| T9 | startup tests | real `identity_grant_sink_for` + store | sink carries an auditor |
| T10 | journal_tests | hold the journal lock from the test; reload | busy refusal within `RELOAD_LOCK_WAIT`; no `out_of_band` |
| T11 | store tests (new file `grant_change_store_tests.rs`) | append event with every `grant_change` field to `FileControlPlaneStore`; `read_audit` | field equal after readback |

## Red-first expectation

On the base every cell except the controls (T1b, T5b) fails on an assertion, not a compile error: the red
commit adds signature-only stubs (`journal` change fn writes the file only; `GrantAuditor::reconcile`
returns `Ok` with no records; `grant_change` field present but not mapped in `audit_fields`; startup
wiring calls a no-op). T1b and T5b are positive controls and pass on red; that is stated in the PR.

## Mutants (design section 11)

M1-M9 map to T1a, T8, T2d, T4a, T3c, T5a, T7a, T4d, T4e. One throwaway PR per mutant until the batched
workflow lands.
