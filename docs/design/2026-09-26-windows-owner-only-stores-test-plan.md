# Windows owner-only stores: test plan

Status: REVISION 2 after test-plan review round 1 (both seats SHIP-WITH-FIXES). Design: `2026-09-26-windows-owner-only-stores.md`
(reviewed, SHIP x2). Code, probes and the red commit wait for the ADR-016 decision.

## 1. What the plan asserts against

The oracle is the design's rule set, never the implementation's own predicate:

- P1-P5 (design §2.2) and the refusal REASON enum `PrivacyRefusal { NullDacl,
  ForeignSid(Sid), NoReadWrite, ForeignOwner(Sid), NotProtected, OtherAceType,
  ReparsePoint, NotLocal, PathMismatch, NotRegular }`. Tests assert the reason, so one
  check cannot mask another (round-2/3 findings on masked mutants).
- Independent evidence where the predicate could be wrong in the same way twice:
  - planted conditions come from `icacls` / PowerShell `Set-Acl` SDDL, never from
    `win_acl`, so construction and inspection are not the same code;
  - W-T1 reads the created object's SDDL with PowerShell `(Get-Acl).Sddl` and compares
    it to the literal expected string, not to `inspect`;
  - W-T14 asks the kernel (a second user's read) rather than any gateway code.
- Every refusal is asserted twice: the store-level error CATEGORY the caller sees
  (`InvalidConfiguration`, `StorageUnavailable`, `UnsafeStore`, `NotPrivate`), and the
  `PrivacyRefusal` reason from calling `private_fs::judge_*` on the same path directly.
  Only the second can tell two refusals apart, so mutants are assigned to it.

Placement: `src/private_fs_tests.rs` (`#[cfg(all(test, windows))]`, a child of
`private_fs` so it reaches private items with no visibility widening), and the store
suites already in tree. Unix gets no new tests: its bodies move unchanged, and the
existing unix suites are the regression net for that move (§5).

## 2. Red-first shape

No Windows assertion is reachable while the stores refuse on non-unix, so the red
commit must let the stores OPEN on Windows without any security logic. It holds:

1. the tests below;
2. the mechanical un-gating: `cfg(unix)` removed from the store bodies in
   `storage.rs`, `commit.rs`, `consent.rs`, `journey/*`, the `cfg(not(unix))` refusal
   stubs deleted, calls routed through `private_fs`, and `validate_path` accepting ANY
   `Prefix` component (without that no Windows store path passes config);
3. signature-only stubs with PERMISSIVE bodies, one line each:
   `create_dir_private` = `fs::create_dir`, `create_file_private` =
   `OpenOptions::create_new`, `replace` = `fs::rename`, `inspect` = an all-pass
   `Inspection`, `volume_is_local` = `Ok(true)`, `final_path` = the input path,
   `try_acquire` = open without locking. This is exactly today's unguarded Windows
   behaviour (`has_mode -> true`), so every security test fails on its ASSERTION.

Item 2 is not security logic, but it is more than a stub. It is in the red commit
because otherwise every row would be red for the same wrong reason ("store refuses on
non-unix"). The red commit is a throwaway CI PR only; it is never merged alone.

Expected red: every W-T row below fails with its stated reason. Expected green in the
same red run: the ~750 fixture tests that only needed the store to open (evidence that
item 2 is complete).

## 3. Rows

| Id | Test fn | Setup | Assert | Red reason (stubs) |
|---|---|---|---|---|
| W-T1 | `created_objects_carry_only_the_user_ace` | init a personal-account store and a task store in a test-owned tree | for each store dir, `authority.json`, a record, `journeys.json`, a task record, both lock sidecars: PowerShell `(Get-Acl p).GetSecurityDescriptorSddlForm('Owner, Access')` == `O:<sid>D:P(A;OICI;FA;;;<sid>)` for dirs, `O:<sid>D:P(A;;FA;;;<sid>)` for files (group section excluded: Windows supplies it) | SDDL shows inherited ACEs (no `P`): string mismatch |
| W-T1b | `objects_are_private_at_the_instant_of_creation` | `cfg(test)` fault boundary `AfterCreate` fires immediately after each `create_*_private` returns, before any other call; the hook runs the W-T1 PowerShell read | same literal SDDL at that instant | permissive stub creates with inherited DACL: mismatch |
| W-T2 | `foreign_ace_on_store_dir_refuses` | init, close, `icacls d /grant *S-1-1-0:R` | reopen refuses, reason `ForeignSid(S-1-1-0)` | stub accepts: reopen succeeds |
| W-T3 | `inherited_ace_on_store_dir_refuses` | store under a test-created parent whose inheritable DACL grants ONLY the current user (so inheritance adds no foreign SID); close; `icacls d /inheritance:e` | reason `NotProtected` (P2 cannot fail by construction) | accepts |
| W-T4 | `foreign_ace_on_each_file_refuses` | table-driven over the six file kinds of W-T1; grant Everyone on one | the operation reading that file refuses with `ForeignSid` (authority on open, record on lookup, journeys on first journey op, task record on load, lease/sidecar on custody) | accepts |
| W-T5 | `junction_in_store_path_refuses` | `mklink /J C:\t\j C:\t\real`; configure store under `C:\t\j\store` | config/open refuses, reason `ReparsePoint` | accepts |
| W-T6 | `symlink_record_refuses` | `mklink` a record name to a private file; skip with logged reason if `mklink` lacks privilege | lookup refuses `ReparsePoint` | accepts |
| W-T7 | `path_prefixes` | lexical only | `\\srv\s\x`, `\\?\UNC\srv\s\x`, `\\.\C:\x`, `\\?\GLOBALROOT\x` refuse `InvalidConfiguration`; `C:\x`, `\\?\C:\x` pass | item 2 makes `validate_path` accept any prefix so stores can open: the refuse half fails |
| W-T8 | `null_dacl_refuses` | `Set-Acl` SDDL `D:NO_ACCESS_CONTROL` on `authority.json` | reason `NullDacl` | accepts |
| W-T8b | `read_only_ace_refuses` | SDDL `O:<sid>D:P(A;;FR;;;<sid>)` | reason `NoReadWrite` (P1, P2, P4, P5 pass by construction) | accepts |
| W-T9 | `custody_across_processes` | test re-execs its own binary (`--exact` child entry, env flag) that opens the store and waits on stdin | parent open: `AlreadyOwned` (task) / `StorageUnavailable` (accounts), NOT `Unsupported`; kill child; parent reacquires within 2 s | stub never locks: parent open succeeds while the child holds it |
| W-T10 | `legacy_token_inherited_acl_refuses` | 3.x token written the 3.x way (`fs::write`, inherited DACL) | migration refuses `NotPrivate`; message names `NotProtected` | stub `inspect` all-pass: migration accepts |
| W-T10b | `legacy_token_remediation_works` | W-T10 file plus `icacls /grant *S-1-1-0:R` and `/setowner *S-1-5-32-544`; run the §2.4 sequence the refusal message printed, parsed from the message itself | migration then accepts; before it, refusal lists `ForeignSid(S-1-1-0)` and `ForeignOwner(S-1-5-32-544)` | accepts before remediation |
| W-T11 | `foreign_owner_refuses` | `icacls f /setowner *S-1-5-32-544` on `authority.json` | reason `ForeignOwner` | accepts |
| W-T12 | `mapped_network_drive_refuses` (ignored; CI step) | `net use X: \\localhost\C$`; store under `X:\t` | `volume_is_local(X:\t handle) == false` asserted directly; store open refuses | stub returns `true` |
| W-T13 | `moved_in_unprotected_file_refuses` | in a non-store dir, SDDL `O:<sid>D:(A;;FA;;;<sid>)` (one user ACE, NOT protected); rename into the store as a valid record name, point the manifest at it via the existing `revoke_fixture` helpers | reason `NotProtected` only | accepts |
| W-T14 | `second_user_cannot_read` (ignored; CI step) | CI step: `net user mgw-probe <random> /add`; the test creates `C:\mgwt\<run>` and grants `Users` read+list on it with inheritance (`icacls /grant *S-1-5-32-545:(OI)(CI)RX`), writes a plain CONTROL file there, then creates both stores inside it; `Start-Process -Credential` runs `Get-Content` as `mgw-probe` | control file IS read by `mgw-probe` (proves the identity, the process launch and the parent ACL work); `authority.json`, a record and a task record all fail with "Access is denied", so denial can only come from the objects' own DACLs | permissive stub inherits `Users` read from the planted parent: `mgw-probe` reads all three |
| W-T15 | `fat32_volume_refuses` (ignored; CI step) | CI step: `diskpart` create+attach two 64 MB VHDs, format one FAT32 (`F:`) and one exFAT (`E:`) | on both, `volume_is_local` false (asserted directly); store open refuses | stub `true` |
| W-T16a | `held_directory_blocks_its_own_rename` | `private_fs::hold_dir(store)` ALONE, no files open; `fs::rename(store, store2)` | rename `Err` with raw OS error 32 and the directory's file id unchanged; then drop the guard and repeat rename + `mklink /J` at the old name: both succeed (control) | stub hold opens with std default sharing (includes delete): the first rename succeeds |
| W-T16 | `open_store_blocks_ancestor_swap` | store open; rename parent; replace parent with a junction | both fail; a lookup afterwards still returns the committed record | as W-T16a |
| W-T17 | `reader_closes_before_replace` | barrier AFTER the reader releases the authority lock and BEFORE any escaped handle could drop; writer commits `refresh_tokens` at that barrier. Attempts are counted inside `private_fs::replace`, a wrapper shared by stub and production bodies | commit succeeds on attempt 1 | **green-in-red regression guard**: the un-gated read path already closes inside the lock, so this row is expected GREEN in the red run; its proof is M17 (a reader that keeps its handle makes attempt 1 fail), stated here rather than claimed as red |
| W-T19 | `other_ace_type_refuses` | `Set-Acl` SDDL `O:<sid>D:P(A;;FA;;;<sid>)(XA;;FR;;;WD;(Member_of {SID(BA)}))` (a conditional callback ACE; every other rule passes) | reason `OtherAceType` | accepts |
| W-T20 | `external_holder_retry_is_bounded` | a thread holds the destination record open (std handle, no delete share). Case A: release after 25 ms; Case B: never release | A: commit succeeds with 2 <= attempts <= 3. B: `StorageUnavailable` after exactly 3 attempts, and a lookup afterwards returns the PREVIOUS committed version (nothing acknowledged) | stub `fs::rename` does not retry or count: A attempts == 1 (std rename may use POSIX semantics and succeed), B commits instead of refusing |
| W-T21 | `foreign_deny_ace_is_accepted` | SDDL `O:<sid>D:P(D;;FW;;;WD)(A;;FA;;;<sid>)` (a deny for Everyone, the user allow) | store opens and reads normally | **green-in-red regression guard** against over-strict P2; proof is M22 |
| W-T18 | `path_swap_between_walk_and_open_refuses` | `cfg(test)` fault boundary `AfterPathWalk` replaces ancestor with a junction to another private store of the same user | reason `PathMismatch` | stub `final_path` echoes input: accepts |

Fixture discipline (all plants): after planting, the helper reads the SDDL back with
PowerShell and asserts it equals the intended literal, and that exactly the rule the
row names fails, before the store is invoked. A plant that Windows altered (default
owner, inheritance, `Set-Acl` normalisation) fails as a FIXTURE error, never as a
misleading refusal reason.

Red-run gate: a CI script compares the red run's failing test names with the list of
rows marked red above and fails the red PR on any difference, so a row that is
unexpectedly green (or red) cannot be hand-recorded past.

Existing coverage that now also runs on Windows: size bounds and non-regular-file
refusals in `src/personal_accounts/store_tests.rs` (`install_bound_fixture` cases) and
`src/gateway/task_service/store_tests.rs` (`store_04`); unix-mode assertions such as
`store_06_private_modes_and_unsafe_sources_are_enforced` stay unix-only, and their
Windows counterparts are W-T1..W-T21.

## 4. Mutant map (each a throwaway CI PR, Tests-only; the named test must redden)

| Mutant | Code change | Reddens |
|---|---|---|
| M1 | P2: accept any ALLOWED SID | W-T2, W-T4 |
| M2 | descriptor without `SE_DACL_PROTECTED` | W-T1 |
| M3 | drop REPARSE_POINT attribute check | W-T5 |
| M4 | lexical prefix accepts `UNC` | W-T7 |
| M5 | task-store privacy predicate `-> true` | W-T4 (task record and lease rows) |
| M6 | drop P4 | W-T11 |
| M7 | `try_acquire` skips `try_lock` | W-T9 |
| M8 | `initialize` back on `write_config_text` | W-T1 (`authority.json` row) |
| M9 | drop P1 | W-T8 (reason assertion) |
| M10 | drop P3 | W-T8b |
| M11 | `volume_is_local` ignores the remote legs | W-T12 |
| M12 | P5 not required on files | W-T13 |
| M13 | `create_file_private` -> std `create_new` | W-T1 |
| M14 | drop `FILE_PERSISTENT_ACLS` leg | W-T15 |
| M15 | held dir handle shares delete | W-T16a |
| M16 | held dir handle without `FILE_LIST_DIRECTORY` | W-T16a |
| M17 | reader handle outlives the lock (kept until after the barrier) | W-T17 |
| M18 | skip the final-path comparison | W-T18 |
| M19 | ignore ACE types other than allow/deny | W-T19 |
| M20 | create with std, THEN protect (throwaway branch only; adds a `SetSecurityInfo` call) | W-T1b |
| M21 | no retry on sharing violation / unbounded retry | W-T20 (A, B) |
| M22 | treat any DENY ACE as foreign | W-T21 |

The ignored CI-step tests (W-T12, W-T14, W-T15) live in module `win_privileged` and run in the mutant PRs too: each mutant PR
runs the full Windows job including the privileged step.

## 5. Un-gating acceptance (the ~750)

- Remove `--skip gateway:: --skip personal_accounts::` (`ci.yml:274-276`) and the
  `cfg(all(test, unix))` gates at `commit.rs:40-42`, `journey/mod.rs:50-65`.
- Pass condition on the Windows job: `gateway::` and `personal_accounts::` run with zero
  failures whose panic site is a store open (`router/tests.rs:82`,
  `store_tests/support.rs:44`, `revoke_fixture.rs:281`, `account_resolver_fixture.rs:407`,
  `service_tests.rs:322`). Any other residual failure is listed by test name with its
  owning issue (W1, #1142) in the PR body; none may be store-related.
- Unix regression net: the unix `Tests` job stays green with its test count unchanged
  or higher (the unix bodies move into `private_fs`, they are not rewritten). The PR
  body quotes the before/after unix test counts.
- The existing crash/fault suites (`crash_tests.rs`, `repair_tests.rs`, every
  `faults::Boundary`) now also run on Windows; they are the interrupted-commit evidence.

## 6. CI steps added to the Windows job

1. existing `cargo test --no-run`;
2. `cargo test --all-features --lib --bins --no-fail-fast` (no skips);
3. privileged step: create `mgw-probe` user, `net use X:`, attach FAT32 VHD, then
   `cargo test --lib -- --ignored win_privileged::`; teardown always runs (`if: always()`).

## 7. Not tested here, with reasons

- Power loss: hosted runners cannot cut power; durability rests on the documented
  `MOVEFILE_WRITE_THROUGH` / `FlushFileBuffers` contracts plus the fault suites (§5).
- Administrator bypass: out of the model by design (root analogue).
- W-T6 may skip where symlink creation needs Developer Mode; junctions (W-T5) cover
  the reparse rule without privilege, and M3 is assigned to W-T5.

## 8. Evidence to record

Red run id (throwaway PR), green run id, one run id per mutant M1-M22, before/after
unix test counts, the list of residual Windows failures by name.

## 9. Review round 1 dispositions

| Finding | Disposition |
|---|---|
| HIGH: W-T14 denial could come from the profile-tree ACL, not the object DACL | Fixed: test-owned tree granting `Users` read, plus a readable control file |
| HIGH (both seats): `OtherAceType` has no row or mutant | Fixed: W-T19, M19 |
| HIGH: create-then-protect exposure invisible to post-creation checks | Fixed: W-T1b reads SDDL at an `AfterCreate` boundary; M20 |
| MEDIUM: W-T1 literal omits the group Windows supplies | Fixed: `GetSecurityDescriptorSddlForm('Owner, Access')` |
| MEDIUM: W-T3 plant also adds foreign inherited ACEs | Fixed: store under a user-only inheritable parent |
| MEDIUM (both seats): W-T16a junction leg cannot give error 32 | Fixed: rename leg asserts 32 and unchanged file id; release-then-succeed control |
| MEDIUM: W-T17 red reason measured missing instrumentation | Fixed: counter in a shared wrapper, barrier before handle drop; row declared a green-in-red regression guard proven by M17 |
| MEDIUM: bounded retry untested | Fixed: W-T20 (release and persistent cases), M21 |
| Improvements | Adopted: deny-ACE row W-T21 + M22; exFAT beside FAT32; plant read-back discipline; automated red-run name comparison; existing-coverage map (§3) |
