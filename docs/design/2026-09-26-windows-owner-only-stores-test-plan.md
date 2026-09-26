# Windows owner-only stores: test plan

Status: DRAFT for two-seat review. Design: `2026-09-26-windows-owner-only-stores.md`
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
- Every refusal is asserted twice: the store-level error CATEGORY the caller sees
  (`InvalidConfiguration`, `StorageUnavailable`, `UnsafeStore`, `NotPrivate`), and the
  `PrivacyRefusal` reason from calling `private_fs::judge_*` on the same path directly.
  Only the second can tell two refusals apart, so mutants are assigned to it.
  - W-T1 reads the created object's SDDL with PowerShell `(Get-Acl).Sddl` and compares
    it to the literal expected string, not to `inspect`;
  - W-T14 asks the kernel (a second user's read) rather than any gateway code.

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
| W-T1 | `created_objects_carry_only_the_user_ace` | init a personal-account store and a task store in a temp dir | for each store dir, `authority.json`, a record, `journeys.json`, a task record, both lock sidecars: `(Get-Acl).Sddl` == `O:<sid>D:P(A;OICI;FA;;;<sid>)` for dirs, `O:<sid>D:P(A;;FA;;;<sid>)` for files | SDDL shows inherited ACEs (`AI`, no `P`): string mismatch |
| W-T2 | `foreign_ace_on_store_dir_refuses` | init, close, `icacls d /grant *S-1-1-0:R` | reopen refuses, reason `ForeignSid(S-1-1-0)` | stub accepts: reopen succeeds |
| W-T3 | `inherited_ace_on_store_dir_refuses` | init, close, `icacls d /inheritance:e` | reason `NotProtected` | accepts |
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
| W-T14 | `second_user_cannot_read` (ignored; CI step) | CI step: `net user mgw-probe <random> /add`; test creates stores, then `Start-Process -Credential` runs `powershell Get-Content` on `authority.json`, a record, a task record | all three exit non-zero with "Access is denied"; control: the same command as the test user succeeds | stub creates with inherited DACL: second user can read (runner temp dirs grant `Users` read) |
| W-T15 | `fat32_volume_refuses` (ignored; CI step) | CI step: `diskpart` create+attach a 64 MB VHD, format FAT32, letter `F:` | `volume_is_local(F:\t)` false (asserted directly); store open refuses | stub `true` |
| W-T16a | `held_directory_blocks_its_own_rename` | `private_fs::hold_dir(store)` ALONE, no files open; `fs::rename(store, store2)`; replace with junction | both `Err` with raw OS error 32 (sharing violation) | stub hold opens with std default sharing (includes delete): rename succeeds |
| W-T16 | `open_store_blocks_ancestor_swap` | store open; rename parent; replace parent with a junction | both fail; a lookup afterwards still returns the committed record | as W-T16a |
| W-T17 | `reader_closes_before_replace` | barrier: reader thread takes the authority lock, opens a record, signals, drops; writer commits `refresh_tokens` | commit succeeds on attempt 1 (test-only `REPLACE_ATTEMPTS` counter == 1) | stub `replace` is `fs::rename`, which ignores the counter: counter 0 fails the `== 1` assertion |
| W-T18 | `path_swap_between_walk_and_open_refuses` | `cfg(test)` fault boundary `AfterPathWalk` replaces ancestor with a junction to another private store of the same user | reason `PathMismatch` | stub `final_path` echoes input: accepts |

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
| M17 | reader handle outlives the lock | W-T17 |
| M18 | skip the final-path comparison | W-T18 |

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

Red run id (throwaway PR), green run id, one run id per mutant M1-M18, before/after
unix test counts, the list of residual Windows failures by name.
