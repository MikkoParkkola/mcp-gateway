# Windows owner-only stores: test plan

Status: REVISION 4 after test-plan review rounds 1-3 (dispositions §9-§11). Design: `2026-09-26-windows-owner-only-stores.md`
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
3. signature-only stubs with PERMISSIVE bodies. Each is a thin wrapper that carries
   the SAME test instrumentation the production body will (so no row fails for missing
   instrumentation) and then makes one std call: `create_dir_private` = fire
   `AfterCreate`, `fs::create_dir`; `create_file_private` = `OpenOptions::create_new`,
   fire `AfterCreate`; `replace` = count the attempt, record the trace, `fs::rename`,
   no retry; `sync_file` = record the trace, `sync_all`; `hold_dir` = open with std
   default sharing; `inspect` = an all-pass `Inspection`; `volume_is_local` =
   `Ok(true)`; `final_path` = the input path (after firing `AfterPathWalk`);
   `try_acquire` = open without locking. The hook, counter and trace are `cfg(test)`
   items of `private_fs`, shared unchanged by stub and production bodies. This is exactly today's unguarded Windows
   behaviour (`has_mode -> true`), so every security test fails on its ASSERTION.

Item 2 is not security logic, but it is more than a stub. It is in the red commit
because otherwise every row would be red for the same wrong reason ("store refuses on
non-unix"). The red commit is a throwaway CI PR only; it is never merged alone.

Expected outcomes, one table for every run kind:

| Rows | Red run | Green run | Mutant run |
|---|---|---|---|
| all W-T rows except those below | FAIL with own `WT-ASSERT` marker | pass | the mapped rows FAIL with their marker |
| W-T17, W-T21 (regression guards) | pass | pass | FAIL under M17 / M22 |
| W-T6 | FAIL, or a logged skip if `mklink` lacks the privilege | pass or logged skip | not a mutant target (M3 uses W-T5) |
| fixture tests that only needed the store to open | pass (evidence item 2 is complete) | pass | pass |

## 3. Rows

| Id | Test fn | Setup | Assert | Red reason (stubs) |
|---|---|---|---|---|
| W-T1 | `created_objects_carry_only_the_user_ace` | init a personal-account store and a task store in a test-owned tree | for each store dir, `authority.json`, a record, `journeys.json`, a task record, both lock sidecars: PowerShell `(Get-Acl p).GetSecurityDescriptorSddlForm('Owner, Access')`, parsed by the test helper and compared FIELD BY FIELD: owner = user SID, `P` flag set, exactly one ACE, allow, user SID, `FA`, `OICI` on dirs and none on files (auto-inherit flags such as `AI`/`AR` are ignored) | SDDL shows inherited ACEs (no `P`): string mismatch |
| W-T1b | `objects_are_private_at_the_instant_of_creation` | `cfg(test)` fault boundary `AfterCreate` sits INSIDE `create_dir_private` / `create_file_private`, immediately after the `CreateDirectoryW` / `CreateFileW` call returns and before any other statement, so a create-then-protect body cannot finish protecting first; the hook runs the W-T1 PowerShell read | same literal SDDL at that instant | permissive stub creates with inherited DACL: mismatch |
| W-T2 | `foreign_ace_on_store_dir_refuses` | init, close, `icacls d /grant *S-1-1-0:R` | reopen refuses, reason `ForeignSid(S-1-1-0)` | stub accepts: reopen succeeds |
| W-T3 | `inherited_ace_on_store_dir_refuses` | store under a test-created parent whose inheritable DACL grants ONLY the current user (so inheritance adds no foreign SID); close; `icacls d /inheritance:e` | reason `NotProtected` (P2 cannot fail by construction) | accepts |
| W-T4 | `foreign_ace_on_each_file_refuses` | table-driven over the six file kinds of W-T1; grant Everyone on one | the operation reading that file refuses with `ForeignSid` (authority on open, record on lookup, journeys on first journey op, task record on load, lease/sidecar on custody) | accepts |
| W-T5 | `junction_in_store_path_refuses` | `mklink /J C:\t\j C:\t\real`; configure store under `C:\t\j\store` | config/open refuses, reason `ReparsePoint` | accepts |
| W-T6 | `symlink_record_refuses` | `mklink` a record name to a private file; skip with logged reason if `mklink` lacks privilege | lookup refuses `ReparsePoint` | accepts |
| W-T7 | `path_prefixes` | lexical only | `\\srv\s\x`, `\\?\UNC\srv\s\x`, `\\.\C:\x`, `\\?\GLOBALROOT\x` refuse `InvalidConfiguration`; `C:\x`, `\\?\C:\x` pass | item 2 makes `validate_path` accept any prefix so stores can open: the refuse half fails |
| W-T8 | `null_dacl_refuses` | `Set-Acl` SDDL `O:<sid>D:PNO_ACCESS_CONTROL` (protected NULL DACL), read back and checked semantically (DACL absent-or-null, protected flag set) rather than by string | reason `NullDacl` | accepts |
| W-T8b | `read_only_ace_refuses` | SDDL `O:<sid>D:P(A;;FR;;;<sid>)` | reason `NoReadWrite` (P1, P2, P4, P5 pass by construction) | accepts |
| W-T9 | `custody_across_processes` | test re-execs its own binary (`--exact` child entry, env flag) that opens the store and waits on stdin | parent open: `AlreadyOwned` (task) / `StorageUnavailable` (accounts), NOT `Unsupported`, AND a test hook confirms the parent opened the sidecar (same file id as the child) so the refusal came from `try_lock`, not from a sharing violation; kill child; parent reacquires within 2 s | stub never locks: parent open succeeds while the child holds it |
| W-T10 | `legacy_token_inherited_acl_refuses` | 3.x token written the 3.x way (`fs::write`, inherited DACL) | migration refuses `NotPrivate`; message names `NotProtected` | stub `inspect` all-pass: migration accepts |
| W-T10b | `legacy_token_remediation_works` | W-T10 file plus `icacls /grant *S-1-1-0:R` and `/setowner *S-1-5-32-544`; run the §2.4 sequence the refusal message printed, parsed from the message itself | migration then accepts; before it, refusal lists `ForeignSid(S-1-1-0)` and `ForeignOwner(S-1-5-32-544)` | accepts before remediation |
| W-T11 | `foreign_owner_refuses` | `icacls f /setowner *S-1-5-32-544` on `authority.json` | reason `ForeignOwner` | accepts |
| W-T12 | `mapped_network_drive_refuses` (ignored; CI step) | `net use X: \\localhost\C$`; store under `X:\t` | `volume_is_local(X:\t handle) == false` asserted directly; store open refuses | stub returns `true` |
| W-T13 | `moved_in_unprotected_file_refuses` | in a test-created source dir whose own DACL is protected with no inheritable ACEs, SDDL `O:<sid>D:(A;;FA;;;<sid>)` (one user ACE, NOT protected, nothing to inherit); rename into the store as a valid record name, point the manifest at it via the existing `revoke_fixture` helpers | reason `NotProtected` only | accepts |
| W-T14 | `second_user_cannot_read` (ignored; CI step) | CI step: `net user mgw-probe <random> /add`, grant it `SeInteractiveLogonRight` (Server images restrict interactive logon to Administrators) while it stays only in Users; the test creates `C:\mgwt\<run>` and grants `Users` read+list on it with inheritance (`icacls /grant *S-1-5-32-545:(OI)(CI)RX`), writes a plain CONTROL file there, then creates both stores inside it; `Start-Process -Credential -WorkingDirectory C:\mgwt\<run>` runs `Get-Content` as `mgw-probe`; a launch failure is `WT-FIXTURE W-T14` | control file IS read by `mgw-probe` (proves the identity, the process launch and the parent ACL work); `authority.json`, a record and a task record all fail with "Access is denied", so denial can only come from the objects' own DACLs | permissive stub inherits `Users` read from the planted parent: `mgw-probe` reads all three |
| W-T15 | `fat32_volume_refuses` (ignored; CI step) | CI step: `diskpart` create+attach two 64 MB VHDs, format one FAT32 (`F:`) and one exFAT (`E:`) | on both, `volume_is_local` false (asserted directly); store open refuses | stub `true` |
| W-T16a | `held_directory_blocks_its_own_rename` | `private_fs::hold_dir(store)` ALONE, no files open; `fs::rename(store, store2)` | rename `Err` with raw OS error 32 and the directory's file id unchanged; then drop the guard and repeat rename + `mklink /J` at the old name: both succeed (control) | stub hold opens with std default sharing (includes delete): the first rename succeeds |
| W-T16 | `open_store_blocks_ancestor_swap` | store open; rename parent; replace parent with a junction | both fail; a lookup afterwards still returns the committed record | as W-T16a |
| W-T17 | `reader_closes_before_replace` (parameterized: personal-account authority lock and task-store state lock) | barrier AFTER the reader releases the authority lock and BEFORE any escaped handle could drop; writer commits `refresh_tokens` at that barrier. Attempts are counted inside `private_fs::replace`, a wrapper shared by stub and production bodies | commit succeeds on attempt 1 | **green-in-red regression guard**: the un-gated read path already closes inside the lock, so this row is expected GREEN in the red run; its proof is M17 (a reader that keeps its handle makes attempt 1 fail), stated here rather than claimed as red |
| W-T19 | `other_ace_type_refuses` | `Set-Acl` SDDL `O:<sid>D:P(A;;FA;;;<sid>)(XA;;FR;;;WD;(Member_of {SID(BA)}))` (a conditional callback ACE; every other rule passes) | reason `OtherAceType` | accepts |
| W-T20 | `external_holder_retry_is_bounded` | a thread holds the destination record open (std handle, no delete share). Case A: after attempt 1 fails, the replace hook BLOCKS until the holder thread acknowledges it has dropped its handle; only then may attempt 2 run. Case B: never release; the test runs under a 10 s watchdog that fails the test (not hangs CI) on expiry | A: commit succeeds with attempts == 2 exactly. B: `StorageUnavailable` after exactly 3 attempts, and a lookup afterwards returns the PREVIOUS committed version | stub has no retry loop: attempt 1 fails with a sharing violation and the commit refuses, so A sees attempts == 1 and an error, B sees attempts == 1 instead of 3 |
| W-T21 | `foreign_deny_ace_is_accepted` | fixture first asserts via `whoami /groups` that the runner token does NOT contain BUILTIN\Guests (S-1-5-32-546); SDDL `O:<sid>D:P(D;;FA;;;S-1-5-32-546)(A;;FA;;;<sid>)` | store opens and reads normally | **green-in-red regression guard** against over-strict P2; proof is M22 |
| W-T22 | `durability_calls_are_made` | commit one grant and one task record with a test-only trace in `private_fs::sync_file` and `private_fs::replace` | per commit: `sync_file` precedes `replace`, `replace` was called with the write-through flag set, and, where probe E1 found it supported, `sync_dir` follows `replace` | stub does not trace: empty trace. Limitation: this proves the CALLS are made, not that the disk honours them (§7) |
| W-T23 | `directory_at_record_name_refuses` | create a DIRECTORY (private, protected) at a valid record name the manifest points to; same for a task record name | lookup / load refuses, reason `NotRegular` | the un-gated reader still refuses the store operation (its `is_file` check moves unchanged), but the stub `judge_*` returns `Ok`, so the `NotRegular` reason assertion fails |
| W-T18 | `path_swap_between_walk_and_open_refuses` | `cfg(test)` fault boundary `AfterPathWalk` replaces ancestor with a junction to another private store of the same user | reason `PathMismatch` | stub `final_path` echoes input: accepts |

Fixture discipline (all plants):

1. Baseline first: before planting, the fixture sets a KNOWN VALID descriptor on the
   object with PowerShell `Set-Acl` (`O:<sid>D:P(A;;FA;;;<sid>)`, or the directory
   form). Objects the permissive red stubs created with inherited DACLs therefore start
   from the same baseline as green-run objects.
2. Plant, then read back with PowerShell and assert the literal intended SDDL.
3. Each row states its EXPECTED FAILURE SET (below); the fixture asserts, with its own
   SDDL parser in the test helper (not `inspect`), that the planted descriptor fails
   exactly that set. Mismatch is a FIXTURE error, never a refusal assertion.

| Row | Expected failure set |
|---|---|
| W-T2, W-T4 | {P2} |
| W-T3 | {P5} |
| W-T8 | {P1, P3} (protected, so not P5; reason asserted: `NullDacl`, which the plan requires be reported first) |
| W-T8b | {P3} |
| W-T10 | {P5} plus any foreign inherited SIDs the runner's temp tree adds (read back and listed, not assumed) |
| W-T10b | {P2, P4, P5} before remediation, {} after |
| W-T11 | {P4} |
| W-T13 | {P5} |
| W-T19 | {P2 other-ACE-type} |
| W-T21 | {} |

Red-run gate: every row's decisive assertion message starts with a unique marker
`WT-ASSERT <id>`; fixture failures start `WT-FIXTURE <id>`. A CI script over the test
output checks the red run against the table in §2: every row executed (W-T6 may
instead log `WT-SKIP W-T6`), each red row failed with its own `WT-ASSERT <id>`
marker, no `WT-FIXTURE` line, no panic outside a marker, and both guards passed. Any difference fails the red PR.

Existing suites and Windows (verified at `src/personal_accounts/tests.rs:516-557`):

- Un-gated to run on Windows: `commit_tests`, `fence_tests`, `revoke_tests`,
  `child_probe` (no unix API use), and `crash_tests`, `authority_tests`,
  `wire_bound_tests` after their 2-3 unix-only fixture calls (modes on
  `OpenOptions`) move to one cross-platform test helper `private_fs::test_write_private`.
  `crash_tests` is the Windows interrupted-commit evidence.
- Stay unix-only: `store_tests.rs` (20 unix API uses; mode and symlink assertions),
  `fifo_tests` (Linux), and task store `store_06` (modes). Their Windows counterparts
  are the W-T rows; `NotRegular` is W-T23.
- `bounds_tests` and task store `store_04` already compile everywhere and now run.

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
| M23 | remove the underlying `sync_all` inside `sync_file` while keeping the trace call (the trace records the `sync_all` RESULT, so a missing call shows as no result) | W-T22 |
| M24 | drop `MOVEFILE_WRITE_THROUGH` in the actual `MoveFileExW` argument (trace records the argument passed, not a separate flag) | W-T22 |
| M25 | drop the regular-file check | W-T23 |
| M26 | P5 not required when inspecting store DIRECTORIES | W-T3 |

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
- `crash_tests`, `repair_tests` and every `faults::Boundary` run on Windows after the
  un-gating in §3; the unix-only list in §3 is the complete set left gated, and the PR
  body repeats it.

## 6. CI steps added to the Windows job

1. existing `cargo test --no-run`;
2. `cargo test --all-features --lib --bins --no-fail-fast` (no skips);
3. privileged step, `if: always() && steps.build.outcome == 'success'` so a red or
   mutant run in step 2 does not skip it: create `mgw-probe`, `net use X: \\localhost\C$`,
   create and attach two 64 MB VHDs with `diskpart` formatted FAT32 (`F:`) and exFAT
   (`E:`), then `cargo test --all-features --lib -- --ignored win_privileged::`;
4. teardown, `if: always()`: remove the user, the mapping and the VHDs;
5. aggregate, `if: always()`: fail the job if step 2 or step 3 failed (both outcomes
   are read explicitly, so neither can hide the other).

## 7. Not tested here, with reasons

- Power loss: hosted runners cannot cut power; durability rests on the documented
  `MOVEFILE_WRITE_THROUGH` / `FlushFileBuffers` contracts plus the fault suites (§5).
- Administrator bypass: out of the model by design (root analogue).
- W-T6 may skip where symlink creation needs Developer Mode; junctions (W-T5) cover
  the reparse rule without privilege, and M3 is assigned to W-T5.

## 8. Evidence to record

Red run id (throwaway PR), green run id, one run id per mutant M1-M26, before/after
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


## 10. Review round 2 dispositions

| Finding | Disposition |
|---|---|
| HIGH: `AfterCreate` could fire after a create-then-protect helper finished | Fixed: boundary inside the helper, right after the create call (W-T1b) |
| MEDIUM: W-T21 denied write to Everyone, which also blocks the user's reads | Fixed: deny Guests, verified absent from the runner token |
| MEDIUM: "exactly one rule fails" contradicted W-T8/W-T10b; stub-created objects lack a baseline | Fixed: externally set baseline descriptor; per-row expected failure sets |
| MEDIUM: name-only red gate accepts fixture errors and panics | Fixed: `WT-ASSERT` / `WT-FIXTURE` markers, execution and marker checks |
| MEDIUM: W-T20 timing-dependent, unbounded mutant could hang CI | Fixed: release on observed failed attempt; 10 s watchdog |
| MEDIUM: privileged step skipped after expected failures | Fixed: `always() && build success`, explicit aggregate step |
| Improvement: durability-call mutants | Adopted: W-T22, M23, M24, with the stated limit that they prove calls, not disk behaviour |
| Improvement: consistent privileged provisioning incl. exFAT | Adopted (§6 step 3) |


## 11. Review round 3 dispositions

| Finding | Disposition |
|---|---|
| HIGH: second user cannot log on interactively on the Server image | Fixed: grant `SeInteractiveLogonRight`, set working dir, launch failure = `WT-FIXTURE` (W-T14) |
| HIGH (both seats): one-line stubs lack the hooks, counters and traces six rows depend on | Fixed: stubs are thin wrappers carrying the same `cfg(test)` instrumentation (§2) |
| HIGH: cited crash/store suites are unix-gated; `NotRegular` has no row | Fixed: explicit un-gate and stay-unix lists (§3, §5); W-T23 + M25 |
| MEDIUM: W-T8 plant also failed P5 | Fixed: protected NULL DACL, checked semantically |
| MEDIUM: W-T13 source parent could add foreign ACEs | Fixed: source dir protected with nothing inheritable |
| MEDIUM: W-T20 case A scheduling-dependent | Fixed: hook waits for the holder's drop acknowledgement |
| MEDIUM: W-T20 red reason wrong for `fs::rename` | Fixed: red reason restated (attempts == 1, no retry) |
| MEDIUM: directory P5 has no mutant | Fixed: M26 on W-T3 |
| LOW: W-T6 skip vs red gate | Fixed: one expectation table (§2) allows `WT-SKIP W-T6` |
| Improvements | Adopted: W-T9 file-id check; W-T22 traces `sync_dir` and the real `MoveFileExW` argument; M23/M24 mutate the platform call, not the wrapper; W-T1 compared field by field; W-T17 covers both stores |
