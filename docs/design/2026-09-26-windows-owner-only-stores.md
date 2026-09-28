# Windows owner-only stores: task store and personal-account store

Status: REVIEWED. Round 4: two independent reviews SHIP (dispositions in §8-§11). ADR-016 accepted 2026-09-27 (maintainer decision).
Linked: W1 (#1142) holds the Windows failure class; probe run 36197759127 / PR #1355.
Maintainer decision (2026-09-26): 4.0 on Windows supports the long-running task
store and the personal-account store, with security equivalent to the unix path.

## 1. Problem

Both stores refuse to run on non-unix, by design, because their privacy rules are
expressed as POSIX modes. About 750 of 915 Windows test failures in the probe come
from fixtures that open one of these stores. Lifting the refusal without a Windows
privacy model would ship a credential store that anyone on the host can read.

### 1.1 Non-unix refusals (what makes Windows fail today)

| Site | Behaviour off unix |
|---|---|
| `src/personal_accounts/storage.rs:375-378` `random_hex` | `InvalidConfiguration` |
| `src/personal_accounts/storage.rs:744-772` `retained_record`/`lookup`/`initialize`/`open` | `None` / `InvalidConfiguration` |
| `src/personal_accounts/commit.rs:628-683` five writers | `InvalidConfiguration` |
| `src/personal_accounts/consent.rs:75-81` guarded commit | `RuntimeNotImplemented` |
| `src/personal_accounts/journey/grant.rs:104-114` `settle` | `InvalidConfiguration` |
| `src/personal_accounts/journey/persist.rs:237-247` `journey_transition_with_authority` | `InvalidConfiguration` |
| `src/personal_accounts/mod.rs:12-18` | `expect(dead_code)` over the whole module off unix (self-deleting once ported) |
| `src/personal_accounts/mod.rs:229,237` | `journeys` slot compiled out off unix |
| `src/fs_lock.rs:57-63` `ExclusiveFileLock::try_acquire` | `Unsupported`, the ONLY thing keeping the task store off Windows (`store.rs:706-714` maps it to `Unavailable`) |
| `.github/workflows/ci.yml:274-276` | Windows job skips `gateway::` and `personal_accounts::` |
| test gating: `commit.rs:40-42`, `journey/mod.rs:50-65` | `cfg(all(test, unix))` |

### 1.2 Unix security rules that need a Windows equivalent

Personal-account store (`src/personal_accounts/storage.rs`, `commit.rs`):

| Rule | Unix mechanism | Site |
|---|---|---|
| R1 store/authority dirs are private | `mode & 0o077 == 0`, not a symlink | `storage.rs:300-311` `private_directory` |
| R2 dirs created private | `DirBuilder.mode(0o700)`, parent dirs no symlinks | `storage.rs:313-332` |
| R3 config paths absolute, only `RootDir`/`Normal`, no symlink component | `symlink_metadata` walk | `storage.rs:278-298` `validate_path` |
| R4 new files private at creation | `create_new` + `mode(0o600)` | `commit.rs:65-74` `open_private` |
| R5 `authority.json` refused if group/world-accessible | `O_NOFOLLOW|O_NONBLOCK`, `fstat` mode `& 0o077`, regular file | `storage.rs:469-489` |
| R6 record / `journeys.json` reads: no symlink, regular, private, bounded | same, in `read_bounded` | `storage.rs:613-646` |
| R7 atomic replace + durability | temp, `sync_all`, `rename`, directory `fsync` | `commit.rs:98-155`, `storage.rs:334-339` |
| R8 single owner process | two `flock` custody locks, nonblocking | `storage.rs:341-358`, `fs_lock.rs:40-55` |
| R9 initial `authority.json` private | goes through `config_persistence::write_config_text` (`storage.rs:446`), NOT `open_private`; on Windows that writer inherits the parent ACL and only warns (`config_persistence.rs:176-220`) | `storage.rs:446-451` |

Task store (`src/gateway/task_service/store.rs`):

| Rule | Unix mechanism | Site | Off unix today |
|---|---|---|---|
| T1 store dir exactly `0700` | `has_mode` on `symlink_metadata` | `:675-690`, `:899-903` | `has_mode` returns `true` (`:905-908`) |
| T2 lease file exactly `0600` | same | `:692-705` | `true` |
| T3 record open no-follow, judge the handle | `O_NOFOLLOW` + `fstat` | `:803-816`, `:740-745` | check-then-open race (`:818-824`), mode unchecked |
| T4 temp created private | `mode(0600)` + `set_permissions` (umask-proof) | `:860-883`, `:929-947` | no-op |
| T5 dir created private | `DirBuilder.mode(0700)` + `set_permissions` | `:910-922` | plain `create_dir_all` (`:924-927`) |
| T6 rename durability | directory `fsync` | `:949-954` | no-op (`:956-959`) |
| T7 single owner | `try_acquire` | `:692-715` | refuses |

**Hazard.** On Windows the task store is off only because `try_acquire` refuses. Every
privacy check under it is already `true` or a no-op. Anyone enabling `try_acquire` for
Windows (the W1 lane touches the same file) would bring the task store up with no
privacy check at all. This design takes ownership of `try_acquire` off unix; W1 keeps
the blocking `lock_exclusive` (coordinated 2026-09-26).

### 1.3 Latent Windows defects found while tracing

- D1 `validate_path` (`storage.rs:280-285`) accepts only `RootDir` and `Normal`. Every
  Windows absolute path begins with a `Prefix` component (`C:`), so it would refuse
  EVERY Windows store path even after the ACL work.
- D2 3.x migration: `migration_source.rs:145-148` `privately_owned` returns `true` off
  unix. 3.x `TokenStorage` wrote Windows tokens with inherited ACLs
  (`oauth/storage.rs:480-540`), so a strict check refuses every real Windows 3.x token.
- D3 `SECURITY.md:65-74` already records the gap and names the fix: "a safe wrapper
  for the Win32 call", blocked on `#![deny(unsafe_code)]` (`src/lib.rs:24`).

### 1.4 Out of scope

Config file, mTLS keys and 3.x `TokenStorage` writers (`SECURITY.md:65-74`) keep their
current warn-once behaviour. The shared module below makes fixing them a follow-up
call-site change; this item does not change them.

## 2. Design

### 2.1 Decision needed from the maintainer: a scoped `unsafe` exception (ADR-016)

Setting or reading a DACL requires Win32 calls; std exposes none. Options:

| Option | Verdict |
|---|---|
| A. `windows-sys` 0.61.2 as a direct `[target.'cfg(windows)']` dependency, wrapped by ONE module with `#![allow(unsafe_code)]` | **Chosen.** Already in `Cargo.lock` via `mio`, `socket2`, `errno`, `dirs-sys`, `schannel` etc.; Microsoft-published; the lock diff must add zero `[[package]]` entries (only features change; features are not recorded in the lock). |
| B. Safe-wrapper crate | Rejected: `windows-permissions` 0.2.4 last released 2021-06-29, `windows-acl` 0.3.0 2021-01-11 (winapi 0.3), `windows-security` 0.23.0 2022-11 (46 recent downloads). Unmaintained; new supply chain. |
| C. Shell out to `icacls` / PowerShell | Rejected: path-based (race between check and use), locale-dependent output, ~100 ms+ per open. Allowed in TESTS only, to plant foreign ACEs. |

The locked rule "`#![deny(unsafe_code)]`" says an exception needs an ADR. ADR-016 will
record: the module path (`src/win_acl.rs`, `cfg(windows)` only, never compiled on unix),
its entire FFI surface (below), that every call is handle-based, and that no other
module may `allow(unsafe_code)`. A CI grep gate asserts `allow(unsafe_code)` appears in
`src/` only in that file plus the existing test-only `alloc_meter.rs:65`.
**Accepted by maintainer decision on 2026-09-27; vetoable until the implementing PR merges.**

FFI surface of `win_acl` (safe `pub(crate)` functions; the full memory-safety
contract of each is in ADR-016):

1. `current_user_sid() -> Sid`: `OpenProcessToken(TOKEN_QUERY)` + `GetTokenInformation(TokenUser)`; the SID is copied into an owned, length-checked buffer (`GetLengthSid`, `IsValidSid`). No global state.
2. `private_descriptor(kind: Dir|File) -> OwnedSd`: an absolute security descriptor, owner = user SID, a protected DACL (`SE_DACL_PROTECTED`) with ONE `ACCESS_ALLOWED` ACE (`FILE_ALL_ACCESS`, user SID); `Dir` adds `OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE`. Setting yourself as owner needs no privilege.
3. `create_dir_private(path) -> io::Result<()>`: `CreateDirectoryW(path, &SECURITY_ATTRIBUTES{ sd })`. **Atomic**: the directory never exists with any other DACL (review round 1, finding G1).
4. `create_file_private(path, share: Share) -> io::Result<File>`: `CreateFileW(path, GENERIC_READ|GENERIC_WRITE|READ_CONTROL, share, &SECURITY_ATTRIBUTES{ sd }, CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT)`, `INVALID_HANDLE_VALUE` checked before the handle becomes `File::from(OwnedHandle)`. `Share::Exclusive` (0) for scratch files; `Share::LockSidecar` (`FILE_SHARE_READ|FILE_SHARE_WRITE`, never `FILE_SHARE_DELETE`) for custody sidecars, so a contender can open the sidecar and reach `LockFileEx` (R2-2). **Atomic** as above; `CREATE_NEW` fails on any existing name, reparse point included.
5. `inspect(&File) -> io::Result<Inspection>`: `GetSecurityInfo(OWNER | DACL)`, ACEs walked with `GetAce` bounded by `AceCount` and each `AceSize`; returns owner SID, protected bit, NULL-DACL flag and (type, flags, SID, mask) per ACE. The handle must carry `READ_CONTROL` (G4).
6. `replace(tmp, dest) -> io::Result<()>`: `MoveFileExW(tmp, dest, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`. Write-through is the documented Windows guarantee that the call does not return until the rename is flushed to disk (G2).
7. `volume_is_local(&File) -> io::Result<bool>`: from the OPEN directory handle, `GetFinalPathNameByHandleW(VOLUME_NAME_DOS)` must not begin `\\?\UNC\`, `GetDriveTypeW` on its volume root (`GetVolumePathNameW`) must be `DRIVE_FIXED` or `DRIVE_REMOVABLE`, and `GetVolumeInformationByHandleW` must report `FILE_PERSISTENT_ACLS` (refuses FAT/exFAT, where no DACL exists to check) (G3).
8. `final_path(&File) -> io::Result<PathBuf>`: `GetFinalPathNameByHandleW(FILE_NAME_NORMALIZED | VOLUME_NAME_DOS)`, called twice (size, then fill) with the returned length checked against the buffer.

No `SetSecurityInfo`: with atomic creation nothing is ever re-protected, so no handle
needs `WRITE_DAC`/`WRITE_OWNER` (G4 resolved by removal, not by widening access).
Opening existing store objects, reparse checks and file flushes use safe std APIs
(`OpenOptionsExt::custom_flags`, `access_mode`, `MetadataExt::file_attributes`, `sync_all`).

### 2.2 What "owner-only" means on Windows

A file or directory is **private** iff, read from the OPEN handle:

- P1 a DACL is present (a NULL DACL grants everyone: refuse);
- P2 every ACCESS_ALLOWED ACE names the current user SID; ACCESS_DENIED ACEs are
  allowed (they only narrow); any other ACE type (object, callback, conditional) refuses;
- P3 at least one ACE grants the current user read+write;
- P4 the owner SID is the current user SID (the owner can rewrite the DACL, so an
  owner other than us is a foreign party with WRITE_DAC).

SYSTEM and BUILTIN\Administrators are NOT granted. Rationale: the unix rule is `0600`
with no root carve-out in the ACL sense; root bypasses modes, and on Windows an
administrator bypasses DACLs the same way through `SeBackupPrivilege` /
`SeTakeOwnershipPrivilege`. Granting them an ACE would add nothing against an admin
and would widen access for any process running as SYSTEM. This matches the POSIX
analogue exactly: the kernel-privileged principal is outside the model, everyone else
is refused.

**Elevated admin.** In an elevated token the default owner of new objects is often
BUILTIN\Administrators, not the user. `private_descriptor` therefore names the user
SID as owner explicitly (a token may always assign its own user as owner). Probe E3
confirms this on the elevated CI runner; if it fails, the fallback P4' = "owner is the
user OR the token's default owner" is an amendment for re-review, not a silent change.

**Inheritance.** P5: `SE_DACL_PROTECTED` is set on every object the stores create and
required on the two store directories, the lock sidecars and every file read. Because
creation is atomic (§2.1 items 3-4), a store object never carries an inherited ACE, so
a file moved in from elsewhere (keeping its foreign or inherited DACL) fails P2/P5
rather than passing by inheritance (test W-T13).

**Parent directories (G1, R2-1).** Atomic creation removes the create-then-protect
window, but every later operation is still a path (`dir.join(name)`), so a writable
ANCESTOR swapped for a junction after validation would redirect writes. Unix has the
same path-based exposure; Windows makes it likelier because `C:\ProgramData` lets
ordinary users create folders. The fix binds the store to its validated directory:

- `open`/`initialize` open each store directory once (BACKUP_SEMANTICS, no-follow,
  `share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)`, i.e. WITHOUT `FILE_SHARE_DELETE`)
  and HOLD that handle in the store for its lifetime, beside the custody lock.
- While a directory handle without delete-sharing is open, Windows refuses to rename
  or delete that directory or any ancestor of it (probe E6 must confirm; W-T16 and
  M15 pin it). So the path cannot be re-pointed while the store is open.
- Before holding it, the configured path is walked again component by component
  without following reparse points: every component must be a plain directory, and
  the last one must have the same `file_identity` as the held handle (§12 A1). This
  catches a swap between the R3 walk and the open. `volume_is_local` runs on the
  same handle.
- If E6 shows ancestors CAN be renamed under a held handle, the fallback is to keep
  every ancestor handle open the same way (bounded by path depth); that is an
  amendment for re-review.

### 2.3 Rule mapping

One shared module `src/private_fs.rs` (safe code; calls `win_acl` on Windows, modes on
unix) replaces the duplicated logic (`private_directory`, `has_mode`, `open_private`,
`set_owner_only`, `force_owner_only`, `sync_directory`, `sync_dir`). Unix behaviour is
unchanged byte for byte: the unix bodies move, they are not rewritten.

| Rule | Windows mechanism |
|---|---|
| R1/T1 private dir | open dir with `custom_flags(FILE_FLAG_BACKUP_SEMANTICS \| FILE_FLAG_OPEN_REPARSE_POINT)` and `access_mode(READ_CONTROL \| FILE_READ_ATTRIBUTES \| FILE_LIST_DIRECTORY)` (a handle with no data access records no sharing, so `FILE_LIST_DIRECTORY` is what makes the missing delete-share bind; R3-1); handle `file_attributes()` must be DIRECTORY and not REPARSE_POINT; `inspect` passes P1-P5; `volume_is_local` true; a no-follow re-walk of the configured path reaches the same `file_identity` (§12 A1); the handle is HELD for the store lifetime without `FILE_SHARE_DELETE` (§2.2 Parent directories) |
| R2/T5 create private dir | `create_dir_private` (atomic DACL), then open and judge exactly as R1. Missing ancestors are created with plain `create_dir` (they are outside the model, as on unix) |
| R3 path | lexical: accept `Prefix(Disk)` and `Prefix(VerbatimDisk)` followed by `RootDir` + `Normal`; refuse UNC, `Verbatim`/`VerbatimUNC`, `DeviceNS`. A drive letter can still map a network share, so locality is decided on the OPEN store directory handle by `volume_is_local` (G3), not by the prefix. Walk: every existing component must be a directory with no REPARSE_POINT attribute (covers symlinks AND junctions, which `is_symlink` misses) |
| R4/T4 create private file | `create_file_private` (atomic DACL, `CREATE_NEW`, share 0, reparse no-follow); the handle carries `GENERIC_READ\|GENERIC_WRITE` only, since nothing re-protects it |
| R5/R6/T3 read | open with `FILE_FLAG_OPEN_REPARSE_POINT` (Windows `O_NOFOLLOW`) and `access_mode(GENERIC_READ \| READ_CONTROL)` (G4); judge the HANDLE: regular file, no REPARSE_POINT attribute, `inspect` passes P1-P5, size bound. FIFOs do not exist in the filesystem namespace, so `O_NONBLOCK` has no analogue to carry |
| R7/T6 atomic replace | file `sync_all` (`FlushFileBuffers`), close, then `win_acl::replace` = `MoveFileExW(REPLACE_EXISTING \| WRITE_THROUGH)`. The directory fsync step maps to write-through; there is NO no-op fallback (G2). If `replace` fails the commit is refused before acknowledgement (`Staged`), exactly like a failed unix rename. The unix directory-sync step after rename becomes, on Windows, an explicit `FlushFileBuffers` on the directory handle (BACKUP_SEMANTICS, `GENERIC_WRITE`) where E1 shows it is supported; where it is not, write-through alone carries durability and this is stated, not silently skipped |
| R8/T7 custody | `try_acquire` off unix: `create_file_private(sidecar, Share::LockSidecar)`; on `AlreadyExists`, open it no-follow with `access_mode(GENERIC_READ \| GENERIC_WRITE \| READ_CONTROL)` and `share_mode(FILE_SHARE_READ \| FILE_SHARE_WRITE)`, require P1-P5. Both paths then call `File::try_lock()` (std, `LockFileEx` nonblocking; needs read or write access, which both handles carry). `TryLockError::WouldBlock` maps to `ErrorKind::WouldBlock` so `AlreadyOwned` is preserved; a sharing violation on open (a contender that did not exclude delete) also maps to `AlreadyOwned`. Atomic creation removes the create-then-protect race (review finding K1) |
| R9 initial authority | `initialize` writes through the store's own `replace_file` instead of `write_config_text`, on both platforms (the unix result is identical: `0600` + fsync + rename + dir sync) |

Open handles and rename (R3-2): `MoveFileExW(REPLACE_EXISTING)` fails while ANY handle
to the destination is open, `FILE_SHARE_DELETE` notwithstanding. So every in-process
read handle on a replaceable file is opened, read and closed under the same store
mutex the writer holds (the personal-account authority lock; the task store's
state lock), and never outlives the read. An EXTERNAL holder (an antivirus scan,
a backup agent) makes `replace` fail with a sharing violation: that is a `Staged`
refusal, retried at most 3 times with 10, 20 and 40 ms waits, then reported as
`StorageUnavailable` exactly like a failed unix rename.
Scratch names stay unique per attempt (a fresh 128-bit suffix in the account store, pid plus counter in the task store), so crash residue never blocks a later `CREATE_NEW`. Probe E2 runs the COMPLETE
production sequence (share-0 temp created, written, synced, closed, then replaced over a
destination another handle holds open) and is recorded, not assumed.

### 2.4 Migration

- Store data: none exists. Both stores have never run on Windows, so no Windows store
  directory can hold data to migrate. A pre-existing directory with inherited ACLs is
  refused with `InvalidConfiguration` / `UnsafeStore`, exactly as a `0755` directory is
  on unix.
- 3.x token source (D2): **refuse** a Windows 3.x token file that fails P1-P5 with
  `SourceRefusal::NotPrivate`, same as a `0644` file on unix. Rejected alternative:
  accept with a warning; it would import a credential other users may already have
  copied, and the unix path refuses the same condition.
- Remediation (G5): the refusal names WHICH rule failed (P1 NULL DACL, P2 foreign SID
  and which, P4 foreign owner, P5 inheritance) and gives the matching command, using
  `%USERDOMAIN%\%USERNAME%` so domain accounts work:
  - store directory: the reliable fix is to move it aside and let the gateway recreate
    it (no store data can pre-date this release on Windows);
  - 3.x token file: `icacls "<f>" /setowner "%USERDOMAIN%\%USERNAME%"` (P4), then
    `icacls "<f>" /inheritance:r /grant:r "%USERDOMAIN%\%USERNAME%:F"` (P5), then
    `icacls "<f>" /remove:g "*S-1-..."` (numeric SIDs need the `*` prefix) for each foreign SID the message lists (P2). The
    first step changes the owner, so when P4 is the failing rule the sequence must run
    from an elevated prompt (a standard user holds no right to take ownership); the
    refusal message says so. The migration re-checks P1-P5 after the operator runs these; W-T10b proves the sequence
    turns a refused file into an accepted one.

## 3. Tests (run on the `windows-2025` CI job)

- Un-gate: `commit.rs:40` repair tests, `journey/mod.rs:50-65`, and the store fixtures
  (`router/tests.rs:82`, `task_service/store_tests/support.rs:44`, `revoke_fixture.rs:281`,
  `account_resolver_fixture.rs:407`, `service_tests.rs:322`). Remove
  `--skip gateway:: --skip personal_accounts::` from `ci.yml:274-276`. Acceptance: those
  module trees run on Windows with zero failures attributable to store open (W1 keeps
  any unrelated residue, listed by test name).
- Delete `mod.rs:12-18` `expect(dead_code)` (it fails by design once the port lands).
- New `cfg(windows)` tests in `private_fs` (each plants its condition with `icacls`
  from test code, then asserts the refusal on the real store open):

| Test | Plant | Expect |
|---|---|---|
| W-T1 created dir/file is private | none | `inspect`: protected, one ACE, user SID, owner = user |
| W-T2 foreign ACE on store dir | `icacls d /grant *S-1-1-0:R` (Everyone) | `open` refuses (`InvalidConfiguration` / `UnsafeStore`) |
| W-T3 inherited ACE on store dir | `icacls d /inheritance:e` | refuses |
| W-T4 foreign ACE on `authority.json` / a record / `journeys.json` / task record / lease | grant Everyone | refuses |
| W-T5 junction in store path | `mklink /J` | `validate_path` / `prepare_dir` refuses |
| W-T6 symlink as record (needs dev mode; skip with a logged reason if `mklink` fails) | `mklink` | refuses |
| W-T7 UNC / `\\?\UNC` / `\\.\` config path | none | `InvalidConfiguration`; `C:\x` and `\\?\C:\x` accepted |
| W-T8 NULL DACL | PowerShell `Set-Acl` with SDDL `D:NO_ACCESS_CONTROL` (no unsafe in tests) | refuses, and the refusal REASON is `NullDacl` (P1). A NULL DACL also fails P3, so only the reason assertion can kill M9 |
| W-T8b allowed ACE without read+write | SDDL `O:<user>D:P(A;;FR;;;<user>)`: protected, one ACE for the user, owner = user, so P1, P2, P4 and P5 all pass | refuses with reason `NoReadWrite` (P3) |
| W-T9 custody across processes | child process (re-exec of the test binary) holds the store; parent opens | `AlreadyOwned` / `StorageUnavailable` (not `Unsupported`); after the child is KILLED the parent reacquires |
| W-T10 3.x token with inherited ACL | default-created file | `NotPrivate`, message lists the failed rule |
| W-T10b remediation works | W-T10 file PLUS an explicit Everyone grant and owner set to Administrators; run the §2.4 `icacls` sequence | migration accepts it |
| W-T11 foreign owner | `icacls f /setowner *S-1-5-32-544` | refuses (P4) |
| W-T12 mapped network drive | `net use X: \\localhost\C$` (runner is admin), store under `X:\` | `volume_is_local` on the `X:\` directory handle returns false (asserted directly), AND the store open refuses |
| W-T13 moved-in file | a file whose DACL is exactly one inherited (not protected) ACE for the user, owner = user, moved into the store under a valid name: fails ONLY P5 | refuses, reason `NotProtected` |
| W-T14 independent identity | CI step creates a local non-admin user; a child started with `Start-Process -Credential` tries to read `authority.json`, a record and a task record | access denied for all three (checks the DACL through the kernel, not through `inspect`) |
| W-T15 non-ACL volume | CI step creates and mounts a FAT32 VHD with `diskpart` (runner is admin); store on it | `volume_is_local` on the FAT32 directory handle returns false (asserted directly; P1-P5 would also refuse, so only this assertion kills M14), AND the store open refuses |
| W-T16a pin holds the store directory itself | guard-level: hold the store directory handle ALONE (no custody sidecar, no files open), then rename that empty directory and replace it with a junction | both fail with a sharing violation; this is the test M15 must redden (an open descendant would otherwise mask it) |
| W-T16 ancestor swap | with the store open, a second thread tries to rename the store directory's parent and to replace it with a junction | both fail; store still reads its own files |
| W-T17 read/replace ordering | barrier-controlled: a reader thread opens the record inside the mutex and signals; the writer then commits | the commit succeeds on its first `replace` attempt (asserted via a test-only attempt counter), and the reader saw a committed version. Deterministic, and independent of antivirus timing |
| W-T18 final-path check | store at `C:\\t\\a\\store`; a `cfg(test)` fault boundary fires between the R3 walk and the directory open, and there replaces ancestor `a` with a junction to another directory holding a valid private `store` of the same user | refuses with reason `PathMismatch` (nothing else refuses: the target is private and local, so only M18 turns this green) |

W-T14, W-T15 and the `net use` part of W-T12 run in a dedicated Windows CI step (`--ignored` filter by name) so
they need no privilege in the default test run.

## 4. Probes before implementation (throwaway CI PR, Windows job)

Each answers one question the design otherwise assumes; the answer is recorded here
as an amendment before the red commit. The probe PR carries only a `cfg(windows)`
test file; any probe needing Win32 waits for the maintainer's `unsafe` decision.

- E1 directory flush: open with `FILE_FLAG_BACKUP_SEMANTICS` and `GENERIC_WRITE`, then `sync_all`: supported / error code (decides the R7 directory step).
- E2 the full replace sequence (share-0 temp, write, sync, close, `MoveFileExW` write-through) over a destination another std handle holds open: works / sharing violation.
- E3 elevated runner: default owner of a new file, and `CreateFileW` with owner = user SID accepted.
- E4 `File::try_lock` on a second handle in the same process returns `WouldBlock`; lock released when a killed child's handle closes.
- E5 `GetFinalPathNameByHandleW` / `GetDriveTypeW` on a `net use` drive letter report remote.
- E2b `MoveFileExW(REPLACE_EXISTING | WRITE_THROUGH)` over a destination held open by a std read handle: fails (expected), confirming R3-2.
- E6 while a handle to `C:\\a\\b\\store` is held WITHOUT `FILE_SHARE_DELETE`, renaming `C:\\a\\b` and `C:\\a` fails (sharing violation), and so does replacing either with a junction.

### 4.1 Probe results (throwaway PR #1508, CI run 36279012847, job 108507160087, windows-2025)

| Probe | Result | Amendment |
|---|---|---|
| E1 directory flush | `sync_all` on a directory handle opened with BACKUP_SEMANTICS succeeds with `GENERIC_WRITE` (with or without `GENERIC_READ`); read-only gives `ERROR_ACCESS_DENIED` | R7 directory step is MANDATORY on Windows: `sync_dir` = BACKUP_SEMANTICS + `GENERIC_WRITE` + `sync_all`. M32 applies |
| E2 / E2b replace | `MoveFileExW(REPLACE_EXISTING \| WRITE_THROUGH)` over a destination a std reader holds open fails with `ERROR_ACCESS_DENIED` (5), not a sharing violation; after the reader closes it succeeds. Std `fs::rename` over the same open reader SUCCEEDS (current std uses POSIX rename semantics) | R3-2 retry triggers on `ERROR_ACCESS_DENIED` and `ERROR_SHARING_VIOLATION`. Design unchanged otherwise: write-through `MoveFileExW` is kept for its documented durability |
| E3 owner | runner token is the built-in Administrator (RID 500), elevated; a std-created file is owned by BUILTIN\Administrators, unprotected, 3 ACEs; `create_file_private` / `create_dir_private` give owner = user, protected, exactly one allow ACE (`FILE_ALL_ACCESS`; directories `OI\|CI`) | Confirms §2.2: explicit owner is required and works elevated. P4' fallback not needed |
| E4 custody | `try_lock` on a second shared handle returns `WouldBlock`; after the first handle drops, it succeeds | Confirms R8 |
| E5 network drive | a `net use` drive letter's final path is `\\?\UNC\localhost\C$\...`; `volume_is_local` false; a local temp dir true | Confirms G3 via the UNC leg; W-T12 is primary, W-T12b not needed |
| E6 pinning | handle WITH `FILE_LIST_DIRECTORY`, no delete share: renaming the store dir fails 32, parent and grandparent fail 5. Metadata-only handle: store-dir rename SUCCEEDS, ancestors still fail 5 | Confirms R3-1 (data access is what pins the directory itself) and R2-1 (ancestors pinned). W-T16a expects 32; W-T16 expects 5 for ancestors. No ancestor-handle fallback needed |

No probe contradicts the design.

## 5. Mutation proof (one throwaway PR each; named test must redden)

| Mutant | Reddens |
|---|---|
| M1 P2 check removed (any ACE accepted) | W-T2, W-T4 |
| M2 descriptor omits PROTECTED flag | W-T1, W-T3 |
| M3 REPARSE_POINT attribute check removed | W-T5 |
| M4 `Prefix` whitelist accepts UNC | W-T7 |
| M5 task-store privacy predicate returns `true` (today's `has_mode`) | W-T4 (task record, lease) |
| M6 owner check removed | W-T11 |
| M7 `try_acquire` skips `try_lock` | W-T9 (the contender now opens the shared sidecar, so only the lock can stop it) |
| M8 `initialize` back on `write_config_text` | W-T1 on `authority.json` |
| M9 NULL-DACL check removed | W-T8 |
| M10 read+write requirement removed | W-T8b |
| M11 `volume_is_local` returns `true` | W-T12 |
| M12 P5 not required on read | W-T13 |
| M14 `FILE_PERSISTENT_ACLS` leg of `volume_is_local` removed | W-T15 |
| M15 store directory handle opened with `FILE_SHARE_DELETE` | W-T16a |
| M16 held directory handle drops `FILE_LIST_DIRECTORY` | W-T16a |
| M17 in-process reader keeps its handle past the store mutex | W-T17 |
| M18 `final_path` comparison skipped | W-T18 |
| M13 `create_file_private` falls back to std `create_new` (inherited DACL) | W-T1 (protected bit and single ACE) |

## 6. Risks

- The ADR is a precedent for `unsafe`; mitigated by one file, a grep gate, handle-only
  calls, and no unix compilation.
- Developer-mode-dependent symlink test (W-T6) may skip on CI; junctions (W-T5) cover the
  reparse rule without privilege.
- Admin bypass is by design (as root on unix); documented in SECURITY.md.
- `MoveFileExW` write-through replaces std `fs::rename` on Windows only; unix keeps
  `rename` + directory `fsync` unchanged.
- Crash durability is argued from the Win32 contracts, not demonstrated by a power cut
  (not possible on hosted runners).
- W-T14 creates a local user on the CI runner (ephemeral VM); never run on a developer host.

## 7. Docs

UPGRADING-4.0 item 68: Windows now runs both stores; an
existing store directory with inherited ACLs is refused, with the fix. It and
DEPLOYMENT.md also state that a store path containing ANY reparse point (junction,
volume mount point, OneDrive-redirected profile folder) or a network drive is refused,
and recommend `%LOCALAPPDATA%\\mcp-gateway`. CHANGELOG under
Unreleased. SECURITY.md "Windows file permissions" rewritten for the two stores.
DEPLOYMENT.md Windows notes. ADR-016.


## 8. Review round 1 dispositions

| Id | Finding | Disposition |
|---|---|---|
| G1 CRITICAL | dir created, then protected; private-parent premise never established | Fixed: atomic `CreateDirectoryW`/`CreateFileW` with the descriptor (§2.1 items 3-4); premise withdrawn (§2.2) |
| G2 CRITICAL | no-op directory-sync fallback loses acknowledged renames | Fixed: fallback deleted; `MoveFileExW` write-through; E1 probes the directory flush with the right flags and access (§2.3 R7, §4) |
| G3 CRITICAL | drive letter can be a network share | Fixed: `volume_is_local` on the open handle (remote path, drive type, persistent ACLs); W-T12, M11 |
| G4 HIGH | handles lack `WRITE_DAC`/`WRITE_OWNER` | Resolved by removal: no post-creation `SetSecurityInfo`; reads request `READ_CONTROL` explicitly |
| G5 MEDIUM | `icacls` remediation leaves foreign grants and owner | Fixed: rule-specific messages and command sequence; W-T10b proves it |
| G-I1 | second identity, real child processes | Adopted: W-T14, W-T9 child process + kill/reacquire |
| G-I2 | E2 must run the full sequence | Adopted: E2 rewritten |
| G-I3 | ADR memory-safety contract | Adopted: ADR-016 §Safety contract |
| K1 LOW | sidecar create/protect race gives wrong error | Removed by atomic creation (§2.3 R8) |
| K-I1 | mutants for P1/P3 | Adopted: M9, M10, W-T8b |
| K-I2 | probe create+reparse flag; non-NTFS volume | Create path is now `CreateFileW` with `CREATE_NEW`; non-ACL volume refused by `FILE_PERSISTENT_ACLS` (W-T15) |
| K-I3 | lead with write-through, not the no-op | Adopted (same as G2) |
| K-I4 | `%USERDOMAIN%\%USERNAME%` | Adopted (§2.4) |
| K-I5 | test the moved-in file claim | Adopted: W-T13, M12 |


## 9. Review round 2 dispositions

| Id | Finding | Disposition |
|---|---|---|
| R2-1 CRITICAL | a writable ancestor swapped for a junction after validation redirects writes | Fixed: store directory handle held without delete-sharing for the store lifetime, final-path check before holding (§2.2); E6, W-T16, M15 |
| R2-2 HIGH (both seats) | sidecar share-0 blocks contenders; `READ_CONTROL` alone cannot `LockFileEx` | Fixed: `Share::LockSidecar`, read+write+`READ_CONTROL` on both create and reopen (§2.1 item 4, §2.3 R8); M7 now reachable |
| R2-3 HIGH | ADR treats every zero return as failure; misses `INVALID_HANDLE_VALUE` | Fixed: ADR-016 §6 now gives each API's own return contract |
| R2-4 MEDIUM | M9, M12, M13 masked by other checks | Fixed: W-T8 asserts the refusal reason; W-T13 fixture fails only P5; M13 assigned to W-T1 |
| R2-5 MEDIUM | `icacls /remove:g` needs `*` before a numeric SID; W-T10b too weak | Fixed (§2.4); W-T10b adds a foreign grant and foreign owner |
| R2-6 MEDIUM | M7 toothless under share-0 | Fixed by R2-2 |
| R2-I1 | M14 for the persistent-ACL leg; W-T15 unconditional | Adopted: M14; W-T15 mounts a FAT32 VHD with `diskpart` |
| R2-I2 | document reparse-point / OneDrive refusal | Adopted (§7) |
| R2-I3 | W1 residue list with expiry | Adopted: the PR lists every remaining Windows failure by test name with its owning issue; none may be attributable to store open |
| R2-I4 | crash-recovery validation | Partly adopted: hosted runners cannot cut power, so durability rests on the documented `MOVEFILE_WRITE_THROUGH` and `FlushFileBuffers` contracts plus E1/E2; stated as a residual risk in §6 |
| R2-I5 | per-function memory invariants in the ADR | Adopted: ADR-016 §Per-function contract |

## 10. Review round 3 dispositions

| Id | Finding | Disposition |
|---|---|---|
| R3-1 CRITICAL | held directory handle has no data access, so its missing delete-share is not enforced | Fixed: `FILE_LIST_DIRECTORY` added (§2.3 R1); W-T16a renames the held empty directory itself; M16 |
| R3-2 HIGH | `MoveFileExW` cannot replace a destination any handle holds open | Fixed: in-process read handles opened and closed under the writer's mutex; external holders get a bounded 3-try retry then `StorageUnavailable` (§2.3); E2b, W-T17, M17 |
| R3-3 MEDIUM | `GetVolumePathNameW` is a BOOL API, not a sizing API | Fixed in ADR-016 §6 |
| R3-4 MEDIUM | `GetLengthSid` called before `IsValidSid` | Fixed: header bounded, then `IsValidSid`, then `GetLengthSid` (ADR-016 per-function contract) |
| R3-5 MEDIUM | M15 masked by an open descendant | Fixed: M15 assigned to W-T16a (empty held directory, no descendants open) |
| R3-6 MEDIUM | M14 masked by P1-P5 on FAT32 | Fixed: W-T15 asserts `volume_is_local` directly |
| R3-I1 | assert `volume_is_local` directly for the mapped drive | Adopted (W-T12) |
| R3-I2 | deterministic kill at commit boundaries | Covered by un-gating the existing fault-boundary and crash suites (`crash_tests.rs`, `repair_tests.rs`, the `faults` boundaries), which then run on Windows |


## 11. Review round 4

Both seats: SHIP. Remaining items folded in without changing the design:
elevation note for the P4 remediation (§2.4); W-T17 made barrier-controlled and
independent of antivirus timing; W-T8b pins P3 alone; W-T18 and M18 pin the final-path
check; the `unsafe` fence covers `src/`, `build.rs`, `benches/` and `examples/`
(ADR-016); scratch-name uniqueness stated (§2.3).

## 12. Implementation amendments

Found by the first full Windows run of the implementation (CI run 36337890807).

- A1, final-path check. The configured path and `GetFinalPathNameByHandleW` disagree
  whenever the path holds an 8.3 short name: the runner's temp directory is
  `C:\Users\RUNNER~1\...`, its final path is the long name, so every reopen refused
  with `PathMismatch`. Expanding short names needs a path lookup that follows
  reparse points, which is the thing being checked. The check is now a no-follow
  re-walk of the configured path after the open: any reparse point on the way
  refuses, and the last component's `file_identity` (volume serial, 128-bit file id)
  must equal the held handle's. W-T18 and M18 are unchanged: a junction swapped in
  for an ancestor refuses with `PathMismatch`.
- A2, lock release. Windows releases the byte-range lock of a closed handle "when
  system resources allow", not at close, so a reopen straight after a drop met the
  old lock (`StorageUnavailable` / `AlreadyOwned` across the account and task store
  suites). The custody lock guard now unlocks explicitly in `Drop`, as the unix guard
  already does with `flock`.
- A3, fixtures. The whole-file lock refuses even a zero-length read of the empty task
  store lease while the store is open, so the store test oracles take an empty
  file's bytes from its length, and `store_01` checks name, count and layout but
  not bytes at Flush and FileSync, where the scratch record is still held with no
  sharing. The 3.x source fixtures plant an owner-only
  descriptor on Windows where they `chmod 0600` on unix. The W-T10b row runs each
  printed `icacls` line verbatim through `cmd`, as a user pastes it.

Found by the final code review and the first mutation runs:

- A4, held directory handles. The judged directory handles are now kept, without delete
  sharing, beside the custody lock for the store's life (§2.2 as written). The first
  implementation dropped them after judging, leaving a swap window before custody; W-T16b
  pins the window. A task store directory created on open is judged like an existing one
  (W-T5/task), and its missing ancestors are created owner-only, as unix creates them `0700`.
- A5, P3. An inherit-only grant does not count toward P3 (W-T8c), a deny naming the user that
  removes read or write fails it (W-T8d), and a `GENERIC_READ|GENERIC_WRITE` grant satisfies
  it (W-T8e). A deny for a group is not resolved: it can only fail closed.
- A6, W-T22. The trace reads the write-through bit from the flags constant passed to
  `MoveFileExW`, so M24 changes what the row observes.
- A7, W-T7 and W-T26. W-T7 gains lexical rows that call `validate_path` alone: through a full
  store open, the locality check refused UNC paths too and hid M4. W-T26 and the scratch-name
  redraw it needs were missing; the account store now redraws a scratch name on residue
  (Windows only; unix keeps its single attempt and no longer deletes a file already at a
  colliding name).
- A8, bounds. Owner SID and DACL reads in `win_acl::inspect` are bounded by the descriptor's
  own length (`GetSecurityDescriptorLength`), not by the maximum SID size.
- A9, 3.x repair text. A runnable repair is printed only for a path made of letters,
  digits, space and `\ : . _ - ( )` (an allowlist, since an administrator may run it
  elevated); any other path gets written instructions and no runnable line (W-T10f), and
  an allowed path gets lines that repair it (W-T10h). The lines are for Windows
  PowerShell: single-quoted literal paths, with every quote character PowerShell
  recognises doubled as a second layer. They name the gateway account by its SID, so they
  stay right in an elevated prompt run as another account. Ownership, when foreign, is
  taken first with `icacls /setowner`; the DACL is then replaced in one write with a
  protected DACL holding only the gateway account's grant, so no intermediate state
  exposes the file (a separate `icacls /reset` would briefly restore inherited access).
  A NULL DACL no longer hides a foreign owner (W-T10g). W-T10b, W-T10d and W-T10e run the
  printed lines and require the file accepted afterwards.
