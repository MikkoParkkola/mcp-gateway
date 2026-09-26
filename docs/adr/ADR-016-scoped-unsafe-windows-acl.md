# ADR-016: One scoped `unsafe` module for Windows owner-only file security

- **Status**: Accepted, 2026-09-27 (maintainer decision: option A, one Windows-only file of
  `unsafe` code). Vetoable until the implementing PR merges; that PR states the exception
  at the top of its summary.
- **Relates to**: `#![deny(unsafe_code)]` (`src/lib.rs:24`), `SECURITY.md` "Windows file
  permissions", design `docs/design/2026-09-26-windows-owner-only-stores.md`.

## Context

4.0 ships a Windows binary, and the maintainer has decided that the task store and the
personal-account store must run on Windows with security equivalent to unix. On unix
both stores rely on owner-only modes (`0600`/`0700`), checked on the open handle.
Windows has no modes. The equivalent is a protected DACL that grants only the current
user, set when the object is created and verified on every open.

The Rust standard library cannot create an object with a chosen security descriptor
and cannot read a DACL. Every route to one goes through Win32 functions, which are
`unsafe` to call from Rust. The crate denies `unsafe` code; `SECURITY.md` already names
"a safe wrapper for the Win32 call" as the fix for this gap.

Alternatives considered:

- A safe-wrapper crate. The candidates on crates.io (`windows-permissions` 0.2.4,
  `windows-acl` 0.3.0, `windows-security` 0.23.0) had their last releases in 2021-2022.
  Adopting one moves the same `unsafe` into an unmaintained dependency we do not review.
- Running `icacls` or PowerShell at runtime. Path-based rather than handle-based (the
  checked file and the opened file can differ), locale-dependent output, and about a
  tenth of a second per open. Kept for tests only, to plant foreign ACLs.
- Keeping the stores unix-only. Rejected by the maintainer decision above.

## Decision

Allow `unsafe` in exactly one module, `src/win_acl.rs`, compiled only on Windows
(`#[cfg(windows)]`, so unix builds contain no new `unsafe`). It calls `windows-sys`
0.61.2, which is already in `Cargo.lock` through `mio`, `socket2`, `errno`, `dirs-sys`
and `schannel`; the change adds it as a direct Windows-only dependency with the
`Win32_Foundation`, `Win32_Security`, `Win32_Security_Authorization`,
`Win32_Storage_FileSystem` and `Win32_System_Threading` features and adds no package to
the lock file.

The module exports nine safe `pub(crate)` functions and nothing else:
`current_user_sid`, `private_descriptor`, `create_dir_private`, `create_file_private`,
`inspect`, `replace`, `volume_is_local`, `final_path` (design §2.1), and
`file_identity` (volume serial and file index, used by the store tests and by the
transparency-log rotation fix so Windows has one audited Win32 wrapper). Callers never see a raw handle,
pointer or Win32 type.

A CI check fails the build if `allow(unsafe_code)`, `expect(unsafe_code)` or an
`unsafe` block appears in `src/`, `build.rs`, `benches/` or `examples/` anywhere except `src/win_acl.rs` and the existing test-only
`src/gateway/server/tests/alloc_meter.rs`.

## Safety contract

Every `unsafe` block carries a `// SAFETY:` comment naming which of these it relies on.

1. **Ownership.** Every buffer passed to Win32 is a Rust-owned `Vec<u8>` or a
   stack value that outlives the call. Buffers Win32 allocates (`GetSecurityInfo`'s
   security descriptor) are wrapped at once in an owner type whose `Drop` calls
   `LocalFree`, exactly once. Handles are wrapped in `OwnedHandle` on return, so the
   standard library closes them.
2. **Alignment.** SID and ACL buffers are allocated as `Vec<u64>` (8-byte alignment,
   above the 4-byte alignment `ACL` and `SID` need) and viewed as bytes.
3. **Bounds.** A SID is accepted only after `IsValidSid`, and its length comes from
   `GetLengthSid`, never from our own arithmetic. The ACE walk is bounded by the ACL's
   `AceCount`; every ACE header is read through `GetAce`, and an ACE whose `AceSize`
   would run past `AclSize` is a refusal, not a read.
4. **Lifetimes.** Pointers returned inside a security descriptor (owner, DACL) are
   used only while the owning wrapper from point 1 is alive; they are copied into owned
   values before it drops.
5. **Strings.** Paths are converted with `OsStrExt::encode_wide` plus a trailing NUL,
   and a path containing an interior NUL is refused before any call.
6. **Errors.** There is no universal rule; each API's own contract is followed, and
   the error value is captured before any other call can overwrite it:
   - `BOOL` APIs (`OpenProcessToken`, `GetTokenInformation`, `CreateDirectoryW`,
     `MoveFileExW`, `GetVolumePathNameW`, `GetFileInformationByHandle`, `GetVolumeInformationByHandleW`,
     `InitializeAcl`, `AddAccessAllowedAceEx`, `InitializeSecurityDescriptor`,
     `SetSecurityDescriptorOwner`, `SetSecurityDescriptorDacl`,
     `SetSecurityDescriptorControl`, `GetAce`): zero is failure, then
     `io::Error::last_os_error()`.
   - `GetSecurityInfo` returns a `WIN32_ERROR`: `ERROR_SUCCESS` (0) is success, any
     other value is the error itself (`io::Error::from_raw_os_error`); last-error is
     not consulted.
   - `CreateFileW` fails with `INVALID_HANDLE_VALUE`, never null; that is checked
     before the value is wrapped in `OwnedHandle`.
   - `GetFinalPathNameByHandleW` returns a length: zero is failure; a return >= the
     buffer length means "retry with this size", done once.
   - `GetVolumePathNameW` is a `BOOL` API (listed above), not a sizing API: it is given
     a zero-initialised buffer of `MAX_PATH` + the input path length UTF-16 units, and
     the terminator is searched for within that length.
   - `GetDriveTypeW` returns a type code, never an error; only the accepted codes pass.
   - `IsValidSid` false means invalid input: refuse without consulting last-error.
7. **No global state.** No statics, no caching of SIDs or descriptors across calls.

## Per-function contract

- `current_user_sid`: `GetTokenInformation(TokenUser)` is called first with a zero
  buffer to get the size, then into a `Vec<u64>`-backed buffer of at least that size
  (TOKEN_USER holds a pointer, so 8-byte alignment is required). The returned `Sid`
  pointer points INTO that buffer; its header is bounded against the buffer end as in
  `inspect`, then `IsValidSid`, then `GetLengthSid`, then it is copied out. The token
  handle is an `OwnedHandle`.
- `private_descriptor`: builds an ABSOLUTE descriptor. The `SECURITY_DESCRIPTOR`, the
  owner SID and the ACL each live in their own `Vec<u64>` inside the returned
  `OwnedSd`, which is not `Clone` and is kept alive for as long as any
  `SECURITY_ATTRIBUTES` points at it. The ACL size is computed as
  `size_of::<ACL>() + size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>() + sid_len`,
  with checked arithmetic.
- `create_dir_private` / `create_file_private`: the `SECURITY_ATTRIBUTES` and the wide
  path live on the caller's stack for the duration of the call.
- `inspect`: the descriptor returned by `GetSecurityInfo` is owned by a `LocalFree`
  guard; the owner and DACL pointers are read only while it lives. For each ACE from
  `GetAce`: the header's `AceSize` must be at least the fixed part of that ACE type,
  and the SID starting at `SidStart` is bounded BEFORE any SID API touches it: the
  8-byte SID header must fit in the ACE, its `SubAuthorityCount` byte is read, and
  `8 + 4 * SubAuthorityCount` must fit in the remaining ACE bytes. Only then is
  `IsValidSid` called, then `GetLengthSid` (whose precondition is a valid SID), and its
  result must equal the bounded length before the SID is copied. The owner SID from
  the descriptor gets `IsValidSid` before `GetLengthSid` for the same reason. Only
  `ACCESS_ALLOWED_ACE_TYPE` and `ACCESS_DENIED_ACE_TYPE` are decoded; any other type is
  reported as "other" without reading past its header, and the caller refuses it.
- `replace`: two NUL-terminated wide paths on the stack.
- `file_identity`: one `BY_HANDLE_FILE_INFORMATION` on the stack, written by the call.
- `volume_is_local` / `final_path`: output buffers sized from the first call, lengths
  checked against the buffer before the `&[u16]` slice is formed.

## Consequences

- Windows gets owner-only stores; the refusals that account for most Windows test
  failures go away.
- The crate's `unsafe` surface is no longer zero on Windows. It is one reviewed file
  with a written contract and a CI fence, and it is absent from unix builds.
- The same module can later give the config file, mTLS keys and 3.x OAuth tokens
  owner-only permissions on Windows; that is a separate change.
- Adding any new Win32 call to `win_acl.rs` is an amendment to this ADR.
