# ADR-016: One scoped `unsafe` module for Windows owner-only file security

- **Status**: Proposed, 2026-09-26. Awaiting maintainer decision; no code lands before it.
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

The module exports seven safe `pub(crate)` functions and nothing else:
`current_user_sid`, `private_descriptor`, `create_dir_private`, `create_file_private`,
`inspect`, `replace`, `volume_is_local` (design §2.1). Callers never see a raw handle,
pointer or Win32 type.

A CI check fails the build if `allow(unsafe_code)` or `expect(unsafe_code)` appears in
`src/` anywhere except `src/win_acl.rs` and the existing test-only
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
6. **Errors.** A zero or false return from any Win32 call becomes
   `io::Error::last_os_error()` immediately, before any other call can overwrite the
   thread's last-error value.
7. **No global state.** No statics, no caching of SIDs or descriptors across calls.

## Consequences

- Windows gets owner-only stores; the refusals that account for most Windows test
  failures go away.
- The crate's `unsafe` surface is no longer zero on Windows. It is one reviewed file
  with a written contract and a CI fence, and it is absent from unix builds.
- The same module can later give the config file, mTLS keys and 3.x OAuth tokens
  owner-only permissions on Windows; that is a separate change.
- Adding any new Win32 call to `win_acl.rs` is an amendment to this ADR.
