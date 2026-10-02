// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Win32 security calls behind owner-only stores on Windows (ADR-016).
//!
//! The ONLY module in the crate allowed `unsafe`. Every export is a safe
//! function; callers never see a raw handle, pointer or Win32 type. Each
//! `unsafe` block names the ADR-016 safety-contract points it relies on.
#![allow(unsafe_code)]

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs::File;
use std::io;
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_REVISION, AddAccessAllowedAceEx,
    CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, GetAce, GetKernelObjectSecurity,
    GetLengthSid, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
    GetSecurityDescriptorLength, GetSecurityDescriptorOwner, GetTokenInformation, InitializeAcl,
    InitializeSecurityDescriptor, IsValidSid, OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
    SetSecurityDescriptorControl, SetSecurityDescriptorDacl, SetSecurityDescriptorOwner,
    TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateDirectoryW, CreateFileW, DELETE, FILE_ALL_ACCESS, FILE_DISPOSITION_INFO,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO, FILE_NAME_NORMALIZED, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK, FileDispositionInfo, FileIdInfo,
    GetDriveTypeW, GetFileInformationByHandleEx, GetFileType, GetFinalPathNameByHandleW,
    GetVolumeInformationByHandleW, GetVolumePathNameW, MOVEFILE_REPLACE_EXISTING,
    MOVEFILE_WRITE_THROUGH, MoveFileExW, READ_CONTROL, SetFileInformationByHandle, VOLUME_NAME_DOS,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

// Fixed ABI values, declared here rather than enabling two more windows-sys
// feature modules for four integers.
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;
const DRIVE_REMOVABLE: u32 = 2;
const DRIVE_FIXED: u32 = 3;
const FILE_PERSISTENT_ACLS: u32 = 8;
/// Fixed part of a SID: revision, sub-authority count, 6-byte authority.
const SID_HEADER: usize = 8;

/// An owned, validated SID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Sid(Vec<u8>);

impl Sid {
    /// SDDL-style `S-R-A-S1-...` rendering, for refusal messages.
    pub(crate) fn to_sddl(&self) -> String {
        let b = &self.0;
        let authority = b[2..8]
            .iter()
            .fold(0_u64, |acc, x| (acc << 8) | u64::from(*x));
        let mut out = format!("S-{}-{authority}", b[0]);
        for chunk in b[SID_HEADER..].as_chunks::<4>().0 {
            let _ = write!(out, "-{}", u32::from_le_bytes(*chunk));
        }
        out
    }

    /// A SID from its authority and sub-authorities: well-known SIDs for
    /// value comparison, and synthetic `Inspection` values in tests. A SID has
    /// at most 15 sub-authorities; the count saturates rather than panics.
    pub(crate) fn from_parts(authority: u8, subs: &[u32]) -> Self {
        let mut b = vec![
            1,
            u8::try_from(subs.len()).unwrap_or(u8::MAX),
            0,
            0,
            0,
            0,
            0,
            authority,
        ];
        for s in subs {
            b.extend_from_slice(&s.to_le_bytes());
        }
        Self(b)
    }
}

/// Which kind of object a descriptor is for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObjectKind {
    Dir,
    File,
}

/// Share mode for a created file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Share {
    /// No sharing: scratch files.
    Exclusive,
    /// Read and write sharing, never delete: custody sidecars.
    LockSidecar,
}

/// One decoded ACE.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Ace {
    Allowed {
        flags: u8,
        mask: u32,
        sid: Sid,
    },
    Denied {
        flags: u8,
        mask: u32,
        sid: Sid,
    },
    /// Any other ACE type; its body is never read.
    Other {
        ace_type: u8,
    },
}

/// What `inspect` read from an open handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Inspection {
    pub(crate) owner: Option<Sid>,
    /// `None` is a NULL DACL (grants everyone).
    pub(crate) dacl: Option<Vec<Ace>>,
    pub(crate) protected: bool,
}

/// UTF-16, NUL-terminated; refuses an interior NUL (ADR-016 contract 5).
fn wide(path: &Path) -> io::Result<Vec<u16>> {
    let w: Vec<u16> = OsStr::new(path).encode_wide().collect();
    if w.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains NUL",
        ));
    }
    let mut w = long_form(path, w)?;
    w.push(0);
    Ok(w)
}

/// std's `get_long_path` rule, so these calls reach every path `std::fs`
/// does without the long-path opt-in: at or past `CreateDirectoryW`'s 248-unit
/// limit the absolute path gets the verbatim prefix (`\\?\`, UNC as
/// `\\?\UNC\`); a verbatim or shorter path reaches Win32 unchanged, and
/// one long only as written (`..`) reaches it resolved.
fn long_form(path: &Path, w: Vec<u16>) -> io::Result<Vec<u16>> {
    const LEGACY_MAX_PATH: usize = 248;
    let starts = |w: &[u16], p: &str| {
        p.encode_utf16()
            .enumerate()
            .all(|(i, c)| w.get(i) == Some(&c))
    };
    if w.is_empty() || starts(&w, r"\\?\") || starts(&w, r"\??\") {
        return Ok(w);
    }
    // GetFullPathNameW: absolute, `/` → `\`, `..` resolved (verbatim skips that).
    let abs: Vec<u16> = std::path::absolute(path)?
        .as_os_str()
        .encode_wide()
        .collect();
    if abs.len() + 1 < LEGACY_MAX_PATH {
        // Short once resolved: the written form unless that is the long one.
        return Ok(if w.len() + 1 < LEGACY_MAX_PATH {
            w
        } else {
            abs
        });
    }
    let (prefix, rest) = if starts(&abs, r"\\?\") || starts(&abs, r"\??\") {
        ("", &abs[..])
    } else if starts(&abs, r"\\.\") {
        (r"\\?\", &abs[4..])
    } else if starts(&abs, r"\\") {
        (r"\\?\UNC\", &abs[2..])
    } else if abs.get(1) == Some(&u16::from(b':')) {
        (r"\\?\", &abs[..])
    } else {
        ("", &abs[..])
    };
    Ok(prefix.encode_utf16().chain(rest.iter().copied()).collect())
}

/// A zeroed, 8-byte-aligned buffer of at least `bytes` bytes (contract 2).
fn aligned(bytes: usize) -> Vec<u64> {
    vec![0_u64; bytes.div_ceil(8)]
}

/// Copy a SID that starts at `ptr` and is known to lie inside `avail` bytes.
/// The header is bounded before any SID API touches it (contract 3).
///
/// # Safety
/// `ptr` must be valid for reads of `avail` bytes.
unsafe fn copy_sid(ptr: *const u8, avail: usize) -> io::Result<Sid> {
    let bad = || io::Error::new(io::ErrorKind::InvalidData, "malformed SID");
    if avail < SID_HEADER {
        return Err(bad());
    }
    // SAFETY: contract 3 — `SID_HEADER <= avail`, so byte 1 is in bounds.
    let count = usize::from(unsafe { *ptr.add(1) });
    let len = SID_HEADER + 4 * count;
    if len > avail {
        return Err(bad());
    }
    // SAFETY: contract 3 — the whole SID is inside the readable range.
    if unsafe { IsValidSid(ptr as PSID) } == 0 {
        return Err(bad());
    }
    // SAFETY: contract 3 — `IsValidSid` passed, the precondition of GetLengthSid.
    let reported = unsafe { GetLengthSid(ptr as PSID) } as usize;
    if reported != len {
        return Err(bad());
    }
    // SAFETY: contract 1/3 — `len` bytes are readable and copied into owned memory.
    Ok(Sid(unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec()))
}

/// Last OS error as `io::Error`, captured immediately (contract 6).
fn last() -> io::Error {
    io::Error::last_os_error()
}

/// The SID of the user this process runs as.
pub(crate) fn current_user_sid() -> io::Result<Sid> {
    let mut raw: HANDLE = std::ptr::null_mut();
    // SAFETY: contract 1/6 — out-pointer to a stack HANDLE; BOOL result checked.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut raw) } == 0 {
        return Err(last());
    }
    // SAFETY: contract 1 — a fresh, valid handle we now own exactly once.
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut len = 0_u32;
    // SAFETY: contract 6 — sizing call with a null buffer; failure is expected.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            std::ptr::null_mut(),
            0,
            &raw mut len,
        );
    }
    if len == 0 {
        return Err(last());
    }
    let mut buf = aligned(len as usize);
    let bytes = buf.len() * 8;
    // SAFETY: contract 1/2 — an 8-byte-aligned owned buffer of `bytes` >= `len`.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buf.as_mut_ptr().cast(),
            u32::try_from(bytes).map_err(|_| io::Error::other("token too large"))?,
            &raw mut len,
        )
    } == 0
    {
        return Err(last());
    }
    let base = buf.as_ptr().cast::<u8>();
    // SAFETY: contract 2/4 — the buffer is aligned for TOKEN_USER and alive.
    let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid }
        .cast::<u8>()
        .cast_const();
    let offset = (sid as usize)
        .checked_sub(base as usize)
        .filter(|o| *o < len as usize)
        .ok_or_else(|| io::Error::other("token SID outside its buffer"))?;
    // SAFETY: contract 3 — `sid` lies inside `buf`, with `len - offset` bytes after it.
    unsafe { copy_sid(sid, len as usize - offset) }
}

/// An absolute security descriptor: owner = user, one protected allow ACE.
/// Its three buffers are heap-owned, so the internal pointers stay valid when
/// this value moves (contract 1/4). Not `Clone`.
pub(crate) struct OwnedSd {
    sd: Vec<u64>,
    _owner: Vec<u64>,
    _acl: Vec<u64>,
}

impl OwnedSd {
    fn as_ptr(&mut self) -> PSECURITY_DESCRIPTOR {
        self.sd.as_mut_ptr().cast()
    }
}

/// The descriptor every store object is created with.
pub(crate) fn private_descriptor(kind: ObjectKind, user: &Sid) -> io::Result<OwnedSd> {
    let sid_len = user.0.len();
    let mut owner = aligned(sid_len);
    // SAFETY: contract 1/2 — copy the validated SID bytes into an aligned owned buffer.
    unsafe {
        std::ptr::copy_nonoverlapping(user.0.as_ptr(), owner.as_mut_ptr().cast::<u8>(), sid_len);
    }
    let acl_len = std::mem::size_of::<ACL>()
        .checked_add(std::mem::size_of::<ACCESS_ALLOWED_ACE>() - std::mem::size_of::<u32>())
        .and_then(|n| n.checked_add(sid_len))
        .ok_or_else(|| io::Error::other("ACL size overflow"))?;
    let mut acl = aligned(acl_len);
    let acl_ptr = acl.as_mut_ptr().cast::<ACL>();
    let flags = match kind {
        ObjectKind::Dir => OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
        ObjectKind::File => 0,
    };
    let mut sd = aligned(std::mem::size_of::<SECURITY_DESCRIPTOR>());
    let sd_ptr: PSECURITY_DESCRIPTOR = sd.as_mut_ptr().cast();
    let owner_ptr: PSID = owner.as_mut_ptr().cast();
    let acl_u32 = u32::try_from(acl_len).map_err(|_| io::Error::other("ACL too large"))?;
    // SAFETY: contract 1/2/3/6 — every pointer is an aligned owned buffer of the
    // size the API requires; each BOOL result is checked before the next call.
    unsafe {
        if InitializeAcl(acl_ptr, acl_u32, ACL_REVISION) == 0
            || AddAccessAllowedAceEx(acl_ptr, ACL_REVISION, flags, FILE_ALL_ACCESS, owner_ptr) == 0
            || InitializeSecurityDescriptor(sd_ptr, SECURITY_DESCRIPTOR_REVISION) == 0
            || SetSecurityDescriptorOwner(sd_ptr, owner_ptr, 0) == 0
            || SetSecurityDescriptorDacl(sd_ptr, 1, acl_ptr, 0) == 0
            || SetSecurityDescriptorControl(sd_ptr, SE_DACL_PROTECTED, SE_DACL_PROTECTED) == 0
        {
            return Err(last());
        }
    }
    Ok(OwnedSd {
        sd,
        _owner: owner,
        _acl: acl,
    })
}

/// Observation point immediately after an object is created and before any
/// other statement (test plan W-T1b). Files pass their live handle, which is
/// held without sharing, so a path-based read would fail.
#[cfg(test)]
pub(crate) type AfterCreateHook = fn(&Path, Option<&File>);
#[cfg(test)]
thread_local! {
    /// Per thread, so parallel tests never observe each other's creations.
    pub(crate) static AFTER_CREATE: std::cell::Cell<Option<AfterCreateHook>> =
        const { std::cell::Cell::new(None) };
    /// Makes private creates on this thread see a volume without ACLs, and
    /// runs at the refusal before cleanup (W-T15d, W-T15e).
    pub(crate) static NO_ACLS: std::cell::Cell<Option<fn(&Path)>> =
        const { std::cell::Cell::new(None) };
    /// Runs after a refused create's creating handle is released or kept, and
    /// before the delete: the window a drop-then-remove cleanup opens (W-T15f).
    pub(crate) static BEFORE_DELETE: std::cell::Cell<Option<fn(&Path)>> =
        const { std::cell::Cell::new(None) };
}

pub(crate) fn after_create(path: &Path, file: Option<&File>) {
    #[cfg(test)]
    if let Some(hook) = AFTER_CREATE.with(std::cell::Cell::get) {
        hook(path, file);
    }
    #[cfg(not(test))]
    let _ = (path, file);
}

/// Create a directory that never exists with any other DACL.
pub(crate) fn create_dir_private(path: &Path, user: &Sid) -> io::Result<()> {
    let mut sd = private_descriptor(ObjectKind::Dir, user)?;
    let w = wide(path)?;
    let attrs = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
        lpSecurityDescriptor: sd.as_ptr(),
        bInheritHandle: 0,
    };
    // SAFETY: contract 1/5/6 — NUL-terminated path and attributes live on this
    // stack frame; `sd` outlives the call; BOOL checked.
    if unsafe { CreateDirectoryW(w.as_ptr(), &raw const attrs) } == 0 {
        return Err(last());
    }
    after_create(path, None);
    Ok(())
}

/// Create a file that never exists with any other DACL. `CREATE_NEW` refuses
/// any existing name, reparse point included.
pub(crate) fn create_file_private(path: &Path, user: &Sid, share: Share) -> io::Result<File> {
    let mut sd = private_descriptor(ObjectKind::File, user)?;
    let w = wide(path)?;
    let attrs = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
        lpSecurityDescriptor: sd.as_ptr(),
        bInheritHandle: 0,
    };
    // Only an unshared handle takes DELETE: a sidecar's readers share no
    // delete, so a creator holding it would lock them out.
    let (share_mode, delete) = match share {
        Share::Exclusive => (0, DELETE),
        Share::LockSidecar => (FILE_SHARE_READ | FILE_SHARE_WRITE, 0),
    };
    // SAFETY: contract 1/5/6 — as above; the result is checked against
    // INVALID_HANDLE_VALUE (never null) before it is owned.
    let raw = unsafe {
        CreateFileW(
            w.as_ptr(),
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL | delete,
            share_mode,
            &raw const attrs,
            CREATE_NEW,
            FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(last());
    }
    // SAFETY: contract 1 — a valid handle, owned exactly once.
    let file = File::from(unsafe { OwnedHandle::from_raw_handle(raw) });
    // A volume without ACLs drops the descriptor and still reports success, so
    // the file would be open to every account. Refuse before any byte is
    // written, and delete the empty file: through this handle when it is
    // unshared, else by a DELETE reopen. A failed deletion is reported.
    let keeps = volume_keeps_acls(&file);
    #[cfg(test)]
    let keeps = match NO_ACLS.with(std::cell::Cell::get) {
        Some(hook) => {
            hook(path);
            Ok(false)
        }
        None => keeps,
    };
    if !matches!(keeps, Ok(true)) {
        let doomed = if share == Share::Exclusive {
            Ok(file)
        } else {
            drop(file);
            std::fs::OpenOptions::new()
                .access_mode(DELETE)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(path)
        };
        #[cfg(test)]
        if let Some(hook) = BEFORE_DELETE.with(std::cell::Cell::get) {
            hook(path);
        }
        let cleanup = match doomed.and_then(|doomed| mark_deleted(&doomed)) {
            Ok(()) => String::new(),
            Err(error) => format!("; the empty file could not be removed: {error}"),
        };
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing to create {}: its volume keeps no ACLs (FAT or exFAT), so the file \
                 cannot be made owner-only; use an NTFS or ReFS volume{cleanup}",
                path.display()
            ),
        ));
    }
    after_create(path, Some(&file));
    Ok(file)
}

/// Owner, DACL and protection of an OPEN handle, which must carry
/// `READ_CONTROL`.
///
/// Everything comes from ONE read: the descriptor as stored on the handle
/// (`GetKernelObjectSecurity`). `GetSecurityInfo` can report a DACL as
/// protected when the stored control bits do not carry `SE_DACL_PROTECTED`
/// (seen on a DACL written without the auto-inherit flag). This is a secrecy
/// guard, so where the two readings can disagree the conservative one is the
/// one read: the stored bit decides, and a DACL without it is refused as not
/// protected.
pub(crate) fn inspect(file: &File) -> io::Result<Inspection> {
    let info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    // u64 words keep the self-relative descriptor aligned for its SIDs/ACL.
    let mut buf: Vec<u64> = Vec::new();
    loop {
        let bytes = u32::try_from(buf.len() * 8)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "descriptor length"))?;
        let mut needed = 0_u32;
        // SAFETY: contract 1/6 — `buf` is writable for `bytes` bytes (null when
        // empty, with length 0); `needed` is an out-pointer on this frame.
        let ok = unsafe {
            GetKernelObjectSecurity(
                file.as_raw_handle(),
                info,
                if buf.is_empty() {
                    std::ptr::null_mut()
                } else {
                    buf.as_mut_ptr().cast()
                },
                bytes,
                &raw mut needed,
            )
        };
        if ok != 0 {
            break;
        }
        let err = last();
        if err.raw_os_error() != i32::try_from(ERROR_INSUFFICIENT_BUFFER).ok() || needed <= bytes {
            return Err(err);
        }
        buf = aligned(needed as usize);
    }
    if buf.is_empty() {
        // A success with no buffer is a broken contract, not an empty descriptor.
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty descriptor",
        ));
    }
    let sd: PSECURITY_DESCRIPTOR = buf.as_mut_ptr().cast();
    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: contract 4/6 — `buf` holds the descriptor for this call; BOOL
    // checked.
    if unsafe { GetSecurityDescriptorControl(sd, &raw mut control, &raw mut revision) } == 0 {
        return Err(last());
    }
    let mut owner: PSID = std::ptr::null_mut();
    let mut defaulted = 0;
    // SAFETY: contract 4/6 — as above; `owner` points into `buf` or is null.
    if unsafe { GetSecurityDescriptorOwner(sd, &raw mut owner, &raw mut defaulted) } == 0 {
        return Err(last());
    }
    let mut present = 0;
    let mut dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: contract 4/6 — as above; `dacl` points into `buf` or is null.
    if unsafe { GetSecurityDescriptorDacl(sd, &raw mut present, &raw mut dacl, &raw mut defaulted) }
        == 0
    {
        return Err(last());
    }
    if present == 0 {
        // No DACL at all grants everyone, like a NULL DACL.
        dacl = std::ptr::null_mut();
    }
    // Owner and DACL lie inside the self-relative descriptor, so every read
    // is bounded by where the descriptor ends.
    // SAFETY: contract 4 — `buf` holds a valid descriptor for this call.
    let sd_len = (unsafe { GetSecurityDescriptorLength(sd) } as usize).min(buf.len() * 8);
    let sd_start = buf.as_ptr() as usize;
    let sd_end = sd_start
        .checked_add(sd_len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "descriptor length"))?;
    let within = |ptr: usize| {
        (sd_start..sd_end)
            .contains(&ptr)
            .then(|| sd_end - ptr)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "outside descriptor"))
    };
    let owner = if owner.is_null() {
        None
    } else {
        let avail = within(owner as usize)?;
        // SAFETY: contract 3/4 — `avail` bytes from `owner` lie inside the live
        // descriptor.
        Some(unsafe { copy_sid(owner.cast::<u8>().cast_const(), avail) }?)
    };
    let aces = if dacl.is_null() {
        None
    } else {
        let avail = within(dacl as usize)?;
        // SAFETY: contract 3/4 — `avail` bytes from `dacl` lie inside the live
        // descriptor.
        Some(unsafe { read_aces(dacl, avail) }?)
    };
    Ok(Inspection {
        owner,
        dacl: aces,
        protected: control & SE_DACL_PROTECTED != 0,
    })
}

/// Decode every ACE, bounded by `AceCount` and `AclSize` (contract 3).
///
/// # Safety
/// `acl` must point at an ACL that outlives this call, readable for `avail`
/// bytes.
unsafe fn read_aces(acl: *const ACL, avail: usize) -> io::Result<Vec<Ace>> {
    let bad = || io::Error::new(io::ErrorKind::InvalidData, "malformed ACL");
    if acl.is_null() || avail < std::mem::size_of::<ACL>() {
        return Err(bad());
    }
    // SAFETY: caller contract — the header lies inside the readable range.
    let header = unsafe { *acl };
    if usize::from(header.AclSize) > avail {
        return Err(bad());
    }
    let acl_end = acl as usize + usize::from(header.AclSize);
    let mut out = Vec::with_capacity(usize::from(header.AceCount));
    for index in 0..u32::from(header.AceCount) {
        let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
        // SAFETY: contract 3/6 — index < AceCount; BOOL checked.
        if unsafe { GetAce(acl, index, &raw mut ace) } == 0 {
            return Err(last());
        }
        let Some(ace) = std::ptr::NonNull::new(ace) else {
            return Err(bad());
        };
        let start = ace.as_ptr() as usize;
        if start < acl as usize || start + std::mem::size_of::<ACE_HEADER>() > acl_end {
            return Err(bad());
        }
        // SAFETY: contract 3 — non-null, and the header lies inside the ACL.
        let h = unsafe { ace.cast::<ACE_HEADER>().as_ptr().read_unaligned() };
        let size = usize::from(h.AceSize);
        if start + size > acl_end {
            return Err(bad());
        }
        let fixed = std::mem::size_of::<ACE_HEADER>() + std::mem::size_of::<u32>();
        match h.AceType {
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_DENIED_ACE_TYPE => {
                if size < fixed + SID_HEADER {
                    return Err(bad());
                }
                // SAFETY: contract 3 — `fixed` bytes are inside the ACE; read
                // unaligned so no alignment is assumed of the ACL's layout.
                let mask = unsafe { (start as *const u8).add(4).cast::<u32>().read_unaligned() };
                // SAFETY: contract 3 — the SID starts at `fixed` and has
                // `size - fixed` bytes before the ACE ends.
                let sid = unsafe { copy_sid((start as *const u8).add(fixed), size - fixed) }?;
                out.push(if h.AceType == ACCESS_ALLOWED_ACE_TYPE {
                    Ace::Allowed {
                        flags: h.AceFlags,
                        mask,
                        sid,
                    }
                } else {
                    Ace::Denied {
                        flags: h.AceFlags,
                        mask,
                        sid,
                    }
                });
            }
            other => out.push(Ace::Other { ace_type: other }),
        }
    }
    Ok(out)
}

/// The flags `replace` passes to `MoveFileExW`; the durability trace (W-T22)
/// reads the write-through bit from here, so it reports the argument itself.
pub(crate) const REPLACE_FLAGS: u32 = MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH;

/// Replace `dest` with `tmp`; returns only once the rename is on disk.
pub(crate) fn replace(tmp: &Path, dest: &Path) -> io::Result<()> {
    let (from, to) = (wide(tmp)?, wide(dest)?);
    // SAFETY: contract 5/6 — two NUL-terminated paths on this frame; BOOL checked.
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), REPLACE_FLAGS) } == 0 {
        return Err(last());
    }
    Ok(())
}

/// The normalised DOS path of an open handle.
pub(crate) fn final_path(file: &File) -> io::Result<PathBuf> {
    let flags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
    let mut buf = vec![0_u16; 512];
    for _ in 0..2 {
        let cap = u32::try_from(buf.len()).map_err(|_| io::Error::other("path too long"))?;
        // SAFETY: contract 1/6 — an owned buffer of `cap` units; 0 = failure,
        // >= cap = required size.
        let n = unsafe {
            GetFinalPathNameByHandleW(file.as_raw_handle(), buf.as_mut_ptr(), cap, flags)
        };
        if n == 0 {
            return Err(last());
        }
        if n < cap {
            buf.truncate(n as usize);
            return Ok(PathBuf::from(std::ffi::OsString::from_wide(&buf)));
        }
        buf = vec![0_u16; n as usize + 1];
    }
    Err(io::Error::other("final path kept growing"))
}

/// True only for a local fixed or removable volume whose filesystem keeps
/// ACLs. `dir` is an open handle to a directory on that volume.
pub(crate) fn volume_is_local(dir: &File) -> io::Result<bool> {
    let path = final_path(dir)?;
    let text = path.to_string_lossy();
    if text.starts_with(r"\\?\UNC\") || (text.starts_with(r"\\") && !text.starts_with(r"\\?\")) {
        return Ok(false);
    }
    let w = wide(&path)?;
    let mut root = vec![0_u16; w.len() + 261];
    let cap = u32::try_from(root.len()).map_err(|_| io::Error::other("path too long"))?;
    // SAFETY: contract 5/6 — BOOL API with a zeroed buffer longer than the input.
    if unsafe { GetVolumePathNameW(w.as_ptr(), root.as_mut_ptr(), cap) } == 0 {
        return Err(last());
    }
    if !root.contains(&0) {
        return Err(io::Error::other("volume path not terminated"));
    }
    // SAFETY: contract 5 — `root` is NUL-terminated within its length.
    let kind = unsafe { GetDriveTypeW(root.as_ptr()) };
    if kind != DRIVE_FIXED && kind != DRIVE_REMOVABLE {
        return Ok(false);
    }
    volume_keeps_acls(dir)
}

/// Set the delete disposition on `file`, opened with `DELETE`.
fn mark_deleted(file: &File) -> io::Result<()> {
    let mark = FILE_DISPOSITION_INFO { DeleteFile: true };
    let size = u32::try_from(std::mem::size_of::<FILE_DISPOSITION_INFO>()).unwrap_or(u32::MAX);
    // SAFETY: contract 1/6 — a live handle; `mark` outlives the call and its
    // exact size is passed; BOOL checked.
    let ok = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            (&raw const mark).cast(),
            size,
        )
    };
    if ok == 0 { Err(last()) } else { Ok(()) }
}

/// True when the open `handle` is a disk object (a file or directory), not a
/// pipe, console or other device.
pub(crate) fn is_disk_object(handle: &File) -> bool {
    // SAFETY: contract 1 — a live handle; the call only reads its type.
    let kind = unsafe { GetFileType(handle.as_raw_handle()) };
    kind == FILE_TYPE_DISK
}

/// True when the filesystem holding the open `handle` keeps ACLs (NTFS, `ReFS`);
/// FAT and exFAT accept a security descriptor at create and discard it.
pub(crate) fn volume_keeps_acls(handle: &File) -> io::Result<bool> {
    let mut fs_flags = 0_u32;
    // SAFETY: contract 6 — only the flags out-pointer is requested; BOOL checked.
    if unsafe {
        GetVolumeInformationByHandleW(
            handle.as_raw_handle(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut fs_flags,
            std::ptr::null_mut(),
            0,
        )
    } == 0
    {
        return Err(last());
    }
    Ok(fs_flags & FILE_PERSISTENT_ACLS != 0)
}

/// (volume serial number, 128-bit file id) of an open file, from
/// `FILE_ID_INFO`. The 64-bit index in `BY_HANDLE_FILE_INFORMATION` is not
/// unique on `ReFS`; this one is, on every filesystem that reports ids.
pub(crate) fn file_identity(file: &File) -> io::Result<(u64, u128)> {
    let mut info = FILE_ID_INFO::default();
    let size = u32::try_from(std::mem::size_of::<FILE_ID_INFO>()).unwrap_or(u32::MAX);
    // SAFETY: contract 1/6 — an out-struct of exactly `size` bytes on this
    // frame; BOOL checked.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            (&raw mut info).cast(),
            size,
        )
    } == 0
    {
        return Err(last());
    }
    Ok((
        info.VolumeSerialNumber,
        u128::from_le_bytes(info.FileId.Identifier),
    ))
}

#[cfg(test)]
#[path = "win_acl_tests.rs"]
mod tests;
