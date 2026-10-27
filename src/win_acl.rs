// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Win32 security calls behind owner-only stores on Windows (ADR-016).
//!
//! The ONLY module in the crate allowed `unsafe`. Every export is a safe
//! function; callers never see a raw handle, pointer or Win32 type. Each
//! `unsafe` block names the ADR-016 safety-contract points it relies on.
#![allow(unsafe_code)]

use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStringExt as _;
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_REVISION, ATTRIBUTE_SECURITY_INFORMATION,
    AddAccessAllowedAceEx, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, GetAce,
    GetKernelObjectSecurity, GetLengthSid, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
    GetSecurityDescriptorLength, GetSecurityDescriptorOwner, GetSecurityDescriptorSacl,
    GetTokenInformation, InitializeAcl, InitializeSecurityDescriptor, IsValidSid,
    LABEL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SCOPE_SECURITY_INFORMATION, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES,
    SECURITY_DESCRIPTOR, SetSecurityDescriptorControl, SetSecurityDescriptorDacl,
    SetSecurityDescriptorOwner, TOKEN_QUERY, TOKEN_USER, TokenUser,
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
/// `SystemServices` values for the two SACL classes `Security` does not
/// export (winnt.h); readable with `READ_CONTROL`, as the other three are.
const PROCESS_TRUST_LABEL_SECURITY_INFORMATION: u32 = 0x80;
const ACCESS_FILTER_SECURITY_INFORMATION: u32 = 0x100;
/// Fixed part of a SID: revision, sub-authority count, 6-byte authority.
const SID_HEADER: usize = 8;

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
    let mut buf = read_descriptor(file, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)?;
    decode(&mut buf)
}

/// The self-relative descriptor stored on `file`, for the parts `info` names.
/// The handle is borrowed for the whole call, so it stays open and valid.
fn read_descriptor(file: &File, info: u32) -> io::Result<Vec<u64>> {
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
    Ok(buf)
}

/// Owner, DACL and protection decoded from a descriptor `read_descriptor`
/// returned.
fn decode(buf: &mut [u64]) -> io::Result<Inspection> {
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

/// Every SACL class that can restrict access and is readable with
/// `READ_CONTROL`. `SACL_SECURITY_INFORMATION` (audit entries) is never
/// requested: it needs `ACCESS_SYSTEM_SECURITY`, and audits restrict nothing.
const ENFORCING_SACL_INFO: u32 = LABEL_SECURITY_INFORMATION
    | SCOPE_SECURITY_INFORMATION
    | ATTRIBUTE_SECURITY_INFORMATION
    | PROCESS_TRUST_LABEL_SECURITY_INFORMATION
    | ACCESS_FILTER_SECURITY_INFORMATION;

/// Owner, DACL and every access-enforcing SACL entry of an open handle that
/// carries `READ_CONTROL`, with the descriptors kept for `create_file_like`.
/// A query that fails is an error, never an empty answer.
pub(crate) fn inspect_for_copy(file: &File) -> io::Result<CopySource> {
    // The copy is created with the owner in its descriptor (ADR-016
    // amendment 3): the kernel assigns the token user's own SID, or a group
    // the token may own by, without a privilege, and fails any other owner
    // with ERROR_INVALID_OWNER, so no owner is ever replaced silently.
    let mut descriptor = read_descriptor(
        file,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | ENFORCING_SACL_INFO,
    )?;
    let inspection = decode(&mut descriptor)?;
    let enforcing_sacl_aces = sacl_ace_count(&mut descriptor)?;
    let owner_only = read_descriptor(file, OWNER_SECURITY_INFORMATION)?;
    Ok(CopySource {
        inspection,
        enforcing_sacl_aces,
        descriptor,
        owner_only,
    })
}

/// How many entries the SACL in `buf` holds; 0 when there is none.
fn sacl_ace_count(buf: &mut [u64]) -> io::Result<usize> {
    let sd: PSECURITY_DESCRIPTOR = buf.as_mut_ptr().cast();
    let mut present = 0;
    let mut defaulted = 0;
    let mut sacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: contract 4/6 — `buf` holds the descriptor `read_descriptor`
    // returned and outlives this call; `sacl` is an out-pointer on this frame
    // and ends up null or pointing into `buf`; BOOL checked.
    if unsafe { GetSecurityDescriptorSacl(sd, &raw mut present, &raw mut sacl, &raw mut defaulted) }
        == 0
    {
        return Err(last());
    }
    if present == 0 || sacl.is_null() {
        return Ok(0);
    }
    // The SACL lies inside the self-relative descriptor: bound it there, as
    // `decode` bounds the owner and DACL, then count with the same decoder.
    // SAFETY: contract 4 — `buf` holds a valid descriptor for this call.
    let sd_len = (unsafe { GetSecurityDescriptorLength(sd) } as usize).min(buf.len() * 8);
    let start = buf.as_ptr() as usize;
    let at = sacl as usize;
    if at < start || at >= start + sd_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SACL outside descriptor",
        ));
    }
    // SAFETY: contract 3/4 — `start + sd_len - at` bytes from `sacl` lie
    // inside the live descriptor.
    Ok(unsafe { read_aces(sacl, start + sd_len - at) }?.len())
}

/// Create `path` (`CREATE_NEW`, unshared, reparse points not followed) with
/// one of the descriptors `model` was read with: owner, DACL and
/// access-enforcing SACL entries for a protected list, or the owner alone for
/// an inherited one, whose entries the folder supplies. The kernel sets the
/// model's owner or fails the create (ERROR_INVALID_OWNER) when this token may
/// not assign it. The caller compares the result with the model before
/// trusting it.
pub(crate) fn create_file_like(
    path: &Path,
    model: &CopySource,
    with: CopyWith,
) -> io::Result<File> {
    let mut descriptor = match with {
        CopyWith::OwnerAndList => model.descriptor.clone(),
        CopyWith::OwnerOnly => model.owner_only.clone(),
    };
    let w = wide(path)?;
    let attrs = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
        lpSecurityDescriptor: descriptor.as_mut_ptr().cast(),
        bInheritHandle: 0,
    };
    // SAFETY: contract 1/5/6 — `descriptor` is a self-relative descriptor as
    // `GetKernelObjectSecurity` stored it (the form `lpSecurityDescriptor`
    // accepts), aligned in u64 words, and with `w` and `attrs` it lives on
    // this frame until the call returns; the result is checked against
    // INVALID_HANDLE_VALUE (never null) before it is owned.
    let raw = unsafe {
        CreateFileW(
            w.as_ptr(),
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL | DELETE,
            0,
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
    after_create(path, Some(&file));
    Ok(file)
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

mod shapes;
pub(crate) use shapes::{Ace, CopySource, CopyWith, Inspection, ObjectKind, Share, Sid};
use shapes::{aligned, wide};

#[cfg(test)]
#[path = "win_acl_tests.rs"]
mod tests;
