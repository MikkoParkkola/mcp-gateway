// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Win32 security calls behind owner-only stores on Windows (ADR-016).
//!
//! The ONLY module in the crate allowed `unsafe`. Every export is a safe
//! function; callers never see a raw handle, pointer or Win32 type. Each
//! `unsafe` block names the ADR-016 safety-contract points it relies on.
#![allow(unsafe_code)]
// Probe branch only: no store calls these yet.
#![cfg_attr(not(test), allow(dead_code))]

use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{
    ERROR_SUCCESS, GENERIC_READ, GENERIC_WRITE, HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_REVISION, AddAccessAllowedAceEx,
    CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, GetAce, GetLengthSid,
    GetSecurityDescriptorControl, GetTokenInformation, InitializeAcl,
    InitializeSecurityDescriptor, IsValidSid, OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
    SetSecurityDescriptorControl, SetSecurityDescriptorDacl, SetSecurityDescriptorOwner,
    TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ALL_ACCESS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_NAME_NORMALIZED, FILE_SHARE_READ, FILE_SHARE_WRITE, GetDriveTypeW,
    GetFinalPathNameByHandleW, GetVolumeInformationByHandleW, GetVolumePathNameW,
    BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle, MOVEFILE_REPLACE_EXISTING,
    MOVEFILE_WRITE_THROUGH, MoveFileExW, READ_CONTROL, VOLUME_NAME_DOS,
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
        let authority = b[2..8].iter().fold(0_u64, |acc, x| (acc << 8) | u64::from(*x));
        let mut out = format!("S-{}-{authority}", b[0]);
        for chunk in b[SID_HEADER..].chunks_exact(4) {
            let sub = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            out.push_str(&format!("-{sub}"));
        }
        out
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
    Allowed { flags: u8, mask: u32, sid: Sid },
    Denied { flags: u8, mask: u32, sid: Sid },
    /// Any other ACE type; its body is never read.
    Other { ace_type: u8 },
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
    let mut w: Vec<u16> = OsStr::new(path).encode_wide().collect();
    if w.contains(&0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"));
    }
    w.push(0);
    Ok(w)
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
        GetTokenInformation(token.as_raw_handle(), TokenUser, std::ptr::null_mut(), 0, &raw mut len);
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
    let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid }.cast::<u8>().cast_const();
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
    Ok(OwnedSd { sd, _owner: owner, _acl: acl })
}

/// `cfg(test)` observation point immediately after an object is created and
/// before any other statement (test plan W-T1b).
#[cfg(test)]
pub(crate) static AFTER_CREATE: std::sync::Mutex<Option<fn(&Path)>> = std::sync::Mutex::new(None);

fn after_create(_path: &Path) {
    #[cfg(test)]
    if let Some(hook) = *AFTER_CREATE.lock().unwrap_or_else(std::sync::PoisonError::into_inner) {
        hook(_path);
    }
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
    after_create(path);
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
    let share_mode = match share {
        Share::Exclusive => 0,
        Share::LockSidecar => FILE_SHARE_READ | FILE_SHARE_WRITE,
    };
    // SAFETY: contract 1/5/6 — as above; the result is checked against
    // INVALID_HANDLE_VALUE (never null) before it is owned.
    let raw = unsafe {
        CreateFileW(
            w.as_ptr(),
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
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
    after_create(path);
    // SAFETY: contract 1 — a valid handle, owned exactly once.
    Ok(File::from(unsafe { OwnedHandle::from_raw_handle(raw) }))
}

/// Frees a `GetSecurityInfo` descriptor exactly once (contract 1).
struct LocalSd(PSECURITY_DESCRIPTOR);

impl Drop for LocalSd {
    fn drop(&mut self) {
        // SAFETY: contract 1 — allocated by GetSecurityInfo, freed once here.
        unsafe { LocalFree(self.0 as HLOCAL) };
    }
}

/// Owner, DACL and protection of an OPEN handle, which must carry
/// `READ_CONTROL`.
pub(crate) fn inspect(file: &File) -> io::Result<Inspection> {
    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: contract 1/6 — out-pointers on this frame; the result is a
    // WIN32_ERROR (0 = success), never a BOOL.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            std::ptr::null_mut(),
            &raw mut dacl,
            std::ptr::null_mut(),
            &raw mut sd,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(i32::try_from(status).unwrap_or(i32::MAX)));
    }
    let guard = LocalSd(sd);
    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: contract 4/6 — `guard` keeps the descriptor alive; BOOL checked.
    if unsafe { GetSecurityDescriptorControl(guard.0, &raw mut control, &raw mut revision) } == 0 {
        return Err(last());
    }
    let owner = if owner.is_null() {
        None
    } else {
        // SAFETY: contract 3/4 — an owner SID inside the live descriptor. Its
        // length is not known before validation, so the header bound is the
        // maximum SID size (8 + 4 * 255).
        Some(unsafe { copy_sid(owner.cast::<u8>().cast_const(), SID_HEADER + 4 * 255) }?)
    };
    let aces = if dacl.is_null() {
        None
    } else {
        // SAFETY: contract 4 — the ACL lives inside the guarded descriptor.
        Some(unsafe { read_aces(dacl) }?)
    };
    drop(guard);
    Ok(Inspection { owner, dacl: aces, protected: control & SE_DACL_PROTECTED != 0 })
}

/// Decode every ACE, bounded by `AceCount` and `AclSize` (contract 3).
///
/// # Safety
/// `acl` must point at a valid ACL that outlives this call.
unsafe fn read_aces(acl: *const ACL) -> io::Result<Vec<Ace>> {
    let bad = || io::Error::new(io::ErrorKind::InvalidData, "malformed ACL");
    // SAFETY: caller contract — a valid ACL header.
    let header = unsafe { *acl };
    let acl_end = acl as usize + usize::from(header.AclSize);
    let mut out = Vec::with_capacity(usize::from(header.AceCount));
    for index in 0..u32::from(header.AceCount) {
        let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
        // SAFETY: contract 3/6 — index < AceCount; BOOL checked.
        if unsafe { GetAce(acl, index, &raw mut ace) } == 0 {
            return Err(last());
        }
        let start = ace as usize;
        if start < acl as usize || start + std::mem::size_of::<ACE_HEADER>() > acl_end {
            return Err(bad());
        }
        // SAFETY: contract 3 — the header lies inside the ACL.
        let h = unsafe { *ace.cast::<ACE_HEADER>() };
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
                // SAFETY: contract 3 — `fixed` bytes are inside the ACE.
                let mask = unsafe { *(start as *const u8).add(4).cast::<u32>() };
                // SAFETY: contract 3 — the SID starts at `fixed` and has
                // `size - fixed` bytes before the ACE ends.
                let sid = unsafe { copy_sid((start as *const u8).add(fixed), size - fixed) }?;
                out.push(if h.AceType == ACCESS_ALLOWED_ACE_TYPE {
                    Ace::Allowed { flags: h.AceFlags, mask, sid }
                } else {
                    Ace::Denied { flags: h.AceFlags, mask, sid }
                });
            }
            other => out.push(Ace::Other { ace_type: other }),
        }
    }
    Ok(out)
}

/// Replace `dest` with `tmp`; returns only once the rename is on disk.
pub(crate) fn replace(tmp: &Path, dest: &Path) -> io::Result<()> {
    let (from, to) = (wide(tmp)?, wide(dest)?);
    // SAFETY: contract 5/6 — two NUL-terminated paths on this frame; BOOL checked.
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) } == 0 {
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
        let n = unsafe { GetFinalPathNameByHandleW(file.as_raw_handle(), buf.as_mut_ptr(), cap, flags) };
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
    let mut fs_flags = 0_u32;
    // SAFETY: contract 6 — only the flags out-pointer is requested; BOOL checked.
    if unsafe {
        GetVolumeInformationByHandleW(
            dir.as_raw_handle(),
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

#[cfg(test)]
#[path = "win_acl_probe_tests.rs"]
mod probe_tests;

/// (volume serial number, file index): the identity of an open file, stable
/// across renames on the same volume.
pub(crate) fn file_identity(file: &File) -> io::Result<(u32, u64)> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: contract 1/6 — an out-struct on this frame; BOOL checked.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut info) } == 0 {
        return Err(last());
    }
    let index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
    Ok((info.dwVolumeSerialNumber, index))
}
