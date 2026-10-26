// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Windows Credential Manager behind `keychain:` references (ADR-028 §2a).
//!
//! The second module allowed `unsafe`, under ADR-016's rules: every export is
//! a safe function, callers never see a pointer or a Win32 type, and every
//! `unsafe` block names the contract it relies on. Each entry is a generic
//! credential whose target is the entry name and whose user is `mcp-gateway`.
//! A value never enters an error: Win32 failures are reported by code.
#![allow(unsafe_code)]

#[cfg(test)]
use windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER;
use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, GetLastError};
#[cfg(test)]
use windows_sys::Win32::Security::Credentials::{
    CRED_PERSIST_LOCAL_MACHINE, CredDeleteW, CredWriteW,
};
use windows_sys::Win32::Security::Credentials::{
    CRED_TYPE_GENERIC, CREDENTIALW, CredFree, CredReadW,
};

use crate::wiped_bytes::WipedBytes;

/// Why a Credential Manager call did not succeed. Never holds a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CredError {
    /// No credential has that target.
    NotFound,
    /// The name holds a NUL, which a Win32 string cannot carry.
    BadName,
    /// A credential with that target already exists; it is left unchanged.
    #[cfg(test)]
    Exists,
    /// Any other failure, by its `GetLastError` code.
    Win32(u32),
}

/// `name` as NUL-terminated UTF-16.
fn wide(name: &str) -> Result<Vec<u16>, CredError> {
    if name.contains('\0') {
        return Err(CredError::BadName);
    }
    Ok(name.encode_utf16().chain(Some(0)).collect())
}

fn last_error() -> CredError {
    // SAFETY: GetLastError has no preconditions; it reads this thread's code.
    match unsafe { GetLastError() } {
        ERROR_NOT_FOUND => CredError::NotFound,
        code => CredError::Win32(code),
    }
}

/// A credential from a successful `CredReadW`. On drop, on every path, its
/// blob is zeroed and then it is freed, exactly once.
struct Read(*mut CREDENTIALW);

impl Read {
    /// The blob pointer and its length; null or 0 when there is none.
    fn blob(&self) -> (*mut u8, usize) {
        // SAFETY: `self.0` came from a CredReadW that returned TRUE, so it
        // points to a CREDENTIALW that stays valid until this guard drops.
        let credential = unsafe { &*self.0 };
        (
            credential.CredentialBlob,
            credential.CredentialBlobSize as usize,
        )
    }
}

#[cfg(test)]
thread_local! {
    /// For each guard dropped on this thread: whether its blob was all zero
    /// at the moment `CredFree` ran.
    pub(crate) static FREED: std::cell::RefCell<Vec<bool>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

impl Drop for Read {
    fn drop(&mut self) {
        let (blob, len) = self.blob();
        if !blob.is_null() && len > 0 {
            // SAFETY: the blob is `len` bytes owned by this credential until
            // CredFree, and nothing else holds a reference into it now.
            unsafe { std::ptr::write_bytes(blob, 0, len) };
        }
        #[cfg(test)]
        {
            let zero = if blob.is_null() {
                true
            } else {
                // SAFETY: as above; the bytes are read before CredFree runs.
                let bytes = unsafe { std::slice::from_raw_parts(blob, len) };
                bytes.iter().all(|byte| *byte == 0)
            };
            FREED.with(|freed| freed.borrow_mut().push(zero));
        }
        // SAFETY: the pointer came from a CredReadW that returned TRUE and is
        // freed only here, once.
        unsafe { CredFree(self.0.cast()) }
    }
}

/// The credential's exact bytes. The Win32 copy is zeroed and freed before
/// this returns.
pub(crate) fn read(name: &str) -> Result<WipedBytes, CredError> {
    let target = wide(name)?;
    let mut found: *mut CREDENTIALW = std::ptr::null_mut();
    // SAFETY: `target` is NUL-terminated UTF-16 owned here and outlives the
    // call; `found` is a valid out-pointer; flags must be 0.
    if unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &raw mut found) } == 0 {
        return Err(last_error());
    }
    // The guard zeroes the blob and frees it however this function returns.
    let read = Read(found);
    let (blob, len) = read.blob();
    if blob.is_null() || len == 0 {
        return Ok(WipedBytes::new(Vec::new()));
    }
    // SAFETY: the blob is `len` bytes valid until `read` drops, and it is
    // only read here; the copy is taken before the guard zeroes it.
    let copy = unsafe { std::slice::from_raw_parts(blob, len) }.to_vec();
    Ok(WipedBytes::new(copy))
}

/// Stores `bytes` under `name`, refusing a name that already exists.
// ponytail: check-then-write is not atomic; ADR-028 makes it create-only under
// the vault lock, which arrives with the write side.
#[cfg(test)]
pub(crate) fn create(name: &str, bytes: &[u8]) -> Result<(), CredError> {
    match read(name) {
        Ok(_) => return Err(CredError::Exists),
        Err(CredError::NotFound) => {}
        Err(other) => return Err(other),
    }
    let mut target = wide(name)?;
    let mut user = wide("mcp-gateway")?;
    let len = u32::try_from(bytes.len()).map_err(|_| CredError::Win32(ERROR_INVALID_PARAMETER))?;
    let credential = CREDENTIALW {
        Type: CRED_TYPE_GENERIC,
        TargetName: target.as_mut_ptr(),
        CredentialBlobSize: len,
        // CredWriteW only reads the blob, so it may point at the caller's bytes.
        CredentialBlob: bytes.as_ptr().cast_mut(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        UserName: user.as_mut_ptr(),
        ..CREDENTIALW::default()
    };
    // SAFETY: every pointer in `credential` outlives the call: `target` and
    // `user` are NUL-terminated buffers owned here, and the blob is `bytes`,
    // `len` long. CredWriteW only reads through them; flags must be 0.
    if unsafe { CredWriteW(&raw const credential, 0) } == 0 {
        return Err(last_error());
    }
    Ok(())
}

/// Removes the credential `name`.
#[cfg(test)]
pub(crate) fn delete(name: &str) -> Result<(), CredError> {
    let target = wide(name)?;
    // SAFETY: `target` is NUL-terminated UTF-16 owned here and outlives the
    // call; flags must be 0.
    if unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) } == 0 {
        return Err(last_error());
    }
    Ok(())
}
