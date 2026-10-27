// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Windows half of an `Inherit` save over an existing file: the scratch keeps
//! the target's access list, or the save is refused before any byte is
//! written. A new target, a volume that keeps no access lists, and an
//! unprotected (folder-inherited) list keep today's default create.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt as _;
use std::path::Path;

use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, READ_CONTROL};

use crate::win_acl::{self, Ace, CopySource, CopyWith, Inspection};

/// The create was refused because this token may not give the new file the
/// owner its descriptor names.
const ERROR_INVALID_OWNER: i32 = 1307;

/// Create the scratch at `scratch` with `source`'s owner and, for
/// [`CopyWith::OwnerAndList`], its list. Exactly `ERROR_INVALID_OWNER` becomes
/// the `foreign-owner` refusal; every other failure is returned as itself.
pub(super) fn create_like(
    scratch: &Path,
    source: &CopySource,
    with: CopyWith,
    target: &Path,
) -> io::Result<File> {
    win_acl::create_file_like(scratch, source, with).map_err(|e| {
        if e.raw_os_error() != Some(ERROR_INVALID_OWNER) {
            return e;
        }
        let runs_as = win_acl::current_user_sid()
            .map_or_else(|_| "this account".to_owned(), |sid| sid.to_sddl());
        refused(
            "foreign-owner",
            target,
            &format!(
                "its owner is {}, which the gateway, running as {runs_as}, cannot give a new \
                 file; give the file that owner, or run the gateway as its owner",
                owner_name(&source.inspection)
            ),
        )
    })
}

/// What the Windows `Inherit` step decided for one save.
pub(super) enum KeptScratch {
    /// A scratch created with the target's access list and checked against it.
    Kept(File),
    /// Create the scratch as before: the target's list is the folder's. The
    /// result is checked against this reading of the target, the one already
    /// judged, so nothing is read twice.
    Default(CopySource),
    /// The volume keeps no access lists (FAT, exFAT): create as before, with
    /// no check, since there is no list to widen.
    NoAcls,
}

/// A refused save; the stable code names the class (one per refusal reason).
fn refused(code: &str, target: &Path, detail: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "{code}: {} was not saved: {detail}; the file is unchanged",
            target.display()
        ),
    )
}

/// Decide, and when keeping, create the scratch at `scratch`. On any refusal
/// no scratch is left behind.
pub(super) fn prepare(target: &Path, scratch: &Path) -> io::Result<KeptScratch> {
    // READ_CONTROL alone: a file whose data the user cannot read still saves.
    let model = OpenOptions::new()
        .access_mode(READ_CONTROL)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(target)?;
    prepare_from(&model, target, scratch)
}

/// [`prepare`] with the model already open (it must carry `READ_CONTROL`):
/// everything about the model is read through this one handle, so a path
/// swapped underneath cannot lend another file's list. `target` only names
/// it in messages.
pub(super) fn prepare_from(model: &File, target: &Path, scratch: &Path) -> io::Result<KeptScratch> {
    match volume_keeps_acls(model) {
        Ok(true) => {}
        // FAT and exFAT keep no list, so there is none to widen.
        Ok(false) => return Ok(KeptScratch::NoAcls),
        Err(e) => {
            return Err(refused(
                "volume-query-failed",
                target,
                &format!("its volume could not be asked whether it keeps access lists ({e})"),
            ));
        }
    }
    let source = win_acl::inspect_for_copy(model).map_err(|e| {
        refused(
            "descriptor-unreadable",
            target,
            &format!("its access list could not be read ({e})"),
        )
    })?;
    if let Some((code, detail)) = source_refusal(&source.inspection, source.enforcing_sacl_aces) {
        return Err(refused(code, target, detail));
    }
    if !source.inspection.protected {
        // An inherited list is the folder's: a default create reproduces it.
        // The check after the create still refuses anything wider.
        return Ok(KeptScratch::Default(source));
    }
    let file = create_like(scratch, &source, CopyWith::OwnerAndList, target)?;
    match verify(&file, &source, target) {
        Ok(()) => Ok(KeptScratch::Kept(file)),
        Err(e) => {
            drop(file);
            let _ = std::fs::remove_file(scratch);
            Err(e)
        }
    }
}

/// The scratch's owner, access list (in order) and access-enforcing SACL
/// entries equal the target's. Runs before any byte is written.
pub(super) fn verify(file: &File, source: &CopySource, target: &Path) -> io::Result<()> {
    let got = win_acl::inspect_for_copy(file).map_err(|e| {
        refused(
            "descriptor-unreadable",
            target,
            &format!("the replacement's access list could not be read ({e})"),
        )
    })?;
    if got.enforcing_sacl_aces > 0 {
        return Err(refused(
            "security-label",
            target,
            "the replacement would carry an integrity label or access policy from its folder",
        ));
    }
    let (want, have) = (&source.inspection, &got.inspection);
    if want.owner != have.owner {
        return Err(refused(
            "foreign-owner",
            target,
            &format!(
                "its owner is {}, but files the gateway creates here are owned by {}; give the \
                 file that owner, or run the gateway as its owner",
                owner_name(want),
                owner_name(have)
            ),
        ));
    }
    if let Some(diff) = first_difference(want, have) {
        return Err(refused(
            "acl-mismatch",
            target,
            &format!(
                "its access list cannot be copied exactly ({diff}); if it was moved in from \
                 another folder, reset its inheritance (icacls <file> /reset)"
            ),
        ));
    }
    Ok(())
}

fn volume_keeps_acls(file: &File) -> io::Result<bool> {
    #[cfg(test)]
    if let Some(answer) = test_seams::VOLUME.with(std::cell::Cell::get) {
        return Ok(answer);
    }
    win_acl::volume_keeps_acls(file)
}

/// Why a target cannot be copied at all, before any scratch exists: any
/// access-enforcing SACL entry (integrity label, scoped policy, resource
/// attribute, trust label, access filter), or a list entry the gateway does
/// not decode.
pub(super) fn source_refusal(
    inspection: &Inspection,
    enforcing_sacl_aces: usize,
) -> Option<(&'static str, &'static str)> {
    if enforcing_sacl_aces > 0 {
        return Some((
            "security-label",
            "it carries an integrity label or access policy the gateway cannot copy",
        ));
    }
    if has_other(inspection) {
        return Some((
            "undecodable-ace",
            "its access list holds an entry type the gateway cannot verify",
        ));
    }
    None
}

fn has_other(inspection: &Inspection) -> bool {
    inspection
        .dacl
        .iter()
        .flatten()
        .any(|ace| matches!(ace, Ace::Other { .. }))
}

fn owner_name(inspection: &Inspection) -> String {
    inspection
        .owner
        .as_ref()
        .map_or_else(|| "nobody".to_owned(), win_acl::Sid::to_sddl)
}

/// The first position where the two lists differ, or `None` when equal in
/// protection, order and content. A NULL list and an empty list differ.
pub(super) fn first_difference(want: &Inspection, have: &Inspection) -> Option<String> {
    #[cfg(test)]
    if test_seams::FORCE_MISMATCH.with(std::cell::Cell::get) {
        return Some("forced by test".to_owned());
    }
    if want.protected != have.protected {
        return Some(format!(
            "protected {} vs {}",
            want.protected, have.protected
        ));
    }
    match (&want.dacl, &have.dacl) {
        (None, None) => None,
        (None, Some(_)) | (Some(_), None) => Some("a list that grants everyone".to_owned()),
        (Some(w), Some(h)) => {
            let len = w.len().max(h.len());
            (0..len).find_map(|i| match (w.get(i), h.get(i)) {
                (Some(a), Some(b)) if a == b => None,
                (a, b) => Some(format!("entry {i}: {} vs {}", describe(a), describe(b))),
            })
        }
    }
}

fn describe(ace: Option<&Ace>) -> String {
    match ace {
        None => "none".to_owned(),
        Some(Ace::Allowed { mask, sid, .. }) => format!("allow {mask:#x} {}", sid.to_sddl()),
        Some(Ace::Denied { mask, sid, .. }) => format!("deny {mask:#x} {}", sid.to_sddl()),
        Some(Ace::Other { ace_type }) => format!("type {ace_type}"),
    }
}

/// Thread-local seams for the volume answer and a forced mismatch, so the
/// fallback and the refusal path are pinned on a normal NTFS runner.
#[cfg(test)]
pub(super) mod test_seams {
    thread_local! {
        pub(crate) static VOLUME: std::cell::Cell<Option<bool>> =
            const { std::cell::Cell::new(None) };
        pub(crate) static FORCE_MISMATCH: std::cell::Cell<bool> =
            const { std::cell::Cell::new(false) };
    }
}
