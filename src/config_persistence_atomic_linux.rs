// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Linux: the access labels a replacement keeps (`security.selinux`,
//! `security.SMACK64`), and the access ACL a scratch inherits from its folder.

use std::fs::File;
use std::io;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use rustix::io::Errno;

/// The access-enforcing labels a replacement keeps, as the kernel names them.
const LABELS: [&str; 2] = ["security.selinux", "security.SMACK64"];

/// The access ACL a new file takes from its folder's default ACL.
const ACCESS_ACL: &str = "system.posix_acl_access";

/// Where the labels to keep are read from.
#[derive(Clone, Copy)]
pub(super) enum At<'a> {
    /// A save's target, by name: reading a label needs no read access to the
    /// file, so a target its owner cannot read keeps saving.
    Path(&'a Path),
    /// A backup's source, through the descriptor its bytes come from.
    File(&'a File),
}

/// What a save keeps on Linux: where its labels come from, and whether the
/// scratch's inherited access ACL is stripped (replacements and `Private`
/// saves; never a backup).
pub(super) struct Keep<'a> {
    pub(super) from: At<'a>,
    pub(super) strip: bool,
}

/// The target's labels as read before the first byte: each name, and its
/// bytes or `None` when the target has no such label.
pub(super) struct Wanted(Vec<(&'static str, Option<Vec<u8>>)>);

impl Wanted {
    /// Nothing to keep: a save with no file to model.
    pub(super) fn none() -> Self {
        Self(Vec::new())
    }
}

/// "No such attribute" or "this filesystem keeps none": nothing to keep.
fn absent(e: Errno) -> bool {
    e == Errno::NODATA || e == Errno::NOTSUP
}

/// One attribute through `get` (an empty buffer asks for the size): its
/// bytes, or `None` when absent. A value that grew between the size probe and
/// the read (`ERANGE`) is read again once.
fn read_with(
    mut get: impl FnMut(&mut [u8]) -> Result<usize, Errno>,
) -> Result<Option<Vec<u8>>, Errno> {
    let mut grew = false;
    loop {
        let len = match get(&mut []) {
            Ok(len) => len,
            Err(e) if absent(e) => return Ok(None),
            Err(e) => return Err(e),
        };
        let mut value = vec![0; len];
        match get(&mut value) {
            Ok(read) => {
                value.truncate(read);
                return Ok(Some(value));
            }
            Err(e) if e == Errno::RANGE && !grew => grew = true,
            Err(e) if absent(e) => return Ok(None),
            Err(e) => return Err(e),
        }
    }
}

/// Steps 3b and 3c, before the first byte: strip the ACL the scratch took
/// from its folder, read the labels to keep, check that a save's target is
/// still the file step 1 modelled, and set the labels on the still-empty
/// scratch, so its bytes never sit under a wider label.
pub(super) fn labels_first(save: &super::Save<'_>, file: &File) -> io::Result<Wanted> {
    if save.keep.strip {
        strip(save.target, file)?;
    }
    let Some(model) = save.model else {
        return Ok(Wanted::none());
    };
    let wanted = read_labels(save.target, save.keep.from)?;
    #[cfg(test)]
    super::seams::after_labels_read(save.target, save.scratch);
    // Read by name, so the name must still be the modelled file.
    let same = save.seen.is_none()
        || std::fs::symlink_metadata(save.target)
            .is_ok_and(|at| (at.dev(), at.ino()) == (model.dev, model.ino));
    if !same {
        return Err(super::changed(save.target));
    }
    set_labels(save.target, &wanted, file)?;
    Ok(wanted)
}

/// Step 3b: remove the access ACL the scratch took from its folder. No ACL,
/// or a filesystem that keeps none, is fine; any other failure is returned
/// and the save does not go ahead.
fn strip(target: &Path, scratch: &File) -> io::Result<()> {
    #[cfg(test)]
    super::seams::event(target, "strip");
    #[cfg(test)]
    let removed = match injected(target, fake::Call::AclStrip) {
        Some(e) => Err(e),
        None => rustix::fs::fremovexattr(scratch, ACCESS_ACL),
    };
    #[cfg(not(test))]
    let removed = {
        let _ = target;
        rustix::fs::fremovexattr(scratch, ACCESS_ACL)
    };
    match removed {
        Err(e) if !absent(e) => Err(e.into()),
        _ => Ok(()),
    }
}

/// Step 3b: the labels to keep, read from `at` before the first byte. A
/// label that cannot be read refuses `label-not-kept`: the writer does not
/// guess what the target carried.
fn read_labels(target: &Path, at: At<'_>) -> io::Result<Wanted> {
    #[cfg(test)]
    super::seams::event(target, "labels-read");
    LABELS
        .iter()
        .map(|&name| {
            read_with(|buf| get(target, at, Side::Source, name, buf))
                .map(|value| (name, value))
                .map_err(|_| super::label_not_kept(target, name))
        })
        .collect::<io::Result<_>>()
        .map(Wanted)
}

/// Step 3c: each label the target carries, given to the still-empty scratch
/// and read back; a scratch that already reads the same bytes needs no set.
/// A set the kernel refuses, or a read-back that differs, refuses
/// `label-not-kept`.
fn set_labels(target: &Path, wanted: &Wanted, scratch: &File) -> io::Result<()> {
    #[cfg(test)]
    super::seams::event(target, "labels-set");
    for &(name, ref value) in &wanted.0 {
        let Some(value) = value else { continue };
        let reads_back = || {
            read_with(|buf| get(target, At::File(scratch), Side::Scratch, name, buf))
                .is_ok_and(|now| now.as_ref() == Some(value))
        };
        if reads_back() {
            continue;
        }
        if set(target, scratch, name, value).is_err() || !reads_back() {
            return Err(super::label_not_kept(target, name));
        }
    }
    Ok(())
}

/// Step 9: the labels at `at` are still the ones read before the first
/// byte, the scratch still carries every one of them, and a stripped scratch
/// still has no access ACL. Anything else is another writer's work.
pub(super) fn still_kept(
    target: &Path,
    wanted: &Wanted,
    scratch: &File,
    at: At<'_>,
    stripped: bool,
) -> bool {
    let labels_hold = wanted.0.iter().all(|&(name, ref value)| {
        let source_same = read(target, at, Side::Source, name).is_ok_and(|now| now == *value);
        let scratch_same = value.is_none()
            || read(target, At::File(scratch), Side::Scratch, name).is_ok_and(|now| now == *value);
        source_same && scratch_same
    });
    labels_hold && (!stripped || acl_absent(target, scratch))
}

/// One whole label of `at`.
fn read(
    target: &Path,
    at: At<'_>,
    side: Side,
    name: &'static str,
) -> Result<Option<Vec<u8>>, Errno> {
    read_with(|buf| get(target, at, side, name, buf))
}

/// The scratch has no access ACL (or its filesystem keeps none).
fn acl_absent(target: &Path, scratch: &File) -> bool {
    #[cfg(test)]
    if let Some(e) = injected(target, fake::Call::AclRead) {
        return absent(e);
    }
    #[cfg(not(test))]
    let _ = target;
    matches!(
        rustix::fs::fgetxattr(scratch, ACCESS_ACL, &mut []),
        Err(e) if absent(e)
    )
}

/// Which side of the save a label read touches.
#[derive(Clone, Copy)]
enum Side {
    /// The target, or a backup's source.
    Source,
    /// The scratch, read back after a set or before the rename.
    Scratch,
}

/// One label read of `at`. Test builds with the folder's label store armed
/// answer from the store instead of the kernel.
fn get(
    target: &Path,
    at: At<'_>,
    side: Side,
    name: &'static str,
    buf: &mut [u8],
) -> Result<usize, Errno> {
    #[cfg(test)]
    if let Some(store) = super::seams::labels(target) {
        let call = match side {
            Side::Source => fake::Call::Read,
            Side::Scratch => fake::Call::ReadBack,
        };
        return store.getxattr(identity(at)?, call, name, buf);
    }
    #[cfg(not(test))]
    let _ = (target, side);
    match at {
        At::Path(path) => rustix::fs::lgetxattr(path, name, buf),
        At::File(file) => rustix::fs::fgetxattr(file, name, buf),
    }
}

/// One label set on the scratch (or into the armed store in test builds).
fn set(target: &Path, scratch: &File, name: &'static str, value: &[u8]) -> Result<(), Errno> {
    #[cfg(test)]
    if let Some(store) = super::seams::labels(target) {
        let meta = scratch.metadata().map_err(|_| Errno::IO)?;
        return store.setxattr(
            (meta.dev(), meta.ino()),
            (meta.mode(), meta.len()),
            name,
            value,
        );
    }
    #[cfg(not(test))]
    let _ = target;
    rustix::fs::fsetxattr(scratch, name, value, rustix::fs::XattrFlags::empty())
}

/// The errno a test injected for `call`, if any. Never in production.
#[cfg(test)]
fn injected(target: &Path, call: fake::Call) -> Option<Errno> {
    super::seams::labels(target)?.injected(call, ACCESS_ACL)
}

/// The file `at` names, as the store keys it: (device, inode).
#[cfg(test)]
fn identity(at: At<'_>) -> Result<(u64, u64), Errno> {
    let meta = match at {
        At::Path(path) => std::fs::symlink_metadata(path),
        At::File(file) => file.metadata(),
    }
    .map_err(|_| Errno::IO)?;
    Ok((meta.dev(), meta.ino()))
}

#[cfg(test)]
pub(crate) use fake::{Call, FakeLabels, SetSeen, Times};

/// The label store the writer rows inject in place of the kernel's
/// `security.*` calls, keyed by file identity. Test builds only.
#[cfg(test)]
mod fake {
    use std::collections::HashMap;
    use std::os::unix::fs::MetadataExt as _;
    use std::path::Path;
    use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

    use rustix::io::Errno;

    /// Which of the writer's label calls an injected errno answers.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Call {
        /// The target's (or a backup source's) label read.
        Read,
        /// The set on the scratch.
        Set,
        /// The scratch's read-back after a set.
        ReadBack,
        /// The removal of the scratch's access ACL (the kernel's own call
        /// unless an errno is injected).
        AclStrip,
        /// The final check that the scratch still has no access ACL.
        AclRead,
    }

    /// How often an injected errno answers.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Times {
        /// Only the next matching call.
        Once,
        /// Every matching call.
        Always,
    }

    /// One set on a scratch: the label's name, and the scratch's mode and
    /// size at that moment.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct SetSeen {
        pub(crate) name: &'static str,
        pub(crate) mode: u32,
        pub(crate) size: u64,
    }

    #[derive(Default)]
    pub(super) struct Store {
        pub(super) values: HashMap<(u64, u64), HashMap<&'static str, Vec<u8>>>,
        pub(super) errors: Vec<(Call, &'static str, i32, Times)>,
        pub(super) rewrite: Option<(&'static str, Vec<u8>)>,
        pub(super) erange_once: bool,
        pub(super) sets: Vec<SetSeen>,
        /// What a file with no label of that name reads, as a folder's
        /// default context does for a new file.
        pub(super) defaults: HashMap<&'static str, Vec<u8>>,
    }

    /// The store, shared with the row that armed it.
    #[derive(Clone, Default)]
    pub(crate) struct FakeLabels(Arc<Mutex<Store>>);

    fn id(path: &Path) -> (u64, u64) {
        let meta = std::fs::symlink_metadata(path).expect("a labelled file exists");
        (meta.dev(), meta.ino())
    }

    impl FakeLabels {
        pub(super) fn store(&self) -> MutexGuard<'_, Store> {
            self.0.lock().unwrap_or_else(PoisonError::into_inner)
        }

        /// Gives the file at `path` the label `name` = `value`.
        pub(crate) fn label(&self, path: &Path, name: &'static str, value: &[u8]) {
            self.store()
                .values
                .entry(id(path))
                .or_default()
                .insert(name, value.to_vec());
        }

        /// The label `name` of the file at `path`, if it has one.
        pub(crate) fn get(&self, path: &Path, name: &str) -> Option<Vec<u8>> {
            self.store()
                .values
                .get(&id(path))
                .and_then(|labels| labels.get(name))
                .cloned()
        }

        /// `call` for `name` answers `errno`, `times`.
        pub(crate) fn fail(&self, call: Call, name: &'static str, errno: i32, times: Times) {
            self.store().errors.push((call, name, errno, times));
        }

        /// Between the next set of `name` and its read-back, the scratch's
        /// value becomes `value`.
        pub(crate) fn rewrite_after_set(&self, name: &'static str, value: &[u8]) {
            self.store().rewrite = Some((name, value.to_vec()));
        }

        /// The next sized read answers `ERANGE`, as when the label grew
        /// between the length probe and the read.
        pub(crate) fn erange_once(&self) {
            self.store().erange_once = true;
        }

        /// Every set so far, in order.
        pub(crate) fn sets(&self) -> Vec<SetSeen> {
            self.store().sets.clone()
        }

        /// Any file without its own `name` label reads `value`.
        pub(crate) fn folder_default(&self, name: &'static str, value: &[u8]) {
            self.store().defaults.insert(name, value.to_vec());
        }

        /// One label read, answered as the kernel would: an injected errno,
        /// `ERANGE` once if armed, `NODATA` for no label, else the size (empty
        /// buffer) or the bytes.
        pub(in super::super) fn getxattr(
            &self,
            id: (u64, u64),
            call: Call,
            name: &'static str,
            buf: &mut [u8],
        ) -> Result<usize, Errno> {
            let mut store = self.store();
            if let Some(errno) = store.take_error(call, name) {
                return Err(Errno::from_raw_os_error(errno));
            }
            if !buf.is_empty() && store.erange_once {
                store.erange_once = false;
                return Err(Errno::RANGE);
            }
            let value = {
                let held = &*store;
                held.values
                    .get(&id)
                    .and_then(|labels| labels.get(name))
                    .or_else(|| held.defaults.get(name))
                    .cloned()
                    .ok_or(Errno::NODATA)?
            };
            if !buf.is_empty() {
                buf.get_mut(..value.len())
                    .ok_or(Errno::RANGE)?
                    .copy_from_slice(&value);
            }
            Ok(value.len())
        }

        /// One label set on the scratch `id`, recording its (mode, size);
        /// an armed rewrite replaces the stored value.
        pub(in super::super) fn setxattr(
            &self,
            id: (u64, u64),
            (mode, size): (u32, u64),
            name: &'static str,
            value: &[u8],
        ) -> Result<(), Errno> {
            let mut store = self.store();
            if let Some(errno) = store.take_error(Call::Set, name) {
                return Err(Errno::from_raw_os_error(errno));
            }
            store.sets.push(SetSeen { name, mode, size });
            let stored = match store.rewrite.take() {
                Some((rewritten, other)) if rewritten == name => other,
                kept => {
                    store.rewrite = kept;
                    value.to_vec()
                }
            };
            store.values.entry(id).or_default().insert(name, stored);
            Ok(())
        }

        /// The errno injected for `call` on `name`, if any.
        pub(in super::super) fn injected(&self, call: Call, name: &str) -> Option<Errno> {
            self.store()
                .take_error(call, name)
                .map(Errno::from_raw_os_error)
        }
    }

    impl Store {
        /// The errno injected for (`call`, `name`); a `Times::Once` entry is
        /// used up.
        fn take_error(&mut self, call: Call, name: &str) -> Option<i32> {
            let at = self
                .errors
                .iter()
                .position(|&(c, n, _, _)| c == call && n == name)?;
            let &(_, _, errno, times) = self.errors.get(at)?;
            if times == Times::Once {
                self.errors.remove(at);
            }
            Some(errno)
        }
    }
}
