// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The shared atomic writer on unix: how a replacement takes the target's
//! group and mode.

use std::path::Path;

/// Whether the scratch ended up in the target's group.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum GidMatch {
    /// `fchown` to the target's gid succeeded.
    Matched,
    /// `fchown` was refused; the mode keeps the owner bits only.
    Unmatched,
}

/// Whether an ACL can widen the group bits past the mode.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AclPresence {
    /// Neither file carries an access ACL. Only the Linux probe can prove it.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    Absent,
    /// An ACL is present, or the probe could not tell.
    PresentOrUnknown,
}

#[cfg(unix)]
impl AclPresence {
    /// Only a proven-absent ACL lets the full mode through; off Linux nothing
    /// can be proven, so the answer is always no.
    fn allows_full_mode(self) -> bool {
        match self {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::Absent => true,
            Self::PresentOrUnknown => false,
        }
    }
}

/// Never wider than the target: the full mode only when the group is the
/// target's and no ACL can widen it; otherwise the owner bits only.
#[cfg(unix)]
pub(super) fn inherit_mode(target_mode: u32, gid: GidMatch, acl: AclPresence) -> u32 {
    if gid == GidMatch::Matched && acl.allows_full_mode() {
        target_mode
    } else {
        target_mode & 0o700
    }
}

/// Narrow the open scratch to the target's mode, never wider (unix,
/// `Inherit` over an existing target only). Runs after the bytes are written
/// and synced: the scratch was created private, so the bytes are never in a
/// wider file. Order is fixed: `fchown` first, then `chmod`, never the other
/// way round — the mode is only meaningful once the group is settled.
#[cfg(unix)]
pub(super) fn apply_inherited_mode(
    scratch: &std::fs::File,
    target: &Path,
    target_meta: &std::fs::Metadata,
) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::fs::PermissionsExt as _;
    // Take the target's group when the process may; a refusal only narrows
    // what the chmod below keeps, and is never an error of the write.
    #[cfg(test)]
    seams::event(target, "chown");
    let gid = match std::os::unix::fs::fchown(scratch, None, Some(target_meta.gid())) {
        Ok(()) => GidMatch::Matched,
        Err(_) => GidMatch::Unmatched,
    };
    // An ACL on either file can widen the group bits past the mode; a target
    // that cannot be opened for the probe counts as widened.
    // Only a regular file is opened for the probe, and without waiting: a path
    // swapped for a FIFO after the stat must not block the save.
    let acl = if target_meta.is_file() {
        match crate::open_nonblocking::open_nonblocking(target) {
            Ok(target) => acl_presence(&target, scratch),
            Err(_) => AclPresence::PresentOrUnknown,
        }
    } else {
        AclPresence::PresentOrUnknown
    };
    #[cfg(test)]
    seams::event(target, "chmod");
    scratch.set_permissions(std::fs::Permissions::from_mode(inherit_mode(
        target_meta.mode() & 0o7777,
        gid,
        acl,
    )))
}

/// Whether either file carries an access ACL that can widen the group bits
/// past the mode. Both fds are probed: the target's ACL widens what the mode
/// means, and the scratch's own (inherited from the directory) survives the
/// chmod below.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn acl_presence(target: &std::fs::File, scratch: &std::fs::File) -> AclPresence {
    // An empty read asks only whether the attribute exists: `NODATA` means no
    // ACL, anything else (present, or an error that hides the answer) counts
    // as one.
    fn absent(file: &std::fs::File) -> bool {
        matches!(
            rustix::fs::fgetxattr(file, "system.posix_acl_access", &mut [0u8; 0][..]),
            Err(e) if e == rustix::io::Errno::NODATA
        )
    }
    if absent(target) && absent(scratch) {
        AclPresence::Absent
    } else {
        AclPresence::PresentOrUnknown
    }
}

/// Without the Linux probe there is no way to tell, so every target counts
/// as widened and keeps the owner bits only.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
fn acl_presence(_target: &std::fs::File, _scratch: &std::fs::File) -> AclPresence {
    AclPresence::PresentOrUnknown
}

/// The pin and order rows' seams, armed per folder so parallel tests never
/// meet and a save on a blocking thread still finds them. Test builds only.
#[cfg(test)]
pub(crate) mod seams {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, PoisonError};

    /// Runs with (target or destination, scratch or source).
    pub(crate) type PathHook = Box<dyn FnMut(&Path, &Path) + Send>;
    /// Runs with the scratch's own descriptor.
    pub(crate) type FileHook = Box<dyn FnMut(&std::fs::File) + Send>;

    /// What one folder's saves meet.
    #[derive(Default)]
    pub(crate) struct Seams {
        /// The target's open (or stat) fails with this errno.
        pub(crate) open_error: Option<i32>,
        /// Just before the first byte is written.
        pub(crate) first_write: Option<FileHook>,
        /// Just before the final checks and the rename: (target, scratch).
        pub(crate) before_verify: Option<PathHook>,
        /// A backup, after its source is modelled: (source, destination).
        pub(crate) after_model: Option<PathHook>,
        creates: usize,
        events: Vec<&'static str>,
    }

    static ARMED: Mutex<Option<HashMap<PathBuf, Seams>>> = Mutex::new(None);

    /// The folder `path` sits in, as the key both sides compute alike.
    fn key(path: &Path) -> PathBuf {
        let dir = path.parent().unwrap_or(path);
        std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf())
    }

    fn with<R>(path: &Path, f: impl FnOnce(&mut Seams) -> R) -> Option<R> {
        let mut armed = ARMED.lock().unwrap_or_else(PoisonError::into_inner);
        armed.as_mut()?.get_mut(&key(path)).map(f)
    }

    /// Seams for every save into `dir` until the guard drops.
    pub(crate) fn arm(dir: &Path, seams: Seams) -> Armed {
        let dir = std::fs::canonicalize(dir).expect("an armed folder exists");
        ARMED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_or_insert_with(HashMap::new)
            .insert(dir.clone(), seams);
        Armed(dir)
    }

    /// The armed folder; reads what its saves did.
    pub(crate) struct Armed(PathBuf);

    impl Armed {
        fn read<R>(&self, f: impl FnOnce(&Seams) -> R) -> R {
            let armed = ARMED.lock().unwrap_or_else(PoisonError::into_inner);
            f(armed
                .as_ref()
                .and_then(|map| map.get(&self.0))
                .expect("armed until dropped"))
        }

        /// Scratch files created so far.
        pub(crate) fn creates(&self) -> usize {
            self.read(|s| s.creates)
        }

        /// The steps the saves took, in order.
        pub(crate) fn events(&self) -> Vec<&'static str> {
            self.read(|s| s.events.clone())
        }
    }

    impl Drop for Armed {
        fn drop(&mut self) {
            if let Some(map) = ARMED
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_mut()
            {
                map.remove(&self.0);
            }
        }
    }

    pub(crate) fn open_error(target: &Path) -> Option<std::io::Error> {
        with(target, |s| s.open_error)
            .flatten()
            .map(std::io::Error::from_raw_os_error)
    }

    pub(crate) fn created(target: &Path) {
        with(target, |s| s.creates += 1);
    }

    pub(crate) fn event(target: &Path, step: &'static str) {
        with(target, |s| s.events.push(step));
    }

    // Each hook is taken out under the lock, run after it is released (it
    // may touch the folder), and put back for the folder's next save.
    pub(crate) fn first_write(target: &Path, scratch: &std::fs::File) {
        if let Some(mut hook) = with(target, |s| s.first_write.take()).flatten() {
            hook(scratch);
            with(target, |s| s.first_write = Some(hook));
        }
    }

    pub(crate) fn before_verify(target: &Path, scratch: &Path) {
        if let Some(mut hook) = with(target, |s| s.before_verify.take()).flatten() {
            hook(target, scratch);
            with(target, |s| s.before_verify = Some(hook));
        }
    }

    pub(crate) fn after_model(source: &Path, destination: &Path) {
        if let Some(mut hook) = with(destination, |s| s.after_model.take()).flatten() {
            hook(source, destination);
            with(destination, |s| s.after_model = Some(hook));
        }
    }
}
