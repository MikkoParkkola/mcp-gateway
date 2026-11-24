// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The shared atomic writer on unix. A save keeps the replaced file's owner
//! (or refuses `foreign-owner`), never widens its group or mode, writes into
//! a scratch nobody else can open, and refuses `target-changed` when another
//! process swaps or alters the file, or the scratch, before the rename.

use std::fs::File;
use std::io::{self, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;

use super::FileMode;

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

/// A save the writer turned down before anything was replaced: the code a
/// caller matches on, and the sentence the user reads.
#[derive(Debug)]
pub(crate) struct WriterRefusal {
    pub(crate) code: &'static str,
    text: String,
}

impl std::fmt::Display for WriterRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

impl std::error::Error for WriterRefusal {}

fn refusal(code: &'static str, text: String) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        WriterRefusal { code, text },
    )
}

/// Another process swapped or altered the file being replaced, or the new
/// copy, while the save was in progress.
fn changed(target: &Path) -> io::Error {
    let shown = target.display();
    refusal(
        "target-changed",
        format!(
            "target-changed: refused to replace {shown}: another process replaced or changed \
             the file during the save. Nothing was written. Save again to write the new \
             contents."
        ),
    )
}

/// The file belongs to someone else and this process may not hand a new
/// file to them.
fn foreign_owner(target: &Path, owner: u32) -> io::Error {
    let shown = target.display();
    let me = rustix::process::geteuid().as_raw();
    refusal(
        "foreign-owner",
        format!(
            "foreign-owner: refused to replace {shown}: the file belongs to uid {owner}, but \
             this gateway runs as uid {me}. Nothing was written. To save it, run the gateway \
             as uid {owner}, or hand the file to uid {me} (chown {me} {shown})."
        ),
    )
}

/// macOS: the writer cannot open the file for reading, so it cannot check
/// what access the file grants (its access control list) and will not guess.
/// (Built in tests elsewhere too, for the seam that injects each refusal.)
#[cfg(any(target_os = "macos", test))]
fn unreadable(target: &Path) -> io::Error {
    let shown = target.display();
    let me = rustix::process::geteuid().as_raw();
    refusal(
        "acl-not-kept",
        format!(
            "acl-not-kept: refused to replace {shown}: this gateway cannot read the file to \
             check its access control list. Nothing was written. To save it, give uid {me} \
             read access to the file."
        ),
    )
}

/// The flags of the one look at the target: never through a link, and never
/// waiting on a FIFO. Linux needs no read access for it (`O_PATH`); macOS
/// opens for events only, which does need read access.
#[cfg(any(target_os = "linux", target_os = "android"))]
const LOOK: i32 =
    (rustix::fs::OFlags::PATH.bits() | rustix::fs::OFlags::NOFOLLOW.bits()).cast_signed();
#[cfg(target_os = "macos")]
const LOOK: i32 = libc::O_EVTONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK;
#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
const LOOK: i32 =
    (rustix::fs::OFlags::NOFOLLOW.bits() | rustix::fs::OFlags::NONBLOCK.bits()).cast_signed();

/// What the writer knows of the file a save replaces (or a backup copies):
/// owner, group, mode and identity, all from one look. The identity pins the
/// file, and its size and modification time catch a rewrite in place: all
/// are compared again just before the rename. A filesystem with coarse times
/// can miss a same-size rewrite within one tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Model {
    uid: u32,
    gid: u32,
    mode: u32,
    dev: u64,
    ino: u64,
    size: u64,
    mtime: (i64, i64),
}

impl Model {
    fn of(meta: &std::fs::Metadata) -> Self {
        Self {
            uid: meta.uid(),
            gid: meta.gid(),
            mode: meta.mode() & 0o7777,
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.size(),
            mtime: (meta.mtime(), meta.mtime_nsec()),
        }
    }
}

/// What step 1 found at a save's target: a regular file (modelled), nothing,
/// or another entry, such as a link, that the rename replaces unmodelled.
/// Step 9 requires the same: the same file, still nothing, or the same entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Seen {
    File(Model),
    Absent,
    Entry { dev: u64, ino: u64 },
}

/// Step 1: what is at `target`, from one look: the regular file's model,
/// nothing, or another entry (a link is replaced, never modelled). Any other
/// failure to look is returned: a file the writer cannot inspect is not an
/// absent one.
fn model_at(target: &Path) -> io::Result<Seen> {
    #[cfg(test)]
    if let Some(forced) = seams::open_error(target) {
        return Err(forced);
    }
    let looked = File::options().read(true).custom_flags(LOOK).open(target);
    let file = match looked {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Seen::Absent),
        // A no-follow open of a link fails with ELOOP off Linux; only a path
        // confirmed to be a link takes the no-model path.
        Err(e) if e.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) => {
            return match std::fs::symlink_metadata(target) {
                Ok(meta) if meta.file_type().is_symlink() => Ok(Seen::Entry {
                    dev: meta.dev(),
                    ino: meta.ino(),
                }),
                _ => Err(e),
            };
        }
        #[cfg(target_os = "macos")]
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return Err(unreadable(target)),
        Err(e) => return Err(e),
    };
    let meta = file.metadata()?;
    Ok(if meta.is_file() {
        Seen::File(Model::of(&meta))
    } else {
        Seen::Entry {
            dev: meta.dev(),
            ino: meta.ino(),
        }
    })
}

/// Step 2: a file another user owns is saved only by a process that may give
/// the new file to that user (root); anyone else is turned away here, before
/// a scratch exists.
fn owner_allows(target: &Path, model: &Model) -> io::Result<()> {
    let euid = rustix::process::geteuid();
    if model.uid == euid.as_raw() || euid.is_root() {
        Ok(())
    } else {
        Err(foreign_owner(target, model.uid))
    }
}

/// One save in progress: where it goes, its scratch, and the model it keeps
/// (taken from `model_path`: the target for a save, the source for a backup).
struct Save<'a> {
    target: &'a Path,
    scratch: &'a Path,
    model_path: &'a Path,
    mode: FileMode,
    model: Option<&'a Model>,
    /// A save's target as step 1 saw it; `None` for a backup, whose
    /// destination is replaced whatever is there.
    seen: Option<Seen>,
}

/// What the new copy was settled to; step 9 checks it is still that.
struct Settled {
    uid: u32,
    gid: Option<u32>,
    mode: Option<u32>,
}

/// Replace `target` with `bytes`: look once and pin, check the owner, write
/// into a mode-0000 scratch, run `check`, settle the scratch's owner, group
/// and mode, verify the scratch and the target, then rename. A refusal leaves
/// the target as it was and no scratch behind.
pub(super) fn write(
    target: &Path,
    bytes: &[u8],
    mode: FileMode,
    observe: impl FnOnce(&File),
    check: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    let seen = model_at(target)?;
    let model = match seen {
        Seen::File(model) => Some(model),
        Seen::Absent | Seen::Entry { .. } => None,
    };
    if let Some(model) = &model {
        owner_allows(target, model)?;
    }
    // Closed from creation whenever the bytes must not sit in a wider file;
    // an `Inherit` file with nothing to inherit from keeps the default create.
    let create = if model.is_some() || mode == FileMode::Private {
        super::ScratchCreate::Closed
    } else {
        super::ScratchCreate::Default
    };
    let (mut file, scratch) =
        super::create_scratch(target, super::super::next_scratch_seed(), create)?;
    #[cfg(test)]
    seams::created(target);
    let save = Save {
        target,
        scratch: &scratch,
        model_path: target,
        mode,
        model: model.as_ref(),
        seen: Some(seen),
    };
    let filled = fill(&save, &mut file, bytes, observe, check);
    finish(&save, file, filled, bytes)
}

/// A backup of `src` at `dst`, made like a save with the source as the model:
/// its bytes and its model come from one descriptor, and a link at `dst` is
/// replaced, not followed.
pub(super) fn copy(src: &Path, dst: &Path) -> io::Result<()> {
    use std::io::Read as _;
    let src = std::fs::canonicalize(src)?;
    let source = File::open(&src)?;
    let model = Model::of(&source.metadata()?);
    owner_allows(dst, &model)?;
    #[cfg(test)]
    seams::after_model(&src, dst);
    let mut bytes = Vec::new();
    (&source).read_to_end(&mut bytes)?;
    let (mut file, scratch) = super::create_scratch(
        dst,
        super::super::next_scratch_seed(),
        super::ScratchCreate::Closed,
    )?;
    #[cfg(test)]
    seams::created(dst);
    let save = Save {
        target: dst,
        scratch: &scratch,
        model_path: &src,
        mode: FileMode::Inherit,
        model: Some(&model),
        seen: None,
    };
    let filled = fill(&save, &mut file, &bytes, |_| {}, || Ok(()));
    finish(&save, file, filled, &bytes)
}

/// Steps 4 to 9 on the open scratch.
fn fill(
    save: &Save<'_>,
    file: &mut File,
    bytes: &[u8],
    observe: impl FnOnce(&File),
    check: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    #[cfg(test)]
    seams::first_write(save.target, file);
    #[cfg(test)]
    seams::event(save.target, "write");
    file.write_all(bytes)?;
    #[cfg(test)]
    seams::event(save.target, "sync");
    file.sync_all()?;
    observe(file);
    #[cfg(test)]
    seams::event(save.target, "check");
    check()?;
    let settled = settle(save, file)?;
    #[cfg(test)]
    seams::before_verify(save.target, save.scratch);
    verify(save, file, &settled)
}

/// Rename a filled scratch into place, then close it; on any failure remove
/// whatever stands at the scratch's name and return the error.
fn finish(save: &Save<'_>, file: File, filled: io::Result<()>, bytes: &[u8]) -> io::Result<()> {
    #[cfg(test)]
    let staged = filled
        .is_ok()
        .then(|| super::super::crash_fs::stage_held(save.target, &file, bytes))
        .flatten();
    #[cfg(not(test))]
    let _ = bytes;
    let renamed = filled.and_then(|()| super::super::rename_with_retry(save.scratch, save.target));
    drop(file);
    if let Err(e) = renamed {
        let _ = std::fs::remove_file(save.scratch);
        return Err(e);
    }
    #[cfg(test)]
    if let Some(staged) = staged {
        super::super::crash_fs::bind(save.target, staged);
    }
    Ok(())
}

/// Steps 7 and 8: owner, then group, then mode, so no later ownership change
/// can clear a bit the mode step set. A private file is owner-only; an
/// inherited one is never wider than the model (`inherit_mode`).
fn settle(save: &Save<'_>, file: &File) -> io::Result<Settled> {
    let euid = rustix::process::geteuid().as_raw();
    let Some(model) = save.model else {
        return Ok(match save.mode {
            FileMode::Private => {
                set_mode(save, file, 0o600)?;
                Settled {
                    uid: euid,
                    gid: None,
                    mode: Some(0o600),
                }
            }
            // Nothing to inherit from: the default create's own access.
            FileMode::Inherit => Settled {
                uid: euid,
                gid: None,
                mode: None,
            },
        });
    };
    if model.uid != euid {
        #[cfg(test)]
        seams::event(save.target, "chown");
        // Only root gets here (step 2); a filesystem that refuses its chown
        // says why in its own error.
        std::os::unix::fs::fchown(file, Some(model.uid), None)?;
    }
    let (mode, gid) = match save.mode {
        FileMode::Private => (0o600, None),
        FileMode::Inherit => {
            #[cfg(test)]
            seams::event(save.target, "chown");
            // The group when the process may take it; without it the mode
            // keeps the owner bits only.
            let gid = match std::os::unix::fs::fchown(file, None, Some(model.gid)) {
                Ok(()) => GidMatch::Matched,
                Err(_) => GidMatch::Unmatched,
            };
            // A model file that cannot be opened for the probe counts as
            // carrying an ACL; the probe never waits on a FIFO.
            let acl = match crate::open_nonblocking::open_nonblocking(save.model_path) {
                Ok(model_file) => acl_presence(&model_file, file),
                Err(_) => AclPresence::PresentOrUnknown,
            };
            let matched = (gid == GidMatch::Matched).then_some(model.gid);
            (inherit_mode(model.mode, gid, acl), matched)
        }
    };
    set_mode(save, file, mode)?;
    Ok(Settled {
        uid: model.uid,
        gid,
        mode: Some(mode),
    })
}

fn set_mode(save: &Save<'_>, file: &File, mode: u32) -> io::Result<()> {
    #[cfg(test)]
    seams::event(save.target, "chmod");
    #[cfg(not(test))]
    let _ = save;
    file.set_permissions(std::fs::Permissions::from_mode(mode))
}

/// Step 9: the scratch, read through its own descriptor, is still what the
/// save settled; the model file, read again by name, is still the file that
/// was modelled, unchanged; and the scratch's name still names this scratch.
/// Anything else is another writer's work, and the save refuses.
fn verify(save: &Save<'_>, file: &File, settled: &Settled) -> io::Result<()> {
    #[cfg(test)]
    if let Some(refused) = seams::refused(save.target) {
        return Err(refused);
    }
    let now = file.metadata()?;
    let scratch_as_settled = now.uid() == settled.uid
        && settled.gid.is_none_or(|gid| now.gid() == gid)
        && settled.mode.is_none_or(|mode| now.mode() & 0o7777 == mode);
    let model_unchanged = save.model.is_none_or(|model| {
        std::fs::symlink_metadata(save.model_path)
            .is_ok_and(|meta| meta.is_file() && Model::of(&meta) == *model)
    });
    // A target that was nothing, or a link, must still be that: a file
    // created or swapped in meanwhile is another writer's, never replaced.
    let target_unchanged = match save.seen {
        None | Some(Seen::File(_)) => true,
        Some(Seen::Absent) => std::fs::symlink_metadata(save.target)
            .is_err_and(|e| e.kind() == io::ErrorKind::NotFound),
        Some(Seen::Entry { dev, ino }) => std::fs::symlink_metadata(save.target)
            .is_ok_and(|at| (at.dev(), at.ino()) == (dev, ino)),
    };
    let name_unchanged = std::fs::symlink_metadata(save.scratch)
        .is_ok_and(|at| (at.dev(), at.ino()) == (now.dev(), now.ino()));
    if scratch_as_settled && model_unchanged && target_unchanged && name_unchanged {
        Ok(())
    } else {
        Err(changed(save.target))
    }
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
        /// The next save's final check before the rename turns it down with
        /// the writer's own refusal of this code (`foreign-owner` names uid
        /// 4101); later saves, such as a restore, go through.
        pub(crate) refuse: Option<&'static str>,
        /// Just before the first byte is written.
        pub(crate) first_write: Option<FileHook>,
        /// Just before the final checks and the rename: (target, scratch).
        pub(crate) before_verify: Option<PathHook>,
        /// A backup, after its source is modelled: (source, destination).
        pub(crate) after_model: Option<PathHook>,
    }

    /// One armed folder: its seams and what its saves did.
    struct Folder {
        seams: Seams,
        creates: usize,
        events: Vec<&'static str>,
    }

    static ARMED: Mutex<Option<HashMap<PathBuf, Folder>>> = Mutex::new(None);

    /// The folder `path` sits in, as the key both sides compute alike.
    fn key(path: &Path) -> PathBuf {
        let dir = path.parent().unwrap_or(path);
        std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf())
    }

    fn with<R>(path: &Path, f: impl FnOnce(&mut Folder) -> R) -> Option<R> {
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
            .insert(
                dir.clone(),
                Folder {
                    seams,
                    creates: 0,
                    events: Vec::new(),
                },
            );
        Armed(dir)
    }

    /// The armed folder; reads what its saves did.
    pub(crate) struct Armed(PathBuf);

    impl Armed {
        fn read<R>(&self, f: impl FnOnce(&Folder) -> R) -> R {
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
        with(target, |s| s.seams.open_error)
            .flatten()
            .map(std::io::Error::from_raw_os_error)
    }

    pub(crate) fn refused(target: &Path) -> Option<std::io::Error> {
        Some(match with(target, |s| s.seams.refuse.take()).flatten()? {
            "foreign-owner" => super::foreign_owner(target, 4101),
            "target-changed" => super::changed(target),
            "acl-not-kept" => super::unreadable(target),
            other => panic!("no writer refusal has the code {other}"),
        })
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
        if let Some(mut hook) = with(target, |s| s.seams.first_write.take()).flatten() {
            hook(scratch);
            with(target, |s| s.seams.first_write = Some(hook));
        }
    }

    pub(crate) fn before_verify(target: &Path, scratch: &Path) {
        if let Some(mut hook) = with(target, |s| s.seams.before_verify.take()).flatten() {
            hook(target, scratch);
            with(target, |s| s.seams.before_verify = Some(hook));
        }
    }

    pub(crate) fn after_model(source: &Path, destination: &Path) {
        if let Some(mut hook) = with(destination, |s| s.seams.after_model.take()).flatten() {
            hook(source, destination);
            with(destination, |s| s.seams.after_model = Some(hook));
        }
    }
}
