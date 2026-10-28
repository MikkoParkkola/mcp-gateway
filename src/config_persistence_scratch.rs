// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The scratch-and-rename writer: claim an owner-only scratch name next to
//! the target, write and sync it, then rename it over the target.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// How many times a rename is retried before the write is reported failed.
///
/// Windows can refuse a rename that Unix would complete: another process
/// holding the destination open produces a sharing violation, which is
/// transient rather than fatal. Retrying a bounded number of times rides that
/// out; giving up after it leaves the previous config in place.
///
/// Retries are immediate and never sleep. The write path is synchronous but is
/// reached from an async task that holds the reload lock, so parking the thread
/// here would stall an executor worker and lengthen exactly the lock hold that
/// the caller's busy bound exists to cap. An immediate retry only rides out a
/// violation that clears within the syscall round trip; a longer-lived one is
/// reported instead of waited on.
const RENAME_ATTEMPTS: u32 = 8;

/// How many scratch names are tried before a write gives up.
///
/// Each name is probed with an exclusive create, so a collision means some
/// other writer owns that name right now. A handful of probes clears any
/// realistic amount of concurrency; past that, failing is more honest than
/// reusing a name whose owner is still writing to it.
pub(super) const SCRATCH_ATTEMPTS: u64 = 8;

/// Replace `path` with `text` atomically: exclusive scratch, `sync_all`, rename.
///
/// The neutral-named door onto the same mechanism as [`write_config_text`](super::write_config_text),
/// for files that are neither config nor YAML. The identity-grants file needs
/// it for a reason stronger than credential hygiene: `IdentityGrantFile`
/// defaults BOTH `schema_version` and `grants`, and the schema check compares
/// against the constant it defaults to, so a write interrupted after the
/// header parses cleanly as ZERO GRANTS — bit-for-bit the deliberate
/// revoke-everything file. With a truncating write, an interrupted
/// `identity grant add` therefore revokes everything, through the SUCCESS
/// path. Fail-open cannot catch it (the file is valid, just short) and no
/// parser can either, because "zero grants was meant" and "the writer died
/// after the header" are the same bytes. Only the writer knows, so only the
/// writer can fix it.
///
/// # Errors
///
/// Returns an error when the file cannot be created or replaced.
pub fn write_text_atomic(path: &Path, text: &str) -> Result<(), String> {
    write_yaml(path, text)
}

pub(super) fn write_yaml(path: &Path, yaml: &str) -> Result<(), String> {
    // Replace the config itself, not a symlink naming it: renaming onto the
    // link would detach the config from its target.
    write_yaml_at(&crate::identity_grants::journal::resolved(path), yaml)
}

/// [`write_yaml`] over `path` itself, the target a lock holder resolved: the
/// rename replaces whatever entry is there, so a symlink planted at the
/// target since is replaced, never followed to another file.
pub(super) fn write_yaml_at(path: &Path, yaml: &str) -> Result<(), String> {
    let (mut file, tmp_path) = create_scratch_exclusive(path, next_scratch_seed())?;

    // Leave no debris behind on any failure. The scratch name is unique per
    // call, so without cleanup each failure would strand one more file next to
    // the config instead of reusing a single stale one.
    let cleanup = |e: &std::io::Error, what: &str| {
        let _ = std::fs::remove_file(&tmp_path);
        format!("Failed to {what} config: {e}")
    };

    // Write through the handle the exclusive create returned. Reopening by
    // path would reopen the gap the exclusive create just closed.
    let written = file
        .write_all(yaml.as_bytes())
        .and_then(|()| file.sync_all());
    // Close before cleanup: Windows cannot delete a file held open without
    // delete sharing.
    drop(file);
    written.map_err(|e| cleanup(&e, "write temp"))?;

    rename_with_retry(&tmp_path, path).map_err(|e| cleanup(&e, "replace"))
}

/// Create `path`, refusing a name already in use, with access limited to this
/// account from the first instant: mode `0600` on unix, an owner-only DACL on
/// Windows. Setting either after creation would leave a window in which a
/// secret written to the file is readable by others.
///
/// # Errors
///
/// Returns the I/O error of the create, `AlreadyExists` for a taken name.
pub(crate) fn create_new_private(path: &Path) -> std::io::Result<std::fs::File> {
    #[cfg(windows)]
    {
        crate::private_fs::create_file_private(path, crate::private_fs::Share::Exclusive)
    }
    #[cfg(not(windows))]
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(path)
    }
}

/// Create `path` private (see [`create_new_private`]), replacing a file of
/// that name left by an earlier writer.
///
/// For a scratch file with a fixed name, so a crash-orphaned one is reused by
/// the next write. The caller holds the lock that keeps other writers out. The
/// old file is removed on Windows because truncating it would keep its old
/// DACL; on unix it is truncated and forced to `0600`, which `mode` alone
/// would not do for an existing file.
///
/// # Errors
///
/// Returns the I/O error of the remove or the create.
pub(crate) fn create_private_replacing(path: &Path) -> std::io::Result<std::fs::File> {
    #[cfg(windows)]
    {
        match std::fs::remove_file(path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        create_new_private(path)
    }
    #[cfg(not(windows))]
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(file)
    }
}

/// Claim a scratch file next to `path` that no other writer holds.
///
/// The create is exclusive, so a name already in use is refused rather than
/// truncated. A refused name belongs to another live writer, so it is left
/// alone and the next name is tried.
///
/// # Errors
///
/// Returns an error when every candidate name is taken, or on any I/O failure
/// other than a collision.
pub(super) fn create_scratch_exclusive(
    path: &Path,
    first: u64,
) -> Result<(std::fs::File, PathBuf), String> {
    // Private AT CREATION, not on the finished file. A config can hold a
    // bearer token, and the scratch file sits next to it for the whole
    // write; creating it wide and tightening afterwards leaves the window
    // open. `rename` preserves the descriptor, so the config inherits it.
    claim_scratch(path, first, create_new_private).map_err(|e| match e {
        ScratchClaimError::AllTaken => format!(
            "Failed to create temp config: {SCRATCH_ATTEMPTS} scratch names next to the config were all in use"
        ),
        ScratchClaimError::Io(e) => format!("Failed to create temp config: {e}"),
    })
}

/// Why no scratch name could be claimed.
pub(super) enum ScratchClaimError {
    /// All [`SCRATCH_ATTEMPTS`] candidate names were in use.
    AllTaken,
    /// An I/O failure other than a collision.
    Io(std::io::Error),
}

/// The one candidate loop behind every rename-based writer here: try
/// [`SCRATCH_ATTEMPTS`] names from `first`, creating each with `create`
/// (which must be exclusive). A name already in use is someone else's
/// scratch file: not ours to write to, and not ours to delete either.
pub(super) fn claim_scratch(
    path: &Path,
    first: u64,
    create: impl Fn(&Path) -> std::io::Result<std::fs::File>,
) -> Result<(std::fs::File, PathBuf), ScratchClaimError> {
    for seed in first..first.wrapping_add(SCRATCH_ATTEMPTS) {
        let candidate = scratch_candidate(path, seed);
        match create(&candidate) {
            Ok(file) => return Ok((file, candidate)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(ScratchClaimError::Io(e)),
        }
    }
    Err(ScratchClaimError::AllTaken)
}

/// Rename `from` over `to`, retrying while the OS reports a transient refusal.
///
/// Retries are immediate; see [`RENAME_ATTEMPTS`] for why this must not sleep.
///
/// `std::fs::rename` replaces an existing `to` on every platform we support,
/// Windows included: std documents the call as "replacing the original file if
/// `to` already exists", and the Windows implementation is `MoveFileExW` with
/// `MOVEFILE_REPLACE_EXISTING` (std `sys/fs/windows.rs`). Two separate reviews
/// have read this loop and reported that Windows renames fail once the config
/// exists; both were wrong. Do not add a `remove_file(to)` before the rename to
/// "fix" it -- that would reintroduce the window where the config is missing,
/// which is the whole thing this function exists to avoid.
pub(super) fn rename_with_retry(from: &Path, to: &Path) -> std::io::Result<()> {
    let mut last = None;
    for _ in 0..RENAME_ATTEMPTS {
        match std::fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(e) if is_transient(&e) => last = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::other("rename exhausted its retries")))
}

/// Whether an error is the kind another process can stop causing.
///
/// A Windows sharing violation surfaces as `PermissionDenied` or, on older
/// mappings, uncategorised. On Unix neither classification is reachable from a
/// rename inside a directory the process just wrote to, so the retry loop
/// costs nothing there.
pub(super) fn is_transient(e: &std::io::Error) -> bool {
    matches!(e.kind(), std::io::ErrorKind::PermissionDenied) || e.raw_os_error() == Some(32)
}

/// The next scratch seed no other writer in this process will pick.
pub(super) fn next_scratch_seed() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// The scratch path for a given seed.
///
/// Split from the counter so a test can name a candidate deterministically.
/// Probing the shared counter to predict the next name is flaky: tests run in
/// parallel threads of one binary and any other write moves it.
pub(super) fn scratch_candidate(path: &Path, seed: u64) -> PathBuf {
    let mut tmp_path = path.as_os_str().to_os_string();
    tmp_path.push(format!(".tmp.{}.{seed}", std::process::id()));
    PathBuf::from(tmp_path)
}
