// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Shared helpers for mutating and persisting gateway config files.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::fs_lock::ExclusiveFileLock;

#[path = "config_persistence_data_dir.rs"]
mod data_dir;
pub use data_dir::gateway_data_dir;

/// Load config tolerantly, returning defaults when the file is absent or unloadable.
///
/// New read-modify-write callers must use [`load_existing_or_default`] so a load
/// failure cannot replace an operator's config with defaults. The reviewed
/// production callers remaining here are CLI list/get, and legacy remove/update
/// whose missing-backend guards reject the empty default before any write.
/// See `docs/design/issue-462-config-preservation.md` for the caller inventory.
/// Literal loading, per [`Config::load_literal`], preserves secret references.
#[must_use]
pub fn load_config_or_default(path: &Path) -> Config {
    if path.exists() {
        Config::load_literal(Some(path)).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "Could not load config, using defaults");
            Config::default()
        })
    } else {
        Config::default()
    }
}

/// Load config from `path`, returning `Config::default()` when the file is absent.
///
/// Literal, per [`Config::load_literal`].
///
/// # Errors
///
/// Returns an error when an existing entry cannot be loaded or its metadata
/// cannot be inspected. A dangling symlink is an existing entry, not absence.
pub fn load_existing_or_default(path: &Path) -> crate::Result<Config> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Config::load_literal(Some(path)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
        Err(error) => Err(crate::Error::Config(format!(
            "Cannot inspect config file {}: {error}",
            path.display()
        ))),
    }
}

/// Serialize `config` as YAML and write it to `path`.
///
/// # Errors
///
/// Returns `Err` on validation, serialisation, or I/O failure, or when the
/// existing file no longer loads.
///
/// Takes the cross-process config lock first ([`lock`]), waiting up to
/// [`CLI_LOCK_WAIT`] while another writer holds it; this blocks the calling
/// thread, so an async caller uses the reload module's write API instead.
pub fn write_config(path: &Path, config: &Config) -> Result<(), String> {
    let held = lock_for_cli(path)?;
    write_config_with(path, config, CommentLoss::Rewrite, &held).map_err(|e| match e {
        Unwritten::Failed(message) | Unwritten::CommentLoss(message) => message,
    })
}

#[path = "config_persistence_splice.rs"]
mod splice;

#[path = "config_persistence_eol.rs"]
mod eol;

#[path = "config_persistence_lock.rs"]
pub(crate) mod lock;

// Only the web UI names a write's dropped comments from the library; the
// CLI keeps its own copy until MIK-8042's API change (MIK-8051).
#[cfg(feature = "webui")]
#[path = "config_persistence_comments.rs"]
pub(crate) mod comments;

/// How long a synchronous writer (the CLI) waits for another writer's
/// config lock: long enough to outlast a gateway's write and reload.
pub(crate) const CLI_LOCK_WAIT: Duration = Duration::from_secs(30);

/// Take the config lock for a CLI write, then load the file again under it.
///
/// The command loaded the file before it waited for the lock, so a file that
/// no longer loads was changed meanwhile: it is refused, not replaced by the
/// command's older copy. A missing file is still created.
fn lock_for_cli(path: &Path) -> Result<ExclusiveFileLock, String> {
    let held = lock::lock_config_blocking(path, Instant::now() + CLI_LOCK_WAIT, |lock| {
        say_waiting(path, lock);
    })
    .map_err(|e| not_locked(path, e))?;
    load_existing_or_default(path)
        .map_err(|e| format!("Failed to load {}: {e}", path.display()))?;
    Ok(held)
}

/// Tell a CLI user, once, why their command is not finishing yet.
fn say_waiting(config: &Path, lock: &Path) {
    eprintln!(
        "Waiting for {} (another writer holds {})...",
        config.display(),
        lock.display()
    );
}

/// A lock that was not taken, as a message ready to print.
fn not_locked(path: &Path, e: lock::NotLocked) -> String {
    match e {
        lock::NotLocked::Busy => format!(
            "Not saved: {} is locked by another writer; retry.",
            path.display()
        ),
        lock::NotLocked::Failed(message) => format!("Not saved: {message}"),
    }
}

/// What a write does when it cannot keep the file's comments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommentLoss {
    /// Re-serialise the whole file (a CLI write given `--force`, and the
    /// reload module's public write API).
    Rewrite,
    /// Write nothing and say what would be lost (web UI backend edits and
    /// CLI writes), and skip a write that would change nothing.
    Refuse,
}

/// A config write that did not happen.
#[derive(Debug)]
pub(crate) enum Unwritten {
    /// Validation, serialisation or I/O failed; the message says which.
    Failed(String),
    /// Refused under [`CommentLoss::Refuse`]; the message names the comments.
    CommentLoss(String),
}

impl From<String> for Unwritten {
    fn from(message: String) -> Self {
        Self::Failed(message)
    }
}

/// [`write_config`] with an explicit answer to a write that would drop the
/// file's comments. Under [`CommentLoss::Refuse`], a `config` that is what
/// the file already loads as writes nothing.
///
/// The file is loaded through the strict loader from a single read, and that
/// exact text is the one edited when `config` differs from it by exactly one
/// backend added, removed or edited. A file that does not load, or that
/// another writer changed into something more than one backend away, is
/// rewritten in full, or refused. An edit landing after that read is
/// overwritten by the rename, as the full rewrite overwrites it.
///
/// # Errors
///
/// [`Unwritten::CommentLoss`] when `mode` refuses a write that would drop
/// comments; [`Unwritten::Failed`] on validation, serialisation or I/O failure.
///
/// `_held` is the config lock ([`lock`]) the caller took before it loaded:
/// the load, the edit and this write are one critical section.
pub(crate) fn write_config_with(
    path: &Path,
    config: &Config,
    mode: CommentLoss,
    _held: &ExclusiveFileLock,
) -> Result<(), Unwritten> {
    write_spliced(path, config, mode, Splice::One)
}

/// The comment lines (as `line N`) that [`write_config_with`] writing
/// `config` to `path` would drop, from the same single read and the same
/// one-backend splice the write makes. Call it inside the locked edit, so
/// the answer is about this write and not one another writer made since.
/// Empty when the write would not splice: a file with comments is then
/// refused, and one without has none to drop.
#[cfg(feature = "webui")]
pub(crate) fn comments_a_write_drops(path: &Path, config: &Config) -> Vec<String> {
    let Ok((before, text)) = Config::load_literal_with_text(path) else {
        return Vec::new();
    };
    splice::with_backends_edited(&text, &before, config, Splice::One)
        .map(|after| comments::dropped_comment_lines(&text, &after))
        .unwrap_or_default()
}

/// Write `config` to `path` for a CLI command, keeping the file's comments.
///
/// The file's text is edited in place when `config` differs from it in
/// `backends` alone: one backend added, removed or edited, or several added or
/// edited (setup and discovery import). A write that would drop comments is
/// refused, and the refusal names the comment lines; [`write_config`] (the
/// CLI's `--force`) rewrites the file in full when it cannot splice. A `config`
/// that is what the file already loads as writes nothing.
///
/// # Errors
///
/// The refusal, which starts with `Not saved:`; an existing file that no
/// longer loads; or a validation, serialisation or I/O failure. Each is a
/// message ready to print.
pub fn write_config_preserving(path: &Path, config: &Config) -> Result<(), String> {
    let _held = lock_for_cli(path)?;
    write_spliced(path, config, CommentLoss::Refuse, Splice::NoRemoval).map_err(|e| match e {
        Unwritten::CommentLoss(message) => message,
        Unwritten::Failed(message) => format!("Failed to write {}: {message}", path.display()),
    })
}

/// How many backends one splice may change.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Splice {
    /// Exactly one: the web UI and the reload write API change one backend
    /// per write, so two differences mean another writer got in between.
    One,
    /// Several when none is a removal (CLI setup and discovery import, which
    /// adds backends and replaces a same-named one).
    NoRemoval,
}

/// [`write_config_with`] with the splice limited to `scope`.
fn write_spliced(
    path: &Path,
    config: &Config,
    mode: CommentLoss,
    scope: Splice,
) -> Result<(), Unwritten> {
    config
        .validate_with_env(&config.env_overlay())
        .map_err(|e| format!("Failed to validate config: {e}"))?;
    let current = Config::load_literal_with_text(path).ok();
    if let Some((before, text)) = &current {
        let value = |c: &Config| serde_json::to_value(c).ok();
        if mode == CommentLoss::Refuse && value(before) == value(config) {
            return Ok(());
        }
        if let Some(edited) = splice::with_backends_edited(text, before, config, scope) {
            return Ok(write_yaml(path, &edited)?);
        }
    }
    if mode == CommentLoss::Refuse {
        let text = current
            .map(|(_, text)| text)
            .or_else(|| std::fs::read_to_string(path).ok());
        if let Some(text) = text.filter(|t| t.contains('#')) {
            return Err(Unwritten::CommentLoss(splice::comment_loss(path, &text)));
        }
    }
    let yaml =
        serde_yaml::to_string(config).map_err(|e| format!("Failed to serialize config: {e}"))?;
    Ok(write_yaml(path, &yaml)?)
}

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
const SCRATCH_ATTEMPTS: u64 = 8;

/// Write `yaml` to a scratch file next to `path`, then rename it over `path`.
///
/// The rename is what makes the write atomic: a reader sees either the old
/// file or the new one, never a half-written one. Writing in place instead
/// would leave the config truncated if the process died mid-write, which is
/// exactly the config a restart needs to be intact.
///
/// This path is deliberately not platform-gated. An earlier version wrote in
/// place on Windows, so the one platform without a crash-safe write was also
/// the one no test covered.
/// Write pre-rendered config text through the same secure path as [`write_config`].
///
/// Exposed for `init`, which renders a starter config as text rather than
/// serialising a `Config`. It must not use `std::fs::write`: the starter config
/// carries a generated admin credential.
///
/// # Errors
///
/// Returns an error when the file cannot be created or replaced.
pub fn write_config_text(path: &Path, yaml: &str) -> Result<(), String> {
    write_yaml(path, yaml)
}

/// Replace `path` with `text` atomically: exclusive scratch, `sync_all`, rename.
///
/// The neutral-named door onto the same mechanism as [`write_config_text`],
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

fn write_yaml(path: &Path, yaml: &str) -> Result<(), String> {
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
fn create_scratch_exclusive(path: &Path, first: u64) -> Result<(std::fs::File, PathBuf), String> {
    for seed in first..first.wrapping_add(SCRATCH_ATTEMPTS) {
        let candidate = scratch_candidate(path, seed);
        // Private AT CREATION, not on the finished file. A config can hold a
        // bearer token, and the scratch file sits next to it for the whole
        // write; creating it wide and tightening afterwards leaves the window
        // open. `rename` preserves the descriptor, so the config inherits it.
        match create_new_private(&candidate) {
            Ok(file) => return Ok((file, candidate)),
            // Someone else's scratch file. Not ours to write to, and not ours
            // to delete either.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(format!("Failed to create temp config: {e}")),
        }
    }
    Err(format!(
        "Failed to create temp config: {SCRATCH_ATTEMPTS} scratch names next to the config were all in use"
    ))
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
fn rename_with_retry(from: &Path, to: &Path) -> std::io::Result<()> {
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
fn is_transient(e: &std::io::Error) -> bool {
    matches!(e.kind(), std::io::ErrorKind::PermissionDenied) || e.raw_os_error() == Some(32)
}

/// The next scratch seed no other writer in this process will pick.
fn next_scratch_seed() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// The scratch path for a given seed.
///
/// Split from the counter so a test can name a candidate deterministically.
/// Probing the shared counter to predict the next name is flaky: tests run in
/// parallel threads of one binary and any other write moves it.
fn scratch_candidate(path: &Path, seed: u64) -> PathBuf {
    let mut tmp_path = path.as_os_str().to_os_string();
    tmp_path.push(format!(".tmp.{}.{seed}", std::process::id()));
    PathBuf::from(tmp_path)
}

#[cfg(test)]
#[path = "config_persistence_tests.rs"]
mod tests;
