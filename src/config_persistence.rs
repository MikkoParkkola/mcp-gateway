// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Shared helpers for mutating and persisting gateway config files.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::fs_lock::ExclusiveFileLock;

#[path = "config_persistence_data_dir.rs"]
mod data_dir;
pub use data_dir::gateway_data_dir;

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
///
/// Deprecated: it replaces the file from the caller's snapshot with no
/// concurrency check, so a change another writer made after the snapshot
/// was taken is lost. Use [`edit_config`]. Removal is planned for 5.0.
#[deprecated(
    since = "4.0.0",
    note = "replaces gateway.yaml from the caller's snapshot with no concurrency check; use edit_config"
)]
pub fn write_config(path: &Path, config: &Config) -> Result<(), String> {
    let locked = lock_for_cli(path)?;
    locked.may_write(path)?;
    write_config_with(&locked.target, config, CommentLoss::Rewrite, &locked.held).map_err(|e| {
        match e {
            Unwritten::Failed(message) | Unwritten::CommentLoss(message) => message,
        }
    })
}

#[path = "config_persistence_keyedit.rs"]
pub(crate) mod keyedit;
#[path = "config_persistence_splice.rs"]
mod splice;
#[cfg(feature = "webui")]
pub(crate) use splice::{NOT_IN_PLACE, edit_text};
#[path = "config_persistence_url.rs"]
mod url_spelling;

#[path = "config_persistence_eol.rs"]
mod eol;

#[path = "config_persistence_lock.rs"]
pub(crate) mod lock;

// The replace journal: undoing a byte replacement after a crash or a refused
// reload (ADR-024).
#[path = "config_persistence_journal.rs"]
pub(crate) mod journal;

// Names the comments a write drops, for the web UI and the CLI (MIK-8051).
#[path = "config_persistence_comments.rs"]
pub(crate) mod comments;

#[path = "config_persistence_atomic.rs"]
mod atomic;
#[cfg(all(test, feature = "webui"))]
pub(crate) use atomic::write_atomic_observed_for_test;
pub use atomic::{FileMode, Symlink, copy_keeping_access, write_atomic};

#[path = "config_persistence_scratch.rs"]
mod scratch;
pub use scratch::write_text_atomic;
use scratch::{
    SCRATCH_ATTEMPTS, ScratchClaimError, claim_scratch, next_scratch_seed, rename_with_retry,
    write_yaml, write_yaml_at,
};
pub(crate) use scratch::{create_new_private, create_private_replacing};
#[cfg(test)]
use scratch::{create_scratch_exclusive, is_transient, scratch_candidate};

/// Recover a byte write a crash left behind, before a serving gateway first
/// loads `config` (ADR-024). Exists for the bundled binary's two serve paths;
/// not a stable API. Read-only commands (`validate`, `doctor`) never call it,
/// so they never write.
///
/// With no journal pending there is nothing to do and no lock is taken: the
/// file is whole, since every writer replaces it by atomic rename. With one,
/// the config lock is taken (waiting up to [`CLI_LOCK_WAIT`]) and recovers it
/// ([`journal::recover`]): back to the original, or keeping bytes a reload
/// accepted.
///
/// # Errors
///
/// A pending journal that cannot be resolved: unusable, held by another
/// writer past the wait, or beside a file this account cannot lock (fix it
/// from the side that can write). The message says what to do; the gateway
/// must not start on either version.
pub fn recover_before_start(config: &Path) -> Result<(), String> {
    if !lock::journal_pending(config) {
        return Ok(());
    }
    match lock::lock_config_blocking(config, Instant::now() + CLI_LOCK_WAIT, |_| {}) {
        Ok(_locked) => Ok(()),
        Err(lock::NotLocked::Busy) => Err(format!(
            "{} has a pending write and another writer holds its lock; start again when it finishes",
            config.display()
        )),
        Err(lock::NotLocked::Failed(message)) => Err(match lock::no_writer_possible(config) {
            Some(why) => format!(
                "a pending write's journal {} sits beside {}, which this gateway cannot lock ({why}); resolve the pending write from the writable side",
                journal::journal_path(config).display(),
                config.display()
            ),
            None => message,
        }),
    }
}

/// Take the config lock for a CLI write, waiting up to [`CLI_LOCK_WAIT`].
/// The holder reads and writes the lock's target, never `path` again: a
/// symlink at `path` re-pointed meanwhile would name another file.
fn cli_lock(path: &Path) -> Result<lock::Locked, String> {
    lock::lock_config_blocking(path, Instant::now() + CLI_LOCK_WAIT, |lock| {
        say_waiting(path, lock);
    })
    .map_err(|e| not_locked(path, e))
}

/// How long a synchronous writer (the CLI) waits for another writer's
/// config lock: long enough to outlast a gateway's write and reload.
pub(crate) const CLI_LOCK_WAIT: Duration = Duration::from_secs(30);

/// Take the config lock for a CLI write, then load the file again under it.
///
/// The command loaded the file before it waited for the lock, so a file that
/// no longer loads was changed meanwhile: it is refused, not replaced by the
/// command's older copy. A missing file is still created.
fn lock_for_cli(path: &Path) -> Result<lock::Locked, String> {
    let locked = cli_lock(path)?;
    load_locked(path, &locked).map_err(|e| format!("Failed to load {}: {e}", path.display()))?;
    Ok(locked)
}

/// [`load_existing_or_default`] for a lock holder: loads the target `path`'s
/// lock resolved, or the default when it is absent ([`lock::Locked::absent`]),
/// so a dangling link at `path` still refuses (GH462).
///
/// # Errors
///
/// As [`load_existing_or_default`].
pub(crate) fn load_locked(path: &Path, locked: &lock::Locked) -> crate::Result<Config> {
    if locked.absent(path).map_err(crate::Error::Config)? {
        return Ok(Config::default());
    }
    Config::load_literal(Some(&locked.target))
}

/// Tell a CLI user, once, why their command is not finishing yet.
fn say_waiting(config: &Path, lock: &Path) {
    eprintln!(
        "Waiting for {} (another writer holds {})...",
        config.display(),
        lock.display()
    );
    let mut waiters = LOCK_WAITERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    waiters.retain(|(path, tell)| {
        if path != config {
            return true;
        }
        // Told once; a test that stopped listening is not an error.
        let _ = tell.send(());
        false
    });
}

/// Who wants to know that a CLI writer started waiting for a config's lock:
/// the concurrency tests, which overlap writers by this signal rather than a
/// fixed sleep. Each sender is told once. Touched only when a writer waits.
static LOCK_WAITERS: std::sync::Mutex<Vec<(PathBuf, std::sync::mpsc::Sender<()>)>> =
    std::sync::Mutex::new(Vec::new());

/// A receiver told once when a CLI writer next starts waiting for `config`'s
/// lock (for tests; see [`LOCK_WAITERS`]).
pub(crate) fn when_waiting_for_lock(config: &Path) -> std::sync::mpsc::Receiver<()> {
    let (tell, told) = std::sync::mpsc::channel();
    LOCK_WAITERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push((config.to_path_buf(), tell));
    told
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

/// What a write does when it cannot edit an existing file in place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommentLoss {
    /// Re-serialise the whole file (a CLI write given `--force`, and the
    /// reload module's public write API).
    Rewrite,
    /// Write an existing file only as a proven in-place edit; otherwise write
    /// nothing and say why (web UI backend edits and CLI writes). A write that
    /// would change nothing is skipped.
    Refuse,
}

/// A config write that did not happen.
#[derive(Debug)]
pub(crate) enum Unwritten {
    /// Validation, serialisation or I/O failed; the message says which.
    Failed(String),
    /// Refused under [`CommentLoss::Refuse`]: the edit could not be made in
    /// place. The message names the comment lines a rewrite would drop, if
    /// any, never their text.
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
/// rewritten in full, or refused. The caller holds the config lock across
/// its load and this write, so no writer that takes the lock lands between
/// them; an edit that ignores the lock (a hand edit) is overwritten.
///
/// # Errors
///
/// [`Unwritten::CommentLoss`] when `mode` refuses a write that would drop
/// comments; [`Unwritten::Failed`] on validation, serialisation or I/O failure.
///
/// `_held` is the config lock ([`lock`]) the caller took before it loaded:
/// the load, the edit and this write are one critical section. `path` is the
/// target that lock resolved, written as it stands, never through a link.
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

/// Load `path`, apply `edit`, and write the result, keeping the file's
/// comments (MIK-8042).
///
/// The load, the edit and the write run under one hold of the config lock
/// ([`lock`]), so a change another writer made before it is never
/// overwritten: `edit` sees the file as it is. The file's text is edited in
/// place when the result differs from it in `backends` alone (several
/// backends added or edited, or one removed). Otherwise the file is
/// rewritten in full under [`CommentLoss::Rewrite`], or, under
/// [`CommentLoss::Refuse`], left as it is, comments or not; the refusal names
/// any comment lines. A result that is what the file already
/// loads as writes nothing under [`CommentLoss::Refuse`]. A missing file is
/// created.
///
/// Returns the comment lines (as `line N`, never their text) the write
/// dropped: those inside a removed entry, or under
/// [`CommentLoss::Rewrite`] every comment a full rewrite lost.
///
/// `edit` must change the `Config` it is given. Replacing it with a copy
/// loaded earlier writes that old copy back and loses what other writers
/// saved since, which is exactly what this function exists to prevent.
///
/// Takes the lock blocking, waiting up to [`CLI_LOCK_WAIT`]; an async caller
/// uses the reload module's write API instead.
///
/// # Errors
///
/// `edit`'s own error; the refusal, which starts with `Not saved:`; a lock
/// that cannot be taken; an existing file that does not load; or a
/// validation, serialisation or I/O failure. Each is a message ready to print.
pub fn edit_config<F>(path: &Path, mode: CommentLoss, edit: F) -> Result<Vec<String>, String>
where
    F: FnOnce(&mut Config) -> Result<(), String>,
{
    // Advisory only: a file that does not load is refused before the lock
    // file is made, so the refusal leaves the directory as it was. The load
    // under the lock is the authoritative one. Skipped while a replace journal
    // is pending: the lock recovers the file before that load.
    if !journal::exists(path) {
        load_existing_or_default(path)
            .map_err(|e| format!("Failed to load {}: {e}", path.display()))?;
    }
    let mut dropped = Vec::new();
    edit_locked(
        path,
        Target::Config,
        |locked| read_config(path, locked),
        |current| {
            let mut config = current
                .as_ref()
                .map_or_else(Config::default, |(c, _)| c.clone());
            edit(&mut config)?;
            let (before, text) = current.as_ref().map(|(c, t)| (c, t.as_str())).unzip();
            let rendered = render(path, before, text, &config, mode, Splice::NoRemoval).map_err(
                |e| match e {
                    Unwritten::CommentLoss(message) => message,
                    Unwritten::Failed(message) => {
                        format!("Failed to write {}: {message}", path.display())
                    }
                },
            )?;
            Ok(rendered.map(|(yaml, lines)| {
                dropped = lines;
                yaml
            }))
        },
    )?;
    Ok(dropped)
}

/// Read `path`'s text (`None` when it does not exist) and write what `edit`
/// returns (`None` writes nothing), under one hold of the config lock, so a
/// change another writer made before it is never overwritten (MIK-8042).
/// For a command that edits the file as text: `init` (create only: its
/// `edit` refuses `Some`) and `upgrade` (a byte-keeping rewrite). Text that
/// does not parse as a config is refused, never written.
///
/// Returns whether the file was written.
///
/// # Errors
///
/// `edit`'s own error; a lock that cannot be taken; a path that is not a
/// regular file; text that does not parse as a config; or a read or write
/// failure. Each is a message ready to print.
pub fn edit_config_text<F>(path: &Path, edit: F) -> Result<bool, String>
where
    F: FnOnce(Option<&str>) -> Result<Option<String>, String>,
{
    // The text path follows the link, as it always has: `init` through a
    // dangling link creates the target and keeps the link.
    edit_locked(
        path,
        Target::FollowLink,
        |locked| read_text(&locked.target),
        |current| edit(current.as_deref()),
    )
}

/// What a missing target means to a locked edit.
#[derive(Clone, Copy)]
enum Target {
    /// A config: a dangling link at the path is damage, never created
    /// (GH462), even when its target was deleted while the edit ran.
    Config,
    /// Text through the link, as `init` has always written it: a dangling
    /// link's target is created and the link kept.
    FollowLink,
}

/// The one locked write path: take the config lock, `read` its target, let
/// `edit` give its new text (`None` writes nothing), prove that text parses
/// as a config, and write it atomically, all in one hold. Returns whether
/// the file was written.
fn edit_locked<T>(
    path: &Path,
    target: Target,
    read: impl FnOnce(&lock::Locked) -> Result<T, String>,
    edit: impl FnOnce(T) -> Result<Option<String>, String>,
) -> Result<bool, String> {
    let locked = cli_lock(path)?;
    let text = edit(read(&locked)?)?;
    // Checked even when nothing is written, so no edit reports on a config
    // the path no longer names.
    match target {
        Target::Config => locked.may_write(path)?,
        Target::FollowLink => locked.still_named_by(path)?,
    }
    let Some(text) = text else {
        return Ok(false);
    };
    // Fail closed (GH462): bytes that do not parse are never written.
    Config::from_file_text(&text).map_err(|e| {
        format!(
            "Not saved: the new {} does not parse as a config: {e}",
            path.display()
        )
    })?;
    write_yaml_at(&locked.target, &text)?;
    Ok(true)
}

/// The config at the target `path`'s lock resolved, and the text it loaded
/// from, or `None` when there is no file ([`lock::Locked::absent`]).
fn read_config(path: &Path, locked: &lock::Locked) -> Result<Option<(Config, String)>, String> {
    if locked.absent(path)? {
        return Ok(None);
    }
    Config::load_literal_with_text(&locked.target)
        .map(Some)
        .map_err(|e| format!("Failed to load {}: {e}", path.display()))
}

/// `path`'s text, or `None` when there is no file. A FIFO or a device would
/// block the read or never end it, so the file is opened without blocking
/// and the handle itself must be a regular file before it is read.
fn read_text(path: &Path) -> Result<Option<String>, String> {
    use std::io::Read as _;
    let failed = |e: &dyn std::fmt::Display| format!("Failed to read {}: {e}", path.display());
    let mut file = match crate::open_nonblocking::open_nonblocking(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        // Windows refuses to open a directory at all: name the cause the same.
        Err(_) if std::fs::metadata(path).is_ok_and(|m| !m.is_file()) => {
            return Err(failed(&"not a regular file"));
        }
        Err(e) => return Err(failed(&e)),
        Ok(file) => file,
    };
    if !file.metadata().map_err(|e| failed(&e))?.is_file() {
        return Err(failed(&"not a regular file"));
    }
    let mut text = String::new();
    file.read_to_string(&mut text).map_err(|e| failed(&e))?;
    Ok(Some(text))
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
    let current = Config::load_literal_with_text(path).ok();
    let (before, text) = current.as_ref().map(|(c, t)| (c, t.as_str())).unzip();
    // A file that does not load is still read, so its comments are refused.
    let unloaded = text
        .is_none()
        .then(|| std::fs::read_to_string(path).ok())
        .flatten();
    let text = text.or(unloaded.as_deref());
    if let Some((yaml, _)) = render(path, before, text, config, mode, scope)? {
        // `path` is the lock holder's target ([`write_config_with`]).
        write_yaml_at(path, &yaml)?;
    }
    Ok(())
}

/// The text a write of `config` over `text` (which loads as `before`, when
/// it loads) should leave, and the comment lines it drops; `None` when
/// nothing needs writing. The text is spliced when `config` differs from
/// `before` in `backends` alone, within `scope`. Otherwise a missing file is
/// rendered in full, and an existing one is too under [`CommentLoss::Rewrite`];
/// under [`CommentLoss::Refuse`] it is refused, comments or not (ADR-024).
fn render(
    path: &Path,
    before: Option<&Config>,
    text: Option<&str>,
    config: &Config,
    mode: CommentLoss,
    scope: Splice,
) -> Result<Option<(String, Vec<String>)>, Unwritten> {
    config
        .validate_with_env(&config.env_overlay())
        .map_err(|e| format!("Failed to validate config: {e}"))?;
    if let (Some(before), Some(text)) = (before, text) {
        let value = |c: &Config| serde_json::to_value(c).ok();
        if mode == CommentLoss::Refuse && value(before) == value(config) {
            return Ok(None);
        }
        if let Some(edited) = splice::with_backends_edited(text, before, config, scope) {
            let dropped = comments::dropped_comment_lines(text, &edited);
            return Ok(Some((edited, dropped)));
        }
    }
    if mode == CommentLoss::Refuse
        && let Some(text) = text
    {
        let why = splice::not_in_place(path, text);
        return Err(Unwritten::CommentLoss(why));
    }
    let commented = text.filter(|t| t.contains('#'));
    let yaml = url_spelling::render(config, text)?;
    let dropped = commented
        .map(|text| comments::dropped_comment_lines(text, &yaml))
        .unwrap_or_default();
    Ok(Some((yaml, dropped)))
}

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
/// It must not be replaced by `std::fs::write`: a starter config carries a
/// generated admin credential.
///
/// Deprecated: it takes no config lock and checks nothing, so it replaces
/// whatever another writer put there. Use [`edit_config_text`]. Removal is
/// planned for 5.0.
///
/// # Errors
///
/// Returns an error when the file cannot be created or replaced.
#[deprecated(
    since = "4.0.0",
    note = "writes gateway.yaml with no config lock and no check; use edit_config_text"
)]
pub fn write_config_text(path: &Path, yaml: &str) -> Result<(), String> {
    write_yaml(path, yaml)
}

#[cfg(test)]
#[path = "config_persistence_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "config_persistence_edit_tests.rs"]
mod edit_tests;
