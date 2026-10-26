// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The replace journal: what a byte replacement of gateway.yaml needs so that
//! a crash, or a refused reload, never leaves bytes on disk that no reload
//! accepted (ADR-024).
//!
//! A replacement writes, in order: a private copy of the original beside the
//! file, this journal in state `staged`, the new bytes over the file, then,
//! once the reload is accepted, state `all_renamed`. Whoever next takes the
//! config lock (any gateway writer, the CLI, a starting gateway) recovers a
//! journal it finds before reading the file: `staged` puts the original
//! back, `all_renamed` keeps the new bytes. Either way the journal and the
//! copy go, the journal first, so a crash during cleanup is recovered again.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::atomic::{FileMode, Symlink, write_atomic};
use crate::identity_grants::journal::resolved;

const VERSION: u32 = 1;

/// How far a replacement got.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum State {
    /// The original is staged; the new bytes may or may not be in place, and
    /// no reload accepted them. Recovery puts the original back.
    Staged,
    /// The new bytes are in place and a reload accepted them. Recovery keeps
    /// them.
    AllRenamed,
}

/// One replacement in flight.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Journal {
    version: u32,
    pub(crate) state: State,
    /// The config file, resolved through a symlink.
    pub(crate) target: PathBuf,
    /// The private copy of the bytes the replacement overwrites.
    pub(crate) original: PathBuf,
    /// The SHA-256 of those bytes, checked after a rollback.
    pub(crate) original_revision: String,
}

/// What recovery did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Recovered {
    /// No journal.
    Nothing,
    /// A `staged` journal: the original is back on disk, so a running
    /// gateway owes a reload.
    RolledBack,
    /// An `all_renamed` journal: the new bytes stand; only cleanup ran.
    KeptNew,
}

/// `.<name>.replace-journal` beside the resolved config.
pub(crate) fn journal_path(config: &Path) -> PathBuf {
    beside(&resolved(config), ".replace-journal")
}

/// `.<name>.replace-original` beside the resolved config.
pub(crate) fn original_path(config: &Path) -> PathBuf {
    beside(&resolved(config), ".replace-original")
}

fn beside(target: &Path, suffix: &str) -> PathBuf {
    let mut name = std::ffi::OsString::from(".");
    name.push(target.file_name().unwrap_or_default());
    name.push(suffix);
    target.with_file_name(name)
}

/// Whether a journal sits beside `config`. Cheap enough for a preflight: a
/// writer that parses the file before locking checks this first, so a
/// stranded half-replaced file never blocks the recovery that fixes it.
pub(crate) fn exists(config: &Path) -> bool {
    std::fs::symlink_metadata(journal_path(config)).is_ok()
}

/// Stage `bytes` (the file's current content) as the private original. Any
/// copy left by a crash before its journal existed is debris, removed first;
/// the caller holds the config lock, so no other replacement owns it.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "called only by the byte writer, whose first caller lands next"
    )
)]
pub(crate) fn stage_original(config: &Path, bytes: &[u8]) -> std::io::Result<PathBuf> {
    let path = original_path(config);
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut file = super::create_new_private(&path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    sync_dir(&path)?;
    Ok(path)
}

/// Write the journal for a replacement of `config` in state `staged`,
/// created exclusive so a second one can never overwrite the first.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "called only by the byte writer, whose first caller lands next"
    )
)]
pub(crate) fn begin(
    config: &Path,
    original: &Path,
    original_revision: String,
) -> std::io::Result<()> {
    let journal = Journal {
        version: VERSION,
        state: State::Staged,
        target: resolved(config),
        original: original.to_path_buf(),
        original_revision,
    };
    let path = journal_path(config);
    let mut file = super::create_new_private(&path)?;
    file.write_all(&serde_json::to_vec(&journal).map_err(std::io::Error::other)?)?;
    file.sync_all()?;
    drop(file);
    sync_dir(&path)
}

/// Mark the journal `all_renamed`: the reload accepted the new bytes. Durable
/// once this returns `Ok`.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "called only by the byte writer, whose first caller lands next"
    )
)]
pub(crate) fn mark_all_renamed(config: &Path) -> std::io::Result<()> {
    let path = journal_path(config);
    let mut journal = read(&path)?;
    journal.state = State::AllRenamed;
    let bytes = serde_json::to_vec(&journal).map_err(std::io::Error::other)?;
    write_atomic(&path, &bytes, FileMode::Private, Symlink::Replace)?;
    sync_dir(&path)
}

/// Remove the journal, durably, then the staged original. A crash between
/// the two leaves only debris, which the next `stage_original` removes.
pub(crate) fn finish(config: &Path) -> std::io::Result<()> {
    let path = journal_path(config);
    std::fs::remove_file(&path)?;
    sync_dir(&path)?;
    match std::fs::remove_file(original_path(config)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Put the staged original back over the target, owner-only as every
/// gateway.yaml write is, and check it re-reads as the original.
///
/// The staged copy is read, never moved: a crash in the middle of this
/// leaves it in place, and the journal still `staged`, for the next try.
pub(crate) fn roll_back(journal: &Journal) -> Result<(), String> {
    let bytes = std::fs::read(&journal.original).map_err(|e| {
        format!(
            "{}: its staged original {} cannot be read ({e}); copy the staged original over {}, then delete {}",
            journal_path(&journal.target).display(),
            journal.original.display(),
            journal.target.display(),
            journal_path(&journal.target).display(),
        )
    })?;
    write_atomic(&journal.target, &bytes, FileMode::Private, Symlink::Follow)
        .and_then(|()| sync_dir(&journal.target))
        .map_err(|e| format!("restoring {} failed: {e}", journal.target.display()))?;
    let back = std::fs::read(&journal.target)
        .map_err(|e| format!("re-reading {} failed: {e}", journal.target.display()))?;
    if crate::hashing::sha256_hex(&back) != journal.original_revision {
        return Err(format!(
            "{} does not read back as its staged original",
            journal.target.display()
        ));
    }
    Ok(())
}

/// Recover a journal beside `config`, if there is one. The caller holds the
/// config lock.
///
/// # Errors
///
/// A journal that cannot be acted on: unreadable, of an unknown version, or
/// `staged` with its original gone. Nothing is changed, and the message says
/// what to do by hand.
pub(crate) fn recover(config: &Path) -> Result<Recovered, String> {
    let path = journal_path(config);
    let journal = match read(&path) {
        Ok(journal) => journal,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Recovered::Nothing),
        Err(e) => {
            return Err(format!(
                "{} cannot be read ({e}); copy {} over {}, then delete {}",
                path.display(),
                original_path(config).display(),
                resolved(config).display(),
                path.display(),
            ));
        }
    };
    let recovered = match journal.state {
        State::Staged => {
            roll_back(&journal)?;
            Recovered::RolledBack
        }
        State::AllRenamed => Recovered::KeptNew,
    };
    finish(config).map_err(|e| format!("removing {} failed: {e}", path.display()))?;
    Ok(recovered)
}

fn read(path: &Path) -> std::io::Result<Journal> {
    let journal: Journal =
        serde_json::from_slice(&std::fs::read(path)?).map_err(std::io::Error::other)?;
    if journal.version != VERSION {
        return Err(std::io::Error::other(format!(
            "journal version {} is not {VERSION}",
            journal.version
        )));
    }
    Ok(journal)
}

/// fsync `path`'s directory, so a create, rename or remove in it is durable.
#[cfg(unix)]
fn sync_dir(path: &Path) -> std::io::Result<()> {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::File::open(dir)?.sync_all()
}

/// Windows: std offers no directory fsync, so a rename's durability is the
/// rename's own, as for every other config write (`rename_with_retry`).
#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps, reason = "matches the unix signature")]
fn sync_dir(_path: &Path) -> std::io::Result<()> {
    Ok(())
}
