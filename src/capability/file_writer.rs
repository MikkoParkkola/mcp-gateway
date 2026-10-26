// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The one writer for capability files: locked per directory, atomic,
//! checked against the base the editor loaded, the pin rewritten in place.
//!
//! The editor sends whole text and the writer writes it verbatim, except the
//! pin line's value (a save) and the base's CRLF and BOM, which a browser
//! textarea drops. Nothing re-serializes, so comments and order stay.

use std::path::{Path, PathBuf};
use std::time::Instant;

use super::execution_context::validate_capability_account_binding;
use super::{compute_capability_hash, unloadable_issues};
use crate::capability::parser::parse_capability_text;
use crate::config_persistence::lock::{NotLocked, lock_config};
use crate::config_persistence::{FileMode, Symlink, write_atomic};
use crate::identity_propagation::AccountStrategyRegistry;

/// What the editor loaded: no file, or the SHA-256 (lowercase hex) of its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Base {
    Absent,
    Bytes(String),
}

/// How the pin line is treated: rewritten for a save, kept for a restore.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PinUpdate {
    InPlace,
    Verbatim,
}

/// The change to commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Change {
    Write(String),
    Delete,
}

/// What happened to the pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PinChange {
    Kept,
    Updated,
    Added,
    None,
}

/// A committed change: the hashes before and after (the next base).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Committed {
    pub(crate) before: Option<String>,
    pub(crate) after: Option<String>,
    pub(crate) pin: PinChange,
}

/// One validation error, with its position or field where it has one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FieldError {
    pub(crate) line: Option<usize>,
    pub(crate) column: Option<usize>,
    pub(crate) field: Option<String>,
    pub(crate) message: String,
}

/// Why nothing was written. `patch` is a unified diff the admin can apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Refused {
    Stale {
        patch: String,
        current_sha256: Option<String>,
    },
    PinMismatch {
        patch: String,
    },
    Unpin {
        patch: String,
    },
    PinAmbiguous {
        patch: String,
    },
    Symlinked {
        real_path: String,
    },
    Unwritable {
        error: String,
        patch: String,
    },
    LockBusy,
    Invalid {
        errors: Vec<FieldError>,
        patch: String,
    },
}

/// One change to one capability file: `<dir>/<name>.yaml`.
#[derive(Debug, Clone)]
pub(crate) struct Edit<'a> {
    pub(crate) dir: &'a Path,
    pub(crate) name: &'a str,
    pub(crate) base: Base,
    pub(crate) change: Change,
    pub(crate) pin: PinUpdate,
}

const PIN_KEY: &str = "sha256:";

fn sha(bytes: &str) -> String {
    crate::hashing::sha256_hex(bytes.as_bytes())
}

/// The top-level pin lines: (line index, value without quotes).
fn pin_lines(text: &str) -> Vec<(usize, String)> {
    text.split('\n')
        .enumerate()
        .filter_map(|(i, line)| {
            let rest = line.strip_prefix(PIN_KEY)?;
            let value = rest.trim().trim_matches(|c| c == '"' || c == '\'');
            Some((i, value.to_string()))
        })
        .collect()
}

/// Whether a pin line carries text after a YAML line break other than `\n`
/// (a lone CR, NEL, LS or PS): the smuggling shape `strip_sha256_line` drops.
fn smuggles(text: &str, index: usize) -> bool {
    let line = text.split('\n').nth(index).unwrap_or_default();
    let body = line.strip_suffix('\r').unwrap_or(line);
    body.contains(['\r', '\u{85}', '\u{2028}', '\u{2029}'])
}

/// Whether the current file's pin no longer matches its bytes.
fn pin_broken(current: &str) -> bool {
    match pin_lines(current).as_slice() {
        [(_, value)] => !value.eq_ignore_ascii_case(&compute_capability_hash(current)),
        _ => false,
    }
}

/// The sent text in the base's style: its BOM kept, and LF made CRLF when
/// every line break in the base is CRLF. A mixed base is written as sent.
fn in_base_style(text: &str, base: Option<&str>) -> String {
    let Some(base) = base else {
        return text.to_string();
    };
    let crlf = base.contains('\n') && base.matches('\n').count() == base.matches("\r\n").count();
    let mut out = if crlf && !text.contains('\r') {
        text.replace('\n', "\r\n")
    } else {
        text.to_string()
    };
    if base.starts_with('\u{feff}') && !out.starts_with('\u{feff}') {
        out.insert(0, '\u{feff}');
    }
    out
}

/// A unified diff from `from` to `to`, one hunk over the whole file.
// ponytail: O(n*m) LCS, fine for capability files (hundreds of lines); a
// hunked diff library when files grow past a few thousand lines.
pub(crate) fn unified_diff(from: &str, to: &str) -> String {
    let a: Vec<&str> = from.lines().collect();
    let b: Vec<&str> = to.lines().collect();
    let mut lcs = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let mut out = format!(
        "--- current\n+++ sent\n@@ -1,{} +1,{} @@\n",
        a.len(),
        b.len()
    );
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        if i < a.len() && j < b.len() && a[i] == b[j] {
            out.push_str(&format!(" {}\n", a[i]));
            i += 1;
            j += 1;
        } else if j < b.len() && (i == a.len() || lcs[i][j + 1] >= lcs[i + 1][j]) {
            out.push_str(&format!("+{}\n", b[j]));
            j += 1;
        } else {
            out.push_str(&format!("-{}\n", a[i]));
            i += 1;
        }
    }
    out
}

fn message(message: impl std::fmt::Display) -> FieldError {
    FieldError {
        line: None,
        column: None,
        field: None,
        message: message.to_string(),
    }
}

/// The loader's acceptance of `text` as `path` (D3), plus the account
/// binding the backend admits with: what can be saved is what loads.
///
/// # Errors
///
/// Every refusal, YAML syntax errors with their line and column.
pub(crate) fn validate(
    text: &str,
    path: &Path,
    accounts: Option<&AccountStrategyRegistry>,
) -> Result<(), Vec<FieldError>> {
    if let Err(e) = crate::yaml::from_str::<crate::yaml::Value>(text) {
        let at = e.location();
        return Err(vec![FieldError {
            line: at.map(|l| l.line()),
            column: at.map(|l| l.column()),
            field: None,
            message: e.to_string(),
        }]);
    }
    let capability = parse_capability_text(text, path).map_err(|e| vec![message(e)])?;
    let issues = unloadable_issues(&capability, path).map_err(|e| vec![message(e)])?;
    if !issues.is_empty() {
        return Err(issues
            .into_iter()
            .map(|i| FieldError {
                field: i.field.map(str::to_string),
                ..message(i.message)
            })
            .collect());
    }
    validate_capability_account_binding(&capability, accounts).map_err(|e| vec![message(e)])
}

/// The bytes a change writes, and what happens to the pin (D2).
fn final_bytes(
    sent: &str,
    current: Option<&str>,
    pin: PinUpdate,
) -> Result<(String, PinChange), Refused> {
    let patch = || unified_diff(current.unwrap_or_default(), sent);
    let was_pinned = current.is_some_and(|c| !pin_lines(c).is_empty());
    let pins = pin_lines(sent);
    if pin == PinUpdate::Verbatim {
        if was_pinned && pins.is_empty() {
            return Err(Refused::Unpin { patch: patch() });
        }
        let change = if pins.is_empty() {
            PinChange::None
        } else {
            PinChange::Kept
        };
        return Ok((sent.to_string(), change));
    }
    let text = in_base_style(sent, current);
    match pins.as_slice() {
        [] if was_pinned => Err(Refused::Unpin { patch: patch() }),
        [] => Ok((text, PinChange::None)),
        [(index, old)] if !smuggles(&text, *index) => {
            let hash = compute_capability_hash(&text);
            let mut lines: Vec<String> = text.split('\n').map(str::to_string).collect();
            let cr = if lines[*index].ends_with('\r') {
                "\r"
            } else {
                ""
            };
            lines[*index] = format!("{PIN_KEY} {hash}{cr}");
            let change = match (was_pinned, old.eq_ignore_ascii_case(&hash)) {
                (false, _) => PinChange::Added,
                (true, true) => PinChange::Kept,
                (true, false) => PinChange::Updated,
            };
            Ok((lines.join("\n"), change))
        }
        _ => Err(Refused::PinAmbiguous { patch: patch() }),
    }
}

/// Commit `edit` under its directory's lock.
pub(crate) async fn commit(
    edit: Edit<'_>,
    accounts: Option<&AccountStrategyRegistry>,
    deadline: Instant,
) -> Result<Committed, Refused> {
    commit_with(edit, accounts, deadline, |_| {}).await
}

/// `<dir>/<name>.yaml`, or the `.yml` file when only that one exists.
fn target_path(dir: &Path, name: &str) -> PathBuf {
    let yaml = dir.join(format!("{name}.yaml"));
    let yml = dir.join(format!("{name}.yml"));
    if std::fs::symlink_metadata(&yaml).is_err() && std::fs::symlink_metadata(&yml).is_ok() {
        yml
    } else {
        yaml
    }
}

/// What a save of `sent` over `current` would write, without writing: the
/// bytes and the pin change, or the refusal the save would answer.
///
/// # Errors
///
/// `Unpin` or `PinAmbiguous`, as [`commit`] would answer.
pub(crate) fn preview(sent: &str, current: Option<&str>) -> Result<(String, PinChange), Refused> {
    final_bytes(sent, current, PinUpdate::InPlace)
}

/// The list's pin column: `verified`, `mismatch` or `unpinned`.
pub(crate) fn pin_state(text: &str) -> &'static str {
    if pin_lines(text).is_empty() {
        "unpinned"
    } else if pin_broken(text) {
        "mismatch"
    } else {
        "verified"
    }
}

/// The SHA-256 (lowercase hex) of `text`: an editor's base and an `ETag`.
pub(crate) fn sha256_of(text: &str) -> String {
    sha(text)
}

/// [`commit`] with `observe` called on the target path once the scratch is
/// written and before the rename: the seam for the swap race and the
/// rename failure (lead ruling 2026-10-26).
#[cfg(test)]
pub(crate) async fn commit_observed(
    edit: Edit<'_>,
    accounts: Option<&AccountStrategyRegistry>,
    deadline: Instant,
    observe: impl FnOnce(&Path) + Send,
) -> Result<Committed, Refused> {
    commit_with(edit, accounts, deadline, observe).await
}

fn unwritable(error: impl std::fmt::Display, patch: String) -> Refused {
    Refused::Unwritable {
        error: error.to_string(),
        patch,
    }
}

async fn commit_with(
    edit: Edit<'_>,
    accounts: Option<&AccountStrategyRegistry>,
    deadline: Instant,
    observe: impl FnOnce(&Path) + Send,
) -> Result<Committed, Refused> {
    let sent = match &edit.change {
        Change::Write(text) => text.as_str(),
        Change::Delete => "",
    };
    let dir = std::fs::canonicalize(edit.dir).map_err(|e| unwritable(e, String::new()))?;
    let path = target_path(&dir, edit.name);
    // The editor never writes through a link (lead ruling 2026-10-26).
    if std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
        let real_path = std::fs::canonicalize(&path)
            .map_or_else(|_| path.display().to_string(), |p| p.display().to_string());
        return Err(Refused::Symlinked { real_path });
    }
    let _held = match lock_config(&dir.join("capabilities"), deadline).await {
        Ok(held) => held,
        Err(NotLocked::Busy) => return Err(Refused::LockBusy),
        Err(NotLocked::Failed(error)) => return Err(unwritable(error, unified_diff("", sent))),
    };
    let current = match std::fs::read_to_string(&path) {
        Ok(text) => Some(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(unwritable(e, unified_diff("", sent))),
    };
    let patch = || unified_diff(current.as_deref().unwrap_or_default(), sent);
    let in_place = edit.pin == PinUpdate::InPlace && matches!(edit.change, Change::Write(_));
    if in_place && current.as_deref().is_some_and(pin_broken) {
        return Err(Refused::PinMismatch { patch: patch() });
    }
    let matches_base = match (&edit.base, &current) {
        (Base::Absent, None) => true,
        (Base::Bytes(hash), Some(text)) => sha(text).eq_ignore_ascii_case(hash),
        _ => false,
    };
    if !matches_base {
        return Err(Refused::Stale {
            patch: patch(),
            current_sha256: current.as_deref().map(sha),
        });
    }
    let before = current.as_deref().map(sha);
    let Change::Write(_) = edit.change else {
        std::fs::remove_file(&path).map_err(|e| unwritable(e, patch()))?;
        return Ok(Committed {
            before,
            after: None,
            pin: PinChange::None,
        });
    };
    let (bytes, pin) = final_bytes(sent, current.as_deref(), edit.pin)?;
    validate(&bytes, &path, accounts).map_err(|errors| Refused::Invalid {
        errors,
        patch: patch(),
    })?;
    // Windows `Inherit` takes the directory's ACL and could widen a private
    // file; Private never widens (lead ruling (A); the shared writer's cause is tracked on its own).
    let mode = if cfg!(windows) {
        FileMode::Private
    } else {
        FileMode::Inherit
    };
    write(&path, &bytes, mode, observe).map_err(|e| unwritable(e, patch()))?;
    Ok(Committed {
        before,
        after: Some(sha(&bytes)),
        pin,
    })
}

#[cfg(not(test))]
fn write(
    path: &Path,
    bytes: &str,
    mode: FileMode,
    _observe: impl FnOnce(&Path),
) -> std::io::Result<()> {
    write_atomic(path, bytes.as_bytes(), mode, Symlink::Replace)
}

#[cfg(test)]
fn write(
    path: &Path,
    bytes: &str,
    mode: FileMode,
    observe: impl FnOnce(&Path),
) -> std::io::Result<()> {
    crate::config_persistence::write_atomic_observed_for_test(
        path,
        bytes.as_bytes(),
        mode,
        Symlink::Replace,
        |_| observe(path),
    )
}

/// `cap pin`: pin `file` in place under its directory's lock (D8). A link
/// is followed, as `cap pin` always has, and the lock is the resolved file's
/// directory, the same lock the editor takes there, so the two never write
/// one file at once.
///
/// # Errors
///
/// The file cannot be resolved, locked, read or written, or is not YAML.
pub fn pin_file(file: &Path) -> Result<String, String> {
    pin_file_until(file, Instant::now() + std::time::Duration::from_secs(30))
}

/// [`pin_file`], waiting for the lock until `deadline`.
fn pin_file_until(file: &Path, deadline: Instant) -> Result<String, String> {
    let real = std::fs::canonicalize(file)
        .map_err(|e| format!("cannot resolve {}: {e}", file.display()))?;
    let dir = real
        .parent()
        .ok_or_else(|| format!("{} has no directory", real.display()))?;
    let _held = crate::config_persistence::lock::lock_config_blocking(
        &dir.join("capabilities"),
        deadline,
        |lock| eprintln!("Waiting for {} (another write holds it)", lock.display()),
    )
    .map_err(|e| match e {
        NotLocked::Busy => format!("{} is locked by another write; retry", dir.display()),
        NotLocked::Failed(error) => error,
    })?;
    let content = std::fs::read_to_string(&real)
        .map_err(|e| format!("cannot read {}: {e}", real.display()))?;
    crate::yaml::from_str::<crate::yaml::Value>(&content)
        .map_err(|e| format!("not a valid YAML file ({}): {e}", real.display()))?;
    let hash = compute_capability_hash(&content);
    let pinned = super::rewrite_with_pin(&content, &hash);
    let mode = if cfg!(windows) {
        FileMode::Private
    } else {
        FileMode::Inherit
    };
    write_atomic(&real, pinned.as_bytes(), mode, Symlink::Replace)
        .map_err(|e| format!("cannot write {}: {e}", real.display()))?;
    Ok(hash)
}

#[cfg(test)]
#[path = "file_writer_tests.rs"]
mod tests;
