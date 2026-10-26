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

/// A top-level `sha256:` line as text: where it is, its value, and the
/// byte span of the value in the line, so a save replaces only the value and
/// keeps its quotes, spacing, comment and terminator.
struct PinLine {
    index: usize,
    value: String,
    span: (usize, usize),
}

/// The top-level pin lines, found as text: what a splice can rewrite.
fn pin_lines(text: &str) -> Vec<PinLine> {
    text.split('\n')
        .enumerate()
        .filter_map(|(index, line)| {
            let after = line.strip_prefix(PIN_KEY)?;
            let gap = after.len() - after.trim_start_matches([' ', '\t']).len();
            let start = PIN_KEY.len() + gap;
            let rest = &line[start..];
            let (from, len) = match rest.chars().next() {
                Some(q @ ('"' | '\'')) => (start + 1, rest[1..].find(q)?),
                _ => (start, rest.find([' ', '\t', '\r']).unwrap_or(rest.len())),
            };
            Some(PinLine {
                index,
                value: line[from..from + len].to_string(),
                span: (from, from + len),
            })
        })
        .collect()
}

/// The document's `sha256` as YAML reads it (lead ruling 2026-10-26: one
/// total rule). A pin is absent only when the key is missing; anything else
/// under it is a pin, and only a string of exactly 64 hex digits can verify.
enum YamlPin {
    /// No top-level `sha256` key.
    Absent,
    /// A string of 64 hex digits: the pin to compare.
    Value(String),
    /// Anything else under the key (a number, a boolean, null, a list, a
    /// map, a string of another length or not hex), or text that is not
    /// YAML and mentions `sha256` at all (a duplicate key is not YAML
    /// here). It can never verify.
    Unreadable,
}

/// The top-level `sha256` key the loader's field comes from, read without
/// the capability schema, so a file whose schema is broken still has its pin
/// judged.
fn yaml_pin(text: &str) -> YamlPin {
    let Ok(doc) = crate::yaml::from_str::<crate::yaml::Value>(text) else {
        // Text that is not YAML cannot have its key located safely (it may
        // be indented, quoted, BOM-prefixed or an explicit `? sha256`), so
        // any mention of the key fails closed.
        return if text.contains("sha256") {
            YamlPin::Unreadable
        } else {
            YamlPin::Absent
        };
    };
    match doc.get("sha256") {
        None => YamlPin::Absent,
        Some(value) => match value.as_str() {
            Some(pin) if pin.len() == 64 && pin.bytes().all(|b| b.is_ascii_hexdigit()) => {
                YamlPin::Value(pin.to_string())
            }
            _ => YamlPin::Unreadable,
        },
    }
}

/// The pin as the loader reads it, or `None` when there is none or the text
/// is not YAML.
fn loader_pin(text: &str) -> Option<String> {
    match yaml_pin(text) {
        YamlPin::Value(pin) => Some(pin),
        YamlPin::Absent | YamlPin::Unreadable => None,
    }
}

/// Whether the text carries a pin, by YAML or, for text that is not YAML, by
/// a pin line.
fn is_pinned(text: &str) -> bool {
    !matches!(yaml_pin(text), YamlPin::Absent) || !pin_lines(text).is_empty()
}

/// Whether a pin line carries text after a YAML line break other than `\n`
/// (a lone CR, NEL, LS or PS): the smuggling shape `strip_sha256_line` drops.
fn smuggles(text: &str, index: usize) -> bool {
    let line = text.split('\n').nth(index).unwrap_or_default();
    let body = line.strip_suffix('\r').unwrap_or(line);
    body.contains(['\r', '\u{85}', '\u{2028}', '\u{2029}'])
}

/// Whether the file's pin no longer matches its bytes: the loader's own
/// comparison (`parser.rs`), on the YAML key whatever the schema says. Text
/// that is not YAML but has a pin line cannot be judged, so it counts as
/// broken: an edit never re-pins bytes nobody verified.
fn pin_broken(current: &str) -> bool {
    match yaml_pin(current) {
        YamlPin::Absent => false,
        YamlPin::Value(pin) => !pin.eq_ignore_ascii_case(&compute_capability_hash(current)),
        // Nothing verified these bytes, so an edit never re-pins them.
        YamlPin::Unreadable => true,
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

/// Past this many table cells the middle of a diff is a full replace: the
/// patch still applies, and memory stays bounded (4M `u32` cells, 16 MB).
const DIFF_MAX_CELLS: usize = 4_000_000;

/// One line of a patch: its tag and its bytes, terminator included.
fn patch_line(out: &mut String, tag: char, line: &str) {
    out.push(tag);
    out.push_str(line);
    if !line.ends_with('\n') {
        out.push_str("\n\\ No newline at end of file\n");
    }
}

/// The middle of a diff as tagged lines, by longest common subsequence.
fn lcs_lines<'a>(a: &[&'a str], b: &[&'a str]) -> Vec<(char, &'a str)> {
    let width = b.len() + 1;
    let mut table = vec![0u32; (a.len() + 1) * width];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            table[i * width + j] = if a[i] == b[j] {
                table[(i + 1) * width + j + 1] + 1
            } else {
                table[(i + 1) * width + j].max(table[i * width + j + 1])
            };
        }
    }
    let mut out = Vec::with_capacity(a.len() + b.len());
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        if i < a.len() && j < b.len() && a[i] == b[j] {
            out.push((' ', a[i]));
            i += 1;
            j += 1;
        } else if j < b.len()
            && (i == a.len() || table[i * width + j + 1] >= table[(i + 1) * width + j])
        {
            out.push(('+', b[j]));
            j += 1;
        } else {
            out.push(('-', a[i]));
            i += 1;
        }
    }
    out
}

/// A unified diff from `from` to `to`, one hunk over the whole file, line
/// terminators kept, a missing final newline marked.
pub(crate) fn unified_diff(from: &str, to: &str) -> String {
    let a: Vec<&str> = from.split_inclusive('\n').collect();
    let b: Vec<&str> = to.split_inclusive('\n').collect();
    let prefix = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let suffix = a[prefix..]
        .iter()
        .rev()
        .zip(b[prefix..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let (mid_a, mid_b) = (&a[prefix..a.len() - suffix], &b[prefix..b.len() - suffix]);
    let cells = (mid_a.len() + 1).saturating_mul(mid_b.len() + 1);
    let middle = if cells <= DIFF_MAX_CELLS {
        lcs_lines(mid_a, mid_b)
    } else {
        mid_a
            .iter()
            .map(|l| ('-', *l))
            .chain(mid_b.iter().map(|l| ('+', *l)))
            .collect()
    };
    // An empty side starts at line 0, as `git apply` requires.
    let start = |n: usize| usize::from(n > 0);
    let mut out = format!(
        "--- current\n+++ sent\n@@ -{},{} +{},{} @@\n",
        start(a.len()),
        a.len(),
        start(b.len()),
        b.len()
    );
    for line in &a[..prefix] {
        patch_line(&mut out, ' ', line);
    }
    for (tag, line) in middle {
        patch_line(&mut out, tag, line);
    }
    for line in &a[a.len() - suffix..] {
        patch_line(&mut out, ' ', line);
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
    let was_pinned = current.is_some_and(is_pinned);
    if pin == PinUpdate::Verbatim {
        if was_pinned && !is_pinned(sent) {
            return Err(Refused::Unpin { patch: patch() });
        }
        let change = if is_pinned(sent) {
            PinChange::Kept
        } else {
            PinChange::None
        };
        return Ok((sent.to_string(), change));
    }
    let mut text = in_base_style(sent, current);
    // A pin on the first line must stay a line the loader's strip sees: a
    // restored BOM in front of it would hide it, and the pin would never
    // verify. The BOM a textarea dropped stays dropped in that one case.
    if pin_lines(sent).first().is_some_and(|p| p.index == 0) && text.starts_with('\u{feff}') {
        text.remove(0);
    }
    let pins = pin_lines(&text);
    match pins.as_slice() {
        // The loader sees a pin no `sha256:` line carries (a quoted key):
        // there is no line to rewrite, so nothing can be saved in place.
        [] if !matches!(yaml_pin(&text), YamlPin::Absent) => {
            Err(Refused::PinAmbiguous { patch: patch() })
        }
        [] if was_pinned => Err(Refused::Unpin { patch: patch() }),
        [] => Ok((text, PinChange::None)),
        [line] if !smuggles(&text, line.index) => {
            let hash = compute_capability_hash(&text);
            let mut lines: Vec<String> = text.split('\n').map(str::to_string).collect();
            lines[line.index].replace_range(line.span.0..line.span.1, &hash);
            let spliced = lines.join("\n");
            // The loader must read back exactly the hash written, or the
            // splice missed (a value shape the line scan reads differently).
            if loader_pin(&spliced).as_deref() != Some(hash.as_str()) {
                return Err(Refused::PinAmbiguous { patch: patch() });
            }
            let before = current.and_then(|c| {
                loader_pin(c).or_else(|| match pin_lines(c).as_slice() {
                    [only] => Some(only.value.clone()),
                    _ => None,
                })
            });
            let change = match before {
                None => PinChange::Added,
                Some(old) if old.eq_ignore_ascii_case(&hash) => PinChange::Kept,
                Some(_) => PinChange::Updated,
            };
            Ok((spliced, change))
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

/// The current file, read without following a link: its text and whether
/// its mode is owner-only. `None` when there is no file.
///
/// # Errors
///
/// `Symlinked` for a link; `Unwritable` for anything that is not a readable
/// regular file.
fn read_current(path: &Path, sent: &str) -> Result<(Option<String>, bool), Refused> {
    use std::io::Read;
    let symlinked = || Refused::Symlinked {
        real_path: std::fs::canonicalize(path)
            .map_or_else(|_| path.display().to_string(), |p| p.display().to_string()),
    };
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(symlinked());
    }
    let mut open = std::fs::OpenOptions::new();
    open.read(true);
    // Unix: never follow a link, and never block on a FIFO or take a
    // terminal; the handle's own metadata then says what was opened.
    #[cfg(unix)]
    {
        use rustix::fs::OFlags;
        use std::os::unix::fs::OpenOptionsExt;
        open.custom_flags(
            (OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY)
                .bits()
                .cast_signed(),
        );
    }
    // Windows: open a link itself rather than its target (no follow), so
    // the handle's metadata shows the link and it is refused below.
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        open.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = match open.open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((None, false)),
        // A link swapped in after the look above: O_NOFOLLOW refuses it.
        #[cfg(unix)]
        Err(e) if e.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) => {
            return Err(symlinked());
        }
        Err(e) => return Err(unwritable(e, unified_diff("", sent))),
    };
    let meta = file
        .metadata()
        .map_err(|e| unwritable(e, unified_diff("", sent)))?;
    if meta.file_type().is_symlink() {
        return Err(symlinked());
    }
    if !meta.is_file() {
        return Err(unwritable("not a regular file", unified_diff("", sent)));
    }
    #[cfg(unix)]
    let private = {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode().trailing_zeros() >= 6
    };
    #[cfg(not(unix))]
    let private = false;
    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|e| unwritable(e, unified_diff("", sent)))?;
    Ok((Some(text), private))
}

/// `<dir>/<name>.yaml`, or the `.yml` file when only that one exists.
fn target_path(dir: &Path, name: &str) -> PathBuf {
    let long_ext = dir.join(format!("{name}.yaml"));
    let short_ext = dir.join(format!("{name}.yml"));
    if std::fs::symlink_metadata(&long_ext).is_err()
        && std::fs::symlink_metadata(&short_ext).is_ok()
    {
        short_ext
    } else {
        long_ext
    }
}

/// What a save of `sent` over `current` would write, without writing: the
/// bytes and the pin change, or the refusal the save would answer.
///
/// # Errors
///
/// `PinMismatch`, `Unpin` or `PinAmbiguous`, as [`commit`] would answer.
pub(crate) fn preview(sent: &str, current: Option<&str>) -> Result<(String, PinChange), Refused> {
    if current.is_some_and(pin_broken) {
        return Err(Refused::PinMismatch {
            patch: unified_diff(current.unwrap_or_default(), sent),
        });
    }
    final_bytes(sent, current, PinUpdate::InPlace)
}

/// The list's pin column: `verified`, `mismatch` or `unpinned`.
pub(crate) fn pin_state(text: &str) -> &'static str {
    if !is_pinned(text) {
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
#[cfg(all(test, unix))]
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
    let _held = match lock_config(&dir.join("capabilities"), deadline).await {
        Ok(held) => held,
        Err(NotLocked::Busy) => return Err(Refused::LockBusy),
        Err(NotLocked::Failed(error)) => return Err(unwritable(error, unified_diff("", sent))),
    };
    // Under the lock: which file, whether it is a link, its bytes and its
    // mode all come from one look, so nothing installed while the lock was
    // awaited is read or replaced (lead ruling 2026-10-26: never a link).
    let target = target_path(&dir, edit.name);
    let (current, private) = read_current(&target, sent)?;
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
        std::fs::remove_file(&target).map_err(|e| unwritable(e, patch()))?;
        return Ok(Committed {
            before,
            after: None,
            pin: PinChange::None,
        });
    };
    let (bytes, pin) = final_bytes(sent, current.as_deref(), edit.pin)?;
    validate(&bytes, &target, accounts).map_err(|errors| Refused::Invalid {
        errors,
        patch: patch(),
    })?;
    // Windows `Inherit` takes the directory's ACL and could widen a private
    // file; Private never widens (lead ruling (A); the shared writer's cause
    // is tracked on its own). On Unix a file read as private is written
    // private, so a file swapped or removed before the rename never falls
    // back to the umask.
    let mode = if cfg!(windows) || private {
        FileMode::Private
    } else {
        FileMode::Inherit
    };
    write(&target, &bytes, mode, observe).map_err(|e| unwritable(e, patch()))?;
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
    pin_file_until(file, Instant::now() + std::time::Duration::from_secs(5))
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
        NotLocked::Busy => format!(
            "{} is held by another write; retry",
            crate::config_persistence::lock::lock_path(&dir.join("capabilities")).display()
        ),
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
