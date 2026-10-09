// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Path quoting for fixtures that hand a temp path to a shell or a YAML
//! scalar, written once so it holds on Windows as well as Unix
//! (windows-portability family, MIK-7911). `tests/windows_portability.rs`
//! walks every helper here through every consumer, and refuses a copy of one
//! defined anywhere else under `tests/`.
//!
//! Included by `#[path]` from each suite that needs it, so an item only one
//! suite uses is dead in the other; that is the layout, not a defect.
#![allow(dead_code)]

use std::path::Path;

/// A path as `sh` reads it: double-quoted so a space cannot split it, with
/// forward slashes because a Windows backslash is a shell escape. `sh`, the
/// gateway's POSIX splitter and the Windows argument rules all read the result
/// as one word.
pub(crate) fn sh_path(path: &Path) -> String {
    format!("\"{}\"", path.display().to_string().replace('\\', "/"))
}

/// `text` as a single-quoted YAML scalar, which writes an apostrophe as two.
pub(crate) fn yaml_single_quoted(text: &str) -> String {
    format!("'{}'", text.replace('\'', "''"))
}

/// A temporary home whose path holds a space and an apostrophe, so a path left
/// unquoted (or unescaped in YAML) in a peer script or its `command:` line
/// breaks and the row fails.
pub(crate) fn hostile_home() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("home o'space ")
        .tempdir()
        .expect("temporary home")
}
