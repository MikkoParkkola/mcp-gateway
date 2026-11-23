// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How a kept config version is shown: a fresh text built line by line from
//! the parse, so no byte of the stored file is ever copied into it. Only keys
//! and values appear; a secret slot appears as its reference or `<set>`.

use crate::yaml::Step;

/// One rendered line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Line {
    /// The node's path, keys escaped so two paths never print alike.
    pub(crate) path: String,
    /// The whole line as printed.
    pub(crate) text: String,
    /// For a masked line, a digest of its stored value, kept in memory only
    /// to tell whether it changed between two versions. Never printed.
    pub(crate) secret: Option<[u8; 32]>,
}

/// A rendered text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rendered {
    pub(crate) lines: Vec<Line>,
}

impl Rendered {
    /// Every line, each ended by a line break.
    pub(crate) fn text(&self) -> String {
        self.lines.iter().map(|line| line.text.clone() + "\n").collect()
    }
}

/// A text the masker will not render, as a whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Withheld;

/// The masked rendering of a gateway.yaml text.
pub(crate) fn rendered_yaml(text: &str) -> Result<Rendered, Withheld> {
    let _ = text;
    Ok(Rendered { lines: Vec::new() })
}

/// The names an env file sets, in file order, each as `NAME=<set>`.
pub(crate) fn rendered_env(text: &str) -> Result<Rendered, Withheld> {
    let _ = text;
    Ok(Rendered { lines: Vec::new() })
}

/// Whether a node at `path` (decoded key segments and positions) is a secret
/// slot by the table, whatever its key is named.
pub(crate) fn slot_path(path: &[Step]) -> bool {
    let _ = path;
    false
}

/// A masked line of `newer` whose stored value differs from the line at the
/// same path, with the same token, in `older` reads `(changed)`.
pub(crate) fn mark_changed(older: &[Line], newer: &mut [Line]) {
    let _ = (older, newer);
}

#[cfg(tp3)]
#[cfg(test)]
#[path = "history_mask_tests.rs"]
mod tests;
