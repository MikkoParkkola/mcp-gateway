// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The pin tables, read at test time from `boundary_pins/<name>.tsv`.
//!
//! Every pin test reads its table through [`pin_table`], so the table's rows
//! come from one loader instead of an `include_str!` per test. The table lives
//! under `src/**`, which `Cargo.toml` `include` ships, so the packaged suite
//! reads it the same way.

use std::path::{Path, PathBuf};

use super::packaged::crate_root;

/// Where the pin tables live, relative to the crate root.
const DIR: &str = "src/gateway/meta_mcp/boundary_pins";

/// One pin table's rows, each with the file it was read from.
pub(super) struct Table {
    rows: Vec<(PathBuf, String)>,
}

impl Table {
    /// The rows with the file each came from, in reading order.
    pub(super) fn rows(&self) -> &[(PathBuf, String)] {
        &self.rows
    }

    /// The row lines joined by newlines, for checks that scan the table's
    /// text. Comment and empty lines are not part of it.
    pub(super) fn text(&self) -> String {
        self.rows
            .iter()
            .map(|(_, line)| line.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// The table `name` of this checkout or unpacked crate.
pub(super) fn pin_table(name: &str) -> Table {
    pin_table_at(crate_root(), name)
}

/// The table `name` under `root`, a crate-shaped directory.
///
/// A row is any line that is not empty and does not start with `#`; each
/// consumer keeps its own stricter filter on top. A missing or unreadable
/// table fails the test, naming the path.
pub(super) fn pin_table_at(root: &Path, name: &str) -> Table {
    try_pin_table_at(root, name).unwrap_or_else(|e| panic!("{e}"))
}

/// [`pin_table_at`], returning the failure instead of panicking.
pub(super) fn try_pin_table_at(root: &Path, name: &str) -> Result<Table, String> {
    let base = root.join(DIR).join(format!("{name}.tsv"));
    let text = std::fs::read_to_string(&base)
        .map_err(|e| format!("cannot read pin table {}: {e}", base.display()))?;
    let rows = text
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| (base.clone(), l.to_owned()))
        .collect();
    Ok(Table { rows })
}

/// The live base text of table `name` in this checkout.
pub(super) fn live_base(name: &str) -> String {
    let path = crate_root().join(DIR).join(format!("{name}.tsv"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// `text` without its first row, and that row with a newline: a real row that
/// a test can place in a fragment only.
pub(super) fn without_first_row(text: &str) -> (String, String) {
    let mut moved = None;
    let mut rest = String::new();
    for line in text.lines() {
        if moved.is_none() && !line.is_empty() && !line.starts_with('#') {
            moved = Some(format!("{line}\n"));
        } else {
            rest.push_str(line);
            rest.push('\n');
        }
    }
    (rest, moved.expect("the table has a row"))
}

/// A crate-shaped temporary root holding table `name` (`base` text, and each
/// `(file, text)` fragment under `name.d/`), and the table read from it.
pub(super) fn scratch_table(
    name: &str,
    base: &str,
    fragments: &[(&str, &str)],
) -> (tempfile::TempDir, Table) {
    let root = tempfile::tempdir().expect("a temp crate");
    let dir = root.path().join(DIR);
    std::fs::create_dir_all(dir.join(format!("{name}.d"))).expect("the fragment directory");
    std::fs::write(dir.join(format!("{name}.tsv")), base).expect("the base table");
    for (file, text) in fragments {
        std::fs::write(dir.join(format!("{name}.d")).join(file), text).expect("a fragment");
    }
    let table = pin_table_at(root.path(), name);
    (root, table)
}

#[path = "fragments_tests.rs"]
mod tests;
