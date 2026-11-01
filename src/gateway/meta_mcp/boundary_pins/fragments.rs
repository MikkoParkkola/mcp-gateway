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
    let base = root.join(DIR).join(format!("{name}.tsv"));
    let text = std::fs::read_to_string(&base)
        .unwrap_or_else(|e| panic!("cannot read pin table {}: {e}", base.display()));
    let rows = text
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| (base.clone(), l.to_owned()))
        .collect();
    Table { rows }
}
