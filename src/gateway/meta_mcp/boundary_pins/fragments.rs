// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The pin tables, read at test time from `boundary_pins/<name>.tsv`.
//!
//! Every pin test reads its table through [`pin_table`], so the table's rows
//! come from one loader instead of an `include_str!` per test. The table lives
//! under `src/**`, which `Cargo.toml` `include` ships, so the packaged suite
//! reads it the same way.

use std::fmt::Write as _;
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
    let dir = root.join(DIR);
    let base = dir.join(format!("{name}.tsv"));
    let mut files = vec![base];
    files.extend(fragment_files(&dir.join(format!("{name}.d")))?);
    let mut rows = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file)
            .map_err(|e| format!("cannot read pin table {}: {e}", file.display()))?;
        rows.extend(
            text.lines()
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(|l| (file.clone(), l.to_owned())),
        );
    }
    Ok(Table { rows })
}

/// The fragment files of a `<name>.d/` directory, sorted by name. Only a
/// missing directory holds none; any other failure to list it fails. Entries
/// not named `*.tsv` are ignored (editor and OS files); a `*.tsv` must be
/// named `<digits>[-<digits>].tsv`.
fn fragment_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(format!(
                "cannot list pin-table fragments {}: {e}",
                dir.display()
            ));
        }
    };
    let mut files = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|e| format!("cannot list pin-table fragments {}: {e}", dir.display()))?
            .path();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if path.extension().is_none_or(|ext| ext != "tsv") {
            continue;
        }
        if !fragment_name_ok(&name) {
            return Err(format!(
                "pin-table fragment {} is not named <digits>[-<digits>].tsv",
                path.display()
            ));
        }
        files.push(path);
    }
    files.sort();
    Ok(files)
}

/// `<digits>[-<digits>].tsv`, ASCII digits only.
fn fragment_name_ok(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".tsv") else {
        return false;
    };
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    match stem.split_once('-') {
        Some((number, part)) => digits(number) && digits(part),
        None => digits(stem),
    }
}

/// How a table file is named in messages: `<name>.tsv` for a base table,
/// `<name>.d/<n>.tsv` for a fragment.
pub(super) fn shown(path: &Path) -> String {
    let file = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    match path.parent().and_then(Path::file_name) {
        Some(parent) if parent.to_string_lossy().ends_with(".d") => {
            format!("{}/{file}", parent.to_string_lossy())
        }
        _ => file,
    }
}

/// The failure message of a multiset table whose pinned rows (each with the
/// file holding it) differ from the computed rows, or `None` when they match
/// as multisets. It lists what to add, in the reader's own fragment, and what
/// to remove with its quantity and the files holding copies; the computed rows
/// follow for comparison only, never as text to paste.
pub(super) fn multiset_delta(
    name: &str,
    computed: &[String],
    pinned: &[(&Path, &str)],
) -> Option<String> {
    use std::collections::BTreeMap;
    let mut want: BTreeMap<&str, usize> = BTreeMap::new();
    for row in computed {
        *want.entry(row.as_str()).or_default() += 1;
    }
    let mut have: BTreeMap<&str, Vec<&Path>> = BTreeMap::new();
    for (file, row) in pinned {
        have.entry(row).or_default().push(file);
    }
    let mut add = Vec::new();
    let mut remove = Vec::new();
    for (row, &n) in &want {
        let held = have.get(row).map_or(0, Vec::len);
        add.extend(std::iter::repeat_n(*row, n.saturating_sub(held)));
    }
    for (row, files) in &have {
        let n = want.get(row).copied().unwrap_or(0);
        if files.len() > n {
            let mut shown_files: Vec<String> = files.iter().map(|f| shown(f)).collect();
            shown_files.dedup();
            remove.push(format!(
                "{} x {row}    (in {})",
                files.len() - n,
                shown_files.join(", ")
            ));
        }
    }
    if add.is_empty() && remove.is_empty() {
        return None;
    }
    let mut message = format!(
        "{name}: {} rows pinned, {} computed; the pinned rows differ\n",
        pinned.len(),
        computed.len()
    );
    if !add.is_empty() {
        let _ = writeln!(
            message,
            "rows to add ({}; put these in your fragment {name}.d/<ticket>.tsv):\n{}",
            add.len(),
            add.join("\n")
        );
    }
    if !remove.is_empty() {
        let _ = writeln!(
            message,
            "rows to remove ({}):\n{}",
            remove.len(),
            remove.join("\n")
        );
    }
    let _ = write!(
        message,
        "for comparison only; do not paste into any table:\n{}",
        computed.join("\n")
    );
    Some(message)
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
