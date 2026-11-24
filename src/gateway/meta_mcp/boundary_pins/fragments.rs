// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The pin tables, read at test time from `boundary_pins/<name>.tsv` plus any
//! `<name>.d/<digits>[-<digits>].tsv` fragments beside it.
//!
//! The pin tests for `allows`, `scoped_backends_classes`, `creation_sites`,
//! `presend_exits`, `delivery_framing_inventory` and `delivery_refusals` read
//! through [`pin_table`]. A new row goes in the change's own fragment, so two
//! changes adding rows never edit the same file. The tables live under
//! `src/**`, which `Cargo.toml` `include` ships, so the packaged suite reads
//! them the same way.

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
        // Any letter case of `tsv` marks a fragment candidate, so `1.TSV` fails
        // the name rule below instead of being skipped and never loaded.
        if path
            .extension()
            .is_none_or(|ext| !ext.eq_ignore_ascii_case("tsv"))
        {
            continue;
        }
        if !fragment_name_ok(&name) {
            return Err(format!(
                "pin-table fragment {} is not named <digits>[-<digits>].tsv",
                path.display()
            ));
        }
        // A regular file only: a directory fails on read, and a special file
        // (a FIFO) could block the read instead of failing.
        if !path.is_file() {
            return Err(format!(
                "pin-table fragment {} is not a regular file",
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
/// follow for comparison only, never as text to paste. With `bless`, the rows
/// to add are also appended to that fragment ([`bless_into`]); the result is
/// the same failure, so a run that wrote rows never passes.
pub(super) fn delta_or_bless(
    name: &str,
    computed: &[String],
    pinned: &[(&Path, &str)],
    bless: Option<Bless<'_>>,
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
            "rows to add ({}; put these in your fragment {name}.d/<ticket>.tsv, or run with \
             {BLESS_VAR}=<ticket> to have them written there):\n{}",
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
    if let Some(bless) = bless.filter(|_| !add.is_empty()) {
        let _ = writeln!(message, "{}", bless_into(bless, name, &add));
    }
    let _ = write!(
        message,
        "for comparison only; do not paste into any table:\n{}",
        computed.join("\n")
    );
    Some(message)
}

/// The variable that turns the bless mode on; its value is the ticket that
/// names the fragment the rows go into.
pub(super) const BLESS_VAR: &str = "BOUNDARY_PINS_BLESS";

/// Where a blessed check writes: a crate-shaped root and the ticket of the
/// fragment, `<name>.d/<ticket>.tsv`.
#[derive(Clone, Copy)]
pub(super) struct Bless<'a> {
    pub(super) root: &'a Path,
    pub(super) ticket: &'a str,
}

/// The ticket a bless names, given the values of [`BLESS_VAR`] and `CI`:
/// none when unset or empty; refused when the value names no fragment, and
/// refused under CI, which never writes the tree.
pub(super) fn bless_from(bless: Option<&str>, ci: Option<&str>) -> Result<Option<String>, String> {
    let Some(ticket) = bless.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if !fragment_name_ok(&format!("{ticket}.tsv")) {
        return Err(format!(
            "{BLESS_VAR}={ticket} names no fragment; want <digits>[-<digits>]"
        ));
    }
    if ci.is_some_and(|value| !value.is_empty()) {
        return Err(format!(
            "{BLESS_VAR}={ticket} with CI set: a CI run never writes pin fragments"
        ));
    }
    Ok(Some(ticket.to_owned()))
}

/// The bless target of the live pin tests: this checkout's root and the
/// ticket the environment names, decided once per process. Only the live
/// `#[test]` functions call it; every check helper takes the result as a
/// parameter, so a test that passes `None` never writes, whatever the
/// environment holds. A refused value fails the calling test.
pub(super) fn bless_ticket() -> Option<Bless<'static>> {
    static DECIDED: std::sync::OnceLock<Result<Option<String>, String>> =
        std::sync::OnceLock::new();
    let decided = DECIDED.get_or_init(|| {
        let read = |key| std::env::var(key).ok();
        bless_from(read(BLESS_VAR).as_deref(), read("CI").as_deref())
    });
    match decided {
        Ok(ticket) => ticket.as_deref().map(|ticket| Bless {
            root: crate_root(),
            ticket,
        }),
        Err(refused) => panic!("{refused}"),
    }
}

/// Append `rows` to the fragment `bless` names for table `name`, and say so
/// in one line for the failure message. Append-only: a new file starts with
/// the base table's `#` header line, when it has one; an existing file keeps
/// its bytes, gaining a newline first when its last line lacks one.
fn bless_into(bless: Bless<'_>, name: &str, rows: &[&str]) -> String {
    let dir = bless.root.join(DIR);
    let path = dir
        .join(format!("{name}.d"))
        .join(format!("{}.tsv", bless.ticket));
    match append_rows(&dir.join(format!("{name}.tsv")), &path, rows) {
        Ok(()) => format!(
            "blessed: {} rows written into {name}.d/{}.tsv; review them before committing",
            rows.len(),
            bless.ticket
        ),
        Err(e) => format!("bless failed: cannot write {}: {e}", path.display()),
    }
}

/// [`bless_into`]'s write: the separator or header, then one line per row.
fn append_rows(base: &Path, path: &Path, rows: &[&str]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut text = String::new();
    match std::fs::read(path) {
        Ok(held) if held.last().is_some_and(|byte| *byte != b'\n') => text.push('\n'),
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let base_text = std::fs::read_to_string(base)?;
            if let Some(header) = base_text.lines().next().filter(|l| l.starts_with('#')) {
                text.push_str(header);
                text.push('\n');
            }
        }
        Err(e) => return Err(e),
    }
    for row in rows {
        text.push_str(row);
        text.push('\n');
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?
        .write_all(text.as_bytes())
}

/// Every fragment file of table `name` under `root`, by file name, with its
/// bytes: what a row compares before and after a check. Listed by
/// [`fragment_files`], so a missing folder is no fragments and any other
/// failure fails the row; an unreadable fragment fails it too, so a snapshot
/// never stands in for a file it could not read.
pub(super) fn fragment_bytes(root: &Path, name: &str) -> Vec<(String, Vec<u8>)> {
    let folder = root.join(DIR).join(format!("{name}.d"));
    let listed = fragment_files(&folder).unwrap_or_else(|e| panic!("{e}"));
    listed
        .into_iter()
        .map(|file| {
            let held = std::fs::read(&file)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", file.display()));
            (shown(&file), held)
        })
        .collect()
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

/// A crate-shaped temporary root holding table `name`: `base` as its base
/// text, every live fragment of the table copied unchanged (so rows that live
/// only in a fragment stay covered), then each extra `(file, text)` fragment.
/// An extra may not reuse a live fragment's name. Returns the root and the
/// table read from it.
pub(super) fn scratch_table(
    name: &str,
    base: &str,
    fragments: &[(&str, &str)],
) -> (tempfile::TempDir, Table) {
    let root = tempfile::tempdir().expect("a temp crate");
    let dir = root.path().join(DIR);
    let frag_dir = dir.join(format!("{name}.d"));
    std::fs::create_dir_all(&frag_dir).expect("the fragment directory");
    std::fs::write(dir.join(format!("{name}.tsv")), base).expect("the base table");
    let live = fragment_files(&crate_root().join(DIR).join(format!("{name}.d")))
        .unwrap_or_else(|e| panic!("{e}"));
    for path in &live {
        let file = path.file_name().expect("a fragment name");
        std::fs::copy(path, frag_dir.join(file)).expect("a live fragment copied");
    }
    for (file, text) in fragments {
        let target = frag_dir.join(file);
        assert!(
            !target.exists(),
            "{file} is a live fragment of {name}; use another name"
        );
        std::fs::write(target, text).expect("a fragment");
    }
    let table = pin_table_at(root.path(), name);
    (root, table)
}

#[path = "fragments_tests.rs"]
mod tests;

#[path = "bless_tests.rs"]
mod bless_tests;
