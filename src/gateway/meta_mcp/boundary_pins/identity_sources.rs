// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every way production code creates a caller identity is a reviewed row in
//! `identity_sources.tsv`, keyed by (file, owner, kind): each call of a
//! checked constructor or the certificate parser and each struct literal of
//! the three identity types, with its count; each macro that names one of
//! them; and, in the three modules that define them, every production item
//! with a fingerprint of its tokens. A new site, a changed count or
//! fingerprint, a stale row or a row with no reason fails.
//!
//! Refused outright, whatever the table says: renaming one of the types by
//! `use .. as` or `type`, a qualified path (`<GrantSubject>::new`), a child
//! module or `include!` in a defining module, and any macro outside a fixed
//! list in a defining module or in an impl of one of the types.
//!
//! Outside the defining modules the compiler is the guard for fields: they are
//! private, and privacy is checked after macro expansion. Inside them the
//! fingerprints are, so any edit there is a reviewed row.

use std::collections::BTreeMap;

use super::fragments::{Table, shown};
use super::packaged::crate_root;
use super::scan::{Place, Sink, walk};

const ROOTS: [&str; 3] = ["src/lib.rs", "src/main.rs", "src/bin/provenance-eval.rs"];

/// (file, owner, kind) -> count, or fingerprint for kind `item`.
pub(super) type Rows = BTreeMap<(String, String, String), String>;

/// What one scan found: the rows, and the forms refused outright.
#[derive(Default, Debug)]
pub(super) struct Scan {
    pub(super) rows: Rows,
    pub(super) refused: Vec<String>,
}

/// Scan one production file, `file` relative to the crate root.
pub(super) fn scan_file(_file: &str, _parsed: &syn::File, _scan: &mut Scan) {}

/// Hands each production file the shared walk reaches to [`scan_file`].
struct Files(Scan);

impl Sink for Files {
    fn file(&mut self, at: &Place, file: &syn::File) {
        scan_file(&at.file, file, &mut self.0);
    }
}

/// The scan of every production file of this crate.
pub(super) fn crate_scan() -> Scan {
    let mut files = Files(Scan::default());
    walk(crate_root(), &ROOTS, &mut files).expect("the walk reads every module");
    files.0
}

/// (file, owner, kind) -> (value, the table file listing it).
type Listed = BTreeMap<(String, String, String), (String, String)>;

/// The reviewed rows (file, owner, kind, value, reason), and the malformed ones.
fn listed(table: &Table) -> (Listed, Vec<String>) {
    let mut rows = Listed::new();
    let mut bad = Vec::new();
    for (path, line) in table.rows() {
        let at = shown(path);
        let cols: Vec<&str> = line.split('\t').collect();
        let [file, owner, kind, value, reason] = cols[..] else {
            bad.push(format!("not five columns in {at}: {line}"));
            continue;
        };
        if reason.trim().is_empty() {
            bad.push(format!("no reason in {at}: {line}"));
        }
        let key = (file.to_owned(), owner.to_owned(), kind.to_owned());
        if let Some((_, earlier)) = rows.insert(key, (value.to_owned(), at.clone())) {
            bad.push(format!(
                "repeated key in {earlier} and {at}: {file}\t{owner}\t{kind}"
            ));
        }
    }
    (rows, bad)
}

/// What differs between a scan and the reviewed table: refused forms,
/// malformed rows, changed values, unlisted sites and stale rows.
pub(super) fn differences(found: &Scan, table: &Table) -> Vec<String> {
    let (want, bad) = listed(table);
    let mut wrong: Vec<String> = found.refused.clone();
    wrong.extend(bad);
    let mut add = Vec::new();
    for (key, value) in &found.rows {
        match want.get(key) {
            Some((listed, _)) if listed == value => {}
            Some((listed, at)) => wrong.push(format!(
                "{listed} -> {value}, review and edit this row in {at}: {}\t{}\t{}",
                key.0, key.1, key.2
            )),
            None => add.push(format!(
                "{}\t{}\t{}\t{value}\t<reason>",
                key.0, key.1, key.2
            )),
        }
    }
    for (key, (_, at)) in want.iter().filter(|(k, _)| !found.rows.contains_key(*k)) {
        wrong.push(format!(
            "stale, remove from {at}: {}\t{}\t{}",
            key.0, key.1, key.2
        ));
    }
    if !add.is_empty() {
        wrong.push(format!(
            "rows to add ({}; put these in your fragment identity_sources.d/<ticket>.tsv):",
            add.len()
        ));
        wrong.extend(add);
    }
    wrong
}

#[path = "identity_sources_tests.rs"]
mod tests;
