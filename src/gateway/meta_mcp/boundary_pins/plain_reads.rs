// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every plain file read in production code, by (file, fn, callee, count),
//! each classified in `plain_reads.tsv`: gateway.yaml is read only through
//! the config guard, so a new plain read anywhere fails here until someone
//! says what it opens. The walk covers the lib, the binary and every other
//! root, skipping test-only code by cfg.
//!
//! A read is a call to a path ending in `fs::read` or `fs::read_to_string`
//! (std or tokio), `File::open`, or `open_nonblocking`. Not seen: a function
//! imported by its bare name, `OpenOptions`, `fs::copy`, and a read through a
//! helper of another name; those helpers are rows themselves where they read.
//!
//! Regenerating the table is a reviewed diff, never a silent refresh: run
//! this test, copy the printed table, and classify every new row.

use std::collections::BTreeMap;
use std::path::Path;

use super::packaged::crate_root;
use super::scan::{Place, Sink, walk};

const ROOTS: [&str; 3] = ["src/lib.rs", "src/main.rs", "src/bin/provenance-eval.rs"];

/// What a plain read site opens.
const CLASSES: [&str; 5] = [
    // The config guard's own open: the one place gateway.yaml is opened to
    // be read for anything that writes.
    "guard",
    // Reads gateway.yaml for a command that writes nothing from it (a
    // report, a notice, a dry run); the reason says what the bytes feed.
    "read-only",
    // Copies gateway.yaml to a backup with the source's own access; nothing
    // in the gateway reads the backup back.
    "backup-copy",
    // Reads a file that is not gateway.yaml; the reason names it.
    "not-config",
    // Opens a path without reading its bytes (a directory to sync, a probe).
    "no-content",
];

/// Known gaps, each closed by deleting its slug once its last row flips.
const PENDING: [&str; 0] = [];

#[derive(Default)]
struct Found {
    reads: BTreeMap<String, usize>,
}

/// The plain read `segments` names, if it is one.
fn read_callee(segments: &[String]) -> Option<String> {
    let last = segments.last()?.as_str();
    let owner = segments.len().checked_sub(2).map(|i| segments[i].as_str());
    match (owner, last) {
        (Some("fs"), "read" | "read_to_string") | (Some("File"), "open") => {
            Some(format!("{}::{last}", owner.unwrap_or_default()))
        }
        (_, "open_nonblocking") => Some("open_nonblocking".to_owned()),
        _ => None,
    }
}

impl Sink for Found {
    fn expr(&mut self, at: &Place, expr: &syn::Expr) {
        let syn::Expr::Call(call) = expr else {
            return;
        };
        let syn::Expr::Path(path) = &*call.func else {
            return;
        };
        let segments: Vec<String> = path
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect();
        if let Some(callee) = read_callee(&segments) {
            let func = at.func.clone().unwrap_or_else(|| "<module>".to_owned());
            *self
                .reads
                .entry(format!("{}\t{func}\t{callee}", at.file))
                .or_default() += 1;
        }
    }
}

fn found_in(root: &Path, roots: &[&str]) -> Vec<String> {
    let mut found = Found::default();
    walk(root, roots, &mut found).expect("the crate walks");
    found
        .reads
        .iter()
        .map(|(key, n)| format!("{key}\t{n}"))
        .collect()
}

fn pinned(text: &str) -> Vec<String> {
    let mut rows: Vec<String> = text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| l.split('\t').take(4).collect::<Vec<_>>().join("\t"))
        .collect();
    rows.sort();
    rows
}

#[test]
fn every_plain_read_is_classified() {
    let have = found_in(crate_root(), &ROOTS);
    let text = include_str!("plain_reads.tsv");
    let want = pinned(text);
    if have != want {
        println!("BEGIN plain_reads.tsv\n{}\nEND", have.join("\n"));
    }
    assert_eq!(
        have, want,
        "plain read sites changed: classify each new one in plain_reads.tsv"
    );
    for row in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
    {
        let mut columns = row.split('\t');
        let class = columns.nth(4).unwrap_or("");
        let reason = columns.next().unwrap_or("").trim();
        let pending = class
            .strip_prefix("pending:")
            .is_some_and(|slug| PENDING.contains(&slug));
        assert!(
            CLASSES.contains(&class) || pending,
            "unclassified plain read: {row}"
        );
        assert!(!reason.is_empty(), "a plain read with no reason: {row}");
    }
    for slug in PENDING {
        assert!(
            text.contains(&format!("\tpending:{slug}\t")),
            "pending:{slug} has no rows left; delete it from PENDING"
        );
    }
    let guards: Vec<&str> = text.lines().filter(|l| l.contains("\tguard\t")).collect();
    assert!(
        guards
            .iter()
            .all(|l| l.starts_with("src/config/secret_file.rs\t")),
        "only the config guard may be classified guard: {guards:?}"
    );
}

/// The walk sees a plain read of the config path in a crate it has never
/// seen, and skips one in test-only code.
#[test]
fn a_new_plain_read_of_the_config_is_seen() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(dir.path().join("src")).expect("src");
    crate::gateway::test_helpers::write_owner_only(
        dir.path().join("src/lib.rs"),
        "pub fn load(config_path: &std::path::Path) -> String {\n    \
         std::fs::read_to_string(config_path).unwrap_or_default()\n}\n\
         pub fn open(config_path: &std::path::Path) {\n    \
         let _ = crate::open_nonblocking::open_nonblocking(config_path);\n    \
         let _ = std::fs::File::open(config_path);\n    let _ = tokio::fs::read(config_path);\n}\n\
         #[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        \
         let _ = std::fs::read(\"x\");\n    }\n}\n",
    )
    .expect("fixture");

    let rows = found_in(dir.path(), &["src/lib.rs"]);

    assert_eq!(
        rows,
        [
            "src/lib.rs\tload\tfs::read_to_string\t1",
            "src/lib.rs\topen\tFile::open\t1",
            "src/lib.rs\topen\tfs::read\t1",
            "src/lib.rs\topen\topen_nonblocking\t1",
        ]
    );
}

/// `src/lib.rs` of a fixture crate holding `source`, walked.
fn fixture_rows(source: &str) -> Vec<String> {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(dir.path().join("src")).expect("src");
    crate::gateway::test_helpers::write_owner_only(dir.path().join("src/lib.rs"), source)
        .expect("fixture");
    found_in(dir.path(), &["src/lib.rs"])
}

/// Every other way to open or copy a file is seen too: an `OpenOptions`
/// open (inline or held in a binding), `File::options`, `fs::copy`, a read
/// imported by its bare name, one imported under another name, and one
/// called through a renamed `fs` module or a renamed `File`.
#[test]
fn every_other_form_of_a_plain_read_is_seen() {
    let rows = fixture_rows(
        "use std::fs::read_to_string;\n\
         use std::fs::read as slurp;\n\
         use std::fs as disk;\n\
         use std::fs::{File as Handle, OpenOptions};\n\
         pub fn inline(p: &std::path::Path) {\n    \
         let _ = std::fs::OpenOptions::new().read(true).open(p);\n}\n\
         pub fn held(p: &std::path::Path) {\n    \
         let mut options = OpenOptions::new();\n    options.read(true);\n    \
         let _ = options.open(p);\n    let _ = std::fs::File::options().read(true).open(p);\n}\n\
         pub fn copied(p: &std::path::Path) {\n    let _ = std::fs::copy(p, p);\n}\n\
         pub fn bare(p: &std::path::Path) {\n    let _ = read_to_string(p);\n}\n\
         pub fn renamed(p: &std::path::Path) {\n    let _ = slurp(p);\n    \
         let _ = disk::read(p);\n    let _ = Handle::open(p);\n}\n",
    );

    assert_eq!(
        rows,
        [
            "src/lib.rs\tbare\tfs::read_to_string\t1",
            "src/lib.rs\tcopied\tfs::copy\t1",
            "src/lib.rs\theld\tFile::options\t1",
            "src/lib.rs\theld\tOpenOptions::new\t1",
            "src/lib.rs\tinline\tOpenOptions::new\t1",
            "src/lib.rs\trenamed\tFile::open\t1",
            "src/lib.rs\trenamed\tfs::read\t2",
        ]
    );
}

/// An `fs` import the walk cannot resolve to a name (a glob) is a row of
/// its own, so it fails the pin until someone classifies it.
#[test]
fn an_fs_import_the_walk_cannot_resolve_is_a_row() {
    let rows = fixture_rows(
        "use std::fs::*;\npub fn hidden(p: &std::path::Path) {\n    let _ = read(p);\n}\n",
    );

    assert_eq!(rows, ["src/lib.rs\t<module>\tuse fs::*\t1"]);
}

/// The walk's roots are the crate's targets: the library, every `[[bin]]`
/// path and every file Cargo finds under `src/bin/`, so a new binary cannot
/// escape the inventory.
#[test]
fn the_walk_roots_are_the_cargo_targets() {
    let root = crate_root();
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).expect("Cargo.toml");
    let mut targets = vec!["src/lib.rs".to_owned()];
    let mut in_bin = false;
    for line in manifest.lines().map(str::trim) {
        if line.starts_with('[') {
            in_bin = line == "[[bin]]";
        } else if in_bin
            && let Some(path) = line
                .strip_prefix("path")
                .map(str::trim_start)
                .and_then(|rest| rest.strip_prefix('='))
        {
            targets.push(path.trim().trim_matches('"').to_owned());
        }
    }
    let autobins = !manifest
        .lines()
        .any(|l| l.trim().replace(' ', "") == "autobins=false");
    if autobins && let Ok(entries) = std::fs::read_dir(root.join("src/bin")) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if path.extension().is_some_and(|e| e == "rs") {
                targets.push(format!("src/bin/{name}"));
            } else if path.join("main.rs").is_file() {
                targets.push(format!("src/bin/{name}/main.rs"));
            }
        }
    }
    targets.sort();
    targets.dedup();
    let mut roots: Vec<String> = ROOTS.iter().map(|r| (*r).to_owned()).collect();
    roots.sort();
    assert_eq!(roots, targets, "ROOTS must list every Cargo target");
}
