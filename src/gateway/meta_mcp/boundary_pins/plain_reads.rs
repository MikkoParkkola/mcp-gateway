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
//! imported by its bare name, `OpenOptions`, and a read through a helper of
//! another name; those helpers are rows themselves where they read.
//!
//! Regenerating the table is a reviewed diff, never a silent refresh: run
//! this test, copy the printed table, and classify every new row.

use std::collections::BTreeMap;
use std::path::Path;

use super::packaged::crate_root;
use super::scan::{Place, Sink, walk};

const ROOTS: [&str; 3] = ["src/lib.rs", "src/main.rs", "src/bin/provenance-eval.rs"];

/// What a plain read site opens.
const CLASSES: [&str; 3] = [
    // The config guard's own open: the one place gateway.yaml is opened to
    // be read.
    "guard",
    // Reads a file that is not gateway.yaml; the reason names it.
    "not-config",
    // Opens a path without reading its bytes (a directory to sync, a probe).
    "no-content",
];

/// Known gaps, each closed by deleting its slug once its last row flips.
const PENDING: [&str; 1] = ["doctor-config-reread"];

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
