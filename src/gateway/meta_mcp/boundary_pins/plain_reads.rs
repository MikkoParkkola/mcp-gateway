// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every plain file read in production code, by (file, fn, callee, count),
//! each classified in `plain_reads.tsv`: gateway.yaml is read only through
//! the config guard, so a new plain read anywhere fails here until someone
//! says what it opens. The walk covers the lib, the binary and every other
//! root, skipping test-only code by cfg.
//!
//! A read is a call to a path ending in `fs::read`, `fs::read_to_string` or
//! `fs::copy` (std, tokio or async-std), `File::open` or `open_nonblocking`,
//! and every `.open(` method call: a method call carries no type, so each one
//! (an `OpenOptions` value inline or held, `File::options`, anything else
//! named `open`) is a counted site of its own. A name a `use` binds, bare,
//! renamed or through a module another `use` bound, is resolved first. The
//! walk fails outright on a `use` it cannot resolve: an `fs` glob, or one
//! name bound to two different paths in one file where one leads under `fs`.
//! Not seen: a read through a helper of another name (those helpers are rows
//! themselves where they read) and reads inside macro token streams.
//!
//! Regenerating the table is a reviewed diff, never a silent refresh: run
//! this test, copy the printed table, and classify every new row.

use std::collections::BTreeMap;
use std::path::Path;

use super::packaged::crate_root;
use super::scan::{Place, Sink, walk};

const ROOTS: [&str; 3] = ["src/lib.rs", "src/main.rs", "src/bin/provenance-eval.rs"];

/// What a plain read site opens.
const CLASSES: [&str; 6] = [
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
    // Opens to create, write or append, never to read.
    "write-only",
];

/// Known gaps, each closed by deleting its slug once its last row flips.
const PENDING: [&str; 0] = [];

#[derive(Default)]
struct Found {
    /// Every call by path: (file, fn, path segments as written).
    calls: Vec<(String, String, Vec<String>)>,
    /// Every `.open(` method call: (file, fn). A method call has no type, so
    /// each one is a site, whatever it opens.
    opens: Vec<(String, String)>,
    /// Per file, every name a `use` binds and the path it was written with.
    uses: BTreeMap<String, Vec<(String, Vec<String>)>>,
    /// `use` globs, as written: (file, path).
    globs: Vec<(String, Vec<String>)>,
}

/// The plain read `segments` names, if it is one.
fn read_callee(segments: &[String]) -> Option<String> {
    let last = segments.last()?.as_str();
    let owner = segments.len().checked_sub(2).map(|i| segments[i].as_str());
    match (owner, last) {
        (Some("fs"), "read" | "read_to_string" | "copy") | (Some("File"), "open") => {
            Some(format!("{}::{last}", owner.unwrap_or_default()))
        }
        (_, "open_nonblocking") => Some("open_nonblocking".to_owned()),
        _ => None,
    }
}

/// Whether `path` is the `fs` module of std, tokio or async-std.
fn is_fs(path: &[String]) -> bool {
    matches!(path, [krate, fs] if fs == "fs" && matches!(krate.as_str(), "std" | "tokio" | "async_std"))
}

/// Each name `tree` binds: (the full path, the local name), or `None` for a
/// glob over the path.
fn bindings(
    tree: &syn::UseTree,
    prefix: &mut Vec<String>,
    out: &mut Vec<(Vec<String>, Option<String>)>,
) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            bindings(&path.tree, prefix, out);
            prefix.pop();
        }
        syn::UseTree::Name(name) if name.ident == "self" => {
            out.push((prefix.clone(), prefix.last().cloned()));
        }
        syn::UseTree::Name(name) => {
            let mut full = prefix.clone();
            full.push(name.ident.to_string());
            out.push((full, Some(name.ident.to_string())));
        }
        syn::UseTree::Rename(rename) => {
            let mut full = prefix.clone();
            if rename.ident != "self" {
                full.push(rename.ident.to_string());
            }
            out.push((full, Some(rename.rename.to_string())));
        }
        syn::UseTree::Glob(_) => out.push((prefix.clone(), None)),
        syn::UseTree::Group(group) => {
            for tree in &group.items {
                bindings(tree, prefix, out);
            }
        }
    }
}

fn func_of(at: &Place) -> String {
    at.func.clone().unwrap_or_else(|| "<module>".to_owned())
}

impl Sink for Found {
    fn item(&mut self, at: &Place, item: &syn::Item) {
        let syn::Item::Use(item) = item else {
            return;
        };
        let mut found = Vec::new();
        bindings(&item.tree, &mut Vec::new(), &mut found);
        for (full, local) in found {
            match local {
                None => self.globs.push((at.file.clone(), full)),
                Some(local) if local != "_" => {
                    self.uses
                        .entry(at.file.clone())
                        .or_default()
                        .push((local, full));
                }
                Some(_) => {}
            }
        }
    }

    fn expr(&mut self, at: &Place, expr: &syn::Expr) {
        match expr {
            syn::Expr::MethodCall(call) if call.method == "open" => {
                self.opens.push((at.file.clone(), func_of(at)));
            }
            syn::Expr::Call(call) => {
                if let syn::Expr::Path(path) = &*call.func {
                    let segments = path.path.segments.iter().map(|s| s.ident.to_string());
                    self.calls
                        .push((at.file.clone(), func_of(at), segments.collect()));
                }
            }
            _ => {}
        }
    }
}

/// `path` with a leading name a `use` in the same file bound replaced by
/// what it stands for, until it starts at a crate; `None` when it does not
/// lead under `fs`.
fn resolved_fs(path: &[String], bound: &BTreeMap<String, Vec<String>>) -> Option<Vec<String>> {
    let mut path = path.to_vec();
    // Each step replaces the first segment; a cycle cannot outlast the names.
    for _ in 0..=bound.len() {
        if path.len() >= 2 && is_fs(&path[..2]) {
            let mut fs = vec!["fs".to_owned()];
            fs.extend(path[2..].iter().cloned());
            return Some(fs);
        }
        let first = path.first()?;
        let target = bound.get(first)?;
        path = target.iter().chain(&path[1..]).cloned().collect();
    }
    None
}

/// Every read row, by `file\tfn\tcallee` and its count. Panics, failing the
/// pin outright, on a `use` the walk cannot resolve: an `fs` glob, or a name
/// bound to two different paths in one file where one of them is under
/// `fs` (the later binding would hide reads through the earlier one).
fn found_in(root: &Path, roots: &[&str]) -> Vec<String> {
    let mut found = Found::default();
    walk(root, roots, &mut found).expect("the crate walks");
    let mut unresolved = Vec::new();
    // Per file: each bound name and what it was first written as; a later
    // binding of the same name to another path is checked once all are in.
    let mut written: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();
    let mut rebound = Vec::new();
    for (file, uses) in &found.uses {
        let names = written.entry(file.clone()).or_default();
        for (local, full) in uses {
            match names.get(local) {
                Some(seen) if seen != full => rebound.push((file, local, seen.clone(), full)),
                Some(_) => {}
                None => {
                    names.insert(local.clone(), full.clone());
                }
            }
        }
    }
    for (file, local, seen, full) in rebound {
        let names = &written[file];
        let (first, later) = (resolved_fs(&seen, names), resolved_fs(full, names));
        if first != later && (first.is_some() || later.is_some()) {
            unresolved.push(format!(
                "{file}: `{local}` is bound to both {} and {}",
                seen.join("::"),
                full.join("::")
            ));
        }
    }
    // Only names that lead under `fs` once resolved stand for an `fs` path.
    let fs_names: BTreeMap<String, BTreeMap<String, Vec<String>>> = written
        .iter()
        .map(|(file, names)| {
            let resolved = names
                .iter()
                .filter_map(|(local, full)| Some((local.clone(), resolved_fs(full, names)?)))
                .collect();
            (file.clone(), resolved)
        })
        .collect();
    for (file, path) in &found.globs {
        let names = written.get(file).cloned().unwrap_or_default();
        if resolved_fs(path, &names).is_some() {
            unresolved.push(format!(
                "{file}: `use {}::*` binds names the walk cannot see; import each one",
                path.join("::")
            ));
        }
    }
    assert!(
        unresolved.is_empty(),
        "fs imports the walk cannot resolve: {unresolved:#?}"
    );
    let mut reads: BTreeMap<String, usize> = BTreeMap::new();
    let empty = BTreeMap::new();
    for (file, func, segments) in &found.calls {
        let names = fs_names.get(file).unwrap_or(&empty);
        let resolved = match segments.first().and_then(|first| names.get(first)) {
            Some(target) => target.iter().chain(&segments[1..]).cloned().collect(),
            None => segments.clone(),
        };
        if let Some(callee) = read_callee(&resolved) {
            *reads
                .entry(format!("{file}\t{func}\t{callee}"))
                .or_default() += 1;
        }
    }
    for (file, func) in &found.opens {
        *reads.entry(format!("{file}\t{func}\t.open")).or_default() += 1;
    }
    reads.iter().map(|(key, n)| format!("{key}\t{n}")).collect()
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

/// Every other way to open or copy a file is seen too: each `.open(` call
/// (an `OpenOptions` value inline or held in a binding, `File::options`),
/// `fs::copy`, a read imported by its bare name, one imported under another
/// name, and one called through a renamed `fs` module or a renamed `File`.
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
            "src/lib.rs\theld\t.open\t2",
            "src/lib.rs\tinline\t.open\t1",
            "src/lib.rs\trenamed\tFile::open\t1",
            "src/lib.rs\trenamed\tfs::read\t2",
        ]
    );
}

/// A second `.open(` on one `OpenOptions` value is a site of its own: the
/// count moves, so the new open cannot inherit the first one's row.
#[test]
fn each_open_on_one_options_value_is_counted() {
    let rows = fixture_rows(
        "pub fn twice(p: &std::path::Path) {\n    \
         let mut options = std::fs::OpenOptions::new();\n    options.read(true);\n    \
         let _ = options.open(p);\n    let _ = options.open(p);\n}\n",
    );

    assert_eq!(rows, ["src/lib.rs\ttwice\t.open\t2"]);
}

/// A read imported through a module a `use` bound first is resolved:
/// `use std::fs; use fs::read_to_string as slurp;`.
#[test]
fn a_chained_fs_import_is_resolved() {
    let rows = fixture_rows(
        "use std::fs;\nuse fs::read_to_string as slurp;\n\
         pub fn chained(p: &std::path::Path) {\n    let _ = slurp(p);\n}\n",
    );

    assert_eq!(rows, ["src/lib.rs\tchained\tfs::read_to_string\t1"]);
}

/// Whether walking a fixture crate holding `source` fails outright.
fn the_walk_refuses(source: &str) -> bool {
    let source = source.to_owned();
    std::panic::catch_unwind(move || fixture_rows(&source)).is_err()
}

/// An `fs` glob import binds names the walk cannot see, so the pin fails
/// outright: explicit imports are required, and no glob can be classified.
#[test]
fn an_fs_glob_import_fails_the_walk() {
    assert!(the_walk_refuses(
        "use std::fs::*;\npub fn hidden(p: &std::path::Path) {\n    let _ = read(p);\n}\n",
    ));
}

/// One name bound to two different things in one file (here `File` and
/// `OpenOptions` in two functions) would let the later binding hide reads
/// through the earlier one, so the pin fails outright.
#[test]
fn an_alias_bound_twice_in_one_file_fails_the_walk() {
    assert!(the_walk_refuses(
        "pub fn a(p: &std::path::Path) {\n    use std::fs::File as H;\n    \
         let _ = H::open(p);\n}\n\
         pub fn b(p: &std::path::Path) {\n    use std::fs::OpenOptions as H;\n    \
         let _ = H::new().read(true).open(p);\n}\n",
    ));
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
