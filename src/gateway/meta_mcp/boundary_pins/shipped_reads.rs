// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8481 PACKED.2: no test reads a repository file the published crate does
//! not ship, except through the packaged-aware helper. The post-merge packaged
//! suite runs the tests from the unpacked crate; a test that joins a literal
//! path onto the crate root and reads it panics there (the post-merge run of
//! #3931 did), while the PR-time packaged job only compiles. This guard moves
//! that failure to the pull request.
//!
//! The rule, per file under `src/`, `tests/` and `benches/`: a file that
//! mentions the crate root (`CARGO_MANIFEST_DIR`) and does not go through the
//! helper (`repo_file` / `read_or_skip`) may not contain a string literal that
//! names an existing file, or an existing path with a directory part, which
//! `Cargo.toml` `include` leaves out. A literal is not proof of a read, and a
//! path built at run time is not seen; both limits are accepted, because the
//! failure this guards is the plain `root.join("literal")` read.

use std::path::{Path, PathBuf};

use syn::visit::Visit;

use super::packaged::{crate_root, is_packaged_crate};

/// The quoted entries of the `include = [ ... ]` array of a `Cargo.toml`.
fn include_patterns(cargo_toml: &str) -> Vec<String> {
    let mut patterns = Vec::new();
    let mut inside = false;
    for line in cargo_toml.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if !inside {
            inside = line.starts_with("include") && line.ends_with('[');
            continue;
        }
        if line == "]" {
            break;
        }
        patterns.extend(
            line.split('"')
                .skip(1)
                .step_by(2)
                .map(str::to_owned)
                .collect::<Vec<_>>(),
        );
    }
    patterns
}

/// Whether the published crate holds `rel` (a file, or a directory with
/// something shipped under it).
fn shipped(patterns: &[String], rel: &str) -> bool {
    let dir_prefix = format!("{}/", rel.trim_end_matches('/'));
    patterns.iter().any(|g| {
        g == rel
            || glob::Pattern::new(g).is_ok_and(|p| p.matches(rel))
            || g.strip_suffix("/**")
                .is_some_and(|d| rel == d || rel.starts_with(&format!("{d}/")))
            || g.starts_with(&dir_prefix)
    })
}

#[derive(Default)]
struct Literals(Vec<String>);

impl<'ast> Visit<'ast> for Literals {
    fn visit_lit_str(&mut self, lit: &'ast syn::LitStr) {
        self.0.push(lit.value());
    }
}

/// The unshipped repo paths a source file names directly.
fn offenders(root: &Path, patterns: &[String], source: &str) -> Vec<String> {
    let reads_the_root = source.contains("CARGO_MANIFEST_DIR");
    let packaged_aware = source.contains("repo_file") || source.contains("read_or_skip");
    if !reads_the_root || packaged_aware {
        return Vec::new();
    }
    let Ok(parsed) = syn::parse_file(source) else {
        return vec!["<unparsable source>".to_owned()];
    };
    let mut literals = Literals::default();
    literals.visit_file(&parsed);
    let mut found: Vec<String> = literals
        .0
        .into_iter()
        .filter(|lit| {
            lit.len() >= 3
                && !lit.starts_with('/')
                && lit
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_./-".contains(c))
        })
        .map(|lit| lit.trim_end_matches('/').to_owned())
        .filter(|lit| {
            let path = root.join(lit);
            path.is_file() || (lit.contains('/') && path.exists())
        })
        .filter(|lit| !shipped(patterns, lit))
        .collect();
    found.sort();
    found.dedup();
    found
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// PACKED.2 on the real tree. Checkout-only: the unpacked crate has the
/// sources but not the repo files whose existence the rule asks about.
#[test]
fn packed_2_no_test_reads_an_unshipped_repo_file_directly() {
    if is_packaged_crate() {
        eprintln!("skipped: the rule needs the repository files");
        return;
    }
    let root = crate_root();
    let cargo_toml = std::fs::read_to_string(root.join("Cargo.toml")).expect("Cargo.toml");
    let patterns = include_patterns(&cargo_toml);
    assert!(
        patterns.len() > 20,
        "the include array was not read ({} entries)",
        patterns.len()
    );
    let mut files = Vec::new();
    for dir in ["src", "tests", "benches"] {
        rust_files(&root.join(dir), &mut files);
    }
    assert!(files.len() > 100, "the walk saw {} files", files.len());
    let mut violations = Vec::new();
    for file in &files {
        let source = std::fs::read_to_string(file).expect("source");
        for lit in offenders(root, &patterns, &source) {
            violations.push(format!(
                "{}: {lit}",
                file.strip_prefix(root).unwrap().display()
            ));
        }
    }
    assert!(
        violations.is_empty(),
        "these files read a repo path the published crate does not ship; read it \
         through boundary_pins::packaged::repo_file, or ship the file in Cargo.toml \
         `include`: {violations:#?}"
    );
}

/// A scratch crate root with `shipped.txt` (in the include list),
/// `tools/run.sh` and `top.sh` (not in it).
fn scratch() -> (tempfile::TempDir, Vec<String>) {
    let root = tempfile::tempdir().expect("tempdir");
    for rel in [
        "shipped.txt",
        "tools/run.sh",
        "top.sh",
        "docs/a.md",
        "docs/b.md",
    ] {
        let path = root.path().join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).expect("mkdir");
        std::fs::write(path, "x").expect("write");
    }
    let toml = "[package]\ninclude = [\n    \"shipped.txt\", # a comment\n    \"docs/a.md\",\n]\n";
    (root, include_patterns(toml))
}

fn reading(lit: &str) -> String {
    format!(
        "fn f() {{ let _ = std::path::Path::new(env!(\"CARGO_MANIFEST_DIR\")).join(\"{lit}\"); }}"
    )
}

#[test]
fn the_include_array_is_parsed() {
    let (_root, patterns) = scratch();
    assert_eq!(patterns, ["shipped.txt", "docs/a.md"]);
}

/// Falsifier: a plain read of an unshipped file is flagged, a file and a path
/// with a directory part alike.
#[test]
fn an_unshipped_file_read_directly_is_flagged() {
    let (root, patterns) = scratch();
    for lit in ["tools/run.sh", "top.sh"] {
        assert_eq!(
            offenders(root.path(), &patterns, &reading(lit)),
            [lit.to_owned()],
            "{lit}"
        );
    }
}

#[test]
fn the_packaged_aware_helper_exempts_a_file() {
    let (root, patterns) = scratch();
    for helper in ["repo_file", "read_or_skip"] {
        let source = format!(
            "{}\nfn g() {{ {helper}(\"tools/run.sh\"); }}",
            reading("tools/run.sh")
        );
        assert!(
            offenders(root.path(), &patterns, &source).is_empty(),
            "{helper}"
        );
    }
}

#[test]
fn shipped_paths_and_non_paths_are_not_flagged() {
    let (root, patterns) = scratch();
    // a shipped file, a directory with a shipped file under it, a name that is
    // not a path, and a path that does not exist
    for lit in ["shipped.txt", "docs", "tools", "no/such/file.txt", "probe"] {
        assert!(
            offenders(root.path(), &patterns, &reading(lit)).is_empty(),
            "{lit}"
        );
    }
}

#[test]
fn a_file_that_never_reads_the_crate_root_is_not_scanned() {
    let (root, patterns) = scratch();
    let source = "fn f() { let _ = \"tools/run.sh\"; }";
    assert!(offenders(root.path(), &patterns, source).is_empty());
}

#[test]
fn glob_and_directory_entries_count_as_shipped() {
    let patterns = vec!["src/**".to_owned(), "upgrading.d/*.md".to_owned()];
    assert!(shipped(&patterns, "src/gateway/mod.rs"));
    assert!(shipped(&patterns, "src"));
    assert!(shipped(&patterns, "upgrading.d/1.md"));
    assert!(shipped(&patterns, "upgrading.d"));
    assert!(!shipped(&patterns, "scripts/dev/pre-push.sh"));
}
