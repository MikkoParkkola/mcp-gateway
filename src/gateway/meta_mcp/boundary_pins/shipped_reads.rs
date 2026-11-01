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
//! reaches the crate root (`CARGO_MANIFEST_DIR`, a crate-root helper call, or
//! an `include_*!`) and does not go through the helper (`repo_file` /
//! `read_or_skip`) may not contain a string literal that names an existing
//! file, or an existing path with a directory part, which `Cargo.toml`
//! `include` leaves out. A literal is not proof of a read, and a path built
//! at run time is not seen; both limits are accepted, because the failure
//! this guards is the plain `root.join("literal")` read.
//!
//! Limits: bindings match by name with no scope analysis (a shadowed binding
//! resolves to the first one); only `include_str!`, `include_bytes!` and
//! `concat!` macro bodies are seen; `include_*!` paths resolve against the
//! source file's directory.

use std::path::{Path, PathBuf};

use syn::visit::Visit;

use super::packaged::{crate_root, is_packaged_crate};

#[path = "shipped_reads_scan.rs"]
mod scan_impl;

use scan_impl::Literals;

/// The `[package]` table of a `Cargo.toml` (up to the next table header), or
/// the whole text when there is no `[package]` header.
fn package_table(cargo_toml: &str) -> &str {
    let mut start = 0;
    let mut found = false;
    let mut offset = 0;
    for line in cargo_toml.split_inclusive('\n') {
        let trimmed = line.trim();
        if found && trimmed.starts_with('[') {
            return &cargo_toml[start..offset];
        }
        if trimmed == "[package]" {
            found = true;
            start = offset + line.len();
        }
        offset += line.len();
    }
    if found {
        &cargo_toml[start..]
    } else {
        cargo_toml
    }
}

/// The text after the `[` opening the `include` array, if `region` holds an
/// `include = [` key. The `[` may follow the `=` on a later line, with only
/// whitespace and comments between.
fn find_include_array(region: &str) -> Option<&str> {
    let mut offset = 0;
    for line in region.split_inclusive('\n') {
        let line_start = offset;
        offset += line.len();
        // The key starts the line (modulo whitespace); anything after `#` is
        // a comment, so a commented-out key never matches.
        let code = line.split('#').next().unwrap_or("");
        let key = code.trim_start();
        let Some(rest) = key.strip_prefix("include") else {
            continue;
        };
        // `includes` is another key: the name ends at a word boundary.
        if rest
            .chars()
            .next()
            .is_some_and(|c| c.is_alphanumeric() || c == '_')
        {
            continue;
        }
        let Some(eq) = rest.find('=') else {
            continue;
        };
        let eq_at = line_start + (code.len() - key.len()) + "include".len() + eq;
        let mut after = &region[eq_at + 1..];
        loop {
            let trimmed = after.trim_start();
            if let Some(comment) = trimmed.strip_prefix('#') {
                after = comment.split_once('\n').map_or("", |(_, rest)| rest);
                continue;
            }
            return trimmed.strip_prefix('[');
        }
    }
    None
}

/// The quoted entries of the `include = [ ... ]` array in the `[package]`
/// table of a `Cargo.toml`. A character lexer: the array may sit on one line
/// or span lines; outside quotes `#` starts a comment (skipped to the end of
/// the line) and the first unquoted `]` ends the array, so a `]` or `#`
/// inside quotes is kept. Inside quotes `\` escapes the next character.
fn include_patterns(cargo_toml: &str) -> Vec<String> {
    let region = package_table(cargo_toml);
    let Some(array) = find_include_array(region) else {
        return Vec::new();
    };
    let mut patterns = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = array.chars();
    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '\\' {
                if let Some(escaped) = chars.next() {
                    current.push(escaped);
                }
            } else if c == '"' {
                in_quotes = false;
                patterns.push(std::mem::take(&mut current));
            } else {
                current.push(c);
            }
        } else if c == '"' {
            in_quotes = true;
        } else if c == '#' {
            for skipped in chars.by_ref() {
                if skipped == '\n' {
                    break;
                }
            }
        } else if c == ']' {
            break;
        }
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

/// The helper module is the sanctioned reader: it names the pinned files in
/// its own vacuity guard, which asks whether they exist.
const HELPER_FILE: &str = "src/gateway/meta_mcp/boundary_pins/packaged.rs";

/// Untracked or tool-owned directories: a literal starting there names no
/// repository file.
const NOT_REPO: [&str; 3] = ["target", ".git", ".worktrees"];

/// The crate-root helper names whose call triggers the scan (the names in
/// use, found by grep): `crate_root()`, `repo_root()` and
/// `golden::repo_root()`.
const ROOT_HELPERS: [&str; 2] = ["crate_root", "repo_root"];

/// Whether `source` calls a [`ROOT_HELPERS`] name: the name as a whole word
/// (the preceding character is not alphanumeric or `_`, so
/// `golden::repo_root(` counts and `my_crate_root(` does not) followed by
/// `(`. Text-level: a definition (`fn crate_root()`) triggers too, which only
/// scans one more file.
fn calls_root_helper(source: &str) -> bool {
    for helper in ROOT_HELPERS {
        let mut start = 0;
        while let Some(found) = source[start..].find(helper) {
            let at = start + found;
            let word_start = !source[..at]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || c == '_');
            if word_start && source[at + helper.len()..].starts_with('(') {
                return true;
            }
            start = at + 1;
        }
    }
    false
}

/// SCAN.3: the file holding the one reviewed `repo_root` read.
const SCAN3_FILE: &str = "tests/mik_8425_yaml_baseline_trees.rs";

/// Whether `lit` is the reviewed SCAN.3 read: the golden test names one
/// unshipped file through `golden::repo_root()`. The golden harness tolerates
/// absent roots (a gone file is a skipped row, a walk over a missing
/// directory yields nothing), and the golden holds 155 shipped rows before
/// `examples/` and `tests/fixtures/` are counted (150 needed), so the test
/// passes from the unpacked crate (confirmed 2026-10-22: built from
/// `cargo package` at 0395b7fc3 with `smithery.yaml` absent, 2 passed).
/// Path-scoped: only this literal in this file is exempt, and it
/// is spelled in parts so this file does not flag itself for naming it.
fn is_reviewed_scan3(rel_norm: &str, lit: &str) -> bool {
    rel_norm == SCAN3_FILE && lit.strip_suffix(".yaml") == Some("smithery")
}

/// The unshipped repo paths a source file names directly (`rel_file` is its
/// path from the crate root).
fn offenders(root: &Path, patterns: &[String], rel_file: &str, source: &str) -> Vec<String> {
    // Windows hands in backslashes; the exemptions name the slash form.
    let rel_norm = rel_file.replace('\\', "/");
    let triggered = source.contains("CARGO_MANIFEST_DIR")
        || source.contains("include_str!")
        || source.contains("include_bytes!")
        || calls_root_helper(source);
    if rel_norm == HELPER_FILE || !triggered {
        return Vec::new();
    }
    let Ok(parsed) = syn::parse_file(source) else {
        return vec!["<unparsable source>".to_owned()];
    };
    let mut literals = Literals {
        dir: Path::new(rel_file)
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default(),
        ..Default::default()
    };
    literals.visit_file(&parsed);
    // A binding's literal is covered only when every use of its name is a
    // direct helper argument; a binding with no uses stays collected.
    let mut exempt = Vec::new();
    for (name, lit) in &literals.bindings {
        let used = literals.uses.get(name).copied().unwrap_or(0);
        let through_helper = literals.helper_uses.get(name).copied().unwrap_or(0);
        if used > 0 && used == through_helper {
            exempt.push(lit.clone());
        }
    }
    literals.covered.extend(exempt);
    // The backslash form names the slash path (`tools\run.sh` is read as
    // `tools/run.sh`), so every collected literal is normalised first.
    let includes: Vec<String> = literals
        .includes
        .iter()
        .map(|lit| lit.replace('\\', "/"))
        .collect();
    let all: Vec<String> = literals
        .all
        .iter()
        .chain(&literals.includes)
        .map(|lit| lit.replace('\\', "/"))
        .collect();
    let covered: Vec<String> = literals
        .covered
        .iter()
        .map(|lit| lit.replace('\\', "/"))
        .collect();
    let norm = |l: &str| l.trim_end_matches('/').to_owned();
    let direct = |lit: &str| {
        let used = all.iter().filter(|l| norm(l) == lit).count();
        let through_helper = covered.iter().filter(|l| norm(l) == lit).count();
        used > through_helper || includes.iter().any(|l| norm(l) == lit)
    };
    let mut found: Vec<String> = all
        .iter()
        .filter(|lit| {
            lit.len() >= 3
                && !lit.starts_with('/')
                && lit
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_./-".contains(c))
        })
        .map(|lit| lit.trim_end_matches('/').to_owned())
        .filter(|lit| !NOT_REPO.contains(&lit.split('/').next().unwrap_or("")))
        .filter(|lit| {
            let path = root.join(lit);
            path.is_file() || (lit.contains('/') && path.exists())
        })
        .filter(|lit| !shipped(patterns, lit))
        .filter(|lit| !is_reviewed_scan3(&rel_norm, lit))
        .filter(|lit| direct(lit))
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
        let rel = file
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        for lit in offenders(root, &patterns, &rel, &source) {
            violations.push(format!("{rel}: {lit}"));
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
            offenders(root.path(), &patterns, FILE, &reading(lit)),
            [lit.to_owned()],
            "{lit}"
        );
    }
}

/// A scratch source file's path.
const FILE: &str = "tests/scratch.rs";

/// A literal passed to the helper is covered.
#[test]
fn a_literal_read_through_the_helper_is_exempt() {
    let (root, patterns) = scratch();
    for helper in ["repo_file", "read_or_skip"] {
        let source = format!(
            "fn f() {{ let _ = env!(\"CARGO_MANIFEST_DIR\"); {helper}(\"tools/run.sh\"); }}"
        );
        assert!(
            offenders(root.path(), &patterns, FILE, &source).is_empty(),
            "{helper}"
        );
    }
}

/// Falsifier: the helper in a file exempts only the literals it is called
/// with; a direct read of the same path, or of another one, is still flagged.
#[test]
fn the_helper_does_not_exempt_a_whole_file() {
    let (root, patterns) = scratch();
    let same = format!(
        "{}\nfn g() {{ repo_file(\"tools/run.sh\"); }}",
        reading("tools/run.sh")
    );
    assert_eq!(
        offenders(root.path(), &patterns, FILE, &same),
        ["tools/run.sh"],
        "the same path, read directly as well"
    );
    let other = format!(
        "{}\nfn g() {{ repo_file(\"top.sh\"); }}",
        reading("tools/run.sh")
    );
    assert_eq!(
        offenders(root.path(), &patterns, FILE, &other),
        ["tools/run.sh"],
        "another path"
    );
}

/// The helper module is the sanctioned reader.
#[test]
fn the_helper_module_is_exempt_by_path() {
    let (root, patterns) = scratch();
    assert!(
        offenders(
            root.path(),
            &patterns,
            HELPER_FILE,
            &reading("tools/run.sh")
        )
        .is_empty()
    );
}

/// Build and VCS directories are not repository files.
/// The same exemption on a Windows-form path (the seat's catch: `strip_prefix`
/// there yields backslashes, and the guard would flag the helper module).
#[test]
fn the_helper_module_exemption_holds_for_a_windows_path() {
    let (root, patterns) = scratch();
    let windows = HELPER_FILE.replace('/', "\\");
    assert_ne!(windows, HELPER_FILE);
    assert!(offenders(root.path(), &patterns, &windows, &reading("tools/run.sh")).is_empty());
}

#[test]
fn a_build_directory_literal_is_not_flagged() {
    let (root, patterns) = scratch();
    std::fs::create_dir_all(root.path().join("target/debug")).expect("mkdir");
    for lit in ["target/debug", ".git/config", ".worktrees/x/y"] {
        std::fs::create_dir_all(root.path().join(lit).parent().unwrap()).expect("mkdir");
        std::fs::write(root.path().join(lit), "x").ok();
        assert!(
            offenders(root.path(), &patterns, FILE, &reading(lit)).is_empty(),
            "{lit}"
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
            offenders(root.path(), &patterns, FILE, &reading(lit)).is_empty(),
            "{lit}"
        );
    }
}

#[test]
fn a_file_that_never_reads_the_crate_root_is_not_scanned() {
    let (root, patterns) = scratch();
    let source = "fn f() { let _ = \"tools/run.sh\"; }";
    assert!(offenders(root.path(), &patterns, FILE, source).is_empty());
}

#[test]
fn glob_and_directory_entries_count_as_shipped() {
    let patterns = vec!["src/**".to_owned(), "upgrading.d/*.md".to_owned()];
    assert!(shipped(&patterns, "src/gateway/mod.rs"));
    assert!(shipped(&patterns, "src"));
    assert!(shipped(&patterns, "upgrading.d/1.md"));
    assert!(shipped(&patterns, "upgrading.d"));
    assert!(!shipped(&patterns, "scripts/never/shipped.sh"));
}

/// The live `Cargo.toml` ships pin-table fragments, so the packaged suite
/// reads every fragment a checkout reads.
#[test]
fn the_package_ships_fragment_files() {
    let cargo_toml = std::fs::read_to_string(crate_root().join("Cargo.toml")).expect("Cargo.toml");
    let patterns = include_patterns(&cargo_toml);
    assert!(shipped(
        &patterns,
        "src/gateway/meta_mcp/boundary_pins/delivery_refusals.d/1.tsv"
    ));
}

/// MIK-8501.SCAN.1: a `crate_root()` call triggers the scan without `CARGO_MANIFEST_DIR`.
#[test]
fn scan1_a_crate_root_helper_call_triggers_the_scan() {
    let (root, patterns) = scratch();
    let source = r#"fn f() { let _ = crate_root().join("tools/run.sh"); }"#;
    assert_eq!(
        offenders(root.path(), &patterns, FILE, source),
        ["tools/run.sh".to_owned()]
    );
}

/// MIK-8501.SCAN.1: a `golden::repo_root()` call triggers the scan.
#[test]
fn scan1_a_golden_repo_root_call_triggers_the_scan() {
    let (root, patterns) = scratch();
    let source = r#"fn f() { let _ = golden::repo_root().join("top.sh"); }"#;
    assert_eq!(
        offenders(root.path(), &patterns, FILE, source),
        ["top.sh".to_owned()]
    );
}

/// MIK-8501.SCAN.1: a bare `repo_root()` call triggers the scan.
#[test]
fn scan1_a_bare_repo_root_call_triggers_the_scan() {
    let (root, patterns) = scratch();
    let source = r#"fn f() { let _ = repo_root().join("top.sh"); }"#;
    assert_eq!(
        offenders(root.path(), &patterns, FILE, source),
        ["top.sh".to_owned()]
    );
}

/// MIK-8501.SCAN.1: lookalike names do not trigger the scan.
#[test]
fn scan1_lookalike_names_do_not_trigger() {
    let (root, patterns) = scratch();
    for source in [
        r#"fn f() { let _ = my_crate_root().join("top.sh"); }"#,
        r#"fn f() { let crate_root = 1; let _ = ("top.sh", crate_root); }"#,
        r#"fn f() { let _ = "top.sh"; }"#,
    ] {
        assert!(
            offenders(root.path(), &patterns, FILE, source).is_empty(),
            "{source}"
        );
    }
}

/// MIK-8501.SCAN.2: a const used only through the helper is exempt.
#[test]
fn scan2_a_const_used_only_through_the_helper_is_exempt() {
    let (root, patterns) = scratch();
    let source = r#"const P: &str = "tools/run.sh"; fn f() { let _ = env!("CARGO_MANIFEST_DIR"); repo_file(P); }"#;
    assert!(offenders(root.path(), &patterns, FILE, source).is_empty());
}

/// MIK-8501.SCAN.2: a let binding used only through the helper is exempt.
#[test]
fn scan2_a_let_used_only_through_the_helper_is_exempt() {
    let (root, patterns) = scratch();
    let source = r#"fn f() { let _ = env!("CARGO_MANIFEST_DIR"); let p = "tools/run.sh"; read_or_skip(root, p, false); }"#;
    assert!(offenders(root.path(), &patterns, FILE, source).is_empty());
}

/// MIK-8501.SCAN.2: a const read directly is flagged.
#[test]
fn scan2_a_const_read_directly_is_flagged() {
    let (root, patterns) = scratch();
    let source = r#"const P: &str = "tools/run.sh"; fn f() { let _ = env!("CARGO_MANIFEST_DIR"); let _ = crate_root().join(P); }"#;
    assert_eq!(
        offenders(root.path(), &patterns, FILE, source),
        ["tools/run.sh".to_owned()]
    );
}

/// MIK-8501.SCAN.2: a let binding read directly is flagged.
#[test]
fn scan2_a_let_read_directly_is_flagged() {
    let (root, patterns) = scratch();
    let source = r#"fn f() { let _ = env!("CARGO_MANIFEST_DIR"); let p = "tools/run.sh"; let _ = crate_root().join(p); }"#;
    assert_eq!(
        offenders(root.path(), &patterns, FILE, source),
        ["tools/run.sh".to_owned()]
    );
}

/// MIK-8501.SCAN.2: a binding used by the helper AND read directly is flagged (falsifier of the exemption).
#[test]
fn scan2_a_binding_also_read_directly_is_flagged() {
    let (root, patterns) = scratch();
    let source = r#"const P: &str = "tools/run.sh"; fn f() { let _ = env!("CARGO_MANIFEST_DIR"); repo_file(P); let _ = crate_root().join(P); }"#;
    assert_eq!(
        offenders(root.path(), &patterns, FILE, source),
        ["tools/run.sh".to_owned()]
    );
}

/// MIK-8501.SCAN.4: `include_str!` alone triggers, resolved from the file's directory.
#[test]
fn scan4_include_str_alone_triggers_and_resolves_from_the_file() {
    let (root, patterns) = scratch();
    std::fs::create_dir_all(root.path().join("tests")).expect("mkdir tests");
    let source = r#"const T: &str = include_str!("../tools/run.sh");"#;
    assert_eq!(
        offenders(root.path(), &patterns, FILE, source),
        ["tools/run.sh".to_owned()]
    );
}

/// MIK-8501.SCAN.4: `include_bytes!` alone triggers the scan.
#[test]
fn scan4_include_bytes_alone_triggers() {
    let (root, patterns) = scratch();
    std::fs::create_dir_all(root.path().join("tests")).expect("mkdir tests");
    let source = r#"const T: &[u8] = include_bytes!("../top.sh");"#;
    assert_eq!(
        offenders(root.path(), &patterns, FILE, source),
        ["top.sh".to_owned()]
    );
}

/// MIK-8501.SCAN.4: a `concat!` literal is seen as one path.
#[test]
fn scan4_a_concat_literal_is_seen() {
    let (root, patterns) = scratch();
    let source = r#"fn f() { let _ = env!("CARGO_MANIFEST_DIR"); let _ = crate_root().join(concat!("tools/", "run.sh")); }"#;
    assert_eq!(
        offenders(root.path(), &patterns, FILE, source),
        ["tools/run.sh".to_owned()]
    );
}

/// MIK-8501.SCAN.4: a backslash literal is normalised to slashes.
#[test]
fn scan4_a_backslash_literal_is_seen() {
    let (root, patterns) = scratch();
    let source = r#"fn f() { let _ = env!("CARGO_MANIFEST_DIR"); let _ = crate_root().join("tools\\run.sh"); }"#;
    assert_eq!(
        offenders(root.path(), &patterns, FILE, source),
        ["tools/run.sh".to_owned()]
    );
}

/// MIK-8501.SCAN.2: a direct use placed before its `const` still counts.
#[test]
fn scan2_a_direct_use_before_the_const_is_flagged() {
    let (root, patterns) = scratch();
    let source = r#"fn f() { let _ = env!("CARGO_MANIFEST_DIR"); let _ = crate_root().join(P); } const P: &str = "tools/run.sh"; fn g() { repo_file(P); }"#;
    assert_eq!(
        offenders(root.path(), &patterns, FILE, source),
        ["tools/run.sh".to_owned()]
    );
}

/// MIK-8501.SCAN.2: a typed `let` used only through the helper is exempt.
#[test]
fn scan2_a_typed_let_used_only_through_the_helper_is_exempt() {
    let (root, patterns) = scratch();
    let source = r#"fn f() { let _ = env!("CARGO_MANIFEST_DIR"); let p: &str = "tools/run.sh"; read_or_skip(root, p, false); }"#;
    assert!(offenders(root.path(), &patterns, FILE, source).is_empty());
}

/// MIK-8501.SCAN.2: a qualified direct use (`self::P`) counts against the exemption.
#[test]
fn scan2_a_qualified_direct_use_is_flagged() {
    let (root, patterns) = scratch();
    let source = r#"const P: &str = "tools/run.sh"; fn f() { let _ = env!("CARGO_MANIFEST_DIR"); read_or_skip(root, P, true); let _ = crate_root().join(self::P); }"#;
    assert_eq!(
        offenders(root.path(), &patterns, FILE, source),
        ["tools/run.sh".to_owned()]
    );
}

/// MIK-8501.SCAN.4: an `include_str!` inside a helper argument is still a direct read.
#[test]
fn scan4_an_include_inside_a_helper_argument_is_flagged() {
    let (root, patterns) = scratch();
    std::fs::create_dir_all(root.path().join("tests")).expect("mkdir tests");
    let source = r#"fn f() { repo_file(include_str!("../tools/run.sh")); }"#;
    assert_eq!(
        offenders(root.path(), &patterns, FILE, source),
        ["tools/run.sh".to_owned()]
    );
}

/// MIK-8501.SCAN.4: a qualified, brace-delimited `std::include_bytes!` is seen.
#[test]
fn scan4_a_qualified_brace_include_is_seen() {
    let (root, patterns) = scratch();
    std::fs::create_dir_all(root.path().join("tests")).expect("mkdir tests");
    let source = r#"const T: &[u8] = std::include_bytes! {"../top.sh"};"#;
    assert_eq!(
        offenders(root.path(), &patterns, FILE, source),
        ["top.sh".to_owned()]
    );
}

/// MIK-8502.DRIFT.3: a one-line `include` array is parsed.
#[test]
fn drift3_a_one_line_include_is_parsed() {
    assert_eq!(
        include_patterns("[package]\ninclude = [\"shipped.txt\", \"docs/a.md\"]\n"),
        ["shipped.txt", "docs/a.md"]
    );
}

/// MIK-8502.DRIFT.3: comments on every line are ignored (green control; the base parser already passes it).
#[test]
fn drift3_comments_on_every_line_are_ignored() {
    assert_eq!(
        include_patterns(
            "[package]\ninclude = [ # open\n    \"a\", # one\n    \"b\" # two\n] # close\n"
        ),
        ["a", "b"]
    );
}

/// MIK-8502.DRIFT.3: a bracket inside quotes does not end the array.
#[test]
fn drift3_a_bracket_inside_quotes_is_kept() {
    assert_eq!(
        include_patterns("[package]\ninclude = [\"a]b\", \"c\"]\n"),
        ["a]b", "c"]
    );
}

/// MIK-8502.DRIFT.3: a hash inside quotes is kept.
#[test]
fn drift3_a_hash_inside_quotes_is_kept() {
    assert_eq!(
        include_patterns(
            "[package]\ninclude = [ # open\n    \"a#b\", # one\n    \"c\" # two\n] # close\n"
        ),
        ["a#b", "c"]
    );
}
