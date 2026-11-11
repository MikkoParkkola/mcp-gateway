// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! SCH.3: no `mutant!` call reaches the release line. The scan is lexical
//! over every git-tracked `.rs` file, recursive into every token group, so a
//! call nested in another macro's tokens is found.

use super::{Site, sites, tracked_rs_files};

fn ids(text: &str) -> Vec<Option<String>> {
    sites(text)
        .expect("fixture tokenizes")
        .into_iter()
        .map(|s| s.id)
        .collect()
}

fn one(id: &str) -> Vec<Option<String>> {
    vec![Some(id.to_owned())]
}

#[test]
fn s1_a_plain_call_is_a_site() {
    assert_eq!(ids("fn f() { mutant!(\"A\", 1, 2); }"), one("A"));
}

#[test]
fn s2_a_call_inside_vec_is_a_site() {
    assert_eq!(
        ids("fn f() { let v = vec![mutant!(\"B\", 1, 2)]; }"),
        one("B")
    );
}

#[test]
fn s3_a_call_inside_assert_is_a_site() {
    assert_eq!(
        ids("fn f() { assert!(mutant!(\"C\", true, true)); }"),
        one("C")
    );
}

#[test]
fn s4_a_call_inside_a_macro_rules_body_is_a_site() {
    assert_eq!(
        ids("macro_rules! m { () => { mutant!(\"D\", 1, 2) } }"),
        one("D")
    );
}

#[test]
fn s5_a_call_inside_a_test_module_is_a_site() {
    assert_eq!(
        ids("#[cfg(test)] mod t { fn g() { mutant!(\"E\", 1, 2); } }"),
        one("E")
    );
}

#[test]
fn s6_spaced_and_path_calls_are_sites() {
    assert_eq!(
        ids(concat!(
            "fn f() { mutant ! (\"F\", 1, 2); crate::mutant!(\"G\", 1, 2); ",
            "mutant!{\"K\", 1, 2}; mutant![\"L\", 1, 2]; }"
        )),
        vec![
            Some("F".to_owned()),
            Some("G".to_owned()),
            Some("K".to_owned()),
            Some("L".to_owned())
        ]
    );
}

#[test]
fn s7_comments_strings_and_a_plain_function_are_not_sites() {
    let text = concat!(
        "// mutant!(\"H\", 1, 2)\n",
        "/* mutant!(\"H2\", 1, 2) */\n",
        "fn f() { let a = \"mutant!(\\\"I\\\", 1, 2)\"; ",
        "let b = r#\"mutant!(\"J\", 1, 2)\"#; mutant(1); }\n",
    );
    assert_eq!(ids(text), Vec::<Option<String>>::new());
}

#[test]
fn s8_the_macro_definition_is_not_a_site() {
    let text = "macro_rules! mutant { ($id:literal, $m:expr, $o:expr $(,)?) => { $o }; }";
    assert_eq!(ids(text), Vec::<Option<String>>::new());
}

#[test]
fn s9_the_walk_reaches_every_source_root() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    // The unpacked published crate (the post-merge packaged suite) ships no
    // nested crates and no git metadata; the same test as
    // boundary_pins::packaged::packaged_crate_at.
    if root.join("Cargo.toml.orig").exists() && !root.join(".git").exists() {
        eprintln!("skipped: the packaged crate is not the repository");
        return;
    }
    let files = tracked_rs_files(root).expect("git ls-files");
    let mut prefixes: Vec<String> = ["src/", "tests/", "benches/", "examples/"]
        .map(str::to_owned)
        .to_vec();
    // Every nested crate on disk, so a new one is covered without an edit.
    for entry in std::fs::read_dir(root.join("crates")).expect("read the nested crates") {
        let entry = entry.expect("nested crate entry");
        if entry.path().is_dir() {
            prefixes.push(format!("crates/{}/", entry.file_name().to_string_lossy()));
        }
    }
    assert!(prefixes.len() > 4, "no nested crate under crates");
    for prefix in prefixes {
        assert!(
            files.iter().any(|f| f.starts_with(&prefix)),
            "no tracked .rs file under {prefix}: the walk is not reading the repository"
        );
    }
}

/// The live repository: the only file a `mutant!` call may appear in is
/// src/mutant.rs (the macro's own self-tests).
#[test]
fn s10_no_mutant_site_outside_its_own_module() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let found = super::repo_sites(root).expect("scan the repository");
    let outside: Vec<String> = found
        .iter()
        .filter(|(path, _)| path != "src/mutant.rs")
        .map(|(path, site)| format!("{path}:{}", site.line))
        .collect();
    assert!(
        outside.is_empty(),
        "mutant! sites outside src/mutant.rs: {outside:?}"
    );
}

/// The walk over a planted repository finds a call nested in another macro
/// in each root a normal source walk could miss.
#[test]
fn s11_planted_calls_in_every_root_are_found() {
    let dir = tempfile::tempdir().expect("tempdir");
    let git = |args: &[&str]| {
        let out = std::process::Command::new("git")
            .args(args)
            .current_dir(dir.path())
            .output()
            .expect("run git");
        assert!(out.status.success(), "git {args:?}: {out:?}");
    };
    git(&["init", "-q"]);
    let planted = [
        "tests/x.rs",
        "benches/x.rs",
        "examples/x.rs",
        "build.rs",
        "crates/nested/src/x.rs",
    ];
    for path in planted {
        let full = dir.path().join(path);
        std::fs::create_dir_all(full.parent().expect("parent")).expect("mkdir");
        std::fs::write(
            &full,
            "fn f() { assert!(vec![mutant!(\"P\", 1, 2)].len() == 1); }\n",
        )
        .expect("write fixture");
    }
    git(&["add", "-A"]);
    let found = super::repo_sites(dir.path()).expect("scan the planted repository");
    let mut paths: Vec<&str> = found.iter().map(|(p, _)| p.as_str()).collect();
    paths.sort_unstable();
    let mut want = planted.to_vec();
    want.sort_unstable();
    assert_eq!(paths, want);
    assert!(
        found
            .iter()
            .all(|(_, s)| s.line == 1 && s.id.as_deref() == Some("P"))
    );
}

/// S12: a definition of `mutant!` is found at any depth, so a nested one that
/// would shadow the crate's own cannot hide.
#[test]
fn s12_a_definition_is_found_at_any_depth() {
    let defs = |text: &str| super::definitions(text).expect("fixture tokenizes");
    assert_eq!(defs("macro_rules! mutant { () => {} }"), vec![1]);
    assert_eq!(
        defs("mod inner {\n    macro_rules! mutant { () => {} }\n}"),
        vec![2]
    );
    assert_eq!(
        defs("#[cfg(any())]\nmacro_rules! mutant { () => {} }"),
        vec![2]
    );
    assert_eq!(
        defs("macro_rules! other { () => { mutant!(\"X\", 1, 2) } }"),
        Vec::<usize>::new()
    );
    assert_eq!(defs("// macro_rules! mutant { }"), Vec::<usize>::new());
}

/// S12: in the live repository the only definitions are the two in
/// `src/mutant_macro.rs` (one per cfg; `a_normal_build_drops_the_mutated_tokens`
/// checks their bodies). The library and the binary both declare that one
/// file as a module, so neither crate has a copy of its own.
#[test]
fn s12_no_definition_outside_the_macro_file() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let found = super::repo_definitions(root).expect("scan the repository");
    let outside: Vec<String> = found
        .iter()
        .filter(|(path, _)| path != MACRO_FILE)
        .map(|(path, line)| format!("{path}:{line}"))
        .collect();
    assert!(
        outside.is_empty(),
        "mutant! defined outside {MACRO_FILE}: {outside:?}"
    );
    assert_eq!(
        found.iter().filter(|(path, _)| path == MACRO_FILE).count(),
        2,
        "two definitions in {MACRO_FILE}"
    );
}

const MACRO_FILE: &str = "src/mutant_macro.rs";

/// S14: the library owns the mutant machinery and all mutation sites.
/// Its first module supplies the macros; `crate::mutant::on` names the switch.
#[test]
fn s14_library_root_carries_the_macros_and_the_switch() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(root.join("src/lib.rs")).expect("read the crate root");
    let file = syn::parse_file(&text).expect("parse the crate root");
    // macro_rules! is textually scoped: the macro module must be the first
    // module, `#[macro_use]`, or a site in an earlier module cannot see it.
    // A module, not include!(): the source walkers follow `mod` items.
    let first_mod = file.items.iter().find_map(|item| match item {
        syn::Item::Mod(m) => Some(m),
        _ => None,
    });
    let first_mod = first_mod.expect("src/lib.rs declares a module");
    assert!(
        first_mod.ident == "mutant_macro"
            && first_mod
                .attrs
                .iter()
                .any(|a| a.path().is_ident("macro_use")),
        "src/lib.rs: the first module must be `#[macro_use] mod mutant_macro;`"
    );
    assert!(
        file.items.iter().any(|item| matches!(item, syn::Item::Mod(m) if m.ident == "mutant")),
        "src/lib.rs declares no `mod mutant`"
    );
}

/// S13: a tree with no git metadata (the remote build mirror) is walked on
/// disk, so the scan still sees every root, and skips build output.
#[test]
fn s13_a_tree_without_git_is_walked_on_disk() {
    let dir = tempfile::tempdir().expect("tempdir");
    for (path, text) in [
        ("src/a.rs", "fn f() { mutant!(\"Q\", 1, 2); }\n"),
        (
            "crates/nested/src/b.rs",
            "fn g() { vec![mutant!(\"R\", 1, 2)]; }\n",
        ),
        (
            "target/debug/build/c.rs",
            "fn h() { mutant!(\"S\", 1, 2); }\n",
        ),
        ("src/target/d.rs", "fn i() { mutant!(\"T\", 1, 2); }\n"),
    ] {
        let full = dir.path().join(path);
        std::fs::create_dir_all(full.parent().expect("parent")).expect("mkdir");
        std::fs::write(&full, text).expect("write fixture");
    }
    let found = super::repo_sites(dir.path()).expect("scan the tree");
    let mut got: Vec<(String, Option<String>)> =
        found.into_iter().map(|(p, s)| (p, s.id)).collect();
    got.sort();
    assert_eq!(
        got,
        vec![
            ("crates/nested/src/b.rs".to_owned(), Some("R".to_owned())),
            ("src/a.rs".to_owned(), Some("Q".to_owned())),
            ("src/target/d.rs".to_owned(), Some("T".to_owned())),
        ]
    );
}

/// S14: a raw identifier names the same macro, so `r#mutant!` is a site and
/// `macro_rules! r#mutant` a definition.
#[test]
fn s14_raw_identifiers_are_found() {
    assert_eq!(ids("fn f() { r#mutant!(\"V\", 1, 2); }"), one("V"));
    assert_eq!(
        super::definitions("macro_rules! r#mutant { () => {} }").expect("tokenizes"),
        vec![1]
    );
}

/// S15: an ID is read only when its spelling is its value: a plain or raw
/// string with no escapes. An escaped one has no ID, so the runner refuses
/// the site instead of guessing.
#[test]
fn s15_only_plain_string_ids_are_read() {
    assert_eq!(ids("fn f() { mutant!(r\"W\", 1, 2); }"), one("W"));
    assert_eq!(ids("fn f() { mutant!(r#\"X\"#, 1, 2); }"), one("X"));
    assert_eq!(ids("fn f() { mutant!(\"\\u{41}\", 1, 2); }"), vec![None]);
    assert_eq!(ids("fn f() { mutant!(ID, 1, 2); }"), vec![None]);
}

/// S16: a file that does not tokenize fails the scan, named, rather than
/// being skipped.
#[test]
fn s16_a_file_that_does_not_tokenize_fails_the_scan() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("src")).expect("mkdir");
    std::fs::write(dir.path().join("src/bad.rs"), "fn f( {\n").expect("write fixture");
    let err = super::repo_sites(dir.path()).expect_err("an unbalanced file refuses");
    assert!(err.contains("src/bad.rs"), "{err}");
}

/// The runner's site list (SCH.6): with `MCP_GATEWAY_MUTANT_LIST` set it
/// prints one `MUTANT-SITE <id> <path>:<line>` line per site outside
/// src/mutant.rs, from the same scanner as the rows above; otherwise it only
/// checks that the scan runs.
#[test]
fn list_mutant_sites() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let found = super::repo_sites(root).expect("scan the repository");
    if std::env::var_os("MCP_GATEWAY_MUTANT_LIST").is_none() {
        return;
    }
    for (path, Site { id, line }) in found.iter().filter(|(p, _)| p != "src/mutant.rs") {
        println!(
            "MUTANT-SITE {} {path}:{line}",
            id.as_deref().unwrap_or("<no-id>")
        );
    }
    println!("MUTANT-SITES-DONE");
}
