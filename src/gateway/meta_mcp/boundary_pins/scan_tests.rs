// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8387 PR-B scanner rows (test plan v2 §2): the scanner's rules on
//! synthetic source, so a scanner fault fails a small named case.

use super::scan::{Cfg, eval, test_only};

fn cfg(predicate: &str) -> Cfg {
    eval(&syn::parse_str::<syn::Meta>(predicate).expect("a predicate"))
}

fn attrs(source: &str) -> Vec<syn::Attribute> {
    let item: syn::ItemFn = syn::parse_str(&format!("{source} fn f() {{}}")).expect("an item");
    item.attrs
}

/// SCAN-TT: the three-valued truth table. `test` is false, any other atom
/// unknown; `all()` is true and `any()` false. The case count is pinned, so
/// a dropped line fails loudly. Mutants: SCAN-m2 (unknown taken as true),
/// SCAN-m6 (first operand only).
#[test]
fn scan_tt_three_valued_cfg_truth_table() {
    // Operands: F = test, U = an unknown atom, T = not(test).
    let (f, u, t) = ("test", "feature = \"x\"", "not(test)");
    let cases = [
        (f.to_string(), Cfg::False),
        (u.to_string(), Cfg::Unknown),
        (t.to_string(), Cfg::True),
        (format!("not({u})"), Cfg::Unknown),
        (format!("not({t})"), Cfg::False),
        ("all()".to_string(), Cfg::True),
        ("any()".to_string(), Cfg::False),
        (format!("all({f}, {f})"), Cfg::False),
        (format!("all({f}, {u})"), Cfg::False),
        (format!("all({f}, {t})"), Cfg::False),
        (format!("all({u}, {f})"), Cfg::False),
        (format!("all({u}, {u})"), Cfg::Unknown),
        (format!("all({u}, {t})"), Cfg::Unknown),
        (format!("all({t}, {f})"), Cfg::False),
        (format!("all({t}, {u})"), Cfg::Unknown),
        (format!("all({t}, {t})"), Cfg::True),
        (format!("any({f}, {f})"), Cfg::False),
        (format!("any({f}, {u})"), Cfg::Unknown),
        (format!("any({f}, {t})"), Cfg::True),
        (format!("any({u}, {f})"), Cfg::Unknown),
        (format!("any({u}, {u})"), Cfg::Unknown),
        (format!("any({u}, {t})"), Cfg::True),
        (format!("any({t}, {f})"), Cfg::True),
        (format!("any({t}, {u})"), Cfg::True),
        (format!("any({t}, {t})"), Cfg::True),
        (format!("not(any({f}, all({u}, {f})))"), Cfg::True),
        (format!("all(not({u}), any({t}, {u}))"), Cfg::Unknown),
    ];
    assert_eq!(cases.len(), 27, "want 27 cases");
    for (predicate, want) in cases {
        assert_eq!(cfg(&predicate), want, "cfg({predicate})");
    }
}

/// SCAN-1..6: which items are test-only. Production is anything not
/// definitely excluded outside tests. Mutants: SCAN-m1 (a predicate that
/// mentions `test` counts as test-only: SCAN-3, SCAN-4), SCAN-m2 (SCAN-5),
/// SCAN-m12 (cfg ignored: SCAN-1, SCAN-2).
#[test]
fn scan_1_to_6_test_only_by_cfg_evaluation() {
    let rows = [
        ("SCAN-1", "#[cfg(test)]", true),
        ("SCAN-2", "#[cfg(all(test, feature = \"x\"))]", true),
        ("SCAN-3", "#[cfg(any(test, feature = \"webui\"))]", false),
        ("SCAN-4", "#[cfg(not(test))]", false),
        ("SCAN-5", "#[cfg(not(feature = \"webui\"))]", false),
        ("SCAN-6", "#[cfg(any(not(test), windows))]", false),
    ];
    for (row, attr, want) in rows {
        assert_eq!(test_only(&attrs(attr)), want, "{row}: {attr}");
    }
}

/// SCAN-18 (test plan v2): what T1e's sink reads off a struct. Derives,
/// including one under `cfg_attr`, and a field more visible than private.
/// Mutants: SCAN-m10 (derives discarded), SCAN-m11 (field visibility
/// ignored), both in the same `Surface` sink T1e uses.
#[test]
fn scan_18_derive_and_field_visibility_extraction() {
    use super::scan::{Place, Sink};
    let item: syn::Item = syn::parse_str(
        "#[derive(Debug, Clone)] #[cfg_attr(feature = \"x\", derive(serde::Serialize))] \
         struct BackendRegistry { pub x: u8, y: u8 }",
    )
    .expect("a struct");
    let mut surface = super::guard_tests::Surface::default();
    surface.item(&Place::default(), &item);
    assert_eq!(
        surface.derives,
        ["Clone", "Debug", "Serialize"]
            .map(String::from)
            .into_iter()
            .collect(),
        "SCAN-18: derives"
    );
    assert_eq!(surface.public_fields, ["x"], "SCAN-18: field visibility");
}

/// Walk a synthetic crate of `(path, source)` files with T1b2's sink and
/// return the broad suppressions it reports.
fn broad_in(files: &[(&str, &str)]) -> Vec<String> {
    let dir = tempfile::tempdir().expect("a temp crate");
    for (path, source) in files {
        let full = dir.path().join(path);
        std::fs::create_dir_all(full.parent().expect("a parent")).expect("dirs");
        std::fs::write(full, source).expect("a file");
    }
    let mut broad = super::guard_tests::Broad::default();
    super::scan::walk(dir.path(), &["src/lib.rs"], &mut broad).expect("the walk");
    broad.0
}

/// SCAN-8b: a broad suppression under nested `cfg_attr` is seen.
/// Mutant SCAN-m3c: `lints_in` stops recursing into `cfg_attr`.
#[test]
fn scan_8b_a_nested_cfg_attr_suppression_is_seen() {
    let found = broad_in(&[(
        "src/lib.rs",
        "#[cfg_attr(feature = \"a\", cfg_attr(feature = \"b\", allow(warnings)))] fn f() {}",
    )]);
    assert_eq!(found.len(), 1, "SCAN-8b: {found:?}");
}

/// SCAN-19: a module file whose own inner attribute says `#![cfg(test)]` is
/// test-only, while the same file without it is production, so the walk
/// both skips the first and reaches the second. Mutant SCAN-m16: the
/// file-level check removed.
#[test]
fn scan_19_a_file_level_cfg_test_module_is_test_only() {
    let module = |inner: &str| format!("{inner}\n#[allow(warnings)] fn f() {{}}");
    let skipped = broad_in(&[
        ("src/lib.rs", "mod a;"),
        ("src/a.rs", &module("#![cfg(test)]")),
    ]);
    assert!(
        skipped.is_empty(),
        "SCAN-19: a #![cfg(test)] file was walked: {skipped:?}"
    );
    let walked = broad_in(&[("src/lib.rs", "mod a;"), ("src/a.rs", &module(""))]);
    assert_eq!(
        walked.len(),
        1,
        "SCAN-19 control: the production file was walked: {walked:?}"
    );
}

/// The files a walk reports, by the path each is named with.
#[derive(Default)]
struct Files(Vec<String>);

impl super::scan::Sink for Files {
    fn file(&mut self, at: &super::scan::Place, _file: &syn::File) {
        self.0.push(at.file.clone());
    }
}

/// SCAN-20: a parent-relative `#[path]` include is reported by its real path,
/// including consecutive `..` components, not by the route taken to it.
#[test]
fn scan_20_a_parent_relative_include_reports_its_normalised_path() {
    let dir = tempfile::tempdir().expect("a temp crate");
    for (path, source) in [
        (
            "src/lib.rs",
            "#[path = \"sub/deep/../../../shared/b.rs\"] mod b;",
        ),
        ("src/sub/deep/keep", ""),
        ("shared/b.rs", "fn b() {}"),
    ] {
        let full = dir.path().join(path);
        std::fs::create_dir_all(full.parent().expect("a parent")).expect("dirs");
        std::fs::write(full, source).expect("a file");
    }
    let mut files = Files::default();
    super::scan::walk(dir.path(), &["src/lib.rs"], &mut files).expect("the walk");
    assert_eq!(files.0, ["src/lib.rs", "shared/b.rs"], "SCAN-20");
}

/// SCAN-21: a `..` with nothing to pop is kept, so an include that escapes
/// the scanned root is named outside it, not as a file inside it.
#[test]
fn scan_21_a_leading_parent_component_is_kept() {
    use super::scan::normalised;
    use std::path::Path;
    assert_eq!(normalised(Path::new("../x.rs")), Path::new("../x.rs"));
    assert_eq!(normalised(Path::new("a/../../x.rs")), Path::new("../x.rs"));
    assert_eq!(normalised(Path::new("../../x.rs")), Path::new("../../x.rs"));
    assert_eq!(normalised(Path::new("a/./b/../c.rs")), Path::new("a/c.rs"));
    assert_eq!(normalised(Path::new("/../x.rs")), Path::new("/x.rs"));

    let dir = tempfile::tempdir().expect("a temp dir");
    let root = dir.path().join("crate");
    std::fs::create_dir_all(root.join("src")).expect("dirs");
    std::fs::write(
        root.join("src/lib.rs"),
        "#[path = \"../../outside.rs\"] mod o;",
    )
    .expect("lib");
    std::fs::write(dir.path().join("outside.rs"), "fn o() {}").expect("outside");
    let mut files = Files::default();
    super::scan::walk(&root, &["src/lib.rs"], &mut files).expect("the walk");
    assert_eq!(files.0[0], "src/lib.rs");
    assert!(
        !files.0[1].starts_with("src/") && files.0[1].ends_with("outside.rs"),
        "SCAN-21: {:?}",
        files.0
    );
}
