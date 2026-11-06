// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The discovery output scan on fixture source (rows G2, G3): each form a
//! maintainer could write is reported raw, passes when shown, and a file the
//! scan cannot read fails the walk.

use super::{Sites, walk};

/// The arguments the scan reports for `source` as `src/discovery/mod.rs` of a
/// scratch crate, as `function site argument` lines.
fn found(source: &str) -> Vec<String> {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("src/discovery")).expect("dirs");
    std::fs::write(dir.path().join("src/lib.rs"), "mod discovery;\n").expect("lib");
    std::fs::write(dir.path().join("src/discovery/mod.rs"), source).expect("module");
    let mut sites = Sites::default();
    walk(dir.path(), &["src/lib.rs"], &mut sites).expect("the walk reads the fixture");
    sites
        .counts
        .keys()
        .map(|(_, func, site, arg)| format!("{func} {site} {arg}"))
        .collect()
}

fn reports(source: &str, want: &str) {
    let got = found(source);
    assert!(
        got.iter().any(|g| g == want),
        "{want:?} not in {got:?}\n{source}"
    );
}

/// G2: every argument form is reported when raw.
#[test]
fn the_output_scan_finds_each_argument_form() {
    let cases = [
        (
            "fn f(e: E) { println!(\"{}\", e.name); }",
            "f println! e.name",
        ),
        (
            "fn f(e: E) { println!(\"{n}\", n = e.name); }",
            "f println! e.name",
        ),
        (
            "fn f(e: E) { let name = e.name; println!(\"{name}\"); }",
            "f println! {name}",
        ),
        (
            "fn f(e: E) { tracing::warn!(server = %e.name, \"skipped\"); }",
            "f warn! e.name",
        ),
        (
            "fn f(e: E) { tracing::warn!(\"skipped {}\", e.name); }",
            "f warn! e.name",
        ),
        (
            "fn f(e: E) { wrap!(println!(\"{}\", e.name)); }",
            "f println! e.name",
        ),
        (
            "fn f(e: E) { wrap!(println!(\"{}\", e.name)); }",
            "f macro wrap!",
        ),
        (
            "fn f(e: E) { tokio::select! { _ = w() => println!(\"{}\", e.name) } }",
            "f select! <body not parsed>",
        ),
        (
            "fn f(e: E) { let v = vec![format!(\"{}\", e.name)]; }",
            "f format! e.name",
        ),
        (
            "macro_rules! out { ($e:expr) => { println!(\"{}\", $e) } }",
            " item macro macro_rules",
        ),
        (
            "fn f(e: E) { assert!(ok(), \"{}\", e.name); }",
            "f assert! e.name",
        ),
        (
            "fn f(e: E) { assert_eq!(e.name, \"x\"); }",
            "f assert_eq! e.name",
        ),
        ("fn f(e: E) { dbg!(e.name); }", "f dbg! e.name"),
        (
            "fn f(e: E) { out.write_all(e.name.as_bytes()); }",
            "f write_all() e.name.as_bytes()",
        ),
        (
            "fn f(e: E) { std::io::Write::write_all(&mut out, e.name.as_bytes()); }",
            "f write_all() e.name.as_bytes()",
        ),
        (
            "fn f(e: E) { s.push_str(&e.name); }",
            "f push_str() &e.name",
        ),
        ("fn f(e: E) { s += &e.name; }", "f += &e.name"),
        (
            "fn shown(s: &str) -> &str { s }\nfn f(e: E) { println!(\"{}\", shown(&e.name)); }",
            "f println! shown(..)",
        ),
        (
            "use tracing::warn as w;\nfn f(e: E) { w!(\"{}\", e.name); }",
            "f warn! e.name",
        ),
        (
            "use crate::cli_support::shown;\nfn shown_path(p: &Path) -> String { let s = shown(&p.to_string_lossy()); s.to_string() }\nfn f(p: &Path) { tracing::debug!(\"{}\", shown_path(p)); }",
            "f debug! shown_path(..)",
        ),
        (
            "fn f(e: E) { println!(concat!(\"{\", \"name}\")); }",
            "f println! <format not a literal>",
        ),
    ];
    for (source, want) in cases {
        reports(source, want);
    }
}

/// G2: the shared escape, literals and test-only code pass.
#[test]
fn shown_literals_and_test_code_pass() {
    let clean = [
        "use crate::cli_support::shown;\nfn f(e: E) { println!(\"{} {}\", shown(&e.name), 3); println!(\"plain\"); }",
        "fn f(e: E) { println!(\"{}\", crate::cli_support::shown(&e.name)); }",
        "use mcp_gateway::cli_support::{Shown, shown};\nfn f(e: E) { s.push_str(&shown(&e.name)); }",
        "#[cfg(test)]\nfn t(e: E) { println!(\"{}\", e.name); }",
        "use crate::cli_support::shown;\nfn shown_path(p: &Path) -> Shown { shown(&p.to_string_lossy()) }\nfn f(p: &Path) { tracing::debug!(\"{}\", shown_path(p)); }",
        "fn field(out: &mut String, label: &str, value: &Shown) { s.push_str(\"x\"); println!(\"{value}\"); }",
    ];
    for source in clean {
        assert_eq!(found(source), Vec::<String>::new(), "{source}");
    }
}

/// G3: a file the scan cannot parse, or a declared module it cannot find,
/// fails the walk rather than shrinking it.
#[test]
fn an_unparseable_scoped_file_fails_the_scan() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("src/discovery")).expect("dirs");
    std::fs::write(dir.path().join("src/lib.rs"), "mod discovery;\n").expect("lib");
    std::fs::write(dir.path().join("src/discovery/mod.rs"), "fn f( {").expect("module");
    assert!(walk(dir.path(), &["src/lib.rs"], &mut Sites::default()).is_err());
    std::fs::write(dir.path().join("src/discovery/mod.rs"), "mod missing;\n").expect("module");
    assert!(walk(dir.path(), &["src/lib.rs"], &mut Sites::default()).is_err());
}
