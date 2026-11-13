// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The sandbox's staged parts land before the code that calls them, each
//! carrying `expect(dead_code)` until its caller exists. That form is a hard
//! error the moment the code goes live, but it cannot say how many parts are
//! still dark. This ratchet can: `staged_dark.tsv` lists every source that
//! still carries the attribute and the part that removes it. A new staged part
//! must add its line, a part that wires one up must delete it, and the ticket
//! closes only when the list is empty.

use std::path::Path;

/// True when `text` carries a staged-dark attribute on a code line (a comment
/// that merely mentions the attribute does not count).
fn carries_staged_dark(text: &str) -> bool {
    text.lines().any(|line| {
        let line = line.trim_start();
        !line.starts_with("//") && line.contains("expect(dead_code")
    })
}

/// Every `.rs` source under `dir` that carries a staged-dark attribute,
/// root-relative.
fn staged_sources(dir: &Path, root: &Path, out: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).expect("read source dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            staged_sources(&path, root, out);
            continue;
        }
        let is_rust = path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"));
        let rel = path
            .strip_prefix(root)
            .expect("under root")
            .to_string_lossy()
            .replace('\\', "/");
        // This file names the attribute in its own samples.
        if is_rust
            && rel != "src/preview_sandbox/staged_tests.rs"
            && carries_staged_dark(&std::fs::read_to_string(&path).expect("read source"))
        {
            out.push(rel);
        }
    }
}

/// The listed sources, each with the part that removes its attribute.
fn listed() -> Vec<(String, String)> {
    include_str!("staged_dark.tsv")
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .map(|line| {
            let (path, part) = line
                .split_once('\t')
                .unwrap_or_else(|| panic!("a staged_dark.tsv line needs a tab: {line:?}"));
            (path.to_owned(), part.to_owned())
        })
        .collect()
}

#[test]
fn the_staged_dark_list_is_exactly_the_sources_that_carry_the_attribute() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut found = Vec::new();
    staged_sources(&root.join("src/preview_sandbox"), root, &mut found);
    found.sort();
    let mut named: Vec<String> = listed().into_iter().map(|(path, _)| path).collect();
    named.sort();
    assert_eq!(
        found, named,
        "src/preview_sandbox/staged_dark.tsv must list every source that still carries \
         expect(dead_code), and nothing else: a new staged part adds its line, the part \
         that wires one up removes it"
    );
}

#[test]
fn every_staged_line_names_the_part_that_removes_it() {
    for (path, part) in listed() {
        assert!(
            !part.trim().is_empty(),
            "{path} is staged dark but names no part that wires it up"
        );
    }
}

#[test]
fn the_scan_tells_an_attribute_from_a_mention() {
    assert!(carries_staged_dark(
        "#![cfg_attr(\n    not(test),\n    expect(dead_code, reason = \"later\")\n)]"
    ));
    assert!(!carries_staged_dark(
        "// a comment that names expect(dead_code) is only a mention"
    ));
    assert!(!carries_staged_dark("/// doc\nfn live() {}\n"));
}
