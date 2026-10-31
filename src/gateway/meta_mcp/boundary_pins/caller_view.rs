// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A call's path reads the capability provider as its caller sees it
//! (`MetaMcp::caller_capabilities`), so a provider hidden from the caller is
//! treated as an unregistered name. Every unfiltered `get_capabilities()`
//! read in production code is listed in `caller_view.tsv` with its class and
//! reason, by file and exact count: a new read, or one more in a listed
//! file, fails until it is classified. Test files are not scanned; an inline
//! test module's reads count toward its file.

use std::collections::BTreeMap;

use super::packaged::crate_root;

const NEEDLE: &str = ".get_capabilities()";

/// Production `.rs` files under `src`, as paths relative to the crate root.
fn production_files(root: &std::path::Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut dirs = vec![root.join("src")];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).expect("src readable").flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n != "tests") {
                    dirs.push(path);
                }
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .expect("under root")
                .to_string_lossy()
                .replace('\\', "/");
            let name = rel.rsplit('/').next().unwrap_or_default();
            if path.extension().is_some_and(|e| e == "rs")
                && !name.ends_with("_tests.rs")
                && name != "tests.rs"
                && !name.contains("_test")
                && !rel.contains("fixture")
            {
                out.push(rel);
            }
        }
    }
    out
}

#[test]
fn every_unfiltered_capability_read_is_classified() {
    let root = crate_root();
    let listed: BTreeMap<String, (usize, String)> = include_str!("caller_view.tsv")
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| {
            let cols: Vec<&str> = l.split('\t').collect();
            assert_eq!(cols.len(), 4, "row needs file, calls, class, reason: {l}");
            assert!(
                ["by-design", "not-a-call-path", "listing"].contains(&cols[2])
                    && !cols[3].trim().is_empty(),
                "row needs a known class and a reason: {l}"
            );
            (
                cols[0].to_owned(),
                (cols[1].parse().expect("calls"), cols[2].to_owned()),
            )
        })
        .collect();
    let mut found = BTreeMap::new();
    for rel in production_files(root) {
        let text = std::fs::read_to_string(root.join(&rel)).expect("source readable");
        let n = text.matches(NEEDLE).count();
        if n > 0 {
            found.insert(rel, n);
        }
    }
    let mut problems = Vec::new();
    for (file, n) in &found {
        match listed.get(file) {
            None => problems.push(format!(
                "{file}: {n} unfiltered get_capabilities() read(s) not in caller_view.tsv; \
                 a call path reads caller_capabilities()"
            )),
            Some((want, _)) if want != n => {
                problems.push(format!("{file}: {n} reads, the row says {want}"));
            }
            Some(_) => {}
        }
    }
    for file in listed.keys().filter(|f| !found.contains_key(*f)) {
        problems.push(format!("{file}: listed, but no read is left"));
    }
    assert!(problems.is_empty(), "{problems:#?}");
}
