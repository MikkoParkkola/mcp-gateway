// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Code written ahead of the part that calls it carries a dead-code
//! expectation whose reason starts "staged:". The accept chain's last part
//! removes the last of them under `src/decisions` and `src/config_reload`;
//! until then this row is red and ignored.

use std::path::Path;

/// Every staged dead-code expectation left under `dir`, as `file:line`.
fn staged_in(dir: &Path, found: &mut Vec<String>) {
    // Built in two pieces so this file does not match itself.
    let marker = format!("reason = \"{}", "staged:");
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .expect("a source directory")
        .map(|entry| entry.expect("a directory entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            staged_in(&path, found);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let text = std::fs::read_to_string(&path).expect("a source file");
            for (n, line) in text.lines().enumerate() {
                if line.contains(&marker) {
                    found.push(format!("{}:{}", path.display(), n + 1));
                }
            }
        }
    }
}

#[test]
#[ignore = "red until the accept route and the reload lookup call the staged items"]
fn no_staged_dead_code_is_left() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = Vec::new();
    for dir in ["decisions", "config_reload"] {
        staged_in(&src.join(dir), &mut found);
    }
    assert!(found.is_empty(), "staged dead code left: {found:#?}");
}
