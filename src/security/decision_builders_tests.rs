// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The census of a call decision's builders. One literal builds the decision
//! object an invocation record carries (`Noted::decision`), and four entry
//! points reach it: the meta call and the direct call through
//! `DispatchNotes::decided`, the router's refusal record and the replay record.
//! Each runs inside the call's token scope, and a real-token row per entry
//! point pins that (`router/direct_audit_tests/token_reach.rs`). A builder
//! added anywhere else changes these counts and fails here, so it cannot ship
//! without its own scope and its own row. Grant-decision rows are another
//! record kind and are not counted.

use std::collections::BTreeMap;
use std::path::Path;

/// Production source files whose production text holds `needle`, with how
/// many times, keyed by their path from the crate root with `/` separators.
fn census(needle: &str) -> BTreeMap<String, usize> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut found = BTreeMap::new();
    let mut dirs = vec![root.join("src")];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).expect("a source directory reads") {
            let path = entry.expect("a directory entry").path();
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            // Test code lives in `*_tests.rs` files, `tests.rs`, `tests/` and
            // `*_tests/` directories; inline test items are blanked below.
            let test_code = name == "tests"
                || name == "tests.rs"
                || name.ends_with("_tests")
                || name.ends_with("_tests.rs");
            if test_code {
                continue;
            }
            if path.is_dir() {
                dirs.push(path);
                continue;
            }
            if !name.ends_with(".rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("a source file reads");
            let count = crate::test_source_text::production_text(&text)
                .matches(needle)
                .count();
            if count > 0 {
                let relative = path.strip_prefix(root).expect("under the crate root");
                found.insert(relative.to_string_lossy().replace('\\', "/"), count);
            }
        }
    }
    found
}

fn counts(rows: &[(&str, usize)]) -> BTreeMap<String, usize> {
    rows.iter()
        .map(|(file, n)| ((*file).to_owned(), *n))
        .collect()
}

#[test]
fn a_call_decision_has_exactly_its_known_builders() {
    // The one literal's callers: `DispatchNotes::decided` (its two arms), the
    // router's refusal record, and the replay record.
    assert_eq!(
        census(".decision("),
        counts(&[
            ("src/gateway/meta_mcp/invoke/audit_decision.rs", 2),
            ("src/gateway/meta_mcp/invoke/audit_replay.rs", 1),
            ("src/gateway/router/meta_refusal_audit.rs", 1),
        ])
    );
    // `DispatchNotes::decided`'s callers: the meta call and the direct call.
    assert_eq!(
        census(".decided("),
        counts(&[
            ("src/gateway/meta_mcp/invoke/audit.rs", 1),
            ("src/gateway/router/backend_handlers/direct_audit.rs", 1),
        ])
    );
}
