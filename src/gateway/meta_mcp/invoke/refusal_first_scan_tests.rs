// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Source-scan pin: every site that folds a dispatch failure into
//! a tool result (`dispatch_error_result`, `account_refused_fill`) first
//! asks whether the failure is a refusal of the caller, which is answered as
//! itself and never folded. A new fold site fails this row until it is
//! reviewed and listed.

use std::collections::BTreeMap;
use std::path::Path;

/// The calls that fold a failure into a tool result.
const FOLDS: [&str; 2] = ["dispatch_error_result(", "account_refused_fill("];

/// The predicate every fold site asks first.
const PREDICATE: &str = "is_authorization_refusal(";

/// The reviewed fold sites, per file. `account_refused_fill`'s own call of
/// `dispatch_error_result` is not one: its callers ask the predicate first.
const REVIEWED: [(&str, usize); 4] = [
    ("caller_verdict.rs", 1),
    ("legacy_bridge.rs", 1),
    ("post_dispatch.rs", 1),
    ("r2_check.rs", 1),
];

/// The function a fold inside it is exempt in, by its definition line.
const EXEMPT_FN: &str = "fn account_refused_fill(";

#[test]
fn every_fold_site_asks_whether_the_failure_refused_the_caller() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/gateway/meta_mcp/invoke");
    let mut found = BTreeMap::new();
    let mut unchecked = Vec::new();
    let entries = std::fs::read_dir(&dir).expect("the invoke directory");
    for entry in entries {
        let path = entry.expect("an entry").path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_owned();
        if !name.ends_with(".rs") || name.contains("tests") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("a source file");
        let lines: Vec<&str> = text.lines().collect();
        for (at, line) in lines.iter().enumerate() {
            let code = line.trim_start();
            if code.starts_with("//") || code.contains("fn dispatch_error_result(") {
                continue;
            }
            if !FOLDS.iter().any(|fold| code.contains(fold)) || code.contains(EXEMPT_FN) {
                continue;
            }
            // The enclosing function: the nearest definition above the call.
            let start = (0..at)
                .rev()
                .find(|&n| lines[n].trim_start().contains("fn "))
                .unwrap_or(0);
            if lines[start].contains(EXEMPT_FN) {
                continue;
            }
            *found.entry(name.clone()).or_insert(0) += 1;
            if !lines[start..at].iter().any(|l| l.contains(PREDICATE)) {
                unchecked.push(format!("{name}:{}", at + 1));
            }
        }
    }
    assert!(
        unchecked.is_empty(),
        "fold sites that never ask whether the failure refused the caller: {unchecked:?}"
    );
    let reviewed: BTreeMap<String, usize> = REVIEWED
        .iter()
        .map(|(file, count)| ((*file).to_owned(), *count))
        .collect();
    assert_eq!(
        found, reviewed,
        "the fold sites changed: review and list them"
    );
}
