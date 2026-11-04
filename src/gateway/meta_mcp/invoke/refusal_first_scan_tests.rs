// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Source-scan pin: every site that folds a dispatch failure into a tool
//! result (`dispatch_error_result`, `account_refused_fill`) first asks, in
//! code, whether the failure is a refusal of the caller, which is answered
//! as itself and never folded. Comments, string literals and char literals
//! are blanked before matching (`test_source_text::sanitize`), so a
//! predicate named only in one of them does not count. A new fold site fails
//! this row until it is reviewed and listed; the scan covers the module's
//! child directories too. It checks that the predicate is asked in the
//! fold's function, not that it guards the same error: the behaviour itself
//! is proved by the rows in `bridge_send_refusal_tests` and
//! `lend_refusal_tests`.

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

/// The fold sites in one file's `text`, counted, and those whose function
/// never asks the predicate in code above them (as `name:line`).
fn fold_sites(name: &str, text: &str) -> (usize, Vec<String>) {
    let code = crate::test_source_text::sanitize(text);
    let lines: Vec<&str> = code.lines().collect();
    let (mut sites, mut unchecked) = (0, Vec::new());
    for (at, line) in lines.iter().enumerate() {
        if line.contains("fn dispatch_error_result(")
            || line.contains(EXEMPT_FN)
            || !FOLDS.iter().any(|fold| line.contains(fold))
        {
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
        sites += 1;
        if !lines[start..at].iter().any(|l| l.contains(PREDICATE)) {
            unchecked.push(format!("{name}:{}", at + 1));
        }
    }
    (sites, unchecked)
}

#[test]
fn every_fold_site_asks_whether_the_failure_refused_the_caller() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/gateway/meta_mcp/invoke");
    let mut found = BTreeMap::new();
    let mut unchecked = Vec::new();
    // The module's files, its child directories included (`audit/`, `gate/`),
    // each named by its path under `invoke/`.
    let mut pending = vec![dir.clone()];
    while let Some(at) = pending.pop() {
        for entry in std::fs::read_dir(&at).expect("an invoke directory") {
            let path = entry.expect("an entry").path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            let name = path
                .strip_prefix(&dir)
                .expect("under invoke")
                .to_string_lossy()
                .replace('\\', "/");
            if path.extension().is_none_or(|ext| ext != "rs") || name.contains("tests") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("a source file");
            let (sites, mut missing) = fold_sites(&name, &text);
            if sites > 0 {
                found.insert(name, sites);
            }
            unchecked.append(&mut missing);
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

/// The scan's own premise: a predicate named only in a line comment, a
/// block comment or a string is not a check (red); a `//` inside a string
/// hides no fold call after it; and one asked in code is (control).
#[test]
fn a_predicate_named_only_in_a_comment_is_not_a_check() {
    let commented = "fn settle(e: Error) -> Value {\n    \
                     // is_authorization_refusal(&e) is asked elsewhere\n    \
                     dispatch_error_result(&e, tool, server, surface)\n}\n";
    let (sites, unchecked) = fold_sites("commented.rs", commented);
    assert_eq!(sites, 1, "premise: one fold site");
    assert_eq!(unchecked, ["commented.rs:3"], "a comment is not a check");

    let blocked = "fn settle(e: Error) -> Value {\n    \
                   /* is_authorization_refusal(&e) */\n    \
                   let note = \"is_authorization_refusal(&e)\";\n    \
                   dispatch_error_result(&e, tool, server, surface)\n}\n";
    let (sites, unchecked) = fold_sites("blocked.rs", blocked);
    assert_eq!(sites, 1, "premise: one fold site");
    assert_eq!(
        unchecked,
        ["blocked.rs:4"],
        "a block comment or a string is not a check"
    );

    let url = "fn settle(e: Error) -> Value {\n    \
               let at = \"http://x\"; dispatch_error_result(&e, tool, server, surface)\n}\n";
    let (sites, unchecked) = fold_sites("url.rs", url);
    assert_eq!(sites, 1, "a `//` in a string hides no fold call after it");
    assert_eq!(unchecked, ["url.rs:2"]);

    let asked = "fn settle(e: Error) -> Result<Value> {\n    \
                 if is_authorization_refusal(&e) {\n        return Err(e);\n    }\n    \
                 Ok(dispatch_error_result(&e, tool, server, surface))\n}\n";
    let (sites, unchecked) = fold_sites("asked.rs", asked);
    assert_eq!(sites, 1, "premise: one fold site");
    assert!(
        unchecked.is_empty(),
        "a check in code counts: {unchecked:?}"
    );
}
