// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The nesting-reachability guard (MIK-8408 stage 3, lead-approved).
//!
//! Why: MIK-8409.NESTED.1 (a plan run inside a plan step renewing under
//! the inner calls) is unreachable on 4.0.0 by construction: a plan
//! step dispatches one backend call through
//! `invoke_tool_with_source`, and nothing on that path can run another
//! plan. Only the two plan engines call `plan_step`, and a step's
//! dispatch bodies name no plan entry point. The day nesting is made
//! reachable — a third `plan_step` call site, or a plan entry point
//! named on the step dispatch path — NESTED.1 must be reopened and
//! proved for the newly reachable shape instead of by construction.
//! These rows are that tripwire.
//!
//! Mutants killed: a third product-code `plan_step(` call (the scan's
//! file map gains a file, or a count); naming `gateway_execute` (or
//! any other listed plan entry point) in any scanned file of the step
//! dispatch callee chain (the second row names them).
//!
//! The scan mirrors
//! `clock_tests::no_disallowed_methods_allow_or_clock_alias_hides_a_clock_read`:
//! `walkdir` over `src/`, test files skipped with `a_test_file`, and
//! only `product_code` read, so comments and `#[cfg(test)]` items
//! never count.

use std::collections::{BTreeMap, BTreeSet};

use crate::clock::tests::{a_test_file, product_code};

/// The `plan_step(` calls in one file's product code: the call token,
/// neither a longer name ending in it (`in_plan_step(`,
/// `first_unproven_plan_step(`) nor the definition
/// (`fn plan_step(` — today's definition is generic,
/// `fn plan_step<F ..>(`, which the token search already misses).
fn plan_step_calls(code: &str) -> usize {
    let is_ident = |c: char| c.is_alphanumeric() || c == '_';
    let mut calls = 0;
    for (at, _) in code.match_indices("plan_step(") {
        let before = &code[..at];
        if before.chars().next_back().is_some_and(is_ident) {
            continue;
        }
        if before.trim_end().ends_with("fn") {
            continue;
        }
        calls += 1;
    }
    calls
}

/// Every `src/` product file: its relative path (`/`-separated) and
/// its `product_code`.
fn product_files() -> Vec<(String, String)> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for entry in walkdir::WalkDir::new(root.join("src")) {
        let entry = entry.expect("src is readable: fixture");
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .expect("under the crate root: fixture");
        if path.extension().is_none_or(|e| e != "rs") || a_test_file(rel) {
            continue;
        }
        let src = std::fs::read_to_string(path).expect("readable source: fixture");
        files.push((rel.to_string_lossy().replace('\\', "/"), product_code(&src)));
    }
    files
}

/// Every `src/` product file (relative path, `/`-separated) that calls
/// `plan_step(`, with its call count, and how many files were read.
fn plan_step_call_sites() -> (BTreeMap<String, usize>, usize) {
    let files = product_files();
    let read = files.len();
    let mut sites = BTreeMap::new();
    for (rel, code) in &files {
        let calls = plan_step_calls(code);
        if calls > 0 {
            sites.insert(rel.clone(), calls);
        }
    }
    (sites, read)
}

/// (a) Exactly the two plan engines call `plan_step`, once each: the
/// chain executor and the playbook invoker. No third site may grow
/// without reopening NESTED.1 (see the module docs).
#[test]
fn only_the_two_plan_engines_call_plan_step() {
    let (sites, read) = plan_step_call_sites();
    assert!(
        read > 0,
        "the scan read no file at all: it is reading nothing"
    );
    let expected: BTreeMap<String, usize> = [
        ("src/gateway/meta_mcp/search/chain_exec.rs".to_owned(), 1),
        ("src/gateway/meta_mcp/playbook_invoker.rs".to_owned(), 1),
    ]
    .into_iter()
    .collect();
    assert_eq!(
        sites, expected,
        "a plan_step call outside the two plan engines makes nested plans \
         reachable: reopen MIK-8409.NESTED.1 for the new shape"
    );
}

/// (b) The step dispatch bodies do not reach a plan. Scanned files,
/// the callee chain a step dispatch goes through before the backend:
/// `src/gateway/meta_mcp/grant_audit.rs` (`invoke_tool`,
/// `invoke_tool_with_source`), `src/gateway/meta_mcp/invoke/policy.rs`
/// (`invoke_tool_sourced`, which the step dispatch calls and which
/// calls on into the traced dispatch), and
/// `src/gateway/meta_mcp/invoke.rs` (`invoke_tool_traced`, the traced
/// dispatch itself, down to the backend call). No scanned file's
/// product code names a plan entry point. Read and confirmed for this
/// row: none of these names occurs in any of them today (the
/// `gateway_run_playbook` in `invoke.rs`'s module doc is a comment,
/// which `product_code` drops).
#[test]
fn the_step_dispatch_path_names_no_plan_entry_point() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for rel in [
        "src/gateway/meta_mcp/grant_audit.rs",
        "src/gateway/meta_mcp/invoke/policy.rs",
        "src/gateway/meta_mcp/invoke.rs",
    ] {
        let src = std::fs::read_to_string(root.join(rel)).expect("readable source: fixture");
        let code = product_code(&src);
        assert!(!code.is_empty(), "the scan read no product code from {rel}");
        for name in [
            "gateway_execute",
            "gateway_run_playbook",
            "execute_chain",
            "chain_exec",
            "PlaybookEngine",
            "playbook_invoker",
        ] {
            assert!(
                !code.contains(name),
                "{rel} names {name}: a step dispatch can reach a plan, \
                 so nested plans are reachable and MIK-8409.NESTED.1 must reopen"
            );
        }
    }
}

/// The plan-replay staging entry points, each spelled as it is called.
const STAGING_ENTRIES: [&str; 5] = [
    "stage_stored_receipt(",
    "stage_task_replay(",
    ".stage_replay(",
    "stage_plan_replay(",
    "stage_entries(",
];

/// The name a line declares a `fn` under, if it declares one: the
/// identifier after the first `fn` word on the line (a `fn(...)`
/// pointer type names nothing and is skipped).
fn declared_fn(line: &str) -> Option<&str> {
    let is_ident = |c: char| c.is_alphanumeric() || c == '_';
    for (at, _) in line.match_indices("fn ") {
        if line[..at].chars().next_back().is_some_and(is_ident) {
            continue;
        }
        let rest = line[at + 3..].trim_start();
        let name = &rest[..rest.find(|c: char| !is_ident(c)).unwrap_or(rest.len())];
        if !name.is_empty() {
            return Some(name);
        }
    }
    None
}

/// Every staging call in `src/` product code, as `(entry as called,
/// file, enclosing fn)`, plus how many files were read. The enclosing
/// fn is the nearest preceding line in the same file that declares a
/// `fn`; a staging entry point's own `fn <name>(` definition line is
/// not a call. A call split across lines is still seen: the scan
/// finds the entry name wherever it occurs and then requires `(` as
/// the next non-whitespace character, across line breaks, so
/// `stage_stored_receipt\n(...)` counts exactly as the one-line
/// spelling does. A name that is the tail of a longer identifier
/// does not count.
fn staging_call_sites() -> (BTreeSet<(String, String, String)>, usize) {
    let files = product_files();
    let read = files.len();
    let is_ident = |c: char| c.is_alphanumeric() || c == '_';
    let mut sites = BTreeSet::new();
    for (rel, code) in &files {
        // Each line's start offset and the fn it declares, so a match
        // at any byte offset reads its own line and enclosing fn.
        let mut lines: Vec<(usize, &str, Option<&str>)> = Vec::new();
        let mut offset = 0_usize;
        for line in code.split_inclusive('\n') {
            lines.push((offset, line, declared_fn(line)));
            offset += line.len();
        }
        let enclosing_at = |at: usize| {
            lines
                .iter()
                .take_while(|(start, _, _)| *start <= at)
                .filter_map(|(_, _, declared)| *declared)
                .last()
                .unwrap_or_default()
        };
        let line_at = |at: usize| {
            lines
                .iter()
                .take_while(|(start, _, _)| *start <= at)
                .last()
                .map_or("", |(_, line, _)| line)
        };
        for entry in STAGING_ENTRIES {
            let token = entry.trim_end_matches('(');
            let bare = token.trim_start_matches('.');
            for (at, _) in code.match_indices(token) {
                // A leading-`.` token carries its own boundary; a bare
                // name must not be the tail of a longer identifier.
                if !token.starts_with('.') && code[..at].chars().next_back().is_some_and(is_ident) {
                    continue;
                }
                let after = code[at + token.len()..].trim_start();
                if !after.starts_with('(') {
                    continue;
                }
                if declared_fn(line_at(at)) == Some(bare) {
                    continue;
                }
                sites.insert((entry.to_owned(), rel.clone(), enclosing_at(at).to_owned()));
            }
        }
    }
    (sites, read)
}

/// (c) plan-replay staging happens only after authorization: a refused
/// read or a refused admission never reaches a staging entry point.
/// Each staging entry point has exactly the call sites below — each
/// one reached only past the authorization its path performs — so any
/// new caller is a new way to stage that must first be shown to sit
/// past authorization too. Indirection does not hide a caller: a new
/// wrapper that reaches staging must itself call one of these names,
/// so it appears as a new caller and fails this guard; calls through
/// a function pointer or trait object are not seen (none exist today).
#[test]
fn staging_entry_points_have_only_their_authorized_callers() {
    let (found, read) = staging_call_sites();
    assert!(
        read > 0,
        "the scan read no file at all: it is reading nothing"
    );
    for entry in STAGING_ENTRIES {
        assert!(
            found.iter().any(|triple| triple.0.as_str() == entry),
            "the scan found no {entry} call at all: it is reading nothing"
        );
    }
    let expected: BTreeSet<(String, String, String)> = [
        (
            "stage_stored_receipt(",
            "src/gateway/meta_mcp/task_replay/judging.rs",
            "refuse_stored",
        ),
        (
            "stage_task_replay(",
            "src/gateway/meta_mcp/task_replay/receipts.rs",
            "stage_stored_receipt",
        ),
        (
            ".stage_replay(",
            "src/gateway/meta_mcp/invoke/audit_replay.rs",
            "audit_replay",
        ),
        (
            "stage_plan_replay(",
            "src/gateway/meta_mcp/invoke/relay.rs",
            "stage_replay",
        ),
        (
            "stage_entries(",
            "src/gateway/meta_mcp/invoke/relay_replay.rs",
            "stage_plan_replay",
        ),
        (
            "stage_entries(",
            "src/gateway/meta_mcp/invoke/relay_replay.rs",
            "stage_task_replay",
        ),
    ]
    .into_iter()
    .map(|(entry, file, enclosing)| (entry.to_owned(), file.to_owned(), enclosing.to_owned()))
    .collect();
    let unexpected: Vec<_> = found.difference(&expected).collect();
    let missing: Vec<_> = expected.difference(&found).collect();
    assert!(
        unexpected.is_empty() && missing.is_empty(),
        "plan-replay staging happens only after authorization: a refused \
         read or a refused admission never reaches a staging entry point. \
         Unexpected callers {unexpected:?}, missing callers (stale \
         allow-list) {missing:?}"
    );
}
