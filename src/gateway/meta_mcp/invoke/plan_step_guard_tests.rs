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
//! any other listed plan entry point) in `grant_audit.rs`, the step
//! dispatch path's own file (the second row names it).
//!
//! The scan mirrors
//! `clock_tests::no_disallowed_methods_allow_or_clock_alias_hides_a_clock_read`:
//! `walkdir` over `src/`, test files skipped with `a_test_file`, and
//! only `product_code` read, so comments and `#[cfg(test)]` items
//! never count.

use std::collections::BTreeMap;

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

/// Every `src/` product file (relative path, `/`-separated) that calls
/// `plan_step(`, with its call count, and how many files were read.
fn plan_step_call_sites() -> (BTreeMap<String, usize>, usize) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut sites = BTreeMap::new();
    let mut read = 0;
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
        read += 1;
        let calls = plan_step_calls(&product_code(&src));
        if calls > 0 {
            sites.insert(rel.to_string_lossy().replace('\\', "/"), calls);
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

/// (b) The step dispatch bodies do not reach a plan: `grant_audit.rs`
/// holds `invoke_tool` and `invoke_tool_with_source` (and calls
/// `invoke_tool_sourced`, in `invoke/policy.rs`), and its product
/// code names no plan entry point. Read and confirmed for this row:
/// none of these names occurs there today.
#[test]
fn the_step_dispatch_path_names_no_plan_entry_point() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("src/gateway/meta_mcp/grant_audit.rs");
    let src = std::fs::read_to_string(&path).expect("readable source: fixture");
    let code = product_code(&src);
    assert!(
        !code.is_empty(),
        "the scan read no product code from grant_audit.rs"
    );
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
            "grant_audit.rs names {name}: a step dispatch can reach a plan, \
             so nested plans are reachable and MIK-8409.NESTED.1 must reopen"
        );
    }
}
