// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Tests for ranked_results_to_json, the search-result JSON projection.
use super::*;
use crate::ranking::SearchResult;

#[test]
fn ranked_results_to_json_converts_correctly() {
    let results = vec![
        SearchResult {
            server: "s1".to_string(),
            tool: "t1".to_string(),
            description: "desc1".to_string(),
            score: 0.95,
            ..SearchResult::new("s1", "t1", "desc1")
        },
        SearchResult {
            server: "s2".to_string(),
            tool: "t2".to_string(),
            description: "desc2".to_string(),
            score: 0.80,
            ..SearchResult::new("s2", "t2", "desc2")
        },
    ];
    let json_results = ranked_results_to_json(results, true);
    assert_eq!(json_results.len(), 2);
    assert_eq!(json_results[0]["server"], "s1");
    assert_eq!(json_results[0]["score"], 0.95);
    assert_eq!(json_results[0]["ranking"]["included"], true);
    assert_eq!(json_results[1]["tool"], "t2");
}

#[test]
fn ranked_results_to_json_prunes_the_constant_signals() {
    // MIK-7084.SURFACE.1b. The code-mode emitter pruned; this one, which
    // serves the ordinary `gateway_search` path, shipped all sixteen signals.
    // Asserted on the emitter rather than on the pruner, because a pruner that
    // prunes proves nothing about a caller that never calls it.
    let results = vec![SearchResult {
        server: "s1".to_string(),
        tool: "t1".to_string(),
        description: "desc1".to_string(),
        score: 0.95,
        ..SearchResult::new("s1", "t1", "desc1")
    }];
    let shown = ranked_results_to_json(results, true);
    let signals = shown[0]["ranking"]["signals"]
        .as_object()
        .expect("explain carries the signals object");
    for constant in ["safety", "trust", "policy_fit", "risk", "latency"] {
        assert!(
            !signals.contains_key(constant),
            "{constant} is the same for every tool in every response and must \
             not be emitted: {:?}",
            signals.keys().collect::<Vec<_>>()
        );
    }
    assert!(
        signals.contains_key("relevance"),
        "pruning must not take the signals that vary: {:?}",
        signals.keys().collect::<Vec<_>>()
    );
}

#[test]
fn ranked_results_to_json_omits_ranking_unless_explain() {
    let results = vec![SearchResult {
        server: "s1".to_string(),
        tool: "t1".to_string(),
        description: "desc1".to_string(),
        score: 0.95,
        ..SearchResult::new("s1", "t1", "desc1")
    }];
    let hidden = ranked_results_to_json(results.clone(), false);
    assert!(hidden[0].get("ranking").is_none());
    assert_eq!(hidden[0]["score"], 0.95);
    let shown = ranked_results_to_json(results, true);
    assert_eq!(shown[0]["ranking"]["included"], true);
}

#[test]
fn ranked_results_to_json_empty_input() {
    let json_results = ranked_results_to_json(vec![], false);
    assert!(json_results.is_empty());
}
