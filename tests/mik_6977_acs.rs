// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-6977: honest task-token math and currently-checkable public claims.

use mcp_gateway::honest_task_tokens::{
    DEFAULT_EXTRA_TURNS, TOOL_COUNTS, schema_only_first_request, task_token_matrix, task_tokens,
};
use std::fs;
use std::path::PathBuf;

fn repo_file(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn readme() -> String {
    fs::read_to_string(repo_file("README.md")).expect("README.md")
}

fn read(path: &str) -> String {
    fs::read_to_string(repo_file(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn mik6977_bench_1_matrix_exists_and_can_lose() {
    assert_eq!(TOOL_COUNTS, [50, 100, 200, 500]);
    assert_eq!(DEFAULT_EXTRA_TURNS, 2);
    let rows = task_token_matrix(27_000);
    assert_eq!(rows.len(), 4);
    let lose = task_tokens(100, 2, 27_000);
    assert!(
        !lose.meta_wins(),
        "the task model must count host context again on the extra request"
    );
    let schema = schema_only_first_request(100);
    assert!(schema.meta_wins());
}

#[test]
fn mik6977_claim_1_readme_does_not_lead_with_unqualified_89() {
    let text = readme();
    let lede = text.chars().take(900).collect::<String>();
    assert!(
        !lede.contains("89%"),
        "lede must not lead with the schema-only 89% figure: {lede}"
    );
    if text.contains("89%") {
        assert!(
            text.contains("schema-only") || text.contains("first-request model"),
            "README must label any 89% math as schema-only / first-request"
        );
    }
    assert!(
        text.to_lowercase().contains("extra search hop") || text.contains("added one turn"),
        "README must disclose the measured extra-turn cost"
    );
}

#[test]
fn mik6977_claim_2_hash_pin_and_owasp_are_not_overclaimed() {
    let text = readme();
    let lower = text.to_lowercase();
    assert!(
        lower.contains("optional") && lower.contains("pin"),
        "README must say capability hash-pinning is optional"
    );
    assert!(
        !text.contains("OWASP_Agentic_AI-10%2F10_covered"),
        "README must not badge OWASP 10/10 as if certified"
    );
    assert!(
        lower.contains("self-assessed") || lower.contains("self-attested"),
        "OWASP coverage must be labelled self-assessed"
    );
    let show_hn = read("docs/show-hn.md").to_lowercase();
    assert!(
        show_hn.contains("unpinned files still load"),
        "Show HN must not imply every capability is hash-pinned"
    );
    let sovereign = read("docs/blog/sovereign-stack-2026-04.md");
    assert!(
        sovereign.contains("PolyForm Noncommercial by default")
            && sovereign.contains("separately licensed MIT core"),
        "the sovereign-stack post must state the runnable gateway's mixed license"
    );
}

#[test]
fn mik6977_bench_2_live_artifact_covers_the_matrix_and_can_lose() {
    let artifact: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(repo_file(
            "benchmarks/results/mik-6977-live-agent-2026-09-04.json",
        ))
        .expect("live benchmark artifact"),
    )
    .expect("valid live benchmark JSON");
    assert_eq!(artifact["schema_version"], "mik-6977.live-agent.v1");
    assert_eq!(
        artifact["method"]["system_under_test"],
        "isolated benchmark MCP server; the mcp-gateway binary is not in the request path"
    );
    assert!(
        artifact["method"]["meta_surface"]
            .as_str()
            .is_some_and(|surface| surface.contains("two synthetic tools"))
    );
    assert_eq!(
        artifact["method"]["catalog_sizes"],
        serde_json::json!([50, 100, 200, 500])
    );
    assert_eq!(artifact["trials"].as_array().map(Vec::len), Some(16));

    for trial in artifact["trials"].as_array().expect("trial rows") {
        assert_eq!(trial["process_exit"], 0);
        assert!(trial["input_tokens"].as_u64().is_some());
        assert!(trial["total_tokens"].as_u64().is_some());
        assert!(trial["latency_ms"].as_f64().is_some());
        assert!(trial["selection_correct"].as_bool().is_some());
        assert!(trial["task_success"].as_bool().is_some());
        assert!(trial["extra_turns"].as_u64().is_some());
        assert!(
            trial["turn_completed_events"]
                .as_u64()
                .is_some_and(|count| count > 0),
            "each trial must record the number of aggregated turn.completed events"
        );
        assert_eq!(trial["errors"].as_array().map(Vec::len), Some(0));
    }

    let rows = artifact["summary"].as_array().expect("summary rows");
    assert_eq!(rows.len(), 4);
    let benchmark_docs = read("docs/BENCHMARKS.md");
    for row in rows {
        let saving = row["measured_input_token_savings_percent"]
            .as_f64()
            .expect("measured input-token delta");
        assert!(
            benchmark_docs.contains(&format!("{saving:.2}%")),
            "benchmark docs must track the checked-in measurement"
        );
    }
}

#[test]
fn mik6977_claim_3_compact_surfaces_match_the_canonical_tool_counts() {
    let llms = read("llms.txt");
    assert!(llms.contains("1.3-16.0% more input tokens"));
    assert!(!llms.contains("7.1-16.1% more input tokens"));

    let library_docs = read("src/lib.rs");
    assert!(library_docs.contains("14 tools minimum"));
    assert!(library_docs.contains("16 in the README benchmark scenario"));
    assert!(library_docs.contains("17 when webhook status is surfaced"));
    assert!(!library_docs.contains("12 tools minimum"));

    let benchmark_docs = read("docs/BENCHMARKS.md");
    assert!(benchmark_docs.contains("Direct mean total task tokens grew"));
    assert!(benchmark_docs.contains("python3 benchmarks/live_agent_tool_selection.py"));
    let runner = read("benchmarks/live_agent_tool_selection.py");
    assert!(!runner.contains("from datetime import UTC"));
    let token_script = read("benchmarks/token_savings.py");
    assert!(token_script.contains("default=\"live\""));
    assert!(token_script.contains("--host-context-tokens-per-request"));
}
