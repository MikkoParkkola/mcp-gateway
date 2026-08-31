// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-6977: honest task-token math and currently-checkable public claims.

use mcp_gateway::honest_task_tokens::{
    DEFAULT_EXTRA_TURNS, TOOL_COUNTS, default_matrix, schema_only_first_request, task_tokens,
};
use std::fs;
use std::path::PathBuf;

fn repo_file(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn readme() -> String {
    fs::read_to_string(repo_file("README.md")).expect("README.md")
}

#[test]
fn mik6977_bench_1_matrix_exists_and_can_lose() {
    assert_eq!(TOOL_COUNTS, [50, 100, 200, 500]);
    assert_eq!(DEFAULT_EXTRA_TURNS, 2);
    let rows = default_matrix();
    assert_eq!(rows.len(), 4);
    let lose = task_tokens(100, 20);
    assert!(
        !lose.meta_wins(),
        "the honest model must be able to lose when extra turns dominate"
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
    assert!(
        text.contains("schema-only") || text.contains("first-request model"),
        "README must label remaining 89% math as schema-only / first-request"
    );
    assert!(
        text.to_lowercase().contains("honest_task_tokens") || text.contains("extra discovery turn"),
        "README must point at the extra-turn task-token model"
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
}
