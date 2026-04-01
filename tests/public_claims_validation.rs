use std::{fs, path::PathBuf};

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct PublicClaims {
    meta_tools: u64,
    startup_benchmark: StartupBenchmark,
    readme_token_savings: TokenSavingsClaim,
}

#[derive(Debug, Deserialize)]
struct StartupBenchmark {
    command: String,
    mean_ms: f64,
}

#[derive(Debug, Deserialize)]
struct TokenSavingsClaim {
    direct_tools: u64,
    direct_tokens_per_tool: u64,
    gateway_tools: u64,
    gateway_tokens_per_tool: u64,
    requests: u64,
    input_cost_per_million_usd: f64,
}

fn repo_file(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn read_repo_file(path: &str) -> String {
    fs::read_to_string(repo_file(path)).unwrap_or_else(|err| panic!("failed to read {path}: {err}"))
}

fn load_claims() -> PublicClaims {
    serde_json::from_str(&read_repo_file("benchmarks/public_claims.json"))
        .expect("benchmarks/public_claims.json should be valid JSON")
}

#[test]
fn readme_quantitative_claims_match_canonical_benchmark_data() {
    let claims = load_claims();
    let readme = read_repo_file("README.md");

    let direct_tokens = claims.readme_token_savings.direct_tools
        * claims.readme_token_savings.direct_tokens_per_tool;
    let gateway_tokens = claims.readme_token_savings.gateway_tools
        * claims.readme_token_savings.gateway_tokens_per_tool;
    let savings_percent = (1.0 - (gateway_tokens as f64 / direct_tokens as f64)) * 100.0;
    let direct_cost = (direct_tokens as f64 * claims.readme_token_savings.requests as f64
        / 1_000_000.0)
        * claims.readme_token_savings.input_cost_per_million_usd;
    let gateway_cost = (gateway_tokens as f64 * claims.readme_token_savings.requests as f64
        / 1_000_000.0)
        * claims.readme_token_savings.input_cost_per_million_usd;
    let savings_usd = direct_cost - gateway_cost;

    assert!(
        readme.contains(&format!("{} meta-tools", claims.meta_tools)),
        "README should advertise the canonical meta-tool count"
    );
    assert!(
        readme.contains(&format!("~{gateway_tokens} tokens")),
        "README should contain the canonical gateway token claim"
    );
    assert!(
        readme.contains(&format!("**{}% savings**", savings_percent.round() as u64)),
        "README should contain the canonical rounded savings percentage"
    );
    assert!(
        readme.contains(&format!("**${} saved per 1K**", savings_usd.round() as u64)),
        "README should contain the canonical rounded cost savings claim"
    );
}

#[test]
fn benchmark_docs_reference_canonical_claim_source_and_reproduction_commands() {
    let claims = load_claims();
    let benchmarks = read_repo_file("docs/BENCHMARKS.md");

    assert!(
        benchmarks.contains("benchmarks/public_claims.json"),
        "benchmark docs should point readers to the canonical machine-readable claims file"
    );
    assert!(
        benchmarks.contains(&claims.startup_benchmark.command),
        "benchmark docs should include the canonical startup command"
    );
    assert!(
        benchmarks.contains("python benchmarks/token_savings.py --scenario readme"),
        "benchmark docs should describe how to reproduce the README token-savings scenario"
    );
    assert!(
        benchmarks.contains(&format!(
            "~{}ms",
            claims.startup_benchmark.mean_ms.round() as u64
        )),
        "benchmark docs should include the canonical rounded startup metric"
    );
}

#[test]
fn token_savings_benchmark_tracks_four_gateway_meta_tools() {
    let script = read_repo_file("benchmarks/token_savings.py");

    assert!(
        script.contains("\"gateway_list_tools\""),
        "token benchmark must include gateway_list_tools so the published meta-tool count stays accurate"
    );
    assert!(
        script.contains("len(GATEWAY_TOOLS)"),
        "token benchmark should derive the gateway tool count from the canonical tool list"
    );
    assert!(
        !script.contains("always 3"),
        "token benchmark should not hard-code the obsolete 3-tool assumption"
    );
}
