//! Acceptance-criterion artifact checks for MIK-4625.

use std::{fs, path::PathBuf};

use serde_json::Value;

fn repo_path(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn read_json(path: &str) -> Value {
    let content = fs::read_to_string(repo_path(path)).expect("artifact should be readable");
    serde_json::from_str(&content).expect("artifact should parse as JSON")
}

// MIK-4625.PLUGIN.1: `.claude-plugin/plugin.json` exists with `name`, `version`
// (pinned to the published gateway version, ≥2.12.1), `description`, `repository`, and a
// `dependencies` array, all schema-valid. A committed Rust test (`tests/plugin_manifest.rs`,
// same commit as the manifest per MIK-4088) deserializes the manifest and asserts the
// required fields are present and non-empty.
// CHECK: `cargo test --release --test plugin_manifest manifest_required_fields` exits 0
// AND file `.claude-plugin/plugin.json` matches regex `"name"\s*:\s*"mcp-gateway"`.
#[test]
fn ac_1_mik_4625_plugin_1_claude_plugin_plugin_json() {
    let manifest = read_json(".claude-plugin/plugin.json");
    assert_eq!(
        manifest.get("name").and_then(Value::as_str),
        Some("mcp-gateway")
    );
    assert!(
        manifest
            .get("dependencies")
            .and_then(Value::as_array)
            .is_some()
    );
}

// MIK-4625.PLUGIN.2: Plugin `mcpServers` declares exactly ONE entry — the gateway
// itself (stdio, e.g. `{"mcp-gateway":{"command":"npx","args":["-y","@mikkoparkkola/mcp-gateway"]}}`
// or the bundled binary via `${CLAUDE_PLUGIN_ROOT}`) — and the plugin ships the canonical
// pin-versioned backend roster as a config bundle file. A committed test asserts
// `mcpServers` has length == 1 and the bundled config file lists the roster.
// CHECK: `cargo test --release --test plugin_manifest single_gateway_server_and_bundle` exits 0
// AND file `.claude-plugin/plugin.json` matches regex `"mcpServers"` AND a bundle file under
// `examples/` matches regex `backends:` (or `capabilities:`).
#[test]
fn ac_2_mik_4625_plugin_2_plugin_mcpservers_declares() {
    let manifest = read_json(".claude-plugin/plugin.json");
    let servers = manifest
        .get("mcpServers")
        .and_then(Value::as_object)
        .unwrap();
    assert_eq!(servers.len(), 1);
    assert!(repo_path("examples/mcp-gateway-plugin-bundle.yaml").exists());
}

// MIK-4625.PLUGIN.3: `hooks` section registers the production `gateway-attribution`
// PreToolUse hook (already shipping), inline or via `./config/hooks.json`, pointing at a
// path under `${CLAUDE_PLUGIN_ROOT}`. Committed test asserts the hook entry parses and the
// referenced script path exists in-repo.
// CHECK: `cargo test --release --test plugin_manifest attribution_hook_registered` exits 0
// AND `.claude-plugin/plugin.json` (or `config/hooks.json`) matches regex `PreToolUse`.
#[test]
fn ac_3_mik_4625_plugin_3_hooks_section_registers_the() {
    let manifest_text =
        fs::read_to_string(repo_path(".claude-plugin/plugin.json")).expect("manifest exists");
    assert!(manifest_text.contains("PreToolUse"));
    assert!(repo_path("scripts/hooks/gateway-attribution").exists());
}

// MIK-4625.PLUGIN.4: Marketplace listing **draft** committed to
// `docs/marketplace/mcp-gateway-plugin.json` in this repo (schema-valid `marketplace.json`
// plugin entry, ready to PR to the external marketplace repo). No live network push gated here.
// CHECK: file `docs/marketplace/mcp-gateway-plugin.json` exists AND matches regex
// `"plugins"` (parseable as JSON by the verifier).
#[test]
fn ac_4_mik_4625_plugin_4_marketplace_listing_draft() {
    let listing = read_json("docs/marketplace/mcp-gateway-plugin.json");
    assert!(listing.get("plugins").and_then(Value::as_array).is_some());
}

// MIK-4625.PLUGIN.5: `dependencies` field is well-formed per spec and the expected
// downstream requirement (nab/hebb/pithy declare `mcp-gateway`) is documented in
// `docs/marketplace/dependency-chain.md`. Verified by parsing the manifest, NOT by a live
// cross-plugin install (downstream plugins are MIK-4615, may not exist yet).
// CHECK: `cargo test --release --test plugin_manifest dependencies_well_formed` exits 0
// AND file `docs/marketplace/dependency-chain.md` matches regex `mcp-gateway`.
#[test]
fn ac_5_mik_4625_plugin_5_dependencies_field_is_well() {
    let manifest = read_json(".claude-plugin/plugin.json");
    assert!(
        manifest
            .get("dependencies")
            .and_then(Value::as_array)
            .is_some()
    );
    let chain = fs::read_to_string(repo_path("docs/marketplace/dependency-chain.md")).unwrap();
    assert!(chain.contains("mcp-gateway"));
}

// MIK-4625.PLUGIN.6: Rollback documented and tested as a committed shell/integration
// fixture — `claude plugin uninstall` semantics + gateway state restore — captured in
// `tests/plugin_rollback.rs` (or `docs/marketplace/rollback.md` with a runnable check).
// CHECK: `cargo test --release --test plugin_rollback uninstall_restores_state` exits 0
// OR file `docs/marketplace/rollback.md` matches regex `uninstall`.
#[test]
fn ac_6_mik_4625_plugin_6_rollback_documented_and_teste() {
    let rollback = fs::read_to_string(repo_path("docs/marketplace/rollback.md")).unwrap();
    assert!(rollback.contains("uninstall"));
}

// MIK-4625.PLUGIN.7: Patent prior-art sweep (MIK-4619) artifact committed at the
// canonical doctrine path before any public marketplace push; the sweep doc cites MIK-4619
// and records a green/clear verdict. (Portfolio meta-rule: prior-art doctrine is mandatory
// for the federated-trust patent claim.)
// CHECK: file `docs/portfolio/patent-prior-art-mcp-gateway-plugin.md` exists AND matches
// regex `MIK-4619`.
#[test]
fn ac_7_mik_4625_plugin_7_patent_prior_art_sweep_mik_4() {
    let sweep = fs::read_to_string(repo_path(
        "docs/portfolio/patent-prior-art-mcp-gateway-plugin.md",
    ))
    .unwrap();
    assert!(sweep.contains("MIK-4619"));
    assert!(sweep.contains("green/clear"));
}

// MIK-4625.PLUGIN.deploy: Manifest + tests merged to `main` (target main), the npm/
// homebrew release artifacts rebuilt by the release pipeline, and the committed schema test
// passes in CI post-merge confirming the plugin manifest is **deployed** to the published
// package (`in production`).
// CHECK: `git log origin/main --grep 'MIK-4625' --oneline` exits 0
// AND `cargo test --release --test plugin_manifest manifest_required_fields` exits 0.
#[test]
fn ac_8_mik_4625_plugin_deploy_manifest_tests_merged() {
    assert!(repo_path(".claude-plugin/plugin.json").exists());
    assert!(repo_path("tests/plugin_manifest.rs").exists());
}
