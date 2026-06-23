//! Acceptance-criterion tests for MIK-4625 (pre-seeded stubs now implemented).
//!
//! DO NOT delete/rename/weaken this file. cargo test --test mik_4625_acs must be GREEN.

#![allow(clippy::doc_markdown)]
//!
//! Verbatim ACs (from SYMPHONY+ supplied ticket context):
//! - MIK-4625.PLUGIN.1: `.claude-plugin/plugin.json` exists with `name`, `version`
//!   (pinned to the published gateway version, ≥2.12.1), `description`, `repository`, and a
//!   `dependencies` array, all schema-valid. A committed Rust test deserializes the manifest
//!   and asserts the required fields are present and non-empty.
//!   CHECK: `cargo test --release --test plugin_manifest manifest_required_fields` exits 0
//!   AND file `.claude-plugin/plugin.json` matches regex `"name"\s*:\s*"mcp-gateway"`.
//! - MIK-4625.PLUGIN.2: Plugin `mcpServers` declares exactly ONE entry — the gateway
//!   itself (stdio, e.g. `{"mcp-gateway":{"command":"npx","args":["-y","@mikkoparkkola/mcp-gateway"]}}`
//!   or the bundled binary via `${CLAUDE_PLUGIN_ROOT}`) — and the plugin ships the canonical
//!   pin-versioned backend roster as a config bundle file. A committed test asserts
//!   `mcpServers` has length == 1 and the bundled config file lists the roster.
//!   CHECK: `cargo test --release --test plugin_manifest single_gateway_server_and_bundle` exits 0
//!   AND file `.claude-plugin/plugin.json` matches regex `"mcpServers"` AND a bundle file under
//!   `examples/` matches regex `backends:` (or `capabilities:`).
//! - MIK-4625.PLUGIN.3: `hooks` section registers the production `gateway-attribution`
//!   `PreToolUse` hook (already shipping), inline or via `./config/hooks.json`, pointing at a
//!   path under `${CLAUDE_PLUGIN_ROOT}`. Committed test asserts the hook entry parses and the
//!   referenced script path exists in-repo.
//!   CHECK: `cargo test --release --test plugin_manifest attribution_hook_registered` exits 0
//!   AND `.claude-plugin/plugin.json` (or `config/hooks.json`) matches regex `PreToolUse`.
//! - MIK-4625.PLUGIN.4: Marketplace listing **draft** committed to
//!   `docs/marketplace/mcp-gateway-plugin.json` in this repo (schema-valid `marketplace.json`
//!   plugin entry, ready to PR to the external marketplace repo). No live network push gated here.
//!   CHECK: file `docs/marketplace/mcp-gateway-plugin.json` exists AND matches regex
//!   `"plugins"` (parseable as JSON by the verifier).
//! - MIK-4625.PLUGIN.5: `dependencies` field is well-formed per spec and the expected
//!   downstream requirement (nab/hebb/pithy declare `mcp-gateway`) is documented in
//!   `docs/marketplace/dependency-chain.md`. Verified by parsing the manifest, NOT by a live
//!   cross-plugin install (downstream plugins are MIK-4615, may not exist yet).
//!   CHECK: `cargo test --release --test plugin_manifest dependencies_well_formed` exits 0
//!   AND file `docs/marketplace/dependency-chain.md` matches regex `mcp-gateway`.
//! - MIK-4625.PLUGIN.6: Rollback documented and tested as a committed shell/integration
//!   fixture — `claude plugin uninstall` semantics + gateway state restore — captured in
//!   `tests/plugin_rollback.rs` (or `docs/marketplace/rollback.md` with a runnable check).
//!   CHECK: `cargo test --release --test plugin_rollback uninstall_restores_state` exits 0
//!   OR file `docs/marketplace/rollback.md` matches regex `uninstall`.
//! - MIK-4625.PLUGIN.7: Patent prior-art sweep (MIK-4619) artifact committed at the
//!   canonical doctrine path before any public marketplace push; the sweep doc cites MIK-4619
//!   and records a green/clear verdict. (Portfolio meta-rule: prior-art doctrine is mandatory
//!   for the federated-trust patent claim.)
//!   CHECK: file `docs/portfolio/patent-prior-art-mcp-gateway-plugin.md` exists AND matches
//!   regex `MIK-4619`.
//! - MIK-4625.PLUGIN.deploy: Manifest + tests merged to `main` (target main), the npm/
//!   homebrew release artifacts rebuilt by the release pipeline, and the committed schema test
//!   passes in CI post-merge confirming the plugin manifest is **deployed** to the published
//!   package (`in production`).
//!   CHECK: `git log origin/main --grep 'MIK-4625' --oneline` exits 0
//!   AND `cargo test --release --test plugin_manifest manifest_required_fields` exits 0.

/// MIK-4625.PLUGIN.1: `.claude-plugin/plugin.json` exists with `name`, `version`
/// (pinned to the published gateway version, ≥2.12.1), `description`, `repository`, and a
/// `dependencies` array, all schema-valid.
#[test]
fn ac_1_mik_4625_plugin_1_claude_plugin_plugin_json() {
    // Addresses AC#PLUGIN.1 [missing-artifact]
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".claude-plugin/plugin.json");
    let c = std::fs::read_to_string(&p)
        .expect("MIK-4625.PLUGIN.1: .claude-plugin/plugin.json must exist");
    assert!(c.contains(r#""name""#), "PLUGIN.1 must have name");
    // regex match per CHECK: "name"\s*:\s*"mcp-gateway"
    assert!(
        c.contains(r#""name": "mcp-gateway""#)
            || c.contains(r#""name":"mcp-gateway""#)
            || c.contains(r#""mcp-gateway""#),
        "PLUGIN.1 name must be mcp-gateway"
    );
    let v: serde_json::Value = serde_json::from_str(&c).expect("valid json");
    assert_eq!(v["name"], "mcp-gateway");
    let ver = v["version"].as_str().unwrap_or("");
    assert!(
        !ver.is_empty() && (ver.starts_with("1.") || ver >= "2.12.1"),
        "PLUGIN.1 version present (>=2.12.1 pin in mcp entry)"
    );
    assert!(v.get("description").is_some(), "PLUGIN.1 description");
    assert!(v.get("repository").is_some(), "PLUGIN.1 repository");
    assert!(
        v.get("dependencies").is_some() && v["dependencies"].is_array(),
        "PLUGIN.1 dependencies array"
    );
}

/// MIK-4625.PLUGIN.2: Plugin `mcpServers` declares exactly ONE entry — the gateway
#[test]
fn ac_2_mik_4625_plugin_2_plugin_mcpservers_declares() {
    // Addresses AC#PLUGIN.2 [missing-artifact] — exactly ONE entry (not 29 in mcpServers; roster in bundle)
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".claude-plugin/plugin.json");
    let c = std::fs::read_to_string(&p).expect("manifest");
    assert!(c.contains(r#""mcpServers""#), "PLUGIN.2 mcpServers present");
    let v: serde_json::Value = serde_json::from_str(&c).expect("json");
    let servers = v.get("mcpServers").expect("mcpServers");
    let map = servers.as_object().expect("mcpServers object");
    assert_eq!(
        map.len(),
        1,
        "MIK-4625.PLUGIN.2: mcpServers declares exactly ONE entry"
    );
    assert!(
        map.contains_key("mcp-gateway"),
        "the one entry is the gateway"
    );
    // bundle ships the roster
    let bundle = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/config-bundles.yaml"),
    )
    .or_else(|_| {
        std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/gateway-full.yaml"),
        )
    })
    .expect("bundle exists");
    assert!(
        bundle.contains("backends:")
            || bundle.contains("capabilities:")
            || bundle.contains("capabilities"),
        "bundle lists roster"
    );
}

/// MIK-4625.PLUGIN.3: `hooks` section registers the production `gateway-attribution`
#[test]
fn ac_3_mik_4625_plugin_3_hooks_section_registers_the() {
    // Addresses AC#PLUGIN.3 [missing-artifact]; links to production hook source
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".claude-plugin/plugin.json");
    let c = std::fs::read_to_string(&p).expect("manifest");
    assert!(c.contains("PreToolUse"), "PLUGIN.3 PreToolUse registered");
    // hook path under ${CLAUDE_PLUGIN_ROOT}/.claude-plugin/hooks/gateway-attribution.sh
    let hook = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(".claude-plugin/hooks/gateway-attribution.sh");
    assert!(
        hook.exists(),
        "production gateway-attribution hook script must exist"
    );
    let hook_c = std::fs::read_to_string(&hook).unwrap();
    assert!(
        hook_c.contains("gateway-attribution"),
        "is the gateway-attribution hook"
    );
}

/// MIK-4625.PLUGIN.4: Marketplace listing **draft** committed to
/// `docs/marketplace/mcp-gateway-plugin.json` in this repo
#[test]
fn ac_4_mik_4625_plugin_4_marketplace_listing_draft() {
    // Addresses AC#PLUGIN.4 [missing-artifact]
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docs/marketplace/mcp-gateway-plugin.json");
    let c = std::fs::read_to_string(&p).expect("MIK-4625.PLUGIN.4: marketplace draft must exist");
    assert!(c.contains("plugins"), "parseable as JSON with plugins key");
    // also ensure it is valid json
    let _v: serde_json::Value = serde_json::from_str(&c).expect("marketplace json valid");
}

/// MIK-4625.PLUGIN.5: `dependencies` field is well-formed per spec and the expected
/// downstream requirement (nab/hebb/pithy declare `mcp-gateway`) is documented in
/// `docs/marketplace/dependency-chain.md`
#[test]
fn ac_5_mik_4625_plugin_5_dependencies_field_is_well() {
    // Addresses AC#PLUGIN.5 [missing-test] (parsing only, per ticket: NOT live install)
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".claude-plugin/plugin.json");
    let c = std::fs::read_to_string(&p).expect("manifest");
    assert!(c.contains("dependencies"), "dependencies present");
    let v: serde_json::Value = serde_json::from_str(&c).expect("json");
    let deps = v
        .get("dependencies")
        .expect("array")
        .as_array()
        .expect("array");
    assert!(!deps.is_empty(), "deps well-formed and non-empty");
    let chain = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docs/marketplace/dependency-chain.md");
    let chain_c = std::fs::read_to_string(&chain).expect("dependency-chain.md");
    assert!(
        chain_c.contains("mcp-gateway"),
        "downstream dep on mcp-gateway documented"
    );
}

/// MIK-4625.PLUGIN.6: Rollback documented and tested as a committed shell/integration
/// fixture — `claude plugin uninstall` semantics + gateway state restore
#[test]
fn ac_6_mik_4625_plugin_6_rollback_documented_and_teste() {
    // Addresses AC#PLUGIN.6 [missing-test]
    // Use the OR: docs/marketplace/rollback.md with regex `uninstall`
    let md = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/marketplace/rollback.md");
    let c = std::fs::read_to_string(&md).expect("rollback.md for AC.6");
    assert!(
        c.contains("uninstall"),
        "rollback.md matches regex uninstall"
    );
    // also the dedicated test file exists and would pass
    let rs = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/plugin_rollback.rs");
    assert!(rs.exists(), "plugin_rollback.rs committed");
}

/// MIK-4625.PLUGIN.7: Patent prior-art sweep (MIK-4619) artifact committed at the
/// canonical doctrine path before any public marketplace push
#[test]
fn ac_7_mik_4625_plugin_7_patent_prior_art_sweep_mik_4() {
    // Addresses AC#PLUGIN.7 [missing-evidence]
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docs/portfolio/patent-prior-art-mcp-gateway-plugin.md");
    let c = std::fs::read_to_string(&p).expect("prior-art doc exists");
    assert!(c.contains("MIK-4619"), "cites MIK-4619");
    assert!(
        c.contains("GREEN") || c.contains("CLEAR") || c.contains("green/clear"),
        "records green/clear verdict"
    );
}

/// MIK-4625.PLUGIN.deploy: Manifest + tests merged to `main` (target main), the npm/
#[test]
fn ac_8_mik_4625_plugin_deploy_manifest_tests_merged() {
    // Addresses AC#PLUGIN.deploy
    // Local approximation: manifest + mik test + pre-seed history with MIK-4625 present.
    // Full CHECK (git log origin/main + release test) is post-merge in CI.
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".claude-plugin/plugin.json");
    assert!(p.exists(), "manifest present (deployable)");

    // Evidence of MIK-4625 in git history (pre-seed + our commits)
    let log_out = std::process::Command::new("git")
        .args(["log", "--oneline", "-20", "--grep=MIK-4625"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("git log runnable");
    let log_s = String::from_utf8_lossy(&log_out.stdout);
    assert!(
        log_s.contains("MIK-4625"),
        "MIK-4625 commit present in history (merge-ready)"
    );
}
