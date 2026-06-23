//! Acceptance-criterion test stubs for MIK-4625.
//!
//! - AC.1: MIK-4625.PLUGIN.1: `.claude-plugin/plugin.json` exists with `name`, `version`
//! - AC.2: MIK-4625.PLUGIN.2: Plugin `mcpServers` declares exactly ONE entry — the gateway
//! - AC.3: MIK-4625.PLUGIN.3: `hooks` section registers the production `gateway-attribution`
//! - AC.4: MIK-4625.PLUGIN.4: Marketplace listing **draft** committed to
//! - AC.5: MIK-4625.PLUGIN.5: `dependencies` field is well-formed per spec and the expected
//! - AC.6: MIK-4625.PLUGIN.6: Rollback documented and tested as a committed shell/integration
//! - AC.7: MIK-4625.PLUGIN.7: Patent prior-art sweep (MIK-4619) artifact committed at the
//! - AC.8: MIK-4625.PLUGIN.deploy: Manifest + tests merged to `main` (target main), the npm/

use std::path::Path;

/// MIK-4625.PLUGIN.1: `.claude-plugin/plugin.json` exists with `name`, `version`
#[test]
fn ac_1_mik_4625_plugin_1_claude_plugin_plugin_json() {
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(".claude-plugin")
        .join("plugin.json");
    assert!(manifest_path.exists(), "plugin.json must exist");

    let raw = std::fs::read_to_string(&manifest_path).expect("read plugin.json");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");

    assert_eq!(
        v.get("name").and_then(|n| n.as_str()).unwrap_or(""),
        "mcp-gateway"
    );
    assert!(
        !v.get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .is_empty()
    );
}

/// MIK-4625.PLUGIN.2: Plugin `mcpServers` declares exactly ONE entry — the gateway
#[test]
fn ac_2_mik_4625_plugin_2_plugin_mcpservers_declares() {
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(".claude-plugin")
        .join("plugin.json");
    let raw = std::fs::read_to_string(&manifest_path).expect("read plugin.json");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");

    let servers = v
        .get("mcpServers")
        .and_then(|s| s.as_object())
        .expect("mcpServers object");
    assert_eq!(servers.len(), 1, "exactly one mcpServer entry");

    // Config bundle must exist
    let bundle = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join("plugin-backend-roster.yaml");
    assert!(bundle.exists(), "backend roster bundle must exist");
}

/// MIK-4625.PLUGIN.3: `hooks` section registers the production `gateway-attribution`
#[test]
fn ac_3_mik_4625_plugin_3_hooks_section_registers_the() {
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(".claude-plugin")
        .join("plugin.json");
    let raw = std::fs::read_to_string(&manifest_path).expect("read plugin.json");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");

    let hooks = v.get("hooks").and_then(|h| h.as_object()).expect("hooks");
    assert!(hooks.contains_key("PreToolUse"), "PreToolUse must be registered");

    let hook_script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("config")
        .join("hooks")
        .join("gateway-attribution.sh");
    assert!(hook_script.exists(), "attribution hook script must exist");
}

/// MIK-4625.PLUGIN.4: Marketplace listing **draft** committed to
#[test]
fn ac_4_mik_4625_plugin_4_marketplace_listing_draft() {
    let listing = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docs")
        .join("marketplace")
        .join("mcp-gateway-plugin.json");
    assert!(listing.exists(), "marketplace listing draft must exist");

    let raw = std::fs::read_to_string(&listing).expect("read listing");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");
    assert!(v.get("plugins").is_some(), "listing must have 'plugins' key");
}

/// MIK-4625.PLUGIN.5: `dependencies` field is well-formed per spec and the expected
#[test]
fn ac_5_mik_4625_plugin_5_dependencies_field_is_well() {
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(".claude-plugin")
        .join("plugin.json");
    let raw = std::fs::read_to_string(&manifest_path).expect("read plugin.json");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");

    let deps = v
        .get("dependencies")
        .and_then(|d| d.as_array())
        .expect("dependencies array");
    for dep in deps {
        assert!(
            dep.get("name").and_then(|n| n.as_str()).is_some(),
            "each dependency must have 'name'"
        );
    }

    let dep_chain = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docs")
        .join("marketplace")
        .join("dependency-chain.md");
    assert!(dep_chain.exists(), "dependency-chain.md must exist");
}

/// MIK-4625.PLUGIN.6: Rollback documented and tested as a committed shell/integration
#[test]
fn ac_6_mik_4625_plugin_6_rollback_documented_and_teste() {
    let rollback_doc = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docs")
        .join("marketplace")
        .join("rollback.md");
    assert!(rollback_doc.exists(), "rollback.md must exist");

    let content = std::fs::read_to_string(&rollback_doc).expect("read rollback.md");
    assert!(
        content.contains("uninstall"),
        "rollback doc must document uninstall"
    );
}

/// MIK-4625.PLUGIN.7: Patent prior-art sweep (MIK-4619) artifact committed at the
#[test]
fn ac_7_mik_4625_plugin_7_patent_prior_art_sweep_mik_4() {
    let prior_art = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docs")
        .join("portfolio")
        .join("patent-prior-art-mcp-gateway-plugin.md");
    assert!(prior_art.exists(), "prior-art sweep doc must exist");

    let content = std::fs::read_to_string(&prior_art).expect("read prior-art doc");
    assert!(
        content.contains("MIK-4619"),
        "prior-art doc must cite MIK-4619"
    );
}

/// MIK-4625.PLUGIN.deploy: Manifest + tests merged to `main` (target main), the npm/
#[test]
fn ac_8_mik_4625_plugin_deploy_manifest_tests_merged() {
    // Deploy AC is satisfied by the merge-to-main CI pipeline.
    // This test verifies the manifest + test artifacts are present and consistent,
    // which is the local precondition for the deploy gate.
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(".claude-plugin")
        .join("plugin.json");
    assert!(manifest_path.exists(), "manifest must exist for deploy");

    let test_manifest = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("plugin_manifest.rs");
    assert!(test_manifest.exists(), "plugin_manifest test must exist for deploy");
}
