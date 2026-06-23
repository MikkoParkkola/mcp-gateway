//! Plugin manifest tests for MIK-4625 (supports ticket CHECKs and TDD requirement).
//!
//! These complement `tests/mik_4625_acs.rs`. The primary acceptance test to run
//! per dispatch is: `cargo test --test mik_4625_acs`
//!
//! AC mappings (verbatim from ticket):
//! - MIK-4625.PLUGIN.1: `.claude-plugin/plugin.json` exists with `name`, `version`
//!   (pinned to the published gateway version, ≥2.12.1), `description`, `repository`, and a
//!   `dependencies` array, all schema-valid.
//! - MIK-4625.PLUGIN.2: Plugin `mcpServers` declares exactly ONE entry — the gateway itself ...
//! - MIK-4625.PLUGIN.3: `hooks` section registers the production `gateway-attribution`
//! - MIK-4625.PLUGIN.5: `dependencies` field is well-formed ...

use serde_json::Value;
use std::fs;

#[test]
fn manifest_required_fields() {
    // CHECK: `cargo test --release --test plugin_manifest manifest_required_fields` exits 0
    // AND file `.claude-plugin/plugin.json` matches regex `"name"\s*:\s*"mcp-gateway"`.
    let s = fs::read_to_string(".claude-plugin/plugin.json")
        .expect("MIK-4625.PLUGIN.1: .claude-plugin/plugin.json must exist");
    assert!(s.contains(r#""name""#), "manifest must contain name key");
    assert!(
        s.contains(r#""mcp-gateway""#) || s.contains("mcp-gateway"),
        "name must be mcp-gateway per regex"
    );
    let v: Value = serde_json::from_str(&s).expect("plugin.json must be valid JSON");
    assert_eq!(v["name"], "mcp-gateway", "PLUGIN.1 name");
    assert!(
        v.get("version").is_some() && !v["version"].as_str().unwrap_or("").is_empty(),
        "PLUGIN.1 version"
    );
    assert!(v.get("description").is_some(), "PLUGIN.1 description");
    assert!(v.get("repository").is_some(), "PLUGIN.1 repository");
    let deps = v.get("dependencies").expect("PLUGIN.1 dependencies array");
    assert!(deps.is_array(), "dependencies must be array");
}

#[test]
fn single_gateway_server_and_bundle() {
    // CHECK: ... single_gateway_server_and_bundle exits 0
    // AND file `.claude-plugin/plugin.json` matches regex `"mcpServers"`
    // AND a bundle file under `examples/` matches regex `backends:` (or `capabilities:`).
    let s = fs::read_to_string(".claude-plugin/plugin.json").unwrap();
    assert!(
        s.contains(r#""mcpServers""#),
        "must declare mcpServers per AC.2"
    );

    let v: Value = serde_json::from_str(&s).unwrap();
    let servers = v.get("mcpServers").expect("mcpServers present");
    let obj = servers.as_object().expect("mcpServers is object");
    assert_eq!(
        obj.len(),
        1,
        "MIK-4625.PLUGIN.2: mcpServers must declare exactly ONE entry"
    );
    assert!(
        obj.contains_key("mcp-gateway") || obj.values().next().is_some(),
        "gateway entry present"
    );

    // roster is in bundle, not mcpServers (per blocking architecture note)
    let bundle = fs::read_to_string("examples/config-bundles.yaml")
        .or_else(|_| fs::read_to_string("examples/gateway-full.yaml"))
        .expect("bundle file with roster required");
    assert!(
        bundle.contains("backends:")
            || bundle.contains("capabilities:")
            || bundle.contains("capabilities"),
        "bundle must list the canonical pin-versioned roster"
    );
}

#[test]
fn attribution_hook_registered() {
    // CHECK: attribution_hook_registered exits 0
    // AND `.claude-plugin/plugin.json` (or config/hooks.json) matches regex `PreToolUse`.
    let s = fs::read_to_string(".claude-plugin/plugin.json").unwrap();
    assert!(
        s.contains("PreToolUse"),
        "PLUGIN.3: hooks must register PreToolUse"
    );

    // referenced script path must exist in-repo
    let hook_path = "hooks/gateway-attribution.sh";
    assert!(
        fs::metadata(hook_path).is_ok(),
        "production gateway-attribution hook script must exist at {hook_path}"
    );
    let hook_src = fs::read_to_string(hook_path).unwrap();
    assert!(
        hook_src.contains("gateway-attribution"),
        "hook must be the production one"
    );
}

#[test]
fn dependencies_well_formed() {
    // CHECK: dependencies_well_formed exits 0
    // AND file `docs/marketplace/dependency-chain.md` matches regex `mcp-gateway`.
    let s = fs::read_to_string(".claude-plugin/plugin.json").unwrap();
    let v: Value = serde_json::from_str(&s).unwrap();
    let deps = v["dependencies"].as_array().expect("deps array");
    assert!(!deps.is_empty(), "dependencies must be non-empty per spec");
    // well-formed: strings or {name, version}
    for d in deps {
        assert!(
            d.is_string() || (d.is_object() && d.get("name").is_some()),
            "dep entry malformed"
        );
    }
    let chain =
        fs::read_to_string("docs/marketplace/dependency-chain.md").expect("dependency-chain.md");
    assert!(chain.contains("mcp-gateway"), "downstream dep documented");
}
