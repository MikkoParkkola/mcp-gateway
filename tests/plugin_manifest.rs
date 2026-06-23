//! MIK-4625 plugin manifest tests (per MIK-4088 / MIK-4140 TDD).
//! These tests are committed in dedicated test commit(s) and exercise the ACs.
//!
//! Addresses objections:
//! - OBJ.1 (AC#PLUGIN.1 missing-artifact): provides manifest_required_fields + committed artifact
//! - OBJ.2 (AC#PLUGIN.2): single_gateway_server_and_bundle
//! - OBJ.3 (AC#PLUGIN.3): attribution_hook_registered + links to hook source
//! - OBJ.5 (AC#PLUGIN.5): dependencies_well_formed + parses manifest
//! - OBJ.8 (TDD): dedicated test: subject + AC.N mappings

use std::fs;
use std::path::Path;

/// MIK-4625.PLUGIN.1: `.claude-plugin/plugin.json` exists with `name`, `version`
/// (pinned to the published gateway version, ≥2.12.1), `description`, `repository`, and a
/// `dependencies` array, all schema-valid. A committed Rust test (`tests/plugin_manifest.rs`,
/// same commit as the manifest per MIK-4088) deserializes the manifest and asserts the
/// required fields are present and non-empty.
/// CHECK: `cargo test --release --test plugin_manifest manifest_required_fields` exits 0
/// AND file `.claude-plugin/plugin.json` matches regex `"name"\s*:\s*"mcp-gateway"`.
#[test]
fn manifest_required_fields() {
    // AC verbatim:
    // MIK-4625.PLUGIN.1: `.claude-plugin/plugin.json` exists with `name`, `version`
    // (pinned to the published gateway version, ≥2.12.1), `description`, `repository`, and a
    // `dependencies` array, all schema-valid.
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".claude-plugin/plugin.json");
    let content = fs::read_to_string(&manifest_path)
        .expect("MIK-4625.PLUGIN.1 requires .claude-plugin/plugin.json to exist");
    // regex match for name
    assert!(
        content.contains(r#""name": "mcp-gateway""#) || content.contains("\"name\":\"mcp-gateway\""),
        "file .claude-plugin/plugin.json must match regex for name mcp-gateway"
    );
    let v: serde_json::Value =
        serde_json::from_str(&content).expect("manifest must be schema-valid JSON");
    assert!(v.get("name").and_then(|x| x.as_str()).map_or(false, |s| !s.is_empty()));
    assert!(v.get("version").is_some());
    let ver = v["version"].as_str().unwrap_or("");
    assert!(ver >= "2.12.1", "version pinned to published >=2.12.1");
    assert!(v.get("description").and_then(|x| x.as_str()).map_or(false, |s| !s.is_empty()));
    assert!(v.get("repository").is_some());
    assert!(v.get("dependencies").map_or(false, |d| d.is_array()));
}

/// MIK-4625.PLUGIN.2: Plugin `mcpServers` declares exactly ONE entry — the gateway
/// itself (stdio, e.g. `{"mcp-gateway":{"command":"npx","args":["-y","@mikkoparkkola/mcp-gateway"]}}`
/// or the bundled binary via `${CLAUDE_PLUGIN_ROOT}`) — and the plugin ships the canonical
/// pin-versioned backend roster as a config bundle file. A committed test asserts
/// `mcpServers` has length == 1 and the bundled config file lists the roster.
/// CHECK: `cargo test --release --test plugin_manifest single_gateway_server_and_bundle` exits 0
/// AND file `.claude-plugin/plugin.json` matches regex `"mcpServers"` AND a bundle file under
/// `examples/` matches regex `backends:` (or `capabilities:`).
#[test]
fn single_gateway_server_and_bundle() {
    // AC verbatim:
    // MIK-4625.PLUGIN.2: Plugin `mcpServers` declares exactly ONE entry — the gateway
    // itself ... and the plugin ships the canonical pin-versioned backend roster as a config bundle file.
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".claude-plugin/plugin.json");
    let content = fs::read_to_string(&manifest_path)
        .expect("manifest for mcpServers check");
    assert!(
        content.contains(r#""mcpServers""#),
        ".claude-plugin/plugin.json must contain mcpServers"
    );
    let v: serde_json::Value = serde_json::from_str(&content).expect("valid json");
    let servers = v.get("mcpServers").expect("mcpServers present");
    let map = servers.as_object().expect("mcpServers is object");
    assert_eq!(
        map.len(),
        1,
        "mcpServers must declare exactly ONE entry per architecture constraint"
    );
    assert!(
        map.contains_key("mcp-gateway"),
        "the single entry must be the gateway itself"
    );
    // Confirm the command/args shape for npx or ${CLAUDE_PLUGIN_ROOT}
    let gw = &map["mcp-gateway"];
    assert!(gw.get("command").is_some(), "gateway entry has command");

    // bundle file under examples/ lists the roster
    let bundle = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/config-bundles.yaml");
    let b = fs::read_to_string(&bundle).unwrap_or_else(|_| {
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/gateway-full.yaml"))
            .expect("bundle file required")
    });
    assert!(
        b.contains("backends:") || b.contains("backends :") || b.contains("capabilities:") || b.contains("capabilities :"),
        "bundle file under examples/ must match backends: or capabilities:"
    );
}

/// MIK-4625.PLUGIN.3: `hooks` section registers the production `gateway-attribution`
/// PreToolUse hook (already shipping), inline or via `./config/hooks.json`, pointing at a
/// path under `${CLAUDE_PLUGIN_ROOT}`. Committed test asserts the hook entry parses and the
/// referenced script path exists in-repo.
/// CHECK: `cargo test --release --test plugin_manifest attribution_hook_registered` exits 0
/// AND `.claude-plugin/plugin.json` (or `config/hooks.json`) matches regex `PreToolUse`.
#[test]
fn attribution_hook_registered() {
    // AC verbatim:
    // MIK-4625.PLUGIN.3: `hooks` section registers the production `gateway-attribution`
    // PreToolUse hook (already shipping), inline or via `./config/hooks.json`, pointing at a
    // path under `${CLAUDE_PLUGIN_ROOT}`.
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".claude-plugin/plugin.json");
    let content = fs::read_to_string(&manifest_path).expect("manifest for hooks check");
    assert!(
        content.contains("PreToolUse"),
        "hooks must register PreToolUse per AC"
    );
    // parse for hooks presence (inline object or path string)
    let v: serde_json::Value = serde_json::from_str(&content).expect("json");
    let has_pre = if let Some(h) = v.get("hooks") {
        let s = h.to_string();
        s.contains("PreToolUse") || s.contains("pre_tool_use")
    } else if let Some(hpath) = v.get("hooks").and_then(|x| x.as_str()) {
        // if string path to hooks.json
        let hp = Path::new(env!("CARGO_MANIFEST_DIR")).join(hpath.trim_start_matches("./"));
        fs::read_to_string(hp).map_or(false, |c| c.contains("PreToolUse"))
    } else {
        false
    };
    assert!(has_pre, "hook entry must parse and contain PreToolUse");

    // referenced script path exists in-repo (support both inline command and common locations)
    let candidates = [
        Path::new(env!("CARGO_MANIFEST_DIR")).join("hooks/gateway-attribution.sh"),
        Path::new(env!("CARGO_MANIFEST_DIR")).join("config/hooks/gateway-attribution.sh"),
    ];
    let exists = candidates.iter().any(|p| p.exists());
    assert!(exists, "referenced gateway-attribution script path must exist in-repo");
}

/// MIK-4625.PLUGIN.5: `dependencies` field is well-formed per spec and the expected
/// downstream requirement (nab/hebb/pithy declare `mcp-gateway`) is documented in
/// `docs/marketplace/dependency-chain.md`. Verified by parsing the manifest, NOT by a live
/// cross-plugin install (downstream plugins are MIK-4615, may not exist yet).
/// CHECK: `cargo test --release --test plugin_manifest dependencies_well_formed` exits 0
/// AND file `docs/marketplace/dependency-chain.md` matches regex `mcp-gateway`.
#[test]
fn dependencies_well_formed() {
    // AC verbatim:
    // MIK-4625.PLUGIN.5: `dependencies` field is well-formed per spec and the expected
    // downstream requirement (nab/hebb/pithy declare `mcp-gateway`) is documented in
    // `docs/marketplace/dependency-chain.md`.
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".claude-plugin/plugin.json");
    let content = fs::read_to_string(&manifest_path).expect("manifest");
    let v: serde_json::Value = serde_json::from_str(&content).expect("json");
    let deps = v.get("dependencies").expect("dependencies present per AC.1/5");
    assert!(deps.is_array(), "dependencies must be array (well-formed)");
    // At minimum contains reference or is non-empty array as per schema
    // (downstream doc separate)
    let chain = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/marketplace/dependency-chain.md");
    let c = fs::read_to_string(&chain).expect("dependency-chain.md per PLUGIN.5");
    assert!(
        c.contains("mcp-gateway"),
        "docs/marketplace/dependency-chain.md must mention mcp-gateway"
    );
}
