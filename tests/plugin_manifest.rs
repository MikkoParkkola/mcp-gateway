//! Plugin manifest validation tests for MIK-4625.
//!
//! Verifies the `.claude-plugin/plugin.json` manifest and supporting
//! artifacts satisfy every acceptance criterion for the mcp-gateway
//! Claude Code plugin substrate.

use serde_json::Value;
use std::path::Path;

/// Helper: read and parse `.claude-plugin/plugin.json` from the repo root.
fn load_plugin_manifest() -> Value {
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(".claude-plugin")
        .join("plugin.json");
    let raw = std::fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", manifest_path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("failed to parse plugin.json: {e}"))
}

/// MIK-4625.PLUGIN.1: `.claude-plugin/plugin.json` exists with `name`, `version`
/// (pinned to the published gateway version, ≥2.12.1), `description`, `repository`,
/// and a `dependencies` array, all schema-valid.
///
/// CHECK: `cargo test --release --test plugin_manifest manifest_required_fields` exits 0
/// AND file `.claude-plugin/plugin.json` matches regex `"name"\s*:\s*"mcp-gateway"`.
#[test]
fn manifest_required_fields() {
    let manifest = load_plugin_manifest();

    // name must be "mcp-gateway" (non-empty, exact match)
    let name = manifest
        .get("name")
        .and_then(Value::as_str)
        .expect("manifest must have 'name' field");
    assert_eq!(name, "mcp-gateway", "name must be 'mcp-gateway'");

    // version must be present, non-empty, and ≥ 2.12.1
    let version = manifest
        .get("version")
        .and_then(Value::as_str)
        .expect("manifest must have 'version' field");
    assert!(!version.is_empty(), "version must not be empty");
    let parts: Vec<u32> = version
        .split('.')
        .map(|p| p.parse().expect("version parts must be numeric"))
        .collect();
    assert!(parts.len() >= 2, "version must have at least major.minor");
    let major = parts[0];
    let minor = parts[1];
    assert!(
        (major, minor) >= (2, 12),
        "version must be ≥ 2.12.1, got {version}"
    );

    // description must be present and non-empty
    let description = manifest
        .get("description")
        .and_then(Value::as_str)
        .expect("manifest must have 'description' field");
    assert!(!description.is_empty(), "description must not be empty");

    // repository must be present and non-empty
    let repository = manifest
        .get("repository")
        .and_then(Value::as_str)
        .expect("manifest must have 'repository' field");
    assert!(
        !repository.is_empty(),
        "repository must not be empty"
    );

    // dependencies must be a non-empty array
    let dependencies = manifest
        .get("dependencies")
        .and_then(Value::as_array)
        .expect("manifest must have 'dependencies' array");
    assert!(
        !dependencies.is_empty(),
        "dependencies array must not be empty"
    );
}

/// MIK-4625.PLUGIN.2: Plugin `mcpServers` declares exactly ONE entry — the gateway
/// itself (stdio, e.g. `{"mcp-gateway":{"command":"npx","args":["-y",
/// "@mikkoparkkola/mcp-gateway"]}}` or the bundled binary via `${CLAUDE_PLUGIN_ROOT}`)
/// — and the plugin ships the canonical pin-versioned backend roster as a config
/// bundle file.
///
/// CHECK: `cargo test --release --test plugin_manifest single_gateway_server_and_bundle`
/// exits 0 AND file `.claude-plugin/plugin.json` matches regex `"mcpServers"` AND a
/// bundle file under `examples/` matches regex `backends:` (or `capabilities:`).
#[test]
fn single_gateway_server_and_bundle() {
    let manifest = load_plugin_manifest();

    // mcpServers must exist and be an object with exactly ONE entry
    let mcp_servers = manifest
        .get("mcpServers")
        .and_then(Value::as_object)
        .expect("manifest must have 'mcpServers' object");
    assert_eq!(
        mcp_servers.len(),
        1,
        "mcpServers must declare exactly ONE entry (the gateway), found {}",
        mcp_servers.len()
    );

    // The single entry must be keyed as "mcp-gateway"
    let gateway_entry = mcp_servers
        .get("mcp-gateway")
        .expect("mcpServers must contain 'mcp-gateway' entry");

    // Must have a command field (stdio transport)
    let command = gateway_entry
        .get("command")
        .and_then(Value::as_str)
        .expect("mcp-gateway server must have 'command' field");
    assert!(!command.is_empty(), "command must not be empty");

    // Verify the config bundle file exists under examples/
    let bundle_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join("plugin-backend-roster.yaml");
    assert!(
        bundle_path.exists(),
        "config bundle must exist at {}",
        bundle_path.display()
    );

    // The bundle must contain 'backends:' or 'capabilities:' markers
    let bundle_content = std::fs::read_to_string(&bundle_path)
        .unwrap_or_else(|e| panic!("failed to read bundle: {e}"));
    let has_backends = bundle_content.contains("backends:");
    let has_capabilities = bundle_content.contains("capabilities:");
    assert!(
        has_backends || has_capabilities,
        "config bundle must contain 'backends:' or 'capabilities:' section"
    );
}

/// MIK-4625.PLUGIN.3: `hooks` section registers the production `gateway-attribution`
/// `PreToolUse` hook (already shipping), inline or via `./config/hooks.json`, pointing
/// at a path under `${CLAUDE_PLUGIN_ROOT}`.
///
/// CHECK: `cargo test --release --test plugin_manifest attribution_hook_registered`
/// exits 0 AND `.claude-plugin/plugin.json` (or `config/hooks.json`) matches regex
/// `PreToolUse`.
#[test]
fn attribution_hook_registered() {
    let manifest = load_plugin_manifest();

    // hooks section must exist
    let hooks = manifest
        .get("hooks")
        .and_then(Value::as_object)
        .expect("manifest must have 'hooks' section");

    // PreToolUse hook must be registered
    let pre_tool_use = hooks
        .get("PreToolUse")
        .expect("hooks must contain 'PreToolUse' entry");

    // PreToolUse must be a non-empty array
    let hooks_array = pre_tool_use
        .as_array()
        .expect("PreToolUse must be an array");
    assert!(
        !hooks_array.is_empty(),
        "PreToolUse hooks array must not be empty"
    );

    // At least one hook must reference the gateway-attribution script
    let hooks_json = serde_json::to_string(&manifest).expect("serialize manifest");
    assert!(
        hooks_json.contains("gateway-attribution"),
        "hooks must reference gateway-attribution script"
    );

    // Verify the referenced hook script exists in-repo
    let hook_script_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("config")
        .join("hooks")
        .join("gateway-attribution.sh");
    assert!(
        hook_script_path.exists(),
        "hook script must exist at {}",
        hook_script_path.display()
    );
}

/// MIK-4625.PLUGIN.5: `dependencies` field is well-formed per spec and the expected
/// downstream requirement (nab/hebb/pithy declare `mcp-gateway`) is documented in
/// `docs/marketplace/dependency-chain.md`.
///
/// CHECK: `cargo test --release --test plugin_manifest dependencies_well_formed`
/// exits 0 AND file `docs/marketplace/dependency-chain.md` matches regex `mcp-gateway`.
#[test]
fn dependencies_well_formed() {
    let manifest = load_plugin_manifest();

    // dependencies must be an array
    let dependencies = manifest
        .get("dependencies")
        .and_then(Value::as_array)
        .expect("manifest must have 'dependencies' array");

    // Each dependency must have 'name' (string) and optionally 'version'
    for (i, dep) in dependencies.iter().enumerate() {
        let name = dep
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("dependency[{i}] must have 'name' string field"));
        assert!(!name.is_empty(), "dependency[{i}].name must not be empty");

        // version, if present, must be a non-empty string
        if let Some(version) = dep.get("version") {
            let v = version
                .as_str()
                .unwrap_or_else(|| panic!("dependency[{i}].version must be a string"));
            assert!(
                !v.is_empty(),
                "dependency[{i}].version must not be empty if present"
            );
        }
    }

    // Verify dependency-chain documentation exists and references mcp-gateway
    let dep_chain_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docs")
        .join("marketplace")
        .join("dependency-chain.md");
    assert!(
        dep_chain_path.exists(),
        "dependency-chain.md must exist at {}",
        dep_chain_path.display()
    );

    let dep_chain_content = std::fs::read_to_string(&dep_chain_path)
        .expect("failed to read dependency-chain.md");
    assert!(
        dep_chain_content.contains("mcp-gateway"),
        "dependency-chain.md must reference 'mcp-gateway'"
    );
}
