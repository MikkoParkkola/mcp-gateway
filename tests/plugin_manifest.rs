use std::{fs, path::PathBuf};

use serde_json::Value;

fn repo_path(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn read_json(path: &str) -> Value {
    let content = fs::read_to_string(repo_path(path)).expect("json artifact should be readable");
    serde_json::from_str(&content).expect("json artifact should parse")
}

fn manifest() -> Value {
    read_json(".claude-plugin/plugin.json")
}

fn string_field<'a>(value: &'a Value, field: &str) -> &'a str {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| panic!("{field} should be a non-empty string"))
}

fn semver_at_least(version: &str, min_major: u64, min_minor: u64, min_patch: u64) -> bool {
    let parts: Vec<u64> = version
        .split('.')
        .map(str::parse)
        .collect::<Result<_, _>>()
        .expect("version should be numeric semver");
    assert_eq!(parts.len(), 3, "version should have major.minor.patch");
    [parts[0], parts[1], parts[2]] >= [min_major, min_minor, min_patch]
}

// MIK-4625.PLUGIN.1: `.claude-plugin/plugin.json` exists with `name`, `version`
// (pinned to the published gateway version, ≥2.12.1), `description`, `repository`, and a
// `dependencies` array, all schema-valid. A committed Rust test (`tests/plugin_manifest.rs`,
// same commit as the manifest per MIK-4088) deserializes the manifest and asserts the
// required fields are present and non-empty.
// CHECK: `cargo test --release --test plugin_manifest manifest_required_fields` exits 0
// AND file `.claude-plugin/plugin.json` matches regex `"name"\s*:\s*"mcp-gateway"`.
#[test]
fn manifest_required_fields() {
    let manifest = manifest();
    assert_eq!(string_field(&manifest, "name"), "mcp-gateway");
    assert!(semver_at_least(
        string_field(&manifest, "version"),
        2,
        12,
        1
    ));
    string_field(&manifest, "description");
    string_field(&manifest, "repository");
    assert!(
        manifest
            .get("dependencies")
            .and_then(Value::as_array)
            .is_some(),
        "dependencies should be an array"
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
fn single_gateway_server_and_bundle() {
    let manifest = manifest();
    let servers = manifest
        .get("mcpServers")
        .and_then(Value::as_object)
        .expect("mcpServers should be an object");
    assert_eq!(
        servers.len(),
        1,
        "plugin should expose exactly one MCP server"
    );

    let gateway = servers
        .get("mcp-gateway")
        .expect("single server should be the gateway");
    assert_eq!(gateway.get("command").and_then(Value::as_str), Some("npx"));
    let args = gateway
        .get("args")
        .and_then(Value::as_array)
        .expect("gateway args should be an array");
    assert!(
        args.iter()
            .any(|arg| arg.as_str() == Some("@mikkoparkkola/mcp-gateway@2.12.1")),
        "gateway package should be pinned"
    );

    let bundle_path = args
        .iter()
        .filter_map(Value::as_str)
        .find(|arg| arg.ends_with("examples/mcp-gateway-plugin-bundle.yaml"))
        .expect("manifest should reference the shipped plugin bundle")
        .replace("${CLAUDE_PLUGIN_ROOT}/", "");
    let bundle = fs::read_to_string(repo_path(&bundle_path)).expect("bundle should be readable");
    assert!(
        bundle.contains("backends:"),
        "bundle should declare backends"
    );
    let parsed: serde_yaml::Value = serde_yaml::from_str(&bundle).expect("bundle should parse");
    let backends = parsed
        .get("backends")
        .and_then(serde_yaml::Value::as_mapping)
        .expect("bundle should have a backend mapping");
    assert_eq!(
        backends.len(),
        29,
        "curated roster should contain 29 backends"
    );
}

// MIK-4625.PLUGIN.3: `hooks` section registers the production `gateway-attribution`
// PreToolUse hook (already shipping), inline or via `./config/hooks.json`, pointing at a
// path under `${CLAUDE_PLUGIN_ROOT}`. Committed test asserts the hook entry parses and the
// referenced script path exists in-repo.
// CHECK: `cargo test --release --test plugin_manifest attribution_hook_registered` exits 0
// AND `.claude-plugin/plugin.json` (or `config/hooks.json`) matches regex `PreToolUse`.
#[test]
fn attribution_hook_registered() {
    let manifest = manifest();
    let pre_tool_use = manifest
        .pointer("/hooks/PreToolUse")
        .and_then(Value::as_array)
        .expect("PreToolUse hook should be registered");
    let command = pre_tool_use
        .iter()
        .flat_map(|entry| {
            entry
                .get("hooks")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .find_map(|hook| hook.get("command").and_then(Value::as_str))
        .expect("PreToolUse hook should contain a command");

    assert!(
        command.starts_with("${CLAUDE_PLUGIN_ROOT}/"),
        "hook command should be rooted at CLAUDE_PLUGIN_ROOT"
    );
    assert!(
        command.contains("gateway-attribution"),
        "hook command should register gateway-attribution"
    );
    let script_path = command.replace("${CLAUDE_PLUGIN_ROOT}/", "");
    assert!(repo_path(&script_path).exists(), "hook script should exist");
}

// MIK-4625.PLUGIN.5: `dependencies` field is well-formed per spec and the expected
// downstream requirement (nab/hebb/pithy declare `mcp-gateway`) is documented in
// `docs/marketplace/dependency-chain.md`. Verified by parsing the manifest, NOT by a live
// cross-plugin install (downstream plugins are MIK-4615, may not exist yet).
// CHECK: `cargo test --release --test plugin_manifest dependencies_well_formed` exits 0
// AND file `docs/marketplace/dependency-chain.md` matches regex `mcp-gateway`.
#[test]
fn dependencies_well_formed() {
    let manifest = manifest();
    let dependencies = manifest
        .get("dependencies")
        .and_then(Value::as_array)
        .expect("dependencies should be an array");
    for dependency in dependencies {
        match dependency {
            Value::String(name) => assert!(!name.trim().is_empty()),
            Value::Object(object) => {
                assert!(
                    object
                        .get("name")
                        .and_then(Value::as_str)
                        .is_some_and(|name| !name.trim().is_empty()),
                    "object dependency should have a non-empty name"
                );
                if let Some(version) = object.get("version") {
                    assert!(
                        version
                            .as_str()
                            .is_some_and(|value| !value.trim().is_empty()),
                        "object dependency version should be a non-empty string"
                    );
                }
            }
            _ => panic!("dependency entries should be strings or objects"),
        }
    }

    let chain = fs::read_to_string(repo_path("docs/marketplace/dependency-chain.md"))
        .expect("dependency chain doc should be readable");
    for plugin in ["nab", "hebb", "pithy", "mcp-gateway"] {
        assert!(
            chain.contains(plugin),
            "dependency chain should mention {plugin}"
        );
    }
}
