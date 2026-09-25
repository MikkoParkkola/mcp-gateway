// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7570.CONFIG.1 (C1): a config key the gateway does not recognise is a
//! load error, not silently ignored.
//!
//! Every row goes through the public `Config::load` on a real file, so the
//! refusal is proven on the path an operator's gateway takes.

use std::path::{Path, PathBuf};

use mcp_gateway::config::Config;

/// Write `yaml` to `gateway.yaml` in a fresh temp dir and load it.
fn load(yaml: &str) -> (tempfile::TempDir, PathBuf, mcp_gateway::Result<Config>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    std::fs::write(&path, yaml).expect("write config");
    let result = Config::load(Some(&path));
    (dir, path, result)
}

/// The refusal for `yaml`, which must name every one of `paths` and the file.
fn refusal(yaml: &str, paths: &[&str]) -> String {
    let (_dir, file, result) = load(yaml);
    let message = match result {
        Ok(_) => panic!("config with unrecognised key(s) {paths:?} loaded; it must be refused"),
        Err(error) => error.to_string(),
    };
    for path in paths {
        assert!(
            message.contains(path),
            "refusal must name `{path}`; got: {message}"
        );
    }
    assert!(
        message.contains(&file.display().to_string()),
        "refusal must name the config file; got: {message}"
    );
    message
}

#[test]
fn unrecognised_root_key_refused() {
    refusal("serverr: {}\n", &["serverr"]);
}

#[test]
fn unrecognised_nested_key_refused() {
    refusal("key_server:\n  enabeld: true\n", &["key_server.enabeld"]);
}

#[test]
fn unrecognised_key_in_sequence_refused() {
    refusal(
        "auth:\n  api_keys:\n    - key: \"c1-test-key-value-long-enough\"\n      name: a\n      bakends: [x]\n",
        &["auth.api_keys[0].bakends"],
    );
}

#[test]
fn unrecognised_key_under_flattened_backend_refused() {
    refusal(
        "backends:\n  x:\n    command: y\n    timout: 5s\n",
        &["backends.x.timout"],
    );
}

#[test]
fn all_unrecognised_keys_reported_together() {
    refusal(
        "serverr: {}\nkey_server:\n  enabeld: true\nbackends:\n  x:\n    command: y\n    timout: 5s\n",
        &["serverr", "key_server.enabeld", "backends.x.timout"],
    );
}

#[test]
fn retired_idle_timeout_refused_with_explanation() {
    let message = refusal(
        "backends:\n  x:\n    command: y\n    idle_timeout: 10m\n",
        &["backends.x.idle_timeout"],
    );
    assert!(
        message.contains("idle hibernation was never implemented"),
        "a retired key's refusal must carry its explanation; got: {message}"
    );
}

/// Gateway configs shipped in `examples/`. The two other YAML files there are
/// a playbook and a capability, which this loader never reads.
const SHIPPED_EXAMPLES: &[&str] = &[
    "circuit-breaker.yaml",
    "config-bundles.yaml",
    "config-fulcrum.yaml",
    "gateway-full.yaml",
    "gateway-minimal.yaml",
    "minimal.yaml",
    "per-client-tool-scopes.yaml",
    "servers.yaml",
    "token-exchange-live.yaml",
];

/// `deploy/helm/mcp-gateway/templates/configmap.yaml` rendered from the default
/// values with `auth.mode: credential` (`toYaml` sorts keys).
const HELM_CREDENTIAL: &str = "auth:
  bearer_token: env:MCP_GATEWAY_TOKEN
  enabled: true
  public_paths:
  - /health
backends: {}
security:
  firewall:
    enabled: true
    scan_requests: true
    scan_responses: true
server:
  host: 0.0.0.0
  port: 39400
  public_url: http://mcp-gateway.default.svc.cluster.local:39400
";

/// The same template with `auth.mode: mesh`.
const HELM_MESH: &str = "backends: {}
security:
  firewall:
    enabled: true
    scan_requests: true
    scan_responses: true
server:
  allow_unauthenticated_network_bind: true
  host: 0.0.0.0
  port: 39400
  public_url: http://mcp-gateway.default.svc.cluster.local:39400
";

/// `deploy/kubernetes/enterprise-alpha/base/configmap.yaml`, `gateway.yaml`.
const ENTERPRISE_ALPHA: &str = "server:
  host: 0.0.0.0
  port: 39400
  public_url: \"http://mcp-gateway.mcp-gateway.svc.cluster.local:39400\"
auth:
  enabled: true
  bearer_token: \"env:MCP_GATEWAY_TOKEN\"
  public_paths: [\"/health\"]
security:
  firewall:
    enabled: true
    scan_requests: true
    scan_responses: true
backends: {}
";

/// Positive control. The env layer lands `MCP_GATEWAY_*` as root keys, and
/// shipped deployments set `MCP_GATEWAY_TOKEN` and `MCP_GATEWAY_LOG_LEVEL`;
/// neither may be refused, and neither may any config this repository ships.
#[test]
fn env_root_keys_and_shipped_examples_load() {
    let mut failures = Vec::new();
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    for name in SHIPPED_EXAMPLES {
        if let Err(error) = Config::load(Some(&examples.join(name))) {
            failures.push(format!("examples/{name}: {error}"));
        }
    }
    for (label, body) in [
        ("helm credential", HELM_CREDENTIAL),
        ("helm mesh", HELM_MESH),
        ("enterprise-alpha", ENTERPRISE_ALPHA),
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let env = dir.path().join("gateway.env");
        std::fs::write(
            &env,
            "MCP_GATEWAY_TOKEN=c1-positive-control-token-0123456789abcdef\n\
             MCP_GATEWAY_LOG_LEVEL=info\nMCP_GATEWAY_LOG_FORMAT=json\n",
        )
        .expect("write env file");
        let yaml = format!("env_files: [\"{}\"]\n{body}", env.display());
        let (_dir, _path, result) = load(&yaml);
        if let Err(error) = result {
            failures.push(format!("{label}: {error}"));
        }
    }
    assert!(
        failures.is_empty(),
        "shipped configs refused:\n{}",
        failures.join("\n")
    );
}
