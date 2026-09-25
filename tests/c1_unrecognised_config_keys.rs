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
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, yaml).expect("write config");
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

/// `TransportConfig` is untagged, so a backend that names two transports
/// resolves to the first that fits and drops the other's keys in silence:
/// `command` wins, and `http_url` is read by nothing.
#[test]
fn keys_of_an_unselected_transport_refused() {
    let message = refusal(
        "backends:\n  x:\n    command: y\n    http_url: http://127.0.0.1:1/mcp\n",
        &["backends.x.http_url"],
    );
    assert!(
        !message.contains("backends.x.command"),
        "the selected transport's key is read; got: {message}"
    );
}

/// The gateway's YAML reader never applied merge keys, so `<<:` was a key
/// nothing read. It is refused like any other, where UPGRADING item 29 says.
#[test]
fn merge_key_refused_at_root() {
    refusal(
        "defaults: &defaults\n  host: 127.0.0.1\n<<: *defaults\n",
        &["<<", "defaults"],
    );
}

#[test]
fn merge_key_refused_under_a_backend() {
    refusal(
        "backends:\n  x:\n    command: y\n    <<: {timeout: 5s}\n",
        &["backends.x.<<"],
    );
}

#[test]
fn retired_backend_circuit_breaker_refused_with_explanation() {
    let message = refusal(
        "backends:\n  x:\n    command: y\n    circuit_breaker:\n      enabled: false\n",
        &["backends.x.circuit_breaker"],
    );
    assert!(
        message.contains("failsafe.circuit_breaker"),
        "the refusal must point at the breaker that is read; got: {message}"
    );
}

/// A non-string key under a backend cannot be matched against the key list;
/// it is refused rather than skipped.
#[test]
fn non_string_backend_key_refused() {
    refusal(
        "backends:\n  x:\n    command: y\n    5: true\n",
        &["backends.x.5"],
    );
}

/// A mapping key given twice. The loader keeps the last value and loads; a
/// bare YAML deserializer into `Config` stops at the second `server` with a
/// "duplicate field" error. The key check must follow the loader, or every key
/// after that point goes unchecked.
const REPEATED_KEY: &str = "server:\n  port: 39400\nserver:\n  port: 39400\n";

#[test]
fn value_the_loader_accepts_loads() {
    let (_dir, _path, result) = load(REPEATED_KEY);
    result.expect("a repeated mapping key loads, last value wins");
}

#[test]
fn unrecognised_key_after_a_loader_accepted_value_refused() {
    refusal(&format!("{REPEATED_KEY}serverr: {{}}\n"), &["serverr"]);
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

/// F15: the inbound WebSocket listener was removed; a config still naming its
/// port must fail to load and say why, not start with the port silently unbound.
#[test]
fn retired_server_ws_port_refused_with_explanation() {
    let message = refusal("server:\n  ws_port: 9000\n", &["server.ws_port"]);
    for part in [
        "inbound WebSocket listener was removed in 4.0",
        "never served MCP",
        "POST /mcp",
        "Remove server.ws_port",
    ] {
        assert!(
            message.contains(part),
            "retired ws_port refusal must say `{part}`; got: {message}"
        );
    }
}

/// F15: `ws_port: null`, the old example default, is refused as retired too.
#[test]
fn retired_server_ws_port_null_refused() {
    let message = refusal("server:\n  ws_port: null\n", &["server.ws_port"]);
    assert!(
        message.contains("inbound WebSocket listener was removed in 4.0"),
        "a null ws_port must carry the retired explanation; got: {message}"
    );
}

/// F15: the retirement names `server.ws_port` only; the same leaf under a
/// backend is an ordinary unknown key.
#[test]
fn backend_ws_port_is_an_ordinary_unknown_key() {
    let message = refusal(
        "backends:\n  x:\n    command: y\n    ws_port: 9000\n",
        &["backends.x.ws_port"],
    );
    assert!(
        message.contains("fix the spelling") && !message.contains("is retired"),
        "a backend ws_port must take the generic path; got: {message}"
    );
}

/// F15 control: a `server` section without `ws_port` still loads.
#[test]
fn server_section_without_ws_port_loads() {
    let (_dir, _path, result) = load("server:\n  host: 127.0.0.1\n  port: 9000\n");
    let config = result.expect("a server section without ws_port must load");
    assert_eq!(config.server.port, 9000);
}

/// YAML files in `examples/` that are not gateway configs: a playbook and a
/// capability, which this loader never reads. Every other `*.yaml` there is
/// swept, so a new example is covered without an edit here.
const NOT_GATEWAY_CONFIGS: &[&str] = &["playbook-morning-briefing.yaml", "transform-example.yaml"];

/// Loaded separately below: its `backends:` is null until completed.
const GATEWAY_FULL: &str = "gateway-full.yaml";

fn shipped_examples(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("read examples/")
        .map(|entry| {
            entry
                .expect("examples/ entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| Path::new(name).extension().is_some_and(|ext| ext == "yaml"))
        .filter(|name| name != GATEWAY_FULL && !NOT_GATEWAY_CONFIGS.contains(&name.as_str()))
        .collect();
    names.sort();
    names
}

/// Examples that already fail `Config::load` without C1, each with the text of
/// its error. They stay in the sweep so a C1 refusal of any of them still
/// fails it; the row is narrowed to "fails for this reason, not for a key".
const FAILS_BEFORE_C1: &[(&str, &str)] = &[
    // Needs FRONTEND_API_KEY and its siblings in the environment.
    (
        "per-client-tool-scopes.yaml",
        "missing environment variable",
    ),
    // An `oidc` rule with no audience is refused at load.
    (
        "token-exchange-live.yaml",
        "must declare at least one non-empty audience",
    ),
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
  transparency_log:
    enabled: true
    path: /var/lib/mcp-gateway/audit/transparency.jsonl
server:
  cleartext_http: cluster_internal
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
  cleartext_http: cluster_internal
auth:
  enabled: true
  bearer_token: \"env:MCP_GATEWAY_TOKEN\"
  public_paths: [\"/health\"]
security:
  firewall:
    enabled: true
    scan_requests: true
    scan_responses: true
  transparency_log:
    enabled: true
    path: /var/lib/mcp-gateway/audit/transparency.jsonl
backends: {}
";

/// Positive control. The env layer lands `MCP_GATEWAY_*` as root keys, and
/// shipped deployments set `MCP_GATEWAY_TOKEN` and `MCP_GATEWAY_LOG_LEVEL`;
/// neither may be refused, and neither may any config this repository ships.
#[test]
fn env_root_keys_and_shipped_examples_load() {
    let mut failures = Vec::new();
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    let names = shipped_examples(&examples);
    assert!(names.len() >= 8, "examples/ sweep found only {names:?}");
    for name in &names {
        // Through a 0600 copy: a git checkout is 0644, which CONFIG.2 refuses.
        let body = std::fs::read_to_string(examples.join(name)).expect("read example");
        // C4 refuses an unset `${VAR}` in an enabled backend, so the variables
        // the examples ask the operator to set are set, as an operator would.
        let vars = tempfile::tempdir().expect("tempdir");
        let body = if body.contains("${") && !body.contains("\nenv_files:") {
            let env = vars.path().join("example.env");
            mcp_gateway::gateway::test_helpers::write_owner_only(
                &env,
                "TAVILY_API_KEY=example-tavily-key\nCONTEXT7_TOKEN=example-context7-token\n",
            )
            .expect("write env file");
            format!("env_files: [\"{}\"]\n{body}", env.display())
        } else {
            body
        };
        let (_dir, _path, result) = load(&body);
        let expected = FAILS_BEFORE_C1.iter().find(|(file, _)| file == name);
        match (result, expected) {
            (Ok(_), None) => {}
            (Ok(_), Some(_)) => failures.push(format!(
                "examples/{name} now loads; drop it from FAILS_BEFORE_C1"
            )),
            (Err(error), Some((_, reason))) if error.to_string().contains(reason) => {}
            (Err(error), _) => failures.push(format!("examples/{name}: {error}")),
        }
    }
    // `gateway-full.yaml` documents every section and leaves `backends:` with
    // all entries commented out, which is null rather than a map and fails
    // before C1. Loaded with only that line completed, so every other key in
    // it goes through the check.
    let full = std::fs::read_to_string(examples.join(GATEWAY_FULL)).expect("read example");
    assert!(
        full.contains("\nbackends:\n"),
        "gateway-full.yaml layout changed"
    );
    let (_dir, _path, result) = load(&full.replace("\nbackends:\n", "\nbackends: {}\n"));
    if let Err(error) = result {
        failures.push(format!("examples/gateway-full.yaml: {error}"));
    }
    for (label, body) in [
        ("helm credential", HELM_CREDENTIAL),
        ("helm mesh", HELM_MESH),
        ("enterprise-alpha", ENTERPRISE_ALPHA),
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let env = dir.path().join("gateway.env");
        mcp_gateway::gateway::test_helpers::write_owner_only(
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

/// A reload that meets an unrecognised key is refused, and the running config
/// stays as it was: UPGRADING item 29 and the CHANGELOG promise both.
#[tokio::test]
async fn refused_reload_keeps_the_running_config() {
    use std::{sync::Arc, time::Duration};

    use mcp_gateway::{
        backend::{Backend, BackendRegistry},
        config_reload::{LiveConfig, ReloadContext},
    };

    let (_dir, path, result) =
        load("backends:\n  keep:\n    command: echo keep\n    description: before\n");
    let running = result.expect("valid startup config");
    let registry = Arc::new(BackendRegistry::new());
    for (name, config) in &running.backends {
        assert!(registry.register(Arc::new(Backend::new(
            name,
            config.clone(),
            &running.failsafe,
            Duration::from_secs(60),
        ))));
    }
    let live = Arc::new(LiveConfig::new(running.clone()));
    let context = ReloadContext::new(
        path.clone(),
        Arc::clone(&live),
        registry,
        running.failsafe.clone(),
        Duration::from_secs(60),
    );

    mcp_gateway::gateway::test_helpers::write_owner_only(
        &path,
        "backends:\n  keep:\n    command: echo keep\n    description: after\nserverr: {}\n",
    )
    .expect("write candidate");
    let refusal = context
        .reload()
        .await
        .expect_err("a reload with an unrecognised key must be refused");
    assert!(
        refusal.contains("serverr"),
        "the reload refusal must name the key; got: {refusal}"
    );
    assert_eq!(
        live.get().backends["keep"].description,
        "before",
        "a refused reload must keep the running config"
    );

    // Control: the same edit without the typo is published.
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &path,
        "backends:\n  keep:\n    command: echo keep\n    description: after\n",
    )
    .expect("write corrected candidate");
    context
        .reload()
        .await
        .expect("the corrected config reloads");
    assert_eq!(live.get().backends["keep"].description, "after");
}

/// C8: `server.request_timeout` was never enforced; a config still carrying it
/// must fail to load and point at the per-backend `timeout` that does bound calls.
#[test]
fn removed_request_timeout_is_refused() {
    let message = refusal(
        "server:\n  request_timeout: 30s\n",
        &["server.request_timeout"],
    );
    for part in [
        "removed in 4.0",
        "never enforced",
        "per-backend `timeout`",
        "Remove server.request_timeout",
    ] {
        assert!(
            message.contains(part),
            "retired request_timeout refusal must say `{part}`; got: {message}"
        );
    }
    // UPGRADING item 39 quotes the refusal verbatim; a reworded message must
    // update the guide too.
    let quote = "`server.request_timeout` is retired: the server-wide request timeout was \
                 removed in 4.0; it was never enforced. Calls are bounded by the per-backend \
                 `timeout`. Remove server.request_timeout.";
    assert!(message.contains(quote), "got: {message}");
    assert!(include_str!("../docs/UPGRADING-4.0.md").contains(quote));
}
