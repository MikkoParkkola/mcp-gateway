// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! P2c1 (MIK-8044 SURF.2): one backend `url` key. Its scheme picks the
//! transport; `http_url` and `ws_url` stay as hidden aliases. Every test goes
//! through `Config::load`, the path a user's file takes.

use super::*;

/// Writes `yaml` as `gateway.yaml` under `dir` and loads it.
fn load(dir: &std::path::Path, yaml: &str) -> Result<Config> {
    let path = dir.join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, yaml).expect("write config");
    Config::load(Some(&path))
}

/// The transport of backend `b` in a config holding only that backend.
fn transport_of(backend_yaml: &str) -> TransportConfig {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = load(dir.path(), &format!("backends:\n  b:\n{backend_yaml}"))
        .unwrap_or_else(|e| panic!("config loads: {e}"));
    config.backends["b"].transport.clone()
}

fn refusal(backend_yaml: &str) -> String {
    let dir = tempfile::tempdir().expect("tempdir");
    match load(dir.path(), &format!("backends:\n  b:\n{backend_yaml}")) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("expected the config to be refused, it loaded"),
    }
}

#[test]
fn an_http_url_builds_the_http_transport() {
    for url in ["http://127.0.0.1:9000/mcp", "https://mcp.example.com/mcp"] {
        match transport_of(&format!("    url: \"{url}\"\n")) {
            TransportConfig::Http { http_url, .. } => assert_eq!(http_url, url),
            other => panic!("{url} built {other:?}"),
        }
    }
}

#[test]
fn a_ws_url_builds_the_websocket_transport() {
    for url in ["ws://127.0.0.1:9000/mcp", "wss://mcp.example.com/mcp"] {
        match transport_of(&format!("    url: \"{url}\"\n")) {
            TransportConfig::WebSocket { ws_url, .. } => assert_eq!(ws_url, url),
            other => panic!("{url} built {other:?}"),
        }
    }
}

#[test]
fn url_with_an_alias_is_refused_naming_both() {
    for alias in ["http_url", "ws_url"] {
        let message = refusal(&format!(
            "    url: \"https://a.example.com/mcp\"\n    {alias}: \"https://b.example.com/mcp\"\n"
        ));
        assert!(
            message.contains("b.url") && message.contains(&format!("b.{alias}")),
            "{alias}: {message}"
        );
    }
}

#[test]
fn a_url_with_another_scheme_is_refused_naming_the_key() {
    // A URL can carry credentials, so the refusal names the key, never the URL.
    let message = refusal("    url: \"ftp://a.example.com/mcp?token=canary-p2c1\"\n");
    assert!(message.contains("b.url"), "{message}");
    assert!(
        !message.contains("canary-p2c1") && !message.contains("a.example.com"),
        "the refusal echoed the URL: {message}"
    );
}

#[test]
fn the_3x_keys_load_unchanged() {
    match transport_of("    http_url: \"https://a.example.com/mcp\"\n") {
        TransportConfig::Http { http_url, .. } => assert_eq!(http_url, "https://a.example.com/mcp"),
        other => panic!("http_url built {other:?}"),
    }
    match transport_of("    ws_url: \"wss://a.example.com/mcp\"\n") {
        TransportConfig::WebSocket { ws_url, .. } => assert_eq!(ws_url, "wss://a.example.com/mcp"),
        other => panic!("ws_url built {other:?}"),
    }
}

#[test]
fn cleartext_credentials_on_url_are_refused_as_on_the_alias() {
    let headers = "    headers:\n      Authorization: \"Bearer t\"\n";
    let via_url = refusal(&format!("    url: \"ws://10.0.0.5/mcp\"\n{headers}"));
    let via_alias = refusal(&format!("    ws_url: \"ws://10.0.0.5/mcp\"\n{headers}"));
    assert_eq!(via_url, via_alias);
}

#[test]
fn a_url_from_the_environment_is_refused_naming_the_variables_that_work() {
    // The file and environment layers merge key by key, so an environment
    // `url` could not replace a file `http_url`; it is refused, not ignored.
    let dir = tempfile::tempdir().expect("tempdir");
    let env = dir.path().join("gw.env");
    crate::gateway::test_helpers::write_owner_only(
        &env,
        "MCP_GATEWAY_BACKENDS__B__URL=wss://env.example.com/mcp\n",
    )
    .expect("write env file");
    let message = match load(
        dir.path(),
        &format!(
            "env_files: ['{}']\nbackends:\n  b:\n    url: \"https://file.example.com/mcp\"\n",
            env.display()
        ),
    ) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("an environment url was ignored instead of refused"),
    };
    assert!(
        message.contains("MCP_GATEWAY_BACKENDS__B__URL")
            && message.contains("MCP_GATEWAY_BACKENDS__B__HTTP_URL")
            && message.contains("MCP_GATEWAY_BACKENDS__B__WS_URL"),
        "{message}"
    );
    assert!(
        !message.contains("env.example.com"),
        "echoed the URL: {message}"
    );
}

#[test]
fn a_key_of_another_transport_beside_url_is_refused() {
    // `cwd` belongs to a stdio backend; beside an http `url` it would be
    // silently ignored, exactly as beside `http_url`.
    let message = refusal("    url: \"https://a.example.com/mcp\"\n    cwd: \"/tmp\"\n");
    assert!(message.contains("b.cwd"), "{message}");
}

#[test]
fn an_environment_transport_over_another_in_the_file_is_refused_naming_both() {
    // Before 4.0 the first transport key present won and the other was
    // dropped without a word, so this `ws_url` never took effect.
    let dir = tempfile::tempdir().expect("tempdir");
    let env = dir.path().join("gw.env");
    crate::gateway::test_helpers::write_owner_only(
        &env,
        "MCP_GATEWAY_BACKENDS__B__WS_URL=wss://env.example.com/mcp\n",
    )
    .expect("write env file");
    let message = match load(
        dir.path(),
        &format!(
            "env_files: ['{}']\nbackends:\n  b:\n    http_url: \"https://file.example.com/mcp\"\n",
            env.display()
        ),
    ) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("two transport keys loaded; one was silently dropped"),
    };
    assert!(
        message.contains("backend b has both http_url and ws_url; keep one"),
        "{message}"
    );
    assert!(!message.contains("example.com"), "echoed a URL: {message}");
}

#[test]
fn two_transport_keys_in_one_file_get_the_unread_key_refusal() {
    // Within one file the strict-key check names the key nothing reads, and
    // the file; the two-transport check covers the file-plus-environment case.
    let message = refusal("    command: \"srv\"\n    http_url: \"https://a.example.com/mcp\"\n");
    assert!(
        message.contains("backends.b.http_url") && !message.contains("backends.b.command"),
        "{message}"
    );
}

/// Writes an env file holding `env_line` and a config naming it with backend
/// `b` on `http_url`; returns the config path.
fn file_with_env(dir: &std::path::Path, env_line: &str) -> std::path::PathBuf {
    let env = dir.join("gw.env");
    crate::gateway::test_helpers::write_owner_only(&env, env_line).expect("write env file");
    let path = dir.join("gateway.yaml");
    let yaml = format!(
        "env_files: ['{}']\nbackends:\n  b:\n    http_url: \"https://file.example.com/mcp\"\n",
        env.display()
    );
    crate::gateway::test_helpers::write_owner_only(&path, &yaml).expect("write config");
    path
}

#[test]
fn an_environment_value_for_the_same_transport_key_still_overrides() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = file_with_env(
        dir.path(),
        "MCP_GATEWAY_BACKENDS__B__HTTP_URL=https://env.example.com/mcp\n",
    );
    let config = Config::load(Some(&path)).unwrap_or_else(|e| panic!("config loads: {e}"));
    match &config.backends["b"].transport {
        TransportConfig::Http { http_url, .. } => {
            assert_eq!(http_url, "https://env.example.com/mcp");
        }
        other => panic!("built {other:?}"),
    }
}

#[test]
fn a_literal_load_reads_the_file_alone_so_an_environment_transport_is_no_conflict() {
    // A rewrite loads the file without the environment layer; the file has one
    // transport key, so it loads and keeps it.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = file_with_env(
        dir.path(),
        "MCP_GATEWAY_BACKENDS__B__WS_URL=wss://env.example.com/mcp\n",
    );
    let config = Config::load_literal(Some(&path)).unwrap_or_else(|e| panic!("config loads: {e}"));
    assert!(
        matches!(config.backends["b"].transport, TransportConfig::Http { .. }),
        "{:?}",
        config.backends["b"].transport
    );
}

#[test]
fn a_url_holding_a_variable_names_the_environment_override() {
    // Backend addresses are never expanded, so `${FS_URL}` is not an address;
    // the way to take one from the environment is the override variable.
    let message = refusal("    url: \"${FS_URL}\"\n");
    assert!(
        message.contains("MCP_GATEWAY_BACKENDS__B__HTTP_URL")
            && message.contains("MCP_GATEWAY_BACKENDS__B__WS_URL")
            && message.contains("delete backends.b.url"),
        "{message}"
    );
}

/// A pair made by the environment alone, over a file that names no transport
/// for the backend, is refused naming both keys.
#[test]
fn a_transport_pair_from_the_environment_alone_is_refused_naming_both() {
    for (lines, keys) in [
        (
            "MCP_GATEWAY_BACKENDS__B__HTTP_URL=https://h.example.test/mcp\nMCP_GATEWAY_BACKENDS__B__WS_URL=wss://w.example.test/mcp\n",
            "http_url and ws_url",
        ),
        (
            "MCP_GATEWAY_BACKENDS__B__COMMAND=srv\nMCP_GATEWAY_BACKENDS__B__HTTP_URL=https://h.example.test/mcp\n",
            "command and http_url",
        ),
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let env = dir.path().join("gw.env");
        crate::gateway::test_helpers::write_owner_only(&env, lines).expect("write env file");
        let message = match load(
            dir.path(),
            &format!(
                "env_files: ['{}']\nbackends:\n  b:\n    description: from the environment\n",
                env.display()
            ),
        ) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("{keys}: a transport pair loaded; one was silently dropped"),
        };
        assert!(
            message.contains(&format!("backend b has both {keys}; keep one")),
            "{message}"
        );
    }
}
