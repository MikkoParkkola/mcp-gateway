// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #1876: a client's server entry keeps its env, headers and argument
//! boundaries through discovery, and a commented Zed settings file is read.

use std::path::Path;

use serde_json::json;

use super::*;

const SENTINEL: &str = "SENTINEL-1876-secret-value";

fn entry(value: &serde_json::Value) -> DiscoveredServer {
    ConfigScanner::parse_server_config(
        "srv",
        value,
        &DiscoverySource::ClaudeDesktop,
        Path::new("/client/config.json"),
    )
    .expect("entry imports")
}

#[test]
fn stdio_env_is_kept() {
    let server =
        entry(&json!({"command": "npx", "args": ["-y", "srv"], "env": {"API_KEY": SENTINEL}}));
    assert_eq!(
        server.env.expose().get("API_KEY").map(String::as_str),
        Some(SENTINEL)
    );
}

#[test]
fn http_headers_are_kept() {
    let server = entry(
        &json!({"url": "https://mcp.example.test/mcp", "headers": {"Authorization": SENTINEL}}),
    );
    assert_eq!(
        server
            .headers
            .expose()
            .get("Authorization")
            .map(String::as_str),
        Some(SENTINEL)
    );
}

#[test]
fn arguments_keep_their_boundaries() {
    let args = ["--config", "/Users/a b/c.json", r#"say "hi""#, ""];
    let server = entry(&json!({"command": "/opt/My Tools/srv", "args": args}));
    let TransportConfig::Stdio { command, .. } = &server.transport else {
        panic!("expected stdio");
    };
    let mut expected = vec!["/opt/My Tools/srv".to_string()];
    expected.extend(args.iter().map(|a| (*a).to_string()));
    assert_eq!(crate::transport::split_command(command), Some(expected));
}

#[tokio::test]
async fn a_commented_zed_settings_file_is_read() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    let text = r#"// Zed settings
{
  "theme": "One Dark", // trailing comment
  /* block */
  "context_servers": {
    "local": { "command": "npx", "args": ["-y", "srv",], "env": { "K": "v", }, },
    "remote": { "url": "https://mcp.example.test/mcp", },
  },
}
"#;
    crate::gateway::test_helpers::write_owner_only(&path, text).unwrap();
    let servers = ConfigScanner::new().parse_zed_config(&path).await.unwrap();
    let names: Vec<&str> = servers.iter().map(|s| s.name.as_str()).collect();
    assert!(
        names.contains(&"local") && names.contains(&"remote"),
        "{names:?}"
    );
    let local = servers.iter().find(|s| s.name == "local").unwrap();
    assert_eq!(local.env.expose().get("K").map(String::as_str), Some("v"));
}

/// Log lines emitted while `run` executes, for the warning assertions.
fn with_logs<T>(run: impl FnOnce() -> T) -> (T, String) {
    #[derive(Clone, Default)]
    struct Sink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    // A process-wide registry keeps every callsite's interest open, so a
    // record is never filtered out before the scoped subscriber sees it.
    crate::test_log_capture::keep_interest_open();
    let sink = Sink::default();
    let writer = sink.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .with_writer(move || writer.clone())
        .finish();
    let out = tracing::subscriber::with_default(subscriber, run);
    let logs = String::from_utf8(sink.0.lock().unwrap().clone()).expect("utf-8 logs");
    (out, logs)
}

#[test]
fn client_variables_become_gateway_syntax_or_are_dropped() {
    let cases = [
        ("${env:API_KEY}", Some("${API_KEY}")),
        ("Bearer ${env:TOKEN}", Some("Bearer ${TOKEN}")),
        ("${env:A}:${env:B}", Some("${A}:${B}")),
        ("${API_KEY}", Some("${API_KEY}")),
        ("plain-value", Some("plain-value")),
        ("${input:token}", None),
        ("${workspaceFolder}/data", None),
        ("${userHome}/.cache", None),
        ("${env:lower_case}", None),
    ];
    for (client, gateway) in cases {
        assert_eq!(
            super::super::client_entry::gateway_value(client).as_deref(),
            gateway,
            "{client}"
        );
    }
}

#[test]
fn an_imported_config_with_client_variables_loads() {
    let (servers, logs) = with_logs(|| {
        let stdio = entry(&json!({"command": "npx", "env": {
            "FROM_ENV": "${env:PATH}",
            "FROM_INPUT": "${input:token}",
            "FROM_WORKSPACE": "${workspaceFolder}/data",
        }}));
        let http = entry(&json!({"url": "https://mcp.example.test/mcp", "headers": {
            "Authorization": "Bearer ${env:PATH}",
            "X-Home": "${userHome}",
        }}));
        (stdio, http)
    });
    let (stdio, http) = servers;
    let env = stdio.env.expose();
    assert_eq!(env.get("FROM_ENV").map(String::as_str), Some("${PATH}"));
    let headers = http.headers.expose();
    assert_eq!(
        headers.get("Authorization").map(String::as_str),
        Some("Bearer ${PATH}")
    );
    for (map, field) in [
        (env, "env.FROM_INPUT"),
        (env, "env.FROM_WORKSPACE"),
        (headers, "headers.X-Home"),
    ] {
        let key = field.split_once('.').expect("field").1;
        assert!(!map.contains_key(key), "{field} was kept");
        let warned = logs
            .lines()
            .any(|l| l.contains(field) && l.contains("srv") && l.contains("ClaudeDesktop"));
        assert!(warned, "{field} dropped without a warning: {logs}");
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    let mut config = crate::config::Config::default();
    config
        .backends
        .insert("stdio".to_string(), stdio.to_backend_config());
    config
        .backends
        .insert("http".to_string(), http.to_backend_config());
    crate::gateway::test_helpers::write_config_fixture(&path, &config).expect("config written");
    crate::config::Config::load(Some(&path)).expect("the written config loads");
}
