// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! End-to-end redaction tests for backend inspection commands.

use std::path::Path;
use std::process::{Command, Output};

const ENV_SECRET: &str = "SENTINEL_CLI_ENV_37a1";
const HEADER_SECRET: &str = "SENTINEL_CLI_HEADER_84dc";
const ARG_SECRET: &str = "SENTINEL_CLI_ARG_b515";
const URL_USER_SECRET: &str = "SENTINEL_CLI_URL_USER_6d9b";
const URL_QUERY_SECRET: &str = "SENTINEL_CLI_URL_QUERY_efe2";
const URL_FRAGMENT_SECRET: &str = "SENTINEL_CLI_URL_FRAGMENT_d209";
/// Webhook-style: the secret IS the path. Slack and Discord both work this way,
/// and an origin+path sanitiser — the conventional one — leaks it whole.
const URL_PATH_SECRET: &str = "SENTINEL_CLI_URL_PATH_c0f4";

fn run_gateway(config: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mcp-gateway"))
        .args(args)
        .arg("--config")
        .arg(config)
        .output()
        .expect("run mcp-gateway")
}

fn combined_output(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn backend_inspection_commands_never_print_config_secrets() {
    let dir = tempfile::tempdir().expect("create CLI redaction workspace");
    let config = dir.path().join("gateway.yaml");
    std::fs::write(
        &config,
        format!(
            r#"backends:
  stdio-secret:
    command: "/usr/bin/example --token '{ARG_SECRET}' --mode safe"
    env:
      SAFE_ENV_NAME: "{ENV_SECRET}"
    headers:
      Authorization: "{HEADER_SECRET}"
  http-secret:
    http_url: "https://user:{URL_USER_SECRET}@svc.example.com/services/{URL_PATH_SECRET}?token={URL_QUERY_SECRET}#{URL_FRAGMENT_SECRET}"
"#
        ),
    )
    .expect("write CLI redaction config");

    let outputs = [
        run_gateway(&config, &["get", "stdio-secret"]),
        run_gateway(&config, &["get", "http-secret"]),
        run_gateway(&config, &["list", "--json"]),
    ];
    for output in &outputs {
        assert!(
            output.status.success(),
            "CLI failed: {}",
            combined_output(output)
        );
    }
    let combined = outputs.iter().map(combined_output).collect::<String>();

    for sentinel in [
        ENV_SECRET,
        HEADER_SECRET,
        ARG_SECRET,
        URL_USER_SECRET,
        URL_QUERY_SECRET,
        URL_FRAGMENT_SECRET,
        URL_PATH_SECRET,
    ] {
        assert!(
            !combined.contains(sentinel),
            "CLI leaked {sentinel}: {combined}"
        );
    }
    assert!(combined.contains("SAFE_ENV_NAME=<set>"));
    assert!(combined.contains("Authorization=<set>"));
    assert!(combined.contains("argument(s) redacted"));
    // The origin is kept so the endpoint is still identifiable; the path is not,
    // because that is where a webhook secret lives.
    assert!(combined.contains("https://svc.example.com"));
    assert!(
        !combined.contains("/services/"),
        "the path must not survive: {combined}"
    );
}

/// A token set only through `MCP_GATEWAY_AUTH__BEARER_TOKEN` must stay in the
/// environment. `add` rewrites gateway.yaml from what it loaded, so a load
/// that merged the override writes the token to disk.
#[test]
fn add_keeps_an_environment_override_out_of_gateway_yaml() {
    const ENV_TOKEN: &str = "SENTINEL_CLI_ENV_OVERRIDE_9b3e";
    let dir = tempfile::tempdir().expect("create CLI workspace");
    let config = dir.path().join("gateway.yaml");
    std::fs::write(&config, "backends: {}\n").expect("write config");

    let output = Command::new(env!("CARGO_BIN_EXE_mcp-gateway"))
        .args(["add", "local", "--command", "echo hi", "--config"])
        .arg(&config)
        .env("MCP_GATEWAY_AUTH__BEARER_TOKEN", ENV_TOKEN)
        .env("MCP_GATEWAY_SERVER__PORT", "39464")
        .output()
        .expect("run mcp-gateway");
    assert!(
        output.status.success(),
        "add failed: {}",
        combined_output(&output)
    );

    let written = std::fs::read_to_string(&config).expect("read config");
    assert!(written.contains("local:"), "add wrote nothing:\n{written}");
    assert!(
        !written.contains(ENV_TOKEN),
        "the environment-only token was written to disk:\n{written}"
    );
    assert!(
        !written.contains("39464"),
        "the environment-only port was written to disk:\n{written}"
    );
}
