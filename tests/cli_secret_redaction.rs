// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! End-to-end redaction tests for backend inspection commands.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::path::Path;
use std::process::Output;

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
    gateway_bin::command(
        config.parent().expect("the config sits in a temp dir"),
        gateway_bin::Inherit::Environment,
    )
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
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &config,
        format!(
            r#"backends:
  stdio-secret:
    command: "/usr/bin/example --token '{ARG_SECRET}' --mode safe"
    env:
      SAFE_ENV_NAME: "{ENV_SECRET}"
      FROM_KEYCHAIN: "keychain:gw.cli-ref"
    headers:
      Authorization: "{HEADER_SECRET}"
      X-Token: "env:CLI_REF_TOKEN"
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
    // A secret reference is shown as written by `get` (ADR-028, MIK-8908.KC.8),
    // and `list --json` stays names-only (MIK-7221).
    let get = combined_output(&outputs[0]);
    assert!(get.contains("FROM_KEYCHAIN=keychain:gw.cli-ref"), "{get}");
    assert!(get.contains("X-Token=env:CLI_REF_TOKEN"), "{get}");
    let list = combined_output(&outputs[2]);
    assert!(!list.contains("keychain:gw.cli-ref"), "{list}");
    assert!(!list.contains("env:CLI_REF_TOKEN"), "{list}");
    assert!(combined.contains("argument(s) redacted"));
    // The origin is kept so the endpoint is still identifiable; the path is not,
    // because that is where a webhook secret lives.
    assert!(combined.contains("https://svc.example.com"));
    assert!(
        !combined.contains("/services/"),
        "the path must not survive: {combined}"
    );
}
