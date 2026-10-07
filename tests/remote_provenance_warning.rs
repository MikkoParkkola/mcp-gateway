// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #1943: a remote backend that runs without signed provenance is named in a
//! startup WARN and in `doctor`. The config leaves `remote_server_signing` out
//! entirely, so what loads is the shipped default.

use stdio_session::gateway_bin;

use std::path::Path;
use std::process::Stdio;

use mcp_gateway::config::Config;
use serde_json::Value;

#[path = "common/stdio_session.rs"]
mod stdio_session;
use stdio_session::StdioSession;

/// A remote backend with no provenance metadata. Port 9 (discard) refuses at
/// once, so no check waits on it.
const CONFIG: &str = "backends:\n  api:\n    http_url: \"http://127.0.0.1:9/mcp\"\n";

fn expected_warning() -> String {
    let config: Config = serde_yaml::from_str(CONFIG).expect("config parses");
    config
        .remote_provenance_warning()
        .expect("the backend runs unverified")
}

fn write_config(home: &Path) {
    mcp_gateway::gateway::test_helpers::write_owner_only(home.join("gateway.yaml"), CONFIG)
        .expect("write gateway.yaml");
}

#[tokio::test]
async fn a_stdio_start_warns_about_an_unverified_remote_backend() {
    let home = tempfile::tempdir().expect("temporary home");
    write_config(home.path());
    let (session, captured) = StdioSession::spawn_capturing_stderr(home.path());
    let lines = session.finish_capturing(captured).await;

    let expected = expected_warning();
    assert!(
        lines
            .iter()
            .any(|line| line.contains("WARN") && line.contains(&expected)),
        "no WARN with {expected:?} in stderr:\n{}",
        lines.join("\n")
    );
}

#[test]
fn doctor_reports_an_unverified_remote_backend() {
    let home = tempfile::tempdir().expect("temporary home");
    write_config(home.path());
    let mut command = gateway_bin::command(home.path(), gateway_bin::Inherit::Nothing);
    command.current_dir(home.path()).stdin(Stdio::null()).args([
        "doctor",
        "--config",
        "gateway.yaml",
        "--format",
        "json",
    ]);
    // A cleared environment loses the Windows system root the process needs to start.
    if let Some(root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", root);
    }
    if let Ok(profile) = std::env::var("LLVM_PROFILE_FILE") {
        command.env("LLVM_PROFILE_FILE", profile);
    }
    let out = command.output().expect("run doctor");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let report: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("doctor stdout is not JSON ({e}):\n{stdout}"));
    let row = report["checks"]
        .as_array()
        .expect("checks array")
        .iter()
        .find(|c| c["category"] == "remote_provenance")
        .unwrap_or_else(|| panic!("no remote_provenance finding in:\n{stdout}"));
    assert_eq!(row["status"], "warn");
    assert_eq!(row["detail"], expected_warning());
}
