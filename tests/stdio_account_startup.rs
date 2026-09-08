// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Real stdio startup admission, including the optional-directory control.
use serde_json::json;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

async fn startup(invalid_account: bool) -> (std::process::Output, bool) {
    let temp = tempfile::tempdir().expect("isolated home");
    let caps = temp.path().join("caps");
    if invalid_account {
        std::fs::create_dir(&caps).unwrap();
        std::fs::write(caps.join("bad.yaml"), "name: isolated_read\ndescription: Synthetic account admission probe\nauth:\n  required: true\n  type: bearer\n  key: oauth:google\n  account: no-such-account\nproviders:\n  primary:\n    service: rest\n    config:\n      base_url: http://127.0.0.1:9\n      path: /read\n      method: GET\n").unwrap();
    }
    let config = temp.path().join("gateway.yaml");
    std::fs::write(
        &config,
        format!(
            "capabilities:\n  enabled: true\n  directories:\n    - {}\n",
            caps.display()
        ),
    )
    .unwrap();
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_mcp-gateway"));
    command
        .args(["--config", config.to_str().unwrap(), "serve", "--stdio"])
        .current_dir(temp.path())
        .env("HOME", temp.path())
        .env("XDG_CONFIG_HOME", temp.path().join("config"))
        .env("XDG_DATA_HOME", temp.path().join("data"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("MCP_GATEWAY_") {
            command.env_remove(name);
        }
    }
    let mut child = command.spawn().expect("spawn shipped binary");
    let request = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"stdio-account-test","version":"1"}}});
    let mut stdin = child.stdin.take().unwrap();
    stdin
        .write_all(format!("{request}\n").as_bytes())
        .await
        .unwrap();
    drop(stdin);
    let output = tokio::time::timeout(Duration::from_secs(60), child.wait_with_output())
        .await
        .expect("startup must terminate after EOF")
        .expect("reap child");
    let initialized = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .any(|reply| reply["id"] == 1 && reply.get("result").is_some());
    (output, initialized)
}

#[tokio::test]
async fn missing_optional_directory_preserves_stdio_initialization() {
    let (output, initialized) = startup(false).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        initialized,
        "missing optional directory must still allow initialize"
    );
}

#[tokio::test]
async fn invalid_capability_account_refuses_before_stdio_initialization() {
    let (output, initialized) = startup(true).await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "invalid account binding must fail startup"
    );
    assert!(!initialized, "must refuse before serving initialize");
    assert!(
        stderr.contains("account admission gate") && stderr.contains("no-such-account"),
        "wrong startup failure: {stderr}"
    );
}
