// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8001.ROUTE.2: a debug child given `MCP_GATEWAY_TEST_HOME_DIR` puts its
//! OAuth token directory under that home, not under `HOME`.
//!
//! On Windows `dirs::home_dir()` ignores `HOME` and `USERPROFILE`, so before
//! the fix the red run creates `.mcp-gateway/oauth` in the runner's real home.
//! CI runners are ephemeral; on Linux and macOS the red run lands in `HOME`,
//! a temp dir here, and never touches the real home.
//!
//! Debug builds only: release builds compile the override out on purpose.
#![cfg(debug_assertions)]

use std::process::Stdio;

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

// Port 1 refuses at once, so the call fails offline after the executor
// (and its token storage) is built.
const CAPABILITY: &str = "name: home_probe
description: Reads one endpoint.
providers:
  primary:
    config:
      base_url: http://127.0.0.1:1
      path: /v1
";

#[test]
fn the_oauth_token_directory_follows_the_test_home() {
    let fixture_home = tempfile::tempdir().expect("tempdir");
    let env_home = tempfile::tempdir().expect("tempdir");
    let file = fixture_home.path().join("home_probe.yaml");
    std::fs::write(&file, CAPABILITY).expect("write capability");

    let out = gateway_bin::command_with_env_home(
        fixture_home.path(),
        env_home.path(),
        gateway_bin::Inherit::Environment,
    )
    .stdin(Stdio::null())
    .args(["cap", "test"])
    .arg(&file)
    .output()
    .expect("run mcp-gateway");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(
        fixture_home.path().join(".mcp-gateway/oauth").is_dir(),
        "the token directory is under the test home: {text}"
    );
    assert!(
        !env_home.path().join(".mcp-gateway/oauth").exists(),
        "nothing lands under HOME: {text}"
    );
}
