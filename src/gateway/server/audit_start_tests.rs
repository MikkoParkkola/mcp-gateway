// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D1-T3 — with auth on, an audit log that cannot open stops the gateway.
//!
//! Drives `build_meta_mcp`, the step both `run` and `run_stdio` take before
//! they bind or read anything.

use super::Gateway;
use crate::config::Config;

/// Auth on, and the log path's parent is a regular file, so the open fails
/// for every user including root.
async fn gateway(auth: bool, dir: &tempfile::TempDir) -> Gateway {
    let blocker = dir.path().join("not-a-dir");
    std::fs::write(&blocker, b"x").expect("blocker file");
    let mut config = Config::default();
    config.auth.enabled = auth;
    config.auth.bearer_token = Some("d1-start-test-token-0123456789abcdef".to_string());
    config.security.transparency_log.enabled = true;
    config.security.transparency_log.path =
        blocker.join("audit.jsonl").to_string_lossy().into_owned();
    Gateway::new(config)
        .await
        .expect("the config itself is valid")
}

#[tokio::test]
async fn audit_log_open_failure_refuses_serve_with_auth() {
    let dir = tempfile::tempdir().unwrap();
    let gateway = gateway(true, &dir).await;
    assert!(
        gateway.build_meta_mcp().await.is_err(),
        "auth is on and the audit log cannot open, so the gateway must not start"
    );
}

/// Positive control: auth off keeps today's warn-and-continue.
#[tokio::test]
async fn audit_log_open_failure_with_auth_off_still_starts() {
    let dir = tempfile::tempdir().unwrap();
    let gateway = gateway(false, &dir).await;
    assert!(gateway.build_meta_mcp().await.is_ok());
}
