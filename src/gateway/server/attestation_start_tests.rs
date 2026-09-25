// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7570.ATTEST.1 — a bad `GATEWAY_ATTESTATION_MODE` stops the gateway.
//!
//! `resolve_attestation_wiring` refusing `enforce` proves nothing if the start
//! path logs the error and carries on. These drive `build_meta_mcp`, the step
//! both `run` and `run_stdio` take before they bind or read anything, on a
//! gateway whose env overlay (an env file, never the process environment)
//! sets the mode, and require `Error::Config` back.

use std::sync::Arc;

use super::Gateway;
use crate::Error;
use crate::attestation::ATTESTATION_MODE_ENV;
use crate::config::{Config, EnvOverlay, LiveEnv, ResolvedEnvFiles};

async fn gateway_with_mode(mode: &str) -> (Gateway, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let env_file = dir.path().join(".env");
    crate::gateway::test_helpers::write_owner_only(
        &env_file,
        format!("{ATTESTATION_MODE_ENV}={mode}\n"),
    )
    .expect("env file");
    let overlay = Arc::new(EnvOverlay::from_paths(&[env_file]));
    let env = Arc::new(LiveEnv::new(overlay, ResolvedEnvFiles::default()));
    let gateway = Gateway::new_with_env(Config::default(), env, None)
        .await
        .expect("the config itself is valid");
    (gateway, dir)
}

async fn start_error(mode: &str) -> String {
    let (gateway, _dir) = gateway_with_mode(mode).await;
    match gateway.build_meta_mcp().await {
        Err(Error::Config(msg)) => msg,
        Err(other) => panic!("{mode:?} must fail start with a config error, got {other}"),
        Ok(_) => panic!("{mode:?} must fail start, but the meta-MCP was built"),
    }
}

/// Positive control: the same path with a valid mode builds, so the refusals
/// below come from the mode and not from the fixture.
#[tokio::test]
async fn observe_mode_starts() {
    let (gateway, _dir) = gateway_with_mode("observe").await;
    assert!(gateway.build_meta_mcp().await.is_ok());
}

#[tokio::test]
async fn enforce_mode_fails_start_with_a_config_error() {
    let msg = start_error("enforce").await;
    assert!(msg.contains("not available in this build"), "{msg}");
}

#[tokio::test]
async fn an_unrecognised_mode_fails_start_naming_the_value() {
    let msg = start_error("enforcee").await;
    assert!(msg.contains("enforcee"), "{msg}");
}
