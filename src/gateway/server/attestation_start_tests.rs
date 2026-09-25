// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7570.ATTEST.1 — a bad `GATEWAY_ATTESTATION_MODE` stops the gateway,
//! and a good `enforce` reaches the running gateway and enforces.
//!
//! `resolve_attestation_wiring` refusing a setting proves nothing if the start
//! path logs the error and carries on. These drive `build_meta_mcp`, the step
//! both `run` and `run_stdio` take before they bind or read anything, on a
//! gateway whose env overlay (an env file, never the process environment)
//! sets the mode, and require `Error::Config` back.

use std::sync::Arc;

use super::Gateway;
use crate::Error;
use crate::attestation::{ATTESTATION_MODE_ENV, ATTESTATION_SIGNING_KEY_ENV};
use crate::config::{Config, EnvOverlay, LiveEnv, ResolvedEnvFiles};

const KEY: &str = "start-test-signing-key";

async fn gateway_with_mode(mode: &str) -> (Gateway, tempfile::TempDir) {
    gateway_with_env(&format!("{ATTESTATION_MODE_ENV}={mode}\n")).await
}

async fn gateway_with_env(body: &str) -> (Gateway, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let env_file = dir.path().join(".env");
    crate::gateway::test_helpers::write_owner_only(&env_file, body).expect("env file");
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

/// `enforce` with a key starts, and the built gateway refuses an unattested
/// call and admits an attested one. Built from the env overlay, never a
/// hand-built mode, so a start path that still refused enforce, or dropped it,
/// fails here.
#[tokio::test]
async fn enforce_mode_with_a_key_starts_and_enforces() {
    use crate::attestation::{BnautAttestationSigner, TokenRequest};
    let (gateway, _dir) = gateway_with_env(&format!(
        "{ATTESTATION_MODE_ENV}=enforce\n{ATTESTATION_SIGNING_KEY_ENV}={KEY}\n"
    ))
    .await;
    let built = gateway
        .build_meta_mcp()
        .await
        .unwrap_or_else(|e| panic!("enforce with a key must start: {e}"));
    let caller = crate::gateway::meta_mcp::anonymous_caller();
    let call = serde_json::json!({"server": "s", "tool": "t", "arguments": {}});
    let err = built
        .meta_mcp
        .check_invocation_policy(&call, None, &caller)
        .expect_err("an unattested call must be refused under enforce");
    assert_eq!(err.to_rpc_code(), -32002, "{err}");

    let token = BnautAttestationSigner::new(KEY.as_bytes().to_vec(), "gateway")
        .issue(
            &TokenRequest {
                agent_identity: "agent".to_string(),
                task_uuid: uuid::Uuid::new_v4(),
                capabilities: vec!["t".to_string()],
            },
            chrono::Utc::now(),
            chrono::TimeDelta::minutes(5),
        )
        .encoded()
        .to_string();
    let mut attested = call;
    attested["attestation"] = serde_json::json!(token);
    built
        .meta_mcp
        .check_invocation_policy(&attested, None, &caller)
        .unwrap_or_else(|e| panic!("a valid token must be admitted: {e}"));
}

#[tokio::test]
async fn enforce_mode_without_a_key_fails_start() {
    let msg = start_error("enforce").await;
    assert!(msg.contains(ATTESTATION_SIGNING_KEY_ENV), "{msg}");
}

#[tokio::test]
async fn an_unrecognised_mode_fails_start_naming_the_value() {
    let msg = start_error("enforcee").await;
    assert!(msg.contains("enforcee"), "{msg}");
}
