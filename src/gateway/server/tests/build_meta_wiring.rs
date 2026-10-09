// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The optional sections `build_meta_mcp` wires into the running meta-MCP.
//!
//! `build_meta_mcp` is a Critical row (MIK-8144): each security section it
//! reads must reach the meta-MCP the serve modes use, and a section it cannot
//! honour must not stop the gateway when the operator asked for a best-effort
//! feature. Each test turns one section on and reads the field it sets.
//!
//! An INFO subscriber is installed so the startup log lines are formatted;
//! without one their field expressions are never evaluated.

use super::*;

fn info_logging() -> tracing::subscriber::DefaultGuard {
    tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_writer(std::io::sink)
            .finish(),
    )
}

async fn built(config: Config) -> Arc<MetaMcp> {
    let gateway = Gateway::new(config).await.expect("gateway");
    gateway
        .build_meta_mcp()
        .await
        .expect("build_meta_mcp")
        .meta_mcp
}

/// Claim capture opens its sink (creating the parent directory) and hands it
/// to the meta-MCP, so derived claims are written for offline scoring.
#[tokio::test]
async fn claim_capture_opens_its_sink_and_reaches_the_meta_mcp() {
    let _log = info_logging();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("claims").join("capture.jsonl");
    let mut config = Config::default();
    config.security.claim_capture.enabled = true;
    config.security.claim_capture.path = path.display().to_string();

    let meta = built(config).await;

    assert!(
        meta.claim_capture.is_some(),
        "an enabled claim capture must be installed on the running meta-MCP"
    );
    assert!(
        path.exists(),
        "the capture sink must be created at the configured path"
    );
}

/// A capture path that cannot be opened leaves capture off and still boots:
/// capture is an offline-scoring aid, not a control, so it must not take the
/// gateway down.
#[tokio::test]
async fn an_unopenable_claim_capture_path_boots_without_capture() {
    let _log = info_logging();
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = Config::default();
    config.security.claim_capture.enabled = true;
    // A directory, not a file: opening it for append fails.
    config.security.claim_capture.path = dir.path().display().to_string();

    let meta = built(config).await;

    assert!(
        meta.claim_capture.is_none(),
        "a sink that failed to open must not be installed"
    );
}

/// Response inspection in action mode blocks HIGH/CRITICAL findings; in
/// observe mode it only logs. The mode the operator chose is the one installed.
#[tokio::test]
async fn response_inspection_installs_the_configured_mode() {
    let _log = info_logging();
    let mut action = Config::default();
    action.security.response_inspection.enabled = true;
    action.security.response_inspection.action_mode = true;
    assert!(
        built(action).await.response_inspection_action_mode,
        "action mode must make inspection findings block"
    );

    let mut observe = Config::default();
    observe.security.response_inspection.enabled = true;
    observe.security.response_inspection.action_mode = false;
    assert!(
        !built(observe).await.response_inspection_action_mode,
        "observe mode must not block"
    );
}

/// The response contract gate is installed with the operator's config,
/// including observe mode.
#[tokio::test]
async fn the_response_contract_reaches_the_meta_mcp_in_observe_mode() {
    let _log = info_logging();
    let mut config = Config::default();
    config.security.response_contract.enabled = true;
    config.security.response_contract.action_mode = false;

    let meta = built(config).await;

    let contract = meta
        .response_contract
        .as_ref()
        .expect("an enabled response contract must be installed");
    assert!(
        !contract.action_mode,
        "the installed contract keeps observe mode"
    );
}
