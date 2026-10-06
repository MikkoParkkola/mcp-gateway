// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7974: a task created with `?codemode=search_and_execute` keeps that
//! surface in the worker that runs it, so its recovery hint names only Code
//! Mode tools. An admin on the standard surface is pointed at
//! `gateway_revive_server` while the backend's breaker is open; the same
//! admin in Code Mode is not.

use super::super::*;
use super::support::*;

fn admin_auth() -> AuthConfig {
    AuthConfig {
        enabled: true,
        api_keys: vec![crate::config::ApiKeyConfig {
            key: None,
            key_sha256: Some(crate::config::api_key_digest_spec(b"key-admin")),
            expires_at: None,
            name: "principal-admin".to_string(),
            rate_limit: 0,
            backends: vec![BACKEND.to_string()],
            allowed_tools: None,
            denied_tools: None,
            admin: true,
            kind: crate::config::ApiKeyKind::Shared,
        }],
        ..AuthConfig::default()
    }
}

/// The settled task, as text, for a call made at `uri` while the breaker is open.
async fn breaker_task(uri: &str, key: &str) -> String {
    let (state, _store) = fixture_state(&admin_auth()).await;
    register(&state, BACKEND, &MockBackend::answering(Answer::ok()));
    state
        .backends
        .get(BACKEND)
        .expect("the backend is registered")
        .trip_circuit_breaker("mik-7974");
    let created = post_at(&state, "key-admin", uri, task_invoke(1, key, json!({}))).await;
    let task = task_id(&created);
    poll_until_terminal(&state, "key-admin", &task)
        .await
        .to_string()
}

#[tokio::test]
async fn a_codemode_task_keeps_code_mode_hints() {
    // Control: on the standard surface this admin is offered the revive tool.
    let standard = breaker_task("/mcp", "mik-7974-standard").await;
    assert!(standard.contains("gateway_revive_server"), "{standard}");

    let code_mode = breaker_task("/mcp?codemode=search_and_execute", "mik-7974-code").await;
    assert!(
        !code_mode.contains("gateway_revive_server") && code_mode.contains("Wait for the circuit"),
        "{code_mode}"
    );
}
