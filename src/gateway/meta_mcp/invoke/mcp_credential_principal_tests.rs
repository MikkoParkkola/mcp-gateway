// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7825: an API-key caller reaches an MCP capability on a multi-user
//! gateway through the real dispatch, keyed by its credential digest.
//!
//! The caller presents a validated credential and nothing else: no identity
//! propagation binding, no OIDC identity, no grant subject. Before the fix the
//! digest never reached the executor, so every such call was refused.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::{Value, json};
use tempfile::TempDir;

use crate::backend::BackendRegistry;
use crate::capability::{CapabilityBackend, CapabilityExecutor};
use crate::gateway::meta_mcp::{Authentication, MetaMcp, MetaMcpCallerContext};
use crate::security::audit::CredentialKind;

static ALLOW_ALL: crate::gateway::authz::AllowAll = crate::gateway::authz::AllowAll;

/// The interpreter for the fake MCP server, found on `PATH` without a shell.
fn python() -> PathBuf {
    let names: &[&str] = if cfg!(windows) {
        &["python.exe", "python3.exe"]
    } else {
        &["python3", "python"]
    };
    let path = std::env::var_os("PATH").expect("PATH in CI");
    std::env::split_paths(&path)
        .flat_map(|dir| names.iter().map(move |name| dir.join(name)))
        .find(|candidate| candidate.is_file())
        .expect("python on PATH in CI")
}

async fn multi_user_meta() -> (MetaMcp, TempDir) {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cap_exec/fake_mcp.py");
    let yaml = format!(
        "name: mcp_probe\ndescription: MCP probe.\nschema:\n  input:\n    type: object\n    \
         properties:\n      operation:\n        type: string\n      text:\n        type: string\n\
         providers:\n  primary:\n    service: mcp\n    timeout: 20\n    config:\n      \
         command: '{}'\n      args: ['{}']\n      transport: stdio\n      tool_selector:\n        \
         param: operation\n        tools:\n          say: {{ tool: echo, arguments: {{ message: \
         \"{{text}}\" }} }}\n",
        python().display(),
        script.display()
    );
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("mcp_probe.yaml"), yaml).unwrap();
    let backend = Arc::new(CapabilityBackend::new(
        "caps",
        Arc::new(CapabilityExecutor::new()),
    ));
    let loaded = backend
        .load_from_directory(dir.path().to_str().unwrap())
        .await
        .unwrap();
    assert_eq!(loaded, 1, "the probe must load");
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.set_capabilities(backend);
    // The production setter `Gateway::start` calls on a multi-user deployment.
    meta.set_multi_user(true);
    (meta, dir)
}

fn caller(
    credential_principal: Option<&str>,
    authentication: Authentication,
) -> MetaMcpCallerContext<'_> {
    MetaMcpCallerContext {
        era: crate::protocol::meta::Era::Legacy,
        channel: &crate::gateway::input_bridge::NoClientChannel,
        task: None,
        signing: None,
        execution: None,
        credential_principal,
        authentication,
        credential_kind: if credential_principal.is_some() {
            CredentialKind::ApiKey
        } else {
            CredentialKind::None
        },
        is_modern: false,
        protocol_revision: Some(crate::protocol::PROTOCOL_VERSION),
        authorizer: &ALLOW_ALL,
        stdio_nonce: None,
        caller_key: None,
        verified_identity: None,
        api_key_name: None,
        agent_id: None,
        agent_declared: None,
        grant_subject: None,
        is_admin: false,
        surface_request: crate::gateway::recovery::SurfaceRequest::Configured,
        input_capabilities: crate::protocol::meta::Declared::NONE,
        retry: &crate::protocol::mrtr::NO_RETRY,
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
    }
}

async fn say(meta: &MetaMcp, caller: &MetaMcpCallerContext<'_>) -> crate::Result<Value> {
    let args = json!({
        "tool": "caps:mcp_probe",
        "arguments": {"operation": "say", "text": "x"},
    });
    meta.code_mode_execute(&args, Some("mik-7825-session"), caller)
        .await
}

/// The child's pid, wherever the response envelope carries it: as a field or
/// inside a JSON text block.
fn pid(value: &Value) -> Option<i64> {
    match value {
        Value::Object(map) => map
            .get("pid")
            .and_then(Value::as_i64)
            .or_else(|| map.values().find_map(pid)),
        Value::Array(items) => items.iter().find_map(pid),
        Value::String(text) => serde_json::from_str::<Value>(text)
            .ok()
            .as_ref()
            .and_then(pid),
        _ => None,
    }
}

#[tokio::test]
async fn two_api_keys_reach_their_own_children_through_dispatch() {
    let (meta, _dir) = multi_user_meta().await;
    let a = say(
        &meta,
        &caller(Some("digest-a"), Authentication::Authenticated),
    )
    .await
    .expect("an API-key caller is served on a multi-user gateway");
    let a_again = say(
        &meta,
        &caller(Some("digest-a"), Authentication::Authenticated),
    )
    .await
    .unwrap();
    let b = say(
        &meta,
        &caller(Some("digest-b"), Authentication::Authenticated),
    )
    .await
    .unwrap();
    let (a, a_again, b) = (pid(&a), pid(&a_again), pid(&b));
    assert!(a.is_some(), "the probe reports its pid");
    assert_eq!(a, a_again, "one key reuses its child");
    assert_ne!(a, b, "another key gets another child");
}

/// Control: a caller that presented no credential is still refused on a
/// multi-user gateway, and so is one whose digest is empty.
#[tokio::test]
async fn a_caller_with_no_credential_digest_is_still_refused() {
    let (meta, _dir) = multi_user_meta().await;
    for caller in [
        caller(None, Authentication::Anonymous),
        caller(Some(""), Authentication::Authenticated),
    ] {
        let err = say(&meta, &caller).await.unwrap_err().to_string();
        assert!(err.contains("identified caller"), "{err}");
    }
}

/// T8: a live call carries the bare principal and the background task it
/// starts carries the recorded owner; both name one key, so one child.
#[test]
fn a_live_call_and_its_task_name_one_credential_owner() {
    use crate::gateway::meta_mcp::support::credential_owner;
    let live = credential_owner(&caller(Some("5e1f0a2b3c4d"), Authentication::Authenticated));
    let task = credential_owner(&caller(
        Some("credential:5e1f0a2b3c4d"),
        Authentication::Authenticated,
    ));
    assert_eq!(live.as_deref(), Some("credential:5e1f0a2b3c4d"));
    assert_eq!(live, task);
    let auth_off = caller(
        Some("local:auth-disabled:tasks:v1"),
        Authentication::Anonymous,
    );
    assert_eq!(
        credential_owner(&auth_off),
        None,
        "auth off names no caller"
    );
    let empty = caller(Some(""), Authentication::Authenticated);
    assert_eq!(credential_owner(&empty), None);
}
