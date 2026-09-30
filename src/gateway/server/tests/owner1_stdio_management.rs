// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7272.OWNER.1 at the production stdio dispatcher: keyless and legacy
//! writes execute every time, and each management branch keeps its keyed
//! behaviour over stdio.
//!
//! Test plan: `docs/design/2026-09-30-sub4-stdio-owner-test-plan.md` (I2).
//! Keyed once and replay are already pinned by `dispatcher_admission_arms.rs`;
//! the reload rows with an installed context live in `owner1_stdio_reload.rs`.

use std::sync::Arc;

use serde_json::{Value, json};

use super::signing_nonce_allocations_support::{BACKEND, Fixture, invoke};
use crate::config::{BackendConfig, Config, TransportConfig};
use crate::gateway::Gateway;
use crate::gateway::meta_mcp::MetaMcp;
use crate::mtls::MtlsPolicy;
use crate::routing_profile::RoutingProfileConfig;
use crate::security::ToolPolicy;

const SESSION: &str = super::super::STDIO_SESSION_ID;
/// The one routing profile the management gateway configures.
const PROFILE: &str = "focus";

/// The production stdio entry point.
async fn dispatch(
    meta: &Arc<MetaMcp>,
    policy: &Arc<ToolPolicy>,
    mtls: &Arc<MtlsPolicy>,
    request: &Value,
) -> Value {
    Gateway::dispatch_single(meta, policy, mtls, request, SESSION)
        .await
        .expect("a request carrying an id must produce a response")
}

/// `request` with every protocol field removed: a 2025 client's frame.
fn legacy(mut request: Value) -> Value {
    if let Some(params) = request.get_mut("params").and_then(Value::as_object_mut) {
        params.remove("_meta");
    }
    request
}

fn call(id: u64, tool: &str, arguments: &Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": {"name": tool, "arguments": arguments}})
}

/// A legacy call carrying only an idempotency key in `_meta`: no protocol
/// field, so it stays a legacy frame (`protocol::meta::classify_request`).
fn legacy_keyed(id: u64, tool: &str, arguments: &Value, key: &str) -> Value {
    let mut request = call(id, tool, arguments);
    request["params"]["_meta"] = json!({(crate::protocol::mrtr::IDEMPOTENCY_KEY_META): key});
    request
}

/// A modern call to a management tool, keyed.
fn modern_keyed(id: u64, tool: &str, arguments: &Value, key: &str) -> Value {
    let mut request = call(id, tool, arguments);
    request["params"]["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
        (crate::protocol::mrtr::IDEMPOTENCY_KEY_META): key,
    });
    request
}

fn error_text(response: &Value) -> String {
    response
        .get("error")
        .map(Value::to_string)
        .unwrap_or_default()
}

/// The JSON a successful meta-tool call returned as its text content.
fn result_json(response: &Value) -> Value {
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("a successful tool call returns text: {response}"));
    serde_json::from_str(text).unwrap_or_else(|_| panic!("the text is JSON: {text}"))
}

// ── Keyless and legacy writes ────────────────────────────────────────────────

/// T1.1. A keyless modern write executes each time it is sent, with no
/// refusal. Not behind the `metrics` feature, unlike `unkeyed_admission.rs`.
#[tokio::test]
async fn keyless_modern_write_executes() {
    let fixture = Fixture::start_mutating().await;
    for id in ["k1", "k2"] {
        let response = Gateway::dispatch_single(
            &fixture.meta,
            &fixture.tool_policy,
            &fixture.mtls_policy,
            &invoke(id, None, json!({})),
            SESSION,
        )
        .await
        .expect("a response");
        assert!(response.get("error").is_none(), "{response}");
    }
    assert_eq!(fixture.backend.tools_call_count(), 2);
}

/// T1.2. A legacy unkeyed write sent twice executes twice.
#[tokio::test]
async fn legacy_unkeyed_repeat_executes_twice() {
    let fixture = Fixture::start_mutating().await;
    for id in ["l1", "l2"] {
        let response = Gateway::dispatch_single(
            &fixture.meta,
            &fixture.tool_policy,
            &fixture.mtls_policy,
            &legacy(invoke(id, None, json!({"note": "same"}))),
            SESSION,
        )
        .await
        .expect("a response");
        assert!(response.get("error").is_none(), "{response}");
    }
    assert_eq!(fixture.backend.tools_call_count(), 2);
}

// ── Management branches ──────────────────────────────────────────────────────

/// The management tools' gateway: one routing profile, one backend to name,
/// and neither a reload context nor a capability backend (the serve loop
/// installs those; `build_meta_mcp` does not).
struct Managed {
    meta: Arc<MetaMcp>,
    policy: Arc<ToolPolicy>,
    mtls: Arc<MtlsPolicy>,
    _data_dir: tempfile::TempDir,
}

async fn managed() -> Managed {
    let mut config = Config::default();
    config.server.modern_protocol = true;
    config
        .routing_profiles
        .insert(PROFILE.to_string(), RoutingProfileConfig::default());
    config.backends.insert(
        BACKEND.to_string(),
        BackendConfig {
            transport: TransportConfig::Http {
                // Never contacted: no row here dispatches to a backend.
                http_url: "http://127.0.0.1:9/".to_string(),
                streamable_http: true,
                protocol_version: None,
            },
            enabled: true,
            ..BackendConfig::default()
        },
    );
    let data_dir = tempfile::tempdir().expect("tempdir");
    let built = Gateway::new(config)
        .await
        .expect("the production constructor accepts this configuration")
        .with_data_dir(data_dir.path().to_path_buf())
        .build_meta_mcp()
        .await
        .expect("the production builder accepts this configuration");
    Managed {
        meta: built.meta_mcp,
        policy: built.tool_policy,
        mtls: built.mtls_policy,
        _data_dir: data_dir,
    }
}

impl Managed {
    async fn send(&self, request: &Value) -> Value {
        dispatch(&self.meta, &self.policy, &self.mtls, request).await
    }
}

/// T1.3. `gateway_kill_server` is destructive, and stdio has no channel to
/// confirm it: both keyed attempts are refused by the confirmation gate, and
/// the server is not killed.
#[tokio::test]
async fn kill_server_is_refused_on_stdio() {
    let gateway = managed().await;
    let arguments = json!({"server": BACKEND});
    for id in [1, 2] {
        let refused = gateway
            .send(&modern_keyed(
                id,
                "gateway_kill_server",
                &arguments,
                "kill-key",
            ))
            .await;
        assert!(
            error_text(&refused).contains("requires confirmation and none could be obtained"),
            "stdio must refuse the destructive call: {refused}"
        );
    }
    let revived = result_json(
        &gateway
            .send(&modern_keyed(
                3,
                "gateway_revive_server",
                &arguments,
                "after-kill",
            ))
            .await,
    );
    assert_eq!(
        revived["was_killed"],
        json!(false),
        "the refused kill must not have run"
    );
}

/// T1.4. A keyed revive answers the same on its replay.
#[tokio::test]
async fn revive_server_replays_its_first_result() {
    let gateway = managed().await;
    let arguments = json!({"server": BACKEND});
    let first = gateway
        .send(&modern_keyed(
            1,
            "gateway_revive_server",
            &arguments,
            "revive-key",
        ))
        .await;
    let second = gateway
        .send(&modern_keyed(
            2,
            "gateway_revive_server",
            &arguments,
            "revive-key",
        ))
        .await;
    assert_eq!(result_json(&first)["status"], json!("active"), "{first}");
    assert_eq!(result_json(&first), result_json(&second));
}

/// T1.5. A keyed legacy `gateway_set_state` replays without a second
/// transition: a re-execution would report `previous: triage`.
#[tokio::test]
async fn set_state_replays_without_a_second_transition() {
    let gateway = managed().await;
    let triage = json!({"state": "triage"});
    for id in [1, 2] {
        let response = gateway
            .send(&legacy_keyed(id, "gateway_set_state", &triage, "state-key"))
            .await;
        assert_eq!(
            result_json(&response)["previous"],
            json!("default"),
            "{response}"
        );
    }
    let after = gateway
        .send(&call(3, "gateway_set_state", &json!({"state": "complete"})))
        .await;
    assert_eq!(
        result_json(&after)["previous"],
        json!("triage"),
        "exactly one keyed transition must have happened: {after}"
    );
}

/// T1.6. A profile the registry lacks is refused before dispatch, which frees
/// the key; the same key then executes for the configured profile and
/// replays after that.
#[tokio::test]
async fn set_profile_refusal_frees_the_key_and_success_replays() {
    let gateway = managed().await;
    let refused = gateway
        .send(&legacy_keyed(
            1,
            "gateway_set_profile",
            &json!({"profile": "no-such-profile"}),
            "profile-key",
        ))
        .await;
    assert!(refused.to_string().contains("routing profile"), "{refused}");
    let configured = json!({"profile": PROFILE});
    let set = gateway
        .send(&legacy_keyed(
            2,
            "gateway_set_profile",
            &configured,
            "profile-key",
        ))
        .await;
    assert!(
        set.get("error").is_none(),
        "the freed key must execute: {set}"
    );
    let replayed = gateway
        .send(&legacy_keyed(
            3,
            "gateway_set_profile",
            &configured,
            "profile-key",
        ))
        .await;
    assert_eq!(set["result"], replayed["result"], "the success must replay");
}

/// T1.7. Without a reload context the branch is refused before dispatch.
#[tokio::test]
async fn reload_config_without_a_reload_context_is_refused() {
    let gateway = managed().await;
    let refused = gateway
        .send(&modern_keyed(
            1,
            "gateway_reload_config",
            &json!({}),
            "reload-key",
        ))
        .await;
    assert!(
        refused
            .to_string()
            .contains("Config reload is not enabled on this gateway"),
        "{refused}"
    );
}

/// T1.9. Without a capability backend the branch is refused before dispatch.
#[tokio::test]
async fn reload_capabilities_without_a_backend_is_refused() {
    let gateway = managed().await;
    let refused = gateway
        .send(&modern_keyed(
            1,
            "gateway_reload_capabilities",
            &json!({}),
            "capabilities-key",
        ))
        .await;
    assert!(
        refused
            .to_string()
            .contains("Capability backend is not enabled on this gateway"),
        "{refused}"
    );
}
