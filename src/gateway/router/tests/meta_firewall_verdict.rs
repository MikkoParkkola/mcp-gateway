// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The Meta-MCP `tools/call` route owes the client a refusal when the REAL
//! response firewall returns `Block` for an authenticated backend target.
//!
//! The post-invocation scan used to run once per `backend_targets` under
//! `ResponseMutationPolicy::Redact`. Two residual defects came out of that
//! shape: a `Block` verdict that did not stop delivery (single target), and —
//! after that was answered — an ORDER-DEPENDENT block on multiple targets,
//! because the first target's redaction removed the very finding a later,
//! refusing target would have blocked on.
//!
//! That pre-pass is not merely redundant with the shared delivery chokepoint at
//! `handlers.rs:1781` (`finalize_response_for_delivery`, which DOES refuse on
//! `Block`). It runs FIRST and it runs under `Redact`, so it mutates the result
//! in place: the credential that produced the `CredentialLeak` finding is
//! replaced before the blocking gate ever inspects the value. The chokepoint
//! then re-runs the detectors on the already-sanitized result, finds nothing,
//! and allows. The router's silent redaction LAUNDERS a blocked artifact into
//! an allowed one. A `Block` rule degrades to an unannounced rewrite plus a
//! success response.
//!
//! Reachability and production limits, stated exactly:
//!
//! * The inner Meta-MCP gate is NOT bypassed or weakened here. Both fixtures
//!   wire ONE `Arc<Firewall>` into both `MetaMcp::set_firewall` and
//!   `AppState::firewall`, which is what `gateway::server` does at startup
//!   (`server/mod.rs:1157`). The inner gate stays armed and keeps its own
//!   obligation.
//! * The defect is therefore an ORDERING defect, not an absent-gate defect,
//!   and it is reachable under that real startup wiring — no mock verdict, no
//!   detached firewall, no forged response. The laundering only needs a finding
//!   class the redactor can remove (credential material); a prompt-injection
//!   finding survives redaction and is still refused downstream, which is why
//!   this regression is pinned on a credential payload.
//! * Nothing here asserts on a helper's return value. The contract is read off
//!   the HTTP response the router actually writes.

use super::super::{AppState, create_router};
use super::{MetaMcp, test_subscriptions, test_task_runtime};
use crate::backend::{Backend, BackendRegistry};
use crate::config::{
    AuthConfig, BackendConfig, FailsafeConfig, StreamingConfig, SurfacedToolConfig,
};
use crate::gateway::{
    AgentAuthState, AgentRegistry, GatewayKeyPair, NotificationMultiplexer, ProxyManager,
    ResolvedAuthConfig,
};
use crate::mtls::{MtlsConfig, MtlsPolicy};
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::firewall::{Firewall, FirewallAction, FirewallConfig, FirewallRule};
use crate::transport::Transport;
use async_trait::async_trait;
use axum::{body::to_bytes, http::StatusCode};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

/// Real credential-shaped material, so the production redactor has something
/// to remove and the production detector has a `CredentialLeak` to find.
const CANARY: &str = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";

/// The tool the surfaced-tool target resolves to, and the rule's match glob.
const TOOL: &str = "leaky_echo";

/// A backend that answers `tools/call` with a credential in its text content.
/// Nothing about the response is special-cased by the gateway: it is an
/// ordinary successful backend result carrying unsafe content.
struct LeakyBackendTransport;

#[async_trait]
impl Transport for LeakyBackendTransport {
    async fn request(
        &self,
        _method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        Ok(JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            json!({
                "content": [{
                    "type": "text",
                    "text": format!("fetched credential {CANARY} for you"),
                }],
                "isError": false,
            }),
        ))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// `AppState` for the Meta-MCP route with the REAL firewall engine wired the
/// way startup wires it: one `Arc<Firewall>` shared by `AppState` and the
/// Meta-MCP, and a surfaced tool so `backend_targets` is non-empty and the
/// route's own per-target obligation actually applies.
async fn firewall_app_state(
    action: FirewallAction,
) -> (Arc<AppState>, Arc<Firewall>, tempfile::TempDir) {
    app_state_with_rules(vec![FirewallRule {
        tool_match: TOOL.to_string(),
        action,
        reason: Some("meta response verdict regression".to_string()),
        scan: Vec::new(),
    }])
    .await
}

/// The same startup wiring, with an explicit rule set so a multi-target call
/// can give different targets different verdicts on ONE artifact.
async fn app_state_with_rules(
    rules: Vec<FirewallRule>,
) -> (Arc<AppState>, Arc<Firewall>, tempfile::TempDir) {
    let backend = Arc::new(Backend::new(
        "demo",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::new(LeakyBackendTransport) as Arc<dyn Transport>);

    let backends = Arc::new(BackendRegistry::new());
    let _ = backends.register(backend);

    let firewall = Arc::new(Firewall::from_config(
        FirewallConfig {
            enabled: true,
            scan_responses: true,
            scan_requests: false,
            credential_redaction: true,
            rules,
            ..FirewallConfig::default()
        },
        None,
    ));

    let mut meta =
        MetaMcp::new(Arc::clone(&backends)).with_surfaced_tools(vec![SurfacedToolConfig {
            server: "demo".to_string(),
            tool: TOOL.to_string(),
        }]);
    // Deliberately ARMED: the inner result-security gate must keep its own
    // obligation. This regression is about the router's obligation running
    // ahead of it, not about removing it.
    meta.set_firewall(Some(Arc::clone(&firewall)));
    let meta_mcp = Arc::new(meta);

    let streaming_config = StreamingConfig::default();
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::clone(&backends),
        streaming_config.clone(),
    ));
    let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));
    let auth_config = Arc::new(ResolvedAuthConfig::from_config(&AuthConfig::default()));
    let agent_auth = AgentAuthState::new(false, Arc::new(AgentRegistry::new()));
    let gateway_key_pair = Arc::new(GatewayKeyPair::generate().expect("gateway key generation"));

    let subscriptions = test_subscriptions();
    let (task_service, task_executor, store_dir) =
        test_task_runtime(&subscriptions, &meta_mcp).await;

    let state = Arc::new(AppState {
        continuation: Arc::new(crate::protocol::continuation::ContinuationState::new()),
        env: None,
        backends,
        meta_mcp,
        meta_mcp_enabled: true,
        multiplexer,
        proxy_manager,
        streaming_config,
        auth_config,
        key_server: None,
        tool_policy: Arc::new(crate::security::ToolPolicy::default()),
        mtls_policy: Arc::new(MtlsPolicy::from_config(&MtlsConfig::default())),
        sanitize_input: false,
        ssrf_protection: false,
        trust_configured_backends: false,
        inflight: Arc::new(tokio::sync::Semaphore::new(8)),
        agent_auth,
        gateway_key_pair,
        capability_dirs: Vec::new(),
        config_path: None,
        firewall: Some(Arc::clone(&firewall)),
        agent_identity_config: crate::config::AgentIdentityConfig::default(),
        control_plane_store: None,
        live_config: std::sync::Arc::new(crate::config_reload::LiveConfig::new(
            crate::config::Config::default(),
        )),
        export_status: None,
        transparency_log: None,
        dashboard_bootstrap: std::sync::Arc::new(crate::gateway::auth::DashboardBootstrap::new()),
        tasks: task_service,
        task_executor,
        subscriptions,
    });
    (state, firewall, store_dir)
}

/// POST one surfaced-tool `tools/call` at the Meta-MCP route and return the
/// status plus decoded body the client would actually receive.
async fn call_surfaced_tool(state: Arc<AppState>, id: &str) -> (StatusCode, Value) {
    let router = create_router(state);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": { "name": TOOL, "arguments": {} }
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

#[tokio::test]
async fn meta_tools_call_refuses_delivery_when_response_firewall_blocks() {
    let (state, firewall, _store) = firewall_app_state(FirewallAction::Block).await;
    let (status, json) = call_surfaced_tool(Arc::clone(&state), "caller-block-1").await;

    // Precondition, asserted so a dispatch failure cannot be mistaken for the
    // security contract holding: the engine really inspected this response.
    assert!(
        firewall.response_inspection_counts().inspections > 0,
        "the real response engine must have inspected the artifact; got {json}"
    );

    // The contract, read off the wire.
    assert_eq!(
        json["id"], "caller-block-1",
        "a native refusal must preserve the caller's JSON-RPC id; got {json}"
    );
    assert!(
        json.get("result").is_none_or(Value::is_null),
        "a blocked response must not ship a result to the client; got {json}"
    );
    assert_eq!(
        json["error"]["message"], "Response blocked by security firewall",
        "the route must answer with the native delivery refusal; got {json}"
    );
    assert_eq!(json["error"]["code"], -32600, "got {json}");

    // No unsafe content, redacted or otherwise, may reach the client on a
    // blocked artifact. A refusal that still echoes the payload is not one.
    let encoded = json.to_string();
    assert!(
        !encoded.contains(CANARY),
        "blocked response leaked credential material; got {json}"
    );
    assert!(
        !encoded.contains("fetched credential"),
        "blocked response leaked backend content; got {json}"
    );
    assert_eq!(
        status,
        StatusCode::OK,
        "JSON-RPC refusal stays a 200; got {json}"
    );
}

#[tokio::test]
async fn meta_tools_call_delivers_redacted_response_when_firewall_allows() {
    // Control: the same engine, the same credential payload, an `Allow` rule.
    // Delivery must still happen, with the id preserved and the credential
    // redacted. This is the arm a fix must not regress into a blanket refusal.
    let (state, firewall, _store) = firewall_app_state(FirewallAction::Allow).await;
    let (status, json) = call_surfaced_tool(Arc::clone(&state), "caller-allow-1").await;

    assert!(
        firewall.response_inspection_counts().inspections > 0,
        "the real response engine must have inspected the artifact; got {json}"
    );
    assert_eq!(status, StatusCode::OK, "got {json}");
    assert_eq!(json["id"], "caller-allow-1", "got {json}");
    assert!(
        json.get("error").is_none_or(Value::is_null),
        "an allowed response must not be refused; got {json}"
    );
    assert!(
        json.get("result").is_some_and(|result| !result.is_null()),
        "an allowed response must be delivered; got {json}"
    );
    assert!(
        !json.to_string().contains(CANARY),
        "an allowed response must still be redacted; got {json}"
    );
}

/// The multi-target ordering defect, over real HTTP.
///
/// `gateway_execute` with a two-step `chain` is the production shape that
/// yields MORE THAN ONE authenticated backend target for a single `tools/call`
/// (`authorization.rs:36` → `targets_from_code_mode_arguments`), and those
/// targets become the route's canonical `response_targets`
/// (`handlers.rs:1262`). Step order is caller-chosen, so the ALLOWED tool can
/// be inspected first.
///
/// Under the per-target loop that used to sit at the post-invocation scan, the
/// first target (`demo:alpha_echo`, an explicit `Allow` rule) scanned under
/// `Redact` and removed the credential in place; the second target
/// (`demo:zeta_echo`, an explicit `Block` rule) then inspected an already-clean
/// artifact, found nothing, and returned `Allow`. The blocking rule was
/// silently defeated by the scan order of a rule that permits.
///
/// The contract: ONE inspection of the artifact, then the strongest action
/// across EVERY target — so the `Block` target refuses regardless of order.
///
/// Reachability notes, honestly stated:
/// * The Meta-MCP's own firewall hook only scans aggregated tool-list/search
///   answers (`meta_mcp/mod.rs:898`), so it is NOT weakened here and does not
///   pre-clean per-step invoke results; the router's post-scan is genuinely the
///   first response gate this artifact meets.
/// * Both chain steps hit the same real backend transport, so the artifact
///   carries the credential when the route inspects it.
#[tokio::test]
async fn meta_tools_call_blocks_when_a_later_target_refuses_after_an_allowing_first_target() {
    let (state, firewall, _store) = app_state_with_rules(vec![
        FirewallRule {
            tool_match: "alpha_echo".to_string(),
            action: FirewallAction::Allow,
            reason: Some("permissive first target".to_string()),
            scan: Vec::new(),
        },
        FirewallRule {
            tool_match: "zeta_echo".to_string(),
            action: FirewallAction::Block,
            reason: Some("credential-refusing later target".to_string()),
            scan: Vec::new(),
        },
    ])
    .await;

    let router = create_router(Arc::clone(&state));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": "caller-multi-1",
                "method": "tools/call",
                "params": {
                    "name": "gateway_execute",
                    "arguments": {
                        // Allowing target FIRST: this is the order that used to
                        // launder the artifact past the refusing target.
                        "chain": [
                            { "tool": "demo:alpha_echo", "arguments": {} },
                            { "tool": "demo:zeta_echo", "arguments": {} }
                        ]
                    }
                }
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert!(
        firewall.response_inspection_counts().inspections > 0,
        "the real response engine must have inspected the artifact; got {json}"
    );
    assert_eq!(status, StatusCode::OK, "got {json}");
    assert_eq!(json["id"], "caller-multi-1", "got {json}");
    assert_eq!(
        json["error"]["message"], "Response blocked by security firewall",
        "a Block rule on ANY authenticated target must refuse delivery, \
         whatever order the targets are inspected in; got {json}"
    );
    assert_eq!(json["error"]["code"], -32600, "got {json}");
    assert!(
        json.get("result").is_none_or(Value::is_null),
        "a blocked multi-target response must not ship a result; got {json}"
    );
    let encoded = json.to_string();
    assert!(
        !encoded.contains(CANARY),
        "blocked response leaked credential material; got {json}"
    );
    assert!(
        !encoded.contains("fetched credential"),
        "blocked response leaked backend content; got {json}"
    );
}

/// Engine-level companion to the HTTP case above: the shared inspection the
/// route now calls must itself fold ALL targets, with the allowing target
/// sorted first. This pins the invariant at the owning API, so a future caller
/// that reintroduces per-target scanning fails here too.
#[tokio::test]
async fn response_artifact_folds_every_target_after_a_single_redacting_scan() {
    use crate::security::response_policy::{
        ResponseArtifactKind, ResponseCorrelation, ResponseMutationPolicy, ResponsePolicyTarget,
    };

    let (_state, firewall, _store) = app_state_with_rules(vec![
        FirewallRule {
            tool_match: "alpha_echo".to_string(),
            action: FirewallAction::Allow,
            reason: None,
            scan: Vec::new(),
        },
        FirewallRule {
            tool_match: "zeta_echo".to_string(),
            action: FirewallAction::Block,
            reason: None,
            scan: Vec::new(),
        },
    ])
    .await;

    let targets = vec![
        ResponsePolicyTarget {
            server: "demo".to_string(),
            tool: "alpha_echo".to_string(),
        },
        ResponsePolicyTarget {
            server: "demo".to_string(),
            tool: "zeta_echo".to_string(),
        },
    ];
    let mut artifact = json!({
        "content": [{ "type": "text", "text": format!("fetched credential {CANARY} for you") }]
    });
    let before = firewall.response_inspection_counts().inspections;
    let verdict = firewall
        .check_response_artifact(
            &mut artifact,
            &targets,
            &ResponseCorrelation {
                session_id: "s-multi",
                caller: "anonymous",
                external_server: "gateway",
                external_tool: "gateway_execute",
            },
            ResponseArtifactKind::FinalResponse,
            ResponseMutationPolicy::Redact,
        )
        .expect("two authenticated targets are a valid policy set");

    assert_eq!(
        firewall.response_inspection_counts().inspections - before,
        1,
        "target count must not multiply content inspection"
    );
    assert_eq!(
        verdict.action,
        FirewallAction::Block,
        "the strongest action across all targets must win"
    );
    assert!(!verdict.allowed, "a Block verdict is not allowed");
}
