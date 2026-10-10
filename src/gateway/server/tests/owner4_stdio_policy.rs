// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7272.OWNER.4: a `ToolPolicy` denial refuses a stdio mutation before its
//! retained result is delivered, with zero dispatch to the denied target,
//! while a permitted neighbouring target works.
//!
//! Test plan: `docs/design/2026-09-30-sub4-stdio-owner-test-plan.md` (I2).
//! Every row runs against ONE `MetaMcp`, so the admission ledger and the
//! idempotency cache that could replay the denied target's result are the
//! same ones the permitted call filled. The policy is the one the dispatcher
//! is handed per request, as `run_stdio` hands it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use crate::config::{BackendConfig, Config, TransportConfig};
use crate::gateway::Gateway;
use crate::security::{ToolPolicy, ToolPolicyConfig};

const BACKEND: &str = "records";
/// The target the second policy denies.
const DENIED: &str = "record_a";
/// A neighbouring target on the same backend that stays permitted.
const NEIGHBOUR: &str = "record_b";
const SESSION: &str = "stdio-session";
/// 45 bytes, above the 32-byte minimum the signing config enforces.
const SIGNING_SECRET: &str = "a-signing-secret-that-is-at-least-32-bytes!!!!";

type Calls = Arc<Mutex<HashMap<String, usize>>>;

/// An HTTP MCP backend with two mutating tools; counts `tools/call` per tool.
async fn counting_backend() -> (String, Calls) {
    let calls: Calls = Arc::default();
    let seen = Arc::clone(&calls);
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
            let seen = Arc::clone(&seen);
            async move {
                let result = match request.get("method").and_then(Value::as_str) {
                    Some("initialize") => json!({
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": BACKEND, "version": "0"},
                    }),
                    Some("tools/list") => json!({"tools": [
                        {"name": DENIED, "description": "fixture", "inputSchema": {"type": "object"}},
                        {"name": NEIGHBOUR, "description": "fixture", "inputSchema": {"type": "object"}},
                    ]}),
                    Some("tools/call") => {
                        let tool = request
                            .pointer("/params/name")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string();
                        *seen.lock().expect("fixture counts").entry(tool.clone()).or_default() += 1;
                        json!({"content": [{"type": "text", "text": format!("recorded by {tool}")}]})
                    }
                    _ => json!({}),
                };
                axum::Json(json!({"jsonrpc": "2.0", "id": request.get("id"), "result": result}))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture backend");
    let address = listener.local_addr().expect("fixture address");
    tokio::spawn(async move { drop(axum::serve(listener, app).await) });
    (format!("http://{address}/"), calls)
}

fn count(calls: &Calls, tool: &str) -> usize {
    calls
        .lock()
        .expect("fixture counts")
        .get(tool)
        .copied()
        .unwrap_or(0)
}

/// Whether the gateway signs messages. A value, not a `bool` parameter,
/// because it selects behaviour.
#[derive(Clone, Copy)]
enum Signing {
    Off,
    On,
}

struct Stdio {
    meta: Arc<crate::gateway::meta_mcp::MetaMcp>,
    permitting: Arc<ToolPolicy>,
    denying: Arc<ToolPolicy>,
    mtls: Arc<crate::mtls::MtlsPolicy>,
    calls: Calls,
    _data_dir: tempfile::TempDir,
}

async fn stdio(signing: Signing) -> Stdio {
    let (url, calls) = counting_backend().await;
    let mut config = Config::default();
    config.cache.enabled = false;
    config.server.modern_protocol = true;
    if let Signing::On = signing {
        config.security.message_signing.enabled = true;
        config.security.message_signing.shared_secret = SIGNING_SECRET.to_string();
        config.security.message_signing.replay_window = 300;
        config.security.message_signing.key_id = "owner-4".to_string();
    }
    config.backends.insert(
        BACKEND.to_string(),
        BackendConfig {
            transport: TransportConfig::Http {
                http_url: url,
                streamable_http: Some(true),
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
    let denying = Arc::new(ToolPolicy::from_config(&ToolPolicyConfig {
        deny: vec![DENIED.to_string()],
        ..ToolPolicyConfig::default()
    }));
    Stdio {
        meta: built.meta_mcp,
        permitting: built.tool_policy,
        denying,
        mtls: built.mtls_policy,
        calls,
        _data_dir: data_dir,
    }
}

/// A modern keyed `gateway_invoke` of `tool`, as a stdio client sends it.
fn keyed(id: &str, tool: &str, key: &str) -> Value {
    json!({
        "jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": {
            "name": "gateway_invoke",
            "arguments": {"server": BACKEND, "tool": tool, "arguments": {"note": "owner-4"}},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
                (crate::protocol::mrtr::IDEMPOTENCY_KEY_META): key,
            }
        }
    })
}

/// The production stdio entry point, with `policy` as the policy in force.
async fn dispatch(stdio: &Stdio, policy: &Arc<ToolPolicy>, request: Value) -> Value {
    Gateway::dispatch_single_with_sink(
        &stdio.meta,
        policy,
        &stdio.mtls,
        request,
        super::super::StdioClient {
            session_id: SESSION,
            channel: &crate::gateway::input_bridge::NoClientChannel,
            handshake_capabilities: crate::protocol::meta::Declared::NONE,
            tasks: None,
            modern: false,
            sanitize: crate::gateway::server::stdio_single::InputSanitizing::Off,
        },
        &super::super::StdioTelemetry::default(),
    )
    .await
    .expect("a request carrying an id must produce a response")
}

fn succeeded(response: &Value) -> bool {
    response.get("error").is_none() && !response.to_string().contains("\\\"isError\\\":true")
}

/// The denied target's retained result must not appear in a refusal.
const RETAINED: &str = "recorded by record_a";

/// T4.1 + T4.2. A keyed call executes under a permitting policy; the same key
/// and arguments under a denying policy are refused before the retained
/// result is delivered, with no new dispatch; the neighbour still works.
async fn denial_precedes_replay(signing: Signing) {
    let stdio = stdio(signing).await;

    let first = dispatch(
        &stdio,
        &stdio.permitting,
        keyed("p1", DENIED, "owner-4-key"),
    )
    .await;
    assert!(
        succeeded(&first),
        "the permitted call must execute: {first}"
    );
    assert!(first.to_string().contains(RETAINED), "{first}");
    assert_eq!(count(&stdio.calls, DENIED), 1);

    let replay = dispatch(&stdio, &stdio.denying, keyed("p2", DENIED, "owner-4-key")).await;
    assert!(
        !succeeded(&replay),
        "the denied target must be refused, not replayed: {replay}"
    );
    assert!(
        !replay.to_string().contains(RETAINED),
        "the refusal must not carry the retained result: {replay}"
    );
    assert_eq!(
        count(&stdio.calls, DENIED),
        1,
        "the denied attempt must not dispatch"
    );

    let neighbour = dispatch(
        &stdio,
        &stdio.denying,
        keyed("p3", NEIGHBOUR, "owner-4-other"),
    )
    .await;
    assert!(
        succeeded(&neighbour),
        "the permitted neighbour must still work: {neighbour}"
    );
    assert_eq!(count(&stdio.calls, NEIGHBOUR), 1);
}

#[tokio::test]
async fn a_denied_target_is_refused_before_its_retained_result() {
    denial_precedes_replay(Signing::Off).await;
}

/// T4.4. The same with message signing on: signing preparation must not let
/// the replay skip the policy in force for this request.
#[tokio::test]
async fn signing_does_not_skip_the_current_policy() {
    denial_precedes_replay(Signing::On).await;
}

/// T4.3. With the denying policy in force from the start, the target never
/// dispatches.
#[tokio::test]
async fn a_denied_target_never_dispatches() {
    let stdio = stdio(Signing::Off).await;
    let refused = dispatch(&stdio, &stdio.denying, keyed("d1", DENIED, "owner-4-fresh")).await;
    assert!(!succeeded(&refused), "{refused}");
    assert_eq!(count(&stdio.calls, DENIED), 0);
}

/// MIK-7928: over stdio under `standard` a `gateway_invoke` nonce is judged
/// after the invocation policy, as on `/mcp`. A denied call with a malformed
/// nonce gets the policy refusal and counts no nonce rejection; an allowed one
/// is refused `-32602` and counted once. Driven on a current-thread runtime
/// inside the scoped recorder, so every metric the call emits is seen.
#[cfg(feature = "metrics")]
#[test]
fn stdio_judges_an_invoke_nonce_after_policy() {
    use crate::security::message_signing::nonce_metrics_support::{
        INVALID_REFUSAL, assert_no_rejections, assert_single_rejection, observe,
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let stdio = runtime.block_on(stdio(Signing::On));
    let call = |policy: &Arc<ToolPolicy>, id: &str, tool: &str| {
        let mut request = keyed(id, tool, id);
        request["params"]["arguments"]["nonce"] = Value::Null;
        observe(|| runtime.block_on(dispatch(&stdio, policy, request)))
    };

    let (denied, events) = call(&stdio.denying, "n1", DENIED);
    assert!(!succeeded(&denied), "{denied}");
    assert_ne!(
        denied["error"]["code"],
        json!(-32602),
        "policy answers first: {denied}"
    );
    assert!(!denied.to_string().contains(INVALID_REFUSAL), "{denied}");
    assert!(
        denied.to_string().contains(&format!(
            "Tool '{DENIED}' on server '{BACKEND}' is blocked by security policy"
        )),
        "the policy's own refusal: {denied}"
    );
    assert_no_rejections(&events);
    assert_eq!(count(&stdio.calls, DENIED), 0);

    let (allowed, events) = call(&stdio.permitting, "n2", NEIGHBOUR);
    assert_eq!(allowed["error"]["code"], json!(-32602), "{allowed}");
    assert_eq!(
        allowed["error"]["message"],
        json!(INVALID_REFUSAL),
        "{allowed}"
    );
    assert_single_rejection(&events, "invalid");
    assert_eq!(count(&stdio.calls, NEIGHBOUR), 0);
}

/// MIK-7928, in every build: the policy answers a denied stdio invoke before
/// its malformed nonce is judged, and an allowed one is refused `-32602`
/// without reaching the backend. The counters are the row above (`metrics`).
#[test]
fn stdio_answers_policy_before_a_malformed_invoke_nonce() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let stdio = runtime.block_on(stdio(Signing::On));
    let call = |policy: &Arc<ToolPolicy>, id: &str, tool: &str| {
        let mut request = keyed(id, tool, id);
        request["params"]["arguments"]["nonce"] = Value::Null;
        runtime.block_on(dispatch(&stdio, policy, request))
    };

    let denied = call(&stdio.denying, "n1", DENIED);
    assert!(!succeeded(&denied), "{denied}");
    assert_ne!(
        denied["error"]["code"],
        json!(-32602),
        "policy answers first: {denied}"
    );
    assert!(
        !denied.to_string().contains("Invalid signing nonce"),
        "{denied}"
    );
    assert!(
        denied.to_string().contains(&format!(
            "Tool '{DENIED}' on server '{BACKEND}' is blocked by security policy"
        )),
        "the policy's own refusal: {denied}"
    );
    assert_eq!(count(&stdio.calls, DENIED), 0);

    let allowed = call(&stdio.permitting, "n2", NEIGHBOUR);
    assert_eq!(
        (&allowed["error"]["code"], &allowed["error"]["message"]),
        (&json!(-32602), &json!("Invalid signing nonce")),
        "{allowed}"
    );
    assert_eq!(count(&stdio.calls, NEIGHBOUR), 0);
}
