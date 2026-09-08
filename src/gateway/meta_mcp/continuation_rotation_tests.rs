// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: MIT
//! ROTATE.9/.12 production dispatch; root owns the shared builder/clock seam.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use serde_json::{Value, json};

use super::{MetaMcp, MetaMcpCallerContext};
use crate::config::{BackendConfig, Config, TransportConfig};
use crate::gateway::authz::AllowAll;
use crate::gateway::destructive_confirmation::ConfirmationChannel;
use crate::key_server::oidc::VerifiedIdentity;
use crate::protocol::mrtr::RetryFields;
use crate::protocol::{JsonRpcResponse, RequestId};

const T: u64 = 1_000;
const BACKEND: &str = "rotation-fixture";
const TOOL: &str = "ask_then_complete";
static ALLOW: AllowAll = AllowAll;

struct BackendFixture {
    url: String,
    calls: Arc<Mutex<Vec<Value>>>,
    effects: Arc<Mutex<Vec<u64>>>,
    oversized_state: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for BackendFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl BackendFixture {
    async fn start() -> Self {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let effects = Arc::new(Mutex::new(Vec::new()));
        let oversized_state = Arc::new(AtomicBool::new(false));
        let call_sink = Arc::clone(&calls);
        let effect_sink = Arc::clone(&effects);
        let oversized_source = Arc::clone(&oversized_state);
        let app=axum::Router::new().route("/",axum::routing::post(move|axum::Json(request):axum::Json<Value>|{
            let calls=Arc::clone(&call_sink);let effects=Arc::clone(&effect_sink);
            let oversized_state=Arc::clone(&oversized_source);
            async move {
                let result=match request["method"].as_str() {
                    Some("initialize")=>json!({"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"rotation-fixture","version":"1"}}),
                    Some("tools/list")=>json!({"tools":[{"name":TOOL,"description":"Ask before a synthetic completion","inputSchema":{"type":"object","properties":{"round":{"type":"integer"}},"required":["round"]},"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":false}}]}),
                    Some("tools/call")=>{
                        let params=request["params"].clone();calls.lock().unwrap().push(params.clone());
                        let round=params["arguments"]["round"].as_u64().expect("fixture round");
                        if params.get("inputResponses").is_some() {
                            assert_eq!(params["requestState"],format!("private-backend-state-{round}"));
                            assert_eq!(params["inputResponses"],json!({"confirm":{"action":"accept","content":{"confirmed":true}}}));
                            effects.lock().unwrap().push(round);
                            json!({"resultType":"complete","isError":false,"content":[{"type":"text","text":"rotation completion"}]})
                        } else {
                            let opaque_state=if oversized_state.load(Ordering::SeqCst) { "x".repeat(9000) } else { format!("private-backend-state-{round}") };
                            json!({"resultType":"input_required","requestState":opaque_state,"inputRequests":{"confirm":{"method":"elicitation/create","params":{"message":"Complete this synthetic operation?","requestedSchema":{"type":"object","properties":{"confirmed":{"type":"boolean"}},"required":["confirmed"]}}}}})
                        }
                    }
                    _=>json!({}),
                };
                axum::Json(json!({"jsonrpc":"2.0","id":request.get("id").cloned().unwrap_or(Value::Null),"result":result}))
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            url,
            calls,
            effects,
            oversized_state,
            task,
        }
    }

    fn config(&self) -> Config {
        let mut config = Config::default();
        config.backends.insert(
            BACKEND.into(),
            BackendConfig {
                enabled: true,
                transport: TransportConfig::Http {
                    http_url: self.url.clone(),
                    streamable_http: true,
                    protocol_version: None,
                },
                ..BackendConfig::default()
            },
        );
        config
    }
}

fn identity() -> VerifiedIdentity {
    VerifiedIdentity {
        subject: "rotation-subject".into(),
        email: "rotation@example.invalid".into(),
        name: None,
        groups: Vec::new(),
        issuer: "https://rotation.example.invalid".into(),
    }
}

async fn dispatch(meta: &MetaMcp, id: u64, round: u64, retry: &RetryFields) -> JsonRpcResponse {
    let identity = identity();
    let declaration = json!({"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"elicitation":{}}}});
    let declared = crate::protocol::meta::classify_request(Some(&declaration), Some("2026-07-28"))
        .declared_capabilities();
    meta.handle_tools_call(
        RequestId::Number(i64::try_from(id).unwrap()),
        "gateway_invoke",
        json!({"server":BACKEND,"tool":TOOL,"arguments":{"round":round}}),
        Some("rotation-session"),
        MetaMcpCallerContext {
            execution: None,
            signing: None,
            is_modern: false,
            credential_principal: None,
            authorizer: &ALLOW,
            api_key_name: None,
            agent_id: None,
            grant_subject: None,
            verified_identity: Some(&identity),
            is_admin: false,
            input_capabilities: declared,
            confirmation: ConfirmationChannel::Unavailable,
            retry,
        },
    )
    .await
}

fn returned_handle(meta: &MetaMcp, value: &Value, now: u64) -> Option<String> {
    match value {
        Value::String(text) => {
            if meta.continuation().keyring().open(text, now).is_ok() {
                return Some(text.clone());
            }
            serde_json::from_str::<Value>(text)
                .ok()
                .and_then(|nested| returned_handle(meta, &nested, now))
        }
        Value::Array(items) => items
            .iter()
            .find_map(|value| returned_handle(meta, value, now)),
        Value::Object(map) => map
            .values()
            .find_map(|value| returned_handle(meta, value, now)),
        _ => None,
    }
}

fn client_key(label: &str) -> RetryFields {
    RetryFields {
        idempotency_key: Some(label.into()),
        ..RetryFields::default()
    }
}

// Called only with the actual root-owned builder result and its trusted callback.
// No Keyring::mint, state replacement, manufactured continuation or clock sleep.
#[expect(
    clippy::too_many_lines,
    reason = "one ordered flow observes the same pending and spent exchanges before and after rotation"
)]
async fn exercise_rotation(
    meta: Arc<MetaMcp>,
    foreign: Arc<MetaMcp>,
    epoch: Arc<AtomicU64>,
    backend: &BackendFixture,
) {
    let continuation = meta.continuation();
    let replica = continuation.replica().to_owned();
    // Spend an actual gateway-issued envelope before rotating. A duplicate
    // afterward detects wholesale state/ledger replacement in the real caller.
    let initial = dispatch(&meta, 100, 0, &client_key("rotation-spent-initial")).await;
    assert!(
        initial.error.is_none(),
        "spent setup must reach backend: {initial:?}"
    );
    let spent_token = returned_handle(&meta, &serde_json::to_value(initial).unwrap(), T).unwrap();
    let spent_payload = continuation.keyring().open(&spent_token, T).unwrap();
    assert_eq!(
        spent_payload.issued_at, T,
        "ROTATE.12: actual mint ignored the trusted builder clock"
    );
    let spent_retry = RetryFields {
        request_state: Some(spent_token),
        input_responses: Some(json!({"confirm":{"action":"accept","content":{"confirmed":true}}})),
        idempotency_key: Some("rotation-spent-first-completion".into()),
        ..RetryFields::default()
    };
    let spent_done = dispatch(&meta, 101, 0, &spent_retry).await;
    assert!(
        spent_done.error.is_none(),
        "pre-rotation real spend must complete: {spent_done:?}"
    );
    assert_eq!(*backend.effects.lock().unwrap(), vec![0]);
    assert_eq!(backend.calls.lock().unwrap().len(), 2);
    let first = dispatch(&meta, 1, 1, &client_key("rotation-first-request")).await;
    assert!(
        first.error.is_none(),
        "fixture must reach a successful interim reply: {first:?}"
    );
    let first_value = serde_json::to_value(&first).unwrap();
    let old = returned_handle(&meta, &first_value, T)
        .expect("client receives an authentic opaque continuation");
    assert!(!first_value.to_string().contains("private-backend-state-1"));
    let opened = continuation.keyring().open(&old, T).unwrap();
    assert_eq!(
        opened.issued_at, T,
        "ROTATE.12: actual mint ignored the trusted builder clock"
    );
    assert_eq!(
        opened.backend_request_state.as_deref(),
        Some("private-backend-state-1")
    );
    assert_eq!(backend.calls.lock().unwrap().len(), 3);
    assert_eq!(*backend.effects.lock().unwrap(), vec![0]);
    let pending_before = continuation.in_flight().snapshot().await;
    assert!(pending_before.contains_key(&opened.hold_key));

    epoch.store(T + 60, Ordering::SeqCst);
    let second = dispatch(&meta, 2, 2, &client_key("rotation-second-request")).await;
    assert!(
        second.error.is_none(),
        "second real mint must reach fixture: {second:?}"
    );
    let new = returned_handle(&meta, &serde_json::to_value(&second).unwrap(), T + 60).unwrap();
    assert_eq!(
        continuation.keyring().open(&new, T + 60).unwrap().issued_at,
        T + 60,
        "ROTATE.12: advanced trusted epoch must reach actual mint"
    );
    let decode = |token: &str| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token)
            .unwrap()
    };
    assert_ne!(
        decode(&old)[1],
        decode(&new)[1],
        "ROTATE.12: actual invoke did not rotate at age boundary"
    );
    assert!(Arc::ptr_eq(&continuation, &meta.continuation()));
    assert_eq!(continuation.replica(), replica);
    assert_eq!(
        continuation
            .in_flight()
            .snapshot()
            .await
            .get(&opened.hold_key),
        pending_before.get(&opened.hold_key)
    );
    assert_eq!(backend.calls.lock().unwrap().len(), 4);
    assert_eq!(*backend.effects.lock().unwrap(), vec![0]);

    let already_spent = RetryFields {
        idempotency_key: Some("rotation-spent-fresh-duplicate".into()),
        ..spent_retry
    };
    let refused = dispatch(&meta, 102, 0, &already_spent).await;
    assert!(
        refused.error.is_some(),
        "ROTATE.9: pre-rotation spent handle returned {refused:?}; backend calls={}, effects={:?}",
        backend.calls.lock().unwrap().len(),
        backend.effects.lock().unwrap()
    );
    assert_eq!(backend.calls.lock().unwrap().len(), 4);
    assert_eq!(*backend.effects.lock().unwrap(), vec![0]);

    let retry = RetryFields {
        request_state: Some(old.clone()),
        input_responses: Some(json!({"confirm":{"action":"accept","content":{"confirmed":true}}})),
        idempotency_key: Some("rotation-first-redemption".into()),
        ..RetryFields::default()
    };
    let foreign_retry = RetryFields {
        idempotency_key: Some("rotation-foreign-refusal".into()),
        ..retry.clone()
    };
    let foreign_continuation = foreign.continuation();
    let foreign_spent_before = foreign_continuation.ledger().len().await;
    assert_eq!(
        foreign_spent_before, 0,
        "second real builder starts with an empty ledger"
    );
    let foreign_refused = dispatch(&foreign, 103, 1, &foreign_retry).await;
    assert!(
        foreign_refused.error.is_some(),
        "ROTATE.9: second actual builder must refuse foreign envelope"
    );
    assert_eq!(
        foreign_continuation.keyring().open(&old, T + 60),
        Err(crate::protocol::continuation::ContinuationError::NotAuthentic),
        "ROTATE.9: refusal alone can hide shared decryption keys behind a missing hold"
    );
    assert_eq!(
        backend.calls.lock().unwrap().len(),
        4,
        "foreign refusal reached backend"
    );
    assert_eq!(*backend.effects.lock().unwrap(), vec![0]);
    assert_eq!(
        foreign_continuation.ledger().len().await,
        foreign_spent_before,
        "ROTATE.9: actual foreign redemption mutated its consumed ledger before refusal"
    );
    let completed = dispatch(&meta, 3, 1, &retry).await;
    assert!(
        completed.error.is_none(),
        "pending exchange must complete after rotation: {completed:?}"
    );
    assert_eq!(*backend.effects.lock().unwrap(), vec![0, 1]);
    assert_eq!(backend.calls.lock().unwrap().len(), 5);
    assert!(
        !continuation
            .in_flight()
            .snapshot()
            .await
            .contains_key(&opened.hold_key)
    );
    assert_eq!(continuation.keyring().open(&old, T + 60).unwrap(), opened);
    let duplicate = RetryFields {
        idempotency_key: Some("rotation-fresh-key-for-duplicate".into()),
        ..retry
    };
    let refused = dispatch(&meta, 4, 1, &duplicate).await;
    assert!(
        refused.error.is_some(),
        "spent continuation must refuse despite fresh idempotency key"
    );
    assert_eq!(*backend.effects.lock().unwrap(), vec![0, 1]);
    assert_eq!(
        backend.calls.lock().unwrap().len(),
        5,
        "duplicate reached backend"
    );
}

/// The real builder uses its standard persistence paths. Isolate those paths in
/// a child test process instead of mutating environment shared by parallel tests.
async fn child_process(label: &str) -> bool {
    const CHILD: &str = "NFR_SEC3_ROTATE12_CHILD";
    if std::env::var(CHILD).as_deref() == Ok(label) {
        return false;
    }
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir(home.path().join("tmp")).unwrap();
    let test_name = format!("gateway::meta_mcp::continuation_rotation_tests::{label}");
    let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", &test_name, "--nocapture", "--test-threads=1"])
        .env_clear()
        .env(CHILD, label)
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env("XDG_CONFIG_HOME", home.path().join("config"))
        .env("XDG_DATA_HOME", home.path().join("data"))
        .env("XDG_CACHE_HOME", home.path().join("cache"))
        .env("XDG_STATE_HOME", home.path().join("state"))
        .env("TMPDIR", home.path().join("tmp"))
        .env("PATH", "/usr/bin:/bin")
        .current_dir(home.path())
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true);
    // Instrumented children must write their profiles outside configuration
    // fixtures, and their real execution must contribute to coverage.
    if let Some(profile) = std::env::var_os("LLVM_PROFILE_FILE") {
        command.env("LLVM_PROFILE_FILE", profile);
    }
    let output = tokio::time::timeout(std::time::Duration::from_secs(45), command.output())
        .await
        .expect("ROTATE.12 isolated fixture deadlock watchdog")
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "ROTATE.12 child failed: {stdout}\n{stderr}"
    );
    assert!(
        stdout.contains(&format!("ROTATE12_COMPLETE:{label}")),
        "zero-selected child is not a passing drive: {stdout}"
    );
    true
}

#[tokio::test]
async fn rotate_12_pending_exchange_survives_real_builder_rotation() {
    const LABEL: &str = "rotate_12_pending_exchange_survives_real_builder_rotation";
    if child_process(LABEL).await {
        return;
    }
    let backend = BackendFixture::start().await;
    let epoch = Arc::new(AtomicU64::new(T));
    // Drive continuation binding and replay guards on every retry. The default
    // response cache can return a prior completion before those guards run;
    // the separate fixture control retains the default cache configuration.
    let mut config = backend.config();
    config.cache.enabled = false;
    let clock = Arc::clone(&epoch);
    let owner = crate::gateway::server::build_meta_mcp_for_test(
        config.clone(),
        Arc::new(move || clock.load(Ordering::SeqCst)),
    )
    .await
    .unwrap();
    let foreign_clock = Arc::clone(&epoch);
    let foreign_owner = crate::gateway::server::build_meta_mcp_for_test(
        config,
        Arc::new(move || foreign_clock.load(Ordering::SeqCst)),
    )
    .await
    .unwrap();
    exercise_rotation(
        Arc::clone(owner.meta()),
        Arc::clone(foreign_owner.meta()),
        epoch,
        &backend,
    )
    .await;
    // Keep the actual owner (including cleanup task) alive for the entire flow.
    drop(owner);
    drop(foreign_owner);
    println!("ROTATE12_COMPLETE:{LABEL}");
}

#[tokio::test]
async fn rotate_12_fixture_control_real_builder_completes_without_rotation() {
    const LABEL: &str = "rotate_12_fixture_control_real_builder_completes_without_rotation";
    if child_process(LABEL).await {
        return;
    }
    let backend = BackendFixture::start().await;
    let owner = crate::gateway::server::build_meta_mcp_for_test(backend.config(), Arc::new(|| T))
        .await
        .unwrap();
    let meta = owner.meta();
    let first = dispatch(meta, 11, 1, &client_key("rotation-control-first")).await;
    assert!(
        first.error.is_none(),
        "real-builder fixture initial dispatch failed: {first:?}"
    );
    let handle = returned_handle(meta, &serde_json::to_value(&first).unwrap(), T).unwrap();
    assert_eq!(backend.calls.lock().unwrap().len(), 1);
    assert!(backend.effects.lock().unwrap().is_empty());
    let retry = RetryFields {
        request_state: Some(handle),
        input_responses: Some(json!({"confirm":{"action":"accept","content":{"confirmed":true}}})),
        idempotency_key: Some("rotation-control-complete".into()),
        ..RetryFields::default()
    };
    let completed = dispatch(meta, 12, 1, &retry).await;
    assert!(
        completed.error.is_none(),
        "real-builder fixture completion failed: {completed:?}"
    );
    assert_eq!(backend.calls.lock().unwrap().len(), 2);
    assert_eq!(*backend.effects.lock().unwrap(), vec![1]);
    drop(owner);
    println!("ROTATE12_COMPLETE:{LABEL}");
}

#[derive(Clone, Copy)]
enum MintFailure {
    SuccessorRng,
    TooLarge,
}

async fn exercise_failed_mint(failure: MintFailure) {
    let backend = BackendFixture::start().await;
    let epoch = Arc::new(AtomicU64::new(T));
    let clock = Arc::clone(&epoch);
    let mut config = backend.config();
    config.cache.enabled = false;
    let owner = crate::gateway::server::build_meta_mcp_for_test(
        config,
        Arc::new(move || clock.load(Ordering::SeqCst)),
    )
    .await
    .unwrap();
    let meta = owner.meta();
    let state = meta.continuation();
    let original = dispatch(meta, 200, 0, &client_key("rollback-original")).await;
    assert!(
        original.error.is_none(),
        "initial live exchange: {original:?}"
    );
    let old_token = returned_handle(meta, &serde_json::to_value(original).unwrap(), T).unwrap();
    let old_payload = state.keyring().open(&old_token, T).unwrap();
    let held_before = state.in_flight().snapshot().await;
    assert_eq!(held_before.len(), 1);
    assert!(held_before.contains_key(&old_payload.hold_key));
    let ledger_before = state.ledger().len().await;
    assert_eq!(backend.calls.lock().unwrap().len(), 1);
    assert!(backend.effects.lock().unwrap().is_empty());

    let rng_calls = Arc::new(AtomicUsize::new(0));
    match failure {
        MintFailure::SuccessorRng => state
            .keyring()
            .set_successor_failure_for_test(Some(Arc::clone(&rng_calls))),
        MintFailure::TooLarge => backend.oversized_state.store(true, Ordering::SeqCst),
    }
    epoch.store(T + 60, Ordering::SeqCst);
    let refused = dispatch(meta, 201, 1, &client_key("rollback-refused")).await;
    let error = refused
        .error
        .as_ref()
        .expect("failed mint must refuse the interim result");
    assert_eq!(
        error.code, -32003,
        "must be the unbindable-continuation refusal: {refused:?}"
    );
    if matches!(failure, MintFailure::SuccessorRng) {
        assert_eq!(
            rng_calls.load(Ordering::SeqCst),
            1,
            "actual successor factory was not reached"
        );
    }
    assert_eq!(backend.calls.lock().unwrap().len(), 2);
    assert!(backend.effects.lock().unwrap().is_empty());
    assert_eq!(state.ledger().len().await, ledger_before);
    assert_eq!(
        state.in_flight().snapshot().await,
        held_before,
        "ROTATE.16: failed mint left an unpublished hold or removed another live exchange"
    );
    assert_eq!(
        state.keyring().open(&old_token, T + 60).unwrap(),
        old_payload
    );

    state.keyring().set_successor_failure_for_test(None);
    backend.oversized_state.store(false, Ordering::SeqCst);
    let later = dispatch(meta, 202, 2, &client_key("rollback-later")).await;
    assert!(
        later.error.is_none(),
        "mint after failure must work: {later:?}"
    );
    let later_token = returned_handle(meta, &serde_json::to_value(later).unwrap(), T + 60).unwrap();
    let later_payload = state.keyring().open(&later_token, T + 60).unwrap();
    let held_after = state.in_flight().snapshot().await;
    assert_eq!(held_after.len(), 2);
    assert_eq!(
        held_after.get(&old_payload.hold_key),
        held_before.get(&old_payload.hold_key)
    );
    assert!(held_after.contains_key(&later_payload.hold_key));
    assert_eq!(backend.calls.lock().unwrap().len(), 3);
    let retry = RetryFields {
        request_state: Some(old_token),
        input_responses: Some(json!({"confirm":{"action":"accept","content":{"confirmed":true}}})),
        idempotency_key: Some("rollback-old-redemption".into()),
        ..RetryFields::default()
    };
    let completed = dispatch(meta, 203, 0, &retry).await;
    assert!(
        completed.error.is_none(),
        "old exchange must remain redeemable: {completed:?}"
    );
    assert_eq!(backend.calls.lock().unwrap().len(), 4);
    assert_eq!(*backend.effects.lock().unwrap(), vec![0]);
    let remaining = state.in_flight().snapshot().await;
    assert_eq!(remaining.len(), 1);
    assert!(remaining.contains_key(&later_payload.hold_key));
    assert!(!remaining.contains_key(&old_payload.hold_key));
    assert_eq!(state.ledger().len().await, ledger_before + 1);
    drop(owner);
}

#[tokio::test]
async fn rotate_16_rng_failure_releases_only_the_unpublished_hold() {
    const LABEL: &str = "rotate_16_rng_failure_releases_only_the_unpublished_hold";
    if child_process(LABEL).await {
        return;
    }
    exercise_failed_mint(MintFailure::SuccessorRng).await;
    println!("ROTATE12_COMPLETE:{LABEL}");
}

#[tokio::test]
async fn rotate_16_oversized_state_releases_only_the_unpublished_hold() {
    const LABEL: &str = "rotate_16_oversized_state_releases_only_the_unpublished_hold";
    if child_process(LABEL).await {
        return;
    }
    exercise_failed_mint(MintFailure::TooLarge).await;
    println!("ROTATE12_COMPLETE:{LABEL}");
}
