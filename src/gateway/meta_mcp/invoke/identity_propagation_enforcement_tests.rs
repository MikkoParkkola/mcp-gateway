// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
/// The permissive authorizer these tests hand out.
static ALLOW_ALL_INVOKE: crate::gateway::authz::AllowAll = crate::gateway::authz::AllowAll;

use std::sync::Arc;

use serde_json::{Value, json};

use crate::backend::BackendRegistry;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::oauth::GatewayKeyPair;
use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode, SignedAssertionStrategy,
    TokenExchangeStrategy,
};
use crate::key_server::oidc::VerifiedIdentity;

fn meta_with_strategy() -> MetaMcp {
    let m = MetaMcp::new(Arc::new(BackendRegistry::new()));
    let key = Arc::new(GatewayKeyPair::generate().expect("keygen"));
    m.set_identity_propagation(Arc::new(SignedAssertionStrategy::new(key, 300)));
    m
}

fn idp_cfg(required: bool) -> IdentityPropagationConfig {
    IdentityPropagationConfig {
        strategy: PropagationStrategyKind::SignedAssertion,
        audience: "https://memory.internal".to_string(),
        required,
        session_mode: SessionMode::Stateless,
        token_exchange_endpoint: None,
        token_exchange_scope: None,
    }
}

fn identity() -> VerifiedIdentity {
    VerifiedIdentity {
        subject: "alice".to_string(),
        email: "alice@corp".to_string(),
        name: None,
        groups: vec![],
        issuer: "https://idp".to_string(),
    }
}

// MIK-6740 IDP4.1/4.2 — the Meta-MCP `gateway_invoke` route audits every
// mint and every fail-closed refusal into the transparency log, identically
// to the direct backend route. Regression guard for the gap where only the
// direct route audited: a mint/refuse on the primary invoke path used to
// leave no audit entry at all.
#[tokio::test]
async fn gateway_invoke_route_audits_mint_and_refuse() {
    use tempfile::NamedTempFile;

    use crate::security::TransparencyLogger;
    use crate::security::transparency_log::TransparencyLogConfig;

    let file = NamedTempFile::new().expect("tempfile");
    let cfg = Arc::new(TransparencyLogConfig {
        enabled: true,
        path: file.path().to_string_lossy().to_string(),
        key_id: "test".to_string(),
        ..TransparencyLogConfig::default()
    });
    let logger = Arc::new(TransparencyLogger::open(cfg).expect("logger opens"));

    let mut m = meta_with_strategy();
    m.enable_transparency_log(Arc::clone(&logger));

    // Successful mint -> idp_mint entry.
    let cred = m
        .resolve_caller_credential("memory", &idp_cfg(true), Some(&identity()))
        .await
        .expect("mint ok");
    let minted_value = cred.headers[0].1.clone();

    // Required + no identity -> fail-closed refuse -> idp_refuse entry.
    m.resolve_caller_credential("memory", &idp_cfg(true), None)
        .await
        .expect_err("must refuse");

    let raw = std::fs::read_to_string(file.path()).expect("read log");
    assert!(
        raw.contains("idp_mint"),
        "mint on the gateway_invoke route must be audited: {raw}"
    );
    assert!(
        raw.contains("idp_refuse"),
        "fail-closed refusal on the gateway_invoke route must be audited: {raw}"
    );
    // Redaction: the minted credential value must never reach the log.
    let token = minted_value
        .strip_prefix("Bearer ")
        .unwrap_or(&minted_value);
    assert!(
        !raw.contains(token),
        "the minted credential must never appear in the transparency log"
    );
}

// Header-capturing transport: records the per-request headers dispatch
// attaches, so a test can assert the propagated credential reached the wire.
type CapturedHeaders = Arc<parking_lot::Mutex<Vec<(String, String)>>>;
// Records the identity key dispatch threads for upstream session
// partitioning (MIK-6784), so a test can assert distinct identities produce
// distinct keys.
type CapturedIdentityKeys = Arc<parking_lot::Mutex<Vec<Option<String>>>>;

struct CapturingTransport {
    captured: CapturedHeaders,
    captured_identity: CapturedIdentityKeys,
}

#[async_trait::async_trait]
impl crate::transport::Transport for CapturingTransport {
    async fn request(
        &self,
        _method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        Ok(crate::protocol::JsonRpcResponse::success(
            crate::protocol::RequestId::Number(1),
            json!({"content": [{"type": "text", "text": "ok"}]}),
        ))
    }
    async fn request_with_headers(
        &self,
        _method: &str,
        _params: Option<Value>,
        extra_headers: &[(String, String)],
        identity_key: Option<&str>,
        _resend: crate::transport::ResendPermission,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        *self.captured.lock() = extra_headers.to_vec();
        self.captured_identity
            .lock()
            .push(identity_key.map(str::to_string));
        self.request(_method, _params).await
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

// Build a MetaMcp whose registry has one identity-required HTTP backend
// ("mem") wired to a header-capturing transport, plus the signed-assertion
// strategy. Returns the meta and the shared capture buffer.
fn meta_with_capturing_backend() -> (MetaMcp, CapturedHeaders) {
    let (m, captured, _identity) = meta_with_capturing_backend_full();
    (m, captured)
}

/// A transparency logger backed by a leaked tempfile — kept alive for the
/// whole test process so a `required`-backend mint has a durable audit sink
/// (without one, the MIK-6740 fail-closed guard aborts the mint). Leaking is
/// fine in a unit test: the file is reclaimed when the process exits.
fn leaked_test_transparency_logger() -> Arc<crate::security::TransparencyLogger> {
    use crate::security::TransparencyLogger;
    use crate::security::transparency_log::TransparencyLogConfig;

    let file = tempfile::NamedTempFile::new().expect("tempfile");
    let path = file.path().to_string_lossy().to_string();
    std::mem::forget(file); // keep the on-disk file alive for the test
    let cfg = Arc::new(TransparencyLogConfig {
        enabled: true,
        path,
        key_id: "test".to_string(),
        ..TransparencyLogConfig::default()
    });
    Arc::new(TransparencyLogger::open(cfg).expect("logger opens"))
}

/// Like [`meta_with_capturing_backend`] but also exposes the buffer of
/// identity keys the transport received (MIK-6784). Wires a transparency log
/// so a `required`-backend mint succeeds (the MIK-6740 fail-closed guard
/// aborts a required mint when no audit sink is configured).
fn meta_with_capturing_backend_full() -> (MetaMcp, CapturedHeaders, CapturedIdentityKeys) {
    build_capturing_backend(true)
}

/// Like [`meta_with_capturing_backend`] but with NO transparency log wired,
/// so a `required`-backend mint must fail closed (MIK-6740 operator-misconfig
/// guard).
fn meta_with_capturing_backend_no_log() -> (MetaMcp, CapturedHeaders) {
    let (m, captured, _identity) = build_capturing_backend(false);
    (m, captured)
}

fn build_capturing_backend(
    with_transparency_log: bool,
) -> (MetaMcp, CapturedHeaders, CapturedIdentityKeys) {
    use crate::backend::Backend;
    use crate::config::{BackendConfig, TransportConfig};

    let registry = Arc::new(BackendRegistry::new());
    let config = BackendConfig {
        transport: TransportConfig::Http {
            http_url: "https://mem.internal/mcp".to_string(),
            streamable_http: Some(true),
            protocol_version: None,
        },
        identity_propagation: Some(idp_cfg(true)),
        ..BackendConfig::r2_off()
    };
    let backend = Arc::new(Backend::new(
        "mem",
        config,
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ));
    let captured = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let captured_identity = Arc::new(parking_lot::Mutex::new(Vec::new()));
    backend.set_transport_for_test(Arc::new(CapturingTransport {
        captured: Arc::clone(&captured),
        captured_identity: Arc::clone(&captured_identity),
    }));
    let _ = registry.register(backend);

    let mut m = MetaMcp::new(registry);
    let key = Arc::new(GatewayKeyPair::generate().expect("keygen"));
    m.set_identity_propagation(Arc::new(SignedAssertionStrategy::new(key, 300)));
    if with_transparency_log {
        m.enable_transparency_log(leaked_test_transparency_logger());
    }
    (m, captured, captured_identity)
}

/// A backend that asks once and then completes.
///
/// Stateful on purpose: a stub returning the same interim twice makes the
/// bridge spin to `RoundsExhausted`, which would pass for "the bridge ran"
/// without proving the retry carried the answer anywhere.
/// How `AskOnceTransport` answers the round that follows the question.
enum RetryRound {
    Completes,
    Fails,
    NeverReaches,
}

struct AskOnceTransport {
    calls: Arc<parking_lot::Mutex<Vec<Value>>>,
    retry_round: RetryRound,
}

#[async_trait::async_trait]
impl crate::transport::Transport for AskOnceTransport {
    async fn request(
        &self,
        _method: &str,
        params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        let round = {
            let mut calls = self.calls.lock();
            calls.push(params.unwrap_or(Value::Null));
            calls.len()
        };
        if round > 1 {
            match self.retry_round {
                RetryRound::Completes => {}
                RetryRound::Fails => {
                    return Err(crate::Error::JsonRpc {
                        code: -32000,
                        message: "the backend failed the bridged retry".to_string(),
                        data: None,
                    });
                }
                RetryRound::NeverReaches => {
                    return Err(crate::Error::TransportConnect(
                        "the bridged retry never left the gateway".to_string(),
                    ));
                }
            }
        }
        let body = if round == 1 {
            json!({
                "resultType": "input_required",
                "inputRequests": {"q1": {"method": "roots/list"}},
                "requestState": "backend-state-1",
            })
        } else {
            json!({"content": [{"type": "text", "text": "completed"}]})
        };
        Ok(crate::protocol::JsonRpcResponse::success(
            crate::protocol::RequestId::Number(1),
            body,
        ))
    }
    async fn request_with_headers(
        &self,
        method: &str,
        params: Option<Value>,
        _extra_headers: &[(String, String)],
        _identity_key: Option<&str>,
        _resend: crate::transport::ResendPermission,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        self.request(method, params).await
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

/// A legacy client that answers whatever the bridge puts to it.
struct AnsweringClient {
    asked: Arc<parking_lot::Mutex<Vec<String>>>,
}

#[async_trait::async_trait]
impl crate::gateway::input_bridge::ClientChannel for AnsweringClient {
    async fn send_request(
        &self,
        _session_id: &str,
        _id: &str,
        method: &str,
        _params: Option<Value>,
    ) -> std::result::Result<Value, crate::gateway::input_bridge::DeliveryError> {
        self.asked.lock().push(method.to_string());
        // A whole JSON-RPC reply, not a bare body: the bridge reads the
        // `result` member off the frame the client put on the wire.
        Ok(json!({"jsonrpc": "2.0", "result": {"roots": []}}))
    }
}

/// A `MetaMcp` with one plain backend that asks once and then completes.
fn meta_that_asks_once(retry_round: RetryRound) -> (MetaMcp, Arc<parking_lot::Mutex<Vec<Value>>>) {
    use crate::backend::Backend;
    use crate::config::{BackendConfig, TransportConfig};

    let registry = Arc::new(BackendRegistry::new());
    let config = BackendConfig {
        transport: TransportConfig::Http {
            http_url: "https://asks.internal/mcp".to_string(),
            streamable_http: Some(true),
            protocol_version: None,
        },
        ..BackendConfig::r2_off()
    };
    let backend = Arc::new(Backend::new(
        "asks",
        config,
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ));
    let calls = Arc::new(parking_lot::Mutex::new(Vec::new()));
    backend.set_transport_for_test(Arc::new(AskOnceTransport {
        calls: Arc::clone(&calls),
        retry_round,
    }));
    let _ = registry.register(backend);
    (MetaMcp::new(registry), calls)
}

// MIK-7212.MRTR.7a/7b on the production path. `tests/mik_7212_mrtr7_bridge_acs.rs`
// constructs `InputBridge` itself, so it stays green when `invoke_tool_traced`
// stops building one — which is what the reconcile merge did, unnoticed. This
// test enters through `invoke_tool_traced`: with no bridge on that path the
// legacy caller is handed a continuation envelope and the backend is called once.
#[tokio::test]
async fn legacy_caller_is_asked_in_band_and_the_backend_is_retried() {
    let (m, calls) = meta_that_asks_once(RetryRound::Completes);
    let asked = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let channel = AnsweringClient {
        asked: Arc::clone(&asked),
    };
    let declared = crate::protocol::meta::classify_request(
        Some(&json!({"_meta": {
            crate::protocol::meta::KEY_PROTOCOL_VERSION: "2026-07-28",
            crate::protocol::meta::KEY_CLIENT_CAPABILITIES: {"roots": {}},
        }})),
        None,
    )
    .declared_capabilities();
    let caller = crate::gateway::meta_mcp::MetaMcpCallerContext {
        task: None,
        signing: None,
        execution: None,
        credential_principal: None,
        authentication: crate::gateway::meta_mcp::Authentication::Anonymous,
        credential_kind: crate::security::audit::CredentialKind::None,
        is_modern: false,
        protocol_revision: None,
        authorizer: &ALLOW_ALL_INVOKE,
        stdio_nonce: None,
        caller_key: None,
        verified_identity: None,
        api_key_name: None,
        agent_id: None,
        agent_declared: None,
        grant_subject: None,
        is_admin: false,
        surface_request: crate::gateway::recovery::SurfaceRequest::Configured,
        input_capabilities: declared,
        retry: &crate::protocol::mrtr::NO_RETRY,
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
        era: crate::protocol::meta::Era::Legacy,
        channel: &channel,
    };
    let args = json!({"server": "asks", "tool": "ask", "arguments": {}});
    m.invoke_tool_traced(&args, Some("session-1"), &caller, "trace-1")
        .await
        .expect("the bridged exchange completes");

    // MRTR.7a: the equivalent legacy request reached the client in band.
    assert_eq!(
        asked.lock().as_slice(),
        ["roots/list".to_string()],
        "the legacy client was never asked, so the bridge is not on the invoke path"
    );
    // MRTR.7b: the backend was retried, carrying the answer and its own state.
    let calls = calls.lock().clone();
    assert_eq!(calls.len(), 2, "the backend was not retried: {calls:?}");
    let retry = calls[1].to_string();
    assert!(
        retry.contains("backend-state-1"),
        "the retry dropped the backend's requestState: {retry}"
    );
    assert!(
        retry.contains("q1"),
        "the retry carried no answer for the question asked: {retry}"
    );
}

// A bridged round that fails after the backend was reached must not free the
// idempotency key. The first dispatch already happened — the interim is what
// opened the exchange — so the release-on-drop default answers a duplicate
// submission by running the side effect a second time.
#[tokio::test]
async fn a_failed_bridged_retry_does_not_free_the_idempotency_key() {
    let (mut m, calls) = meta_that_asks_once(RetryRound::Fails);
    m.enable_idempotency(
        Arc::new(crate::idempotency::IdempotencyCache::new()),
        std::time::Duration::from_secs(60),
    );
    let asked = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let channel = AnsweringClient {
        asked: Arc::clone(&asked),
    };
    let declared = crate::protocol::meta::classify_request(
        Some(&json!({"_meta": {
            crate::protocol::meta::KEY_PROTOCOL_VERSION: "2026-07-28",
            crate::protocol::meta::KEY_CLIENT_CAPABILITIES: {"roots": {}},
        }})),
        None,
    )
    .declared_capabilities();
    let retry = crate::protocol::mrtr::RetryFields {
        input_responses: None,
        request_state: None,
        idempotency_key: Some("key-1".to_string()),
        malformed: Vec::new(),
        attestation: None,
    };
    let caller = crate::gateway::meta_mcp::MetaMcpCallerContext {
        task: None,
        signing: None,
        execution: None,
        credential_principal: None,
        authentication: crate::gateway::meta_mcp::Authentication::Anonymous,
        credential_kind: crate::security::audit::CredentialKind::None,
        is_modern: false,
        protocol_revision: None,
        authorizer: &ALLOW_ALL_INVOKE,
        stdio_nonce: None,
        caller_key: None,
        verified_identity: None,
        api_key_name: None,
        agent_id: None,
        agent_declared: None,
        grant_subject: None,
        is_admin: false,
        surface_request: crate::gateway::recovery::SurfaceRequest::Configured,
        input_capabilities: declared,
        retry: &retry,
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
        era: crate::protocol::meta::Era::Legacy,
        channel: &channel,
    };
    let args = json!({"server": "asks", "tool": "ask", "arguments": {}});

    let first = m
        .invoke_tool_traced(&args, Some("session-1"), &caller, "trace-1")
        .await;
    assert!(first.is_err(), "the bridged retry was supposed to fail");
    let dispatched = calls.lock().len();
    assert_eq!(dispatched, 2, "the backend was not retried: {dispatched}");

    let second = m
        .invoke_tool_traced(&args, Some("session-1"), &caller, "trace-2")
        .await;
    assert_eq!(
        calls.lock().len(),
        dispatched,
        "the key was freed after a round that may have acted, so the duplicate re-executed"
    );
    let served = second
        .expect("the duplicate is served from the cache")
        .into_parts()
        .0;
    assert!(
        served.to_string().contains("outcome is unknown"),
        "the duplicate was served something other than the uncertainty marker: {served}"
    );
    assert_eq!(
        served.get("isError").and_then(Value::as_bool),
        Some(true),
        "a round that may have acted must replay as a failure, not a success: {served}"
    );
}

// The mirror image: a bridged round refused before it left the gateway —
// no such backend, no such tool, an open circuit, a transport that never
// connected — provably did not act, so its key must be readmitted. Marking
// it executed would strand the caller on an operation that never ran.
#[tokio::test]
async fn a_bridged_retry_refused_before_dispatch_frees_the_idempotency_key() {
    let (mut m, calls) = meta_that_asks_once(RetryRound::NeverReaches);
    m.enable_idempotency(
        Arc::new(crate::idempotency::IdempotencyCache::new()),
        std::time::Duration::from_secs(60),
    );
    let asked = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let channel = AnsweringClient {
        asked: Arc::clone(&asked),
    };
    let declared = crate::protocol::meta::classify_request(
        Some(&json!({"_meta": {
            crate::protocol::meta::KEY_PROTOCOL_VERSION: "2026-07-28",
            crate::protocol::meta::KEY_CLIENT_CAPABILITIES: {"roots": {}},
        }})),
        None,
    )
    .declared_capabilities();
    let retry = crate::protocol::mrtr::RetryFields {
        input_responses: None,
        request_state: None,
        idempotency_key: Some("key-1".to_string()),
        malformed: Vec::new(),
        attestation: None,
    };
    let caller = crate::gateway::meta_mcp::MetaMcpCallerContext {
        task: None,
        signing: None,
        execution: None,
        credential_principal: None,
        authentication: crate::gateway::meta_mcp::Authentication::Anonymous,
        credential_kind: crate::security::audit::CredentialKind::None,
        is_modern: false,
        protocol_revision: None,
        authorizer: &ALLOW_ALL_INVOKE,
        stdio_nonce: None,
        caller_key: None,
        verified_identity: None,
        api_key_name: None,
        agent_id: None,
        agent_declared: None,
        grant_subject: None,
        is_admin: false,
        surface_request: crate::gateway::recovery::SurfaceRequest::Configured,
        input_capabilities: declared,
        retry: &retry,
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
        era: crate::protocol::meta::Era::Legacy,
        channel: &channel,
    };
    let args = json!({"server": "asks", "tool": "ask", "arguments": {}});

    let first = m
        .invoke_tool_traced(&args, Some("session-1"), &caller, "trace-1")
        .await;
    assert!(first.is_err(), "the bridged retry was supposed to fail");
    let dispatched = calls.lock().len();
    assert_eq!(dispatched, 2, "the backend was not retried: {dispatched}");

    let second = m
        .invoke_tool_traced(&args, Some("session-1"), &caller, "trace-2")
        .await;
    drop(second);
    assert!(
        calls.lock().len() > dispatched,
        "the key stayed settled after a round that provably did not act, so the caller \
         cannot retry an operation that never ran"
    );
}

#[cfg(test)]
mod resolution;
