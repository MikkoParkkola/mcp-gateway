// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D1 invocation records through the real `invoke_tool` path: who, outcome,
//! and what the hashes cover (D1-T4 to T8, T15, T16).

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::authz::{AllowAll, DenyAll, ToolAuthorizer};
use crate::gateway::meta_mcp::{Authentication, MetaMcp, MetaMcpCallerContext};
use crate::identity_grants::GrantSubject;
use crate::key_server::oidc::VerifiedIdentity;
use crate::protocol::RequestId;
use crate::security::audit::CredentialKind;
use crate::security::transparency_log::TransparencyLogConfig;
use crate::transport::Transport;

/// A backend that answers every `tools/call` with one scripted reply.
struct Scripted(Result<Value, String>);

#[async_trait::async_trait]
impl Transport for Scripted {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        // F13: a cold call lists the backend before R2 judges it (closed by
        // default), so the fixture serves the one tool its calls name.
        if method == "tools/list" {
            return Ok(crate::protocol::JsonRpcResponse::success_serialized(
                RequestId::Number(1),
                json!({"tools": [{"name": "read", "inputSchema": {"type": "object"}}]}),
            ));
        }
        match &self.0 {
            Ok(v) => Ok(crate::protocol::JsonRpcResponse::success_serialized(
                RequestId::Number(1),
                v.clone(),
            )),
            Err(e) => Err(crate::Error::Transport(e.clone())),
        }
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

/// A backend that answers every `tools/call` with its own JSON-RPC error.
struct PeerError(i32);

#[async_trait::async_trait]
impl Transport for PeerError {
    async fn request(
        &self,
        method: &str,
        params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        if method == "tools/call" {
            return Ok(crate::protocol::JsonRpcResponse::error(
                Some(RequestId::Number(1)),
                self.0,
                "the peer's own refusal",
            ));
        }
        Scripted(Ok(ok_result())).request(method, params).await
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

fn ok_result() -> Value {
    json!({"content": [{"type": "text", "text": "ok"}], "isError": false})
}

/// A gateway with one backend `alpha` and a log in `dir`.
fn meta(reply: Result<Value, String>, dir: &tempfile::TempDir) -> MetaMcp {
    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        "alpha",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(Scripted(reply)));
    let _ = registry.register(backend);
    let logger = crate::security::TransparencyLogger::open(Arc::new(TransparencyLogConfig {
        enabled: true,
        path: dir
            .path()
            .join("audit.jsonl")
            .to_string_lossy()
            .into_owned(),
        key_id: "d1".to_string(),
        ..TransparencyLogConfig::default()
    }))
    .expect("open log");
    let mut meta = MetaMcp::new(registry);
    meta.enable_transparency_log(Arc::new(logger));
    meta
}

/// Invocation records only: entries naming a `tool`.
fn records(dir: &tempfile::TempDir) -> Vec<Value> {
    std::fs::read_to_string(dir.path().join("audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|e| e.get("tool").is_some())
        .collect()
}

fn only_record(dir: &tempfile::TempDir) -> Value {
    let all = records(dir);
    assert_eq!(
        all.len(),
        1,
        "expected exactly one invocation record: {all:?}"
    );
    all.into_iter().next().unwrap()
}

/// Who calls. Built the way `router/handlers.rs` builds a caller.
struct Caller {
    principal: String,
    account: String,
    authenticated: bool,
    grant: Option<GrantSubject>,
    identity: Option<VerifiedIdentity>,
    kind: CredentialKind,
}

fn context<'a>(
    authorizer: &'a (dyn ToolAuthorizer + Sync),
    who: &'a Caller,
) -> MetaMcpCallerContext<'a> {
    MetaMcpCallerContext {
        signing: None,
        execution: None,
        credential_principal: Some(who.principal.as_str()),
        authentication: if who.authenticated {
            Authentication::Authenticated
        } else {
            Authentication::Anonymous
        },
        credential_kind: who.kind,
        is_modern: false,
        protocol_revision: Some(crate::protocol::PROTOCOL_VERSION),
        authorizer,
        api_key_name: Some(who.account.as_str()),
        agent_id: None,
        agent_declared: None,
        grant_subject: who.grant.clone(),
        stdio_nonce: None,
        caller_key: None,
        verified_identity: who.identity.as_ref(),
        is_admin: false,
        surface_request: crate::gateway::recovery::SurfaceRequest::Configured,
        input_capabilities: crate::protocol::meta::Declared::NONE,
        retry: &crate::protocol::mrtr::NO_RETRY,
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
        task: None,
        era: crate::protocol::meta::Era::Legacy,
        channel: &crate::gateway::input_bridge::NoClientChannel,
    }
}

fn api_key_caller() -> Caller {
    Caller {
        principal: crate::gateway::auth::principal_of("k-SECRET-123"),
        account: "ci".to_string(),
        authenticated: true,
        grant: None,
        identity: None,
        kind: CredentialKind::ApiKey,
    }
}

fn oidc_caller() -> Caller {
    let identity = VerifiedIdentity {
        subject: "123".to_string(),
        email: "x@corp.com".to_string(),
        name: None,
        groups: vec![],
        issuer: "https://a.example".to_string(),
    };
    let actor = identity.stable_actor_id();
    Caller {
        principal: crate::gateway::auth::principal_of(&actor),
        account: actor,
        authenticated: true,
        grant: Some(GrantSubject::new(
            "https://a.example",
            "123",
            Some("x@corp.com".to_string()),
        )),
        identity: Some(identity),
        kind: CredentialKind::OidcBearer,
    }
}

fn args() -> Value {
    json!({"server": "alpha", "tool": "read", "arguments": {}})
}

/// D1-T4. An OIDC caller is recorded by `(issuer, sub)` and kind; its email
/// and grant label are never written.
#[tokio::test]
async fn invocation_record_names_oidc_subject_and_kind() {
    let dir = tempfile::tempdir().unwrap();
    let meta = meta(Ok(ok_result()), &dir);
    let who = oidc_caller();
    meta.invoke_tool(&args(), None, &context(&AllowAll, &who))
        .await
        .expect("allowed call");
    let record = only_record(&dir);
    assert_eq!(record["schema_version"], json!(2), "{record}");
    assert_eq!(record["outcome"], json!("ok"), "{record}");
    assert_eq!(
        record["who"]["authority"],
        json!("https://a.example"),
        "{record}"
    );
    assert_eq!(record["who"]["subject"], json!("123"), "{record}");
    assert_eq!(
        record["who"]["credential_kind"],
        json!("oidc_bearer"),
        "{record}"
    );
    let trace = record["trace_id"].as_str().unwrap_or_default();
    assert!(!trace.is_empty(), "{record}");
    assert!(!record.to_string().contains("x@corp.com"), "{record}");
}

/// D1-T5. An API-key caller: kind, key name, 12-hex principal, and the key
/// itself nowhere in the log.
#[tokio::test]
async fn api_key_record_never_contains_secret() {
    let dir = tempfile::tempdir().unwrap();
    let meta = meta(Ok(ok_result()), &dir);
    let who = api_key_caller();
    meta.invoke_tool(&args(), None, &context(&AllowAll, &who))
        .await
        .expect("allowed call");
    let record = only_record(&dir);
    assert_eq!(
        record["who"]["credential_kind"],
        json!("api_key"),
        "{record}"
    );
    assert_eq!(record["who"]["account"], json!("ci"), "{record}");
    let principal = record["who"]["principal"].as_str().unwrap_or_default();
    assert!(
        principal.len() == 12 && principal.chars().all(|c| c.is_ascii_hexdigit()),
        "{record}"
    );
    let raw = std::fs::read(dir.path().join("audit.jsonl")).unwrap();
    assert!(
        !raw.windows(12).any(|w| w == b"k-SECRET-123"),
        "the key reached the log"
    );
}

/// D1-T6. A refused call writes one `denied` record with the refusal code and
/// no response hash.
#[tokio::test]
async fn denied_call_writes_denied_record() {
    let dir = tempfile::tempdir().unwrap();
    let meta = meta(Ok(ok_result()), &dir);
    let who = api_key_caller();
    let err = meta
        .invoke_tool(&args(), None, &context(&DenyAll, &who))
        .await
        .expect_err("DenyAll refuses");
    let crate::Error::Forbidden { code, .. } = err else {
        panic!("DenyAll must refuse with Forbidden, got {err:?}");
    };
    let record = only_record(&dir);
    assert_eq!(record["outcome"], json!("denied"), "{record}");
    assert_eq!(record["error_code"], json!(code), "{record}");
    assert!(record.get("response_hash").is_none(), "{record}");
}

/// D1-T7. A backend transport failure writes an `error` record with the
/// failure's code, although the caller receives it as an `isError` tool
/// result (the dispatch path converts it for the LLM's recovery hint).
#[tokio::test]
async fn backend_error_writes_error_record() {
    let dir = tempfile::tempdir().unwrap();
    let meta = meta(Err("connection reset".to_string()), &dir);
    let who = api_key_caller();
    let _ = meta
        .invoke_tool(&args(), None, &context(&AllowAll, &who))
        .await;
    let record = only_record(&dir);
    assert_eq!(record["outcome"], json!("error"), "{record}");
    assert_eq!(record["error_code"], json!(-32000), "{record}");
}

/// D1-T8. A result with `isError: true` is a `tool_error`, with no code.
#[tokio::test]
async fn tool_error_result_is_tool_error() {
    let dir = tempfile::tempdir().unwrap();
    let failing = json!({"content": [{"type": "text", "text": "bad"}], "isError": true});
    let meta = meta(Ok(failing), &dir);
    let who = api_key_caller();
    let _ = meta
        .invoke_tool(&args(), None, &context(&AllowAll, &who))
        .await;
    let record = only_record(&dir);
    assert_eq!(record["outcome"], json!("tool_error"), "{record}");
    assert!(record.get("error_code").is_none(), "{record}");
}

fn sha256_of(value: &Value) -> String {
    format!(
        "sha256:{}",
        crate::hashing::sha256_hex(crate::hashing::canonical_json(value).as_bytes())
    )
}

/// D1-T15. `request_hash` covers the whole params object the caller sent,
/// gateway directives included.
#[tokio::test]
async fn request_hash_covers_what_caller_sent() {
    let dir = tempfile::tempdir().unwrap();
    let meta = meta(Ok(ok_result()), &dir);
    let who = api_key_caller();
    let with_full = json!({
        "server": "alpha",
        "tool": "read",
        "arguments": {"q": 1, "_full": true, "_claim": {"text": "c"}},
    });
    let plain = json!({"server": "alpha", "tool": "read", "arguments": {"q": 1}});
    for sent in [&with_full, &plain] {
        let _ = meta
            .invoke_tool(sent, None, &context(&AllowAll, &who))
            .await;
    }
    let all = records(&dir);
    assert_eq!(all.len(), 2, "{all:?}");
    assert_eq!(
        all[0]["request_hash"],
        json!(sha256_of(&with_full)),
        "{}",
        all[0]
    );
    assert_eq!(
        all[1]["request_hash"],
        json!(sha256_of(&plain)),
        "{}",
        all[1]
    );
    assert_ne!(all[0]["request_hash"], all[1]["request_hash"]);
}

/// D1-T16. `response_hash` covers the value the caller received, after trace
/// and provenance augmentation.
#[tokio::test]
async fn response_hash_covers_returned_value() {
    use crate::attestation::{BnautAttestationSigner, RESULT_PROVENANCE_DOMAIN_INFO};
    let dir = tempfile::tempdir().unwrap();
    let mut meta = meta(Ok(ok_result()), &dir);
    meta.enable_provenance_stamping(
        BnautAttestationSigner::new(b"prov-key".to_vec(), "unit")
            .with_audience("test-gateway")
            .derive_domain(RESULT_PROVENANCE_DOMAIN_INFO),
    );
    let who = api_key_caller();
    let returned = meta
        .invoke_tool(&args(), None, &context(&AllowAll, &who))
        .await
        .expect("allowed call");
    assert_ne!(
        returned,
        ok_result(),
        "precondition: the result was augmented"
    );
    let record = only_record(&dir);
    assert_eq!(
        record["response_hash"],
        json!(sha256_of(&returned)),
        "{record}"
    );
}

/// MIK-7645 AC2: `audit_replay`'s `FailClosed` arm. The fault hits only the
/// replay's own invocation append (the one write after it is armed), so the
/// cell isolates that arm: the replay is withheld with -32005, never
/// delivered unrecorded.
#[tokio::test]
async fn a_replay_whose_record_fails_is_withheld() {
    use crate::security::audit::AuditFailurePolicy;
    use crate::security::transparency_log::rotation_fault::WriteFault;
    let dir = tempfile::tempdir().unwrap();
    let mut meta = meta(Ok(ok_result()), &dir);
    let logger = Arc::new(
        crate::security::TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: dir
                .path()
                .join("closed.jsonl")
                .to_string_lossy()
                .into_owned(),
            key_id: "d1".to_string(),
            ..TransparencyLogConfig::default()
        }))
        .expect("open log")
        .with_failure_policy(AuditFailurePolicy::FailClosed),
    );
    meta.enable_transparency_log(Arc::clone(&logger));
    let who = api_key_caller();
    let replay = crate::protocol::JsonRpcResponse::success(RequestId::Number(7), ok_result());
    logger.arm_write_fault(Some(WriteFault::WriteError));
    let answer = meta
        .audit_replay(
            "gateway_invoke",
            &args(),
            None,
            &context(&AllowAll, &who),
            replay,
            None,
        )
        .await;
    assert!(answer.result.is_none(), "delivered unrecorded: {answer:?}");
    let error = answer.error.expect("the replay is withheld");
    assert_eq!(error.code, -32005, "{error:?}");
    assert_eq!(logger.write_faults_fired(), 1, "the fault hit the record");
}

// MIK-7116.MIN.1 attribution, which reads the firewall's `arg_keys`.
#[cfg(feature = "firewall")]
mod chain_replay;
#[cfg(feature = "firewall")]
mod tenants;

/// MIK-7735. A backend's own `-32001` / `-32004` answer is the peer's
/// refusal, not the gateway's policy: the record says `error`, with the
/// peer's code, never `denied`.
#[tokio::test]
async fn a_peer_error_code_is_not_a_gateway_denial() {
    for code in [-32001, -32004] {
        let dir = tempfile::tempdir().unwrap();
        let meta = meta(Ok(ok_result()), &dir);
        let backend = meta.backends.get("alpha").expect("alpha");
        backend.set_transport_for_test(Arc::new(PeerError(code)));
        let who = api_key_caller();
        let _ = meta
            .invoke_tool(&args(), None, &context(&AllowAll, &who))
            .await;
        let record = only_record(&dir);
        assert_eq!(record["outcome"], json!("error"), "{code}: {record}");
        assert_eq!(record["error_code"], json!(code), "{code}: {record}");
    }
}

/// MIK-7735. A replay records the class its first execution carried, stored
/// beside the cached delivery: the code alone cannot say whose refusal a
/// `-32001` was. A peer's answer replays as `error`, a gateway refusal as
/// `denied`, with the same code.
#[tokio::test]
async fn a_replay_keeps_the_stored_class_of_its_first_execution() {
    use crate::gateway::meta_mcp::admission::ReplayAudit;
    use crate::security::audit::AuditOutcome;
    for (stored, label) in [
        (AuditOutcome::Error(-32001), "error"),
        (AuditOutcome::Denied(-32001), "denied"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let meta = meta(Ok(ok_result()), &dir);
        let who = api_key_caller();
        let delivered =
            crate::protocol::JsonRpcResponse::success(RequestId::Number(1), ok_result());
        let _ = meta
            .audit_replay(
                "gateway_invoke",
                &args(),
                None,
                &context(&AllowAll, &who),
                delivered,
                Some(ReplayAudit::new(stored, None)),
            )
            .await;
        let record = only_record(&dir);
        assert_eq!(record["outcome"], json!(label), "{label}: {record}");
        assert_eq!(record["error_code"], json!(-32001), "{label}: {record}");
    }
}

/// MIK-7735. With no stored class (the first run wrote no record) the replay
/// derives one from the delivered error, which carries a code and no
/// provenance: it must not claim a gateway denial for a bare `-32001`.
#[tokio::test]
async fn a_replayed_error_with_no_stored_class_is_not_claimed_as_a_denial() {
    let dir = tempfile::tempdir().unwrap();
    let meta = meta(Ok(ok_result()), &dir);
    let who = api_key_caller();
    let delivered =
        crate::protocol::JsonRpcResponse::error(Some(RequestId::Number(1)), -32001, "peer says no");
    let _ = meta
        .audit_replay(
            "gateway_invoke",
            &args(),
            None,
            &context(&AllowAll, &who),
            delivered,
            None,
        )
        .await;
    let record = only_record(&dir);
    assert_eq!(record["outcome"], json!("error"), "{record}");
    assert_eq!(record["error_code"], json!(-32001), "{record}");
}
