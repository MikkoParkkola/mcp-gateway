// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7324.COV.3: the stdio path's first step (`Gateway::prepare_signing`)
//! refuses a malformed chain nonce before anything parses the request, and
//! the refusal keeps the caller's id. A well-formed nonce is not refused.
//! With message signing on, a signing envelope it cannot restore is refused
//! with no id at all.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::backend::BackendRegistry;
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::mrtr::CHAIN_NONCE_META;

async fn dispatch(nonce: Value) -> Value {
    let meta = Arc::new(MetaMcp::new(Arc::new(BackendRegistry::new())));
    let request = json!({
        "jsonrpc": "2.0",
        "id": "cov3-nonce",
        "method": "tools/call",
        "params": {
            "name": "gateway_list_servers",
            "arguments": {},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
                (CHAIN_NONCE_META): nonce
            }
        }
    });
    dispatch_on(&meta, request).await
}

async fn dispatch_on(meta: &Arc<MetaMcp>, request: Value) -> Value {
    dispatch_sanitizing(
        meta,
        request,
        crate::gateway::server::stdio_single::InputSanitizing::Off,
    )
    .await
}

async fn dispatch_sanitizing(
    meta: &Arc<MetaMcp>,
    request: Value,
    sanitize: crate::gateway::server::stdio_single::InputSanitizing,
) -> Value {
    let mtls_policy = Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig::default(),
    ));
    super::super::Gateway::dispatch_single_for_client(
        meta,
        &crate::gateway::authz::default_line(meta),
        &mtls_policy,
        request,
        super::super::StdioClient {
            session_id: "cov3-stdio",
            channel: &crate::gateway::input_bridge::NoClientChannel,
            handshake_capabilities: crate::protocol::meta::Declared::NONE,
            tasks: None,
            serving: crate::gateway::server::stdio_single::ModernServing::Enabled,
            discover: crate::gateway::server::stdio_single::DiscoverListing::Configured,
            sanitize,
        },
    )
    .await
    .expect("a request carrying an id is answered")
}

#[tokio::test]
async fn a_malformed_chain_nonce_is_refused_with_the_callers_id() {
    let too_long = "n".repeat(257);
    for nonce in [json!(""), json!(7), json!(too_long)] {
        let response = dispatch(nonce.clone()).await;
        assert_eq!(
            response.pointer("/error/code").and_then(Value::as_i64),
            Some(-32602),
            "nonce {nonce} must be refused as invalid params: {response}"
        );
        assert_eq!(response["id"], json!("cov3-nonce"), "{response}");
        let message = response
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(message.contains(CHAIN_NONCE_META), "{message}");
    }
}

#[tokio::test]
async fn a_well_formed_chain_nonce_is_not_refused() {
    let response = dispatch(json!("n-1")).await;
    assert!(response.get("error").is_none(), "{response}");
    assert_eq!(response["id"], json!("cov3-nonce"), "{response}");
    assert!(response.get("result").is_some(), "{response}");
}

/// The signing fixture's audit log.
#[derive(Clone, Copy)]
enum Audit {
    /// No transparency log.
    Off,
    /// A log in the fixture's directory (`audit.jsonl`), best-effort.
    Logged,
    /// The same log failing closed, which the server picks when auth is on.
    FailClosed,
}

/// A `MetaMcp` with message signing on, built by the production constructor
/// and builder.
async fn signing_meta() -> (Arc<MetaMcp>, std::sync::Arc<tempfile::TempDir>) {
    signing_meta_with(Audit::Off).await
}

/// [`signing_meta`] with its audit log as `audit` says.
async fn signing_meta_with(audit: Audit) -> (Arc<MetaMcp>, std::sync::Arc<tempfile::TempDir>) {
    let mut config = crate::config::Config::default();
    config.server.modern_protocol = true;
    let signing = &mut config.security.message_signing;
    signing.enabled = true;
    signing.shared_secret = "a-signing-secret-that-is-at-least-32-bytes!!!!".to_string();
    signing.key_id = "cov3-stdio".to_string();
    let data_dir = crate::test_dir_keep::kept_tempdir();
    if !matches!(audit, Audit::Off) {
        config.security.transparency_log.enabled = Some(true);
        config.security.transparency_log.path =
            crate::gateway::meta_mcp::grant_audit_fixture::log_path(&data_dir)
                .to_string_lossy()
                .into_owned();
    }
    if matches!(audit, Audit::FailClosed) {
        config.auth.enabled = true;
        config.auth.api_keys = vec![crate::config::ApiKeyConfig {
            name: "stdio".to_string(),
            key_sha256: Some(crate::config::api_key_digest_spec(b"k")),
            ..Default::default()
        }];
    }
    let built = super::super::Gateway::new(config)
        .await
        .expect("the config is valid")
        .with_data_dir(data_dir.path().to_path_buf())
        .build_meta_mcp_published()
        .await
        .expect("the builder accepts it");
    assert!(built.meta_mcp.signing_enabled(), "the fixture must sign");
    (built.meta_mcp, data_dir)
}

fn external_invoke(id: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "gateway_invoke",
            "arguments": { "server": "absent", "tool": "t", "arguments": {} },
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        }
    })
}

/// The envelope keeps a string or integer id; any other id cannot be restored,
/// so the refusal carries no id rather than echoing one it did not accept.
#[tokio::test]
async fn with_signing_on_an_unrestorable_envelope_is_refused_with_no_id() {
    let (meta, _dir) = signing_meta().await;
    let response = dispatch_on(&meta, external_invoke(&json!({ "not": "an id" }))).await;
    assert_eq!(
        response.pointer("/error/code").and_then(Value::as_i64),
        Some(-32600),
        "{response}"
    );
    assert_eq!(
        response.pointer("/error/message").and_then(Value::as_str),
        Some("Invalid signing request ID"),
        "{response}"
    );
    assert_eq!(response["id"], Value::Null, "{response}");
}

/// Control: the same call with a string id gets past the envelope, and
/// whatever it is answered with carries that id.
#[tokio::test]
async fn with_signing_on_a_restorable_envelope_keeps_its_id() {
    let (meta, _dir) = signing_meta().await;
    let response = dispatch_on(&meta, external_invoke(&json!("cov3-signed"))).await;
    assert_eq!(response["id"], json!("cov3-signed"), "{response}");
    assert_ne!(
        response.pointer("/error/message").and_then(Value::as_str),
        Some("Invalid signing request ID"),
        "{response}"
    );
}

/// C6 gap table rank 3 (startup, `Gateway::prepare_signing`): a request other
/// than `tools/call` is refused for a malformed chain nonce by this step
/// alone. `tools/call` re-checks the nonce at dispatch, which would hide this
/// step failing open; `tools/list` has no second check.
#[tokio::test]
async fn a_malformed_chain_nonce_on_another_method_is_refused() {
    let meta = Arc::new(MetaMcp::new(Arc::new(BackendRegistry::new())));
    let request = json!({
        "jsonrpc": "2.0",
        "id": "cov3-list",
        "method": "tools/list",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
                (CHAIN_NONCE_META): ""
            }
        }
    });
    let response = dispatch_on(&meta, request).await;
    assert_eq!(
        response.pointer("/error/code").and_then(Value::as_i64),
        Some(-32602),
        "a malformed nonce must be refused as invalid params: {response}"
    );
    assert_eq!(response["id"], json!("cov3-list"), "{response}");
    let message = response
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(message.contains(CHAIN_NONCE_META), "{message}");
}

/// The fixture's invocation records, with the one refusal record every
/// envelope row expects: denied, -32600, the request's form (`syntax`).
/// The envelope error is a plain -32600: the writer notes the intake site's
/// kind as a refusal, then classes the outcome denied. The target is the one
/// [`external_invoke`] names, on the meta route.
fn assert_one_envelope_record(dir: &tempfile::TempDir, response: &Value) {
    let records = crate::gateway::meta_mcp::grant_audit_fixture::invocations(dir);
    let [record] = records.as_slice() else {
        panic!("exactly one record: {records:#?}; answer {response}");
    };
    assert_eq!(record["outcome"], json!("denied"), "{record}");
    assert_eq!(record["error_code"], json!(-32600), "{record}");
    assert_eq!(record["decision"]["kind"], json!("syntax"), "{record}");
    assert_eq!(record["route"], json!("meta"), "{record}");
    assert_eq!(record["server"], json!("absent"), "{record}");
    assert_eq!(record["tool"], json!("t"), "{record}");
}

/// E3: the unrestorable envelope of the row above, with
/// the log on: answered exactly as that row pins, and recorded once.
#[tokio::test]
async fn e3_stdio_an_unrestorable_envelope_is_recorded() {
    let (meta, dir) = signing_meta_with(Audit::Logged).await;
    let response = dispatch_on(&meta, external_invoke(&json!({ "not": "an id" }))).await;
    assert_eq!(
        response.pointer("/error/code").and_then(Value::as_i64),
        Some(-32600),
        "{response}"
    );
    assert_eq!(
        response.pointer("/error/message").and_then(Value::as_str),
        Some("Invalid signing request ID"),
        "{response}"
    );
    assert_eq!(response["id"], Value::Null, "{response}");
    assert_one_envelope_record(&dir, &response);
}

/// E3b: a name that becomes `gateway_invoke` only once
/// sanitizing strips its BEL (as `signed_order`'s S6 on `/mcp`) changes the
/// request's origin. The answer has no id although the request's id (1)
/// was usable, and the refusal is recorded once.
#[tokio::test]
async fn e3b_stdio_a_changed_origin_is_recorded_and_answered_with_no_id() {
    let (meta, dir) = signing_meta_with(Audit::Logged).await;
    let mut request = external_invoke(&json!(1));
    request["params"]["name"] = json!("gateway_\u{7}invoke");
    let response = dispatch_sanitizing(
        &meta,
        request,
        crate::gateway::server::stdio_single::InputSanitizing::On,
    )
    .await;
    assert_eq!(
        response.pointer("/error/code").and_then(Value::as_i64),
        Some(-32600),
        "{response}"
    );
    assert_eq!(
        response.pointer("/error/message").and_then(Value::as_str),
        Some("Invalid signing request origin"),
        "{response}"
    );
    assert_eq!(response["id"], Value::Null, "{response}");
    assert_one_envelope_record(&dir, &response);
}

/// E5: E3's request under a log that fails closed and
/// cannot be written: the answer is the log's unavailability, still with no
/// id, and nothing is recorded.
#[tokio::test]
async fn e5_stdio_a_fail_closed_log_that_cannot_write_answers_unavailable() {
    let (meta, dir) = signing_meta_with(Audit::FailClosed).await;
    meta.transparency_log()
        .expect("the fixture logs")
        .set_append_failure_for_test(true);
    let response = dispatch_on(&meta, external_invoke(&json!({ "not": "an id" }))).await;
    assert_eq!(
        (
            response.pointer("/error/code").and_then(Value::as_i64),
            response["id"].is_null()
        ),
        (Some(-32005), true),
        "{response}"
    );
    assert!(
        crate::gateway::meta_mcp::grant_audit_fixture::invocations(&dir).is_empty(),
        "no record: {response}"
    );
}
