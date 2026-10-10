// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2480: a stdio call answered from a completed execution (an idempotent
//! replay) writes one invocation record, as the HTTP meta route does (#2477).

use serde_json::{Value, json};

use super::signing_nonce_allocations_support::{Fixture, SESSION, invoke};
use crate::gateway::meta_mcp::grant_audit_fixture::{invocations, log_path, logger};

/// `invoke` carrying `key` in `_meta`, where the stdio dispatcher reads it.
fn keyed_request(id: &str, key: &str) -> Value {
    let mut request = invoke(id, None, json!({"note": "2480"}));
    request["params"]["_meta"][crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    request
}

/// The production stdio entry point, called as `run_stdio` calls it.
async fn dispatch(fixture: &Fixture, request: Value) -> Value {
    super::super::Gateway::dispatch_single_with_sink(
        &fixture.meta,
        &fixture.tool_policy,
        &fixture.mtls_policy,
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

/// AC3. The re-issued key is answered from the first execution without
/// reaching the backend, and still writes its own record carrying the first
/// execution's outcome, code and hashes.
#[tokio::test]
async fn stdio_replay_writes_an_invocation_record() {
    let dir = tempfile::tempdir().expect("a private log directory");
    let fixture = Fixture::start_audited(&log_path(&dir)).await;
    let first = dispatch(&fixture, keyed_request("r1", "key-2480")).await;
    assert!(first.get("error").is_none(), "{first}");
    let second = dispatch(&fixture, keyed_request("r2", "key-2480")).await;
    assert!(second.get("error").is_none(), "{second}");
    assert_eq!(
        fixture.backend.tools_call_count(),
        1,
        "the second call must be a replay: {second}"
    );

    let all = invocations(&dir);
    assert_eq!(all.len(), 2, "one record per delivered call: {all:#?}");
    let (original, replay) = (&all[0], &all[1]);
    assert!(replay.get("response_hash").is_some(), "{replay}");
    for field in ["outcome", "error_code", "request_hash", "response_hash"] {
        assert_eq!(replay[field], original[field], "{field}: {replay}");
    }
}

/// MIK-7920.STDIO.3: under fail-closed, a refused delivery record withholds
/// the first answer, and the stored delivery of its sync admission is that
/// refusal. A replay of the key answers the refusal; it must not deliver the
/// value the first call never delivered (the stdio row of
/// `direct_audit_tests/meta_replay.rs`).
#[tokio::test]
async fn stdio_replay_after_a_refused_delivery_record_stays_withheld() {
    use crate::security::audit::AuditFailurePolicy;
    let dir = tempfile::tempdir().expect("a private log directory");
    let log = logger(&dir, AuditFailurePolicy::FailClosed);
    let mut fixture = Fixture::start_mutating().await;
    std::sync::Arc::get_mut(&mut fixture.meta)
        .expect("the fixture holds the only handle")
        .enable_transparency_log(std::sync::Arc::clone(&log));
    log.fail_next_append_of_kind_for_test("response_delivery_attempt");
    let first = dispatch(&fixture, keyed_request("r1", "key-7920")).await;
    assert_eq!(
        first["error"]["code"], -32005,
        "the first value must be withheld: {first}"
    );
    let second = dispatch(&fixture, keyed_request("r2", "key-7920")).await;
    assert_eq!(
        fixture.backend.tools_call_count(),
        1,
        "the second call must be a replay: {second}"
    );
    assert_eq!(
        second["error"]["code"], -32005,
        "the replay must not deliver the withheld value: {second}"
    );
}
