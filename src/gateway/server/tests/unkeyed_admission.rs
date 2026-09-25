// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F10: an un-keyed modern `tools/call` is admitted unprotected by default and
//! refused only under `server.idempotency_key: required`.
//!
//! Driven through the production stdio dispatcher (T9), which reaches the same
//! `admit_meta_sync` → `admit_operation` refusal point as the HTTP meta route.
//! Counter rows read a scoped Prometheus recorder, so the tests stay on the
//! current-thread runtime and await dispatch inline.

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use serde_json::{Value, json};

use super::signing_nonce_allocations_support::{Fixture, SESSION, Target, error_of, invoke};
use crate::config::IdempotencyKeyMode::{Optional, Required};

const COUNTER: &str = "mcp_unkeyed_calls_total";

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
        },
        &super::super::StdioTelemetry::default(),
    )
    .await
    .expect("a request carrying an id must produce a response")
}

fn with_key(mut request: Value, key: Value) -> Value {
    request["params"]["_meta"][crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = key;
    request
}

/// A legacy frame carries none of the `io.modelcontextprotocol/*` keys; one
/// present and the rest absent is the malformed shape, not a legacy one.
fn legacy(mut request: Value) -> Value {
    request["params"]["_meta"]
        .as_object_mut()
        .expect("the invoke builder must produce a _meta object")
        .retain(|key, _| !key.starts_with("io.modelcontextprotocol/"));
    request
}

/// Every `mcp_unkeyed_calls_total` sample as (label set, value).
fn samples(handle: &PrometheusHandle) -> Vec<(Vec<String>, u64)> {
    handle
        .render()
        .lines()
        .filter_map(|line| line.strip_prefix(COUNTER))
        .filter_map(|rest| rest.strip_prefix('{'))
        .map(|rest| {
            let (labels, value) = rest.split_once("} ").expect("labelled sample");
            let mut labels: Vec<String> = labels.split(',').map(str::to_owned).collect();
            labels.sort();
            (labels, value.trim().parse().expect("counter value"))
        })
        .collect()
}

fn count(handle: &PrometheusHandle, era: &str, read_only: bool) -> u64 {
    let want = vec![
        format!("era=\"{era}\""),
        format!("read_only_hint=\"{read_only}\""),
    ];
    samples(handle)
        .into_iter()
        .filter(|(labels, _)| *labels == want)
        .map(|(_, value)| value)
        .sum()
}

fn total(handle: &PrometheusHandle) -> u64 {
    samples(handle).into_iter().map(|(_, value)| value).sum()
}

fn assert_ok(phase: &str, response: &Value) {
    assert!(
        response.get("error").is_none(),
        "{phase} must succeed, got {response}"
    );
}

fn assert_invalid_params(phase: &str, response: &Value) -> String {
    let (code, message) = error_of(response);
    assert_eq!(code, -32602, "{phase} must be -32602, got {response}");
    message
}

fn recorder() -> (
    metrics_exporter_prometheus::PrometheusRecorder,
    PrometheusHandle,
) {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    (recorder, handle)
}

/// T1 + T9: the default admits an un-keyed modern mutation, once, counted with
/// exactly `{era, read_only_hint}` and no principal label.
#[tokio::test]
async fn t1_unkeyed_modern_mutation_is_admitted_by_default() {
    let fixture = Fixture::start_keyed_mode(Target::MutatingUncached, Optional).await;
    let (recorder, handle) = recorder();
    let _guard = telemetry_metrics::set_default_local_recorder(&recorder);

    let response = dispatch(&fixture, invoke("t1", None, json!({}))).await;

    assert_ok("an un-keyed modern mutation under optional", &response);
    assert_eq!(fixture.backend.tools_call_count(), 1);
    assert_eq!(count(&handle, "modern", false), 1, "{}", handle.render());
    for (labels, _) in samples(&handle) {
        let names: Vec<&str> = labels
            .iter()
            .map(|label| label.split('=').next().unwrap_or_default())
            .collect();
        assert_eq!(names, ["era", "read_only_hint"], "label set: {labels:?}");
    }
}

/// T2 + T9: `required` restores the refusal, names the key, and neither
/// reaches the backend nor moves the counter.
#[tokio::test]
async fn t2_required_refuses_unkeyed_modern_mutation() {
    let fixture = Fixture::start_keyed_mode(Target::MutatingUncached, Required).await;
    let (recorder, handle) = recorder();
    let _guard = telemetry_metrics::set_default_local_recorder(&recorder);

    let response = dispatch(&fixture, invoke("t2", None, json!({}))).await;

    let message = assert_invalid_params("an un-keyed modern mutation under required", &response);
    assert!(
        message.contains(crate::protocol::mrtr::IDEMPOTENCY_KEY_META),
        "the refusal must name the key: {message}"
    );
    assert_eq!(fixture.backend.tools_call_count(), 0);
    assert_eq!(total(&handle), 0, "{}", handle.render());
}

/// T3: a keyed call re-issued under a new request id executes once, in both
/// modes (existing guarantee).
#[tokio::test]
async fn t3_keyed_reissue_executes_once() {
    for mode in [Optional, Required] {
        let fixture = Fixture::start_keyed_mode(Target::MutatingUncached, mode).await;
        let (recorder, handle) = recorder();
        let _guard = telemetry_metrics::set_default_local_recorder(&recorder);
        for id in ["t3-a", "t3-b"] {
            let request = with_key(invoke(id, None, json!({})), json!("t3-key"));
            assert_ok("a keyed call", &dispatch(&fixture, request).await);
        }
        assert_eq!(fixture.backend.tools_call_count(), 1, "{mode:?}");
        assert_eq!(total(&handle), 0, "a keyed call is not un-keyed");
    }
}

/// T4: a malformed key is -32602 in both modes, before execution.
#[tokio::test]
async fn t4_malformed_key_is_refused_in_both_modes() {
    for mode in [Optional, Required] {
        let fixture = Fixture::start_keyed_mode(Target::MutatingUncached, mode).await;
        let (recorder, handle) = recorder();
        let _guard = telemetry_metrics::set_default_local_recorder(&recorder);
        let request = with_key(invoke("t4", None, json!({})), json!(42));
        assert_invalid_params("a malformed key", &dispatch(&fixture, request).await);
        assert_eq!(fixture.backend.tools_call_count(), 0, "{mode:?}");
        assert_eq!(total(&handle), 0, "a refusal is not an admission");
    }
}

/// T5: a read-only-marked tool, un-keyed, is admitted and counted as such.
#[tokio::test]
async fn t5_unkeyed_read_only_call_is_counted_read_only() {
    let fixture = Fixture::start_keyed_mode(Target::ReadOnlyCached, Optional).await;
    let (recorder, handle) = recorder();
    let _guard = telemetry_metrics::set_default_local_recorder(&recorder);

    let response = dispatch(&fixture, invoke("t5", None, json!({}))).await;

    assert_ok("an un-keyed read-only call", &response);
    assert_eq!(count(&handle, "modern", true), 1, "{}", handle.render());
    assert_eq!(total(&handle), 1);
}

/// T7: the accepted exposure. An un-keyed re-issue cannot be recognised, so it
/// executes twice and counts twice.
#[tokio::test]
async fn t7_unkeyed_reissue_executes_twice_by_default() {
    let fixture = Fixture::start_keyed_mode(Target::MutatingUncached, Optional).await;
    let (recorder, handle) = recorder();
    let _guard = telemetry_metrics::set_default_local_recorder(&recorder);

    for id in ["t7-a", "t7-b"] {
        assert_ok(
            "an un-keyed call",
            &dispatch(&fixture, invoke(id, None, json!({}))).await,
        );
    }

    assert_eq!(fixture.backend.tools_call_count(), 2);
    assert_eq!(count(&handle, "modern", false), 2, "{}", handle.render());
}

/// T8: `required` refuses neither a legacy frame nor a read-only-marked tool.
#[tokio::test]
async fn t8_required_scope_excludes_legacy_and_read_only() {
    let fixture = Fixture::start_keyed_mode(Target::MutatingUncached, Required).await;
    let (recorder, handle) = recorder();
    let _guard = telemetry_metrics::set_default_local_recorder(&recorder);
    let response = dispatch(&fixture, legacy(invoke("t8-legacy", None, json!({})))).await;
    assert_ok("an un-keyed legacy mutation under required", &response);
    assert_eq!(fixture.backend.tools_call_count(), 1);
    assert_eq!(count(&handle, "legacy", false), 1, "{}", handle.render());

    let fixture = Fixture::start_keyed_mode(Target::ReadOnlyCached, Required).await;
    let response = dispatch(&fixture, invoke("t8-read", None, json!({}))).await;
    assert_ok("an un-keyed read-only call under required", &response);
    assert_eq!(count(&handle, "modern", true), 1, "{}", handle.render());
}
