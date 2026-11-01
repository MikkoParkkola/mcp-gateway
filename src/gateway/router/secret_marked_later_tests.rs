// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A value marked secret after answers holding it were stored: every stored
//! answer is scrubbed against the values current when it is sent, so each
//! comes back redacted whatever was current when it was kept (MIK-9105). The
//! backend is a real HTTP MCP server whose answers say `received ...`, and the
//! word `received` is the value marked.

use serde_json::json;
use std::sync::Arc;

use super::direct_guards_fixture::{
    fixture_with_secrets_over_http, initialize, post_direct, post_meta_invoke,
};
use super::secret_echo_tests::{Calls, Reply, echo_server};
use super::secret_injection_direct_tests::{finished_task, submit_task};

/// The text every echo answer holds, marked secret after it was stored.
const MARKED: &str = "received";

/// The marker a redacted value is replaced with.
const MARKER: &str = "[redacted]";

fn redacted(answer: &serde_json::Value, what: &str) {
    let text = answer.to_string();
    assert!(
        !text.contains(MARKED),
        "{what} still holds the marked value: {answer}"
    );
    assert!(
        text.contains(MARKER),
        "{what} was emptied, not redacted: {answer}"
    );
}

/// A keyed call's stored answer (served again by its idempotency key), a
/// stored task's result (`tasks/get`) and a repeated keyed task: each was
/// kept while the value was plain, and each is redacted once it is marked.
/// None of them calls the backend again.
#[tokio::test]
async fn answers_kept_before_a_value_was_marked_are_redacted_when_served() {
    let calls = Calls::default();
    let url = echo_server(Arc::clone(&calls), Reply::Echo).await;
    let fx = fixture_with_secrets_over_http(Vec::new(), url).await;
    let session = initialize(&fx, "k-std").await;
    let invoke = || {
        post_meta_invoke(
            &fx,
            "k-std",
            "alpha",
            "read",
            json!({}),
            Some("idem-marked-1"),
            Some(&session),
        )
    };
    let (_, first) = invoke().await;
    assert!(
        first.to_string().contains(MARKED),
        "premise: kept while plain: {first}"
    );
    let (id, _) = submit_task(&fx, "idem-marked-task").await;
    let finished = finished_task(&fx, &id).await;
    assert!(
        finished.to_string().contains(MARKED),
        "premise: kept while plain: {finished}"
    );
    let (_, repeated) = submit_task(&fx, "idem-marked-task").await;
    assert!(
        repeated.to_string().contains(MARKED),
        "premise: a repeated keyed task serves the stored output: {repeated}"
    );
    let sent = calls.lock().len();

    fx.state.backends.mark_for_test("alpha", MARKED);

    let (_, repeat) = invoke().await;
    redacted(&repeat, "the keyed call's stored answer");
    redacted(&finished_task(&fx, &id).await, "the stored task's result");
    let (again, resubmitted) = submit_task(&fx, "idem-marked-task").await;
    assert_eq!(again, id, "premise: the keyed resubmit names the same task");
    redacted(&resubmitted, "the repeated keyed task");
    assert_eq!(
        calls.lock().len(),
        sent,
        "premise: every answer came from a store"
    );
}

/// The direct route: a keyed call's stored answer, served again by its key
/// after the value it holds was marked, is redacted, and the backend is not
/// called again.
#[tokio::test]
async fn a_direct_route_keyed_repeat_is_redacted_when_served() {
    let calls = Calls::default();
    let url = echo_server(Arc::clone(&calls), Reply::Echo).await;
    let fx = fixture_with_secrets_over_http(Vec::new(), url).await;
    let session = initialize(&fx, "k-std").await;
    let call = || {
        post_direct(
            &fx,
            "alpha",
            "k-std",
            "read",
            json!({}),
            Some("idem-direct-marked"),
            Some(&session),
        )
    };
    let (_, first) = call().await;
    assert!(
        first.to_string().contains(MARKED),
        "premise: kept while plain: {first}"
    );
    let sent = calls.lock().len();

    fx.state.backends.mark_for_test("alpha", MARKED);

    let (_, repeat) = call().await;
    redacted(&repeat, "the direct route's stored answer");
    assert_eq!(
        calls.lock().len(),
        sent,
        "premise: the repeat came from a store"
    );
}
