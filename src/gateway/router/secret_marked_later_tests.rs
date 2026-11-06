// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A value marked secret after answers holding it were stored: every stored
//! answer is scrubbed against the values current when it is sent, so each
//! comes back redacted whatever was current when it was kept. The
//! backend is a real HTTP MCP server whose answers say `received ...`, and the
//! word `received` is the value marked.

use serde_json::json;
use std::sync::Arc;

use super::direct_guards_fixture::{
    fixture_with_secrets_over_http, initialize, post_direct, post_meta_invoke,
};
use super::secret_echo_tests::{Calls, Reply, echo_server};
use super::secret_injection_direct_tests::{SECRET, argument_rule, finished_task, submit_task};

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

/// A fresh keyed task holds no stored output: while a value set refuses,
/// its creation is still acknowledged, never answered with the refusal.
#[tokio::test]
async fn a_fresh_keyed_task_is_acknowledged_while_a_value_set_refuses() {
    let calls = Calls::default();
    let url = echo_server(Arc::clone(&calls), Reply::Echo).await;
    let fx = fixture_with_secrets_over_http(Vec::new(), url).await;
    fx.state.backends.overflow_for_test("alpha");
    let (id, made) = submit_task(&fx, "idem-fresh-while-refusing").await;
    assert!(
        made.get("error").is_none() && !id.is_empty(),
        "the creation was answered with the refusal: {made}"
    );
}

/// A task whose backend echoes the value a `secrets:` rule injected: its
/// stored result read by `tasks/get`, and the keyed repeat that serves it
/// again, each carry the marker in the value's place. Tasks are served on
/// `/mcp` only; `/mcp/{name}` refuses every task method.
#[tokio::test]
async fn an_injected_value_echoed_into_a_task_is_redacted_when_read_and_repeated() {
    let calls = Calls::default();
    let url = echo_server(Arc::clone(&calls), Reply::Echo).await;
    let fx = fixture_with_secrets_over_http(vec![argument_rule()], url).await;
    let (id, _) = submit_task(&fx, "idem-injected-task").await;
    let finished = finished_task(&fx, &id).await;
    assert!(
        calls
            .lock()
            .iter()
            .any(|params| params.pointer("/arguments/api_key") == Some(&json!(SECRET))),
        "premise: the rule injected the value into the task's call"
    );
    let (again, repeated) = submit_task(&fx, "idem-injected-task").await;
    assert_eq!(again, id, "premise: the keyed resubmit names the same task");
    for (what, answer) in [("tasks/get", &finished), ("the keyed repeat", &repeated)] {
        let text = answer.to_string();
        assert!(!text.contains(SECRET), "{what} holds the value: {answer}");
        assert!(text.contains(MARKER), "{what} lost the echo: {answer}");
    }
}
