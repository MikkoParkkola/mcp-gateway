// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend that echoes the secret its rule injects: the echo is redacted in
//! every answer and in everything the gateway keeps. That covers a repeat the
//! idempotency cache serves, a task's answer and its keyed resubmit, and the
//! task store on disk. The backend is a real HTTP MCP server, so its bytes
//! pass through the transport where the scrub runs.

use serde_json::json;
use std::sync::Arc;

use super::direct_guards_fixture::{fixture_with_secrets_served_by, initialize, post_meta_invoke};
use super::secret_echo_tests::{Calls, Reply, echo_server};
use super::secret_injection_direct_tests::{
    SECRET, argument_rule, files_under, finished_task, holds, submit_task,
};

/// The marker an echoed secret is replaced with.
const MARKER: &str = "[redacted]";

/// The echo is redacted in a keyed answer and its cached repeat, in a task's
/// answer and its keyed resubmit, and in the stored task. Each sink is first
/// shown to hold the call (T1.12, T2.1).
#[tokio::test]
async fn an_echo_is_redacted_in_every_answer_and_everything_kept() {
    let calls = Calls::default();
    let url = echo_server(Arc::clone(&calls), Reply::Echo).await;
    let fx = fixture_with_secrets_served_by(vec![argument_rule()], url).await;
    let session = initialize(&fx, "k-std").await;
    let mut answers = Vec::new();
    for _ in 0..2 {
        let (_, body) = post_meta_invoke(
            &fx,
            "k-std",
            "alpha",
            "read",
            json!({}),
            Some("idem-echo-1"),
            Some(&session),
        )
        .await;
        assert!(body.get("error").is_none(), "premise: {body}");
        answers.push(body);
    }
    assert_eq!(
        calls.lock().len(),
        1,
        "premise: the repeat was served from the cache"
    );
    assert_eq!(
        calls.lock()[0].pointer("/arguments/api_key"),
        Some(&json!(SECRET)),
        "premise: the call carried the injected secret"
    );

    let (id, made) = submit_task(&fx, "idem-echo-task").await;
    let finished = finished_task(&fx, &id).await;
    assert_eq!(
        calls.lock().len(),
        2,
        "premise: the task's own send reached the backend"
    );
    let (again, resubmitted) = submit_task(&fx, "idem-echo-task").await;
    assert_eq!(again, id, "premise: the keyed resubmit names the same task");
    assert_eq!(
        calls.lock().len(),
        2,
        "premise: the resubmit dispatched nothing"
    );

    for answer in &answers {
        let text = answer.to_string();
        assert!(
            !text.contains(SECRET),
            "an answer holds the secret: {answer}"
        );
        assert!(
            text.contains(MARKER),
            "an answer was emptied, not redacted: {answer}"
        );
    }
    for answer in [&made, &finished, &resubmitted] {
        assert!(
            !answer.to_string().contains(SECRET),
            "a task answer holds the secret: {answer}"
        );
    }

    let stored = files_under(fx.store_path());
    assert!(
        stored.iter().any(|(_, bytes)| holds(bytes, &id)),
        "premise: a scanned file holds the stored task"
    );
    let kept: Vec<_> = stored
        .iter()
        .filter(|(_, bytes)| holds(bytes, SECRET))
        .map(|(path, _)| path)
        .collect();
    assert!(kept.is_empty(), "a stored file holds the secret: {kept:?}");
    assert!(
        stored.iter().any(|(_, bytes)| holds(bytes, MARKER)),
        "the stored task result was emptied, not redacted"
    );
}
