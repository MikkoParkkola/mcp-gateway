// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Real-process periodic expiry and same-process admission release.
//! Observe completion and disk presence before expiry; recreate the same key
//! before SIGTERM and require a distinct handle plus a second backend call.
//! After graceful exit, restart the same store and verify the expired ID stays absent.
//! In-flight writer joining and retention exclusions are covered by owner tests.

#![cfg(unix)]

#[path = "task_expiry_http_lifecycle/helper.rs"]
mod helper;

use serde_json::{Value, json};

use helper::{
    COMPLETION_BOUND, EXPIRY_BOUND, Gateway, POLL_GAP, durable_records, free_port, serve_backend,
    task_invoke, tasks_get, write_config,
};

const KEY: &str = "task-expiry-http-lifecycle";

const NO_SUCH_TASK_CODE: i64 = -32602;
const NO_SUCH_TASK_MESSAGE: &str = "no such task";

fn task_id_of(created: &Value) -> String {
    created
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            panic!("a declared task-augmented call must be answered with a task handle: {created}")
        })
        .to_string()
}

fn assert_no_such_task(body: &Value, context: &str) {
    assert_eq!(
        body.pointer("/error/code"),
        Some(&json!(NO_SUCH_TASK_CODE)),
        "{context}: the answer must be `missing_task_error`'s own code: {body}"
    );
    assert_eq!(
        body.pointer("/error/message").and_then(Value::as_str),
        Some(NO_SUCH_TASK_MESSAGE),
        "{context}: and its own id-free wording: {body}"
    );
    assert_eq!(
        body.pointer("/error/data"),
        None,
        "{context}: a refusal carrying data about the task hands back what the \
         wording withholds: {body}"
    );
    assert_eq!(
        body["_httpStatus"],
        json!(200),
        "{context}: the modern tail answers an in-band JSON-RPC error with 200; \
         anything else is a different route answering: {body}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[expect(
    clippy::too_many_lines,
    reason = "one end-to-end lifecycle scenario (start, reap, restart, verify) read as a single sequence is the point of this test"
)]
async fn a_configured_expiry_interval_reaps_a_real_task_and_shutdown_releases_the_store() {
    let mock = serve_backend().await;
    let temp_root = tempfile::tempdir().expect("a private root for config, store and logs");
    let root = temp_root.path();
    let port = free_port();
    let config = write_config(root, port, &mock.url);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("bounded HTTP client");

    let mut first = Gateway::start(root, &config, port, "gateway-1.log");
    first.wait_until_ready(&client).await;

    let created = first.post(&client, &task_invoke(1, KEY)).await;
    assert_eq!(
        created.pointer("/result/resultType"),
        Some(&json!("task")),
        "a declared task-augmented call is answered with a task handle, not a \
         synchronous result that dropped the `task` member: {created}\n{}",
        first.logs()
    );
    let first_id = task_id_of(&created);

    mock.backend.wait_for_calls(1).await;

    let mut saw_record = false;
    let mut last = Value::Null;
    let settled = tokio::time::timeout(COMPLETION_BOUND, async {
        loop {
            if durable_records(root)
                .iter()
                .any(|name| name.starts_with(&first_id))
            {
                saw_record = true;
            }
            let body = first.post(&client, &tasks_get(2, &first_id)).await;
            if body.pointer("/result/status") == Some(&json!("completed")) {
                return body;
            }
            last = body;
            tokio::time::sleep(POLL_GAP).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "'{first_id}' never completed within {COMPLETION_BOUND:?}; last answer: {last} \
             (a not-found here means the record expired before the run finished — \
             raise helper::TTL_MS, this is not an expiry defect)\n{}",
            first.logs()
        )
    });
    assert_eq!(
        settled
            .pointer("/result/result/structuredContent/marker")
            .and_then(Value::as_str),
        Some(helper::MARKER),
        "the completed task must carry the actual backend payload, so this is a \
         real dispatch and not a synthesised completion: {settled}\n{}",
        first.logs()
    );
    assert!(
        saw_record,
        "no `{first_id}.json` was ever seen in {}: the task was answered with a \
         handle that no durable record stood behind, and the deletion asserted \
         below would then be the deletion of nothing\n{}",
        helper::store_dir(root).display(),
        first.logs()
    );

    let mut last = Value::Null;
    let expired = tokio::time::timeout(EXPIRY_BOUND, async {
        loop {
            let body = first.post(&client, &tasks_get(3, &first_id)).await;
            let gone_from_disk = !durable_records(root)
                .iter()
                .any(|name| name.starts_with(&first_id));
            if body.get("error").is_some() && gone_from_disk {
                return body;
            }
            last = body;
            tokio::time::sleep(POLL_GAP).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "'{first_id}' was still readable and/or still on disk {EXPIRY_BOUND:?} after \
             creation, with tasks.default_ttl_ms={} and tasks.expiry_interval={:?}: the \
             configured sweep did not run. Last answer: {last}; records: {:?}\n{}",
            helper::TTL_MS,
            helper::EXPIRY_INTERVAL,
            durable_records(root),
            first.logs()
        )
    });
    assert_no_such_task(&expired, "the expired task, read from the first child");
    assert_eq!(
        mock.backend.calls(),
        1,
        "expiry is not a dispatch: the only backend run is the create's\n{}",
        first.logs()
    );

    let recreated = first.post(&client, &task_invoke(5, KEY)).await;
    assert_eq!(
        recreated.pointer("/result/resultType"),
        Some(&json!("task")),
        "the same key after expiry is a fresh logical request and must be \
         admitted: {recreated}\n{}",
        first.logs()
    );
    let second_id = task_id_of(&recreated);
    assert_ne!(
        second_id,
        first_id,
        "reusing the key after expiry must mint a DISTINCT handle; the same id \
         back is the deleted task being replayed\n{}",
        first.logs()
    );

    mock.backend.wait_for_calls(2).await;
    let mut last = Value::Null;
    let settled = tokio::time::timeout(COMPLETION_BOUND, async {
        loop {
            let body = first.post(&client, &tasks_get(6, &second_id)).await;
            if body.pointer("/result/status") == Some(&json!("completed")) {
                return body;
            }
            last = body;
            tokio::time::sleep(POLL_GAP).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "the re-created '{second_id}' never completed within {COMPLETION_BOUND:?}; \
             last answer: {last}\n{}",
            first.logs()
        )
    });
    assert_eq!(
        settled
            .pointer("/result/result/structuredContent/marker")
            .and_then(Value::as_str),
        Some(helper::MARKER),
        "the second run carries the backend's payload too: {settled}\n{}",
        first.logs()
    );

    let status = first.terminate().await;
    assert!(
        status.success(),
        "SIGTERM must end in a clean exit ({status}): a gateway that dies any \
         other way has not run its shutdown path, so nothing below could \
         distinguish a released lease from a crashed one\n{}",
        first.logs()
    );
    drop(first);

    let mut second = Gateway::start(root, &config, port, "gateway-2.log");
    second.wait_until_ready(&client).await;

    let replayed = second.post(&client, &tasks_get(4, &first_id)).await;
    assert_no_such_task(&replayed, "the expired handle, after a restart");

    let status = second.terminate().await;
    assert!(
        status.success(),
        "the second child must also exit cleanly ({status})\n{}",
        second.logs()
    );
}
