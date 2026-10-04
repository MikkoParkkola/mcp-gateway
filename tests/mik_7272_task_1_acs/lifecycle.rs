// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::*;

// =======================================================================
// MIK-7311.LIFECYCLE.2 — an accepted task survives the loss of the
// connection that created it, stays queryable by the same principal, and
// stays invisible to every other one.
// =======================================================================

/// Both not-found verbs, each anchored to a KNOWN refusal rather than to
/// two agreeing unknowns.
///
/// Byte-identity alone proves only that two answers match; it is satisfied
/// by a gateway that answers both with a success. The code and the message
/// are therefore asserted first, against the one constant the gateway uses
/// for absent-or-foreign (`missing_task_error`,
/// `src/gateway/router/handlers.rs:216`), and the identity is what proves
/// the refusal discloses nothing further.
async fn refused_identically(
    state: &Arc<AppState>,
    principal: &str,
    id_from: i64,
    method: &str,
    real_task: &str,
) {
    let (_, real) = post_against(
        Arc::clone(state),
        principal,
        modern(id_from, method, json!({ "taskId": real_task }), true),
    )
    .await;
    let (_, fabricated) = post_against(
        Arc::clone(state),
        principal,
        modern(
            id_from + 1,
            method,
            json!({ "taskId": FABRICATED_ID }),
            true,
        ),
    )
    .await;

    assert_eq!(
        real.pointer("/error/code").and_then(Value::as_i64),
        Some(-32602),
        "'{method}' on a task this caller does not own must be refused as absent: {real}"
    );
    assert_eq!(
        real.pointer("/error/message").and_then(Value::as_str),
        Some("no such task"),
        "the refusal must carry the one constant message, not a narrating one: {real}"
    );
    assert_eq!(
        shape(real),
        shape(fabricated),
        "'{method}' on another principal's task must be byte-identical to an id \
         that never existed"
    );
}

/// Poll `tasks/get` AS `principal` until the task is terminal.
///
/// The unattributed poller cannot be used here: these rows run with
/// authentication on and `/mcp` closed, so an unattributed request never
/// reaches a task handler at all.
async fn poll_until_terminal(
    state: &Arc<AppState>,
    principal: &str,
    id_from: i64,
    task_id: &str,
) -> Value {
    let mut last = Value::Null;
    tokio::time::timeout(fixture::BOUND, async {
        let mut request_id = id_from;
        loop {
            let (_, body) = post_against(
                Arc::clone(state),
                principal,
                modern(request_id, "tasks/get", json!({ "taskId": task_id }), true),
            )
            .await;
            request_id += 1;
            if let Some("completed" | "failed" | "cancelled") =
                body.pointer("/result/status").and_then(Value::as_str)
            {
                return body;
            }
            last = body;
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "'{task_id}' never reached a terminal status within {:?}: {last}",
            fixture::BOUND
        )
    })
}

/// Wait until every subscription permit is back in the registry.
///
/// The permit is released when the stream's body is dropped, which happens
/// on another task, so the return is awaited rather than assumed.
async fn await_no_open_subscriptions(state: &Arc<AppState>) {
    let deadline = tokio::time::Instant::now() + fixture::BOUND;
    loop {
        let available = state.subscriptions.available();
        if available == SUBSCRIPTION_CAPACITY {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "a dropped subscription stream still holds a permit after {:?}: \
             {available} of {SUBSCRIPTION_CAPACITY} available",
            fixture::BOUND
        );
        tokio::task::yield_now().await;
    }
}

/// The task is HELD at the backend for the whole row, so every assertion is
/// made about a task that is provably still running: a gateway that quietly
/// settled or discarded the task on the disconnect would answer a terminal
/// status here rather than a running one.
#[tokio::test]
async fn lifecycle_2_a_task_survives_a_dropped_stream_and_stays_private() {
    let (fixture, gate) = state_holding().await;
    let (_, created) = post_against(
        Arc::clone(&fixture.state),
        "key-a",
        task_invoke(60, "mik-7311-lifecycle-2-disconnect"),
    )
    .await;
    let task_id = task_id_of(&created);
    fixture.backend.wait_for_calls(1).await;

    // THE CONNECTION THAT IS LOST. An admitted listen answers
    // `text/event-stream`, which the post helper reports as a null body
    // rather than draining a stream that never ends — so a null body here
    // IS the admission, and the permit it took is the observable.
    let admitted = post_answer_against(
        Arc::clone(&fixture.state),
        "key-a",
        modern(
            62,
            "subscriptions/listen",
            json!({ "taskIds": [task_id.clone()] }),
            true,
        ),
    )
    .await;
    assert!(
        admitted.is_open_stream(),
        "the owner's listen must be admitted AS A STREAM, or the disconnect \
         below is a disconnect of nothing. Read off the content type, not off \
         an absent body: a 200 that carried nothing parses to the same null: \
         {admitted:?}"
    );

    // DISCONNECT. The helper dropped the response body when it returned,
    // which drops the listener and returns its permit. Waiting for that
    // makes "the stream went away" an observed fact: without it a gateway
    // that never tore the subscription down would pass everything below.
    await_no_open_subscriptions(&fixture.state).await;

    // Every request from here is a fresh, independently authenticated POST,
    // which is what reconnect means on this transport.
    let (_, after) = post_against(
        Arc::clone(&fixture.state),
        "key-a",
        modern(64, "tasks/get", json!({ "taskId": task_id.clone() }), true),
    )
    .await;
    assert_eq!(
        after.pointer("/result/taskId").and_then(Value::as_str),
        Some(task_id.as_str()),
        "the creating principal must still resolve the task after the stream \
         was lost: {after}"
    );
    assert_eq!(
        after.pointer("/result/status").and_then(Value::as_str),
        Some("working"),
        "the backend is still holding the dispatch, so the task is running — a \
         terminal status here means the disconnect settled it: {after}"
    );

    refused_identically(&fixture.state, "key-b", 65, "tasks/get", &task_id).await;
    refused_identically(&fixture.state, "key-b", 67, "tasks/cancel", &task_id).await;

    // NOT asserted here: a foreign `subscriptions/listen`. The route
    // narrows a foreign `taskIds` to the empty list IN SILENCE rather than
    // refusing (`src/gateway/router/handlers.rs:1050-1062`), so both the
    // foreign and the fabricated answer are streams with no readable body
    // over this helper — a comparison of the two cannot fail, whatever the
    // gateway does. `ac_task_1_12_subscription_admission_hides_another_
    // principals_task` already carries that pair, with the same ceiling
    // recorded on it. The discriminating oracles for THIS row are the two
    // refusals above.

    // A foreign cancel that mutated the task WHILE answering not-found
    // would satisfy every assertion above. The whole answer is compared,
    // not one field: anything the probes changed shows up here.
    let (_, unchanged) = post_against(
        Arc::clone(&fixture.state),
        "key-a",
        modern(71, "tasks/get", json!({ "taskId": task_id.clone() }), true),
    )
    .await;
    assert_eq!(
        shape(unchanged),
        shape(after),
        "the foreign probes must leave the owner's view of the task exactly as \
         it was"
    );

    // Control, after the foreign probes so those ran against a live task.
    let (_, cancelled) = post_against(
        Arc::clone(&fixture.state),
        "key-a",
        modern(
            72,
            "tasks/cancel",
            json!({ "taskId": task_id.clone() }),
            true,
        ),
    )
    .await;
    assert!(
        cancelled.get("error").is_none(),
        "the creating principal still controls the task after the stream was \
         lost: {cancelled}"
    );
    let (_, observed) = post_against(
        Arc::clone(&fixture.state),
        "key-a",
        modern(73, "tasks/get", json!({ "taskId": task_id }), true),
    )
    .await;
    assert_eq!(
        observed.pointer("/result/status").and_then(Value::as_str),
        Some("cancelled"),
        "an accepted cancel that changed nothing would pass the assertion \
         above: {observed}"
    );

    assert_eq!(
        fixture.backend.calls(),
        1,
        "one create, one dispatch: no read, refusal or cancel re-runs the tool"
    );
    gate.release_all();
}

/// THE OTHER HALF OF "SURVIVES". The row above proves the RECORD outlives
/// the connection; it cannot prove the WORK does, because the backend is
/// held for its whole life and the task is then cancelled. Here the held
/// dispatch is released AFTER the stream is gone, and the task runs to a
/// completed result — a gateway that abandoned the worker with the client
/// would leave the record `working` for ever and fail on the bound.
#[tokio::test]
async fn lifecycle_2_a_task_whose_client_vanished_still_runs_to_completion() {
    let (fixture, gate) = state_holding().await;
    let (_, created) = post_against(
        Arc::clone(&fixture.state),
        "key-a",
        task_invoke(100, "mik-7311-lifecycle-2-completes"),
    )
    .await;
    let task_id = task_id_of(&created);
    fixture.backend.wait_for_calls(1).await;

    let admitted = post_answer_against(
        Arc::clone(&fixture.state),
        "key-a",
        modern(
            102,
            "subscriptions/listen",
            json!({ "taskIds": [task_id.clone()] }),
            true,
        ),
    )
    .await;
    assert!(
        admitted.is_open_stream(),
        "the owner's listen must be admitted as a stream: {admitted:?}"
    );
    await_no_open_subscriptions(&fixture.state).await;

    // The work was held until after the connection was lost, so what
    // finishes it can only be the gateway's own executor.
    gate.release_all();

    let settled = poll_until_terminal(&fixture.state, "key-a", 103, &task_id).await;
    assert_eq!(
        settled.pointer("/result/status").and_then(Value::as_str),
        Some("completed"),
        "a task whose client vanished must still reach a terminal completed \
         status: {settled}"
    );
    assert_eq!(
        settled
            .pointer("/result/result/structuredContent/marker")
            .and_then(Value::as_str),
        Some("mik-7272-backend-answered"),
        "the stored result must be the BACKEND's answer — a terminal status \
         carrying no result is a task that was closed, not one that ran: \
         {settled}"
    );
    assert_eq!(
        fixture.backend.calls(),
        1,
        "the release finishes the dispatch already in flight; it does not \
         start a second one"
    );
}

/// A whole gateway is lost and a second one opens over the same store.
///
/// Strictly stronger than the criterion's client disconnect, and kept
/// alongside it rather than in place of it: this row cannot observe
/// per-connection cleanup, and the row above cannot observe durability.
/// The backend answers immediately here, so the task is terminal before the
/// restart and startup recovery
/// (`src/gateway/task_service/execution/recovery.rs:36-80`) has nothing to
/// re-settle — what is asserted is that the RESULT was retained.
#[tokio::test]
async fn lifecycle_2_a_task_survives_a_gateway_restart_and_stays_private() {
    let store_dir = tempfile::tempdir().expect("a task store the test owns");

    // Scoped so the first gateway — its custody lease, its executor and its
    // loopback listener — is gone before the second one opens.
    let (task_id, before) = {
        let fixture = state_over(store_dir.path()).await;
        let (_, created) = post_against(
            Arc::clone(&fixture.state),
            "key-a",
            task_invoke(80, "mik-7311-lifecycle-2-restart"),
        )
        .await;
        let task_id = task_id_of(&created);
        fixture.backend.wait_for_calls(1).await;
        let before = poll_until_terminal(&fixture.state, "key-a", 81, &task_id).await;
        assert_eq!(
            before.pointer("/result/status").and_then(Value::as_str),
            Some("completed"),
            "the task must settle before the restart, or this row is about \
             recovery rather than about retention: {before}"
        );
        (task_id, before)
    };

    let restarted = state_over(store_dir.path()).await;

    let (_, recovered) = post_against(
        Arc::clone(&restarted.state),
        "key-a",
        modern(85, "tasks/get", json!({ "taskId": task_id.clone() }), true),
    )
    .await;
    assert_eq!(
        shape(recovered),
        shape(before),
        "the second gateway must answer the creating principal with the SAME \
         task, field for field: a partially recovered record is a task that \
         did not survive"
    );

    refused_identically(&restarted.state, "key-b", 86, "tasks/get", &task_id).await;
    refused_identically(&restarted.state, "key-b", 88, "tasks/cancel", &task_id).await;

    assert_eq!(
        restarted.backend.calls(),
        0,
        "recovery is a read of the store: a second gateway that re-dispatched \
         the tool would answer every assertion above and run the work twice"
    );
}

/// THE FALSIFIER for the row above. Same steps, but the second gateway
/// opens over an EMPTY directory — and now the task's own creator is told
/// it does not exist, in the same words as an id nobody ever minted.
///
/// Without this row, a read path that answered success for any well-formed
/// id would satisfy the restart row completely.
#[tokio::test]
async fn lifecycle_2_a_fresh_store_answers_the_same_task_as_absent() {
    let store_dir = tempfile::tempdir().expect("a task store the test owns");
    let task_id = {
        let fixture = state_over(store_dir.path()).await;
        let (_, created) = post_against(
            Arc::clone(&fixture.state),
            "key-a",
            task_invoke(90, "mik-7311-lifecycle-2-fresh-store"),
        )
        .await;
        let task_id = task_id_of(&created);
        fixture.backend.wait_for_calls(1).await;
        poll_until_terminal(&fixture.state, "key-a", 91, &task_id).await;
        task_id
    };

    let empty_dir = tempfile::tempdir().expect("a second, empty task store");
    let fresh = state_over(empty_dir.path()).await;

    refused_identically(&fresh.state, "key-a", 95, "tasks/get", &task_id).await;
    // Both verbs, as on the row this one falsifies: a control path that
    // accepted any well-formed id on cancel would be invisible to a
    // read-only negative. Proved: against the POPULATED store with the get
    // arm removed, this arm alone fails, and the accepted cancel answers a
    // bare `{"resultType":"complete"}`.
    refused_identically(&fresh.state, "key-a", 97, "tasks/cancel", &task_id).await;
}

/// THE THIRD INSPECT ROUTE. `tasks/get` and `tasks/cancel` refuse a foreign
/// caller outright; `subscriptions/listen` does not — it narrows a foreign
/// `taskIds` to the empty list IN SILENCE and still answers a stream
/// (`src/gateway/router/handlers.rs:1050-1062`). Two streams that look
/// alike prove nothing about what travels down them, so this row reads the
/// frames.
///
/// The owner's stream is the PERMISSIVE CONTROL and is drained FIRST: it
/// must carry a frame naming the task before the foreign stream is judged.
/// Without it, an empty foreign stream would be satisfied by a gateway that
/// emits no task events at all.
#[tokio::test]
async fn lifecycle_2_a_foreign_listener_receives_no_event_for_the_task() {
    let (fixture, gate) = state_holding().await;
    let (_, created) = post_against(
        Arc::clone(&fixture.state),
        "key-a",
        task_invoke(110, "mik-7311-lifecycle-2-foreign-stream"),
    )
    .await;
    let task_id = task_id_of(&created);
    fixture.backend.wait_for_calls(1).await;

    // Both listeners are opened BEFORE the task settles, so neither can
    // miss the event by arriving late.
    let mut foreign = listen_stream(&fixture.state, "key-b", 112, &task_id).await;
    let mut owner = listen_stream(&fixture.state, "key-a", 113, &task_id).await;

    gate.release_all();

    let carried = drain_for(&mut owner, &task_id, Expect::TerminalStatus).await;
    assert!(
        carried.is_some(),
        "the owner's own stream must carry a terminal status event for the \
         task, or the foreign stream below is empty because nothing was ever \
         emitted"
    );

    // Deliberately the WIDER predicate on this side. The control needs a
    // specific event to prove one was emitted at all; the negative must
    // reject EVERY task notification naming the task, or a gateway that
    // leaked a `working` frame and withheld the `completed` one would pass.
    let leaked = drain_for(&mut foreign, &task_id, Expect::AnyTaskEvent).await;
    assert!(
        leaked.is_none(),
        "a principal who does not own the task must receive no event naming \
         it: {leaked:?}"
    );
}

/// Open a listen stream AS `principal` and hand back its body.
///
/// `post_against` drops the body when it returns, which is right for every
/// row that only needs the admission. A row that reads what travels down
/// the stream has to hold it.
async fn listen_stream(
    state: &Arc<AppState>,
    principal: &str,
    request_id: i64,
    task_id: &str,
) -> axum::body::BodyDataStream {
    let response = send(
        Arc::clone(state),
        Some(principal),
        modern(
            request_id,
            "subscriptions/listen",
            json!({ "taskIds": [task_id] }),
            true,
        ),
    )
    .await;
    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "'{principal}' must be admitted — the narrowing this row is about \
         happens INSIDE an admitted stream, so a refusal here would test \
         something else"
    );
    assert_eq!(
        response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream"),
        "an admitted listen is a stream; anything else has no frames to read"
    );
    response.into_body().into_data_stream()
}

/// What a drained frame has to be to count.
#[derive(Clone, Copy)]
enum Expect {
    /// The settled status the release produces. Used for the CONTROL: it
    /// has to prove an event was emitted, so it names the one event the
    /// release is known to cause.
    TerminalStatus,
    /// Any task notification naming the task. Used for the NEGATIVE, which
    /// must not be satisfied by a gateway that leaks a different frame.
    AnyTaskEvent,
}

/// Read frames until one matches, or until the drain's deadline passes.
///
/// ONE deadline for the whole drain, not one per chunk: the stream stays
/// open and sends a keepalive every 15s, so a per-chunk timeout that
/// restarts on every frame would never conclude "nothing arrived" once
/// anything else shares the stream. The same bound serves the control and
/// the negative, so the two observations are comparable.
///
/// Frames are appended to a rolling buffer rather than matched one chunk at
/// a time. In this in-process path `axum::response::Sse` writes a whole
/// event per frame, so a split is not expected — but a matcher that can
/// only see inside one chunk would answer "no leak" if framing ever
/// changed, which is the wrong way for this row to fail.
async fn drain_for(
    stream: &mut axum::body::BodyDataStream,
    task_id: &str,
    expect: Expect,
) -> Option<String> {
    use futures::StreamExt;

    let drained = tokio::time::timeout(fixture::BOUND, async {
        let mut seen = String::new();
        while let Some(chunk) = stream.next().await {
            seen.push_str(&String::from_utf8(chunk.ok()?.to_vec()).ok()?);
            // Matched per COMPLETE SSE record, never across the whole
            // buffer: `\n\n` ends a record, so a buffer-wide conjunction
            // would let the task id come from one frame and the method
            // from another and call that a match.
            if let Some(record) = seen.split("\n\n").find(|record| {
                record.contains(task_id)
                    && match expect {
                        Expect::TerminalStatus => record.contains("completed"),
                        Expect::AnyTaskEvent => record.contains("notifications/tasks"),
                    }
            }) {
                return Some(record.to_string());
            }
        }
        None
    })
    .await;
    drained.ok().flatten()
}
