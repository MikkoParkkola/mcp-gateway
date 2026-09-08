// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! I2 — `notifications/tasks` on a real `subscriptions/listen` stream, and who
//! is allowed to see one.
//!
//! Approved design r3 §6: `ListenRequest` reads `taskIds` from the params
//! **root** (where `handlers.rs:1034-1046` writes it), `delivers()` matches
//! `params.taskId` against that list, and the executor emits at the single
//! `published` tail after a successful durable write. No new authentication
//! surface, envelope or per-send policy is asked for: the ownership narrowing
//! that already exists becomes load-bearing for delivery.
//!
//! # What is red today, and why
//!
//! `NotificationKind::from_method` returns `None` for `notifications/tasks`
//! (`subscriptions.rs:49`) and `ListenRequest::from_params` reads only
//! `params.notifications` (`:101`), so every filter below parses as EMPTY and
//! `delivers()` answers `false` for everything — and nothing is published at
//! the tail. The rows fail on behaviour: a stream that was admitted,
//! acknowledged and left open carries nothing after a durable transition that
//! provably happened. Nothing here names `NotificationKind::Tasks` or
//! `ListenRequest::task_ids`, so no row is red merely for absence.
//!
//! # Why the negatives are not silence
//!
//! Every absence row observes a channel that carried something first: the
//! foreign-task and narrowed-filter streams are opened BEFORE the release, so
//! what they must not receive is published into the generation they are on, and
//! each one's own acknowledgement proves it live. `subscription_stream`
//! (`streaming.rs:448-474`) loops on `recv` and `continue`s past what a filter
//! drops, closing only on `Closed`/`Lagged` — so `StreamEvent::Closed` is a
//! distinct, loudly failing answer rather than a quiet pass. One registry
//! serves both the route and the executor (`tests.rs:518-520,555`), or every
//! routed row would fail for a fixture reason wearing the shape of the RED.
//!
//! # Kinds this route cannot observe (reported, not worked around)
//!
//! * **`Create`.** The filter is fixed when the stream opens and an id the
//!   caller does not yet own narrows to `[]`, so the id must exist before any
//!   admissible subscription — which puts the `Created` emission strictly
//!   earlier. Not chased into `task_service` privacy from here.
//! * **`Recover`.** Reached only by reopening a store after an interrupted run.
//!
//! Route-observable and covered below: **settle** and **cancel**, plus a
//! rejected/no-op write publishing nothing.
use super::super::*;
use super::support::*;

use crate::gateway::subscription_registry::delivers;
use crate::protocol::subscriptions::{ListenRequest, NotificationKind};

// The reader, the stream opener and the two shaped assertions. A child of this
// module rather than a sibling, so the parent promotes ONE declaration.
#[path = "notifications_helpers.rs"]
mod helpers;

use helpers::{
    ReleasedOnDrop, SUBSCRIPTION_ID_META, TASK_NOTIFICATION, assert_only_its_own_task,
    assert_receives_nothing, expect_message, open_listen, task_notification,
};

// =====================================================================
// The route, two principals, one broadcast generation
// =====================================================================

/// Each principal receives its OWN task's notification and never the other's.
///
/// Mechanism: the per-listener filter in `subscription_stream`. One
/// process-wide broadcast reaches both streams and each stream's own `taskIds`
/// decides, so with both open before either task settles, A's notification
/// really does pass through B's receiver and really is dropped there.
///
/// The durable transition is asserted BEFORE the stream is read — both tasks
/// poll to `completed` carrying the backend's result, and the counted mock saw
/// exactly two dispatches — so a failure reads "the transition happened and
/// nothing was published", never "nothing was dispatched".
#[tokio::test]
async fn a_task_notification_reaches_its_owner_and_never_the_other_principal() {
    let (mock, gate) = MockBackend::holding(Answer::ok());
    let mut gate = ReleasedOnDrop(gate);
    let (state, _store) = state_with(&mock).await;

    let created_a = post(
        &state,
        "key-a",
        task_invoke(7101, "n1-a", json!({ "q": "a" })),
    )
    .await;
    let id_a = task_id(&created_a);
    let created_b = post(
        &state,
        "key-b",
        task_invoke(7102, "n1-b", json!({ "q": "b" })),
    )
    .await;
    let id_b = task_id(&created_b);

    // Both dispatches are at the backend and held, so both records exist and
    // neither has settled yet — which is what lets the filters name them.
    gate.0.wait_for_dispatch().await;
    gate.0.wait_for_dispatch().await;

    let mut stream_a = open_listen(&state, "key-a", 7001, json!({ "taskIds": [&id_a] })).await;
    let mut stream_b = open_listen(&state, "key-b", 7002, json!({ "taskIds": [&id_b] })).await;

    gate.0.release_all();
    let settled_a = poll_until_terminal(&state, "key-a", &id_a).await;
    let settled_b = poll_until_terminal(&state, "key-b", &id_b).await;
    assert_carries_the_backend_result(&settled_a);
    assert_carries_the_backend_result(&settled_b);
    std::assert_eq!(
        mock.calls(),
        2,
        "each principal's task must reach the backend once, or the transitions \
         the notifications are about did not happen; the backend saw {:?}",
        mock.seen()
    );

    assert_only_its_own_task(&mut stream_a, &id_a, 7001, "principal-a").await;
    assert_only_its_own_task(&mut stream_b, &id_b, 7002, "principal-b").await;
}

/// A filter mixing an owned and a foreign task receives NEITHER, and a filter
/// that asked for no task at all stays quiet.
///
/// A different mechanism from the row above: the handler's ALL-OR-EMPTY
/// narrowing (`handlers.rs:1036-1045`) rewrites the whole `taskIds` array to
/// `[]` when any entry is unowned, so principal A loses its own task too —
/// the existing rule rather than a new one.
///
/// The control stream is the same principal, generation and task, differing
/// only in naming nothing foreign. Without it both silences below would be the
/// silence of a system that publishes nothing.
#[tokio::test]
async fn a_mixed_owner_filter_and_an_unrequested_filter_receive_nothing() {
    let (mock, gate) = MockBackend::holding(Answer::ok());
    let mut gate = ReleasedOnDrop(gate);
    let (state, _store) = state_with(&mock).await;

    let created_a = post(
        &state,
        "key-a",
        task_invoke(7201, "n2-a", json!({ "q": "a" })),
    )
    .await;
    let id_a = task_id(&created_a);
    let created_b = post(
        &state,
        "key-b",
        task_invoke(7202, "n2-b", json!({ "q": "b" })),
    )
    .await;
    let id_b = task_id(&created_b);
    gate.0.wait_for_dispatch().await;
    gate.0.wait_for_dispatch().await;

    let mut control = open_listen(&state, "key-a", 7011, json!({ "taskIds": [&id_a] })).await;
    let mut mixed = open_listen(&state, "key-a", 7012, json!({ "taskIds": [&id_a, &id_b] })).await;
    let mut quiet = open_listen(&state, "key-a", 7013, json!({ "notifications": {} })).await;

    gate.0.release_all();
    assert_carries_the_backend_result(&poll_until_terminal(&state, "key-a", &id_a).await);
    assert_carries_the_backend_result(&poll_until_terminal(&state, "key-b", &id_b).await);

    // Positive first: the generation these two silences belong to demonstrably
    // carried a notification.
    assert_only_its_own_task(&mut control, &id_a, 7011, "principal-a's control stream").await;
    assert_receives_nothing(
        &mut mixed,
        "a filter naming one owned and one foreign task is narrowed to the empty \
         list, so it receives neither — its own included",
    )
    .await;
    assert_receives_nothing(
        &mut quiet,
        "a listener that asked for no task receives no task notification",
    )
    .await;
}

/// A cancel publishes at the same tail a settle does — and a repeat, which
/// writes nothing, publishes nothing.
///
/// Design §6 is ONE call site for every durable write kind, so the claim is
/// "cancel reaches the same seam", not "cancel also emits somewhere"; the
/// no-op half is the rest of that claim. `tasks/get` still reporting
/// `cancelled` after the repeat is what makes the silence a no-op rather than a
/// failed cancel. The repeat's JSON-RPC code is deliberately not pinned — that
/// is the store's answer to a terminal record and this row does not own it.
#[tokio::test]
async fn a_cancel_publishes_once_and_a_repeat_publishes_nothing() {
    let (mock, gate) = MockBackend::holding(Answer::ok());
    let mut gate = ReleasedOnDrop(gate);
    let (state, _store) = state_with(&mock).await;

    let created = post(
        &state,
        "key-a",
        task_invoke(7301, "n3-a", json!({ "q": "c" })),
    )
    .await;
    let id = task_id(&created);
    // Held at the backend, so the task is genuinely running when it is
    // cancelled: cooperative cancel is licensed, and the durable transition is
    // what publishes.
    gate.0.wait_for_dispatch().await;

    let mut stream = open_listen(&state, "key-a", 7031, json!({ "taskIds": [&id] })).await;

    let cancelled = post(
        &state,
        "key-a",
        task_method(7302, "tasks/cancel", json!({ "taskId": &id })),
    )
    .await;
    std::assert_eq!(
        cancelled.pointer("/result/resultType"),
        Some(&json!("complete")),
        "the cancel must commit before its notification can be expected: {cancelled}"
    );

    let event = expect_message(&mut stream, "the cancelled task's notification").await;
    std::assert_eq!(event["method"], json!(TASK_NOTIFICATION), "{event}");
    std::assert_eq!(event["params"]["taskId"], json!(&id), "{event}");
    std::assert_eq!(
        event["params"]["_meta"][SUBSCRIPTION_ID_META],
        json!(7031),
        "{event}"
    );

    let _repeat = post(
        &state,
        "key-a",
        task_method(7303, "tasks/cancel", json!({ "taskId": &id })),
    )
    .await;
    let after = get_task(&state, "key-a", &id).await;
    std::assert_eq!(
        status_of(&after),
        "cancelled",
        "the repeat must leave the record where the first cancel put it: {after}"
    );
    assert_receives_nothing(
        &mut stream,
        "a repeated cancel writes no new durable transition, so the publication \
         tail must not fire for it",
    )
    .await;
}

// =====================================================================
// Parser and registration controls
//
// PURE controls over the current parser, filter and method list. They pin
// placement, matching and exclusion cheaply; none is runtime proof of delivery,
// and none may stand in for the routed rows above. The task ids here are
// hand-built strings for that reason — they name nothing durable.
// =====================================================================

/// Control — the task method is subscribable, and the request-scoped pair
/// stays out. Asserted through `from_method`'s Some/None rather than by naming
/// a variant that does not exist, so it is red for behaviour, not absence.
#[test]
fn control_the_task_method_is_subscribable_and_request_scoped_ones_are_not() {
    std::assert!(
        NotificationKind::from_method(TASK_NOTIFICATION).is_some(),
        "`{TASK_NOTIFICATION}` must be a subscribable kind, or no filter can \
         ever opt into it"
    );
    for method in ["notifications/progress", "notifications/message"] {
        std::assert!(
            NotificationKind::from_method(method).is_none(),
            "{method} belongs to the request that caused it and must never \
             become subscribable"
        );
    }
}

/// Control — the filter is read from the params ROOT and matches by task id.
///
/// Root placement is not a detail: `handlers.rs:1042` writes the narrowed array
/// to `params.taskIds`, so a parser reading it under `notifications` would
/// silently never see the narrowing at all.
#[test]
fn control_the_task_filter_is_read_from_the_params_root_and_matches_by_task_id() {
    let named = ListenRequest::from_params(Some(&json!({
        "taskIds": ["task-control-1"],
        "notifications": {}
    })))
    .expect("a listen request carrying a notifications object parses");
    std::assert!(
        delivers(&named, &task_notification("task-control-1")),
        "a filter naming a task must receive that task's notification"
    );
    std::assert!(
        !delivers(&named, &task_notification("task-control-2")),
        "a task the client never named is a task it did not ask for"
    );
    for method in ["notifications/progress", "notifications/message"] {
        std::assert!(
            !delivers(
                &named,
                &json!({ "jsonrpc": "2.0", "method": method,
                         "params": { "taskId": "task-control-1" } })
            ),
            "{method} must not ride this stream even for a task the client owns"
        );
    }

    let nested = ListenRequest::from_params(Some(&json!({
        "notifications": { "taskIds": ["task-control-1"] }
    })))
    .expect("an unrecognised key must not sink the request");
    std::assert!(
        !delivers(&nested, &task_notification("task-control-1")),
        "the handler writes `taskIds` at the params root; a filter found \
         anywhere else was never the one the ownership narrowing rewrote"
    );

    let narrowed = ListenRequest::from_params(Some(&json!({
        "taskIds": [],
        "notifications": {}
    })))
    .expect("an empty filter is a valid request");
    std::assert!(
        !delivers(&narrowed, &task_notification("task-control-1")),
        "the empty list a non-owner is narrowed to must opt into nothing — that \
         is what closes the ownership rule at the broadcast door"
    );
}

/// Control — the method is registered for this revision (design §6 delta on
/// `protocol/meta.rs:279`). Membership only: a length assertion would break on
/// the next unrelated method.
#[test]
fn control_the_task_notification_method_is_registered_for_2026_07_28() {
    std::assert!(
        crate::protocol::meta::ADDED_IN_2026_07_28.contains(&TASK_NOTIFICATION),
        "`{TASK_NOTIFICATION}` is added by 2026-07-28 and must be registered as \
         such: {:?}",
        crate::protocol::meta::ADDED_IN_2026_07_28
    );
}
