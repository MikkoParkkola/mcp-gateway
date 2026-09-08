// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;

// =====================================================================
// A — a nonce the gateway refuses stops the request before it can commit
// =====================================================================

/// A — a malformed nonce on a task-augmented call refuses before the task
/// record and before the backend.
///
/// Malformed in each of the four spellings `capture` classes as invalid
/// (`signing.rs:57`): a non-string, an empty string, `null`, and one byte past
/// the 256-byte ceiling. The refusal is the boundary's own
/// (`signing.rs:185` -> `-32602 "Invalid signing nonce"`), and it is decided at
/// `handlers.rs:1506` — above `handle_tools_call`, so the task intent built at
/// `handlers.rs:1448` is a struct that is dropped rather than a record that is
/// written.
///
/// The oracles are the count and the directory, not the error shape: an
/// implementation that answered `-32602` *after* committing would satisfy a
/// shape assertion and fail this row.
#[tokio::test]
async fn joint_a_a_malformed_nonce_refuses_before_the_task_record_and_the_backend() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, store) = signed_state(&mock).await;
    let _primed =
        prime_one_settled_task(&state, 300, "joint-a1-prime", "joint-a1-nonce-prime").await;
    let baseline = assert_primed(&mock, &store);

    for (id, nonce) in [
        (310, json!(17)),
        (311, json!("")),
        (312, json!(null)),
        (313, json!("x".repeat(257))),
    ] {
        let key = format!("joint-a1-unused-{id}");
        let refused = bounded(
            "a malformed-nonce task create",
            post(
                &state,
                "key-a",
                with_nonce(task_invoke(id, &key, json!({ "q": "malformed" })), nonce),
            ),
        )
        .await;

        std::assert_eq!(
            error_code(&refused),
            -32602,
            "a malformed nonce is refused by the signing boundary, with its own \
             source-correlated code: {refused}"
        );
        std::assert_eq!(
            refused.pointer("/error/message"),
            Some(&json!("Invalid signing nonce")),
            "and with the boundary's own wording, not a rewritten one: {refused}"
        );
        assert!(
            refused.pointer("/result/taskId").is_none(),
            "a refusal is not a handle: {refused}"
        );
    }

    std::assert_eq!(
        mock.calls(),
        1,
        "only the priming task ever reached the backend; the backend saw {:?}",
        mock.seen()
    );
    std::assert_eq!(
        durable_records(&store),
        baseline,
        "and no refused call left a durable record behind its refusal — the \
         store holds exactly what the priming task put there"
    );
}

/// A — with `require_nonce`, a task-augmented call carrying NO nonce refuses on
/// the same boundary.
///
/// The enforcement branch is `signing.rs:200`: `-32001`, "Nonce required when
/// message signing is enforced". Separate from the malformed row because it is a
/// different decision with a different code, and a row that lumped them could
/// pass on either.
#[tokio::test]
async fn joint_a_a_missing_required_nonce_refuses_before_the_task_record_and_the_backend() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, store) = signed_state(&mock).await;
    let _primed =
        prime_one_settled_task(&state, 320, "joint-a2-prime", "joint-a2-nonce-prime").await;
    let baseline = assert_primed(&mock, &store);

    let refused = bounded(
        "a nonce-less task create",
        post(
            &state,
            "key-a",
            task_invoke(321, "joint-a2-unused", json!({ "q": "missing" })),
        ),
    )
    .await;

    std::assert_eq!(
        error_code(&refused),
        -32001,
        "an enforced gateway refuses a nonce-less external invoke: {refused}"
    );
    std::assert_eq!(
        refused.pointer("/error/message"),
        Some(&json!("Nonce required when message signing is enforced")),
        "with the enforcement branch's own wording: {refused}"
    );
    assert!(
        refused.pointer("/result/taskId").is_none(),
        "a refusal is not a handle: {refused}"
    );
    std::assert_eq!(
        mock.calls(),
        1,
        "the refused call dispatched nothing; the backend saw {:?}",
        mock.seen()
    );
    std::assert_eq!(
        durable_records(&store),
        baseline,
        "and wrote no record: an unsigned-able answer must not leave a task \
         behind it"
    );
}

/// A — a nonce already spent by an accepted call cannot buy a NEW task.
///
/// The replay is primed by a real successful task (its nonce is genuinely
/// registered by the same store the second call is checked against), and the
/// second call carries a *fresh, unused* idempotency key — so it is a request to
/// create something new, refused on the nonce alone. Reusing the primed key
/// would have been answered by task deduplication, and the row would have proved
/// nothing about replay.
#[tokio::test]
async fn joint_a_a_replayed_nonce_with_a_fresh_task_key_creates_nothing() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, store) = signed_state(&mock).await;
    let spent = "joint-a3-nonce-spent";
    let primed = prime_one_settled_task(&state, 330, "joint-a3-prime", spent).await;
    let baseline = assert_primed(&mock, &store);

    let refused = bounded(
        "a replayed-nonce task create",
        post(
            &state,
            "key-a",
            with_nonce(
                task_invoke(331, "joint-a3-fresh-key", json!({ "q": "replayed" })),
                json!(spent),
            ),
        ),
    )
    .await;

    std::assert_eq!(
        error_code(&refused),
        -32001,
        "a spent nonce is refused by the nonce store's own decision \
         (`message_signing.rs:292`): {refused}"
    );
    std::assert_eq!(
        refused.pointer("/error/message"),
        Some(&json!("Nonce replay detected")),
        "and the refusal names replay, so an operator can tell it from the \
         enforcement branch that shares its code: {refused}"
    );
    assert!(
        refused.pointer("/result/taskId").is_none(),
        "a replay is not a handle: {refused}"
    );
    std::assert_eq!(
        mock.calls(),
        1,
        "the replay dispatched nothing; the backend saw {:?}",
        mock.seen()
    );
    std::assert_eq!(
        durable_records(&store),
        baseline,
        "and created no second record — the fresh key it carried admitted \
         nothing, because the nonce was decided first"
    );
    let survivor = bounded(
        "re-reading the primed task",
        get_task(&state, "key-a", &primed),
    )
    .await;
    assert_carries_the_backend_result(&survivor);
}

// =====================================================================
// B — an accepted nonce buys exactly one execution, signed
// =====================================================================

/// B — a valid, freshly-nonced task call is dispatched exactly once, settles
/// with the backend's own result, and its handle is delivered signed.
///
/// The barrier is real: [`GateHandle::wait_for_dispatch`] returns only once the
/// injected transport has actually been entered, so "dispatched" is an
/// observation rather than an inference from the handle. The gate is released
/// before any assertion runs, so a failing assertion cannot leave the held
/// dispatch — and therefore the worker — parked.
///
/// That the task reaches `completed` is also the no-second-consumption evidence
/// for the nonce: the worker's rebuilt context carries `signing: None`
/// (`task_service/execution/context.rs:114`), so if it re-registered the create's
/// nonce the dispatch would be refused as a replay and the task would settle
/// `failed` instead.
#[tokio::test]
async fn joint_b_a_signed_task_dispatches_once_and_settles_with_the_backend_result() {
    struct ReleaseOnDrop(GateHandle);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            self.0.release_all();
        }
    }
    let (mock, gate) = MockBackend::holding(Answer::ok());
    let mut gate = ReleaseOnDrop(gate);
    let (state, store) = signed_state(&mock).await;
    let nonce = "joint-b1-nonce-fresh";

    let created = bounded(
        "the signed task create",
        post(
            &state,
            "key-a",
            with_nonce(
                task_invoke(340, "joint-b1-key", json!({ "q": "signed" })),
                json!(nonce),
            ),
        ),
    )
    .await;

    let dispatched = tokio::time::timeout(BOUND, gate.0.wait_for_dispatch()).await;
    // Release even when dispatch did not arrive, before any response or
    // timeout assertion can panic and strand the held worker.
    gate.0.release_all();
    dispatched.expect("the first dispatch must reach the backend within the bound");
    let id = task_id(&created);
    assert!(
        !id.is_empty(),
        "the handle is the route's own task id, never one this test invented: {created}"
    );
    let _ = assert_signed_for_nonce(&created, nonce);
    let settled = bounded(
        "the signed task settling",
        poll_until_terminal(&state, "key-a", &id),
    )
    .await;

    assert_carries_the_backend_result(&settled);
    std::assert_eq!(
        mock.calls(),
        1,
        "one accepted nonce buys exactly one dispatch; the backend saw {:?}",
        mock.seen()
    );
    let seen = mock.seen();
    let dispatched = serde_json::to_string(&seen).unwrap_or_default();
    assert!(
        !dispatched.contains("nonce") && !dispatched.contains("_signature"),
        "the gateway's own signing controls are not the backend's business, and \
         must never be forwarded as tool arguments: {seen:?}"
    );
    std::assert_eq!(
        durable_records(&store).len(),
        1,
        "one accepted task, one durable record"
    );
}

/// B — the same owner, key and body with a NEW nonce is answered with the SAME
/// handle, dispatches nothing further, and is signed afresh.
///
/// The create's own nonce is spent by then — replaying it would be row A3 — so
/// the honest repeat carries a second one. Two facts have to hold together:
/// deduplication is decided on the request (the nonce is lifted out before
/// anything digests the arguments, `signing.rs:53`), and delivery is decided per
/// response.
///
/// The second MAC is compared against the first only as evidence that the block
/// was produced for this delivery rather than copied from the retained one: the
/// v2 MAC covers body, request id, nonce and timestamp together
/// (`message_signing_v2.rs:79`).
#[tokio::test]
async fn joint_b_a_new_nonce_on_the_same_key_returns_the_same_handle_signed_afresh() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, store) = signed_state(&mock).await;
    let body = json!({ "q": "repeated" });
    let call = |id: i64, nonce: &str| {
        with_nonce(task_invoke(id, "joint-b2-key", body.clone()), json!(nonce))
    };

    let created = bounded(
        "the first signed task create",
        post(&state, "key-a", call(350, "joint-b2-nonce-first")),
    )
    .await;
    let id = task_id(&created);
    let first_mac = assert_signed_for_nonce(&created, "joint-b2-nonce-first");
    let settled = bounded(
        "the first task settling",
        poll_until_terminal(&state, "key-a", &id),
    )
    .await;
    assert_carries_the_backend_result(&settled);

    let repeat = bounded(
        "the repeat with a fresh nonce",
        post(&state, "key-a", call(351, "joint-b2-nonce-second")),
    )
    .await;

    std::assert_eq!(
        task_id(&repeat),
        id,
        "a fresh nonce is a fresh delivery, not a fresh execution: the repeat \
         must be answered with the ORIGINAL handle: {repeat}"
    );
    std::assert_eq!(
        mock.calls(),
        1,
        "and must dispatch nothing a second time; the backend saw {:?}",
        mock.seen()
    );
    let second_mac = assert_signed_for_nonce(&repeat, "joint-b2-nonce-second");
    assert_ne!(
        second_mac, first_mac,
        "the repeat's signature is produced for the repeat: an identical MAC \
         would mean a retained block was replayed to the client: {repeat}"
    );
    std::assert_eq!(
        durable_records(&store).len(),
        1,
        "two accepted calls, one execution, one record"
    );
}

// =====================================================================
// C — one principal and one key, one admission authority
// =====================================================================

/// C — the same verified principal and the same explicit key must not be
/// admitted as a task AND as a synchronous execution.
///
/// Expected RED, and by design rather than by fixture. Two `ExecutionAdmission`
/// instances exist — `MetaMcp::build` (`meta_mcp/mod.rs:464`) and `open_runtime`
/// (`task_service/mod.rs:70`) — and no constructor or setter joins them, so the
/// key reserved durably under `Mode::Task` is invisible to the synchronous
/// admission that `handlers.rs:1535` consults. Under one authority this second
/// call cannot be admitted: the mode field alone refuses it
/// (`idempotency/admission.rs:236`), and that `Refusal::Mismatch` is answered
/// `409` at `meta_mcp/admission.rs:192`.
///
/// The oracle is the counter as much as the code. A refusal that had already
/// dispatched would have done the thing it declined.
#[tokio::test]
async fn joint_c_one_key_must_not_admit_both_a_task_and_a_sync_execution() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, store) = signed_state(&mock).await;
    let shared_key = "joint-c-shared-key";
    let body = json!({ "q": "one-authority" });

    let created = bounded(
        "the task create",
        post(
            &state,
            "key-a",
            with_nonce(
                task_invoke(360, shared_key, body.clone()),
                json!("joint-c-nonce-task"),
            ),
        ),
    )
    .await;
    let id = task_id(&created);
    let settled = bounded(
        "the task settling",
        poll_until_terminal(&state, "key-a", &id),
    )
    .await;
    assert_carries_the_backend_result(&settled);
    let baseline = assert_primed(&mock, &store);

    let crossed = bounded(
        "the synchronous call on the task's key",
        post(
            &state,
            "key-a",
            with_nonce(
                keyed(sync_invoke(361, body), shared_key),
                json!("joint-c-nonce-sync"),
            ),
        ),
    )
    .await;

    std::assert_eq!(
        mock.calls(),
        1,
        "the key is already owned by a durable task, so the synchronous route \
         must dispatch nothing on it; the backend saw {:?}",
        mock.seen()
    );
    std::assert_eq!(
        error_code(&crossed),
        409,
        "one principal and one key have ONE admission authority, and a second \
         mode on it is a self-mismatch rather than second protection: {crossed}"
    );
    std::assert_eq!(
        durable_records(&store),
        baseline,
        "and the refused crossing changed nothing on disk"
    );
}

/// C, control — a different, unused key on the same principal still dispatches
/// synchronously.
///
/// Its own test rather than a tail on the row above, which fails today: an
/// assertion placed after a failing one never runs and therefore proves nothing.
/// Without this control, "the crossing dispatched nothing" cannot be told from
/// "this signed fixture cannot dispatch synchronously at all".
#[tokio::test]
async fn joint_c_control_a_fresh_key_on_the_same_principal_still_dispatches() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = signed_state(&mock).await;
    let body = json!({ "q": "fresh-key-control" });

    let created = bounded(
        "the task create",
        post(
            &state,
            "key-a",
            with_nonce(
                task_invoke(370, "joint-c-control-task-key", body.clone()),
                json!("joint-c-control-nonce-task"),
            ),
        ),
    )
    .await;
    let id = task_id(&created);
    let settled = bounded(
        "the task settling",
        poll_until_terminal(&state, "key-a", &id),
    )
    .await;
    assert_carries_the_backend_result(&settled);

    let synchronous = bounded(
        "the synchronous call on a fresh key",
        post(
            &state,
            "key-a",
            with_nonce(
                keyed(sync_invoke(371, body), "joint-c-control-sync-key"),
                json!("joint-c-control-nonce-sync"),
            ),
        ),
    )
    .await;

    assert!(
        synchronous.get("error").is_none(),
        "a fresh key on the same principal is ordinary work: {synchronous}"
    );
    std::assert_eq!(
        mock.calls(),
        2,
        "the task's dispatch and the synchronous one; the backend saw {:?}",
        mock.seen()
    );
    assert!(
        serde_json::to_string(&synchronous)
            .unwrap_or_default()
            .contains("mock-backend-answered"),
        "and the backend's own result reached the caller: {synchronous}"
    );
    let _ = assert_signed_for_nonce(&synchronous, "joint-c-control-nonce-sync");
}
