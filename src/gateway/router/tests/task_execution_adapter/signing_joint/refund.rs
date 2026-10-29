// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8353 slice 3c (NONCEFX.8, R4a): a signed task submit refused after its
//! nonce was admitted, with nothing acted, gives the nonce back.
//!
//! The oracle (plan t1): send 1 under N is refused with the kind's own answer;
//! send 2, identical, under N gets the same answer, not a replay (the refund);
//! the refusal's cause is cleared; send 3 under N is served; send 4 under N is
//! "Nonce replay detected" (single use). RED on base: send 2 is a replay.
use super::*;

const REPLAY: &str = "Nonce replay detected";

fn message(body: &Value) -> String {
    body.pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// A signed task `gateway_invoke` under `key` and `nonce`.
fn signed_task(id: i64, key: &str, nonce: &str, q: &str) -> Value {
    with_nonce(task_invoke(id, key, json!({ "q": q })), json!(nonce))
}

/// Send 1 and send 2 met the kind's own refusal; send 2 was not a replay.
fn assert_refused_twice(kind: &str, first: &Value, second: &Value, code: i64, text: &str) {
    std::assert_eq!(
        error_code(first),
        code,
        "{kind}: premise, the kind's code: {first}"
    );
    assert!(
        message(first).contains(text),
        "{kind}: premise, the kind's own refusal: {first}"
    );
    assert!(
        !message(second).contains(REPLAY),
        "{kind}: the refused submit kept its nonce, so its honest re-send is a replay: {second}"
    );
    std::assert_eq!(
        error_code(second),
        code,
        "{kind}: send 2 met the same refusal: {second}"
    );
}

/// Send 3 under the nonce was served; send 4 under it is a replay.
fn assert_single_use(kind: &str, served: &Value, fourth: &Value) {
    task_id(served);
    assert!(
        message(fourth).contains(REPLAY),
        "{kind}: the nonce was given back twice: {fourth}"
    );
}

/// The signed fixture with one task worker, so a held dispatch saturates it.
async fn signed_saturated_state(
    mock: &Arc<MockBackend>,
) -> (Arc<AppState>, crate::gateway::router::tests::FixtureDir) {
    let mut config = crate::config::Config::default();
    config.tasks.max_workers = 1;
    let (mut state, store) =
        test_router_app_state_with_auth_and_config(&two_principal_auth(), config).await;
    {
        let app = Arc::get_mut(&mut state).expect("the fixture state is still exclusive");
        let meta = Arc::get_mut(&mut app.meta_mcp).expect("the meta layer is still exclusive");
        meta.enable_message_signing(
            MessageSigner::new(SIGNING_SECRET.to_vec(), None, SIGNING_KEY_ID.to_owned()),
            REPLAY_WINDOW,
            true,
        );
    }
    register(&state, BACKEND, mock);
    (state, store)
}

/// S-mismatch: the key reused for other arguments (-32602).
#[tokio::test]
async fn s3c_mismatch_refusal_gives_the_nonce_back() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, store) = signed_state(&mock).await;
    prime_one_settled_task(&state, 400, "s3c-mis", "s3c-mis-n0").await;
    let records = assert_primed(&mock, &store);

    let first = post(
        &state,
        "key-a",
        signed_task(401, "s3c-mis", "s3c-mis-n1", "other"),
    )
    .await;
    let second = post(
        &state,
        "key-a",
        signed_task(402, "s3c-mis", "s3c-mis-n1", "other"),
    )
    .await;
    assert_refused_twice(
        "S-mismatch",
        &first,
        &second,
        -32602,
        "idempotency key already used with a different request",
    );
    std::assert_eq!(mock.calls(), 1, "premise: no refusal dispatched");
    std::assert_eq!(
        durable_records(&store),
        records,
        "premise: no refusal wrote a record"
    );

    let served = post(
        &state,
        "key-a",
        signed_task(403, "s3c-mis-2", "s3c-mis-n1", "other"),
    )
    .await;
    let fourth = post(
        &state,
        "key-a",
        signed_task(404, "s3c-mis-3", "s3c-mis-n1", "other"),
    )
    .await;
    assert_single_use("S-mismatch", &served, &fourth);
}

/// S-sealed (the R4a matrix row): new keyed tasks sealed (409).
#[tokio::test]
async fn s3c_sealed_refusal_gives_the_nonce_back() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, store) = signed_state(&mock).await;
    prime_one_settled_task(&state, 410, "s3c-seal-prime", "s3c-seal-n0").await;
    let records = assert_primed(&mock, &store);
    let admission = state.task_executor.service.admission();
    admission.adjust_sealed(0, 1);

    let first = post(
        &state,
        "key-a",
        signed_task(411, "s3c-seal", "s3c-seal-n1", "s"),
    )
    .await;
    let second = post(
        &state,
        "key-a",
        signed_task(412, "s3c-seal", "s3c-seal-n1", "s"),
    )
    .await;
    assert_refused_twice(
        "S-sealed",
        &first,
        &second,
        409,
        crate::idempotency::admission::SEALED_MESSAGE,
    );
    std::assert_eq!(mock.calls(), 1, "premise: no refusal dispatched");
    std::assert_eq!(
        durable_records(&store),
        records,
        "premise: no refusal wrote a record"
    );

    admission.adjust_sealed(1, 0);
    let served = post(
        &state,
        "key-a",
        signed_task(413, "s3c-seal", "s3c-seal-n1", "s"),
    )
    .await;
    let fourth = post(
        &state,
        "key-a",
        signed_task(414, "s3c-seal-2", "s3c-seal-n1", "s"),
    )
    .await;
    assert_single_use("S-sealed", &served, &fourth);
}

/// S-capacity: every task worker busy (-32603).
#[tokio::test]
async fn s3c_capacity_refusal_gives_the_nonce_back() {
    let (mock, mut gate) = MockBackend::holding(Answer::ok());
    let (state, store) = signed_saturated_state(&mock).await;
    let held = post(
        &state,
        "key-a",
        signed_task(420, "s3c-cap-held", "s3c-cap-n0", "h"),
    )
    .await;
    let held_id = task_id(&held);
    gate.wait_for_dispatch().await;
    let records = durable_records(&store);

    let first = post(
        &state,
        "key-a",
        signed_task(421, "s3c-cap", "s3c-cap-n1", "c"),
    )
    .await;
    let second = post(
        &state,
        "key-a",
        signed_task(422, "s3c-cap", "s3c-cap-n1", "c"),
    )
    .await;
    let calls = mock.calls();
    let after = durable_records(&store);
    gate.release_all();
    assert_refused_twice(
        "S-capacity",
        &first,
        &second,
        -32603,
        "every task worker is busy; retry later",
    );
    std::assert_eq!(calls, 1, "premise: only the held task reached the backend");
    std::assert_eq!(after, records, "premise: no refusal wrote a record");

    let settled = poll_until_terminal(&state, "key-a", &held_id).await;
    assert_carries_the_backend_result(&settled);
    let joined = state
        .task_executor
        .drain(std::time::Duration::from_secs(5))
        .await;
    assert!(joined.is_clean(), "the held worker finished: {joined:?}");
    let served = post(
        &state,
        "key-a",
        signed_task(423, "s3c-cap", "s3c-cap-n1", "c"),
    )
    .await;
    let fourth = post(
        &state,
        "key-a",
        signed_task(424, "s3c-cap-2", "s3c-cap-n1", "c"),
    )
    .await;
    assert_single_use("S-capacity", &served, &fourth);
}

/// S-inflight: the key's create is parked at the publication seam, so the
/// same call under another nonce is "already being created" (-32002).
#[tokio::test]
async fn s3c_in_flight_refusal_gives_the_nonce_back() {
    use std::sync::Mutex;
    use std::sync::atomic::AtomicBool;
    use std::sync::mpsc::{TryRecvError, channel};

    let mock = MockBackend::answering(Answer::ok());
    let (state, store) = signed_state(&mock).await;
    let (arrived_tx, arrived_rx) = channel::<()>();
    let (resume_tx, resume_rx) = channel::<()>();
    let held = Arc::new(Mutex::new((arrived_tx, resume_rx)));
    let fired = AtomicBool::new(false);
    state
        .task_executor
        .barrier_on_publication(Arc::new(move || {
            if fired.swap(true, std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            let guard = held.lock().expect("the barrier mutex is never poisoned");
            let _ = guard.0.send(());
            let _ = guard.1.recv();
        }))
        .await;
    let producer = tokio::spawn({
        let state = Arc::clone(&state);
        async move {
            post(
                &state,
                "key-a",
                signed_task(430, "s3c-inf", "s3c-inf-n0", "i"),
            )
            .await
        }
    });
    bounded("the parked create reaching the publication seam", async {
        loop {
            match arrived_rx.try_recv() {
                Ok(()) => return,
                Err(TryRecvError::Empty) => tokio::task::yield_now().await,
                Err(TryRecvError::Disconnected) => panic!("the barrier was dropped"),
            }
        }
    })
    .await;
    let records = durable_records(&store);

    let first = bounded(
        "send 1 while parked",
        post(
            &state,
            "key-a",
            signed_task(431, "s3c-inf", "s3c-inf-n1", "i"),
        ),
    )
    .await;
    let second = bounded(
        "send 2 while parked",
        post(
            &state,
            "key-a",
            signed_task(432, "s3c-inf", "s3c-inf-n1", "i"),
        ),
    )
    .await;
    // Read before the release: the producer dispatches once released.
    let calls = mock.calls();
    let after = durable_records(&store);
    let _ = resume_tx.send(());
    let created = bounded("the released create", producer)
        .await
        .expect("the parked create did not panic");
    task_id(&created);
    assert_refused_twice(
        "S-inflight",
        &first,
        &second,
        -32002,
        "a task with this idempotency key is already being created",
    );
    std::assert_eq!(
        calls,
        0,
        "premise: nothing reached the backend while parked"
    );
    std::assert_eq!(after, records, "premise: no refusal wrote a record");

    let served = post(
        &state,
        "key-a",
        signed_task(433, "s3c-inf-2", "s3c-inf-n1", "i"),
    )
    .await;
    let fourth = post(
        &state,
        "key-a",
        signed_task(434, "s3c-inf-3", "s3c-inf-n1", "i"),
    )
    .await;
    assert_single_use("S-inflight", &served, &fourth);
}

/// The server a `require`-chain row names; it is never reached.
const CHAINED: &str = "s3c-chained";

/// S-chained: a task to a backend that requires a signature chain (-32001).
#[tokio::test]
async fn s3c_chained_refusal_gives_the_nonce_back() {
    use crate::config::{BackendConfig, ChainEmit, ChainMode, FailsafeConfig};

    let mock = MockBackend::answering(Answer::ok());
    // principal-a may reach both backends, so the chain check, not route
    // authorization, decides the call to CHAINED.
    let mut auth = two_principal_auth();
    for key in &mut auth.api_keys {
        key.backends.push(CHAINED.to_string());
    }
    let (mut state, store) = fixture_state(&auth).await;
    {
        let app = Arc::get_mut(&mut state).expect("the fixture state is still exclusive");
        let meta = Arc::get_mut(&mut app.meta_mcp).expect("the meta layer is still exclusive");
        meta.enable_message_signing(
            MessageSigner::new(SIGNING_SECRET.to_vec(), None, SIGNING_KEY_ID.to_owned()),
            REPLAY_WINDOW,
            true,
        );
        meta.set_chain_signer(
            crate::gateway::chain_test_support::signer(),
            ChainEmit::OnRequest,
        );
    }
    register(&state, BACKEND, &mock);
    let chained = Arc::new(crate::backend::Backend::new(
        CHAINED,
        BackendConfig {
            enabled: true,
            signature_chain: ChainMode::Require,
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ));
    let chained_mock = MockBackend::answering(Answer::ok());
    chained.set_transport_for_test(Arc::clone(&chained_mock) as Arc<dyn Transport>);
    assert!(state.backends.register(chained), "fixture registration");
    prime_one_settled_task(&state, 440, "s3c-ch-prime", "s3c-ch-n0").await;
    let to_chained = |id: i64, nonce: &str| {
        let mut body = signed_task(id, &format!("s3c-ch-{id}"), nonce, "c");
        body["params"]["arguments"]["server"] = json!(CHAINED);
        body
    };
    // The route-stage gate fills CHAINED's cold catalogue on its first call:
    // an effect, so that call's nonce stays spent. Warmed here, under its own
    // nonce, the rows below meet a warm catalogue with nothing acted.
    let warmed = post(&state, "key-a", to_chained(445, "s3c-ch-warm")).await;
    std::assert_eq!(
        error_code(&warmed),
        -32001,
        "premise: the warming call meets the chain refusal: {warmed}"
    );
    let records = assert_primed(&mock, &store);

    let first = post(&state, "key-a", to_chained(441, "s3c-ch-n1")).await;
    let second = post(&state, "key-a", to_chained(442, "s3c-ch-n1")).await;
    assert_refused_twice(
        "S-chained",
        &first,
        &second,
        -32001,
        "task execution is not available for a backend that requires a signature chain",
    );
    std::assert_eq!(mock.calls(), 1, "premise: no refusal dispatched");
    std::assert_eq!(
        durable_records(&store),
        records,
        "premise: no refusal wrote a record"
    );

    let served = post(
        &state,
        "key-a",
        signed_task(443, "s3c-ch-ok", "s3c-ch-n1", "c"),
    )
    .await;
    let fourth = post(
        &state,
        "key-a",
        signed_task(444, "s3c-ch-ok2", "s3c-ch-n1", "c"),
    )
    .await;
    assert_single_use("S-chained", &served, &fourth);
}

/// K-unavailable-published (KEEP; green on base and after): the create
/// commits its record and publishes its key, then the store reports failure,
/// so the submit is "task store unavailable" after it acted. The nonce stays
/// spent: the honest re-send under it is a replay.
#[tokio::test]
async fn s3c_unavailable_after_publication_keeps_the_nonce() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, store) = signed_state(&mock).await;
    prime_one_settled_task(&state, 450, "s3c-un-prime", "s3c-un-n0").await;
    let records = assert_primed(&mock, &store);
    state.task_executor.fail_next_publication_for_test().await;

    let first = post(
        &state,
        "key-a",
        signed_task(451, "s3c-un", "s3c-un-n1", "u"),
    )
    .await;
    std::assert_eq!(
        error_code(&first),
        -32603,
        "premise: the store's refusal: {first}"
    );
    assert!(
        message(&first).contains("task store unavailable"),
        "premise: the store's own refusal: {first}"
    );
    assert!(
        durable_records(&store).len() > records.len(),
        "premise: the refused create wrote its record before it failed"
    );
    let resent = post(
        &state,
        "key-a",
        signed_task(452, "s3c-un-2", "s3c-un-n1", "u"),
    )
    .await;
    assert!(
        message(&resent).contains(REPLAY),
        "an Unavailable after the record was written gave the nonce back: {resent}"
    );
}
