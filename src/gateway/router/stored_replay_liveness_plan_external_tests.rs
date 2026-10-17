// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8406 rows on the token-exchange backend: a plan step on an Unjudged
//! account (per-caller mint, no `account:`, still in the catalogue) whose
//! live resolution fails once the `IdP` is gone and the cached token's TTL
//! has passed. The live twin answers that resolution error; a keyed plan
//! replay must give the same answer, with nothing sent and no plan executor
//! entered. External strategies never raise an offerable refusal
//! (`refusal::mark` marks only the vault's not-connected states), so these
//! rows carry PLANREPLAY.4's external case. Current-thread: the forced clock
//! is this thread's.

use std::sync::atomic::Ordering;

use super::*;

/// A keyed `gateway_execute` single on [`r6m_token_exchange::TX`].
fn execute(key: &str, task: bool) -> Value {
    let mut params = json!({"name": "gateway_execute",
        "arguments": {"tool": format!("{}:{TOOL}", r6m_token_exchange::TX),
            "arguments": {"folder": "inbox"}},
        "_meta": meta(Some(key), task)});
    if task {
        params["task"] = json!({});
    }
    params
}

/// `answer` with the JSON-RPC `id` masked.
fn id_masked(answer: &Value) -> Value {
    let mut masked = answer.clone();
    masked["id"] = Value::Null;
    masked
}

/// Kill `idp` and move this thread's clock past the cached token's TTL (one
/// hour); the retained result (one day) is still present.
fn outlive_the_token(idp: r6m_token_exchange::LiveIdp) -> crate::clock::test_clock::Forced {
    idp.kill();
    let now = crate::clock::unix_secs().expect("a test host clock reads after 1970");
    crate::clock::test_clock::at_secs(now + 7200)
}

/// P11 (sync, RED at 1577d7ff6): a keyed `gateway_execute` single on the
/// token-exchange backend succeeds; the `IdP` dies and the token's TTL
/// passes; the same keyed call is answered exactly as the same call made live
/// with a fresh key (normalising only `id`), with nothing sent and no plan
/// executor entered. Kills mSync (no gate on the HTTP Replay arm) and
/// mErrServe (the walk's `Err` arm continues to the serve).
#[tokio::test]
async fn p11_unjudged_plan_replay_answers_the_live_resolution_error() {
    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let alice = r6m_token_exchange::alice();
    let (router, sends, _dirs, served, _hold) =
        r6m_token_exchange::gateway_with_meta(&key, idp.endpoint(), &alice).await;
    let meta_mcp = Arc::clone(&served.meta_mcp);
    let call = ("tools/call", "gateway_execute");
    let first =
        r6m_token_exchange::send_method_as(&router, &alice, call, execute("p11", false)).await;
    assert!(
        first.to_string().contains(MARKER),
        "premise: the plan dispatched: {first}"
    );
    let sent = sends.load(Ordering::SeqCst);
    let entered = crate::gateway::meta_mcp::plan_entries::count(&meta_mcp);
    let _clock = outlive_the_token(idp);
    let again =
        r6m_token_exchange::send_method_as(&router, &alice, call, execute("p11", false)).await;
    // mProceed is killed only by this entries assert: a fall-through to the
    // live run refuses the same way and sends nothing. Keep it.
    let replay_entries = crate::gateway::meta_mcp::plan_entries::count(&meta_mcp) - entered;
    let replay_sends = sends.load(Ordering::SeqCst) - sent;
    let live =
        r6m_token_exchange::send_method_as(&router, &alice, call, execute("p11-live", false)).await;
    // The live twin's code, measured: the resolution error.
    assert_eq!(
        live.pointer("/error/code"),
        Some(&json!(-32603)),
        "premise: the live call is refused with the resolution error: {live}"
    );
    assert!(
        !again.to_string().contains(MARKER),
        "P11: the stored plan output was served: {again}"
    );
    assert_eq!(
        id_masked(&again),
        id_masked(&live),
        "P11: the replay differs from the live call"
    );
    assert_eq!(replay_sends, 0, "P11: the replay reached the backend");
    assert_eq!(
        replay_entries, 0,
        "P11: the replay entered the plan executor"
    );
}

/// P9p (task half, RED at 1577d7ff6): the same as a task-augmented keyed
/// `gateway_execute`. The task completes; the `IdP` dies and the TTL passes;
/// the repeated task call is answered exactly as the same call made live
/// (normalising only `id`), with no stored task, no new task, nothing sent
/// and no plan executor entered. Kills mCarve (the plan carve-out serves the
/// stored task) and mErrServe.
#[tokio::test]
async fn p9p_unjudged_plan_task_repeat_answers_the_live_resolution_error() {
    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let alice = r6m_token_exchange::alice();
    let (router, sends, _dirs, served, _hold) =
        r6m_token_exchange::gateway_with_meta(&key, idp.endpoint(), &alice).await;
    let meta_mcp = Arc::clone(&served.meta_mcp);
    let call = ("tools/call", "gateway_execute");
    let made =
        r6m_token_exchange::send_method_as(&router, &alice, call, execute("p9p", true)).await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    let bound = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let params = json!({"taskId": id, "_meta": meta(None, true)});
        let got =
            r6m_token_exchange::send_method_as(&router, &alice, ("tasks/get", &id), params).await;
        let status = got.pointer("/result/status").and_then(Value::as_str);
        if status == Some("completed") {
            break;
        }
        assert!(
            std::time::Instant::now() < bound && !matches!(status, Some("failed" | "cancelled")),
            "premise: the task completed: {got}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let sent = sends.load(Ordering::SeqCst);
    assert_eq!(sent, 1, "premise: the step was sent once");
    let entered = crate::gateway::meta_mcp::plan_entries::count(&meta_mcp);
    let _clock = outlive_the_token(idp);
    let again =
        r6m_token_exchange::send_method_as(&router, &alice, call, execute("p9p", true)).await;
    // mProceed is killed only by this entries assert: a fall-through to the
    // live run refuses the same way and sends nothing. Keep it.
    let replay_entries = crate::gateway::meta_mcp::plan_entries::count(&meta_mcp) - entered;
    let replay_sends = sends.load(Ordering::SeqCst) - sent;
    let live =
        r6m_token_exchange::send_method_as(&router, &alice, call, execute("p9p-live", false)).await;
    // The live twin's code, measured: the resolution error.
    assert_eq!(
        live.pointer("/error/code"),
        Some(&json!(-32603)),
        "premise: the live call is refused with the resolution error: {live}"
    );
    assert!(
        again.pointer("/result/taskId").is_none(),
        "P9p: the repeat answered a task (stored or new): {again}"
    );
    assert_eq!(
        id_masked(&again),
        id_masked(&live),
        "P9p: the repeat differs from the live call"
    );
    assert_eq!(replay_sends, 0, "P9p: the repeat reached the backend");
    assert_eq!(
        replay_entries, 0,
        "P9p: the replay entered the plan executor"
    );
}

/// P9k-mixed (task half, RED at 1577d7ff6; kills mFirst): a task-augmented
/// keyed chain `[plain:read, tx:read]` completes, recording both targets in
/// order. The `IdP` dies and the TTL passes; the repeat answers the first
/// unproven step's live resolution error (CR-1: the single form's live twin
/// on [`r6m_token_exchange::TX`]), with nothing sent and no executor entered.
/// A walk over `stored.targets.first()` alone (mFirst) sees only the plain
/// target, which mints nothing per caller, and serves the stored task.
#[tokio::test]
async fn p9k_mixed_task_chain_judges_every_recorded_target() {
    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let alice = r6m_token_exchange::alice();
    let (router, sends, _dirs, served, _hold) =
        r6m_token_exchange::gateway_with_meta(&key, idp.endpoint(), &alice).await;
    let meta_mcp = Arc::clone(&served.meta_mcp);
    let call = ("tools/call", "gateway_execute");
    let step = |server: &str| json!({"tool": format!("{server}:{TOOL}"), "arguments": {"folder": "inbox"}});
    let mut chain = json!({"name": "gateway_execute",
        "arguments": {"chain": [step(r6m_token_exchange::PLAIN), step(r6m_token_exchange::TX)]},
        "_meta": meta(Some("p9k-mixed"), true)});
    chain["task"] = json!({});
    let made = r6m_token_exchange::send_method_as(&router, &alice, call, chain.clone()).await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    let bound = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let params = json!({"taskId": id, "_meta": meta(None, true)});
        let got =
            r6m_token_exchange::send_method_as(&router, &alice, ("tasks/get", &id), params).await;
        let status = got.pointer("/result/status").and_then(Value::as_str);
        if status == Some("completed") {
            break;
        }
        assert!(
            std::time::Instant::now() < bound && !matches!(status, Some("failed" | "cancelled")),
            "premise: the task completed: {got}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let sent = sends.load(Ordering::SeqCst);
    assert_eq!(sent, 2, "premise: both steps were sent");
    let recorded: Vec<(String, String)> = served
        .task_executor
        .service
        .store
        .targets_for_test(&id)
        .into_iter()
        .map(|target| (target.server, target.tool))
        .collect();
    assert_eq!(
        recorded,
        [
            (r6m_token_exchange::PLAIN.to_string(), TOOL.to_string()),
            (r6m_token_exchange::TX.to_string(), TOOL.to_string()),
        ],
        "premise: the task recorded plain first, then tx"
    );
    let entered = crate::gateway::meta_mcp::plan_entries::count(&meta_mcp);
    let _clock = outlive_the_token(idp);
    let again = r6m_token_exchange::send_method_as(&router, &alice, call, chain).await;
    // mProceed is killed only by this entries assert: a fall-through to the
    // live run refuses the same way and sends nothing. Keep it.
    let replay_entries = crate::gateway::meta_mcp::plan_entries::count(&meta_mcp) - entered;
    let replay_sends = sends.load(Ordering::SeqCst) - sent;
    let live =
        r6m_token_exchange::send_method_as(&router, &alice, call, execute("p9k-mixed-live", false))
            .await;
    // The live twin's code, measured: the resolution error.
    assert_eq!(
        live.pointer("/error/code"),
        Some(&json!(-32603)),
        "premise: the live call is refused with the resolution error: {live}"
    );
    assert!(
        again.pointer("/result/taskId").is_none(),
        "P9k-mixed: the repeat answered a task: only the first recorded step \
         (plain, which mints nothing) was judged, not the second (tx): {again}"
    );
    assert_eq!(
        id_masked(&again),
        id_masked(&live),
        "P9k-mixed: the repeat is not the tx step's live answer (the first \
         unproven step; plain, recorded first, mints nothing)"
    );
    assert_eq!(replay_sends, 0, "P9k-mixed: the repeat reached a backend");
    assert_eq!(
        replay_entries, 0,
        "P9k-mixed: the replay entered the plan executor"
    );
}

/// P9-legacy (task half, GUARD; mutant mLegacyServe): a plan task row
/// written before targets were recorded (`strip_targets_for_test`: no
/// targets, version 3) is refused at its repeat, fail closed, before any
/// account walk: -32003 "stored task result has no recorded provenance"
/// (MIK-7686), with no task, nothing sent and no plan executor entered. An
/// empty list read as recorded (mLegacyServe) walks nothing and serves it.
#[tokio::test]
async fn p9_legacy_a_plan_row_with_no_recorded_targets_is_refused() {
    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let alice = r6m_token_exchange::alice();
    let (router, sends, _dirs, served, _hold) =
        r6m_token_exchange::gateway_with_meta(&key, idp.endpoint(), &alice).await;
    let call = ("tools/call", "gateway_execute");
    let made =
        r6m_token_exchange::send_method_as(&router, &alice, call, execute("p9-legacy", true)).await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    let bound = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let params = json!({"taskId": id, "_meta": meta(None, true)});
        let got =
            r6m_token_exchange::send_method_as(&router, &alice, ("tasks/get", &id), params).await;
        let status = got.pointer("/result/status").and_then(Value::as_str);
        if status == Some("completed") {
            break;
        }
        assert!(
            std::time::Instant::now() < bound && !matches!(status, Some("failed" | "cancelled")),
            "premise: the task completed: {got}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    served
        .task_executor
        .service
        .store
        .strip_targets_for_test(&id);
    let sent = sends.load(Ordering::SeqCst);
    let entered = crate::gateway::meta_mcp::plan_entries::count(&served.meta_mcp);
    let again =
        r6m_token_exchange::send_method_as(&router, &alice, call, execute("p9-legacy", true)).await;
    assert_eq!(
        again.pointer("/error/code"),
        Some(&json!(-32003)),
        "P9-legacy: the legacy plan row was not refused: {again}"
    );
    assert!(
        again
            .pointer("/error/message")
            .and_then(Value::as_str)
            .is_some_and(|message| message.contains("no recorded provenance")),
        "P9-legacy: not the provenance refusal: {again}"
    );
    assert_eq!(
        sends.load(Ordering::SeqCst) - sent,
        0,
        "P9-legacy: the repeat reached the backend"
    );
    assert_eq!(
        crate::gateway::meta_mcp::plan_entries::count(&served.meta_mcp) - entered,
        0,
        "P9-legacy: the repeat entered the plan executor"
    );
    drop(idp);
}

/// Polls `tasks/get` (up to 10 s) until task `id` reaches `want`.
async fn await_status(
    router: &axum::Router,
    alice: &crate::key_server::oidc::VerifiedIdentity,
    id: &str,
    want: &str,
) {
    let bound = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let params = json!({"taskId": id, "_meta": meta(None, true)});
        let got =
            r6m_token_exchange::send_method_as(router, alice, ("tasks/get", id), params).await;
        if got.pointer("/result/status").and_then(Value::as_str) == Some(want) {
            return;
        }
        assert!(
            std::time::Instant::now() < bound,
            "premise: the task reached {want}: {got}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// A plan task held at its backend, so it stays working: the keyed
/// `gateway_execute` task is made, and its step has reached the backend.
async fn held_plan_task(
    router: &axum::Router,
    alice: &crate::key_server::oidc::VerifiedIdentity,
    (sends, hold): (&std::sync::atomic::AtomicUsize, &r6m_token_exchange::Hold),
    key: &str,
) -> String {
    hold.send_replace(true);
    let made = r6m_token_exchange::send_method_as(
        router,
        alice,
        ("tools/call", "gateway_execute"),
        execute(key, true),
    )
    .await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    let bound = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while sends.load(Ordering::SeqCst) == 0 {
        assert!(
            std::time::Instant::now() < bound,
            "premise: the held step reached the backend"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    id
}

/// Premise of P9n and P9i: a run that has not settled recorded no target.
fn assert_no_target_recorded(served: &crate::gateway::router::AppState, id: &str) {
    assert!(
        served
            .task_executor
            .service
            .store
            .targets_for_test(id)
            .is_empty(),
        "premise: an unsettled plan row already holds a recorded target"
    );
}

/// The repeat answered the stored row itself, in `status`, with no error.
fn assert_row_status(row: &str, again: &Value, id: &str, status: &str) {
    assert!(
        again.get("error").is_none(),
        "{row}: the repeat of a row with no backend output was refused: {again}"
    );
    assert_eq!(
        again.pointer("/result/taskId").and_then(Value::as_str),
        Some(id),
        "{row}: not the stored row: {again}"
    );
    assert_eq!(
        again.pointer("/result/status").and_then(Value::as_str),
        Some(status),
        "{row}: not the row's status: {again}"
    );
}

/// P9n (MIK-8406, task half; the `serves_backend_output` decision): a plan
/// task still WORKING (its step held at the backend) is repeated after its
/// Unjudged account stops resolving (the `IdP` dies, the token's TTL
/// passes). A working row hands out no backend output, so its repeat
/// answers the row's status as before, not the account refusal: a caller
/// polling by repeat keeps learning where its task is. Nothing is sent and
/// no plan executor is entered. Green without a `serves_backend_output`
/// guard: targets reach the store only when a run settles, so a working row
/// has none and the walk is empty (premise below). A change that records
/// targets mid-run turns this row red, which is where the guard belongs.
#[tokio::test]
async fn p9n_a_working_plan_row_repeat_answers_its_status() {
    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let alice = r6m_token_exchange::alice();
    let (router, sends, _dirs, served, hold) =
        r6m_token_exchange::gateway_with_meta(&key, idp.endpoint(), &alice).await;
    let id = held_plan_task(&router, &alice, (&sends, &hold), "p9n").await;
    assert_no_target_recorded(&served, &id);
    let (sent, entered) = (
        sends.load(Ordering::SeqCst),
        crate::gateway::meta_mcp::plan_entries::count(&served.meta_mcp),
    );
    let _clock = outlive_the_token(idp);
    let again = r6m_token_exchange::send_method_as(
        &router,
        &alice,
        ("tools/call", "gateway_execute"),
        execute("p9n", true),
    )
    .await;
    assert_row_status("P9n", &again, &id, "working");
    assert_eq!(sends.load(Ordering::SeqCst), sent, "P9n: the repeat sent");
    assert_eq!(
        crate::gateway::meta_mcp::plan_entries::count(&served.meta_mcp),
        entered,
        "P9n: the repeat entered the plan executor"
    );
    hold.send_replace(false);
}

/// P9i (MIK-8406, task half; the `serves_backend_output` decision): the same
/// plan task, cancelled while held, is repeated after its Unjudged account
/// stops resolving. A cancelled row hands out no backend output, so the
/// repeat answers the row as cancelled, not the account refusal. Nothing is
/// sent and no plan executor is entered. Green without the guard for the
/// same reason as P9n: the cancel arm returns before any settle, so a
/// cancelled row records no target (premise below).
#[tokio::test]
async fn p9i_a_cancelled_plan_row_repeat_answers_its_status() {
    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let alice = r6m_token_exchange::alice();
    let (router, sends, _dirs, served, hold) =
        r6m_token_exchange::gateway_with_meta(&key, idp.endpoint(), &alice).await;
    let id = held_plan_task(&router, &alice, (&sends, &hold), "p9i").await;
    let cancel = json!({"taskId": id, "_meta": meta(None, true)});
    let cancelled =
        r6m_token_exchange::send_method_as(&router, &alice, ("tasks/cancel", &id), cancel).await;
    assert!(
        cancelled.get("error").is_none(),
        "premise: the task cancelled: {cancelled}"
    );
    await_status(&router, &alice, &id, "cancelled").await;
    assert_no_target_recorded(&served, &id);
    let (sent, entered) = (
        sends.load(Ordering::SeqCst),
        crate::gateway::meta_mcp::plan_entries::count(&served.meta_mcp),
    );
    let _clock = outlive_the_token(idp);
    let again = r6m_token_exchange::send_method_as(
        &router,
        &alice,
        ("tools/call", "gateway_execute"),
        execute("p9i", true),
    )
    .await;
    assert_row_status("P9i", &again, &id, "cancelled");
    assert_eq!(sends.load(Ordering::SeqCst), sent, "P9i: the repeat sent");
    assert_eq!(
        crate::gateway::meta_mcp::plan_entries::count(&served.meta_mcp),
        entered,
        "P9i: the repeat entered the plan executor"
    );
    hold.send_replace(false);
}

/// P9g (MIK-8406, task half; mutant mEmptyRefuse): a completed plan row
/// whose recorded target list is empty (its run dispatched nothing; built
/// with the test-only `empty_targets_for_test`) is served as stored at its
/// repeat, with no account judged: the `IdP` is dead, so any resolution
/// would refuse. Refusing an empty recorded list (mEmptyRefuse) fails this
/// row.
#[tokio::test]
async fn p9g_a_plan_row_with_an_empty_recorded_list_is_served() {
    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let alice = r6m_token_exchange::alice();
    let (router, sends, _dirs, served, _hold) =
        r6m_token_exchange::gateway_with_meta(&key, idp.endpoint(), &alice).await;
    let made = r6m_token_exchange::send_method_as(
        &router,
        &alice,
        ("tools/call", "gateway_execute"),
        execute("p9g", true),
    )
    .await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    await_status(&router, &alice, &id, "completed").await;
    served
        .task_executor
        .service
        .store
        .empty_targets_for_test(&id);
    let sent = sends.load(Ordering::SeqCst);
    let _clock = outlive_the_token(idp);
    let again = r6m_token_exchange::send_method_as(
        &router,
        &alice,
        ("tools/call", "gateway_execute"),
        execute("p9g", true),
    )
    .await;
    assert_row_status("P9g", &again, &id, "completed");
    assert_eq!(sends.load(Ordering::SeqCst), sent, "P9g: the repeat sent");
}

/// A keyed `gateway_execute` single whose step asks for input: the fixture's
/// backend answers an input round on folder [`r6m_token_exchange::ASK`].
fn asking(key: &str, task: bool) -> Value {
    let mut params = execute(key, task);
    params["arguments"]["arguments"]["folder"] = json!(r6m_token_exchange::ASK);
    params
}

/// P9j (ii) (MIK-8406, task half; mutant mCarve): a plan task parks
/// `input_required` on the token-exchange backend, its target recorded at
/// the park. With the account live, its repeat serves the parked row (the
/// prompt). The `IdP` then dies and the TTL passes: the repeat is answered
/// exactly as the same call made live (normalising only `id`), with no row
/// served, nothing sent and no plan executor entered. A carve-out that
/// serves plan tasks unjudged (mCarve, the pre-fix base) serves the prompt.
#[tokio::test]
async fn p9j_an_input_required_plan_row_repeat_answers_the_live_resolution_error() {
    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let alice = r6m_token_exchange::alice();
    let (router, sends, _dirs, served, _hold) =
        r6m_token_exchange::gateway_with_meta(&key, idp.endpoint(), &alice).await;
    let meta_mcp = Arc::clone(&served.meta_mcp);
    let call = ("tools/call", "gateway_execute");
    let made = r6m_token_exchange::send_method_as(&router, &alice, call, asking("p9j", true)).await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    await_status(&router, &alice, &id, "input_required").await;
    assert!(
        !served
            .task_executor
            .service
            .store
            .targets_for_test(&id)
            .is_empty(),
        "premise: the park recorded the plan's target"
    );
    let served_prompt =
        r6m_token_exchange::send_method_as(&router, &alice, call, asking("p9j", true)).await;
    assert_row_status("P9j all-live", &served_prompt, &id, "input_required");
    let (sent, entered) = (
        sends.load(Ordering::SeqCst),
        crate::gateway::meta_mcp::plan_entries::count(&meta_mcp),
    );
    let _clock = outlive_the_token(idp);
    let again =
        r6m_token_exchange::send_method_as(&router, &alice, call, asking("p9j", true)).await;
    let replay_entries = crate::gateway::meta_mcp::plan_entries::count(&meta_mcp) - entered;
    let replay_sends = sends.load(Ordering::SeqCst) - sent;
    let live =
        r6m_token_exchange::send_method_as(&router, &alice, call, asking("p9j-live", false)).await;
    assert_eq!(
        live.pointer("/error/code"),
        Some(&json!(-32603)),
        "premise: the live call is refused with the resolution error: {live}"
    );
    assert!(
        again.pointer("/result/taskId").is_none(),
        "P9j: the repeat answered a task (stored or new): {again}"
    );
    assert_eq!(
        id_masked(&again),
        id_masked(&live),
        "P9j: the repeat differs from the live call"
    );
    assert_eq!(replay_sends, 0, "P9j: the repeat reached the backend");
    assert_eq!(
        replay_entries, 0,
        "P9j: the replay entered the plan executor"
    );
}
