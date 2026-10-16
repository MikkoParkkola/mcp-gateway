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
    let (router, sends, _dirs, meta_mcp) =
        r6m_token_exchange::gateway_with_meta(&key, idp.endpoint(), &alice).await;
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
    let (router, sends, _dirs, meta_mcp) =
        r6m_token_exchange::gateway_with_meta(&key, idp.endpoint(), &alice).await;
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
    let (router, sends, _dirs, meta_mcp) =
        r6m_token_exchange::gateway_with_meta(&key, idp.endpoint(), &alice).await;
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
        "P9k-mixed: the repeat answered a task (stored or new): {again}"
    );
    assert_eq!(
        id_masked(&again),
        id_masked(&live),
        "P9k-mixed: the repeat is not the first unproven step's live answer"
    );
    assert_eq!(replay_sends, 0, "P9k-mixed: the repeat reached a backend");
    assert_eq!(
        replay_entries, 0,
        "P9k-mixed: the replay entered the plan executor"
    );
}
