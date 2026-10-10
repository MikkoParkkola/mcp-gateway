// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202 AC12 and AC13: an input round neither loses the backend's ask nor
//! fails a redemption because the clock read before 1970 for a moment. The
//! waits run on paused time; "observe the wait" is yielding until the store's
//! refused-read count grows, before any advance or cancel. Each row names its
//! mutant.

use super::super::*;
use super::input_round::*;
use super::support::*;
use crate::gateway::task_service::RedemptionRead;
use std::time::Duration;

/// The worker's clock retry under test (`CLOCK_RETRY`, 20 ms).
const CLOCK_RETRY: Duration = Duration::from_millis(20);

/// Scheduler turns a wait may take before the row fails; time stays paused.
const TURNS: usize = 2_000_000;

fn store(state: &Arc<AppState>) -> &crate::gateway::task_service::TaskStore {
    &state.task_executor.service.store
}

fn at(secs: u64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(i64::try_from(secs).unwrap(), 0).unwrap()
}

fn before_epoch(state: &Arc<AppState>) {
    store(state).set_clock_for_test(chrono::DateTime::from_timestamp(-1, 0));
}

/// Yield, without letting paused time advance, until the store has refused
/// more than `past` reads; the new count.
async fn observe_wait(state: &Arc<AppState>, past: usize) -> usize {
    for _ in 0..TURNS {
        if store(state).refused_reads_for_test() > past {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(store(state).refused_reads_for_test() > past, "no wait seen");
    store(state).refused_reads_for_test()
}

/// Yield until `ready` holds (store-side reads only, so time stays paused).
async fn until(what: &str, mut ready: impl FnMut() -> bool) {
    for _ in 0..TURNS {
        if ready() {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("never: {what}");
}

fn has_round(state: &Arc<AppState>, id: &str) -> bool {
    store(state).input_round_for_test(id).0.is_some()
}

/// AC12 (RED by mutant). The backend asks while the task store's clock reads
/// before 1970: the worker holds the gated, unminted round, waits, then seals
/// and parks with ONE store read, under the original binding, and the answer
/// still redeems. Mutant: invoke refuses the mint on an unreadable clock (the
/// base behaviour), so the task settles on the abandoned result.
#[tokio::test(start_paused = true)]
async fn a_round_asked_on_an_unreadable_clock_is_sealed_after_the_wait_and_redeems() {
    let (mock, mut gate) =
        MockBackend::holding(Answer::Sequence(vec![ask("confirm", STATE_1), done()]));
    let (state, _dir) = state_with(&mock).await;
    let id = task_id(&post(&state, "key-a", create(1, "ac12-wait")).await);
    gate.wait_for_dispatch().await;
    before_epoch(&state);
    gate.release_all();

    // The funnel's probe and the worker's own read: the wait has begun.
    let waiting = observe_wait(&state, 1).await;
    let seen = get_task(&state, "key-a", &id).await;
    std::assert_eq!(status_of(&seen), "working", "{seen}");
    std::assert!(!has_round(&state, &id));
    std::assert!(!seen.to_string().contains(STATE_1), "{seen}");

    // Sealed at the store's time, which is not the wall clock's.
    let t = crate::protocol::continuation::now_unix_secs() + 100;
    store(&state).set_clock_for_test(Some(at(t)));
    let reads = store(&state).readable_reads_for_test();
    tokio::time::advance(CLOCK_RETRY).await;
    until("the round parks", || has_round(&state, &id)).await;
    std::assert!(store(&state).refused_reads_for_test() >= waiting);
    std::assert_eq!(
        store(&state).readable_reads_for_test() - reads,
        1,
        "one checked read dates both the mint and the park"
    );
    let (round, _) = store(&state).input_round_for_test(&id);
    let token = round
        .and_then(|round| round.request_state)
        .expect("a sealed continuation");
    let sealed = state
        .meta_mcp
        .continuation()
        .keyring()
        .open(&token, t)
        .unwrap();
    std::assert_eq!(sealed.issued_at, t, "sealed at the store's checked time");
    std::assert_eq!(sealed.backend_request_state.as_deref(), Some(STATE_1));
    let shown = get_task(&state, "key-a", &id).await;
    std::assert!(!shown.to_string().contains(&token), "{shown}");
    std::assert!(!shown.to_string().contains(STATE_1), "{shown}");

    // The original binding: the same caller's answer redeems it.
    let redeemed = post(
        &state,
        "key-a",
        update(2, &id, json!({ "confirm": answer() })),
    )
    .await;
    std::assert!(redeemed.get("error").is_none(), "{redeemed}");
    let settled = poll_until_terminal(&state, "key-a", &id).await;
    std::assert_eq!(status_of(&settled), "completed", "{settled}");
    std::assert_eq!(mock.calls(), 2);
}

/// AC12 GUARD. A call with no task worker is refused at once on an unreadable
/// clock: no wait on the request thread, nothing sealed, nothing kept.
/// Mutant: a wait on the request thread (time stands still under pause, so the
/// call would never return).
#[tokio::test(start_paused = true)]
async fn a_call_without_a_worker_is_refused_at_once_on_an_unreadable_clock() {
    let mock = MockBackend::answering(Answer::Sequence(vec![ask("confirm", STATE_1), done()]));
    let (state, _dir) = state_with(&mock).await;
    let refused_before = store(&state).refused_reads_for_test();
    let call = declaring_elicitation(modern(
        1,
        "tools/call",
        json!({
            "name": "gateway_invoke",
            "arguments": { "server": BACKEND, "tool": TOOL, "arguments": { "q": 1 } }
        }),
        true,
    ));
    let _clock = crate::clock::test_clock::before_epoch();
    let answered = tokio::time::timeout(Duration::from_secs(1), post(&state, "key-a", call))
        .await
        .expect("refused with time frozen, not waited on");
    std::assert_eq!(mock.calls(), 1, "the backend was asked: {answered}");
    std::assert!(answered.get("error").is_some(), "{answered}");
    let text = answered.to_string();
    std::assert!(
        !text.contains("requestState") && !text.contains(STATE_1),
        "{text}"
    );
    std::assert_eq!(store(&state).refused_reads_for_test(), refused_before);
    std::assert!(!text.contains("taskId"), "no task was created: {text}");
}

/// The parked round's deadline.
fn due(state: &Arc<AppState>, id: &str) -> u64 {
    store(state)
        .input_round_for_test(id)
        .0
        .and_then(|round| round.continuation_deadline)
        .expect("a parked round carries its deadline")
}

/// Let every runnable task run, without letting paused time advance.
async fn settle_yields() {
    for _ in 0..300 {
        tokio::task::yield_now().await;
    }
}

/// A parked round answered in time whose first `script` redemption samples are
/// given: the answer is acked, the resume worker is running.
async fn answered_with(
    key: &str,
    script: impl FnOnce(u64) -> Vec<RedemptionRead>,
) -> (
    Arc<MockBackend>,
    Arc<AppState>,
    tempfile::TempDir,
    String,
    u64,
) {
    let mock = MockBackend::answering(Answer::Sequence(vec![ask("confirm", STATE_1), done()]));
    let (state, dir) = state_with(&mock).await;
    let id = parked(&state, key).await;
    let due = due(&state, &id);
    let expires = due + crate::gateway::task_service::CONTINUATION_DEADLINE_MARGIN_SECS;
    store(&state).set_clock_for_test(Some(at(due - 1)));
    store(&state).script_redemption_reads_for_test(script(expires));
    let acked = post(
        &state,
        "key-a",
        update(2, &id, json!({ "confirm": answer() })),
    )
    .await;
    std::assert!(acked.get("error").is_none(), "{acked}");
    (mock, state, dir, id, due)
}

/// AC13 (RED by mutant). Each redemption sample that cannot be read is typed,
/// waited out and retried with the continuation unspent; exactly one dispatch
/// follows the last recovery. Mutant: `ClockUnreadable` mapped to `Expired`,
/// which closes the round at the first refusal.
#[tokio::test(start_paused = true)]
async fn a_redemption_on_an_unreadable_clock_waits_and_retries_unspent() {
    let (mock, state, _dir, id, due) =
        answered_with("ac13-wait", |_| vec![RedemptionRead::Unreadable; 2]).await;
    let mut seen = 0;
    for attempt in 1..=2 {
        seen = observe_wait(&state, seen).await;
        let snapshot = store(&state).refused_reads_for_test();
        std::assert_eq!(mock.calls(), 1, "attempt {attempt}: nothing dispatched");
        tokio::time::advance(Duration::from_millis(19)).await;
        settle_yields().await;
        std::assert_eq!(store(&state).refused_reads_for_test(), snapshot, "too soon");
        tokio::time::advance(Duration::from_millis(1)).await;
        until("the wait polls again", || {
            store(&state).refused_reads_for_test() > snapshot
        })
        .await;
        if attempt < 2 {
            seen = store(&state).refused_reads_for_test();
        }
        store(&state).set_clock_for_test(Some(at(due - 1)));
        tokio::time::advance(CLOCK_RETRY).await;
        until("the redemption is sampled", || {
            store(&state).redemptions_consumed_for_test().len() >= attempt
        })
        .await;
    }
    let settled = poll_until_terminal(&state, "key-a", &id).await;
    std::assert_eq!(status_of(&settled), "completed", "{settled}");
    std::assert_eq!(
        store(&state).redemptions_consumed_for_test(),
        vec![RedemptionRead::Unreadable; 2]
    );
    std::assert_eq!(mock.calls(), 2, "exactly one dispatch after recovery");
}

/// Control: with nothing scripted a redemption samples the store's own clock,
/// readable, and an unreadable one is the same wait.
#[tokio::test(start_paused = true)]
async fn an_empty_script_passes_the_store_clock_through() {
    let (mock, state, _dir, id, _due) = answered_with("ac13-control", |_| Vec::new()).await;
    let settled = poll_until_terminal(&state, "key-a", &id).await;
    std::assert_eq!(status_of(&settled), "completed", "{settled}");
    std::assert!(store(&state).redemptions_consumed_for_test().is_empty());
    std::assert_eq!(mock.calls(), 2);
}

/// AC13 (RED by mutant). A readable sample past the deadline is a real expiry:
/// the round closes with no wait. Mutant: the open uses the worker's earlier
/// time, so a continuation already dead is redeemed and dispatched.
#[tokio::test(start_paused = true)]
async fn a_redemption_sampled_past_the_deadline_closes_the_round() {
    let (mock, state, _dir, id, _due) = answered_with("ac13-expiry", |expires| {
        vec![RedemptionRead::At(at(expires + 1))]
    })
    .await;
    let settled = poll_until_terminal(&state, "key-a", &id).await;
    std::assert_eq!(status_of(&settled), "cancelled", "{settled}");
    std::assert_eq!(mock.calls(), 1, "never dispatched into a dead continuation");
    std::assert_eq!(store(&state).refused_reads_for_test(), 0, "no wait");
}

/// How a waiting worker is stopped.
#[derive(Clone, Copy, Debug)]
enum Stop {
    Cancel,
    Shutdown,
}

async fn stop(state: &Arc<AppState>, id: &str, how: Stop) {
    match how {
        Stop::Cancel => {
            let cancel = task_method(9, "tasks/cancel", json!({ "taskId": id }));
            std::assert!(post(state, "key-a", cancel).await.get("error").is_none());
        }
        Stop::Shutdown => {
            let outcome = state
                .task_executor
                .cancel_remaining(Duration::from_secs(5))
                .await;
            std::assert!(outcome.stopped, "the waiting worker outlived shutdown");
        }
    }
}

/// Once stopped, the wait reads the clock no more.
async fn assert_wait_ended(state: &Arc<AppState>) {
    settle_yields().await;
    let snapshot = store(state).refused_reads_for_test();
    tokio::time::advance(CLOCK_RETRY).await;
    settle_yields().await;
    tokio::time::advance(CLOCK_RETRY).await;
    settle_yields().await;
    std::assert_eq!(
        store(state).refused_reads_for_test(),
        snapshot,
        "still waiting"
    );
}

/// AC12 and AC13 (RED by mutant). Cancel, and separately shutdown, end both
/// waits, but only after the wait and its typed outcome are observed: the
/// unminted round held (AC12), the continuation unspent (AC13). Mutant: the
/// wait ignores cancel.
#[tokio::test(start_paused = true)]
async fn cancel_and_shutdown_end_both_clock_waits() {
    for how in [Stop::Cancel, Stop::Shutdown] {
        // AC12: the round is held unminted.
        let (mock, mut gate) =
            MockBackend::holding(Answer::Sequence(vec![ask("confirm", STATE_1), done()]));
        let (state, _dir) = state_with(&mock).await;
        let id = task_id(&post(&state, "key-a", create(1, "ac12-stop")).await);
        gate.wait_for_dispatch().await;
        before_epoch(&state);
        gate.release_all();
        observe_wait(&state, 1).await;
        std::assert!(!has_round(&state, &id), "{how:?}: held unminted");
        stop(&state, &id, how).await;
        assert_wait_ended(&state).await;
        std::assert_eq!(mock.calls(), 1);

        // AC13: the continuation is unspent.
        let (mock, state, _dir, id, _due) =
            answered_with("ac13-stop", |_| vec![RedemptionRead::Unreadable]).await;
        observe_wait(&state, 0).await;
        std::assert_eq!(mock.calls(), 1, "{how:?}: undispatched");
        stop(&state, &id, how).await;
        assert_wait_ended(&state).await;
        std::assert_eq!(mock.calls(), 1);
    }
}

/// Production `redemption_now` is exactly `store.now()`: past its test-only
/// script it reads no other clock. Mutant: a second read (wall clock, or
/// `crate::clock`) beside or instead of the store's.
#[test]
fn production_redemption_now_is_the_store_clock_and_no_other() {
    let source = include_str!("../../../task_service/store_input.rs");
    let start = source
        .find("pub(crate) fn redemption_now")
        .expect("the sampler");
    let body = &source[start..];
    let body = &body[..body.find("\n    }\n").expect("its end")];
    // Production code only: not the signature, not the test-only script block.
    let mut in_script = false;
    let production: Vec<&str> = body
        .lines()
        .skip(1)
        .filter(|line| {
            in_script |= line.contains("#[cfg(test)]");
            let keep = !in_script;
            in_script &= *line != "        }";
            keep
        })
        .collect();
    let raw = ["SystemTime", "Utc", "Instant"].map(|name| format!("{name}::now"));
    for line in &production {
        for other in raw
            .iter()
            .map(String::as_str)
            .chain(["crate::clock", "clock_now"])
        {
            std::assert!(
                !line.contains(other),
                "redemption_now reads {other}: {line}"
            );
        }
    }
    std::assert_eq!(
        production
            .iter()
            .map(|line| line.trim())
            .collect::<Vec<_>>(),
        ["self.now()"]
    );
}

/// The suite's state with response inspection blocking (action mode).
async fn state_blocking_responses(mock: &Arc<MockBackend>) -> (Arc<AppState>, tempfile::TempDir) {
    let (state, dir) = state_with(mock).await;
    let mut app = Arc::try_unwrap(state).unwrap_or_else(|_| panic!("fixture state is exclusive"));
    let mut meta =
        Arc::try_unwrap(app.meta_mcp).unwrap_or_else(|_| panic!("fixture meta is exclusive"));
    meta.enable_response_inspection_action_mode();
    app.meta_mcp = Arc::new(meta);
    (Arc::new(app), dir)
}

/// AC12 (RED by mutant). A backend asks for input behind a refusing response
/// gate while the store clock is unreadable: the gate refuses, nothing is
/// sealed, no worker is parked and none waits. Assembled at runtime so secret
/// scanners do not flag the source. Mutant: the hand-off to the worker moved
/// before `gated?`, so the refused payload waits for a clock and is sealed.
#[tokio::test(start_paused = true)]
async fn a_round_refused_by_a_gate_on_an_unreadable_clock_is_not_minted_or_parked() {
    let mut question = ask("confirm", STATE_1);
    let key = ["AKIA", "IOSFODNN7", "EXAMPLE"].concat();
    question["content"] = json!([{ "type": "text", "text": key }]);
    let (mock, mut gate) = MockBackend::holding(Answer::Sequence(vec![question, done()]));
    let (state, _dir) = state_blocking_responses(&mock).await;
    let id = task_id(&post(&state, "key-a", create(1, "ac12-gate")).await);
    gate.wait_for_dispatch().await;
    before_epoch(&state);
    gate.release_all();
    // Settled by events, not by a count or a clock: the round either reaches
    // a terminal status or the store refuses a read because the payload is
    // waiting for the clock. Paused time cannot advance while this yields.
    let refused = store(&state).refused_reads_for_test();
    let settled = loop {
        let seen = get_task(&state, "key-a", &id).await;
        if is_terminal(&status_of(&seen)) {
            break seen;
        }
        std::assert_eq!(
            store(&state).refused_reads_for_test(),
            refused,
            "the refused payload waits for the clock: {seen}"
        );
        tokio::task::yield_now().await;
    };
    std::assert_eq!(status_of(&settled), "failed", "{settled}");
    std::assert!(!has_round(&state, &id), "nothing was parked");
    std::assert_eq!(mock.calls(), 1);
    std::assert!(!settled.to_string().contains(STATE_1), "{settled}");
}
