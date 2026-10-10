// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8176 stage 4, task arm of the slot-release matrix (test plan t3, Part
//! B). A parked round's sealed continuation never reaches the client; the
//! stored round owns its slot until the resume redeems it, and gives it back
//! when the round ends any other way. Every cell is run; every failing cell is
//! reported, not the first.
use super::super::*;
use super::input_round::*;
use super::input_round_races::state_with_config;
use super::support::*;
use std::time::Duration;

/// Slots held now, on the slot table's own (wall) clock.
async fn held(state: &Arc<AppState>) -> usize {
    let now = crate::protocol::continuation::now_unix_secs();
    state.meta_mcp.continuation().in_flight().len(now).await
}

/// Wait (bounded) until `held` reaches `want`: a release runs on a spawned
/// task, so it lands shortly after the drop that triggers it.
async fn settles_at(state: &Arc<AppState>, want: usize) -> usize {
    let bound = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let now = held(state).await;
        if now == want || tokio::time::Instant::now() >= bound {
            return now;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Freeze the task store's clock at unix second `secs`.
fn clock(state: &Arc<AppState>, secs: u64) {
    let at = chrono::DateTime::from_timestamp(i64::try_from(secs).unwrap(), 0).unwrap();
    state
        .task_executor
        .service
        .store
        .set_clock_for_test(Some(at));
}

fn deadline(state: &Arc<AppState>, id: &str) -> u64 {
    let (round, _) = state.task_executor.service.store.input_round_for_test(id);
    round
        .expect("an open round")
        .continuation_deadline
        .expect("a stored continuation carries its deadline")
}

/// A task whose backend asks once, parked on its round. `ttl_ms` overrides
/// the task TTL when given.
async fn parked_task(
    key: &str,
    ttl_ms: Option<u64>,
) -> (Arc<MockBackend>, Arc<AppState>, tempfile::TempDir, String) {
    let mock = MockBackend::answering(Answer::Sequence(vec![ask("confirm", STATE_1), done()]));
    let mut config = crate::config::Config::default();
    if let Some(ttl) = ttl_ms {
        config.tasks.default_ttl_ms = ttl;
    }
    let (state, dir) = state_with_config(&mock, config).await;
    let id = parked(&state, key).await;
    (mock, state, dir, id)
}

/// Run the expiry sweep with the store clock at `secs` until `id` leaves
/// `input_required`, bounded.
async fn sweep_at(state: &Arc<AppState>, id: &str, secs: u64) {
    let sweep = state
        .task_executor
        .start_expiry(Duration::from_millis(20))
        .expect("the sweep starts");
    clock(state, secs);
    let bound = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < bound {
        let seen = get_task(state, "key-a", id).await;
        if status_of(&seen) != "input_required" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    drop(sweep);
}

/// The task-arm cells. Each returns `Some(reason)` when it fails.
#[derive(Clone, Copy, Debug)]
enum Cell {
    /// B1 (guard): the parked round keeps its slot after the worker ends,
    /// and the resume redeems it.
    KeptThroughResume,
    /// B2 (SLOT.10): a cancelled parked round gives its slot back.
    CancelledReleases,
    /// B3 (SLOT.10): a round the sweep closes at its continuation deadline
    /// gives its slot back at the close, not at the slot's own expiry.
    ClosedAtDeadlineReleases,
    /// B4 (SLOT.10): a parked round dropped at its task TTL gives its slot
    /// back.
    ExpiredAtTtlReleases,
    /// B6 (guard): a completed result that carries a sealed question, read
    /// through tasks/get, keeps its slot when the task later expires.
    CompletedReadKeeps,
    /// B7 (SLOT.8, task): the same result never read gives its slot back when
    /// the task expires.
    CompletedUnreadReleases,
    /// B10 (guard, N1): an idempotent re-create of a completed task answers
    /// the stored task (`BeginOutcome::Existing`); that delivery keeps the
    /// slot when the task later expires.
    RecreateDeliversKeeps,
    /// B11 (M1): a result too large for its record settles as the gateway's
    /// bounded failure, which carries no question, so the slot is given back
    /// when the worker ends.
    BoundedSettleReleases,
}

const CELLS: [Cell; 8] = [
    Cell::KeptThroughResume,
    Cell::CancelledReleases,
    Cell::ClosedAtDeadlineReleases,
    Cell::ExpiredAtTtlReleases,
    Cell::CompletedReadKeeps,
    Cell::CompletedUnreadReleases,
    Cell::RecreateDeliversKeeps,
    Cell::BoundedSettleReleases,
];

async fn run(cell: Cell) -> Option<String> {
    let key = format!("slot-tasks-{cell:?}");
    match cell {
        Cell::KeptThroughResume => {
            let (mock, state, _dir, id) = parked_task(&key, None).await;
            settle_quiet().await;
            let parked = held(&state).await;
            if parked != 1 {
                return Some(format!("parked round holds {parked} slots, want 1"));
            }
            let acked = post(
                &state,
                "key-a",
                update(2, &id, json!({ "confirm": answer() })),
            )
            .await;
            if acked.get("error").is_some() {
                return Some(format!("resume refused: {acked}"));
            }
            let settled = poll_until_terminal(&state, "key-a", &id).await;
            if status_of(&settled) != "completed" || mock.calls() != 2 {
                return Some(format!("resume did not redeem: {settled}"));
            }
            let after = settles_at(&state, 0).await;
            (after != 0).then(|| format!("redeemed slot still held: {after}"))
        }
        Cell::CancelledReleases => {
            let (_mock, state, _dir, id) = parked_task(&key, None).await;
            let cancelled = post(
                &state,
                "key-a",
                task_method(2, "tasks/cancel", json!({ "taskId": id })),
            )
            .await;
            if cancelled.get("error").is_some() {
                return Some(format!("cancel refused: {cancelled}"));
            }
            let after = settles_at(&state, 0).await;
            (after != 0).then(|| format!("cancelled round still holds {after} slots"))
        }
        Cell::ClosedAtDeadlineReleases => {
            let (_mock, state, _dir, id) = parked_task(&key, None).await;
            let at = deadline(&state, &id);
            sweep_at(&state, &id, at).await;
            let after = settles_at(&state, 0).await;
            (after != 0).then(|| format!("round closed at its deadline still holds {after} slots"))
        }
        Cell::ExpiredAtTtlReleases => {
            let (_mock, state, _dir, id) = parked_task(&key, Some(60_000)).await;
            let past_ttl = crate::protocol::continuation::now_unix_secs() + 61;
            sweep_at(&state, &id, past_ttl).await;
            let after = settles_at(&state, 0).await;
            (after != 0).then(|| format!("round dropped at its TTL still holds {after} slots"))
        }
        Cell::BoundedSettleReleases => {
            // Measured, never guessed. The cap sits between the initial
            // record's stored size and the result's own size, so no record
            // that keeps the result fits and every fallback short of the
            // bounded failure is refused. The bounded record is then measured
            // the same way and must fit too. A change in any of the three
            // sizes fails this setup loudly instead of turning the row green
            // or red for another reason.
            let (initial, result) = record_sizes(&format!("{key}-measure")).await;
            let cap = initial + (result - initial) / 2;
            if !(initial < cap && cap < result) {
                return Some(format!(
                    "no room for a cap: initial record {initial} B, result alone {result} B"
                ));
            }
            let mock = MockBackend::answering(Answer::Sequence(vec![long_question(), done()]));
            let mut config = crate::config::Config::default();
            config.tasks.max_record_bytes = cap;
            let (state, _dir) = state_with_config(&mock, config).await;
            state.meta_mcp.set_playbook_engine(asking_playbook());
            let created = post(&state, "key-a", playbook_task_body(&key)).await;
            if created.get("error").is_some() {
                return Some(format!(
                    "the {cap} B cap refused the request itself: {created}"
                ));
            }
            let id = task_id(&created);
            let settled = poll_until_terminal(&state, "key-a", &id).await;
            if status_of(&settled) != "failed" || !sealed_in(&state, &settled).is_empty() {
                let stored = state.task_executor.service.store.record_bytes_for_test(&id);
                return Some(format!(
                    "not a bounded failure without a question (initial {initial} B, result {result} B, cap {cap} B, stored record {stored:?} B): status {}",
                    status_of(&settled)
                ));
            }
            let bounded = state.task_executor.service.store.record_bytes_for_test(&id);
            if !bounded.is_some_and(|bytes| bytes < cap) {
                return Some(format!(
                    "the bounded record {bounded:?} B does not fit the {cap} B cap"
                ));
            }
            let after = settles_at(&state, 0).await;
            (after != 0).then(|| format!("bounded settle still holds {after} slots"))
        }
        Cell::RecreateDeliversKeeps => {
            let (state, _dir, id) = completed_playbook_task(&key).await;
            let again = post(&state, "key-a", playbook_task_body(&key)).await;
            if sealed_in(&state, &again).is_empty() {
                return Some(format!("the re-create answer carries no question: {again}"));
            }
            if task_id(&again) != id {
                return Some(format!("the re-create made a new task: {again}"));
            }
            let past_ttl = crate::protocol::continuation::now_unix_secs() + 61;
            expire_at(&state, &id, past_ttl).await;
            let after = settles_at(&state, 1).await;
            (after != 1)
                .then(|| format!("re-create delivered, then {after} slots held after expiry"))
        }
        Cell::CompletedReadKeeps | Cell::CompletedUnreadReleases => {
            let read = matches!(cell, Cell::CompletedReadKeeps);
            let (state, _dir, id) = completed_playbook_task(&key).await;
            if held(&state).await != 1 {
                return Some("the completed result holds no slot".into());
            }
            if read {
                let seen = get_task(&state, "key-a", &id).await;
                if sealed_in(&state, &seen).is_empty() {
                    return Some(format!("tasks/get did not deliver the question: {seen}"));
                }
            }
            let past_ttl = crate::protocol::continuation::now_unix_secs() + 61;
            expire_at(&state, &id, past_ttl).await;
            let want = usize::from(read);
            let after = settles_at(&state, want).await;
            (after != want).then(|| format!("after expiry {after} slots held, want {want}"))
        }
    }
}

/// A playbook task (TTL 60 s) completed with its step's sealed question in
/// the result.
async fn completed_playbook_task(key: &str) -> (Arc<AppState>, tempfile::TempDir, String) {
    let mock = MockBackend::answering(Answer::Sequence(vec![ask("confirm", STATE_1), done()]));
    let mut config = crate::config::Config::default();
    config.tasks.default_ttl_ms = 60_000;
    let (state, dir) = state_with_config(&mock, config).await;
    state.meta_mcp.set_playbook_engine(asking_playbook());
    let created = post(&state, "key-a", playbook_task_body(key)).await;
    let id = task_id(&created);
    // Settled without a read: the worker's commit is observed through the
    // store, so the row's own read (or its absence) is the only delivery.
    let bound = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < bound {
        if settled_unread(&state, &id) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    (state, dir, id)
}

/// The keyed task-augmented `gateway_run_playbook` call for `key`.
fn playbook_task_body(key: &str) -> Value {
    keyed(
        declaring_elicitation(modern(
            1,
            "tools/call",
            json!({ "name": "gateway_run_playbook", "arguments": { "name": "ask-once" }, "task": {} }),
            true,
        )),
        key,
    )
}

/// Whether `id` has settled, read from the store without a tasks/get.
fn settled_unread(state: &Arc<AppState>, id: &str) -> bool {
    state
        .task_executor
        .service
        .store
        .status_for_test(id)
        .is_some_and(|status| status == crate::gateway::task_service::TaskStatus::Completed)
}

/// Run the sweep with the store clock at `secs` until `id` is gone, bounded.
async fn expire_at(state: &Arc<AppState>, id: &str, secs: u64) {
    let sweep = state
        .task_executor
        .start_expiry(Duration::from_millis(20))
        .expect("the sweep starts");
    clock(state, secs);
    let bound = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < bound
        && state
            .task_executor
            .service
            .store
            .status_for_test(id)
            .is_some()
    {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    drop(sweep);
}

/// MATRIX.1's task cell (A3 names it).
#[tokio::test]
async fn slot_release_matrix_tasks() {
    let mut failures = Vec::new();
    for cell in CELLS {
        if let Some(why) = run(cell).await {
            failures.push(format!("{cell:?}: {why}"));
        }
    }
    std::assert!(
        failures.is_empty(),
        "task slot cells failed:\n{}",
        failures.join("\n")
    );
}

/// A question whose message is long enough that no record holding the
/// result fits a cap the initial record does.
fn long_question() -> Value {
    let mut asked = ask("confirm", STATE_1);
    asked["inputRequests"]["confirm"]["params"]["message"] = json!("q".repeat(4096));
    asked
}

/// The stored size of the playbook task's record just after its create, and
/// the size of its result alone once it has completed, under the default cap.
async fn record_sizes(key: &str) -> (usize, usize) {
    let mock = MockBackend::answering(Answer::Sequence(vec![long_question(), done()]));
    let (state, _dir) = state_with(&mock).await;
    state.meta_mcp.set_playbook_engine(asking_playbook());
    // The worker is held at its dispatch marker, so the record read is the
    // one written before any result: the initial size, not a race.
    let (observer, mut hold) = observe_dispatched(&state);
    let created = post(&state, "key-a", playbook_task_body(key)).await;
    let id = task_id(&created);
    hold.arrived
        .recv()
        .await
        .expect("the worker reaches dispatch");
    let initial = state
        .task_executor
        .service
        .store
        .record_bytes_for_test(&id)
        .expect("the created record");
    hold.disarm_and_release(&observer);
    let settled = poll_until_terminal(&state, "key-a", &id).await;
    // The result alone: no record that keeps it can be smaller.
    let result = settled["result"]["result"].to_string().len();
    (initial, result)
}

/// A one-step playbook whose step's backend asks: the carrier the plan names
/// for a completed answer that nests a sealed question (t3 C0, F2).
fn asking_playbook() -> crate::playbook::PlaybookEngine {
    let definition: crate::playbook::PlaybookDefinition = serde_json::from_value(json!({
        "playbook": "1.0",
        "name": "ask-once",
        "description": "one step whose backend stops to ask",
        "steps": [ { "name": "step", "tool": TOOL, "server": BACKEND, "arguments": {} } ]
    }))
    .expect("the probe playbook deserialises");
    let mut engine = crate::playbook::PlaybookEngine::new();
    engine.register(definition);
    engine
}

/// Every string in `value` that opens as a continuation under `state`'s
/// keyring, with the slot it names.
fn sealed_in(state: &Arc<AppState>, value: &Value) -> Vec<String> {
    // A string that is itself a JSON document (an answer `gateway_invoke`
    // text-wraps into `content[].text`) is searched inside as well.
    fn strings(value: &Value, out: &mut Vec<String>) {
        match value {
            Value::String(s) => {
                out.push(s.clone());
                if let Ok(inner) = serde_json::from_str::<Value>(s)
                    && !inner.is_string()
                {
                    strings(&inner, out);
                }
            }
            Value::Array(items) => items.iter().for_each(|i| strings(i, out)),
            Value::Object(map) => map.values().for_each(|v| strings(v, out)),
            _ => {}
        }
    }
    let continuation = state.meta_mcp.continuation();
    let now = crate::protocol::continuation::now_unix_secs();
    let mut found = Vec::new();
    strings(value, &mut found);
    found
        .into_iter()
        .filter_map(|s| {
            continuation
                .keyring()
                .open(&s, now)
                .ok()
                .map(|p| p.hold_key)
        })
        .collect()
}

/// C0 (task arm): does a task's COMPLETED result carry a sealed question?
/// The B rows for completed results (B6-B10) need such a carrier; if none is
/// reachable, they are recorded unreachable with this row as the proof.
#[tokio::test]
async fn c0_a_completed_playbook_task_carries_its_steps_sealed_question() {
    let mock = MockBackend::answering(Answer::Sequence(vec![ask("confirm", STATE_1), done()]));
    let (state, _dir) = state_with(&mock).await;
    state.meta_mcp.set_playbook_engine(asking_playbook());
    let body = keyed(
        declaring_elicitation(modern(
            1,
            "tools/call",
            json!({ "name": "gateway_run_playbook", "arguments": { "name": "ask-once" }, "task": {} }),
            true,
        )),
        "c0-playbook",
    );
    let created = post(&state, "key-a", body).await;
    let settled = poll_until_terminal(&state, "key-a", &task_id(&created)).await;
    let sealed = sealed_in(&state, &settled);
    std::assert_eq!(status_of(&settled), "completed", "{settled}");
    std::assert!(
        !sealed.is_empty(),
        "no sealed question in the completed result: {settled}"
    );
    std::assert_eq!(held(&state).await, 1, "its slot is held: {settled}");
    // For B11's record cap: the completed result's size.
    eprintln!(
        "c0 completed result bytes: {}",
        settled["result"].to_string().len()
    );
}

/// C0 (replay-cache arm, `/mcp`): is a final answer that carries a sealed
/// question cached, so a keyed repeat replays it? The SLOT.8 cache rows need
/// such a carrier; if none is cached, the arm is recorded unreachable with
/// this row as the proof.
#[tokio::test]
async fn c0_a_keyed_playbook_call_on_mcp_replays_its_sealed_question_from_the_cache() {
    let mock = MockBackend::answering(Answer::Sequence(vec![ask("confirm", STATE_1), done()]));
    let (state, _dir) = state_with(&mock).await;
    state.meta_mcp.set_playbook_engine(asking_playbook());
    let call = || {
        keyed(
            declaring_elicitation(modern(
                1,
                "tools/call",
                json!({ "name": "gateway_run_playbook", "arguments": { "name": "ask-once" } }),
                true,
            )),
            "c0-cache",
        )
    };
    let first = post(&state, "key-a", call()).await;
    let replay = post(&state, "key-a", call()).await;
    std::assert!(
        !sealed_in(&state, &first).is_empty(),
        "the first answer carries no question: {first}"
    );
    std::assert!(
        !sealed_in(&state, &replay).is_empty(),
        "the replay carries no question: {replay}"
    );
    std::assert_eq!(
        mock.calls(),
        1,
        "the repeat was served from the cache, not dispatched again"
    );
}

/// B8: a `tasks/get` whose delivery record the log refuses (fail-closed)
/// withholds the result, so it hands nothing off. The stored task still owns
/// the slot and keeps it; the slot is given back when the task expires unread.
#[tokio::test]
async fn b8_a_refused_tasks_get_leaves_the_slot_with_its_task() {
    let dir = tempfile::tempdir().expect("a private log directory");
    let log = crate::gateway::meta_mcp::grant_audit_fixture::logger(
        &dir,
        crate::security::audit::AuditFailurePolicy::FailClosed,
    );
    let sink = Arc::clone(&log);
    let (state, _store) = super::super::meta_fixture::test_router_app_state_with_meta(
        &two_principal_auth(),
        None,
        move |mut meta| {
            meta.enable_transparency_log(sink);
            meta
        },
    )
    .await;
    let mock = MockBackend::answering(Answer::Sequence(vec![ask("confirm", STATE_1), done()]));
    register(&state, BACKEND, &mock);
    state.meta_mcp.set_playbook_engine(asking_playbook());
    let created = post(&state, "key-a", playbook_task_body("b8-refused-read")).await;
    let id = task_id(&created);
    let bound = tokio::time::Instant::now() + Duration::from_secs(5);
    while !settled_unread(&state, &id) && tokio::time::Instant::now() < bound {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    std::assert_eq!(held(&state).await, 1, "the completed result holds its slot");
    log.fail_next_append_of_kind_for_test("response_delivery_attempt");
    let refused = get_task(&state, "key-a", &id).await;
    std::assert_eq!(
        refused.pointer("/error/code").and_then(Value::as_i64),
        Some(-32005),
        "the read is withheld: {refused}"
    );
    std::assert_eq!(
        settles_at(&state, 1).await,
        1,
        "the stored task still owns the slot"
    );
    // Past the default 24 h task TTL on the store's clock.
    let past_ttl = crate::protocol::continuation::now_unix_secs() + 86_400 + 61;
    expire_at(&state, &id, past_ttl).await;
    std::assert_eq!(
        settles_at(&state, 0).await,
        0,
        "the unread task's expiry gives the slot back"
    );
}

/// B5: a resume cancelled while its worker is paused at `point`. The cancel
/// commits first, then the worker is released. The round's slot must end
/// given back (never kept by a cancelled task, never refused while owned).
async fn cancelled_while_resuming(
    point: crate::gateway::task_service::execution::resume_seams::ResumePoint,
) -> Option<String> {
    use crate::gateway::task_service::execution::resume_seams::pause_at_for_test;
    let (_mock, state, _dir, id) = parked_task(&format!("b5-{point:?}"), None).await;
    let pause = pause_at_for_test(point);
    let resuming = {
        let (state, id) = (Arc::clone(&state), id.clone());
        tokio::spawn(async move {
            post(
                &state,
                "key-a",
                update(2, &id, json!({ "confirm": answer() })),
            )
            .await
        })
    };
    if tokio::time::timeout(Duration::from_secs(5), pause.reached())
        .await
        .is_err()
    {
        return Some(format!("the resume worker never reached {point:?}"));
    }
    let cancelling = {
        let (state, id) = (Arc::clone(&state), id.clone());
        tokio::spawn(async move {
            post(
                &state,
                "key-a",
                task_method(3, "tasks/cancel", json!({ "taskId": id })),
            )
            .await
        })
    };
    let bound = tokio::time::Instant::now() + Duration::from_secs(5);
    let cancelled = loop {
        let status = state.task_executor.service.store.status_for_test(&id);
        if status == Some(crate::gateway::task_service::TaskStatus::Cancelled) {
            break true;
        }
        if tokio::time::Instant::now() >= bound {
            break false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    pause.release();
    drop(pause);
    let _ = resuming.await;
    let _ = cancelling.await;
    if !cancelled {
        return Some(format!(
            "the cancel never committed while the worker sat at {point:?}"
        ));
    }
    let after = settles_at(&state, 0).await;
    (after != 0).then(|| format!("cancelled at {point:?}: {after} slots still held"))
}

/// B5, both windows (red on base: a cancelled task never gives its round's
/// slot back there).
#[tokio::test]
async fn b5_a_resume_cancelled_in_either_window_gives_the_slot_back() {
    use crate::gateway::task_service::execution::resume_seams::ResumePoint;
    let mut failures = Vec::new();
    for point in [ResumePoint::Spawned, ResumePoint::BeforeRedeem] {
        if let Some(why) = cancelled_while_resuming(point).await {
            failures.push(why);
        }
    }
    std::assert!(
        failures.is_empty(),
        "B5 windows failed:\n{}",
        failures.join("\n")
    );
}
