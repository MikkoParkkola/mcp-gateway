// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8408 stage 4: the route-level guard rows of the test plan
//! (the relay replay test plan), as
//! retargeted by d4 H4: G18/G21 read the replay entry's `calls`,
//! G20 is dropped. Each row names its mutant and asserts through
//! the route (bob's relay refused or not) or, for `calls`, the
//! firewall's replay-digest seam. The rig is `relay_plan_replay`'s.
//!
//! This file holds the authorization, restart, detection-off and
//! lapse rows (G12, G46, G32, G25, G37) and the shared helpers;
//! the content rows (G1, G11/G41, G18, G21, G26, G27) are in
//! `relay_plan_replay_content_guards`.
use super::super::*;
use super::relay_plan_replay::{
    ALPHA, BETA, OTHER_PROSE, PROSE, Rig, SUGGEST, Sensitivity, WINDOW_SECS, answering, chain,
    erring_step, keyed_call, playbook, playbook_args, rig, rig_with, task_call,
};
use super::support::*;
use pretty_assertions::assert_eq;

use crate::security::firewall::{CollusionAction, CollusionConfig, Firewall, FirewallConfig};

/// [`Rig::refused`] for a bare second-gateway `state`.
pub(super) async fn probe_refused(
    state: &Arc<AppState>,
    who: &str,
    id: i64,
    relayed: &str,
) -> bool {
    let reply = post(state, who, sync_invoke(id, json!({"text": relayed}))).await;
    if reply["error"]["code"] == -32002 {
        return true;
    }
    assert!(
        reply.get("error").is_none()
            && reply.to_string().contains("ok")
            && !reply.to_string().contains(relayed),
        "a non-refused probe must succeed with the probe's answer: {reply}"
    );
    false
}

/// Alice's live `gateway_invoke` of `server:echo`: the control delivery.
pub(super) async fn live_invoke(state: &Arc<AppState>, id: i64, server: &str) -> Value {
    let call = json!({"name": "gateway_invoke",
        "arguments": {"server": server, "tool": TOOL, "arguments": {}}});
    post(state, "key-a", modern(id, "tools/call", call, false)).await
}

/// The settled row of `task` (its revision keys the replay entry, F1).
pub(super) fn committed(
    state: &Arc<AppState>,
    task: &str,
) -> crate::gateway::task_service::CommittedTask {
    state
        .tasks
        .get(&admission_principal(), task)
        .expect("stored task: fixture")
}

/// The replay store key of `task`'s settled row at `revision` (F1).
pub(super) fn task_key(task: &str, revision: u64) -> crate::security::firewall::StoredKey {
    crate::security::firewall::StoredKey::Task {
        id: task.to_owned(),
        revision,
    }
}

/// `server`'s listing no longer names its tool (MIK-8392 absent answer).
pub(super) fn delist(state: &Arc<AppState>, server: &str) {
    let other =
        json!({"name": "other", "description": "Reads.", "inputSchema": {"type": "object"}});
    let backend = state
        .backends
        .get(server)
        .expect("step backend registered: fixture");
    let _ = backend.remember_listed_tools(None, false, &[other]);
}

/// `server`'s listing names its tool again (undoes [`delist`]).
pub(super) fn relist(state: &Arc<AppState>, server: &str) {
    let tool = json!({"name": TOOL, "description": "Reads.", "inputSchema": {"type": "object"}});
    let backend = state
        .backends
        .get(server)
        .expect("step backend registered: fixture");
    let _ = backend.remember_listed_tools(None, false, &[tool]);
}

/// The three principals, each allowed alpha and beta beside the probe.
pub(super) fn plan_auth() -> AuthConfig {
    let mut auth = three_principal_auth();
    for key in &mut auth.api_keys {
        key.backends.extend([ALPHA.to_string(), BETA.to_string()]);
    }
    auth
}

/// A gateway with no firewall (relay detection off) over the shared
/// step mocks, with G25's playbook registered: the first gateway of
/// G25-T/H.
async fn off_gateway(
    alpha: &Arc<MockBackend>,
    beta: &Arc<MockBackend>,
) -> (Arc<AppState>, crate::gateway::router::tests::FixtureDir) {
    let (state, store) = super::super::meta_fixture::test_router_app_state_with_meta_and_firewall(
        &plan_auth(),
        None,
        None,
        |meta| {
            let definition: crate::playbook::PlaybookDefinition =
                crate::yaml::from_str(&playbook()).expect("playbook fixture must parse");
            let mut engine = crate::playbook::PlaybookEngine::new();
            engine.register(definition);
            meta.set_playbook_engine(engine);
            meta
        },
    )
    .await;
    register(&state, BACKEND, &answering("ok"));
    register(&state, ALPHA, alpha);
    register(&state, BETA, beta);
    (state, store)
}

/// G25-H's detection-on gateway over `off`'s admission, with its
/// freshly keyed relay firewall and the playbook registered, and
/// the probe and step backends registered.
async fn on_gateway_over_off(
    off: &Arc<AppState>,
    alpha: &Arc<MockBackend>,
    beta: &Arc<MockBackend>,
) -> (Arc<AppState>, crate::gateway::router::tests::FixtureDir) {
    let relay_fw = Arc::new(
        Firewall::from_config(
            FirewallConfig {
                collusion: CollusionConfig {
                    action: CollusionAction::Block,
                    min_matches: 1,
                    sources: vec![format!("{ALPHA}:*"), format!("{BETA}:*")],
                    window_secs: WINDOW_SECS,
                    ..CollusionConfig::default()
                },
                ..FirewallConfig::default()
            },
            None,
        )
        .keyed_for_test()
        .keeping_every_kgram(),
    );
    relay_fw.advance_collusion_clock_for_test(std::time::Duration::ZERO);
    let admission = Arc::clone(off.meta_mcp.execution_admission());
    let handle = Arc::clone(&relay_fw);
    let (on, on_store) = super::super::meta_fixture::test_router_app_state_with_meta_and_firewall(
        &plan_auth(),
        None,
        None,
        move |mut meta| {
            meta.share_execution_admission_for_test(admission);
            meta.share_keyring_with_for_test(&handle);
            meta.set_firewall(Some(handle));
            let definition: crate::playbook::PlaybookDefinition =
                crate::yaml::from_str(&playbook()).expect("playbook fixture must parse");
            let mut engine = crate::playbook::PlaybookEngine::new();
            engine.register(definition);
            meta.set_playbook_engine(engine);
            meta
        },
    )
    .await;
    register(&on, BACKEND, &answering("ok"));
    register(&on, ALPHA, alpha);
    register(&on, BETA, beta);
    (on, on_store)
}

/// The second rig's gateway (fresh firewall/store) reopened over
/// `tasks_dir`, whose first custodian was dropped: G32's restart
/// and G25-T's reopen, by `state_with_record_budget`'s runtime swap.
/// The custody lease frees with the old state, so the open retries.
pub(super) async fn state_over_tasks(second: Rig, tasks_dir: std::path::PathBuf) -> Arc<AppState> {
    let Rig { state, .. } = second;
    let mut app = Arc::try_unwrap(state).unwrap_or_else(|_| panic!("fixture state is exclusive"));
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    let runtime = loop {
        let opened = crate::gateway::task_service::open_runtime_with_admission(
            &tasks_dir,
            crate::config::TasksConfig::default().max_workers,
            crate::gateway::task_service::StoreLimits::default(),
            Arc::clone(&app.subscriptions),
            Arc::clone(app.meta_mcp.execution_admission()),
        )
        .await;
        match opened {
            Ok(runtime) => break runtime,
            Err(e) if tokio::time::Instant::now() < deadline => {
                let _ = e;
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            Err(e) => panic!(
                "the task store at {} could not be reopened: {e:?}",
                tasks_dir.display()
            ),
        }
    };
    (app.tasks, app.task_executor) = runtime;
    Arc::new(app)
}

/// The shared tail of G32 and G25-T: on the reopened `on`, alice's
/// re-read of `task` still serves its stored answer and renews
/// nothing, counted absent, while a live delivery receipts (control).
pub(super) async fn renews_nothing_after_reopen(on: &Arc<AppState>, task: &str, id: i64) {
    let measured = get_task(on, "key-a", task);
    #[cfg(feature = "metrics")]
    let (read, absent) = crate::gateway::count_plan_replay_skipped("absent", measured);
    #[cfg(not(feature = "metrics"))]
    let read = measured.await;
    assert_eq!(status_of(&read), "completed", "base: {read}");
    assert!(
        read.to_string().contains(PROSE),
        "premise: the stored answer serves: {read}"
    );
    assert!(
        !probe_refused(on, "key-b", id, PROSE).await,
        "the re-read renewed a receipt the gateway never held"
    );
    #[cfg(feature = "metrics")]
    assert_eq!(
        absent, 1,
        "not counted exactly once reason=absent for the one absent lookup"
    );
    let live = live_invoke(on, id + 1, ALPHA).await;
    assert!(
        live.get("error").is_none(),
        "control premise: live delivery succeeds: {live}"
    );
    assert!(
        probe_refused(on, "key-b", id + 2, PROSE).await,
        "control: it receipts its own deliveries"
    );
}

/// G37 (T): two re-reads past two lapses both renew (F2's fresh digest).
/// Mutant: one-shot replay.
#[tokio::test]
async fn g37_two_rereads_past_two_lapses_both_renew() {
    let rig = rig(PROSE, OTHER_PROSE, None).await;
    let task = rig.settle_task("g37", "gateway_execute", chain()).await;
    for round in 0_i64..2 {
        assert!(
            rig.refused("key-b", 370 + round * 10, PROSE).await,
            "P0 round {round}: live receipt holds"
        );
        rig.lapse().await;
        assert!(
            !rig.refused("key-b", 371 + round * 10, PROSE).await,
            "P1 round {round}: lapsed"
        );
        let before = rig.calls();
        let read = get_task(&rig.state, "key-a", &task).await;
        assert_eq!(status_of(&read), "completed", "base: {read}");
        assert_eq!(rig.calls(), before, "P2: nothing ran again");
        assert!(
            rig.refused("key-b", 372 + round * 10, PROSE).await,
            "re-read {round} renewed nothing"
        );
    }
}

/// G12 (T): carol's unauthorized `tasks/get` of alice's plan task is
/// refused before staging; had it staged for her, bob would meet her
/// live witness. Alice's re-read alongside renews (control). The
/// staging seam records only the direct route, so the empty staging
/// is read through its route consequence: no renewal.
/// Mutant: stage before the gate.
#[tokio::test]
async fn g12_an_unauthorized_task_reread_stages_nothing() {
    let rig = rig(PROSE, OTHER_PROSE, None).await;
    let task = rig.settle_task("g12-t", "gateway_execute", chain()).await;
    rig.lapse().await;
    assert!(!rig.refused("key-b", 120, PROSE).await, "P1: lapsed");
    let refused = get_task(&rig.state, "key-c", &task).await;
    assert!(
        refused.get("error").is_some() && !refused.to_string().contains(PROSE),
        "premise: carol's read is refused, output withheld: {refused}"
    );
    assert!(
        !rig.refused("key-b", 121, PROSE).await,
        "the unauthorized re-read staged a receipt"
    );
    let read = get_task(&rig.state, "key-a", &task).await;
    assert_eq!(status_of(&read), "completed", "base: {read}");
    assert!(
        rig.refused("key-b", 122, PROSE).await,
        "positive control: the owner's re-read renews"
    );
}

/// G12 (H): alice's key repeated over a different chain is an admission
/// refusal and renews nothing; her faithful repeat renews (control).
/// Mutant: stage before the gate.
#[tokio::test]
async fn g12_a_sync_admission_refusal_stages_nothing() {
    let rig = rig(PROSE, OTHER_PROSE, None).await;
    let first = post(
        &rig.state,
        "key-a",
        keyed_call(1, "g12-h", "gateway_execute", &chain()),
    )
    .await;
    assert!(first.get("error").is_none(), "base: delivered: {first}");
    assert_eq!(rig.calls(), (1, 1), "premise: both steps dispatched");
    rig.lapse().await;
    assert!(!rig.refused("key-b", 130, PROSE).await, "P1: lapsed");
    let other = json!({"chain": [{"tool": format!("{BETA}:{TOOL}"), "arguments": {}},
                                 {"tool": format!("{ALPHA}:{TOOL}"), "arguments": {}}]});
    let conflict = post(
        &rig.state,
        "key-a",
        keyed_call(2, "g12-h", "gateway_execute", &other),
    )
    .await;
    assert!(
        conflict.get("error").is_some(),
        "premise: same key, other operation refused: {conflict}"
    );
    assert_eq!(
        rig.calls(),
        (1, 1),
        "premise: the refusal dispatched nothing"
    );
    assert!(
        !rig.refused("key-b", 131, PROSE).await,
        "the admission refusal staged a receipt"
    );
    let replay = post(
        &rig.state,
        "key-a",
        keyed_call(3, "g12-h", "gateway_execute", &chain()),
    )
    .await;
    assert_eq!(
        replay["result"], first["result"],
        "control premise: retained answer served"
    );
    assert!(
        rig.refused("key-b", 132, PROSE).await,
        "positive control: the admitted replay renews"
    );
}

/// G46 (T): once alpha's listing lacks its tool, alice's own re-read
/// answers absent (MIK-8392, -32601) and stages nothing; the same
/// re-read before the delist renews (control, first lapse).
/// Mutant: stage before the gate.
#[tokio::test]
async fn g46_a_stored_read_refusal_stages_nothing() {
    let rig = rig(PROSE, OTHER_PROSE, None).await;
    let task = rig.settle_task("g46", "gateway_execute", chain()).await;
    rig.lapse().await;
    let control = get_task(&rig.state, "key-a", &task).await;
    assert_eq!(status_of(&control), "completed", "base: {control}");
    assert!(
        rig.refused("key-b", 460, PROSE).await,
        "positive control: authorized re-read renews"
    );
    rig.lapse().await;
    assert!(!rig.refused("key-b", 461, PROSE).await, "P1: lapsed again");
    delist(&rig.state, ALPHA);
    let refused = get_task(&rig.state, "key-a", &task).await;
    assert_eq!(
        refused.pointer("/error/code"),
        Some(&json!(-32601)),
        "premise: absent answer: {refused}"
    );
    assert!(
        !refused.to_string().contains(PROSE),
        "premise: no output delivered: {refused}"
    );
    assert!(
        !rig.refused("key-b", 462, PROSE).await,
        "the refused plan replay staged a receipt"
    );
}

/// G46b (absent): staging before the authorization gate is observable
/// through the replay-skip counter. With the task's replay entry
/// removed, alice's refused re-read (the MIK-8392 delist refusal of
/// G46) counts `absent == 0` exactly: no lookup ran on the refused
/// read. Mutant (planted bug) killed: "stage before the gate inside
/// `refuse_stored`" — a call to `stage_stored_receipt` at the top of
/// `refuse_stored` would look the entry up on the refused read and
/// count `absent == 1`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g46b_a_refused_read_with_an_absent_entry_counts_no_absent_lookup() {
    let rig = rig(PROSE, OTHER_PROSE, None).await;
    let task = rig.settle_task("g46b-a", "gateway_execute", chain()).await;
    let row = committed(&rig.state, &task);
    assert!(
        rig.relay
            .replay_digests(&task_key(&task, row.revision))
            .is_some(),
        "premise: the settled task captured a replay entry"
    );
    rig.relay.remove_replay(&task_key(&task, row.revision));
    delist(&rig.state, ALPHA);
    let measured = get_task(&rig.state, "key-a", &task);
    #[cfg(feature = "metrics")]
    let (refused, absent) = crate::gateway::count_plan_replay_skipped("absent", measured);
    #[cfg(not(feature = "metrics"))]
    let refused = measured.await;
    assert_eq!(
        refused.pointer("/error/code"),
        Some(&json!(-32601)),
        "premise: absent answer, read refused before staging: {refused}"
    );
    #[cfg(feature = "metrics")]
    assert_eq!(
        absent, 0,
        "the refused read looked up a replay entry: staging ran before the gate"
    );
}

/// G46b (expired): the same refused read with the task's replay entry
/// expired counts `expired == 0` exactly and leaves the entry in
/// place (expiry is lazy, on an authorized lookup): alice's later
/// authorized re-read of the same task counts `expired == 1`
/// exactly, and renews nothing. Mutant (planted bug) killed: "stage
/// before the gate inside `refuse_stored`" — a call to
/// `stage_stored_receipt` at the top of `refuse_stored` would count
/// the expiry on the refused read and evict the entry there, so the
/// authorized read would count `absent`, not `expired == 1`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g46b_a_refused_read_with_an_expired_entry_leaves_it_for_the_authorized_read() {
    let rig = rig(PROSE, OTHER_PROSE, None).await;
    let task = rig.settle_task("g46b-x", "gateway_execute", chain()).await;
    let row = committed(&rig.state, &task);
    assert_eq!(
        row.task.ttl_ms(),
        Some(86_400_000),
        "premise: the row's TTL is the entry's 24 h retention"
    );
    assert!(
        rig.relay
            .replay_digests(&task_key(&task, row.revision))
            .is_some(),
        "premise: the settled task captured a replay entry"
    );
    rig.relay
        .advance_collusion_clock_for_test(std::time::Duration::from_secs(86_400 + 1));
    delist(&rig.state, ALPHA);
    let measured = get_task(&rig.state, "key-a", &task);
    #[cfg(feature = "metrics")]
    let (refused, expired) = crate::gateway::count_plan_replay_skipped("expired", measured);
    #[cfg(not(feature = "metrics"))]
    let refused = measured.await;
    assert_eq!(
        refused.pointer("/error/code"),
        Some(&json!(-32601)),
        "premise: absent answer, read refused before staging: {refused}"
    );
    #[cfg(feature = "metrics")]
    assert_eq!(
        expired, 0,
        "the refused read judged the entry expired: staging ran before the gate"
    );
    relist(&rig.state, ALPHA);
    let measured = get_task(&rig.state, "key-a", &task);
    #[cfg(feature = "metrics")]
    let (read, expired) = crate::gateway::count_plan_replay_skipped("expired", measured);
    #[cfg(not(feature = "metrics"))]
    let read = measured.await;
    assert_eq!(status_of(&read), "completed", "base: {read}");
    assert!(
        read.to_string().contains(PROSE),
        "premise: the authorized re-read serves the stored answer: {read}"
    );
    #[cfg(feature = "metrics")]
    assert_eq!(
        expired, 1,
        "the authorized re-read did not count the lazy expiry exactly once"
    );
    assert!(
        !rig.refused("key-b", 463, PROSE).await,
        "the expired entry renewed a receipt"
    );
}

/// G32 (T): a fresh firewall over the same task store (a restart)
/// stages nothing on re-read, counted absent; the entry died with
/// the first process.
/// Mutant: re-derive when absent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g32_a_restarted_gateway_stages_nothing_counted_absent() {
    let first = rig(PROSE, OTHER_PROSE, None).await;
    let task = first.settle_task("g32", "gateway_execute", chain()).await;
    assert!(
        first.refused("key-b", 320, PROSE).await,
        "P0: live receipt holds"
    );
    let Rig {
        state: first_state,
        _store: first_store,
        ..
    } = first;
    let tasks_dir = first_store.path().join("tasks");
    drop(first_state);
    let restarted = state_over_tasks(rig(PROSE, OTHER_PROSE, None).await, tasks_dir).await;
    renews_nothing_after_reopen(&restarted, &task, 321).await;
}

/// G25 (T): a plan task delivered with detection off renews nothing
/// when the store is reopened with detection on, counted absent, and
/// no gateway text in its stored answer is receipted: beta's step
/// answers the parameter-style tool error R9 uses, so the stored
/// answer carries the gateway's [`SUGGEST`] advice (premise).
/// Mutants: open the provenance scope only when relay is active; no
/// gateway-writes scope with detection off.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g25_a_detection_off_plan_task_renews_nothing_once_detection_is_on() {
    let alpha = answering(PROSE);
    let beta = erring_step();
    let (off, off_store) = off_gateway(&alpha, &beta).await;
    let created = post(
        &off,
        "key-a",
        task_call(1, "g25-t", "gateway_run_playbook", &playbook_args()),
    )
    .await;
    let task = task_id(&created);
    let settled = poll_until_terminal(&off, "key-a", &task).await;
    assert_eq!(status_of(&settled), "completed", "premise: {settled}");
    assert!(
        settled.to_string().contains(SUGGEST),
        "premise: stored answer carries the gateway's advice: {settled}"
    );
    assert_eq!(
        (alpha.calls(), beta.calls()),
        (1, 1),
        "premise: dispatched, detection off"
    );
    let joined = off
        .task_executor
        .drain(std::time::Duration::from_secs(10))
        .await;
    assert!(joined.is_clean(), "the workers must finish: {joined:?}");
    let tasks_dir = off_store.path().join("tasks");
    drop(off);
    let on = state_over_tasks(rig(PROSE, OTHER_PROSE, Some(&playbook())).await, tasks_dir).await;
    renews_nothing_after_reopen(&on, &task, 250).await;
    assert!(
        !probe_refused(&on, "key-b", 253, SUGGEST).await,
        "the re-read receipted the gateway's own advice"
    );
}

/// G25 (H): a keyed plan delivered with detection off, replayed once
/// the firewall is swapped on over the same admission, renews
/// nothing, counted absent, and receipts no gateway text: the stored
/// answer carries [`SUGGEST`] (premise, as G25-T). Mutants: as G25-T.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g25_a_detection_off_keyed_plan_renews_nothing_once_detection_is_on() {
    let alpha = answering(PROSE);
    let beta = erring_step();
    let (off, _off_store) = off_gateway(&alpha, &beta).await;
    let first = post(
        &off,
        "key-a",
        keyed_call(1, "g25-h", "gateway_run_playbook", &playbook_args()),
    )
    .await;
    assert!(first.get("error").is_none(), "base: delivered: {first}");
    assert!(
        first.to_string().contains(SUGGEST),
        "premise: stored answer carries the gateway's advice: {first}"
    );
    assert_eq!(
        (alpha.calls(), beta.calls()),
        (1, 1),
        "premise: dispatched, detection off"
    );
    let (on, _on_store) = on_gateway_over_off(&off, &alpha, &beta).await;
    let measured = post(
        &on,
        "key-a",
        keyed_call(2, "g25-h", "gateway_run_playbook", &playbook_args()),
    );
    #[cfg(feature = "metrics")]
    let (replay, absent) = crate::gateway::count_plan_replay_skipped("absent", measured);
    #[cfg(not(feature = "metrics"))]
    let replay = measured.await;
    assert_eq!(
        replay["result"], first["result"],
        "premise: retained answer replayed unchanged"
    );
    assert_eq!(
        (alpha.calls(), beta.calls()),
        (1, 1),
        "P2: the replay dispatched nothing"
    );
    assert!(
        !probe_refused(&on, "key-b", 253, PROSE).await,
        "renewed a detection-off plan (step A)"
    );
    assert!(
        !probe_refused(&on, "key-b", 254, OTHER_PROSE).await,
        "renewed a detection-off plan (step B)"
    );
    assert!(
        !probe_refused(&on, "key-b", 257, SUGGEST).await,
        "the replay receipted the gateway's own advice"
    );
    #[cfg(feature = "metrics")]
    assert_eq!(
        absent, 1,
        "not counted exactly once reason=absent for the one absent lookup"
    );
    let live = live_invoke(&on, 255, ALPHA).await;
    assert!(
        live.get("error").is_none(),
        "control premise: live delivery succeeds: {live}"
    );
    assert!(
        probe_refused(&on, "key-b", 256, PROSE).await,
        "control: it receipts its own deliveries"
    );
}

/// R7b (REPLAY.5, found in the final review round): a plan whose steps
/// all run on ONE distinct target. `Record.targets` is deduplicated, so
/// the task records a single target, but it is still a plan: a re-read
/// must replay its per-step snapshots, not stage the stored plan output
/// as one single-target receipt. No `sources` rule: step A is sensitive
/// only by its context-integrity verdict, which the playbook's output
/// mapping drops (premise). The re-read still renews A's receipt as
/// sensitive.
/// Mutant killed: route a completed task by its target count (a plan
/// on one distinct target takes the single-target arm and renews
/// nothing).
#[tokio::test]
async fn r7b_a_one_target_playbook_still_renews_its_verdict_sensitive_step() {
    let classified = format!("{PROSE} Contact: keeper@orchardcoop.fi");
    let playbook = format!(
        "name: replay\ndescription: plan steps\non_error: continue\ninputs: {{}}\nsteps:\n\
         \x20 - name: s1\n    server: {ALPHA}\n    tool: {TOOL}\n\
         \x20 - name: s2\n    server: {ALPHA}\n    tool: {TOOL}\n\
         output:\n  type: object\n  properties:\n\
         \x20   a:\n      path: $s1.content[0].text\n"
    );
    let rig = rig_with(
        &classified,
        OTHER_PROSE,
        Some(&playbook),
        Sensitivity::Verdict,
    )
    .await;
    // Settled here, not by `Rig::settle_task`, whose premise is one call
    // on each of alpha and beta.
    let created = post(
        &rig.state,
        "key-a",
        task_call(1, "r7b", "gateway_run_playbook", &playbook_args()),
    )
    .await;
    let task = task_id(&created);
    let settled = poll_until_terminal(&rig.state, "key-a", &task).await;
    assert_eq!(status_of(&settled), "completed", "base: {settled}");
    let joined = rig
        .state
        .task_executor
        .drain(std::time::Duration::from_secs(10))
        .await;
    assert!(
        joined.is_clean(),
        "the settling worker must finish: {joined:?}"
    );
    assert_eq!(rig.calls(), (2, 0), "premise: both steps ran on alpha");
    let targets = rig
        .state
        .task_executor
        .service
        .store
        .targets_for_test(&task)
        .len();
    assert_eq!(targets, 1, "premise: the plan records ONE distinct target");
    let shown = get_task(&rig.state, "key-a", &task).await.to_string();
    assert!(
        shown.contains("orchardcoop") && !shown.contains("personal_data"),
        "premise: the stored output carries A's text but not the step's verdict: {shown}"
    );
    rig.renews_after(&[&classified], None, get_task(&rig.state, "key-a", &task))
        .await;
}

/// G49 (REPLAY.4, NFR.WORKLOAD.1; final review round): a multi-step
/// replay parses, hashes and fingerprints the delivered answer once per
/// delivery, not once per replayed step. Measured as the bytes one task
/// re-read allocates, process-wide in an isolated child: the same 64 KiB
/// plan answer re-read as a 4-step chain allocates under twice what it
/// allocates as a 1-step chain. Per-step re-parsing measured 4.4x on the
/// base (GitHub run 39410318997); once per delivery measured 1.36x.
/// Mutant killed: keep each replayed digest against a freshly parsed
/// answer (the per-step `delivery_parts` / hash / k-gram build).
#[test]
fn g49_a_multi_step_replay_parses_the_answer_once() {
    use crate::gateway::server::signing_allocation_tests::alloc_meter::{
        isolate, measure_async_process_wide,
    };
    let path = {
        let m = module_path!();
        let m = m.split_once("::").map_or(m, |(_c, rest)| rest);
        format!("{m}::g49_a_multi_step_replay_parses_the_answer_once")
    };
    if isolate(&path) {
        return;
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a test runtime builds: fixture");
    let bytes_for = |steps: usize| {
        rt.block_on(async {
            let unit = "The orchard ledger records seven rows of late pears and the grafting dates. ";
            let size = 64 * 1024 / steps;
            let text = unit.repeat(size / unit.len() + 1)[..size].to_owned();
            let rig = rig(&text, &text, None).await;
            let chain = json!({"chain": (0..steps)
                .map(|i| json!({"tool": format!("{}:{TOOL}", if i % 2 == 0 { ALPHA } else { BETA }), "arguments": {}}))
                .collect::<Vec<_>>()});
            let created = post(&rig.state, "key-a", task_call(1, "g49", "gateway_execute", &chain)).await;
            let task = task_id(&created);
            let settled = poll_until_terminal(&rig.state, "key-a", &task).await;
            assert_eq!(status_of(&settled), "completed", "base: {settled}");
            let joined = rig
                .state
                .task_executor
                .drain(std::time::Duration::from_secs(30))
                .await;
            assert!(joined.is_clean(), "the settling worker must finish: {joined:?}");
            assert!(
                (0..16u64).any(|r| rig.relay.replay_digests(&task_key(&task, r)).is_some()),
                "premise: the plan's replay entry was stored, so the re-read replays it"
            );
            let warm = get_task(&rig.state, "key-a", &task).await;
            assert!(warm.get("error").is_none(), "premise: the re-read serves: {warm}");
            let (read, measured) =
                measure_async_process_wide(|| get_task(&rig.state, "key-a", &task)).await;
            assert_eq!(
                read["result"].to_string().len(),
                warm["result"].to_string().len(),
                "premise: the measured re-read returned the stored answer: {read}"
            );
            measured.bytes
        })
    };
    let one = bytes_for(1);
    let four = bytes_for(4);
    assert!(
        four < 2 * one,
        "a 4-step replay allocated {four} B against {one} B for 1 step: the delivered answer is re-parsed per step"
    );
}
