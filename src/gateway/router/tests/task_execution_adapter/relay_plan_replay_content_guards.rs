// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8408 stage 4: the content guard rows of the test plan
//! (the relay replay test plan): what a
//! replay does with a stored answer's content (G1, G11/G41, G18,
//! G21, G26, G27). Split from `relay_plan_replay_guards`, whose
//! shared helpers these rows reuse. The rig is
//! `relay_plan_replay`'s.
use super::super::*;
use super::relay_plan_replay::{
    ALPHA, BETA, OTHER_PROSE, PROSE, Rig, SUGGEST, Sensitivity, answering, chain, erring_step,
    keyed_call, playbook, playbook_args, rig, rig_with_mocks, task_call, text,
};
use super::relay_plan_replay_guards::{committed, live_invoke, plan_auth, probe_refused, task_key};
use super::support::*;
use pretty_assertions::assert_eq;

use crate::security::firewall::{Firewall, FirewallAction, FirewallConfig, FirewallRule};

/// G1's rig: the `on_error: continue` playbook over alpha delivering
/// sensitive [`PROSE`] and beta answering the parameter-style tool
/// error R9 uses, so the gateway writes [`SUGGEST`] into beta's step
/// result and the stored answer carries it (asserted as a premise by
/// each row, R9's style). Every k-gram is kept (`min_matches: 1`), so
/// the 77-char advice flags whenever receipted (test plan §10).
async fn suggest_rig() -> Rig {
    rig_with_mocks(
        answering(PROSE),
        erring_step(),
        Some(&playbook()),
        Sensitivity::Rule,
    )
    .await
}

/// G1's control: `text` as alpha's backend text on a fresh rig flags.
async fn flags_as_backend_text(text: &str) {
    let control = rig(text, OTHER_PROSE, None).await;
    let delivered = live_invoke(&control.state, 10, ALPHA).await;
    assert!(
        delivered.get("error").is_none() && delivered.to_string().contains(text),
        "control premise: alice delivered the text as backend text: {delivered}"
    );
    assert!(
        control.refused("key-b", 11, text).await,
        "control: identical string as backend text flags"
    );
}

/// G1's shared tail: live and after `reread`, alpha's text is refused
/// for bob and the gateway's own advice never is.
async fn gateway_text_never_receipted(
    rig: &Rig,
    text: &str,
    advice: &str,
    base: i64,
    reread: impl std::future::Future<Output = Value>,
) {
    assert!(
        rig.refused("key-b", base, text).await,
        "P0: live receipt holds for alpha's text"
    );
    assert!(
        !rig.refused("key-b", base + 1, advice).await,
        "premise: live receipt never held the advice"
    );
    rig.lapse().await;
    assert!(!rig.refused("key-b", base + 2, text).await, "P1: lapsed");
    let read = reread.await;
    assert!(
        read.get("error").is_none(),
        "base: the re-read is served: {read}"
    );
    assert!(
        rig.refused("key-b", base + 3, text).await,
        "control: the re-read renewed alpha's text"
    );
    assert!(
        !rig.refused("key-b", base + 4, advice).await,
        "the replay receipted the gateway's own advice"
    );
}

/// G1 (T): the gateway's own advice in a step's stored result is never
/// receipted on a task re-read; the identical string as backend text
/// flags (control rig), and alpha's prose renews as usual.
/// Mutant: snapshot built from the stored answer.
#[tokio::test]
async fn g1_a_task_reread_never_receipts_the_gateways_own_advice() {
    let rig = suggest_rig().await;
    let task = rig
        .settle_task("g1-t", "gateway_run_playbook", playbook_args())
        .await;
    let shown = get_task(&rig.state, "key-a", &task).await;
    assert!(
        shown.to_string().contains(PROSE),
        "premise: stored answer carries alpha's text: {shown}"
    );
    assert!(
        shown.to_string().contains(SUGGEST),
        "premise: stored answer carries the gateway's advice: {shown}"
    );
    flags_as_backend_text(SUGGEST).await;
    gateway_text_never_receipted(
        &rig,
        PROSE,
        SUGGEST,
        10,
        get_task(&rig.state, "key-a", &task),
    )
    .await;
}

/// G1 (H): the same on a keyed synchronous playbook replay.
/// Mutant: snapshot built from the stored answer.
#[tokio::test]
async fn g1_a_keyed_replay_never_receipts_the_gateways_own_advice() {
    let rig = suggest_rig().await;
    let first = post(
        &rig.state,
        "key-a",
        keyed_call(1, "g1-h", "gateway_run_playbook", &playbook_args()),
    )
    .await;
    assert!(first.get("error").is_none(), "base: delivered: {first}");
    assert!(
        first.to_string().contains(SUGGEST),
        "premise: stored answer carries the gateway's advice: {first}"
    );
    flags_as_backend_text(SUGGEST).await;
    let replay = post(
        &rig.state,
        "key-a",
        keyed_call(2, "g1-h", "gateway_run_playbook", &playbook_args()),
    );
    gateway_text_never_receipted(&rig, PROSE, SUGGEST, 20, async move {
        let replay = replay.await;
        assert_eq!(
            replay["result"], first["result"],
            "P2: retained result unchanged"
        );
        replay
    })
    .await;
    assert_eq!(rig.calls(), (1, 1), "P2: nothing ran again");
}

/// G18 (T, d4 H4): a chain pausing at step 1 then resuming lists
/// only the final round's call (label 1, beta) in the entry's
/// `calls`; the final answer carries only step 1's text, so the
/// re-read renews step 1 and stages nothing under label 0.
/// Mutant: stage under label 0 from the final answer.
#[tokio::test]
async fn g18_a_resumed_chain_lists_the_final_rounds_call_and_stages_nothing_under_step_0() {
    let beta = MockBackend::answering(Answer::Sequence(vec![
        super::input_round::ask("confirm", super::input_round::STATE_1),
        text(OTHER_PROSE),
    ]));
    let rig = rig_with_mocks(answering(PROSE), beta, None, Sensitivity::Rule).await;
    let created = post(
        &rig.state,
        "key-a",
        declaring_elicitation(task_call(1, "g18", "gateway_execute", &chain())),
    )
    .await;
    let task = task_id(&created);
    super::input_round::wait_input_required(&rig.state, &task).await;
    assert_eq!(rig.calls(), (1, 1), "premise: step 0 ran, step 1 asked");
    let acked = post(
        &rig.state,
        "key-a",
        super::input_round::update(2, &task, json!({"confirm": super::input_round::answer()})),
    )
    .await;
    assert!(
        acked.get("error").is_none(),
        "premise: answer accepted: {acked}"
    );
    let settled = poll_until_terminal(&rig.state, "key-a", &task).await;
    assert_eq!(status_of(&settled), "completed", "base: {settled}");
    assert!(
        settled.to_string().contains(OTHER_PROSE) && !settled.to_string().contains(PROSE),
        "premise: final answer carries step 1's text, not step 0's: {settled}"
    );
    assert_eq!(rig.calls(), (1, 2), "premise: resume re-ran step 1 only");
    rig.lapse().await;
    let stored = committed(&rig.state, &task);
    let (digests, calls) = rig
        .relay
        .replay_digests(&task_key(&task, stored.revision))
        .expect("the settled plan has a replay entry: fixture");
    assert!(
        calls.contains(&(Some(1), BETA.to_string(), TOOL.to_string())),
        "entry calls do not list {BETA}: {calls:?}"
    );
    assert!(
        digests.iter().all(|e| e.label != Some(0)),
        "premise: no digest carries label 0"
    );
    assert!(!rig.refused("key-b", 180, OTHER_PROSE).await, "P1: lapsed");
    let read = get_task(&rig.state, "key-a", &task).await;
    assert_eq!(status_of(&read), "completed", "base: {read}");
    assert!(
        rig.refused("key-b", 181, OTHER_PROSE).await,
        "control: resumed step renewed"
    );
    assert!(
        !rig.refused("key-b", 182, PROSE).await,
        "replay staged label 0 for undelivered text"
    );
}

/// G21 (T, d4 H4): playbook `on_error: continue`, B's tool reports an
/// error. `calls` holds B, and replay copies live for B exactly
/// (d4: replay copies live, never more): bob relaying B's text
/// meets the same outcome after the lapse and re-read as while
/// the live receipt held. A's text renews as before.
/// Mutant: note only on success.
#[tokio::test]
async fn g21_a_failed_playbook_step_is_listed_and_replays_as_live() {
    let failing = MockBackend::answering(Answer::Sequence(vec![json!({
        "content": [{"type": "text", "text": OTHER_PROSE}], "isError": true})]));
    let rig = rig_with_mocks(
        answering(PROSE),
        failing,
        Some(&playbook()),
        Sensitivity::Rule,
    )
    .await;
    let task = rig
        .settle_task("g21", "gateway_run_playbook", playbook_args())
        .await;
    let shown = get_task(&rig.state, "key-a", &task).await.to_string();
    assert!(
        shown.contains("steps_failed") && shown.contains("s2"),
        "premise: playbook carried on past the failed step: {shown}"
    );
    let live_b_refused = rig.refused("key-b", 209, OTHER_PROSE).await;
    rig.lapse().await;
    let stored = committed(&rig.state, &task);
    let (_, calls) = rig
        .relay
        .replay_digests(&task_key(&task, stored.revision))
        .expect("the settled plan has a replay entry: fixture");
    assert!(
        calls.contains(&(Some(1), BETA.to_string(), TOOL.to_string())),
        "entry calls do not hold failed step B: {calls:?}"
    );
    assert!(!rig.refused("key-b", 210, PROSE).await, "P1: lapsed");
    let read = get_task(&rig.state, "key-a", &task).await;
    assert_eq!(status_of(&read), "completed", "base: {read}");
    assert!(
        rig.refused("key-b", 211, PROSE).await,
        "control: delivered step renewed"
    );
    assert_eq!(
        rig.refused("key-b", 212, OTHER_PROSE).await,
        live_b_refused,
        "replay must equal live for failed step B"
    );
}

/// G26's playbook: step s1 on alpha, step s2 on `second`, its output
/// mapping only s1's text.
fn scoped_playbook(second: &str) -> String {
    format!(
        "name: scoped\ndescription: one reachable step, one scoped away\non_error: continue\ninputs: {{}}\nsteps:\n\
         \x20 - name: s1\n    server: {ALPHA}\n    tool: {TOOL}\n\
         \x20 - name: s2\n    server: {second}\n    tool: {TOOL}\n\
         output:\n  type: object\n  properties:\n\x20   a:\n      path: $s1.content[0].text\n"
    )
}

/// G26 (T): a playbook step refused at its own dispatch gets no
/// receipt. At submit both steps are inside alice's scope (s2 on
/// beta, so MIK-8315 admits the task); inside the task's commit
/// the playbook is swapped for the same-named one whose s2 names
/// a backend outside every caller's scope (X8's swap in
/// `settlement`), so the worker's dispatch of s2 is what refuses
/// it, before its counted mock is reached. Nothing under its name
/// in `calls` or digests, and bob succeeds for its would-be text.
/// Mutant: snapshot pre-dispatch results.
#[tokio::test]
async fn g26_a_step_refused_before_dispatch_gets_no_receipt() {
    let rig = rig(PROSE, OTHER_PROSE, Some(&scoped_playbook(BETA))).await;
    let vault = answering(OTHER_PROSE);
    register(&rig.state, FORBIDDEN_BACKEND, &vault);
    let meta = Arc::clone(&rig.state.meta_mcp);
    let swapped = std::sync::atomic::AtomicBool::new(false);
    rig.state
        .task_executor
        .barrier_on_publication(Arc::new(move || {
            if !swapped.swap(true, std::sync::atomic::Ordering::SeqCst) {
                let definition: crate::playbook::PlaybookDefinition =
                    crate::yaml::from_str(&scoped_playbook(FORBIDDEN_BACKEND))
                        .expect("playbook fixture must parse");
                let mut engine = crate::playbook::PlaybookEngine::new();
                engine.register(definition);
                meta.set_playbook_engine(engine);
            }
        }))
        .await;
    let args = json!({"name": "scoped", "arguments": {}});
    let created = post(
        &rig.state,
        "key-a",
        task_call(1, "g26", "gateway_run_playbook", &args),
    )
    .await;
    let task = task_id(&created);
    let settled = poll_until_terminal(&rig.state, "key-a", &task).await;
    assert_eq!(
        status_of(&settled),
        "completed",
        "premise: carried on past the refused step: {settled}"
    );
    rig.lapse().await;
    assert_eq!(
        vault.calls(),
        0,
        "premise: the refused step never dispatched"
    );
    assert_eq!(rig.alpha.calls(), 1, "premise: the allowed step ran");
    let stored = committed(&rig.state, &task);
    let (digests, calls) = rig
        .relay
        .replay_digests(&task_key(&task, stored.revision))
        .expect("the settled plan has a replay entry: fixture");
    assert!(
        calls.iter().all(|(_, s, _)| s != FORBIDDEN_BACKEND),
        "entry calls hold the refused step: {calls:?}"
    );
    assert!(
        digests.iter().all(|e| e.server != FORBIDDEN_BACKEND),
        "a digest is under the refused source"
    );
    let read = get_task(&rig.state, "key-a", &task).await;
    assert_eq!(status_of(&read), "completed", "base: {read}");
    assert!(
        rig.refused("key-b", 260, PROSE).await,
        "control: delivered step renewed"
    );
    assert!(
        !rig.refused("key-b", 261, OTHER_PROSE).await,
        "replay receipted the refused step's text"
    );
}

/// A database URL over 200 chars: the credential redactor's match
/// runs to the next whitespace, so redacting it removes the whole run.
fn removed_run() -> String {
    format!(
        "postgres://ledger:pw@db.local/{}",
        "orchard-archive-north-slope-pear-rows-".repeat(6)
    )
}

/// Indexed filler taking alpha's step text past the record cap
/// (6 KiB), so live retention cuts its middle and the receipt
/// carries the cut's `cut_fps` set into its replay snapshot: the
/// set F4 drops and counts against a changed replay answer.
fn over_cap_tail() -> String {
    (0..1_200)
        .map(|i| format!("row{i:04}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The router firewall of one G11 gateway: credentials allowed, and
/// redacted only when `redact` (the second gateway's tightened
/// policy). It exempts `rig`'s keyring, as startup pairs them.
fn g11_router(rig: &Rig, redact: bool) -> Arc<Firewall> {
    let keys = rig
        .relay
        .continuations_for_test()
        .expect("the relay firewall is keyed: fixture");
    Arc::new(
        Firewall::from_config(
            FirewallConfig {
                enabled: true,
                scan_responses: true,
                scan_requests: false,
                credential_redaction: redact,
                rules: vec![FirewallRule {
                    tool_match: "*".to_string(),
                    action: FirewallAction::Allow,
                    reason: None,
                    scan: Vec::new(),
                }],
                ..FirewallConfig::default()
            },
            None,
        )
        .with_continuations(keys),
    )
}

/// `rig` with the untightened router policy installed, so its first
/// delivery carries the credential run unredacted and unrefused
/// (the rig's own final check would refuse it, -32600).
fn with_unredacted_router(rig: Rig) -> Rig {
    let router_fw = g11_router(&rig, false);
    let Rig {
        state,
        _store: store,
        relay,
        alpha,
        beta,
    } = rig;
    let mut app = Arc::try_unwrap(state).unwrap_or_else(|_| panic!("fixture state is exclusive"));
    app.firewall = Some(router_fw);
    Rig {
        state: Arc::new(app),
        _store: store,
        relay,
        alpha,
        beta,
    }
}

/// G11's second gateway: `rig`'s retained answers and relay
/// firewall, with the tightened (redacting) router policy.
async fn redacting_gateway(
    rig: &Rig,
) -> (Arc<AppState>, crate::gateway::router::tests::FixtureDir) {
    let router_fw = g11_router(rig, true);
    let admission = Arc::clone(rig.state.meta_mcp.execution_admission());
    let shared = Arc::clone(&rig.relay);
    let (on, on_store) = super::super::meta_fixture::test_router_app_state_with_meta_and_firewall(
        &plan_auth(),
        None,
        Some(router_fw),
        move |mut meta| {
            meta.share_execution_admission_for_test(admission);
            meta.share_keyring_with_for_test(&shared);
            meta.set_firewall(Some(shared));
            meta
        },
    )
    .await;
    register(&on, BACKEND, &answering("ok"));
    register(&on, ALPHA, &rig.alpha);
    register(&on, BETA, &rig.beta);
    (on, on_store)
}

/// G11/G41 (H): the replay-time final check (the second gateway's
/// credential redaction, tightened since the first delivery, whose
/// gateway neither redacted nor refused credentials) removes
/// a ≥200-char run of alpha's text from the replayed answer — the
/// delivered answer differs from the stored one (premise). Alpha's
/// step text runs past the record cap, so live retention cuts its
/// middle and the stored snapshot carries the cut's `cut_fps` set
/// (premise, via the cut counter that set is counted with). Bob
/// relaying the removed run then succeeds, the kept text is refused,
/// and the filtered drop is counted `reason=filtered` (F4's counter
/// for the cut and seam-excuse sets dropped against a changed answer).
/// Mutant: skip filtering on a changed answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g11_a_replay_time_redaction_renews_only_what_it_delivers() {
    let removed = removed_run();
    assert!(
        removed.len() >= 200,
        "premise: the redacted run is ≥200 chars"
    );
    let alpha_text = format!("{PROSE} {removed} {}", over_cap_tail());
    let rig = with_unredacted_router(rig(&alpha_text, OTHER_PROSE, None).await);
    let cuts_before = rig.relay.relay_text_cuts();
    let first = post(
        &rig.state,
        "key-a",
        keyed_call(1, "g11", "gateway_execute", &chain()),
    )
    .await;
    assert!(
        first.get("error").is_none() && first.to_string().contains(&removed),
        "base: first delivery carries the run unredacted: {first}"
    );
    assert!(
        rig.relay.relay_text_cuts() > cuts_before,
        "premise: live retention cut alpha's over-cap step, so its stored snapshot carries cut_fps"
    );
    assert!(
        rig.refused("key-b", 110, &removed).await,
        "P0: live receipt holds for the run"
    );
    assert!(
        rig.refused("key-b", 111, PROSE).await,
        "P0: live receipt holds for the prose"
    );
    rig.lapse().await;
    assert!(
        !rig.refused("key-b", 112, &removed).await,
        "P1: lapsed (run)"
    );
    assert!(
        !rig.refused("key-b", 113, PROSE).await,
        "P1: lapsed (prose)"
    );

    let (on, _on_store) = redacting_gateway(&rig).await;
    let measured = post(
        &on,
        "key-a",
        keyed_call(2, "g11", "gateway_execute", &chain()),
    );
    #[cfg(feature = "metrics")]
    let (replay, filtered) = crate::gateway::count_plan_replay_skipped("filtered", measured);
    #[cfg(not(feature = "metrics"))]
    let replay = measured.await;
    assert!(replay.get("error").is_none(), "base: replayed: {replay}");
    assert_ne!(
        replay["result"], first["result"],
        "premise: stored and delivered answers differ"
    );
    assert!(
        replay.to_string().contains("orchard ledger") && !replay.to_string().contains(&removed),
        "premise: the replay delivers the prose without the redacted run: {replay}"
    );
    assert_eq!(rig.calls(), (1, 1), "P2: the replay dispatched nothing");
    assert!(
        !probe_refused(&on, "key-b", 114, &removed).await,
        "the replay renewed text it did not deliver"
    );
    assert!(
        probe_refused(&on, "key-b", 115, PROSE).await,
        "control: the delivered rest is refused"
    );
    #[cfg(feature = "metrics")]
    assert_eq!(
        filtered, 1,
        "the filtered drop was not counted exactly once reason=filtered"
    );
}

/// G11b's rig and the removed run: alpha's over-cap step text with the
/// credential run in its cut middle, and the untightened router.
async fn g11b_rig() -> (Rig, String) {
    let removed = removed_run();
    let filler = |tag: &str| {
        (0..450)
            .map(|i| format!("{tag}{i:04}"))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let alpha_text = format!("{PROSE} {} {removed} {}", filler("head"), filler("tail"));
    let at = alpha_text
        .find(&removed)
        .expect("the run is in alpha's text: fixture");
    assert!(
        at > 3 * 1024 && at + removed.len() < alpha_text.len() - 3 * 1024,
        "premise: the run lies in the cut middle, past the kept head and before the kept tail"
    );
    // Alpha answers the plan's over-cap text first, then (carol's live
    // call) a short copy of the head and the run: under the cap, so the
    // run is fingerprinted and carol is a live witness for it. An
    // over-cap copy would cut the run from her receipt too.
    let witness = format!("{PROSE} {removed}");
    let alpha = MockBackend::answering(Answer::Sequence(vec![text(&alpha_text), text(&witness)]));
    let rig = with_unredacted_router(
        rig_with_mocks(alpha, answering(OTHER_PROSE), None, Sensitivity::Rule).await,
    );
    (rig, removed)
}

/// G11b (H): as G11, but the replay-time redaction removes text only
/// from inside the live receipt's cut middle. Alpha's step text runs
/// past the record cap with the credential run past the kept head
/// (half the 6 KiB cap) and before the kept tail (premise), so the
/// stored snapshot carries the cut's `cut_fps` excuse for it (premise,
/// via the cut counter) while no kept segment holds it. Carol holds a
/// fresh whole copy after the lapse, so alice's excuse is what stands
/// between her and refusal. After the re-read on the redacting
/// gateway, alice relaying the removed middle run is refused — her
/// renewed receipt carries no excuse for text the replay did not
/// deliver — while the delivered head still renews (alice excused for
/// it, bob refused), and the filtered drop is counted exactly once.
/// Measured on 7593703a6: the old fast path (keep the snapshot whenever
/// every kept segment is present, without the `identical` gate) is
/// equivalent here, since the receipt's retained fingerprints cover the
/// cut middle, so the leaf check already fails and the filtering path
/// runs either way. That mutant is killed at unit level by
/// `d11_a_changed_answer_drops_both_excuse_sets_in_both_branches` and at
/// route level by `g11c_another_step_changing_drops_a_fully_delivered_steps_excuses`.
/// This row pins the route outcome. Mutant killed: skip filtering on a
/// changed answer (G11).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g11b_a_redaction_inside_the_cut_middle_drops_its_excuse() {
    let (rig, removed) = g11b_rig().await;
    let cuts_before = rig.relay.relay_text_cuts();
    let first = post(
        &rig.state,
        "key-a",
        keyed_call(1, "g11m", "gateway_execute", &chain()),
    )
    .await;
    assert!(
        first.get("error").is_none()
            && first.to_string().contains(&removed)
            && first.to_string().contains("tail0449"),
        "base: first delivery carries the run and the tail unredacted: {first}"
    );
    assert!(
        rig.relay.relay_text_cuts() > cuts_before,
        "premise: live retention cut alpha's over-cap step, so its stored snapshot carries cut_fps"
    );
    rig.lapse().await;
    assert!(
        !rig.refused("key-b", 120, &removed).await,
        "P1: lapsed (run)"
    );
    let carol = post(
        &rig.state,
        "key-c",
        modern(
            121,
            "tools/call",
            json!({"name": "gateway_invoke",
                   "arguments": {"server": ALPHA, "tool": TOOL, "arguments": {}}}),
            false,
        ),
    )
    .await;
    assert!(
        carol.get("error").is_none() && carol.to_string().contains(&removed),
        "premise: carol was delivered the head and the run: {carol}"
    );
    assert!(
        rig.refused("key-a", 122, &removed).await,
        "premise: carol is a live witness for the run and alice holds no live copy"
    );
    assert!(
        rig.refused("key-a", 123, PROSE).await,
        "premise: carol is a live witness for the head and alice holds no live copy"
    );

    let (on, _on_store) = redacting_gateway(&rig).await;
    let before = rig.calls();
    let measured = post(
        &on,
        "key-a",
        keyed_call(2, "g11m", "gateway_execute", &chain()),
    );
    #[cfg(feature = "metrics")]
    let (replay, filtered) = crate::gateway::count_plan_replay_skipped("filtered", measured);
    #[cfg(not(feature = "metrics"))]
    let replay = measured.await;
    assert!(replay.get("error").is_none(), "base: replayed: {replay}");
    assert_ne!(
        replay["result"], first["result"],
        "premise: stored and delivered answers differ"
    );
    assert!(
        replay.to_string().contains(PROSE)
            && replay.to_string().contains("tail0449")
            && !replay.to_string().contains(&removed),
        "premise: the redaction touched only the cut middle; head and tail still deliver: {replay}"
    );
    assert_eq!(rig.calls(), before, "P2: the replay dispatched nothing");
    assert!(
        probe_refused(&on, "key-a", 124, &removed).await,
        "the reader kept an excuse for the removed middle text"
    );
    assert!(
        !probe_refused(&on, "key-a", 125, PROSE).await,
        "control: the delivered head renewed the reader's excuse"
    );
    assert!(
        probe_refused(&on, "key-b", 126, PROSE).await,
        "control: bob, who never held the head, is refused"
    );
    #[cfg(feature = "metrics")]
    assert_eq!(
        filtered, 1,
        "the filtered drop was not counted exactly once reason=filtered"
    );
}

/// G11c (H): the F4 `identical` gate at route level. Alpha's step text
/// runs past the record cap (its stored snapshot carries `cut_fps`,
/// premise via the cut counter) and is delivered again in full; only
/// beta's step changes, its credential run redacted by the second
/// gateway's tightened policy. The answer differs (premise), so alpha's
/// receipt goes through the filtering path although every one of its
/// kept segments and fingerprints is still delivered: its excuse-only
/// sets are dropped and counted `reason=filtered`.
/// Mutant killed: the old fast path (no `identical` gate): alpha's
/// fully delivered receipt would keep its sets, and nothing would be
/// counted for it. d11 pins the same gate at unit level.
#[cfg(feature = "metrics")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g11c_another_step_changing_drops_a_fully_delivered_steps_excuses() {
    let removed = removed_run();
    let alpha_text = format!("{PROSE} {}", over_cap_tail());
    let beta_text = format!("{OTHER_PROSE} {removed}");
    let rig = with_unredacted_router(rig(&alpha_text, &beta_text, None).await);
    let cuts_before = rig.relay.relay_text_cuts();
    let first = post(
        &rig.state,
        "key-a",
        keyed_call(1, "g11c", "gateway_execute", &chain()),
    )
    .await;
    assert!(
        first.get("error").is_none() && first.to_string().contains(&removed),
        "base: first delivery carries beta's run unredacted: {first}"
    );
    assert!(
        rig.relay.relay_text_cuts() > cuts_before,
        "premise: live retention cut alpha's over-cap step, so its stored snapshot carries cut_fps"
    );
    let (on, _on_store) = redacting_gateway(&rig).await;
    let measured = post(
        &on,
        "key-a",
        keyed_call(2, "g11c", "gateway_execute", &chain()),
    );
    let (replay, filtered) = crate::gateway::count_plan_replay_skipped("filtered", measured);
    assert!(replay.get("error").is_none(), "base: replayed: {replay}");
    assert_ne!(
        replay["result"], first["result"],
        "premise: stored and delivered answers differ"
    );
    assert!(
        replay.to_string().contains("row1199") && !replay.to_string().contains(&removed),
        "premise: alpha is delivered in full and only beta's run is redacted: {replay}"
    );
    assert_eq!(rig.calls(), (1, 1), "P2: the replay dispatched nothing");
    assert_eq!(
        filtered, 1,
        "alpha's fully delivered receipt kept its excuse sets against a changed answer"
    );
}
