// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8408 stage 4: the content guard rows of the test plan
//! (docs/internal/design/2026-10-12-mik-8408-test-plan.md): what a
//! replay does with a stored answer's content (G1, G11/G41, G18,
//! G21, G26, G27). Split from `relay_plan_replay_guards`, whose
//! shared helpers these rows reuse. The rig is
//! `relay_plan_replay`'s.
use super::super::*;
use super::relay_plan_replay::{
    ALPHA, BETA, OTHER_PROSE, PROSE, Rig, Sensitivity, answering, chain, keyed_call, playbook,
    playbook_args, rig, rig_with, rig_with_mocks, task_call, text,
};
#[cfg(feature = "metrics")]
use super::relay_plan_replay_guards::skipped_count;
use super::relay_plan_replay_guards::{committed, delist, live_invoke, plan_auth, probe_refused};
use super::support::*;
use pretty_assertions::assert_eq;

use crate::security::firewall::{Firewall, FirewallAction, FirewallConfig, FirewallRule};

/// The first string value of member `key` anywhere in `value`. A
/// wrapped answer carries its JSON in a text block, so a string
/// that parses as JSON is searched inside too: that is where a
/// keyed chain answer carries its step verdicts.
fn find_member(value: &Value, key: &str) -> Option<String> {
    match value {
        Value::Object(map) => match map.get(key) {
            Some(Value::String(found)) => Some(found.clone()),
            _ => map.values().find_map(|inner| find_member(inner, key)),
        },
        Value::Array(items) => items.iter().find_map(|inner| find_member(inner, key)),
        Value::String(inner_text) => serde_json::from_str::<Value>(inner_text)
            .ok()
            .and_then(|inner| find_member(&inner, key)),
        _ => None,
    }
}

/// The gateway-written member of a verdict-bearing step result: the
/// `content_sha256` in its `_context_integrity` verdict. 64 chars,
/// past a k-gram; this rig keeps every k-gram (`min_matches: 1`), so
/// it flags whenever receipted (test plan §10 on R9's 77-char advice).
fn gateway_member(answer: &Value) -> String {
    let member =
        find_member(answer, "content_sha256").expect("stored answer carries the verdict: fixture");
    assert!(
        member.len() >= 48,
        "premise: member longer than a k-gram: {member}"
    );
    member
}

/// G1's control: `member` as alpha's backend text on a fresh rig flags.
async fn flags_as_backend_text(member: &str) {
    let control = rig(member, OTHER_PROSE, None).await;
    let delivered = live_invoke(&control.state, 10, ALPHA).await;
    assert!(
        delivered.get("error").is_none() && delivered.to_string().contains(member),
        "control premise: alice delivered the member as backend text: {delivered}"
    );
    assert!(
        control.refused("key-b", 11, member).await,
        "control: identical string as backend text flags"
    );
}

/// G1's shared tail: on a verdict rig, live and after `reread`, alpha's
/// text is refused for bob and the gateway member never is.
async fn gateway_member_never_receipted(
    rig: &Rig,
    text: &str,
    member: &str,
    base: i64,
    reread: impl std::future::Future<Output = Value>,
) {
    assert!(
        rig.refused("key-b", base, text).await,
        "P0: live receipt holds for alpha's text"
    );
    assert!(
        !rig.refused("key-b", base + 1, member).await,
        "premise: live receipt never held the member"
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
        !rig.refused("key-b", base + 4, member).await,
        "the replay receipted the gateway's own member"
    );
}

/// G1 (T): the gateway's own member in alpha's stored result is never
/// receipted on a task re-read; the identical string as backend text
/// flags (control rig).
/// Mutant: snapshot built from the stored answer.
#[tokio::test]
async fn g1_a_task_reread_never_receipts_the_gateways_own_member() {
    let text = format!("{PROSE} Contact: keeper@orchardcoop.fi");
    let rig = rig_with(&text, OTHER_PROSE, None, Sensitivity::Verdict).await;
    let task = rig.settle_task("g1-t", "gateway_execute", chain()).await;
    let shown = get_task(&rig.state, "key-a", &task).await;
    assert!(
        shown.to_string().contains(PROSE),
        "premise: stored answer carries alpha's text: {shown}"
    );
    let member = gateway_member(&shown);
    flags_as_backend_text(&member).await;
    gateway_member_never_receipted(
        &rig,
        &text,
        &member,
        10,
        get_task(&rig.state, "key-a", &task),
    )
    .await;
}

/// G1 (H): the same on a keyed synchronous chain replay.
/// Mutant: snapshot built from the stored answer.
#[tokio::test]
async fn g1_a_keyed_replay_never_receipts_the_gateways_own_member() {
    let text = format!("{PROSE} Contact: keeper@orchardcoop.fi");
    let rig = rig_with(&text, OTHER_PROSE, None, Sensitivity::Verdict).await;
    let first = post(
        &rig.state,
        "key-a",
        keyed_call(1, "g1-h", "gateway_execute", &chain()),
    )
    .await;
    assert!(first.get("error").is_none(), "base: delivered: {first}");
    let member = gateway_member(&first);
    flags_as_backend_text(&member).await;
    let replay = post(
        &rig.state,
        "key-a",
        keyed_call(2, "g1-h", "gateway_execute", &chain()),
    );
    gateway_member_never_receipted(&rig, &text, &member, 20, async move {
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
async fn g18_a_resumed_chain_lists_both_steps_and_stages_nothing_under_step_0() {
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
        .task_replay_digests(&task, stored.revision)
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
async fn g21_a_failed_playbook_step_is_listed_and_stages_nothing() {
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
        .task_replay_digests(&task, stored.revision)
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
                    serde_yaml::from_str(&scoped_playbook(FORBIDDEN_BACKEND))
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
        .task_replay_digests(&task, stored.revision)
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
async fn redacting_gateway(rig: &Rig) -> (Arc<AppState>, tempfile::TempDir) {
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
#[tokio::test]
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
    #[cfg(feature = "metrics")]
    let filtered_before = skipped_count("filtered");
    let replay = post(
        &on,
        "key-a",
        keyed_call(2, "g11", "gateway_execute", &chain()),
    )
    .await;
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
    assert!(
        skipped_count("filtered") > filtered_before,
        "the filtered drop was not counted"
    );
}

/// An open listen stream's frames, read one SSE block at a time
/// (`notifications_helpers` is private to `notifications`, so the
/// minimal reader is local; the request is support's own).
struct Frames {
    body: axum::body::BodyDataStream,
    buffer: Vec<u8>,
    ended: bool,
}

impl Frames {
    fn take_frame(&mut self) -> Option<Value> {
        loop {
            let end = self.buffer.windows(2).position(|pair| pair == b"\n\n")?;
            let block: Vec<u8> = self.buffer.drain(..end + 2).collect();
            let text = String::from_utf8(block).expect("a subscription frame is UTF-8: fixture");
            let data: Vec<&str> = text
                .lines()
                .filter_map(|l| l.strip_prefix("data: "))
                .collect();
            if data.is_empty() {
                continue;
            }
            let payload = data.join("\n");
            return Some(
                serde_json::from_str(&payload).expect("a subscription frame is JSON: fixture"),
            );
        }
    }

    async fn next_frame(&mut self, what: &str) -> Value {
        use futures::StreamExt as _;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Some(frame) = self.take_frame() {
                return frame;
            }
            assert!(!self.ended, "the listen stream ended before {what} arrived");
            match tokio::time::timeout_at(deadline, self.body.next()).await {
                Err(elapsed) => panic!("{what} never arrived on the listen stream: {elapsed}"),
                Ok(None) => self.ended = true,
                Ok(Some(Ok(chunk))) => self.buffer.extend_from_slice(&chunk),
                Ok(Some(Err(error))) => panic!("the listen body failed mid-stream: {error}"),
            }
        }
    }

    /// Frames until one reports `task` completed; that frame.
    async fn completed_frame(&mut self, task: &str) -> Value {
        for _ in 0..8 {
            let frame = self.next_frame("the completed task frame").await;
            if frame["params"]["taskId"] == task && frame["params"]["status"] == "completed" {
                return frame;
            }
        }
        panic!("no completed frame for {task} arrived on the listen stream");
    }
}

/// Open alice's listen stream over `task`, consuming its acknowledgement.
async fn open_listen(state: &Arc<AppState>, id: i64, task: &str) -> Frames {
    let body = task_method(id, "subscriptions/listen", json!({"taskIds": [task]}));
    let response = create_router(Arc::clone(state))
        .oneshot(http_request(Some("key-a"), &body))
        .await
        .expect("the router must answer: fixture");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "premise: the listen is admitted"
    );
    let mut frames = Frames {
        body: response.into_body().into_data_stream(),
        buffer: Vec::new(),
        ended: false,
    };
    let ack = frames.next_frame("the listen acknowledgement").await;
    assert_eq!(
        ack["method"], "notifications/subscriptions/acknowledged",
        "premise ack: {ack}"
    );
    frames
}

/// A chain task held at step B, its listen stream open, then released
/// and settled: the shared setup of G27a/G27b. The frame is left
/// unread, so it is built and committed only when the row pulls it.
async fn settled_with_listener(key: &str) -> (Rig, String, Frames) {
    let (beta, mut gate) = MockBackend::holding(Answer::Sequence(vec![text(OTHER_PROSE)]));
    let rig = rig_with_mocks(answering(PROSE), beta, None, Sensitivity::Rule).await;
    let created = post(
        &rig.state,
        "key-a",
        task_call(1, key, "gateway_execute", &chain()),
    )
    .await;
    let task = task_id(&created);
    gate.wait_for_dispatch().await;
    let frames = open_listen(&rig.state, 7001, &task).await;
    gate.release_all();
    let settled = poll_until_terminal(&rig.state, "key-a", &task).await;
    assert_eq!(status_of(&settled), "completed", "premise: {settled}");
    (rig, task, frames)
}

/// G27a (T): a notify subscriber's frame of the completed plan task
/// stages and commits the replayed receipts: past the lapse, bob is
/// refused only after the frame is delivered.
/// Mutant: commit on a withheld frame (its inverse, never committing
/// on a delivered frame, leaves bob unrefused here).
#[tokio::test]
async fn g27a_a_delivered_notify_frame_commits_the_replayed_receipts() {
    let (rig, task, mut frames) = settled_with_listener("g27a").await;
    rig.lapse().await;
    assert!(
        !rig.refused("key-b", 270, PROSE).await,
        "P1: lapsed before the frame"
    );
    let frame = frames.completed_frame(&task).await;
    assert!(
        frame.to_string().contains(PROSE),
        "premise: the frame carries the full task: {frame}"
    );
    assert!(
        rig.refused("key-b", 271, PROSE).await,
        "the delivered frame committed no receipt (step A)"
    );
    assert!(
        rig.refused("key-b", 272, OTHER_PROSE).await,
        "the delivered frame committed no receipt (step B)"
    );
}

/// G27b (T): a frame the stored-read gate withholds (alpha delisted
/// after settlement, so the frame goes out minimal) commits none.
/// Mutant: commit on a withheld frame.
#[tokio::test]
async fn g27b_a_withheld_notify_frame_commits_nothing() {
    let (rig, task, mut frames) = settled_with_listener("g27b").await;
    rig.lapse().await;
    assert!(
        !rig.refused("key-b", 280, PROSE).await,
        "P1: lapsed before the frame"
    );
    delist(&rig.state, ALPHA);
    let frame = frames.completed_frame(&task).await;
    assert!(
        !frame.to_string().contains(PROSE),
        "premise: the withheld frame carries no output: {frame}"
    );
    assert!(
        !rig.refused("key-b", 281, PROSE).await,
        "the withheld frame committed a receipt"
    );
}
