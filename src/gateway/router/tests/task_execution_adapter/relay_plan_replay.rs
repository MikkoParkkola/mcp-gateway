// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8408 red rows at the POST route: a plan's stored answer read again (a
//! task re-read, a keyed synchronous replay) is a second delivery, so it
//! renews the reader's relay receipts step by step, as a single-target
//! re-read already does (`task_get_renews_the_receipt`). Each row lets the
//! live receipt lapse on the relay firewall's frozen clock, proves it lapsed
//! (P1), re-reads, proves the re-read ran nothing (P2: no backend call), and
//! only then asserts the renewal.
//!
//! Test plan: the relay replay test plan.
use super::super::*;
use super::support::*;
use pretty_assertions::assert_eq;

use crate::security::firewall::{CollusionAction, CollusionConfig, Firewall, FirewallConfig};

/// Step A's server: its text is sensitive (a `sources` rule).
pub(super) const ALPHA: &str = "alpha";
/// Step B's server: plain text.
pub(super) const BETA: &str = "beta";

/// Step A's prose: longer than a k-gram many times over.
pub(super) const PROSE: &str = "The orchard ledger for the north slope records seven rows of late pears, \
    the grafting dates for each rootstock, the hours the drip lines ran during the dry weeks of \
    August, and which crew pruned the older trees after the second frost.";

/// Step B's prose.
pub(super) const OTHER_PROSE: &str = "Minutes of the harbour committee: the dredging contract moves to the \
    spring tender, the ferry timetable keeps its Sunday gap, and the pilot boat needs a new \
    engine mount before the first autumn gale.";

/// Short fields, one per step, each under a k-gram, for the seam row.
const FIELD_A: &str = "north slope rows seven to twelve, late pears";
const FIELD_B: &str = "south terrace rows one to six, early quinces";

/// The relay window, in seconds; the rows advance the frozen clock past it.
pub(super) const WINDOW_SECS: u64 = 1;

pub(super) fn text(text: &str) -> Value {
    json!({"content": [{"type": "text", "text": text}], "isError": false})
}

/// A backend that answers every call with `answer` (the last answer repeats).
pub(super) fn answering(answer: &str) -> Arc<MockBackend> {
    MockBackend::answering(Answer::Sequence(vec![text(answer)]))
}

/// The row's gateway: three callers allowed `mock`, `alpha` and `beta`; the
/// `block` relay detector over `alpha:*` with every k-gram kept and one shared
/// fingerprint enough to refuse; and the handle that ages its receipts.
pub(super) struct Rig {
    pub(super) state: Arc<AppState>,
    pub(super) _store: crate::gateway::router::tests::FixtureDir,
    pub(super) relay: Arc<Firewall>,
    pub(super) alpha: Arc<MockBackend>,
    pub(super) beta: Arc<MockBackend>,
}

pub(super) async fn rig(alpha_text: &str, beta_text: &str, playbook: Option<&str>) -> Rig {
    rig_with(alpha_text, beta_text, playbook, Sensitivity::Rule).await
}

/// How step A's text is made sensitive.
#[derive(Clone, Copy)]
pub(super) enum Sensitivity {
    /// A `sources` rule over `alpha:*`.
    Rule,
    /// No `sources` rule: a context-integrity verdict (personal data, monitor
    /// only) on the step's result.
    Verdict,
}

pub(super) async fn rig_with(
    alpha_text: &str,
    beta_text: &str,
    playbook: Option<&str>,
    sensitivity: Sensitivity,
) -> Rig {
    rig_with_mocks(
        answering(alpha_text),
        answering(beta_text),
        playbook,
        sensitivity,
    )
    .await
}

/// [`rig_with`] over caller-built step mocks (a sequence, a failure, a
/// held dispatch): the guard rows' steps are not all plain answers.
pub(super) async fn rig_with_mocks(
    alpha: Arc<MockBackend>,
    beta: Arc<MockBackend>,
    playbook: Option<&str>,
    sensitivity: Sensitivity,
) -> Rig {
    let relay = Arc::new(
        Firewall::from_config(
            FirewallConfig {
                collusion: CollusionConfig {
                    action: CollusionAction::Block,
                    min_matches: 1,
                    sources: match sensitivity {
                        Sensitivity::Rule => vec![format!("{ALPHA}:*"), format!("{BETA}:*")],
                        Sensitivity::Verdict => Vec::new(),
                    },
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
    // Frozen from the start: a slow runner must not age a receipt in real
    // time before a premise reads it; only the explicit lapse moves it.
    relay.advance_collusion_clock_for_test(std::time::Duration::ZERO);
    let mut auth = three_principal_auth();
    for key in &mut auth.api_keys {
        key.backends.extend([ALPHA.to_string(), BETA.to_string()]);
    }
    let definition: Option<crate::playbook::PlaybookDefinition> =
        playbook.map(|p| crate::yaml::from_str(p).expect("playbook fixture must parse"));
    let handle = Arc::clone(&relay);
    let (state, store) = super::super::meta_fixture::test_router_app_state_with_meta_and_firewall(
        &auth,
        None,
        None,
        move |mut meta| {
            meta.share_keyring_with_for_test(&handle);
            meta.set_firewall(Some(handle));
            if matches!(sensitivity, Sensitivity::Verdict) {
                use crate::context_integrity::{
                    ContextIntegrityDecisionKind, ContextIntegrityKernel, ContextIntegrityPolicy,
                    ContextIntegrityPolicyMode,
                };
                let allow = ContextIntegrityDecisionKind::Allow;
                meta.set_context_integrity_kernel(ContextIntegrityKernel::new(
                    ContextIntegrityPolicy {
                        mode: ContextIntegrityPolicyMode::MonitorOnly,
                        untrusted_instruction_decision: allow,
                        guarded_material_decision: allow,
                        personal_data_decision: allow,
                        destructive_instruction_decision: allow,
                        tool_poisoning_decision: allow,
                        high_risk_action_decision: allow,
                        allow_benign_read_only: true,
                        non_bypassable: false,
                    },
                ));
            }
            if let Some(definition) = definition {
                let mut engine = crate::playbook::PlaybookEngine::new();
                engine.register(definition);
                meta.set_playbook_engine(engine);
            }
            meta
        },
    )
    .await;
    // `mock` is the probe: bob's relays go to it, and it answers only "ok",
    // so a probe never hands bob a copy of the tested text.
    register(&state, BACKEND, &answering("ok"));
    register(&state, ALPHA, &alpha);
    register(&state, BETA, &beta);
    Rig {
        state,
        _store: store,
        relay,
        alpha,
        beta,
    }
}

impl Rig {
    /// `who` sends `relayed` to the probe; whether the relay was refused.
    pub(super) async fn refused(&self, who: &str, id: i64, relayed: &str) -> bool {
        let reply = post(&self.state, who, sync_invoke(id, json!({"text": relayed}))).await;
        if reply["error"]["code"] == -32002 {
            return true;
        }
        // Not refused: it must be the probe's own clean answer, so an
        // unrelated error never reads as a send that went through.
        assert!(
            reply.get("error").is_none() && reply.to_string().contains("ok"),
            "a relay probe that is not refused must succeed with the probe's answer: {reply}"
        );
        assert!(
            !reply.to_string().contains(relayed),
            "the probe must not deliver the tested text: {reply}"
        );
        false
    }

    /// Join every task worker, then age the receipts past the window.
    pub(super) async fn lapse(&self) {
        let joined = self
            .state
            .task_executor
            .drain(std::time::Duration::from_secs(10))
            .await;
        assert!(joined.is_clean(), "the workers must finish: {joined:?}");
        self.relay
            .advance_collusion_clock_for_test(std::time::Duration::from_secs(WINDOW_SECS + 1));
    }

    /// Both step backends' call counts.
    pub(super) fn calls(&self) -> (usize, usize) {
        (self.alpha.calls(), self.beta.calls())
    }
}

/// A two-step chain: A then B.
pub(super) fn chain() -> Value {
    json!({"chain": [
        {"tool": format!("{ALPHA}:{TOOL}"), "arguments": {}},
        {"tool": format!("{BETA}:{TOOL}"), "arguments": {}},
    ]})
}

/// A playbook of one step on each of `alpha` and `beta`, its output mapping
/// both steps' text.
pub(super) fn playbook() -> String {
    format!(
        "name: replay\ndescription: plan steps\non_error: continue\ninputs: {{}}\nsteps:\n\
         \x20 - name: s1\n    server: {ALPHA}\n    tool: {TOOL}\n\
         \x20 - name: s2\n    server: {BETA}\n    tool: {TOOL}\n\
         output:\n  type: object\n  properties:\n\
         \x20   a:\n      path: $s1.content[0].text\n\
         \x20   b:\n      path: $s2.content[0].text\n"
    )
}

pub(super) fn playbook_args() -> Value {
    json!({"name": "replay", "arguments": {}})
}

/// A task-augmented `name` call with `arguments`, under idempotency `key`.
pub(super) fn task_call(id: i64, key: &str, name: &str, arguments: &Value) -> Value {
    keyed(
        modern(
            id,
            "tools/call",
            json!({"name": name, "arguments": arguments, "task": {}}),
            true,
        ),
        key,
    )
}

/// The same call synchronous, under idempotency `key`: a repeat is served
/// from the retained answer.
pub(super) fn keyed_call(id: i64, key: &str, name: &str, arguments: &Value) -> Value {
    keyed(
        modern(
            id,
            "tools/call",
            json!({"name": name, "arguments": arguments}),
            false,
        ),
        key,
    )
}

impl Rig {
    /// Run `name(arguments)` as alice's task to its end; the task id.
    pub(super) async fn settle_task(&self, key: &str, name: &str, arguments: Value) -> String {
        let created = post(&self.state, "key-a", task_call(1, key, name, &arguments)).await;
        let task = task_id(&created);
        let settled = poll_until_terminal(&self.state, "key-a", &task).await;
        assert_eq!(status_of(&settled), "completed", "base: {settled}");
        // Terminal visibility precedes the worker's settlement commit: join
        // the worker, so the live receipts exist before any premise reads them.
        let joined = self
            .state
            .task_executor
            .drain(std::time::Duration::from_secs(10))
            .await;
        assert!(
            joined.is_clean(),
            "the settling worker must finish: {joined:?}"
        );
        assert_eq!(
            self.calls(),
            (1, 1),
            "premise: both steps dispatched, one call each"
        );
        let targets: Vec<(String, String)> = self
            .state
            .task_executor
            .service
            .store
            .targets_for_test(&task)
            .into_iter()
            .map(|t| (t.server, t.tool))
            .collect();
        assert_eq!(
            targets,
            vec![
                (ALPHA.to_string(), TOOL.to_string()),
                (BETA.to_string(), TOOL.to_string())
            ],
            "premise: the row records two distinct targets, so the base takes the multi-target path"
        );
        task
    }

    /// The shared tail of every route row. P0: bob relaying each of `texts`
    /// is refused while the live receipts hold (they exist). P1: after the
    /// lapse, none is refused. P2: `reread` ran nothing, and when `expected`
    /// is given it delivered exactly that retained result. Then each is
    /// refused again: the re-read renewed it.
    pub(super) async fn renews_after(
        &self,
        texts: &[&str],
        expected: Option<&Value>,
        reread: impl std::future::Future<Output = Value>,
    ) {
        for (i, text) in (0_i64..).zip(texts) {
            assert!(
                self.refused("key-b", 100 + i, text).await,
                "premise P0: the live receipt holds for {text:.40}"
            );
        }
        self.lapse().await;
        for (i, text) in (0_i64..).zip(texts) {
            assert!(
                !self.refused("key-b", 110 + i, text).await,
                "premise P1: the live receipt lapsed for {text:.40}"
            );
        }
        let before = self.calls();
        let read = reread.await;
        assert!(
            read.get("error").is_none(),
            "base: the re-read is served: {read}"
        );
        assert_eq!(
            self.calls(),
            before,
            "premise P2: the re-read was served from the stored answer, not run again"
        );
        if let Some(expected) = expected {
            assert_eq!(
                read["result"], expected["result"],
                "premise P2: the replay delivered the retained result unchanged"
            );
        }
        for (i, text) in (0_i64..).zip(texts) {
            assert!(
                self.refused("key-b", 120 + i, text).await,
                "the re-read renewed no receipt for {text:.40}"
            );
        }
    }
}

/// R1 (REPLAY.5): alice's `tasks/get` of a completed chain task renews both
/// steps' receipts.
#[tokio::test]
async fn a_plan_task_read_renews_each_step_receipt() {
    let rig = rig(PROSE, OTHER_PROSE, None).await;
    let task = rig.settle_task("r1", "gateway_execute", chain()).await;
    rig.renews_after(
        &[PROSE, OTHER_PROSE],
        None,
        get_task(&rig.state, "key-a", &task),
    )
    .await;
}

/// R2 (REPLAY.5): the same for a two-step playbook task.
#[tokio::test]
async fn a_playbook_task_read_renews_each_step_receipt() {
    let rig = rig(PROSE, OTHER_PROSE, Some(&playbook())).await;
    let task = rig
        .settle_task("r2", "gateway_run_playbook", playbook_args())
        .await;
    rig.renews_after(
        &[PROSE, OTHER_PROSE],
        None,
        get_task(&rig.state, "key-a", &task),
    )
    .await;
}

/// R3 (REPLAY.6): a keyed synchronous `gateway_execute` repeated is served
/// from the retained answer, and that delivery renews both steps' receipts.
#[tokio::test]
async fn a_keyed_chain_replay_renews_each_step_receipt() {
    let rig = rig(PROSE, OTHER_PROSE, None).await;
    let first = post(
        &rig.state,
        "key-a",
        keyed_call(1, "r3", "gateway_execute", &chain()),
    )
    .await;
    assert!(first.get("error").is_none(), "base: delivered: {first}");
    assert_eq!(rig.calls(), (1, 1), "premise: both steps dispatched");
    rig.renews_after(
        &[PROSE, OTHER_PROSE],
        Some(&first),
        post(
            &rig.state,
            "key-a",
            keyed_call(2, "r3", "gateway_execute", &chain()),
        ),
    )
    .await;
}

/// R4 (REPLAY.6): the same for a keyed synchronous playbook.
#[tokio::test]
async fn a_keyed_playbook_replay_renews_each_step_receipt() {
    let rig = rig(PROSE, OTHER_PROSE, Some(&playbook())).await;
    let first = post(
        &rig.state,
        "key-a",
        keyed_call(1, "r4", "gateway_run_playbook", &playbook_args()),
    )
    .await;
    assert!(first.get("error").is_none(), "base: delivered: {first}");
    assert_eq!(rig.calls(), (1, 1), "premise: both steps dispatched");
    rig.renews_after(
        &[PROSE, OTHER_PROSE],
        Some(&first),
        post(
            &rig.state,
            "key-a",
            keyed_call(2, "r4", "gateway_run_playbook", &playbook_args()),
        ),
    )
    .await;
}

/// G29 (REPLAY.5, red): alice repeats the task-augmented call itself (same
/// key, same body); the existing task is served (the Existing arm), and that
/// delivery renews.
#[tokio::test]
async fn a_task_augmented_repeat_renews() {
    let rig = rig(PROSE, OTHER_PROSE, None).await;
    rig.settle_task("g29", "gateway_execute", chain()).await;
    rig.renews_after(
        &[PROSE, OTHER_PROSE],
        None,
        post(
            &rig.state,
            "key-a",
            task_call(1, "g29", "gateway_execute", &chain()),
        ),
    )
    .await;
}

/// R5 (REPLAY.5): carol takes a fresh copy of A's text after alice's lapsed;
/// alice's re-read gives her back her same-source excuse, so her own send of
/// that text is not refused, while bob's still is.
#[tokio::test]
async fn a_plan_task_read_keeps_the_readers_excuse() {
    let rig = rig(PROSE, OTHER_PROSE, None).await;
    let task = rig.settle_task("r5", "gateway_execute", chain()).await;
    rig.lapse().await;
    let carol = post(
        &rig.state,
        "key-c",
        modern(
            50,
            "tools/call",
            json!({"name": "gateway_invoke",
                   "arguments": {"server": ALPHA, "tool": TOOL, "arguments": {}}}),
            false,
        ),
    )
    .await;
    assert!(
        carol.get("error").is_none() && carol.to_string().contains(PROSE),
        "premise: carol was delivered A's whole text: {carol}"
    );
    assert!(
        rig.refused("key-a", 51, PROSE).await,
        "premise: carol is a live witness and alice holds no live copy"
    );
    let before = rig.calls();
    let read = get_task(&rig.state, "key-a", &task).await;
    assert_eq!(status_of(&read), "completed", "base: {read}");
    assert_eq!(rig.calls(), before, "premise P2: nothing ran again");
    assert!(
        rig.refused("key-b", 52, PROSE).await,
        "control: bob, who never held the text, is refused"
    );
    assert!(
        !rig.refused("key-a", 53, PROSE).await,
        "alice's re-read did not renew her same-source excuse"
    );
}

/// R6 (REPLAY.5): two short fields, one per step, delivered side by side are
/// a seam; a playbook task re-read renews it.
#[tokio::test]
async fn a_plan_task_read_renews_the_cross_step_seam() {
    let rig = rig(FIELD_A, FIELD_B, Some(&playbook())).await;
    let task = rig
        .settle_task("r6", "gateway_run_playbook", playbook_args())
        .await;
    let shown = get_task(&rig.state, "key-a", &task).await.to_string();
    assert!(
        shown.contains(FIELD_A) && shown.contains(FIELD_B),
        "premise: the playbook output holds both fields: {shown}"
    );
    let pair = format!("{FIELD_A}{FIELD_B}");
    assert!(
        !rig.refused("key-b", 60, FIELD_A).await && !rig.refused("key-b", 61, FIELD_B).await,
        "premise: neither field alone is matched"
    );
    rig.renews_after(&[&pair], None, get_task(&rig.state, "key-a", &task))
        .await;
}

/// R7 (REPLAY.5): no `sources` rule; step A is sensitive only by its
/// context-integrity verdict (personal data), which sits on the step's result
/// and which the playbook's output mapping drops. A task re-read still renews
/// A's receipt as sensitive.
#[tokio::test]
async fn a_verdict_sensitive_playbook_step_renews() {
    let classified = format!("{PROSE} Contact: keeper@orchardcoop.fi");
    let rig = rig_with(
        &classified,
        OTHER_PROSE,
        Some(&playbook()),
        Sensitivity::Verdict,
    )
    .await;
    let task = rig
        .settle_task("r7", "gateway_run_playbook", playbook_args())
        .await;
    let shown = get_task(&rig.state, "key-a", &task).await.to_string();
    assert!(
        shown.contains("orchardcoop") && !shown.contains("personal_data"),
        "premise: the stored output carries A's text but not the step's verdict: {shown}"
    );
    rig.renews_after(&[&classified], None, get_task(&rig.state, "key-a", &task))
        .await;
}

/// The gateway's recovery advice for a tool error it reads as a parameter
/// problem: the gateway's own text, longer than a k-gram.
pub(super) const SUGGEST: &str =
    "Check the tool's input schema, correct the offending parameter(s), and retry.";

/// A step backend whose every answer is a tool error with no text block,
/// as R9's erring mock answers in kind: the gateway reads it as a
/// parameter problem and writes [`SUGGEST`] into the step result's
/// recovery advice, which a playbook under `on_error: continue` carries
/// into its stored answer's step reason.
pub(super) fn erring_step() -> Arc<MockBackend> {
    MockBackend::answering(Answer::Sequence(vec![json!({
        "content": [], "isError": true
    })]))
}

/// R9's second gateway: the first gateway's retained answers
/// (`admission`) with relay detection on, over the same backends.
async fn detection_on_gateway(
    auth: &AuthConfig,
    admission: Arc<crate::idempotency::admission::ExecutionAdmission>,
    erring: &Arc<MockBackend>,
) -> (Arc<AppState>, crate::gateway::router::tests::FixtureDir) {
    let relay_fw = Arc::new(
        Firewall::from_config(
            FirewallConfig {
                collusion: CollusionConfig {
                    action: CollusionAction::Block,
                    min_matches: 1,
                    sources: vec![format!("{ALPHA}:*")],
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
    let handle = Arc::clone(&relay_fw);
    let (on, on_store) = super::super::meta_fixture::test_router_app_state_with_meta_and_firewall(
        auth,
        None,
        None,
        move |mut meta| {
            meta.share_execution_admission_for_test(admission);
            meta.share_keyring_with_for_test(&handle);
            meta.set_firewall(Some(handle));
            meta
        },
    )
    .await;
    register(&on, BACKEND, &answering("ok"));
    register(&on, ALPHA, erring);
    (on, on_store)
}

/// R9 (REPLAY.3, D5): a keyed single-target call answered while relay
/// detection was off is retained without the record of what the gateway
/// wrote into it (the scope that notes it opens only with detection on).
/// Replayed once detection is on, the receipt must still leave the gateway's
/// own advice out; today it receipts it as the backend's text.
#[tokio::test]
async fn a_detection_off_answer_replayed_on_never_receipts_gateway_text() {
    let note = format!("{PROSE} The rootstock column is empty for row nine.");
    let erring = MockBackend::answering(Answer::Sequence(vec![json!({
        "content": [{"type": "text", "text": note}],
        "isError": true
    })]));
    let mut auth = three_principal_auth();
    for key in &mut auth.api_keys {
        key.backends.extend([ALPHA.to_string(), BETA.to_string()]);
    }
    // First gateway: no firewall, so relay detection is off.
    let (off, _off_store) =
        super::super::meta_fixture::test_router_app_state_with_meta_and_firewall(
            &auth,
            None,
            None,
            |meta| meta,
        )
        .await;
    register(&off, BACKEND, &answering("ok"));
    register(&off, ALPHA, &erring);
    let call = || json!({"server": ALPHA, "tool": TOOL, "arguments": {}});
    let first = post(
        &off,
        "key-a",
        keyed_call(1, "r9", "gateway_invoke", &call()),
    )
    .await;
    assert!(
        first.to_string().contains(SUGGEST),
        "premise: the gateway wrote its advice into the answer: {first}"
    );
    assert_eq!(erring.calls(), 1, "premise: the call dispatched once");

    // Second gateway: the same retained answers, relay detection on.
    let admission = Arc::clone(off.meta_mcp.execution_admission());
    let (on, _on_store) = detection_on_gateway(&auth, admission, &erring).await;
    let probe = |state: &Arc<AppState>, who: &'static str, id: i64, relayed: String| {
        let state = Arc::clone(state);
        async move {
            let reply = post(
                &state,
                who,
                sync_invoke(id, json!({"text": relayed.clone()})),
            )
            .await;
            if reply["error"]["code"] == -32002 {
                return true;
            }
            assert!(
                reply.get("error").is_none()
                    && reply.to_string().contains("ok")
                    && !reply.to_string().contains(&relayed),
                "a relay probe that is not refused must succeed with the probe's answer: {reply}"
            );
            false
        }
    };
    assert!(
        !probe(&on, "key-b", 90, note.clone()).await,
        "premise P1: nothing is receipted on the new gateway yet"
    );
    let retained = post(&on, "key-a", keyed_call(2, "r9", "gateway_invoke", &call())).await;
    assert!(
        retained.to_string().contains(SUGGEST),
        "premise: the retained answer, advice included, was replayed: {retained}"
    );
    assert_eq!(
        erring.calls(),
        1,
        "premise P2: the replay was served from the retained answer"
    );
    assert!(
        probe(&on, "key-b", 91, note.clone()).await,
        "control: the replay renewed the backend's own text"
    );
    assert!(
        !probe(&on, "key-b", 92, SUGGEST.to_string()).await,
        "the replay receipted the gateway's own advice as the backend's text"
    );
}
