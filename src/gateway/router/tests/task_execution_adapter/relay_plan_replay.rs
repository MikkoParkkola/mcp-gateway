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
//! Test plan: docs/internal/design/2026-10-12-mik-8408-test-plan.md.
use super::super::*;
use super::support::*;
use pretty_assertions::assert_eq;

use crate::security::firewall::{CollusionAction, CollusionConfig, Firewall, FirewallConfig};

/// Step A's server: its text is sensitive (a `sources` rule).
const ALPHA: &str = "alpha";
/// Step B's server: plain text.
const BETA: &str = "beta";

/// Step A's prose: longer than a k-gram many times over.
const PROSE: &str = "The orchard ledger for the north slope records seven rows of late pears, \
    the grafting dates for each rootstock, the hours the drip lines ran during the dry weeks of \
    August, and which crew pruned the older trees after the second frost.";

/// Step B's prose.
const OTHER_PROSE: &str = "Minutes of the harbour committee: the dredging contract moves to the \
    spring tender, the ferry timetable keeps its Sunday gap, and the pilot boat needs a new \
    engine mount before the first autumn gale.";

/// Short fields, one per step, each under a k-gram, for the seam row.
const FIELD_A: &str = "north slope rows seven to twelve, late pears";
const FIELD_B: &str = "south terrace rows one to six, early quinces";

/// The relay window, in seconds; the rows advance the frozen clock past it.
const WINDOW_SECS: u64 = 1;

fn text(text: &str) -> Value {
    json!({"content": [{"type": "text", "text": text}], "isError": false})
}

/// A backend that answers every call with `answer` (the last answer repeats).
fn answering(answer: &str) -> Arc<MockBackend> {
    MockBackend::answering(Answer::Sequence(vec![text(answer)]))
}

/// The row's gateway: three callers allowed `mock`, `alpha` and `beta`; the
/// `block` relay detector over `alpha:*` with every k-gram kept and one shared
/// fingerprint enough to refuse; and the handle that ages its receipts.
struct Rig {
    state: Arc<AppState>,
    _store: tempfile::TempDir,
    relay: Arc<Firewall>,
    alpha: Arc<MockBackend>,
    beta: Arc<MockBackend>,
}

async fn rig(alpha_text: &str, beta_text: &str, playbook: Option<&str>) -> Rig {
    rig_with(alpha_text, beta_text, playbook, Sensitivity::Rule).await
}

/// How step A's text is made sensitive.
#[derive(Clone, Copy)]
enum Sensitivity {
    /// A `sources` rule over `alpha:*`.
    Rule,
    /// No `sources` rule: a context-integrity verdict (personal data, monitor
    /// only) on the step's result.
    Verdict,
}

async fn rig_with(
    alpha_text: &str,
    beta_text: &str,
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
                        Sensitivity::Rule => vec![format!("{ALPHA}:*")],
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
    let mut auth = three_principal_auth();
    for key in &mut auth.api_keys {
        key.backends.extend([ALPHA.to_string(), BETA.to_string()]);
    }
    let definition: Option<crate::playbook::PlaybookDefinition> =
        playbook.map(|p| serde_yaml::from_str(p).expect("playbook fixture must parse"));
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
    let alpha = answering(alpha_text);
    let beta = answering(beta_text);
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
    async fn refused(&self, who: &str, id: i64, relayed: &str) -> bool {
        let reply = post(&self.state, who, sync_invoke(id, json!({"text": relayed}))).await;
        if reply["error"]["code"] == -32002 {
            return true;
        }
        assert!(
            !reply.to_string().contains(relayed),
            "the probe must not deliver the tested text: {reply}"
        );
        false
    }

    /// Join every task worker, then age the receipts past the window.
    async fn lapse(&self) {
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
    fn calls(&self) -> (usize, usize) {
        (self.alpha.calls(), self.beta.calls())
    }
}

/// A two-step chain: A then B.
fn chain() -> Value {
    json!({"chain": [
        {"tool": format!("{ALPHA}:{TOOL}"), "arguments": {}},
        {"tool": format!("{BETA}:{TOOL}"), "arguments": {}},
    ]})
}

/// A playbook of one step on each of `alpha` and `beta`, its output mapping
/// both steps' text.
fn playbook() -> String {
    format!(
        "name: replay\ndescription: plan steps\non_error: continue\ninputs: {{}}\nsteps:\n\
         \x20 - name: s1\n    server: {ALPHA}\n    tool: {TOOL}\n\
         \x20 - name: s2\n    server: {BETA}\n    tool: {TOOL}\n\
         output:\n  type: object\n  properties:\n\
         \x20   a:\n      path: $s1.content[0].text\n\
         \x20   b:\n      path: $s2.content[0].text\n"
    )
}

fn playbook_args() -> Value {
    json!({"name": "replay", "arguments": {}})
}

/// A task-augmented `name` call with `arguments`, under idempotency `key`.
fn task_call(id: i64, key: &str, name: &str, arguments: Value) -> Value {
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
fn keyed_call(id: i64, key: &str, name: &str, arguments: Value) -> Value {
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
    async fn settle_task(&self, key: &str, name: &str, arguments: Value) -> String {
        let created = post(&self.state, "key-a", task_call(1, key, name, arguments)).await;
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
            "premise: both steps dispatched, one call each (two distinct targets)"
        );
        task
    }

    /// The shared tail of every route row: the receipt lapsed (P1), `reread`
    /// ran nothing (P2), and bob relaying A's text is then refused.
    async fn renews_after(&self, relayed: &str, reread: impl std::future::Future<Output = Value>) {
        self.lapse().await;
        assert!(
            !self.refused("key-b", 100, relayed).await,
            "premise P1: the live receipt lapsed"
        );
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
        assert!(
            self.refused("key-b", 101, relayed).await,
            "the re-read renewed no receipt for the step's text"
        );
    }
}

/// R1 (REPLAY.5): alice's `tasks/get` of a completed chain task renews step
/// A's receipt.
#[tokio::test]
async fn a_plan_task_read_renews_each_step_receipt() {
    let rig = rig(PROSE, OTHER_PROSE, None).await;
    let task = rig.settle_task("r1", "gateway_execute", chain()).await;
    rig.renews_after(PROSE, get_task(&rig.state, "key-a", &task))
        .await;
}

/// R2 (REPLAY.5): the same for a two-step playbook task.
#[tokio::test]
async fn a_playbook_task_read_renews_each_step_receipt() {
    let rig = rig(PROSE, OTHER_PROSE, Some(&playbook())).await;
    let task = rig
        .settle_task("r2", "gateway_run_playbook", playbook_args())
        .await;
    rig.renews_after(PROSE, get_task(&rig.state, "key-a", &task))
        .await;
}

/// R3 (REPLAY.6): a keyed synchronous `gateway_execute` repeated is served
/// from the retained answer, and that delivery renews step A's receipt.
#[tokio::test]
async fn a_keyed_chain_replay_renews_each_step_receipt() {
    let rig = rig(PROSE, OTHER_PROSE, None).await;
    let first = post(
        &rig.state,
        "key-a",
        keyed_call(1, "r3", "gateway_execute", chain()),
    )
    .await;
    assert!(first.get("error").is_none(), "base: delivered: {first}");
    assert_eq!(rig.calls(), (1, 1), "premise: both steps dispatched");
    rig.renews_after(
        PROSE,
        post(
            &rig.state,
            "key-a",
            keyed_call(2, "r3", "gateway_execute", chain()),
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
        keyed_call(1, "r4", "gateway_run_playbook", playbook_args()),
    )
    .await;
    assert!(first.get("error").is_none(), "base: delivered: {first}");
    assert_eq!(rig.calls(), (1, 1), "premise: both steps dispatched");
    rig.renews_after(
        PROSE,
        post(
            &rig.state,
            "key-a",
            keyed_call(2, "r4", "gateway_run_playbook", playbook_args()),
        ),
    )
    .await;
}

/// G29 (REPLAY.5, red): alice repeats the task-augmented call itself; the
/// existing task is served (the Existing arm), and that delivery renews.
#[tokio::test]
async fn a_task_augmented_repeat_renews() {
    let rig = rig(PROSE, OTHER_PROSE, None).await;
    rig.settle_task("g29", "gateway_execute", chain()).await;
    rig.renews_after(
        PROSE,
        post(
            &rig.state,
            "key-a",
            task_call(1, "g29", "gateway_execute", chain()),
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
        carol.to_string().contains("north slope"),
        "premise: carol was delivered A's text: {carol}"
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
    let pair = format!("{FIELD_A}{FIELD_B}");
    assert!(
        !rig.refused("key-b", 60, FIELD_A).await && !rig.refused("key-b", 61, FIELD_B).await,
        "premise: neither field alone is matched"
    );
    assert!(
        rig.refused("key-b", 62, &pair).await,
        "premise: the live seam is receipted"
    );
    rig.renews_after(&pair, get_task(&rig.state, "key-a", &task))
        .await;
}

/// R7 (REPLAY.6): no `sources` rule; step A is sensitive only by its
/// context-integrity verdict (personal data), which sits on the step's result
/// and which the playbook's output mapping drops. A keyed replay of the
/// playbook still renews A's receipt as sensitive. (Synchronous: on the task
/// path the live settlement itself loses the verdict, reported separately.)
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
    let first = post(
        &rig.state,
        "key-a",
        keyed_call(1, "r7", "gateway_run_playbook", playbook_args()),
    )
    .await;
    assert!(first.get("error").is_none(), "base: delivered: {first}");
    assert!(
        !first.to_string().contains("personal_data"),
        "premise: the output mapping dropped the step's verdict: {first}"
    );
    assert!(
        rig.refused("key-b", 70, &classified).await,
        "premise: the live receipt is sensitive by the step's verdict alone"
    );
    rig.renews_after(
        &classified,
        post(
            &rig.state,
            "key-a",
            keyed_call(2, "r7", "gateway_run_playbook", playbook_args()),
        ),
    )
    .await;
}

/// The gateway's recovery advice for a tool error it reads as a parameter
/// problem: the gateway's own text, longer than a k-gram.
const SUGGEST: &str =
    "Check the tool's input schema, correct the offending parameter(s), and retry.";

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
    let first = post(&off, "key-a", keyed_call(1, "r9", "gateway_invoke", call())).await;
    assert!(
        first.to_string().contains(SUGGEST),
        "premise: the gateway wrote its advice into the answer: {first}"
    );
    assert_eq!(erring.calls(), 1, "premise: the call dispatched once");

    // Second gateway: the same retained answers, relay detection on.
    let relay = Arc::new(
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
    let admission = Arc::clone(off.meta_mcp.execution_admission());
    let handle = Arc::clone(&relay);
    let (on, _on_store) = super::super::meta_fixture::test_router_app_state_with_meta_and_firewall(
        &auth,
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
    register(&on, ALPHA, &erring);
    let probe = |state: &Arc<AppState>, who: &'static str, id: i64, relayed: String| {
        let state = Arc::clone(state);
        async move {
            let reply = post(&state, who, sync_invoke(id, json!({"text": relayed}))).await;
            reply["error"]["code"] == -32002
        }
    };
    assert!(
        !probe(&on, "key-b", 90, note.clone()).await,
        "premise P1: nothing is receipted on the new gateway yet"
    );
    let replay = post(&on, "key-a", keyed_call(2, "r9", "gateway_invoke", call())).await;
    assert!(
        replay.to_string().contains(SUGGEST),
        "premise: the retained answer, advice included, was replayed: {replay}"
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
