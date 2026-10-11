// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8323 engine rows: a playbook never hands a step's sealed continuation
//! envelope to another step's backend. The asking step's result carries a
//! REAL envelope minted by a real `ContinuationState`, so the oracle (does a
//! recorded argument contain that exact string) does not depend on the code
//! under test.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};

use super::*;
use crate::protocol::continuation::{
    ContinuationState, ProbeBudget, ProbeRefusal, sealed_state_in,
};
/// A real envelope, minted for a test exchange.
async fn real_envelope(state: &ContinuationState) -> String {
    let now = crate::protocol::continuation::now_unix_secs();
    let payload = state
        .begin_exchange(
            "srv".into(),
            None,
            "fp".into(),
            &crate::protocol::continuation::QuotaKey::for_test("fp"),
            "digest".into(),
            now,
        )
        .await
        .expect("a fresh state has a slot");
    state.keyring().mint(&payload).expect("the envelope seals")
}

/// Answers `ask` with a result whose `requestState` is the envelope, `inner`
/// with a nested output carrying it, anything else with `{"ok": true}`, and
/// records every call's arguments.
struct Recording {
    state: ContinuationState,
    envelope: String,
    seen: Mutex<Vec<(String, Value)>>,
    /// Envelope opens the engine's probe spent, across every step.
    opens: AtomicUsize,
}

#[async_trait::async_trait]
impl ToolInvoker for Recording {
    async fn invoke(&self, _server: &str, tool: &str, arguments: Value) -> crate::Result<Value> {
        self.seen.lock().unwrap().push((tool.to_owned(), arguments));
        Ok(match tool {
            "ask" => json!({"resultType": "input_required",
                            "inputRequests": {"k1": {"method": "elicitation/create"}},
                            "requestState": self.envelope}),
            "inner" => json!({"output": {"token": self.envelope}}),
            // Fails its first dispatch with an ordinary (retryable) error.
            "flaky" if self.dispatched("flaky") == 1 => {
                return Err(crate::Error::Internal("flaky".into()));
            }
            _ => json!({"ok": true}),
        })
    }

    fn sealed_state_in(
        &self,
        value: &Value,
        budget: &mut ProbeBudget,
    ) -> Result<bool, ProbeRefusal> {
        let before = budget.spent();
        let found = sealed_state_in(self.state.keyring(), value, budget);
        self.opens
            .fetch_add(budget.spent() - before, Ordering::SeqCst);
        found
    }
}

impl Recording {
    /// How many times `tool` was dispatched.
    fn dispatched(&self, tool: &str) -> usize {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|(t, _)| t == tool)
            .count()
    }

    /// The tools whose recorded arguments contain the envelope.
    fn carried(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, arguments)| arguments.to_string().contains(&self.envelope))
            .map(|(tool, _)| tool.clone())
            .collect()
    }
}

/// `first` (a step named after its tool) then `stage(arguments)`, continuing
/// past a refused step.
fn two_steps(first: &str, stage_arguments: &Value) -> PlaybookDefinition {
    serde_json::from_value(json!({
        "playbook": "1.0",
        "name": "carry",
        "description": "a later step references an earlier step's result",
        "on_error": "continue",
        "steps": [
            { "name": first, "tool": first, "server": "srv", "arguments": {} },
            { "name": "stage", "tool": "stage", "server": "srv", "arguments": stage_arguments }
        ]
    }))
    .expect("the playbook deserialises")
}

async fn recording() -> Recording {
    let state = ContinuationState::new();
    Recording {
        envelope: real_envelope(&state).await,
        state,
        seen: Mutex::default(),
        opens: AtomicUsize::new(0),
    }
}

/// The producer ran once, then the stage step was refused for carrying the
/// envelope and never dispatched (seats c1: an unrelated failure must not
/// satisfy a "nothing reached a backend" row).
fn assert_refused_after(invoker: &Recording, ran: &crate::Result<PlaybookResult>, producer: &str) {
    assert_eq!(
        invoker.dispatched(producer),
        1,
        "setup: {producer} did not run"
    );
    assert_eq!(
        invoker.dispatched("stage"),
        0,
        "the stage step was dispatched"
    );
    let reason = ran
        .as_ref()
        .ok()
        .and_then(|result| result.step_errors.get("stage"))
        .cloned()
        .unwrap_or_default();
    assert!(
        reason.contains("sealed continuation"),
        "the stage step was not refused for the envelope: {ran:?}"
    );
}

/// R11: the envelope inside an array element of a step's arguments (the
/// whole asking step, as one element) reaches no backend. Red on base.
#[tokio::test]
async fn r11_an_envelope_in_an_array_element_reaches_no_backend() {
    let invoker = recording().await;
    let mut engine = PlaybookEngine::new();
    engine.register(two_steps("ask", &json!({ "list": ["$ask"] })));
    let ran = engine.execute("carry", json!({}), &invoker).await;
    assert_refused_after(&invoker, &ran, "ask");
    assert!(
        invoker.carried().is_empty(),
        "the envelope reached: {:?}",
        invoker.carried()
    );
}

/// R12: a nested result maps the envelope to a path that does not name
/// `requestState` (`$inner.output.token`). The load-time check admits it; the
/// run-time check must refuse it. Red on base.
#[tokio::test]
async fn r12_an_envelope_under_another_name_reaches_no_backend() {
    let invoker = recording().await;
    let mut engine = PlaybookEngine::new();
    engine.register(two_steps("inner", &json!({ "t": "$inner.output.token" })));
    let ran = engine.execute("carry", json!({}), &invoker).await;
    assert_refused_after(&invoker, &ran, "inner");
    assert!(
        invoker.carried().is_empty(),
        "the envelope reached: {:?}",
        invoker.carried()
    );
}

/// R4: a step argument that names a step's `requestState`, in any spelling the
/// resolver accepts, refuses the playbook, naming the step and the
/// reference; `requestStateOfX` is another field and runs. Red on base: every
/// definition runs.
#[tokio::test]
async fn r4_a_reference_to_a_steps_request_state_is_refused_by_name() {
    for reference in [
        json!("$ask.requestState"),
        json!("$ask..requestState"),
        json!("$sub.output.requestState"),
        json!("note: $ask.requestState"),
        json!({ "nested": ["$ask.requestState"] }),
    ] {
        let invoker = recording().await;
        let mut engine = PlaybookEngine::new();
        engine.register(two_steps("ask", &json!({ "x": reference })));
        let refused = engine.execute("carry", json!({}), &invoker).await;
        let message = match &refused {
            Err(error) => error.to_string(),
            Ok(result) => panic!(
                "{reference}: the playbook ran: {:?}",
                result.steps_completed
            ),
        };
        assert!(
            message.contains("stage") && message.contains("requestState"),
            "{reference}: the refusal does not name the step and reference: {message}"
        );
        assert!(
            !invoker
                .seen
                .lock()
                .unwrap()
                .iter()
                .any(|(tool, _)| tool == "stage"),
            "{reference}: the refused playbook still dispatched its step"
        );
    }
    let invoker = recording().await;
    let mut engine = PlaybookEngine::new();
    engine.register(two_steps("ask", &json!({ "x": "$ask.requestStateOfX" })));
    assert!(
        engine.execute("carry", json!({}), &invoker).await.is_ok(),
        "requestStateOfX names another field and must run"
    );
    assert_eq!(invoker.dispatched("stage"), 1, "the stage step did not run");
}

/// R5: `load_from_directory` skips a playbook whose step names a step's
/// `requestState`, and still loads its neighbour. Red on base: both load.
#[test]
fn r5_loading_skips_a_playbook_that_names_a_request_state() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bad = "playbook: '1.0'\nname: bad\ndescription: d\nsteps:\n  - {name: ask, tool: ask, server: srv, arguments: {}}\n  - {name: stage, tool: stage, server: srv, arguments: {x: '$ask.requestState'}}\n";
    let good = "playbook: '1.0'\nname: good\ndescription: d\nsteps:\n  - {name: ask, tool: ask, server: srv, arguments: {}}\n";
    std::fs::write(dir.path().join("bad.yaml"), bad).expect("write");
    std::fs::write(dir.path().join("good.yaml"), good).expect("write");
    let mut engine = PlaybookEngine::new();
    let loaded = engine
        .load_from_directory(dir.path().to_str().expect("utf-8 path"))
        .expect("the directory reads");
    assert!(
        engine.get("good").is_some(),
        "setup: the good playbook loads"
    );
    assert!(
        engine.get("bad").is_none(),
        "a playbook naming a requestState loaded"
    );
    assert_eq!(loaded, 1, "only the good playbook counts as loaded");
}

/// `count` framed near-misses: the real envelope with one ciphertext
/// character changed, so each passes the gate and fails to open.
fn near_misses(envelope: &str, count: usize) -> Vec<String> {
    (0..count)
        .map(|n| {
            let mut chars: Vec<char> = envelope.chars().collect();
            let at = 30 + n;
            chars[at] = if chars[at] == 'A' { 'B' } else { 'A' };
            chars.into_iter().collect()
        })
        .collect()
}

/// A one-step playbook `strategy`, whose `tool` step takes `arguments`.
fn one_step(tool: &str, arguments: &Value, strategy: &str) -> PlaybookDefinition {
    serde_json::from_value(json!({
        "playbook": "1.0", "name": "carry", "description": "probe budget",
        "on_error": strategy, "max_retries": 2,
        "steps": [ { "name": tool, "tool": tool, "server": "srv", "arguments": arguments } ]
    }))
    .expect("the playbook deserialises")
}

async fn run(
    invoker: &Recording,
    definition: PlaybookDefinition,
    inputs: Value,
) -> crate::Result<PlaybookResult> {
    let mut engine = PlaybookEngine::new();
    engine.register(definition);
    engine.execute("carry", inputs, invoker).await
}

/// R8: 1,000 gate rejects (about 1 MiB) cost no open and the step runs; the
/// same rejects followed by 17 framed near-misses cost exactly 16 opens, then
/// the step is refused on the cap and never dispatched. A removed gate spends
/// the budget on the rejects and fails the first half.
#[tokio::test]
async fn r8_the_gate_opens_no_reject_and_the_cap_refuses_the_seventeenth() {
    let rejects: Vec<String> = (0..1_000)
        .map(|_| format!("B{}", "A".repeat(1_000)))
        .collect();
    let invoker = recording().await;
    let definition = one_step("stage", &json!({ "items": "$inputs.items" }), "abort");
    let ran = run(&invoker, definition.clone(), json!({ "items": rejects })).await;
    assert!(ran.is_ok(), "rejects alone were refused: {ran:?}");
    assert_eq!(
        invoker.opens.load(Ordering::SeqCst),
        0,
        "a gate reject was opened"
    );

    let invoker = recording().await;
    let mut items = rejects;
    items.extend(near_misses(&invoker.envelope, 17));
    let refused = run(&invoker, definition, json!({ "items": items })).await;
    let message = refused
        .expect_err("the seventeenth candidate must refuse")
        .to_string();
    assert!(
        message.contains("too many"),
        "not the cap refusal: {message}"
    );
    assert_eq!(invoker.opens.load(Ordering::SeqCst), 16);
    assert_eq!(
        invoker.dispatched("stage"),
        0,
        "the refused step was dispatched"
    );
}

/// R8b: the budget is per step, not per reference: 17 near-misses split 9 and
/// 8 across two references still refuse after 16 opens.
#[tokio::test]
async fn r8b_the_budget_spans_every_reference_of_a_step() {
    let invoker = recording().await;
    let mut a = near_misses(&invoker.envelope, 17);
    let b = a.split_off(9);
    let definition = one_step(
        "stage",
        &json!({ "a": "$inputs.a", "b": "$inputs.b" }),
        "abort",
    );
    let refused = run(&invoker, definition, json!({ "a": a, "b": b })).await;
    assert!(refused.is_err(), "17 candidates over two references ran");
    assert_eq!(invoker.opens.load(Ordering::SeqCst), 16);
    assert_eq!(invoker.dispatched("stage"), 0);
}

/// R14: a retried step is checked once: 9 near-misses cost 9 opens across
/// both attempts. Re-checking inside the retry loop would cost 18.
#[tokio::test]
async fn r14_a_retry_does_not_recheck_or_refill_the_budget() {
    let invoker = recording().await;
    let definition = one_step("flaky", &json!({ "items": "$inputs.items" }), "retry");
    let items = near_misses(&invoker.envelope, 9);
    let ran = run(&invoker, definition, json!({ "items": items })).await;
    assert!(ran.is_ok(), "the retried step failed: {ran:?}");
    assert_eq!(
        invoker.dispatched("flaky"),
        2,
        "setup: the step was not retried"
    );
    assert_eq!(invoker.opens.load(Ordering::SeqCst), 9);
}

/// gpt c1: a malformed reference (`$missing.[`) in a loaded playbook does not
/// panic the load check; the playbook loads (it names no `requestState`).
#[test]
fn loading_a_malformed_reference_does_not_panic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let odd = "playbook: '1.0'\nname: odd\ndescription: d\nsteps:\n  - {name: s, tool: t, server: srv, arguments: {x: '$missing.['}}\n";
    std::fs::write(dir.path().join("odd.yaml"), odd).expect("write");
    let mut engine = PlaybookEngine::new();
    let loaded = engine
        .load_from_directory(dir.path().to_str().expect("utf-8 path"))
        .expect("the directory reads");
    assert_eq!(loaded, 1);
}

/// grok c2: under a clock that reads before 1970, a step whose arguments carry
/// a framed candidate is refused with the clock reason and never dispatched.
#[tokio::test]
async fn an_unreadable_clock_refuses_the_step_before_dispatch() {
    let invoker = recording().await;
    let mut engine = PlaybookEngine::new();
    engine.register(two_steps("ask", &json!({ "x": "$ask" })));
    let _clock = crate::clock::test_clock::before_epoch();
    let ran = engine.execute("carry", json!({}), &invoker).await;
    assert_eq!(invoker.dispatched("ask"), 1, "setup: ask did not run");
    assert_eq!(
        invoker.dispatched("stage"),
        0,
        "the stage step was dispatched"
    );
    let reason = ran
        .as_ref()
        .ok()
        .and_then(|result| result.step_errors.get("stage"))
        .cloned()
        .unwrap_or_default();
    assert!(
        reason.contains("clock is unreadable"),
        "not the clock refusal: {ran:?}"
    );
}
