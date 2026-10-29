// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8429: a step that meets a transient custody Busy ends the plan, and a
//! step whose tool answers `isError` is a failed step (merged MIK-8329).
//! Rows STEP.1 (the Busy ends the plan, under every policy, with no null fill
//! and no successor), STEP.2/STEP.3 (an ordinary error, a look-alike of the
//! Busy's text included, keeps today's policy) and PBERR.1 (an `isError`
//! result follows `on_error`, but is never re-sent: the tool ran, so its side
//! effect may be done; the MIK-8429 hold, D1). D3: the tool's text never
//! reaches an error message (so no log line), only the error's data, capped.

use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use serde_json::json;

/// What a scripted step answers.
#[derive(Clone, Copy)]
enum Answer {
    Served,
    /// The gateway-sealed transient a busy custody raises before any send.
    Busy,
    /// The same code, text and data, without the gateway's seal.
    LookAlike,
    /// A tool that failed in the success channel: `{"isError": true}`.
    ToolError,
    /// A tool error whose text is 10,000 characters long (D3).
    LongToolError,
    /// A connection never made on the first call (the one failure re-sent), [`Self::Busy`] after it.
    TransportThenBusy,
    /// A connection never made on the first call, [`Self::Served`] after it.
    TransportThenServed,
}

fn look_alike() -> crate::Error {
    crate::Error::JsonRpc {
        code: -32603,
        message: "temporarily unavailable, retry".to_owned(),
        data: Some(json!({"retryable": true})),
    }
}

/// Answers each tool as scripted and counts the calls each one receives.
struct Scripted {
    script: HashMap<&'static str, Answer>,
    calls: parking_lot::Mutex<HashMap<String, usize>>,
    total: AtomicUsize,
}

impl Scripted {
    fn new(script: &[(&'static str, Answer)]) -> Self {
        Self {
            script: script.iter().copied().collect(),
            calls: parking_lot::Mutex::default(),
            total: AtomicUsize::new(0),
        }
    }

    fn calls(&self, tool: &str) -> usize {
        self.calls.lock().get(tool).copied().unwrap_or(0)
    }
}

#[async_trait::async_trait]
impl ToolInvoker for Scripted {
    async fn invoke(&self, _server: &str, tool: &str, _arguments: Value) -> crate::Result<Value> {
        let call = {
            let mut calls = self.calls.lock();
            let count = calls.entry(tool.to_owned()).or_default();
            *count += 1;
            *count
        };
        self.total.fetch_add(1, Ordering::SeqCst);
        let answer = match self.script.get(tool).copied().unwrap_or(Answer::Served) {
            Answer::TransportThenBusy | Answer::TransportThenServed if call == 1 => {
                return Err(crate::Error::TransportConnect(
                    "connection refused".to_owned(),
                ));
            }
            Answer::TransportThenBusy => Answer::Busy,
            Answer::TransportThenServed => Answer::Served,
            other => other,
        };
        match answer {
            // `TransportThenServed` after its first call (resolved above).
            Answer::Served | Answer::TransportThenServed => Ok(json!({"served": tool})),
            // `TransportThenBusy` after its first call (resolved above).
            Answer::Busy | Answer::TransportThenBusy => Err(
                crate::personal_accounts::refusal::transient_retry_error(None),
            ),
            Answer::LookAlike => Err(look_alike()),
            Answer::ToolError => Ok(json!({
                "isError": true,
                "content": [{"type": "text", "text": format!("{tool} failed upstream")}],
            })),
            Answer::LongToolError => Ok(json!({
                "isError": true,
                "content": [{"type": "text", "text": "q".repeat(10_000)}],
            })),
        }
    }

    fn sealed_state_in(
        &self,
        _value: &Value,
        _budget: &mut crate::protocol::continuation::ProbeBudget,
    ) -> Result<bool, crate::protocol::continuation::ProbeRefusal> {
        // A test double holds no keyring, so it sealed nothing.
        Ok(false)
    }
}

fn step(name: &str) -> PlaybookStep {
    PlaybookStep {
        name: name.to_string(),
        tool: name.to_string(),
        server: "test".to_string(),
        arguments: HashMap::new(),
        condition: None,
    }
}

async fn run(
    on_error: ErrorStrategy,
    steps: &[&str],
    invoker: &Scripted,
) -> crate::Result<PlaybookResult> {
    let mut engine = PlaybookEngine::new();
    engine.register(PlaybookDefinition {
        playbook: "1.0".to_string(),
        name: "busy".to_string(),
        description: "a busy step".to_string(),
        inputs: json!({}),
        steps: steps.iter().copied().map(step).collect(),
        output: None,
        on_error,
        max_retries: 3,
        timeout: 60,
    });
    engine.execute("busy", json!({}), invoker).await
}

/// The tool's text a step failure carries in its data (D3), if any.
fn tool_text(error: &crate::Error) -> Option<&str> {
    match error {
        crate::Error::JsonRpc {
            data: Some(data), ..
        } => data["tool_text"].as_str(),
        _ => None,
    }
}

fn is_sealed_transient(error: &crate::Error) -> bool {
    crate::personal_accounts::refusal::transient_data(error).is_some()
}

/// STEP.1, first step: under every policy the Busy ends the plan with the
/// sealed retryable error, the step is called once (no in-plan retry), and
/// its successor never starts. Red on the line: `continue` and `retry`
/// null-fill the step and run `second`, and `retry` calls `first` three times.
#[tokio::test]
async fn a_busy_first_step_ends_the_plan_retryable_under_every_policy() {
    for policy in [
        ErrorStrategy::Abort,
        ErrorStrategy::Continue,
        ErrorStrategy::Retry,
    ] {
        let invoker = Scripted::new(&[("first", Answer::Busy)]);
        let outcome = run(policy, &["first", "second"], &invoker).await;
        let error = match outcome {
            Ok(result) => panic!(
                "STEP.1 {policy:?}: the plan carried on past a busy step: failed {:?}, completed {:?}",
                result.steps_failed, result.steps_completed
            ),
            Err(error) => error,
        };
        assert!(
            is_sealed_transient(&error) && error.is_pre_dispatch(),
            "STEP.1 {policy:?}: not the sealed, unsent retryable error: {error}"
        );
        assert_eq!(
            invoker.calls("second"),
            0,
            "STEP.1 {policy:?}: a successor started"
        );
        assert_eq!(
            invoker.calls("first"),
            1,
            "STEP.1 {policy:?}: the busy step was retried in the plan"
        );
    }
}

/// STEP.1, after a completed step: the plan still ends, but an earlier step
/// may have reached its backend, so the error must no longer read as unsent
/// (`is_pre_dispatch`): it would free the run's key for a re-run of `first`.
/// Red on the line: `continue` null-fills `second` and runs `third`.
#[tokio::test]
async fn a_busy_step_after_a_completed_one_ends_the_plan_as_possibly_sent() {
    for policy in [
        ErrorStrategy::Abort,
        ErrorStrategy::Continue,
        ErrorStrategy::Retry,
    ] {
        let invoker = Scripted::new(&[("second", Answer::Busy)]);
        let outcome = run(policy, &["first", "second", "third"], &invoker).await;
        let Err(error) = outcome else {
            panic!("STEP.1 {policy:?}: the plan carried on past a busy step");
        };
        assert!(
            !error.is_pre_dispatch(),
            "STEP.1 {policy:?}: the plan's error reads as unsent after `first` ran: {error}"
        );
        assert_eq!(
            invoker.calls("third"),
            0,
            "STEP.1 {policy:?}: a successor started"
        );
        assert_eq!(invoker.calls("first"), 1, "{policy:?}: premise");
    }
}

/// STEP.2 / STEP.3 negative control: the Busy's look-alike, the same code,
/// text and `retryable` data without the gateway's seal, is an ordinary
/// error and keeps its policy: `continue` null-fills it and runs the
/// successor, `retry` records it after one call (a backend's error answer
/// follows a send, so it is not re-sent) and runs the successor,
/// `abort` returns it unchanged. Red if Busy is recognised from its text.
#[tokio::test]
async fn an_ordinary_step_error_keeps_its_policy() {
    let invoker = Scripted::new(&[("first", Answer::LookAlike)]);
    let result = run(ErrorStrategy::Continue, &["first", "second"], &invoker)
        .await
        .expect("STEP.2 continue: the plan carries on");
    assert_eq!(result.steps_failed, vec!["first"]);
    assert_eq!(result.steps_completed, vec!["second"]);
    assert_eq!(result.output["first"], Value::Null);
    assert!(result.step_errors.contains_key("first"));

    let invoker = Scripted::new(&[("first", Answer::LookAlike)]);
    let result = run(ErrorStrategy::Retry, &["first", "second"], &invoker)
        .await
        .expect("STEP.2 retry: the plan carries on");
    assert_eq!(
        invoker.calls("first"),
        1,
        "STEP.2 retry: a backend's error answer is not re-sent"
    );
    assert_eq!(result.steps_completed, vec!["second"]);

    let invoker = Scripted::new(&[("first", Answer::LookAlike)]);
    let error = run(ErrorStrategy::Abort, &["first", "second"], &invoker)
        .await
        .expect_err("STEP.2 abort: the plan stops");
    assert!(error.to_string().contains("temporarily unavailable, retry"));
    assert!(!is_sealed_transient(&error));
    assert_eq!(invoker.calls("second"), 0);
    assert_eq!(invoker.total.load(Ordering::SeqCst), 1);
}

/// STEP.1, after a FAILED step: an ordinary error may have been raised after
/// its send, so a later Busy also ends the plan as possibly sent. Red on the
/// line: `continue` and `retry` run `third`.
#[tokio::test]
async fn a_busy_step_after_a_failed_one_ends_the_plan_as_possibly_sent() {
    for policy in [ErrorStrategy::Continue, ErrorStrategy::Retry] {
        let invoker = Scripted::new(&[("first", Answer::LookAlike), ("second", Answer::Busy)]);
        let outcome = run(policy, &["first", "second", "third"], &invoker).await;
        let Err(error) = outcome else {
            panic!("STEP.1 {policy:?}: the plan carried on past a busy step");
        };
        assert!(
            !error.is_pre_dispatch() && !is_sealed_transient(&error),
            "STEP.1 {policy:?}: the plan's error reads as unsent after `first` was tried: {error}"
        );
        assert_eq!(
            invoker.calls("third"),
            0,
            "STEP.1 {policy:?}: a successor started"
        );
    }
}

/// PBERR.1, abort: an `isError` result stops the plan with an error carrying
/// the tool's text, and the successor never starts. Red on the line: the
/// step is recorded completed and `second` runs.
#[tokio::test]
async fn a_tool_error_step_aborts_an_abort_plan() {
    let invoker = Scripted::new(&[("first", Answer::ToolError)]);
    let outcome = run(ErrorStrategy::Abort, &["first", "second"], &invoker).await;
    let Err(error) = outcome else {
        panic!("PBERR.1 abort: an isError step was recorded completed");
    };
    assert!(
        !error.to_string().contains("first failed upstream")
            && error.to_string().contains("the tool reported an error"),
        "D3 abort: the tool's text is in the message, so in every log line: {error}"
    );
    assert_eq!(
        tool_text(&error),
        Some("first failed upstream"),
        "D3 abort: the caller still gets the tool's text, as data"
    );
    assert!(!error.is_pre_dispatch(), "PBERR.1 abort: {error}");
    assert_eq!(
        invoker.calls("second"),
        0,
        "PBERR.1 abort: a successor started"
    );
}

/// PBERR.1, continue: the step is failed, null-filled with its reason, and
/// the successor runs. Red on the line: `first` is recorded completed with the
/// error value as its result.
#[tokio::test]
async fn a_tool_error_step_is_null_filled_under_continue() {
    let invoker = Scripted::new(&[("first", Answer::ToolError)]);
    let result = run(ErrorStrategy::Continue, &["first", "second"], &invoker)
        .await
        .expect("PBERR.1 continue: the plan carries on");
    assert_eq!(result.steps_failed, vec!["first"], "PBERR.1 continue");
    assert_eq!(result.steps_completed, vec!["second"], "PBERR.1 continue");
    assert_eq!(
        result.output["first"],
        Value::Null,
        "PBERR.1 continue: null fill"
    );
    assert!(
        result
            .step_errors
            .get("first")
            .is_some_and(|reason| reason.contains("first failed upstream")),
        "PBERR.1 continue: the reason is recorded: {:?}",
        result.step_errors
    );
}

/// D1, retry: a tool error is never re-sent. The tool ran and answered, so
/// its side effect (an email, a row) may be done; the step is handled as under
/// continue after one call. Red before the hold fix: called 3 times.
#[tokio::test]
async fn a_tool_error_step_is_not_resent_under_retry() {
    let invoker = Scripted::new(&[("first", Answer::ToolError)]);
    let result = run(ErrorStrategy::Retry, &["first", "second"], &invoker)
        .await
        .expect("D1 retry: the plan carries on");
    assert_eq!(
        invoker.calls("first"),
        1,
        "D1 retry: a tool error was re-sent"
    );
    assert_eq!(result.steps_failed, vec!["first"], "D1 retry");
    assert_eq!(result.steps_completed, vec!["second"], "D1 retry");
    assert!(
        result
            .step_errors
            .get("first")
            .is_some_and(|reason| reason.contains("first failed upstream")),
        "D1 retry: the reason is recorded: {:?}",
        result.step_errors
    );
}

/// D3: a long tool text is capped at 256 characters in the error's data and
/// in `step_errors`, and never reaches the message. Red before the hold fix:
/// 2,048 characters of it are in the message.
#[tokio::test]
async fn a_long_tool_text_is_capped_and_kept_out_of_the_message() {
    let invoker = Scripted::new(&[("first", Answer::LongToolError)]);
    let Err(error) = run(ErrorStrategy::Abort, &["first"], &invoker).await else {
        panic!("D3: an isError step was recorded completed");
    };
    // A run of the tool's `q`s, not a single one: the may-have-run sentence
    // says "request".
    assert!(
        !error.to_string().contains("qq"),
        "D3: the tool's text is in the message: {error}"
    );
    let text = tool_text(&error).expect("D3: the tool's text is in the data");
    assert!(
        text.chars().count() <= 257 && text.ends_with('…'),
        "D3: the data is not capped at 256 characters and marked cut: {} chars",
        text.chars().count()
    );
    // MIK-8667: exact, 256 characters kept and the marker after them.
    assert_eq!(text, format!("{}…", "q".repeat(256)));
    let invoker = Scripted::new(&[("first", Answer::LongToolError)]);
    let result = run(ErrorStrategy::Continue, &["first"], &invoker)
        .await
        .expect("D3 continue: the plan carries on");
    let reason = &result.step_errors["first"];
    // A run, not a count: the reason's own words may hold a `q`.
    assert!(
        !reason.contains(&"q".repeat(257)),
        "D3 continue: step_errors is not capped: {} chars",
        reason.chars().count()
    );
}

/// PBERR.1 control: `isError: false` and a result with no `isError` are
/// completed steps, as today.
#[tokio::test]
async fn a_result_without_is_error_true_is_a_completed_step() {
    struct Answers;
    #[async_trait::async_trait]
    impl ToolInvoker for Answers {
        async fn invoke(&self, _: &str, tool: &str, _: Value) -> crate::Result<Value> {
            Ok(match tool {
                "first" => json!({"isError": false, "content": []}),
                _ => json!({"isError": "true"}),
            })
        }
        fn sealed_state_in(
            &self,
            _value: &Value,
            _budget: &mut crate::protocol::continuation::ProbeBudget,
        ) -> Result<bool, crate::protocol::continuation::ProbeRefusal> {
            Ok(false)
        }
    }
    let mut engine = PlaybookEngine::new();
    engine.register(PlaybookDefinition {
        playbook: "1.0".to_string(),
        name: "fine".to_string(),
        description: "results that are not tool errors".to_string(),
        inputs: json!({}),
        steps: vec![step("first"), step("second")],
        output: None,
        on_error: ErrorStrategy::Abort,
        max_retries: 1,
        timeout: 60,
    });
    let result = engine
        .execute("fine", json!({}), &Answers)
        .await
        .expect("PBERR.1 control: both complete");
    assert_eq!(result.steps_completed, vec!["first", "second"]);
}

/// STEP.1 partial run within one step (C1b): under `retry`, the first attempt
/// of `first` failed before its send and is retried; the retry meets Busy. The
/// plan ends, and its error must not read as unsent: the plan counts every
/// non-busy attempt as possibly sent, conservatively.
#[tokio::test]
async fn a_busy_retry_after_a_transport_failure_ends_the_plan_as_possibly_sent() {
    let invoker = Scripted::new(&[("first", Answer::TransportThenBusy)]);
    let outcome = run(ErrorStrategy::Retry, &["first", "second"], &invoker).await;
    let Err(error) = outcome else {
        panic!("STEP.1 retry: the plan carried on past a busy attempt");
    };
    assert!(
        !error.is_pre_dispatch() && !is_sealed_transient(&error),
        "STEP.1 retry: the error reads as unsent after an attempt ran: {error}"
    );
    assert_eq!(
        invoker.calls("first"),
        2,
        "STEP.1 retry: stopped at the busy attempt"
    );
    assert_eq!(
        invoker.calls("second"),
        0,
        "STEP.1 retry: a successor started"
    );
}

/// D1 control: a failure before the send is still retried, and the
/// served retry is the step's result.
#[tokio::test]
async fn a_transport_failure_then_a_served_retry_completes_the_step() {
    let invoker = Scripted::new(&[("first", Answer::TransportThenServed)]);
    let result = run(ErrorStrategy::Retry, &["first", "second"], &invoker)
        .await
        .expect("PBERR.1 retry: the plan completes");
    assert_eq!(invoker.calls("first"), 2, "PBERR.1 retry: one retry");
    assert_eq!(result.steps_completed, vec!["first", "second"]);
    assert!(result.steps_failed.is_empty(), "{:?}", result.steps_failed);
    assert_eq!(result.output["first"], json!({"served": "first"}));
}
