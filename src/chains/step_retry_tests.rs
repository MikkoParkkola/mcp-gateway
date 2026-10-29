// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A chain step is re-sent only after an error raised before its request was
//! sent. A step whose request may have reached the backend runs once, and its
//! result says it may have run.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use super::ChainExecutor;
use crate::Error;
use crate::chains::{Chain, ChainCheckpointStore, ChainRetryPolicy, ChainStep, StepState};
use crate::playbook::ToolInvoker;

/// A row's label and the error its first call answers.
type Case = (&'static str, fn() -> Error);

/// One scripted answer per call; past the script every call succeeds.
type Answer = Box<dyn FnOnce() -> crate::Result<Value> + Send>;

/// An invoker that answers from a script and counts its calls.
struct Scripted {
    answers: Mutex<VecDeque<Answer>>,
    calls: AtomicU32,
}

impl Scripted {
    fn new(answers: Vec<Answer>) -> Self {
        Self {
            answers: Mutex::new(answers.into()),
            calls: AtomicU32::new(0),
        }
    }

    fn calls(&self) -> u32 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl ToolInvoker for Scripted {
    fn sealed_state_in(
        &self,
        _value: &Value,
        _budget: &mut crate::protocol::continuation::ProbeBudget,
    ) -> std::result::Result<bool, crate::protocol::continuation::ProbeRefusal> {
        Ok(false)
    }

    async fn invoke(&self, _server: &str, _tool: &str, _arguments: Value) -> crate::Result<Value> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let next = self.answers.lock().expect("script").pop_front();
        next.map_or_else(|| Ok(json!({"ok": true})), |answer| answer())
    }
}

fn answer(error: impl FnOnce() -> Error + Send + 'static) -> Answer {
    Box::new(move || Err(error()))
}

/// A typed HTTP status error, as reqwest raises it.
fn http_status(status: u16) -> Error {
    let response = axum::http::Response::builder()
        .status(status)
        .body(String::new())
        .expect("fixture response builds");
    Error::Http(
        reqwest::Response::from(response)
            .error_for_status()
            .expect_err("a fixture status is non-2xx"),
    )
}

fn retryable_answer(status: u16) -> Error {
    Error::JsonRpcRetryable {
        code: -32000,
        message: "backend error".to_string(),
        status,
        data: None,
    }
}

/// The step result of a one-step chain run against `invoker`, three attempts
/// allowed. `optional` marks the step optional.
async fn run_one(invoker: &Scripted, optional: bool) -> crate::chains::ChainStepResult {
    let dir = tempfile::tempdir().expect("a checkpoint dir");
    let executor = ChainExecutor::new(
        ChainCheckpointStore::new(dir.path()).expect("a store"),
        ChainRetryPolicy::new(3, Duration::from_millis(1)),
    );
    let step = ChainStep::new("pay", "charge_card").input(json!({"amount": 1}));
    let step = if optional { step.optional() } else { step };
    let chain = Chain::new(format!("chain-{}", uuid::Uuid::new_v4())).step(step);
    let result = executor
        .execute(&chain, json!({}), invoker)
        .await
        .expect("the chain runs");
    result.steps.into_iter().next().expect("one step result")
}

fn assert_ran_once(invoker: &Scripted, step: &crate::chains::ChainStepResult, what: &str) {
    assert_eq!(invoker.calls(), 1, "{what}: the step was re-sent");
    assert_eq!(step.state, StepState::Failed, "{what}");
    assert_eq!(step.attempts, 1, "{what}: attempts made, not allowed");
    let error = step.error.as_deref().unwrap_or_default();
    assert!(
        error.ends_with(crate::error::MAY_HAVE_RUN),
        "{what}: {error}"
    );
}

/// MIK-9042.CHAIN.1: each error that can follow a send ends the step after one
/// call, and the step says it may have run.
#[tokio::test]
async fn a_step_whose_request_may_have_reached_the_backend_runs_once() {
    let cases: Vec<Case> = vec![
        ("BackendTimeout", || {
            Error::BackendTimeout("no answer".into())
        }),
        ("Transport", || Error::Transport("stream reset".into())),
        ("Http 500", || http_status(500)),
        ("Io", || Error::Io(std::io::Error::other("broken pipe"))),
        ("JsonRpcRetryable 429", || retryable_answer(429)),
        ("JsonRpcRetryable 503", || retryable_answer(503)),
        ("JsonRpcRetryable 500", || retryable_answer(500)),
    ];
    for (what, error) in cases {
        let invoker = Scripted::new(vec![answer(error)]);
        let step = run_one(&invoker, false).await;
        assert_ran_once(&invoker, &step, what);
    }
}

/// MIK-9042.CHAIN.2: an error raised before the send is still retried.
#[tokio::test]
async fn a_step_refused_before_its_send_is_retried() {
    let cases: Vec<Case> = vec![
        ("TransportConnect", || {
            Error::TransportConnect("connection refused".into())
        }),
        ("BackendUnavailable", || {
            Error::BackendUnavailable("starting".into())
        }),
    ];
    for (what, error) in cases {
        let invoker = Scripted::new(vec![answer(error)]);
        let step = run_one(&invoker, false).await;
        assert_eq!(invoker.calls(), 2, "{what}");
        assert_eq!(step.state, StepState::Completed, "{what}");
        assert_eq!(step.attempts, 2, "{what}");
    }
}

/// MIK-9042.CHAIN.4: a retried pre-send failure, then a lost round: the
/// ceiling holds on the second attempt too.
#[tokio::test]
async fn a_lost_round_after_a_retried_refusal_ends_the_step() {
    let invoker = Scripted::new(vec![
        answer(|| Error::TransportConnect("connection refused".into())),
        answer(|| Error::BackendTimeout("no answer".into())),
    ]);
    let step = run_one(&invoker, false).await;
    assert_eq!(invoker.calls(), 2, "the lost round was re-sent");
    assert_eq!(step.state, StepState::Failed);
    assert_eq!(step.attempts, 2);
    let error = step.error.as_deref().unwrap_or_default();
    assert!(error.ends_with(crate::error::MAY_HAVE_RUN), "{error}");
}

/// MIK-9042.CHAIN.5: an optional step that may have run is skipped after one
/// call, and says so.
#[tokio::test]
async fn an_optional_step_that_may_have_run_is_skipped_once_and_says_so() {
    let invoker = Scripted::new(vec![answer(|| Error::BackendTimeout("no answer".into()))]);
    let step = run_one(&invoker, true).await;
    assert_eq!(invoker.calls(), 1, "the optional step was re-sent");
    assert_eq!(step.state, StepState::Skipped);
    assert_eq!(step.attempts, 1);
    let error = step.error.as_deref().unwrap_or_default();
    assert!(error.ends_with(crate::error::MAY_HAVE_RUN), "{error}");
}

/// MIK-9042.CHAIN.6: the step-failed event carries the attempts made.
#[test]
fn the_step_failed_event_reports_the_attempts_made() {
    let records = crate::test_log_capture::records(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("a runtime");
        runtime.block_on(async {
            let invoker = Scripted::new(vec![answer(|| Error::BackendTimeout("no answer".into()))]);
            run_one(&invoker, false).await;
        });
    });
    let failed: Vec<&Value> = records
        .iter()
        .filter(|record| record["fields"]["event"] == "step_failed")
        .collect();
    assert_eq!(failed.len(), 1, "{records:#?}");
    assert_eq!(failed[0]["fields"]["attempts"], 1, "{}", failed[0]);
}

/// MIK-9042.CHAIN.7: a pre-send error a chain does not retry gets no
/// may-have-run text; a backend's plain error answer, which follows a send,
/// does.
#[tokio::test]
async fn only_an_error_after_the_send_says_the_step_may_have_run() {
    let invoker = Scripted::new(vec![answer(|| Error::BackendNotFound("gone".into()))]);
    let step = run_one(&invoker, false).await;
    assert_eq!(invoker.calls(), 1);
    let error = step.error.as_deref().unwrap_or_default();
    assert!(!error.contains(crate::error::MAY_HAVE_RUN), "{error}");

    let invoker = Scripted::new(vec![answer(|| Error::JsonRpc {
        code: -32602,
        message: "invalid params".into(),
        data: None,
    })]);
    let step = run_one(&invoker, false).await;
    assert_ran_once(&invoker, &step, "plain JsonRpc");
}
