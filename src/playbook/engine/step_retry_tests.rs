// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A playbook step under `on_error: retry` is re-sent only after an error
//! raised before its request was sent. A step whose request may have reached
//! the backend runs once, and its recorded reason says it may have run.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

use super::*;
use serde_json::json;

type Answer = Box<dyn FnOnce() -> crate::Result<Value> + Send>;

/// Answers from a script, then succeeds; counts every call.
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
    async fn invoke(&self, _server: &str, _tool: &str, _arguments: Value) -> crate::Result<Value> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let next = self.answers.lock().expect("script").pop_front();
        next.map_or_else(|| Ok(json!({"served": true})), |answer| answer())
    }

    fn sealed_state_in(
        &self,
        _value: &Value,
        _budget: &mut crate::protocol::continuation::ProbeBudget,
    ) -> Result<bool, crate::protocol::continuation::ProbeRefusal> {
        Ok(false)
    }
}

fn answer(error: impl FnOnce() -> crate::Error + Send + 'static) -> Answer {
    Box::new(move || Err(error()))
}

fn http_status(status: u16) -> crate::Error {
    let response = axum::http::Response::builder()
        .status(status)
        .body(String::new())
        .expect("fixture response builds");
    crate::Error::Http(
        reqwest::Response::from(response)
            .error_for_status()
            .expect_err("a fixture status is non-2xx"),
    )
}

fn retryable_answer(status: u16) -> crate::Error {
    crate::Error::JsonRpcRetryable {
        code: -32000,
        message: "backend error".to_string(),
        status,
        data: None,
    }
}

/// An engine holding one one-step playbook, `pay`, under `on_error`, with
/// three attempts.
fn engine(on_error: ErrorStrategy) -> PlaybookEngine {
    let mut engine = PlaybookEngine::new();
    engine.register(PlaybookDefinition {
        playbook: "1.0".to_string(),
        name: "pay".to_string(),
        description: "One step that has a side effect".to_string(),
        inputs: json!({}),
        steps: vec![PlaybookStep {
            name: "charge".to_string(),
            tool: "charge_card".to_string(),
            server: "billing".to_string(),
            arguments: HashMap::from([("amount".to_string(), json!(1))]),
            condition: None,
        }],
        output: None,
        on_error,
        max_retries: 3,
        timeout: 60,
    });
    engine
}

/// MIK-9042.PLAY.1: under `retry`, each error that can follow a send ends the
/// step after one call.
#[tokio::test]
async fn a_step_whose_request_may_have_reached_the_backend_is_not_re_sent() {
    let cases: Vec<(&str, fn() -> crate::Error)> = vec![
        ("BackendTimeout", || {
            crate::Error::BackendTimeout("no answer".into())
        }),
        ("Transport", || {
            crate::Error::Transport("stream reset".into())
        }),
        ("Http 500", || http_status(500)),
        ("Io", || {
            crate::Error::Io(std::io::Error::other("broken pipe"))
        }),
        ("JsonRpcRetryable 503", || retryable_answer(503)),
        ("JsonRpcRetryable 500", || retryable_answer(500)),
        ("JsonRpc", || crate::Error::JsonRpc {
            code: -32602,
            message: "invalid params".into(),
            data: None,
        }),
    ];
    for (what, error) in cases {
        let invoker = Scripted::new(vec![answer(error)]);
        let result = engine(ErrorStrategy::Retry)
            .execute("pay", json!({}), &invoker)
            .await
            .expect("retry carries on past a failed step");
        assert_eq!(invoker.calls(), 1, "{what}: the step was re-sent");
        assert_eq!(result.steps_failed, vec!["charge"], "{what}");
    }
}

/// MIK-9042.PLAY.2: an error raised before the send is still retried.
#[tokio::test]
async fn a_step_refused_before_its_send_is_retried() {
    let cases: Vec<(&str, fn() -> crate::Error)> = vec![
        ("TransportConnect", || {
            crate::Error::TransportConnect("connection refused".into())
        }),
        ("BackendUnavailable", || {
            crate::Error::BackendUnavailable("starting".into())
        }),
    ];
    for (what, error) in cases {
        let invoker = Scripted::new(vec![answer(error)]);
        let result = engine(ErrorStrategy::Retry)
            .execute("pay", json!({}), &invoker)
            .await
            .expect("the playbook runs");
        assert_eq!(invoker.calls(), 2, "{what}");
        assert_eq!(result.steps_completed, vec!["charge"], "{what}");
    }
}

/// MIK-9042.PLAY.3: the recorded reason says the step may have run, under
/// `retry` and under `continue`; a pre-send error's reason does not.
#[tokio::test]
async fn the_failed_steps_reason_says_it_may_have_run() {
    for strategy in [ErrorStrategy::Retry, ErrorStrategy::Continue] {
        let invoker = Scripted::new(vec![answer(|| {
            crate::Error::BackendTimeout("no answer".into())
        })]);
        let result = engine(strategy)
            .execute("pay", json!({}), &invoker)
            .await
            .expect("the playbook carries on");
        let reason = result
            .step_errors
            .get("charge")
            .cloned()
            .unwrap_or_default();
        assert!(
            reason.ends_with(crate::error::MAY_HAVE_RUN),
            "{strategy:?}: {reason}"
        );
    }
    let invoker = Scripted::new(vec![answer(|| crate::Error::JsonRpc {
        code: -32602,
        message: "invalid params".into(),
        data: None,
    })]);
    let result = engine(ErrorStrategy::Continue)
        .execute("pay", json!({}), &invoker)
        .await
        .expect("the playbook carries on");
    let reason = result
        .step_errors
        .get("charge")
        .cloned()
        .unwrap_or_default();
    assert!(
        reason.ends_with(crate::error::MAY_HAVE_RUN),
        "a backend's plain error answer follows a send: {reason}"
    );
    let invoker = Scripted::new(vec![answer(|| {
        crate::Error::BackendNotFound("gone".into())
    })]);
    let result = engine(ErrorStrategy::Continue)
        .execute("pay", json!({}), &invoker)
        .await
        .expect("the playbook carries on");
    let reason = result
        .step_errors
        .get("charge")
        .cloned()
        .unwrap_or_default();
    assert!(!reason.contains(crate::error::MAY_HAVE_RUN), "{reason}");
}

/// MIK-9042.PLAY.5: a retried pre-send failure, then a lost round: the
/// ceiling holds past the first attempt.
#[tokio::test]
async fn a_lost_round_after_a_retried_refusal_ends_the_step() {
    let invoker = Scripted::new(vec![
        answer(|| crate::Error::TransportConnect("connection refused".into())),
        answer(|| crate::Error::BackendTimeout("no answer".into())),
    ]);
    let result = engine(ErrorStrategy::Retry)
        .execute("pay", json!({}), &invoker)
        .await
        .expect("the playbook carries on");
    assert_eq!(invoker.calls(), 2, "the lost round was re-sent");
    assert_eq!(result.steps_failed, vec!["charge"]);
}

/// MIK-9042.PLAY.4: under `abort`, a step that may have run ends the plan with
/// an error a caller can read without a crate-private method: it is a
/// `Transport` error (a lost round) whose text ends with the may-have-run
/// sentence. A refusal and a tool's own `isError` answer keep their type.
#[tokio::test]
async fn an_aborted_step_that_may_have_run_says_so_in_its_error() {
    let cases: Vec<(&str, fn() -> crate::Error)> = vec![
        ("BackendTimeout", || {
            crate::Error::BackendTimeout("no answer".into())
        }),
        ("Io", || {
            crate::Error::Io(std::io::Error::other("broken pipe"))
        }),
        ("JsonRpcRetryable 500", || retryable_answer(500)),
        ("JsonRpc", || crate::Error::JsonRpc {
            code: -32602,
            message: "invalid params".into(),
            data: None,
        }),
    ];
    for (what, error) in cases {
        let invoker = Scripted::new(vec![answer(error)]);
        let returned = engine(ErrorStrategy::Abort)
            .execute("pay", json!({}), &invoker)
            .await
            .expect_err("abort ends the plan");
        assert!(
            matches!(returned, crate::Error::Transport(_)),
            "{what}: {returned:?}"
        );
        assert!(
            returned.to_string().ends_with(crate::error::MAY_HAVE_RUN),
            "{what}: {returned}"
        );
    }
    let refusal = Scripted::new(vec![answer(|| crate::Error::Forbidden {
        code: -32003,
        status: 403,
        message: "step not permitted for this caller".into(),
    })]);
    let returned = engine(ErrorStrategy::Abort)
        .execute("pay", json!({}), &refusal)
        .await
        .expect_err("abort ends the plan");
    assert!(
        matches!(returned, crate::Error::Forbidden { .. }),
        "a refusal keeps its type: {returned:?}"
    );
    let unsent = Scripted::new(vec![answer(|| {
        crate::Error::TransportConnect("connection refused".into())
    })]);
    let returned = engine(ErrorStrategy::Abort)
        .execute("pay", json!({}), &unsent)
        .await
        .expect_err("abort makes one attempt");
    assert!(
        matches!(returned, crate::Error::TransportConnect(_)),
        "a step never sent is not marked as may-have-run: {returned:?}"
    );
}
