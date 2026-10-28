// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A library caller can tell a call that may have run from one refused before
//! its send, with the public `Error::outcome_undetermined` (MIK-9042). A
//! playbook under `on_error: abort` returns the step's error unchanged, so this
//! is the caller's one way to know whether to reconcile before running it
//! again.

use std::collections::HashMap;

use async_trait::async_trait;
use mcp_gateway::Error;
use mcp_gateway::playbook::{
    ErrorStrategy, PlaybookDefinition, PlaybookEngine, PlaybookStep, ToolInvoker,
};
use mcp_gateway::protocol::continuation::{ProbeBudget, ProbeRefusal};
use serde_json::{Value, json};

#[test]
fn a_library_caller_can_tell_may_have_run_from_never_sent() {
    let may_have_run = [
        Error::BackendTimeout("no answer".into()),
        Error::Transport("stream reset".into()),
        Error::Io(std::io::Error::other("broken pipe")),
        Error::JsonRpcRetryable {
            code: -32000,
            message: "backend error".into(),
            status: 503,
            data: None,
        },
    ];
    for error in &may_have_run {
        assert!(error.outcome_undetermined(), "{error:?}");
    }
    for error in [
        Error::TransportConnect("connection refused".into()),
        Error::BackendUnavailable("starting".into()),
    ] {
        assert!(!error.outcome_undetermined(), "{error:?}");
    }
}

/// Answers every call with the error its function builds.
struct Failing(fn() -> Error);

#[async_trait]
impl ToolInvoker for Failing {
    async fn invoke(
        &self,
        _server: &str,
        _tool: &str,
        _arguments: Value,
    ) -> mcp_gateway::Result<Value> {
        Err((self.0)())
    }

    fn sealed_state_in(
        &self,
        _value: &Value,
        _budget: &mut ProbeBudget,
    ) -> Result<bool, ProbeRefusal> {
        Ok(false)
    }
}

/// MIK-9042.PLAY.4: under `abort`, each error that can follow a send comes
/// back from the engine still reading as "may have run".
#[tokio::test]
async fn an_aborted_playbook_returns_an_error_that_says_it_may_have_run() {
    let cases: [(&str, fn() -> Error); 4] = [
        ("BackendTimeout", || {
            Error::BackendTimeout("no answer".into())
        }),
        ("Io", || Error::Io(std::io::Error::other("broken pipe"))),
        ("JsonRpcRetryable 500", || Error::JsonRpcRetryable {
            code: -32000,
            message: "backend error".into(),
            status: 500,
            data: None,
        }),
        ("JsonRpc", || Error::JsonRpc {
            code: -32602,
            message: "invalid params".into(),
            data: None,
        }),
    ];
    for (what, make) in cases {
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
                arguments: HashMap::new(),
                condition: None,
            }],
            output: None,
            on_error: ErrorStrategy::Abort,
            max_retries: 3,
            timeout: 60,
        });
        let error = engine
            .execute("pay", json!({}), &Failing(make))
            .await
            .expect_err("abort returns the step's error");
        assert!(error.outcome_undetermined(), "{what}: {error:?}");
    }
}
