// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8323 engine rows: a playbook never hands a step's sealed continuation
//! envelope to another step's backend. The asking step's result carries a
//! REAL envelope minted by a real `ContinuationState`, so the oracle (does a
//! recorded argument contain that exact string) does not depend on the code
//! under test.

use std::sync::Mutex;

use serde_json::{Value, json};

use super::*;
use crate::protocol::continuation::ContinuationState;

/// A real envelope, minted for a test exchange.
async fn real_envelope(state: &ContinuationState) -> String {
    let now = crate::protocol::continuation::now_unix_secs();
    let payload = state
        .begin_exchange("srv".into(), None, "fp".into(), "digest".into(), now)
        .await
        .expect("a fresh state has a slot");
    state.keyring().mint(&payload).expect("the envelope seals")
}

/// Answers `ask` with a result whose `requestState` is the envelope, `inner`
/// with a nested output carrying it, anything else with `{"ok": true}`, and
/// records every call's arguments.
struct Recording {
    envelope: String,
    seen: Mutex<Vec<(String, Value)>>,
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
            _ => json!({"ok": true}),
        })
    }
}

impl Recording {
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
fn two_steps(first: &str, stage_arguments: Value) -> PlaybookDefinition {
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
        seen: Mutex::default(),
    }
}

/// R11: the envelope inside an array element of a step's arguments (the
/// whole asking step, as one element) reaches no backend. Red on base.
#[tokio::test]
async fn r11_an_envelope_in_an_array_element_reaches_no_backend() {
    let invoker = recording().await;
    let mut engine = PlaybookEngine::new();
    engine.register(two_steps("ask", json!({ "list": ["$ask"] })));
    let _ = engine.execute("carry", json!({}), &invoker).await;
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
    engine.register(two_steps("inner", json!({ "t": "$inner.output.token" })));
    let _ = engine.execute("carry", json!({}), &invoker).await;
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
        engine.register(two_steps("ask", json!({ "x": reference })));
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
    engine.register(two_steps("ask", json!({ "x": "$ask.requestStateOfX" })));
    assert!(
        engine.execute("carry", json!({}), &invoker).await.is_ok(),
        "requestStateOfX names another field and must run"
    );
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
