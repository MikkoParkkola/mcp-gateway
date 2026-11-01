// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The scrub's refusal of an answer that echoed an injected value, delivered
//! from a composite step and from a caller-forwarded read: the call records
//! `refused` only where that refusal is what it delivers.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::authz::AllowAll;
use crate::gateway::delivery_facts;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::authz_tests::ctx;
use crate::protocol::{JsonRpcResponse, RequestId};

/// An injected value the backend echoes as its `error.code`.
const ECHOED_CODE: i32 = 7_391_540;

/// A backend whose every call answers with an error echoing
/// [`ECHOED_CODE`], scrubbed as a transport scrubs it: on the call's own
/// task, so it is that call's scrub that builds the refusal.
struct Echoing;

#[async_trait::async_trait]
impl crate::transport::Transport for Echoing {
    async fn request(
        &self,
        _method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        let needles = crate::security::needles::NeedleSet::with_grace(Duration::from_secs(3_600));
        needles.insert("b", &ECHOED_CODE.to_string());
        let echo = crate::Error::JsonRpc {
            code: ECHOED_CODE,
            message: "no".into(),
            data: None,
        };
        crate::security::needles::scrub_answer(&needles, Err(echo))
    }
    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }
    fn is_connected(&self) -> bool {
        true
    }
    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// The backend `alpha`, answering through [`Echoing`].
fn echoing_backend() -> Arc<Backend> {
    let backend = Arc::new(Backend::new(
        "alpha",
        BackendConfig::r2_off(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(Echoing));
    backend
}

/// A one-step playbook reading `alpha`, ending as `on_error` says.
fn playbook(on_error: &str) -> String {
    format!(
        "name: echoed\ndescription: one step whose answer echoes a credential\n\
         on_error: {on_error}\nsteps:\n  - name: read\n    server: alpha\n    tool: read\n"
    )
}

/// The playbook run under `on_error`: its answer and its delivery record.
async fn run(on_error: &str) -> (Value, serde_json::Map<String, Value>) {
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(echoing_backend()));
    let meta = MetaMcp::new(registry);
    let mut engine = crate::playbook::PlaybookEngine::new();
    engine.register(crate::yaml::from_str(&playbook(on_error)).expect("the playbook parses"));
    meta.set_playbook_engine(engine);
    let mut fields = serde_json::Map::new();
    let answer = delivery_facts::scope(async {
        let response = Box::pin(meta.handle_tools_call(
            RequestId::Number(1),
            "gateway_run_playbook",
            json!({ "name": "echoed" }),
            None,
            ctx(&AllowAll),
        ))
        .await;
        delivery_facts::record_fields(delivery_facts::snapshot().as_ref(), false, &mut fields);
        serde_json::to_value(&response).expect("response is JSON")
    })
    .await;
    (answer, fields)
}

/// W2: a playbook that ends on its step's echo refusal records `refused`.
#[tokio::test]
async fn a_playbook_ending_on_an_echo_refusal_records_refused() {
    let (answer, fields) = run("abort").await;
    assert!(
        !answer.to_string().contains(&ECHOED_CODE.to_string()),
        "premise: the echo was not delivered: {answer}"
    );
    assert_eq!(
        fields.get("response_effect"),
        Some(&json!("refused")),
        "{answer} {fields:?}"
    );
}

/// W2: a playbook that carries on past that step delivers its report: the
/// step's refusal is not the plan's, but the echo is still recorded.
#[tokio::test]
async fn a_playbook_past_an_echo_refusal_records_the_echo_not_a_refusal() {
    let (answer, fields) = run("continue").await;
    assert!(
        answer.to_string().contains("steps_failed"),
        "premise: the report was delivered: {answer}"
    );
    assert_eq!(
        fields.get("response_effect"),
        Some(&json!("rewritten")),
        "{answer} {fields:?}"
    );
}

/// W3: a caller-forwarded read whose answer the scrub replaced delivers the
/// refusal, and records `refused`.
#[tokio::test]
async fn a_forwarded_echo_refusal_records_refused() {
    let backend = echoing_backend();
    let mut fields = serde_json::Map::new();
    let response = delivery_facts::scope(async {
        let response = MetaMcp::forward_for_caller(
            RequestId::Number(1),
            &backend,
            "resources/read",
            json!({"uri": "file:///x"}),
            (crate::transport::LentCredential::default(), None),
            json!({}),
        )
        .await;
        delivery_facts::record_fields(delivery_facts::snapshot().as_ref(), false, &mut fields);
        response
    })
    .await;
    let error = response.error.expect("premise: the refusal was delivered");
    assert!(
        error
            .message
            .contains("contained a credential the gateway injected"),
        "premise: {error:?}"
    );
    assert_eq!(
        fields.get("response_effect"),
        Some(&json!("refused")),
        "{fields:?}"
    );
}

/// The invariant the composite rows rest on: a step's scrub refusal reaches
/// `invoke_tool` folded, as `Ok` holding an `isError` result, with the step's
/// own cell already marked refused (the dispatch error path reads it there).
/// If the dispatch error path ever returns this error as `Err` instead, this
/// row goes red, and `invoke_tool` must read the refusal in the step's cell
/// itself again.
#[tokio::test]
async fn a_steps_echo_refusal_reaches_invoke_tool_folded_and_marked() {
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(echoing_backend()));
    let meta = MetaMcp::new(registry);
    let mut fields = serde_json::Map::new();
    let answer = delivery_facts::scope(async {
        let answer = meta
            .invoke_tool(
                &json!({"server": "alpha", "tool": "read", "arguments": {}}),
                None,
                &ctx(&AllowAll),
            )
            .await;
        delivery_facts::composite_ended(delivery_facts::CompositeEnd::of(&answer));
        delivery_facts::record_fields(delivery_facts::snapshot().as_ref(), false, &mut fields);
        answer
    })
    .await;
    let answer = answer.expect("folded: the step's error is a tool result, not Err");
    assert_eq!(answer["isError"], json!(true), "{answer}");
    assert_eq!(
        fields.get("response_effect"),
        Some(&json!("refused")),
        "the step's cell marked it: {answer} {fields:?}"
    );
}
