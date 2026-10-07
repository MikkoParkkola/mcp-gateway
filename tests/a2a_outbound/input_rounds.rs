// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8063 A2A.8/A2A.9: an agent's question becomes an MCP input round, a
//! long delegation is followed to its end, and an abandoned one is canceled
//! at the agent.

use std::time::Duration;

use serde_json::{Value, json};

use super::stub::{self, Agent, Step};
use super::{TOOL, backend, backend_timed, texts};

/// The agent's one question, keyed as the transport asks it.
const ASK_KEY: &str = "a2a_reply";

fn asking_then(answer: &str) -> Agent {
    let mut agent = Agent::answering(Value::Null);
    agent.answer = stub::script(vec![
        Step::Reply(stub::task_in("TASK_STATE_INPUT_REQUIRED", "which city?")),
        Step::Reply(stub::completed_task(json!([{"text": answer}]))),
    ]);
    agent
}

fn first_call() -> Value {
    json!({"name": TOOL, "arguments": {"message": "weather?"}})
}

fn retry(state: &Value, answer: Value) -> Value {
    let mut params = first_call();
    params["requestState"] = state.clone();
    params["inputResponses"] = json!({ ASK_KEY: answer });
    params
}

async fn send(
    backend: &mcp_gateway::backend::Backend,
    params: Value,
    identity: Option<&str>,
) -> mcp_gateway::protocol::JsonRpcResponse {
    backend
        .request_with_headers("tools/call", Some(params), &[], identity)
        .await
        .expect("the transport answers")
}

/// A2A.8: the question is an `input_required` round; an accepted reply
/// continues the SAME agent task and the agent's final answer comes back.
#[tokio::test]
async fn a2a_8_a_question_is_an_input_round_that_continues_the_same_task() {
    let (base, log) = stub::serve(asking_then("sunny in Helsinki")).await;
    let backend = backend(&base, None, &[]);

    let asked = send(&backend, first_call(), Some("user-1")).await;
    let asked = asked.result.expect("an interim result, not an error");
    assert_eq!(asked["resultType"], "input_required", "{asked}");
    let question = &asked["inputRequests"][ASK_KEY];
    assert_eq!(question["method"], "elicitation/create", "{asked}");
    assert!(
        question.to_string().contains("which city?"),
        "the agent's words reach the user: {asked}"
    );
    let state = asked["requestState"].clone();
    assert!(state.is_string(), "{asked}");
    assert!(
        !state.as_str().unwrap_or_default().contains("task-2"),
        "the agent's task id never reaches the client: {state}"
    );

    let accept = json!({"action": "accept", "content": {"reply": "Helsinki"}});
    let answered = send(&backend, retry(&state, accept), Some("user-1")).await;
    let answered = answered.result.expect("the final answer");
    assert_eq!(texts(&answered), ["sunny in Helsinki"], "{answered}");

    let sends = stub::sends(&log);
    assert_eq!(sends.len(), 2, "one question, one continuation");
    let second = &sends[1].body["params"]["message"];
    assert_eq!(second["taskId"], "task-2", "{second}");
    assert_eq!(second["contextId"], "ctx-2", "{second}");
    assert_eq!(second["parts"][0]["text"], "Helsinki", "{second}");
}

/// A2A.8: a requestState is one-shot and belongs to the identity it was
/// issued to; a replay or another caller's retry never reaches the agent.
#[tokio::test]
async fn a2a_8_another_caller_or_a_replay_cannot_continue_the_task() {
    let (base, log) = stub::serve(asking_then("done")).await;
    let backend = backend(&base, None, &[]);
    let asked = send(&backend, first_call(), Some("user-1")).await;
    let state = asked.result.expect("interim")["requestState"].clone();
    let accept = json!({"action": "accept", "content": {"reply": "x"}});

    let stolen = send(&backend, retry(&state, accept.clone()), Some("user-2")).await;
    assert_eq!(
        stolen.error.map(|e| e.code),
        Some(-32602),
        "another identity is refused"
    );
    let anonymous = send(&backend, retry(&state, accept.clone()), None).await;
    assert_eq!(
        anonymous.error.map(|e| e.code),
        Some(-32602),
        "no identity is refused"
    );
    assert_eq!(
        stub::sends(&log).len(),
        1,
        "no refused retry reached the agent"
    );

    send(&backend, retry(&state, accept.clone()), Some("user-1")).await;
    let replay = send(&backend, retry(&state, accept), Some("user-1")).await;
    assert_eq!(
        replay.error.map(|e| e.code),
        Some(-32602),
        "a state is one-shot"
    );
    assert_eq!(
        stub::sends(&log).len(),
        2,
        "the replay never reached the agent"
    );
}

/// A2A.9: a declined question cancels the agent's task.
#[tokio::test]
async fn a2a_9_a_declined_question_cancels_the_agents_task() {
    let (base, log) = stub::serve(asking_then("unused")).await;
    let backend = backend(&base, None, &[]);
    let asked = send(&backend, first_call(), None).await;
    let state = asked.result.expect("interim")["requestState"].clone();

    let declined = send(&backend, retry(&state, json!({"action": "decline"})), None).await;
    let declined = declined.result.expect("a tool result");
    assert_eq!(declined["isError"], true, "{declined}");
    let cancels = stub::calls(&log, "CancelTask");
    assert_eq!(cancels.len(), 1, "the agent's task was canceled");
    assert_eq!(cancels[0]["params"]["id"], "task-2");
    assert_eq!(stub::sends(&log).len(), 1, "nothing else was sent");
}

/// A2A.9: an agent that answers before finishing is followed with `GetTask`
/// to its answer.
#[tokio::test]
async fn a2a_9_an_unfinished_reply_is_followed_to_the_answer() {
    let mut agent = Agent::answering(Value::Null);
    agent.answer = stub::script(vec![
        Step::Reply(stub::task_in("TASK_STATE_WORKING", "on it")),
        Step::Reply(stub::task_in("TASK_STATE_WORKING", "still on it")),
        Step::Reply(stub::completed_task(json!([{"text": "finished"}]))),
    ]);
    let (base, log) = stub::serve(agent).await;
    let result = send(&backend(&base, None, &[]), first_call(), None)
        .await
        .result
        .expect("the answer");
    assert_eq!(texts(&result), ["finished"], "{result}");
    let polls = stub::calls(&log, "GetTask");
    assert_eq!(polls.len(), 2, "followed until it finished");
    assert_eq!(polls[0]["params"]["id"], "task-2");
}

/// A2A.9: a delegation still unfinished at the backend timeout is canceled
/// at the agent and reported as a tool error.
#[tokio::test]
async fn a2a_9_past_the_deadline_the_task_is_canceled() {
    let mut agent = Agent::answering(Value::Null);
    agent.answer = stub::script(vec![Step::Reply(stub::task_in(
        "TASK_STATE_WORKING",
        "forever",
    ))]);
    let (base, log) = stub::serve(agent).await;
    let backend = backend_timed(&base, None, &[], Duration::from_secs(3));
    let result = send(&backend, first_call(), None)
        .await
        .result
        .expect("a tool result");
    assert_eq!(result["isError"], true, "{result}");
    assert_eq!(
        stub::calls(&log, "CancelTask").len(),
        1,
        "canceled at the agent"
    );
}

/// A2A.9: a delegation abandoned while the agent holds it (the caller's
/// future dropped: a gateway task canceled, a client gone) is canceled at
/// the agent once it has named its task.
#[tokio::test]
async fn a2a_9_an_abandoned_delegation_is_canceled_at_the_agent() {
    let mut agent = Agent::answering(Value::Null);
    agent.answer = stub::script(vec![
        Step::Reply(stub::task_in("TASK_STATE_WORKING", "started")),
        Step::Hang,
    ]);
    let (base, log) = stub::serve(agent).await;
    let backend = std::sync::Arc::new(backend(&base, None, &[]));
    let call = tokio::spawn({
        let backend = std::sync::Arc::clone(&backend);
        async move { send(&backend, first_call(), None).await }
    });
    // Abandoned only once the agent holds a GetTask for the named task.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while stub::calls(&log, "GetTask").is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the follow never started"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    call.abort();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while stub::calls(&log, "CancelTask").is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "an abandoned delegation must be canceled at the agent"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(stub::calls(&log, "CancelTask")[0]["params"]["id"], "task-2");
}

/// A2A.8 through the gateway: on `/mcp` the agent's question reaches a client
/// that declared elicitation, the gateway seals the state it relays, and the
/// retry continues the agent's task.
#[tokio::test]
async fn a2a_8_an_input_round_through_the_gateway_funnel() {
    use super::common;
    let (base, log) = stub::serve(asking_then("sunny via the funnel")).await;
    let (state, _store) = common::state(common::Fixture::default()).await;
    assert!(
        state
            .backends
            .register(std::sync::Arc::new(backend(&base, None, &[])))
    );
    let frame = |key: &str, extra: &[(&str, Value)]| {
        let mut params = json!({"name": "gateway_invoke", "arguments": {
            "server": "agent", "tool": TOOL, "arguments": {"message": "weather?"}}});
        for (name, value) in extra {
            params[*name] = value.clone();
        }
        params["_meta"] = json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {"elicitation": {}},
            "io.modelcontextprotocol/clientInfo": {"name": "a2a-rows", "version": "1"},
        });
        params["_meta"][mcp_gateway::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
    };

    let asked = post_as(&state, "/mcp", frame("a2a-8-ask", &[]), None, Some("alice")).await;
    let result = &asked["result"];
    assert_eq!(result["resultType"], "input_required", "{asked}");
    let envelope = result["requestState"].clone();
    assert!(envelope.is_string(), "{asked}");

    let accept = json!({ ASK_KEY: {"action": "accept", "content": {"reply": "Helsinki"}} });
    let answered = post_as(
        &state,
        "/mcp",
        frame(
            "a2a-8-retry",
            &[("requestState", envelope), ("inputResponses", accept)],
        ),
        None,
        Some("alice"),
    )
    .await;
    assert!(
        answered.to_string().contains("sunny via the funnel"),
        "the agent's final answer comes back: {answered}"
    );
    let sends = stub::sends(&log);
    assert_eq!(sends.len(), 2, "{answered}");
    assert_eq!(sends[1].body["params"]["message"]["taskId"], "task-2");
}

/// POST `body` to `uri` as the bearer `key` and/or the verified `subject`
/// (the extension the identity layer would insert).
async fn post_as(
    state: &std::sync::Arc<super::common::AppState>,
    uri: &str,
    body: Value,
    key: Option<&str>,
    subject: Option<&str>,
) -> Value {
    use super::common::{Body, Request, ServiceExt, create_router};
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28");
    if let Some(key) = key {
        builder = builder.header("authorization", format!("Bearer {key}"));
    }
    if let Some(method) = body.get("method").and_then(Value::as_str) {
        builder = builder.header("mcp-method", method);
    }
    if let Some(name) = body.pointer("/params/name").and_then(Value::as_str) {
        builder = builder.header("mcp-name", name);
    }
    let mut request = builder
        .body(Body::from(serde_json::to_vec(&body).expect("body")))
        .expect("request");
    if let Some(subject) = subject {
        request
            .extensions_mut()
            .insert(mcp_gateway::key_server::oidc::VerifiedIdentity {
                subject: subject.to_owned(),
                email: format!("{subject}@a2a.test"),
                name: None,
                groups: Vec::new(),
                issuer: "https://idp.a2a.test".to_owned(),
            });
    }
    let response = create_router(std::sync::Arc::clone(state))
        .oneshot(request)
        .await
        .expect("router answers");
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body reads");
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// MIK-8063 D2: on the per-backend route the agent's question is bound to the
/// authenticated caller who was asked. A second caller holding a leaked
/// token is refused and nothing reaches the agent; the asked caller resumes.
#[tokio::test]
async fn a2a_8_a_leaked_token_is_refused_to_another_caller_on_the_backend_route() {
    use super::common;
    let (base, log) = stub::serve(asking_then("for alice")).await;
    let mut alice = common::api_key("key-alice", 0, None);
    alice.name = "alice".into();
    let mut bob = common::api_key("key-bob", 0, None);
    bob.name = "bob".into();
    let fixture = common::Fixture {
        auth: common::auth_with(vec![alice, bob], None),
        ..common::Fixture::default()
    };
    let (state, _store) = common::state(fixture).await;
    assert!(
        state
            .backends
            .register(std::sync::Arc::new(backend(&base, None, &[])))
    );
    let call = |extra: &[(&str, Value)], key: &str| {
        let mut params = first_call();
        for (name, value) in extra {
            params[*name] = value.clone();
        }
        params["_meta"] = json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {"elicitation": {}},
            "io.modelcontextprotocol/clientInfo": {"name": "a2a-rows", "version": "1"},
        });
        params["_meta"][mcp_gateway::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
    };

    let asked = post_as(
        &state,
        "/mcp/agent",
        call(&[], "d2-ask"),
        Some("key-alice"),
        None,
    )
    .await;
    assert_eq!(asked["result"]["resultType"], "input_required", "{asked}");
    let token = asked["result"]["requestState"].clone();
    let accept = json!({ ASK_KEY: {"action": "accept", "content": {"reply": "Helsinki"}} });
    let answer = [("requestState", token), ("inputResponses", accept)];

    let stolen = post_as(
        &state,
        "/mcp/agent",
        call(&answer, "d2-bob"),
        Some("key-bob"),
        None,
    )
    .await;
    assert!(
        stolen.get("error").is_some(),
        "another caller is refused: {stolen}"
    );
    assert_eq!(
        stub::sends(&log).len(),
        1,
        "the refused retry never reached the agent"
    );

    let resumed = post_as(
        &state,
        "/mcp/agent",
        call(&answer, "d2-alice"),
        Some("key-alice"),
        None,
    )
    .await;
    assert!(
        resumed.to_string().contains("for alice"),
        "the asked caller resumes: {resumed}"
    );
    assert_eq!(stub::sends(&log).len(), 2);
}
