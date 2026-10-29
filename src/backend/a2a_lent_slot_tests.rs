// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An A2A backend whose identity binding is required is reached per user
//! only as that user: its per-user slot fetches the agent's card under the
//! credential the user's dispatch lends, and neither that fetch nor any
//! send carries the backend's static headers.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::http::HeaderMap;
use axum::routing::{get, post};
use serde_json::{Value, json};

use super::Backend;
use super::slot_eviction_tests::{AUDIENCE, subscriber_credential};
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};
use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};

const USER: &str = "u:alpha";
const STATIC_HEADER: &str = "x-static-credential";

/// One request the agent received: its path, the JSON-RPC method it carried
/// (empty for a card fetch), the task it concerns (the id a `SendMessage`
/// was given, or the one a poll or cancel names), its `Authorization`, and
/// whether it carried the static header.
#[derive(Debug, Clone)]
struct Seen {
    path: &'static str,
    method: String,
    task: String,
    authorization: String,
    static_header: bool,
}

fn seen(path: &'static str, method: &str, task: &str, headers: &HeaderMap) -> Seen {
    Seen {
        path,
        method: method.to_owned(),
        task: task.to_owned(),
        authorization: headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string(),
        static_header: headers.contains_key(STATIC_HEADER),
    }
}

/// How the recording agent answers a task.
#[derive(Clone, Copy)]
enum Script {
    /// Every `SendMessage` completes at once.
    Completes,
    /// A task stays working until it is canceled.
    Works,
}

fn task_reply(task: &str, state: &str) -> Value {
    json!({"id": task, "contextId": "c-1",
        "status": {"state": state, "message": {
            "messageId": "m", "role": "ROLE_AGENT", "parts": [{"text": "done"}]}}})
}

/// The result `script` answers JSON-RPC `method` about `task` with.
fn rpc_result(script: Script, method: &str, task: &str) -> Value {
    match (script, method) {
        (Script::Completes, _) => json!({"task": task_reply(task, "TASK_STATE_COMPLETED")}),
        (Script::Works, "SendMessage") => json!({"task": task_reply(task, "TASK_STATE_WORKING")}),
        (Script::Works, "CancelTask") => task_reply(task, "TASK_STATE_CANCELED"),
        (Script::Works, _) => task_reply(task, "TASK_STATE_WORKING"),
    }
}

/// An A2A 1.0 agent on loopback that records every request and answers as
/// `script` says.
async fn recording_agent() -> (String, Arc<Mutex<Vec<Seen>>>) {
    agent(Script::Completes, None).await
}

/// [`recording_agent`] answering as `script`, its card advertising
/// `advertised` as its endpoint when given.
async fn agent(script: Script, advertised: Option<String>) -> (String, Arc<Mutex<Vec<Seen>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let endpoint = advertised.unwrap_or_else(|| format!("{base}/a2a"));
    let log = Arc::new(Mutex::new(Vec::new()));
    let (card_log, rpc_log) = (Arc::clone(&log), Arc::clone(&log));
    let tasks = Arc::new(std::sync::atomic::AtomicUsize::new(1));
    let app = Router::new()
        .route(
            "/.well-known/agent-card.json",
            get(move |headers: HeaderMap| {
                card_log.lock().unwrap().push(seen("card", "", "", &headers));
                let endpoint = endpoint.clone();
                async move {
                    axum::Json(json!({"name": "recording", "supportedInterfaces": [
                        {"url": endpoint, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}]}))
                }
            }),
        )
        .route(
            "/a2a",
            post(move |headers: HeaderMap, axum::Json(body): axum::Json<Value>| {
                let method = body["method"].as_str().unwrap_or_default().to_owned();
                // Each new task gets its own id; a poll or cancel names one.
                let task = if method == "SendMessage" {
                    format!("t-{}", tasks.fetch_add(1, std::sync::atomic::Ordering::SeqCst))
                } else {
                    body["params"]["id"].as_str().unwrap_or_default().to_owned()
                };
                rpc_log.lock().unwrap().push(seen("rpc", &method, &task, &headers));
                async move {
                    axum::Json(
                        json!({"jsonrpc": "2.0", "id": body["id"], "result": rpc_result(script, &method, &task)}),
                    )
                }
            }),
        );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, log)
}

/// The credential `headers` with a send check that always passes.
fn checked(headers: &[(String, String)]) -> crate::transport::LentCredential {
    crate::transport::LentCredential {
        headers: headers.to_vec().into(),
        check: Some(Arc::new(|| Box::pin(async { Ok(()) }))),
    }
}

/// The agent's one tool, called with `message`.
fn delegate_params() -> Value {
    json!({"name": crate::a2a::translator::TOOL_NAME,
        "arguments": {"message": "hi"}})
}

/// An A2A backend at `base` with a static credential header and a required
/// identity binding.
fn required_a2a_backend(base: &str) -> Arc<Backend> {
    let mut headers = HashMap::new();
    headers.insert(STATIC_HEADER.to_string(), "gateway-owned".to_string());
    Arc::new(Backend::new(
        "a2a-lent",
        BackendConfig {
            transport: TransportConfig::A2a {
                a2a_url: base.to_string(),
                a2a_agent_card_path: None,
            },
            headers,
            timeout: Duration::from_secs(10),
            identity_propagation: Some(IdentityPropagationConfig {
                strategy: PropagationStrategyKind::SignedAssertion,
                audience: AUDIENCE.to_string(),
                required: true,
                session_mode: SessionMode::PerUser,
                token_exchange_endpoint: None,
                token_exchange_scope: None,
            }),
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ))
}

/// START.6 (A2A): the user's first call starts their slot. The card fetch
/// goes out under the user's credential, and no request carries the
/// backend's static header.
#[tokio::test]
async fn an_a2a_per_user_slot_is_reached_only_as_its_user() {
    let (base, log) = recording_agent().await;
    let backend = required_a2a_backend(&base);
    let credential = subscriber_credential(USER);
    let bearer = credential[0].1.clone();

    let _ = backend
        .request_with_headers_lent(
            "tools/call",
            Some(delegate_params()),
            checked(&credential),
            Some(USER),
        )
        .await;

    let log = log.lock().unwrap().clone();
    assert!(
        log.iter().any(|s| s.path == "card") && log.iter().any(|s| s.path == "rpc"),
        "premise: the slot fetched the card and the call reached the agent: {log:?}"
    );
    let carried: Vec<_> = log.iter().filter(|s| s.static_header).collect();
    assert!(
        carried.is_empty(),
        "a per-user request carried the backend's static header: {carried:?}"
    );
    let not_as_user: Vec<_> = log.iter().filter(|s| s.authorization != bearer).collect();
    assert!(
        not_as_user.is_empty(),
        "a per-user request reached the agent other than as its user: {not_as_user:?}"
    );
}

/// A card that advertises an endpoint on another origin is refused: the call
/// fails and neither origin receives a send.
#[tokio::test]
async fn a_cross_origin_card_endpoint_is_refused_before_any_send() {
    let (other, other_log) = recording_agent().await;
    let (base, log) = agent(Script::Completes, Some(format!("{other}/a2a"))).await;
    let backend = required_a2a_backend(&base);

    let result = backend
        .request_with_headers_lent(
            "tools/call",
            Some(delegate_params()),
            checked(&subscriber_credential(USER)),
            Some(USER),
        )
        .await;

    assert!(result.is_err(), "the cross-origin card was accepted");
    let rpcs = log
        .lock()
        .unwrap()
        .iter()
        .filter(|s| s.path == "rpc")
        .count();
    assert_eq!(rpcs, 0, "a call reached the agent past a cross-origin card");
    let elsewhere = other_log.lock().unwrap().clone();
    assert!(
        elsewhere.is_empty(),
        "the other origin was sent to: {elsewhere:?}"
    );
}

/// A per-user call whose task works, driven until its cancel guard is armed
/// (the first `GetTask` poll goes out after the arm), and not yet dropped:
/// dropping the returned closure's capture abandons it. With the agent's log.
async fn abandoned_while_armed() -> (Box<dyn FnOnce()>, Arc<Mutex<Vec<Seen>>>) {
    let (base, log) = agent(Script::Works, None).await;
    let backend = required_a2a_backend(&base);
    let methods = {
        let log = Arc::clone(&log);
        move || -> Vec<String> {
            log.lock()
                .unwrap()
                .iter()
                .map(|s| s.method.clone())
                .collect()
        }
    };
    let mut call = Box::pin(async move {
        backend
            .request_with_headers_lent(
                "tools/call",
                Some(delegate_params()),
                checked(&subscriber_credential(USER)),
                Some(USER),
            )
            .await
    });
    let armed = async {
        while !methods().iter().any(|m| m == "GetTask") {
            tokio::task::yield_now().await;
        }
    };
    tokio::select! {
        result = &mut call => panic!("premise: the dispatch was still running: {result:?}"),
        () = armed => {}
    }
    (Box::new(move || drop(call)), log)
}

/// A dispatch abandoned while its task works queues no `CancelTask` once it
/// has ended: the slot has no credential left to send as. The cancel is
/// decided when the abandoned call drops, so the row reads that decision
/// rather than waiting out a window.
#[tokio::test]
async fn a_deferred_cancel_after_the_dispatch_ended_sends_nothing() {
    let (abandon, log) = abandoned_while_armed().await;

    let ((), warnings) = crate::test_log_capture::capture_warnings(abandon);

    assert!(
        warnings.contains("a deferred A2A cancel on a per-user slot was refused"),
        "the abandoned dispatch's cancel was not refused: {warnings:?}"
    );
    let sent: Vec<String> = log
        .lock()
        .unwrap()
        .iter()
        .map(|s| s.method.clone())
        .collect();
    assert!(
        !sent.iter().any(|m| m == "CancelTask"),
        "a cancel was sent after its dispatch ended: {sent:?}"
    );
}

/// The refused deferred cancel is counted, by reason.
#[cfg(feature = "metrics")]
#[tokio::test]
async fn a_refused_deferred_cancel_is_counted() {
    let (abandon, _log) = abandoned_while_armed().await;
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();

    telemetry_metrics::with_local_recorder(&recorder, abandon);

    let rendered = handle.render();
    assert!(
        rendered.lines().any(|line| line.starts_with(
            "mcp_gateway_per_user_send_refused_total{reason=\"a2a_deferred_cancel\"}"
        ) && line.ends_with(" 1")),
        "the refused cancel was not counted:\n{rendered}"
    );
}

/// One user's slot is one pooled A2A transport: two of that user's calls in
/// flight at once, each lending a different credential (a refresh mid-task),
/// each send carrying its own call's credential, never the newer loan.
#[tokio::test]
async fn two_calls_on_one_pooled_slot_each_send_their_own_credential() {
    let (base, log) = agent(Script::Works, None).await;
    let backend = required_a2a_backend(&base);
    let (old, new) = (
        vec![("Authorization".to_owned(), "Bearer old-token".to_owned())],
        vec![("Authorization".to_owned(), "Bearer new-token".to_owned())],
    );
    let polls = || -> Vec<String> {
        log.lock()
            .unwrap()
            .iter()
            .filter(|s| s.method == "GetTask")
            .map(|s| s.authorization.clone())
            .collect()
    };
    let first = backend.request_with_headers_lent(
        "tools/call",
        Some(delegate_params()),
        checked(&old),
        Some(USER),
    );
    let second = backend.request_with_headers_lent(
        "tools/call",
        Some(delegate_params()),
        checked(&new),
        Some(USER),
    );
    let both_polled = async {
        loop {
            let seen = polls();
            if seen.iter().any(|a| a == "Bearer old-token")
                && seen.iter().any(|a| a == "Bearer new-token")
            {
                return;
            }
            tokio::task::yield_now().await;
        }
    };
    tokio::select! {
        result = first => panic!("premise: the first call was still running: {result:?}"),
        result = second => panic!("premise: the second call was still running: {result:?}"),
        () = crate::test_pause::within("each call polling as itself", both_polled) => {}
    }

    let log = log.lock().unwrap().clone();
    let foreign: Vec<_> = log
        .iter()
        .filter(|s| s.authorization != "Bearer old-token" && s.authorization != "Bearer new-token")
        .collect();
    assert!(
        foreign.is_empty(),
        "a send carried neither call's credential: {foreign:?}"
    );
    let created: Vec<&Seen> = log.iter().filter(|s| s.method == "SendMessage").collect();
    assert_eq!(
        created.len(),
        2,
        "premise: each call created its own task: {log:?}"
    );
    for task in created {
        let swapped: Vec<&Seen> = log
            .iter()
            .filter(|s| s.task == task.task && s.authorization != task.authorization)
            .collect();
        assert!(
            swapped.is_empty(),
            "task {} was created as {} but sent as another credential: {swapped:?}",
            task.task,
            task.authorization
        );
    }
}

/// A call whose credential's check refuses sends nothing: neither the card
/// fetch nor any rpc carries it.
#[tokio::test]
async fn a_call_whose_check_refuses_sends_nothing_to_the_agent() {
    let (base, log) = recording_agent().await;
    let backend = required_a2a_backend(&base);
    let refusing = crate::transport::LentCredential {
        headers: subscriber_credential(USER).into(),
        check: Some(Arc::new(|| {
            Box::pin(async { Err(crate::transport::Refusal::ThisLoan) })
        })),
    };

    let result = backend
        .request_with_headers_lent("tools/call", Some(delegate_params()), refusing, Some(USER))
        .await;

    assert!(result.is_err(), "a refused credential was sent");
    let log = log.lock().unwrap().clone();
    assert!(log.is_empty(), "the agent received a refused call: {log:?}");
}
