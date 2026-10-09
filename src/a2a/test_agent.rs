// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test support: a local A2A 1.0 agent and a transport started against it.
//!
//! One stub for every suite that needs a real A2A peer (the transport's own
//! rows and the egress rows, MIK-8139), so no second copy drifts.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Router;
use axum::routing::{get, post};
use futures::future::BoxFuture;
use serde_json::{Value, json};

use super::transport::A2aTransport;
use crate::security::ssrf::DestinationPolicy;

/// Serve an agent on 127.0.0.1 and return its base URL. The card advertises
/// `{base}/a2a` (JSON-RPC, A2A 1.0); every POST there is answered by
/// `handler`, which maps the request body to the reply body.
pub(crate) async fn serve<F>(handler: F) -> String
where
    F: Fn(Value) -> BoxFuture<'static, Value> + Clone + Send + Sync + 'static,
{
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let endpoint = format!("{base}/a2a");
    let app = Router::new()
        .route(
            "/.well-known/agent-card.json",
            get(move || {
                let endpoint = endpoint.clone();
                async move {
                    axum::Json(json!({"name": "stub", "supportedInterfaces": [
                        {"url": endpoint, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}]}))
                }
            }),
        )
        .route(
            "/a2a",
            post(move |axum::Json(body): axum::Json<Value>| {
                let reply = handler(body);
                async move { axum::Json(reply.await) }
            }),
        );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    base
}

/// A transport started against `base`. `Configured`: a loopback stub is the
/// operator's own destination, not a fetched one.
pub(crate) async fn started(base: &str) -> Arc<A2aTransport> {
    A2aTransport::start(
        base,
        None,
        &HashMap::new(),
        Duration::from_secs(60),
        DestinationPolicy::Configured,
    )
    .await
    .unwrap()
}

/// What a [`scripted_agent`] records: the ids it was asked to cancel, and
/// how many `GetTask`s reached it.
pub(crate) struct Script {
    pub(crate) canceled: Arc<parking_lot::Mutex<Vec<String>>>,
    pub(crate) polls: Arc<AtomicUsize>,
}

/// An agent that answers each `SendMessage` with a new task `t-<n>` in
/// `state`, never answers `GetTask`, and records each `CancelTask` (then
/// never answers it when `cancel_hangs`).
pub(crate) async fn scripted_agent(state: &'static str, cancel_hangs: bool) -> (String, Script) {
    let script = Script {
        canceled: Arc::default(),
        polls: Arc::default(),
    };
    let (canceled, polls) = (Arc::clone(&script.canceled), Arc::clone(&script.polls));
    let sends = Arc::new(AtomicUsize::new(0));
    let base = serve(move |body: Value| -> BoxFuture<'static, Value> {
        let (canceled, polls, sends) = (
            Arc::clone(&canceled),
            Arc::clone(&polls),
            Arc::clone(&sends),
        );
        Box::pin(async move {
            let id = body["id"].clone();
            match body["method"].as_str() {
                Some("GetTask") => {
                    polls.fetch_add(1, Ordering::SeqCst);
                    std::future::pending::<()>().await;
                }
                Some("CancelTask") => {
                    let task = body["params"]["id"].as_str().unwrap_or_default();
                    canceled.lock().push(task.to_owned());
                    if cancel_hangs {
                        std::future::pending::<()>().await;
                    }
                }
                _ => {}
            }
            let n = sends.fetch_add(1, Ordering::SeqCst) + 1;
            json!({"jsonrpc": "2.0", "id": id, "result": {"task": {
                "id": format!("t-{n}"), "contextId": "c-1",
                "status": {"state": state, "message": {
                    "messageId": "m", "role": "ROLE_AGENT", "parts": [{"text": "which?"}]}}}}})
        })
    })
    .await;
    (base, script)
}
