// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The upstream-tasks capability (the typed opt-in).

use super::*;

// =========================================================================
// Upstream tasks capability (the typed opt-in)
//
// The one thing worth proving here is that the CHOICE of metadata follows the
// API the caller reached for, not anything in the payload: the typed method
// declares the tasks extension and the ordinary one cannot be talked into it.
// A helper-level assertion could not show that, so these go through the real
// `Transport` methods and read the bytes the server received.
// =========================================================================

/// Bodies a recorder server was `POSTed`, in arrival order.
type RecordedBodies = Arc<RwLock<Vec<serde_json::Value>>>;

/// A local server that records every request body and answers an empty result.
async fn spawn_body_recorder() -> (String, RecordedBodies, tokio::task::JoinHandle<()>) {
    use axum::{Json, Router, extract::State, routing::post};

    async fn record(
        State(bodies): State<RecordedBodies>,
        body: axum::body::Bytes,
    ) -> Json<serde_json::Value> {
        bodies
            .write()
            .push(serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null));
        Json(serde_json::json!({"jsonrpc":"2.0","id":1,"result":{}}))
    }

    let bodies: RecordedBodies = Arc::new(RwLock::new(Vec::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/messages", post(record))
        .with_state(Arc::clone(&bodies));
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}/messages"), bodies, server)
}

/// A transport whose peer is *determined* to speak the modern dialect, which is
/// the only state in which the opt-in may be sent.
async fn make_modern_transport(url: &str) -> Arc<HttpTransport> {
    use crate::protocol::era::{EraCache, ProbeOutcome};

    let era = Arc::new(EraCache::for_backend("tasks-opt-in-test"));
    let resolved = era
        .resolve_with(|| async {
            ProbeOutcome::Result(serde_json::json!({
                "capabilities": {},
                "supportedVersions": [MODERN_VERSIONS[0]],
            }))
        })
        .await;
    assert_eq!(resolved, Era::Modern, "test fixture must pin a modern peer");

    let transport = make_transport(url);
    transport.attach_era(era);
    transport
}

/// The `_meta` object of the single request the recorder received.
fn only_request_meta(bodies: &RecordedBodies) -> serde_json::Value {
    let bodies = bodies.read();
    assert_eq!(bodies.len(), 1, "expected exactly one request on the wire");
    bodies[0]["params"]["_meta"].clone()
}

/// MIK-8218 ERASNAP.2: while another holder has the era lock, a request to a
/// peer determined Modern still goes out modern-shaped. Before the fix the
/// held lock read as "no verdict" and the request went out legacy (no `_meta`).
#[tokio::test]
async fn a_held_era_lock_still_sends_a_modern_request() {
    let (url, bodies, server) = spawn_body_recorder().await;
    let transport = make_modern_transport(&url).await;
    let era = Arc::clone(transport.era.get().expect("the fixture attaches an era"));
    let held = era.hold_for_test().await;

    let sent = transport.request_with_headers(
        "tools/call",
        Some(serde_json::json!({"name": "read"})),
        &[],
        None,
        ResendPermission::Denied,
    );
    tokio::time::timeout(std::time::Duration::from_secs(10), sent)
        .await
        .expect("the request path never waits on the era lock")
        .expect("the recorder answers a well-formed result");
    drop(held);

    assert_eq!(
        only_request_meta(&bodies)[KEY_PROTOCOL_VERSION],
        MODERN_VERSIONS[0],
        "a held era lock shaped a request to a modern peer legacy"
    );
    server.abort();
}

/// The typed path is the only one that declares the extension, and it declares
/// exactly one — the implemented `tasks`, not whatever the caller passed.
#[tokio::test]
async fn task_capability_request_declares_only_the_tasks_extension() {
    let (url, bodies, server) = spawn_body_recorder().await;
    let transport = make_modern_transport(&url).await;

    // The caller supplies its own `_meta` key AND a forged capability set: the
    // first survives (it is not this transport's to discard), the second does not.
    let params = serde_json::json!({
        "name": "slow_tool",
        "_meta": {
            "trace": "keep-me",
            "io.modelcontextprotocol/clientCapabilities": {
                "extensions": {
                    "io.modelcontextprotocol/tasks": {"forged": true},
                    "com.example/elevated": {}
                }
            }
        }
    });

    transport
        .request_with_task_capability("tools/call", Some(params), &[], None)
        .await
        .expect("the recorder answers a well-formed result");

    let meta = only_request_meta(&bodies);
    assert_eq!(
        meta["io.modelcontextprotocol/clientCapabilities"],
        serde_json::json!({"extensions": {"io.modelcontextprotocol/tasks": {}}}),
        "only the implemented tasks extension may be declared, with an empty body"
    );
    assert_eq!(meta[KEY_PROTOCOL_VERSION], MODERN_VERSIONS[0]);
    assert_eq!(meta["trace"], "keep-me", "caller `_meta` keys survive");
    server.abort();
}

/// `tasks/get` carries the same declaration — the SDK requires it on every poll.
#[tokio::test]
async fn task_capability_request_declares_the_extension_on_tasks_get() {
    let (url, bodies, server) = spawn_body_recorder().await;
    let transport = make_modern_transport(&url).await;

    transport
        .request_with_task_capability(
            "tasks/get",
            Some(serde_json::json!({"taskId": "opaque-handle"})),
            &[],
            None,
        )
        .await
        .expect("the recorder answers a well-formed result");

    let meta = only_request_meta(&bodies);
    assert_eq!(
        meta["io.modelcontextprotocol/clientCapabilities"],
        serde_json::json!({"extensions": {"io.modelcontextprotocol/tasks": {}}})
    );
    server.abort();
}

/// The ordinary API cannot be talked into the opt-in. Same transport, same
/// method, same forged payload as the typed test above — empty capabilities.
#[tokio::test]
async fn ordinary_request_still_declares_empty_capabilities() {
    let (url, bodies, server) = spawn_body_recorder().await;
    let transport = make_modern_transport(&url).await;

    let params = serde_json::json!({
        "name": "slow_tool",
        "_meta": {
            "io.modelcontextprotocol/clientCapabilities": {
                "extensions": {"io.modelcontextprotocol/tasks": {}}
            }
        }
    });

    transport
        .request_with_headers(
            "tools/call",
            Some(params),
            &[],
            None,
            ResendPermission::Denied,
        )
        .await
        .expect("the recorder answers a well-formed result");

    let meta = only_request_meta(&bodies);
    assert_eq!(
        meta["io.modelcontextprotocol/clientCapabilities"],
        serde_json::json!({}),
        "an ordinary request declares no capabilities, whatever the caller put in `params`"
    );
    server.abort();
}

/// A method outside the adapter's vocabulary is refused locally: nothing is sent.
#[tokio::test]
async fn task_capability_refuses_a_method_outside_the_vocabulary() {
    let (url, bodies, server) = spawn_body_recorder().await;
    let transport = make_modern_transport(&url).await;

    let err = transport
        .request_with_task_capability("tasks/cancel", None, &[], None)
        .await
        .expect_err("`tasks/cancel` is not in this adapter's vocabulary");

    assert!(
        err.to_string().contains("tasks/cancel"),
        "the refusal must name the method, got: {err}"
    );
    assert!(
        bodies.read().is_empty(),
        "a refused method must not reach the wire"
    );
    server.abort();
}

/// A peer not known to be modern has no `_meta` envelope to read the opt-in
/// from, so the call is refused rather than sent — a synchronous answer to a
/// submission would be recorded as a task upstream never created.
#[tokio::test]
async fn task_capability_refuses_a_peer_not_known_to_be_modern() {
    let (url, bodies, server) = spawn_body_recorder().await;
    // No era cache attached: the era is undetermined, which reads as legacy.
    let transport = make_transport(&url);

    let err = transport
        .request_with_task_capability("tools/call", None, &[], None)
        .await
        .expect_err("a legacy/undetermined peer must not receive the opt-in");

    assert!(
        err.to_string().contains("2026"),
        "the refusal must name the dialect requirement, got: {err}"
    );
    assert!(
        bodies.read().is_empty(),
        "a refused era must not reach the wire"
    );
    server.abort();
}

/// The trait default fails locally instead of quietly degrading to an ordinary
/// request, which would submit a task the peer answers synchronously.
#[tokio::test]
async fn default_task_capability_impl_refuses_without_falling_back() {
    struct NoMetaTransport;

    #[async_trait]
    impl Transport for NoMetaTransport {
        async fn request(&self, _method: &str, _params: Option<Value>) -> Result<JsonRpcResponse> {
            panic!("the tasks opt-in must never fall back to the ordinary request path");
        }
        async fn notify(&self, _method: &str, _params: Option<Value>) -> Result<()> {
            Ok(())
        }
        fn is_connected(&self) -> bool {
            true
        }
        async fn close(&self) -> Result<()> {
            Ok(())
        }
    }

    let err = NoMetaTransport
        .request_with_task_capability("tools/call", None, &[], None)
        .await
        .expect_err("a transport with no modern `_meta` channel cannot declare the extension");
    assert!(
        err.to_string().contains("tools/call") && err.to_string().contains("tasks capability"),
        "the refusal must name the method and the reason, got: {err}"
    );
}
