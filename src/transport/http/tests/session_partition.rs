// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Per-identity MCP-Session-Id partitioning (MIK-6784, GW.1).

use super::*;

// =========================================================================
// MIK-6784 (GW.1): per-identity MCP-Session-Id partitioning
// =========================================================================

/// GW.1 unit: `build_mcp_headers` selects the session bound to the caller's
/// identity bucket, so two identities never share a session and a caller with
/// no negotiated session gets no session header at all.
#[tokio::test]
async fn build_headers_selects_session_per_identity_bucket() {
    let t = make_transport("http://localhost");
    t.sessions
        .write()
        .insert("alice".to_string(), "sess-alice".to_string());
    t.sessions
        .write()
        .insert("bob".to_string(), "sess-bob".to_string());
    t.sessions
        .write()
        .insert(String::new(), "sess-default".to_string());

    let alice = t
        .build_mcp_headers(HeaderMode::Request { method: "m" }, Some("alice"))
        .await
        .unwrap();
    let bob = t
        .build_mcp_headers(HeaderMode::Request { method: "m" }, Some("bob"))
        .await
        .unwrap();
    let anon = t
        .build_mcp_headers(HeaderMode::Request { method: "m" }, None)
        .await
        .unwrap();
    let absent = t
        .build_mcp_headers(HeaderMode::Request { method: "m" }, Some("carol"))
        .await
        .unwrap();

    assert_eq!(alice["mcp-session-id"], "sess-alice");
    assert_eq!(bob["mcp-session-id"], "sess-bob");
    assert_ne!(
        alice["mcp-session-id"], bob["mcp-session-id"],
        "two identities must never share a session id"
    );
    assert_eq!(
        anon["mcp-session-id"], "sess-default",
        "no-identity path uses the shared default bucket"
    );
    assert!(
        !absent.contains_key("mcp-session-id"),
        "an identity with no negotiated session sends no session header"
    );
}

/// Stateful mock backend for the session-partition test: a caller with no
/// session is minted a fresh unique one (and told which); a caller presenting a
/// session has it echoed back verbatim. Extracted from the test body to keep
/// the test under the line cap.
async fn partition_mock_handler(
    axum::extract::State(counter): axum::extract::State<Arc<std::sync::atomic::AtomicU32>>,
    headers: axum::http::HeaderMap,
    axum::Json(body): axum::Json<Value>,
) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use serde_json::json;

    if body.get("id").is_none() {
        return StatusCode::ACCEPTED.into_response();
    }
    let incoming = headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if incoming.is_empty() {
        let n = counter.fetch_add(1, Ordering::Relaxed) + 1;
        let minted = format!("sess-{n}");
        let mut resp_headers = axum::http::HeaderMap::new();
        resp_headers.insert("mcp-session-id", minted.parse().unwrap());
        (
            StatusCode::OK,
            resp_headers,
            axum::Json(json!({"jsonrpc": "2.0", "id": body["id"], "result": {"session": minted}})),
        )
            .into_response()
    } else {
        (
            StatusCode::OK,
            axum::Json(
                json!({"jsonrpc": "2.0", "id": body["id"], "result": {"session": incoming}}),
            ),
        )
            .into_response()
    }
}

/// GW.1 integration: against a stateful backend that mints a distinct session
/// per handshake, each caller identity negotiates and reuses its OWN session;
/// one identity's session is never stamped onto another's request. Regression
/// test for the Arc-shared single-session slot (MIK-6784).
#[tokio::test]
async fn stateful_backend_partitions_sessions_across_identities() {
    use axum::{Router, routing::post};

    let counter = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/mcp", post(partition_mock_handler))
        .with_state(Arc::clone(&counter));
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let transport = make_transport(&format!("http://{addr}/mcp"));

    let session_of = |resp: &JsonRpcResponse| -> String {
        resp.result.as_ref().unwrap()["session"]
            .as_str()
            .unwrap()
            .to_string()
    };

    // Each identity's first request negotiates its own session.
    let a1 = transport
        .request_with_headers(
            "tools/call",
            None,
            &[],
            Some("alice"),
            ResendPermission::Permitted,
        )
        .await
        .unwrap();
    let b1 = transport
        .request_with_headers(
            "tools/call",
            None,
            &[],
            Some("bob"),
            ResendPermission::Permitted,
        )
        .await
        .unwrap();
    let alice_session = session_of(&a1);
    let bob_session = session_of(&b1);
    assert_ne!(
        alice_session, bob_session,
        "distinct identities must negotiate distinct sessions"
    );

    // Second round: each identity reuses ITS OWN session — never the other's.
    let a2 = transport
        .request_with_headers(
            "tools/call",
            None,
            &[],
            Some("alice"),
            ResendPermission::Permitted,
        )
        .await
        .unwrap();
    let b2 = transport
        .request_with_headers(
            "tools/call",
            None,
            &[],
            Some("bob"),
            ResendPermission::Permitted,
        )
        .await
        .unwrap();
    assert_eq!(
        session_of(&a2),
        alice_session,
        "alice must reuse alice's session, not bob's"
    );
    assert_eq!(
        session_of(&b2),
        bob_session,
        "bob must reuse bob's session, not alice's"
    );

    // The transport's own bucket map reflects the partition.
    assert_eq!(
        transport.sessions.read().get("alice").cloned(),
        Some(alice_session)
    );
    assert_eq!(
        transport.sessions.read().get("bob").cloned(),
        Some(bob_session)
    );

    server.abort();
}
