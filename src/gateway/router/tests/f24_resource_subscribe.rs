// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F24: `resources/subscribe` and `resources/unsubscribe` are refused at
//! dispatch, and never reach a backend of either era.
//!
//! Takes over what `meta_mcp::era_gate_tests` rows 14 to 15c proved about the
//! transport (a modern backend is never sent the verbs) and extends it to a
//! legacy backend. Before F24 a legacy backend was forwarded both verbs, and a
//! gateway that then dropped every `resources/updated` left the client waiting.

use super::*;

/// Records every method that reaches the wire. Answers `server/discover` the
/// way its era does, and everything else successfully, so "never arrived"
/// cannot pass because the peer refused.
struct RecordingPeer {
    methods: Mutex<Vec<String>>,
    modern: bool,
}

#[async_trait]
impl Transport for RecordingPeer {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::error::Result<JsonRpcResponse> {
        self.methods.lock().unwrap().push(method.to_string());
        let id = RequestId::Number(1);
        if method == "server/discover" {
            let code = if self.modern {
                crate::protocol::era::UNSUPPORTED_PROTOCOL_VERSION
            } else {
                crate::protocol::era::METHOD_NOT_FOUND_CODE
            };
            return Ok(JsonRpcResponse::error(Some(id), code, "declined"));
        }
        Ok(JsonRpcResponse::success_serialized(id, json!({})))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::error::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::error::Result<()> {
        Ok(())
    }
}

async fn peer(name: &str, modern: bool) -> (Arc<Backend>, Arc<RecordingPeer>) {
    let recorder = Arc::new(RecordingPeer {
        methods: Mutex::new(Vec::new()),
        modern,
    });
    let backend = Arc::new(Backend::new(
        name,
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let transport = Arc::clone(&recorder) as Arc<dyn Transport>;
    backend.set_transport_for_test(Arc::clone(&transport));
    backend.resolve_era_for_test(&transport).await;
    (backend, recorder)
}

async fn post(router: &axum::Router, body: Value, headers: &[(&str, &str)]) -> Value {
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let request = request
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    let bytes = to_bytes(response.into_body(), 65_536).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn resource_subscriptions_are_refused_and_reach_no_backend_of_either_era() {
    let (legacy, legacy_wire) = peer("legacy_peer", false).await;
    let (modern, modern_wire) = peer("modern_peer", true).await;
    let (state, _store) = test_router_app_state().await;
    assert!(state.backends.register(legacy) && state.backends.register(modern));
    let router = create_router(state);

    for method in ["resources/subscribe", "resources/unsubscribe"] {
        let legacy_answer = post(
            &router,
            json!({"jsonrpc": "2.0", "id": 1, "method": method,
                   "params": {"uri": "file:///owned.txt"}}),
            &[("mcp-protocol-version", "2025-06-18")],
        )
        .await;
        let modern_answer = post(
            &router,
            json!({"jsonrpc": "2.0", "id": 2, "method": method, "params": {
                "uri": "file:///owned.txt",
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }}),
            &[
                ("mcp-protocol-version", "2026-07-28"),
                ("mcp-method", method),
            ],
        )
        .await;
        for (era, answer) in [("legacy", &legacy_answer), ("modern", &modern_answer)] {
            assert_eq!(
                answer["error"]["code"], -32601,
                "{method} from a {era} client must be refused: {answer}"
            );
        }
    }

    for (era, wire) in [("legacy", &legacy_wire), ("modern", &modern_wire)] {
        let seen = wire.methods.lock().unwrap().clone();
        assert!(
            !seen.iter().any(|m| m.starts_with("resources/")),
            "no resources/* verb may reach the {era} backend: {seen:?}"
        );
    }
}
