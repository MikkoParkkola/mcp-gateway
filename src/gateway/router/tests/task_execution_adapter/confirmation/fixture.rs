// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;

pub(super) const DESTRUCTIVE: &str = "erase_fixture";

struct AnnotatedBackend(Arc<MockBackend>);

#[async_trait]
impl Transport for AnnotatedBackend {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        if method == "tools/list" {
            return Ok(JsonRpcResponse::success(
                RequestId::Number(1),
                json!({"tools": [
                    {"name": DESTRUCTIVE, "description": "Erase fixture data", "inputSchema": {"type": "object"},
                     "annotations": {"destructiveHint": true, "readOnlyHint": false}},
                    {"name": TOOL, "description": "Read fixture data", "inputSchema": {"type": "object"},
                     "annotations": {"destructiveHint": false, "readOnlyHint": true}}
                ]}),
            ));
        }
        self.0.request(method, params).await
    }
    async fn notify(&self, method: &str, params: Option<Value>) -> crate::Result<()> {
        self.0.notify(method, params).await
    }
    fn is_connected(&self) -> bool {
        true
    }
    async fn close(&self) -> crate::Result<()> {
        self.0.close().await
    }
}

pub(super) async fn fixture(mock: &Arc<MockBackend>) -> (Arc<AppState>, tempfile::TempDir) {
    fixture_with(mock, crate::config::Config::default(), |_| {}).await
}

/// [`fixture`] under `config`, with `meta` applied to the surfaced-tool
/// `MetaMcp` while it is still exclusively owned (signing goes in here).
pub(super) async fn fixture_with(
    mock: &Arc<MockBackend>,
    config: crate::config::Config,
    meta: impl FnOnce(&mut MetaMcp),
) -> (Arc<AppState>, tempfile::TempDir) {
    // Boxed: the setup future is large, and inlined it would be carried by
    // every row that awaits a fixture.
    Box::pin(fixture_under(mock, &two_principal_auth(), config, meta)).await
}

/// [`fixture`] with `key-k1` and `key-k2` added: two KEY-ONLY callers, which
/// `verified_subject` maps to no identity, so the only thing that tells them
/// apart is the credential itself (`MIK-8137`). Not added to
/// `two_principal_auth`, whose `three_principal_auth` already extends it.
pub(super) async fn key_only_fixture(
    mock: &Arc<MockBackend>,
) -> (Arc<AppState>, tempfile::TempDir) {
    let mut auth = two_principal_auth();
    for (key, name) in [("key-k1", "principal-k1"), ("key-k2", "principal-k2")] {
        let mut extra = auth.api_keys[0].clone();
        extra.key_sha256 = Some(crate::config::api_key_digest_spec(key.as_bytes()));
        extra.name = name.to_string();
        auth.api_keys.push(extra);
    }
    Box::pin(fixture_under(
        mock,
        &auth,
        crate::config::Config::default(),
        |_| {},
    ))
    .await
}

async fn fixture_under(
    mock: &Arc<MockBackend>,
    auth: &crate::config::AuthConfig,
    config: crate::config::Config,
    meta: impl FnOnce(&mut MetaMcp),
) -> (Arc<AppState>, tempfile::TempDir) {
    let (mut state, store) =
        crate::gateway::router::tests::test_router_app_state_with_auth_and_config(auth, config)
            .await;
    let inner = Arc::get_mut(&mut state).expect("fixture is not shared yet");
    let mut surfaced = MetaMcp::new(Arc::clone(&inner.backends)).with_surfaced_tools(vec![
        crate::config::SurfacedToolConfig {
            server: BACKEND.into(),
            tool: DESTRUCTIVE.into(),
        },
        crate::config::SurfacedToolConfig {
            server: BACKEND.into(),
            tool: TOOL.into(),
        },
    ]);
    meta(&mut surfaced);
    inner.meta_mcp = Arc::new(surfaced);
    let backend = Arc::new(Backend::new(
        BACKEND,
        BackendConfig {
            enabled: true,
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::new(AnnotatedBackend(Arc::clone(mock))));
    assert!(state.backends.register(Arc::clone(&backend)));
    backend
        .get_tools()
        .await
        .expect("load actual transport annotations");
    let listed = post(&state, "key-a", modern(1, "tools/list", json!({}), true)).await;
    let tools = listed
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .expect("public tool catalog");
    let destructive = tools
        .iter()
        .find(|tool| tool["name"] == DESTRUCTIVE)
        .expect("surfaced tool is visible");
    std::assert_eq!(
        destructive.pointer("/annotations/destructiveHint"),
        Some(&json!(true))
    );
    (state, store)
}

pub(super) fn request(key: &str) -> Value {
    declaring_elicitation(keyed(
        modern(
            2,
            "tools/call",
            json!({
                "name": DESTRUCTIVE, "arguments": {"record": "fixture"}, "task": {}
            }),
            true,
        ),
        key,
    ))
}

pub(super) fn retry(original: &Value, challenge: &Value, action: &str) -> Value {
    std::assert_eq!(
        challenge.pointer("/result/resultType"),
        Some(&json!("input_required"))
    );
    assert!(challenge.pointer("/result/taskId").is_none());
    let requests = challenge
        .pointer("/result/inputRequests")
        .and_then(Value::as_object)
        .expect("issued challenge");
    std::assert_eq!(requests.len(), 1);
    let (issued_key, _) = requests.iter().next().expect("one issued challenge");
    let token = challenge
        .pointer("/result/requestState")
        .and_then(Value::as_str)
        .expect("sealed grant");
    assert!(!token.is_empty());
    let mut retry = original.clone();
    retry["params"]["requestState"] = json!(token);
    retry["params"]["inputResponses"] = json!({issued_key: {"action": action}});
    retry
}
