// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A capability that shares a backend's name never receives that backend's
//! secrets: its REST call is not a send to the backend, so no rule of the
//! backend's applies to it.
//!
//! Defence in depth, not a user-facing case: config load already refuses a
//! backend named like the capabilities source (`Config::validate`,
//! src/config/validation.rs), so only a gateway assembled in code, as here,
//! can pair the two.

use std::sync::Mutex;

use super::*;
use crate::secret_injection::{CredentialRule, CredentialType, InjectTarget};

/// The backend's secret: a literal, so no environment is read.
const SECRET: &str = "backend-only-secret-91d2";

/// What the capability's endpoint received: the request target, the
/// headers and the body, as text.
type Seen = Arc<Mutex<Vec<String>>>;

/// Registers capability `probe` under the source name `capabilities`, a POST
/// to a local endpoint that records every request.
async fn recording_capability(meta: &MetaMcp) -> Seen {
    let seen: Seen = Arc::default();
    let sink = Arc::clone(&seen);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        let app = axum::Router::new().route(
            "/probe",
            axum::routing::post(
                move |uri: axum::http::Uri, headers: axum::http::HeaderMap, body: String| {
                    let sink = Arc::clone(&sink);
                    async move {
                        sink.lock()
                            .expect("recorder")
                            .push(format!("{uri}\n{headers:?}\n{body}"));
                        axum::Json(json!({"ok": true}))
                    }
                },
            ),
        );
        axum::serve(listener, app).await.expect("serve");
    });
    let base_url = crate::test_fixture_host::fixture_url(port);
    let definition = crate::capability::parse_capability(&format!(
        "name: probe\ndescription: the capability under test\n\
         providers:\n  primary:\n    service: rest\n    config:\n      \
         base_url: {base_url}\n      path: /probe\n      method: POST\n"
    ))
    .expect("fixture capability");
    let client = crate::test_fixture_host::fixture_client(Duration::from_secs(5));
    let executor =
        Arc::new(crate::capability::CapabilityExecutor::new().with_test_http_client(client));
    let capabilities = Arc::new(crate::capability::CapabilityBackend::new(
        "capabilities",
        executor,
    ));
    capabilities
        .register_capability(definition)
        .expect("register");
    meta.set_capabilities(capabilities);
    seen
}

/// The backend sharing the capabilities source's name: lists nothing and
/// counts every `tools/call` it is sent.
struct Shadowed(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl crate::transport::Transport for Shadowed {
    async fn request(
        &self,
        method: &str,
        _params: Option<serde_json::Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        if method == "tools/call" {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        Ok(crate::protocol::JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            json!({"tools": []}),
        ))
    }
    async fn notify(&self, _method: &str, _params: Option<serde_json::Value>) -> crate::Result<()> {
        Ok(())
    }
    fn is_connected(&self) -> bool {
        true
    }
    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// A backend named `capabilities` with an `argument` rule for every tool: the
/// capability of that name sends no trace of the secret, in its target,
/// headers or body. The name clash is refused before dispatch
/// (`Error::AmbiguousBackend`), so neither the capability's endpoint nor the
/// backend's transport is sent anything at all.
#[tokio::test]
async fn a_capability_sharing_a_backend_name_gets_none_of_its_secrets() {
    let rule = CredentialRule {
        name: "api".to_string(),
        credential_type: CredentialType::ApiKey,
        value: SECRET.to_string(),
        inject_as: InjectTarget::Argument,
        inject_key: "api_key".to_string(),
        tools: vec!["*".to_string()],
    };
    let registry = Arc::new(BackendRegistry::with_secret_resolver(Arc::new(
        crate::secrets::SecretResolver::new(),
    )));
    let config = crate::config::BackendConfig {
        secrets: vec![rule],
        ..crate::config::BackendConfig::default()
    };
    let backend = Arc::new(crate::backend::Backend::new(
        "capabilities",
        config,
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    let backend_calls = Arc::new(AtomicUsize::new(0));
    backend.set_transport_for_test(Arc::new(Shadowed(Arc::clone(&backend_calls))));
    assert!(registry.register(backend));
    let meta = MetaMcp::new(registry);
    let seen = recording_capability(&meta).await;
    let answer = meta
        .invoke_tool(
            &json!({"server": "capabilities", "tool": "probe", "arguments": {"q": "x"}}),
            Some("session-1"),
            &allow_all_ctx_named(Some("alice"), None),
        )
        .await;
    assert!(
        matches!(
            &answer,
            Err(crate::Error::AmbiguousBackend { server, rule: None }) if server == "capabilities"
        ),
        "the clash is refused before dispatch: {answer:?}"
    );
    assert_eq!(
        seen.lock().expect("recorder").len(),
        0,
        "the capability's endpoint was sent nothing"
    );
    assert_eq!(
        backend_calls.load(Ordering::SeqCst),
        0,
        "the backend was sent nothing"
    );
}
