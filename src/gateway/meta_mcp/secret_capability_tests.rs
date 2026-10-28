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
use crate::secret_injection::{CredentialRule, CredentialType, InjectTarget, SecretInjector};

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
    let definition = crate::capability::parse_capability(&format!(
        "name: probe\ndescription: the capability under test\n\
         providers:\n  primary:\n    service: rest\n    config:\n      \
         base_url: http://localhost:{port}\n      path: /probe\n      method: POST\n"
    ))
    .expect("fixture capability");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client");
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

/// A backend named `capabilities` with an `argument` rule for every tool: the
/// capability of that name sends no trace of the secret, in its target,
/// headers or body.
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
    let injector = SecretInjector::new(std::collections::HashMap::from([(
        "capabilities".to_string(),
        vec![rule],
    )]));
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new())).with_secret_injector(injector);
    let seen = recording_capability(&meta).await;
    let answer = meta
        .invoke_tool(
            &json!({"server": "capabilities", "tool": "probe", "arguments": {"q": "x"}}),
            Some("session-1"),
            &allow_all_ctx_named(Some("alice"), None),
        )
        .await;
    assert!(answer.is_ok(), "premise: the call succeeds: {answer:?}");
    let seen = seen.lock().expect("recorder").clone();
    assert_eq!(seen.len(), 1, "premise: the capability was called once");
    assert!(
        !seen[0].contains(SECRET),
        "the backend's secret reached the capability's endpoint: {}",
        seen[0]
    );
}
