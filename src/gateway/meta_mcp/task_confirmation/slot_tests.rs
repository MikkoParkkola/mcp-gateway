// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which tool-cache slot the destructive task gate classifies from.
//!
//! The call dispatches on the caller's slot. For a backend with identity
//! propagation that slot cannot be named before the credential is minted, and
//! the gate must not mint, so the shared slot says nothing about it. A tool
//! whose catalogue entry cannot be read from the dispatch slot is confirmed as
//! if it were destructive.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use super::{TaskConfirmation, TaskConfirmationRequest};
use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig, SurfacedToolConfig};
use crate::gateway::meta_mcp::MetaMcp;
use crate::idempotency::admission::ExecutionAdmission;
use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};
use crate::key_server::oidc::VerifiedIdentity;
use crate::protocol::meta::Declared;
use crate::protocol::mrtr::RetryFields;
use crate::protocol::{JsonRpcResponse, RequestId, Tool, ToolAnnotations, ToolsListResult};

const SERVER: &str = "ledger";
const TOOL: &str = "delete_issue";
const KEY: &str = "key-1";

/// What the fixture upstream says about `TOOL`.
#[derive(Clone, Copy)]
enum Hint {
    Destructive,
    Harmless,
}

/// A transport serving one tool list; the hint can be changed between fetches.
struct Canned {
    destructive: std::sync::atomic::AtomicBool,
}

impl Canned {
    fn new(hint: Hint) -> Arc<Self> {
        Arc::new(Self {
            destructive: std::sync::atomic::AtomicBool::new(matches!(hint, Hint::Destructive)),
        })
    }

    fn set(&self, hint: Hint) {
        self.destructive
            .store(matches!(hint, Hint::Destructive), Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl crate::transport::Transport for Canned {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        assert_eq!(method, "tools/list", "fixture serves only tools/list");
        let tool = Tool {
            name: TOOL.to_string(),
            title: None,
            description: Some("slot fixture".to_string()),
            input_schema: json!({ "type": "object" }),
            output_schema: None,
            annotations: Some(ToolAnnotations {
                destructive_hint: Some(self.destructive.load(Ordering::SeqCst)),
                ..ToolAnnotations::default()
            }),
            role: None,
            projection: None,
        };
        Ok(JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            ToolsListResult {
                tools: vec![tool],
                next_cursor: None,
            },
        ))
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

/// Counts every mint. The gate must never reach it.
struct CountingMint(AtomicUsize);

#[async_trait::async_trait]
impl crate::identity_propagation::IdentityPropagation for CountingMint {
    async fn propagate(
        &self,
        identity: &VerifiedIdentity,
        backend: &crate::identity_propagation::BackendDescriptor,
    ) -> Result<
        crate::identity_propagation::PropagatedCredential,
        crate::identity_propagation::PropagationError,
    > {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(crate::identity_propagation::PropagatedCredential {
            headers: vec![("Authorization".to_string(), "Bearer minted".to_string())],
            expires_at: i64::MAX,
            cache_binding: format!("{}@{}", identity.subject, backend.audience),
            subject_key: identity.subject.clone(),
            audience: backend.audience.clone(),
            scopes: Vec::new(),
        })
    }
}

fn propagating() -> BackendConfig {
    BackendConfig {
        identity_propagation: Some(IdentityPropagationConfig {
            strategy: PropagationStrategyKind::SignedAssertion,
            audience: SERVER.to_string(),
            required: true,
            session_mode: SessionMode::PerUser,
            token_exchange_endpoint: None,
            token_exchange_scope: None,
        }),
        ..Default::default()
    }
}

struct Fixture {
    meta: MetaMcp,
    wire: Arc<Canned>,
    backend: Arc<Backend>,
    mint: Arc<CountingMint>,
    admission: Arc<ExecutionAdmission>,
}

/// One surfaced tool on one backend. `shared` primes the shared slot with
/// that hint; `None` leaves it cold.
async fn fixture(config: BackendConfig, shared: Option<Hint>) -> Fixture {
    let wire = Canned::new(shared.unwrap_or(Hint::Harmless));
    // A zero TTL, so a second fetch re-reads the wire instead of the cache.
    let backend = Arc::new(Backend::new(
        SERVER,
        config,
        &FailsafeConfig::default(),
        Duration::ZERO,
    ));
    backend.set_transport_for_test(wire.clone());
    if shared.is_some() {
        backend
            .get_tools_shared()
            .await
            .expect("fixture primes the shared slot");
    }
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(Arc::clone(&backend)), "fixture registers");
    let meta = MetaMcp::new(registry).with_surfaced_tools(vec![SurfacedToolConfig {
        server: SERVER.to_string(),
        tool: TOOL.to_string(),
    }]);
    assert_eq!(
        meta.surfaced_tool_server(TOOL),
        Some(SERVER),
        "premise: surfaced"
    );
    let mint = Arc::new(CountingMint(AtomicUsize::new(0)));
    meta.set_identity_propagation(mint.clone());
    Fixture {
        meta,
        wire,
        backend,
        mint,
        admission: ExecutionAdmission::new(Arc::new(|| 1_000)),
    }
}

fn identity() -> VerifiedIdentity {
    VerifiedIdentity {
        subject: "alice".to_string(),
        email: "alice@example.invalid".to_string(),
        name: None,
        groups: Vec::new(),
        issuer: "https://issuer.example.invalid".to_string(),
    }
}

fn elicitation() -> Declared {
    Declared::from_handshake(Some(&json!({ "elicitation": {} })))
}

fn fresh() -> RetryFields {
    RetryFields {
        input_responses: None,
        request_state: None,
        idempotency_key: Some(KEY.to_string()),
        malformed: Vec::new(),
        attestation: None,
    }
}

async fn ask(fx: &Fixture, retry: &RetryFields, declared: Declared) -> TaskConfirmation {
    let who = identity();
    let arguments = json!({ "id": 1 });
    let task = json!({ "ttl": 60_000 });
    let outcome = fx
        .meta
        .confirm_destructive_task(&TaskConfirmationRequest {
            id: RequestId::Number(7),
            tool_name: TOOL,
            arguments: &arguments,
            task: Some(&task),
            retry,
            verified_identity: Some(&who),
            input_capabilities: declared,
            is_modern: true,
            admission: &fx.admission,
        })
        .await;
    assert_eq!(fx.mint.0.load(Ordering::SeqCst), 0, "the gate never mints");
    outcome
}

/// States that are not confirmation grants: garbage, and an authentic envelope
/// minted for a backend exchange, which only the purpose check tells apart.
async fn foreign_states(fx: &Fixture) -> Vec<String> {
    let payload = fx
        .meta
        .continuation
        .begin_exchange(
            SERVER.to_string(),
            None,
            "fingerprint".to_string(),
            "digest".to_string(),
            crate::protocol::continuation::now_unix_secs(),
        )
        .await
        .expect("a backend exchange can be held");
    let envelope = fx
        .meta
        .continuation
        .keyring()
        .mint(&payload)
        .expect("a backend envelope mints");
    vec!["not-a-confirmation-grant".to_string(), envelope]
}

/// The challenge's prompt, issued key and sealed state, or a panic naming
/// what came back instead.
fn challenge(outcome: &TaskConfirmation) -> (String, String, String) {
    let TaskConfirmation::Answer(response) = outcome else {
        panic!("expected a challenge, got {outcome:?}");
    };
    let result = response.result.as_ref().expect("a challenge is a result");
    let (key, request) = result["inputRequests"]
        .as_object()
        .and_then(|requests| requests.iter().next())
        .expect("a challenge asks one question");
    (
        request["params"]["message"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        key.clone(),
        result["requestState"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    )
}

const UNCLASSIFIED: &str = "could not be established";

/// T1: the shared slot is not the dispatch slot on a propagating backend, so
/// its "harmless" proves nothing and the call is confirmed.
#[tokio::test]
async fn propagating_backend_ignores_a_harmless_shared_slot() {
    let fx = fixture(propagating(), Some(Hint::Harmless)).await;
    let (message, _, _) = challenge(&ask(&fx, &fresh(), elicitation()).await);
    assert!(
        message.contains(UNCLASSIFIED),
        "unclassified prompt: {message}"
    );
}

/// T2: nothing cached anywhere on a propagating backend.
#[tokio::test]
async fn propagating_backend_with_a_cold_shared_slot_is_confirmed() {
    let fx = fixture(propagating(), None).await;
    let (message, _, _) = challenge(&ask(&fx, &fresh(), elicitation()).await);
    assert!(
        message.contains(UNCLASSIFIED),
        "unclassified prompt: {message}"
    );
}

/// T3 (guard): an ordinary backend's harmless tool is not the gate's business.
#[tokio::test]
async fn ordinary_backend_harmless_tool_is_not_confirmed() {
    let fx = fixture(BackendConfig::default(), Some(Hint::Harmless)).await;
    let outcome = ask(&fx, &fresh(), elicitation()).await;
    assert!(
        matches!(outcome, TaskConfirmation::NotRequired),
        "expected NotRequired, got {outcome:?}"
    );
}

/// T4 (guard): a known destructive tool keeps the destructive prompt.
#[tokio::test]
async fn ordinary_backend_destructive_tool_keeps_its_prompt() {
    let fx = fixture(BackendConfig::default(), Some(Hint::Destructive)).await;
    let (message, _, _) = challenge(&ask(&fx, &fresh(), elicitation()).await);
    assert!(
        message.contains("destructive tool"),
        "destructive prompt: {message}"
    );
    assert!(
        !message.contains(UNCLASSIFIED),
        "not unclassified: {message}"
    );
}

/// T5: a cold shared slot on an ordinary backend is not "harmless".
#[tokio::test]
async fn ordinary_backend_with_a_cold_slot_is_confirmed() {
    let fx = fixture(BackendConfig::default(), None).await;
    let (message, _, _) = challenge(&ask(&fx, &fresh(), elicitation()).await);
    assert!(
        message.contains(UNCLASSIFIED),
        "unclassified prompt: {message}"
    );
}

/// T6: a client that cannot be asked is refused, in words that do not claim
/// the tool is known to be destructive.
#[tokio::test]
async fn unclassified_without_elicitation_is_refused_as_unclassified() {
    let fx = fixture(propagating(), None).await;
    let outcome = ask(&fx, &fresh(), Declared::NONE).await;
    let TaskConfirmation::Answer(response) = &outcome else {
        panic!("expected a refusal, got {outcome:?}");
    };
    let error = response.error.as_ref().expect("a refusal is an error");
    assert_eq!(error.code, -32021);
    assert!(
        error.message.contains("could not be classified"),
        "refusal text: {}",
        error.message
    );
}

/// T7: a grant issued while the tool read destructive is still redeemed after
/// the slot re-reads it as harmless. Classification is not re-litigated
/// against a grant the caller already holds.
#[tokio::test]
async fn a_held_grant_is_redeemed_after_the_slot_turns_harmless() {
    let fx = fixture(BackendConfig::default(), Some(Hint::Destructive)).await;
    let (_, issued_key, state) = challenge(&ask(&fx, &fresh(), elicitation()).await);

    fx.wire.set(Hint::Harmless);
    fx.backend.get_tools_shared().await.expect("slot re-fills");
    assert!(
        matches!(
            ask(&fx, &fresh(), elicitation()).await,
            TaskConfirmation::NotRequired
        ),
        "premise: the tool now reads harmless"
    );

    let retry = RetryFields {
        input_responses: Some(json!({ issued_key: { "action": "accept" } })),
        request_state: Some(state),
        ..fresh()
    };
    let outcome = ask(&fx, &retry, elicitation()).await;
    let TaskConfirmation::Granted(cleared) = &outcome else {
        panic!("expected Granted, got {outcome:?}");
    };
    assert!(
        cleared.request_state.is_none(),
        "grant metadata is stripped"
    );
}

/// T8 (guard): a harmless call carrying some other layer's state is left alone.
#[tokio::test]
async fn a_foreign_request_state_on_a_harmless_call_is_not_ours() {
    let fx = fixture(BackendConfig::default(), Some(Hint::Harmless)).await;
    for state in foreign_states(&fx).await {
        let retry = RetryFields {
            request_state: Some(state),
            ..fresh()
        };
        let outcome = ask(&fx, &retry, elicitation()).await;
        assert!(
            matches!(outcome, TaskConfirmation::NotRequired),
            "expected NotRequired, got {outcome:?}"
        );
    }
}

/// T11: a requestState that is not a confirmation grant exempts nothing. On a
/// call that must be confirmed it is presented as a grant and refused.
#[tokio::test]
async fn a_foreign_request_state_does_not_exempt_an_unclassified_call() {
    let fx = fixture(propagating(), None).await;
    for state in foreign_states(&fx).await {
        let retry = RetryFields {
            request_state: Some(state),
            ..fresh()
        };
        let outcome = ask(&fx, &retry, elicitation()).await;
        let TaskConfirmation::Answer(response) = &outcome else {
            panic!("expected a refusal, got {outcome:?}");
        };
        assert!(
            response.error.is_some(),
            "refused, not challenged: {response:?}"
        );
    }
}
