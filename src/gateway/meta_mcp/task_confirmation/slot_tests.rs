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
    /// Answer a fresh `tools/call` with a question (MIK-8293 S3d); off, a
    /// call is a fixture error.
    asks: std::sync::atomic::AtomicBool,
}

impl Canned {
    fn new(hint: Hint) -> Arc<Self> {
        Arc::new(Self {
            destructive: std::sync::atomic::AtomicBool::new(matches!(hint, Hint::Destructive)),
            asks: std::sync::atomic::AtomicBool::new(false),
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
        if method == "tools/call" && self.asks.load(Ordering::SeqCst) {
            return Ok(JsonRpcResponse::success(
                RequestId::Number(1),
                json!({
                    "resultType": "input_required",
                    "inputRequests": {"k1": {"method": "elicitation/create",
                        "params": {"message": "Which account?", "requestedSchema": {"type": "object"}}}},
                    "requestState": "backend-state-1"
                }),
            ));
        }
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
    fixture_on(SERVER, config, shared).await
}

/// [`fixture`] with the backend under a chosen name.
async fn fixture_on(server: &str, config: BackendConfig, shared: Option<Hint>) -> Fixture {
    let wire = Canned::new(shared.unwrap_or(Hint::Harmless));
    // A zero TTL, so a second fetch re-reads the wire instead of the cache.
    let backend = Arc::new(Backend::new(
        server,
        config,
        // No row here tests the per-backend rate limiter, and S3d (MIK-8293)
        // sends 64 calls in a burst.
        &FailsafeConfig {
            rate_limit: crate::config::RateLimitConfig {
                enabled: false,
                ..crate::config::RateLimitConfig::default()
            },
            ..FailsafeConfig::default()
        },
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
        server: server.to_string(),
        tool: TOOL.to_string(),
    }]);
    assert_eq!(
        meta.surfaced_tool_server(TOOL),
        Some(server),
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
    ask_as(fx, retry, declared, Some(&identity())).await
}

async fn ask_as(
    fx: &Fixture,
    retry: &RetryFields,
    declared: Declared,
    who: Option<&VerifiedIdentity>,
) -> TaskConfirmation {
    let arguments = json!({ "id": 1 });
    let task = json!({ "ttl": 60_000 });
    // What the HTTP edge hands over for this caller: its binding through
    // `principal_source`, as the edge derives it, and the task owner it
    // routes to. No identity here means no key either: unbindable.
    let caller = crate::gateway::meta_mcp::MetaMcpCallerContext {
        verified_identity: who,
        ..crate::gateway::meta_mcp::anonymous_caller()
    };
    let principal = crate::protocol::mrtr::source_fingerprint(caller.principal_source(None));
    let owner = who
        .map(VerifiedIdentity::stable_actor_id)
        .unwrap_or_default();
    let outcome = fx
        .meta
        .confirm_destructive_task(&TaskConfirmationRequest {
            id: RequestId::Number(7),
            tool_name: TOOL,
            arguments: &arguments,
            task: Some(&task),
            retry,
            verified_identity: who,
            principal,
            quota: caller.quota_key(),
            owner: &owner,
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
            &crate::protocol::continuation::QuotaKey::for_test("fingerprint"),
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
    // The refusal names exactly the capability to declare: the confirmation
    // capability, which `challenge` now reads from its constant (MIK-8248).
    assert_eq!(
        error.data.as_ref().map(|d| &d["requiredCapabilities"]),
        Some(&json!(["elicitation"])),
        "refusal data: {:?}",
        error.data
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

/// T12: with no verified identity the call runs on the shared slot, so a
/// harmless shared entry is believed even on a propagating backend.
#[tokio::test]
async fn an_anonymous_caller_is_classified_from_the_shared_slot() {
    let fx = fixture(propagating(), Some(Hint::Harmless)).await;
    let outcome = ask_as(&fx, &fresh(), elicitation(), None).await;
    assert!(
        matches!(outcome, TaskConfirmation::NotRequired),
        "expected NotRequired, got {outcome:?}"
    );

    // Destructive or missing: still never waved through for an anonymous
    // caller, who cannot be bound to a grant and is refused instead.
    for shared in [Some(Hint::Destructive), None] {
        let fx = fixture(propagating(), shared).await;
        let outcome = ask_as(&fx, &fresh(), elicitation(), None).await;
        let TaskConfirmation::Answer(response) = &outcome else {
            panic!("expected a refusal, got {outcome:?}");
        };
        assert!(response.error.is_some(), "refused: {response:?}");
    }
}

/// MIK-8137 R3 (BIND.2): a caller with neither an identity nor a key is still
/// refused as unbindable once key-only callers can be bound: binding the key
/// must not turn "no principal" into "everyone is one principal".
#[tokio::test]
async fn a_caller_with_no_identity_and_no_key_is_refused_as_unbindable() {
    let fx = fixture(BackendConfig::default(), Some(Hint::Destructive)).await;
    let (code, message) = refusal(&ask_as(&fx, &fresh(), elicitation(), None).await);
    assert_eq!(code, -32003, "{message}");
    assert!(message.contains("cannot name"), "{message}");
}

fn refusal(outcome: &TaskConfirmation) -> (i32, String) {
    let TaskConfirmation::Answer(response) = outcome else {
        panic!("expected a refusal, got {outcome:?}");
    };
    assert!(
        response.result.is_none(),
        "a refusal is no result: {response:?}"
    );
    let error = response.error.as_ref().expect("a refusal is an error");
    (error.code, error.message.clone())
}

/// A challenge answered with `accept`, and the payload sealed inside it.
async fn accepted_challenge(fx: &Fixture) -> (RetryFields, crate::protocol::continuation::Payload) {
    let (_, issued_key, state) = challenge(&ask(fx, &fresh(), elicitation()).await);
    let payload = fx
        .meta
        .continuation
        .keyring()
        .open(&state, crate::protocol::continuation::now_unix_secs())
        .expect("the issued grant is authentic");
    let retry = RetryFields {
        input_responses: Some(json!({ issued_key: { "action": "accept" } })),
        request_state: Some(state),
        ..fresh()
    };
    (retry, payload)
}

/// Mutant: the undeclared-capability refusal for a known destructive tool is
/// dropped, or reworded to claim the tool is unclassified.
#[tokio::test]
async fn a_destructive_call_from_a_client_that_cannot_be_asked_is_refused() {
    let fx = fixture(BackendConfig::default(), Some(Hint::Destructive)).await;
    let (code, message) = refusal(&ask(&fx, &fresh(), Declared::NONE).await);
    assert_eq!(code, -32021);
    assert!(message.contains("is destructive"), "{message}");
    assert!(!message.contains("could not be classified"), "{message}");
    // Positive control: the same call from a client that declared it can be asked.
    challenge(&ask(&fx, &fresh(), elicitation()).await);
}

/// Mutant: a full hold table still mints a grant naming an exchange nobody holds.
#[tokio::test]
async fn a_full_hold_table_refuses_the_challenge_and_mints_no_grant() {
    let fx = fixture(BackendConfig::default(), Some(Hint::Destructive)).await;
    let now = crate::protocol::continuation::now_unix_secs();
    let table = fx.meta.continuation.in_flight();
    let mut held = Vec::new();
    // A caller per hold: the table fills, not one caller's share (MIK-8293).
    while let Some(key) = table
        .hold(
            "filler",
            &crate::protocol::continuation::QuotaKey::for_test(&format!("filler-{}", held.len())),
            now + 300,
            now,
        )
        .await
    {
        held.push(key);
        assert!(held.len() <= 1 << 16, "the hold table is bounded");
    }
    assert!(!held.is_empty());
    assert_eq!(refusal(&ask(&fx, &fresh(), elicitation()).await).0, -32003);

    // Positive control: one freed slot and the same call is asked again.
    assert!(table.complete(&held[0], now).await);
    challenge(&ask(&fx, &fresh(), elicitation()).await);
}

/// Mutant: a mint failure is answered with a challenge, or with the grant.
#[tokio::test]
async fn a_grant_that_cannot_be_sealed_refuses_the_challenge() {
    // The backend's name is sealed into the envelope; one this long exceeds
    // the envelope bound, which is how a mint refuses.
    let long = "b".repeat(16 * 1024);
    let fx = fixture_on(&long, BackendConfig::default(), Some(Hint::Destructive)).await;
    assert_eq!(refusal(&ask(&fx, &fresh(), elicitation()).await).0, -32003);

    // Positive control: an ordinary name seals.
    let fx = fixture(BackendConfig::default(), Some(Hint::Destructive)).await;
    challenge(&ask(&fx, &fresh(), elicitation()).await);
}

/// Mutant: the hold check removed, so a grant for an exchange this replica no
/// longer holds is honoured, or the refusal also burns the caller's redemption.
#[tokio::test]
async fn a_grant_whose_hold_is_gone_is_refused_without_spending_it() {
    let fx = fixture(BackendConfig::default(), Some(Hint::Destructive)).await;
    let (retry, payload) = accepted_challenge(&fx).await;
    let now = crate::protocol::continuation::now_unix_secs();
    assert!(
        fx.meta
            .continuation
            .in_flight()
            .complete(&payload.hold_key, now)
            .await
    );
    assert_eq!(refusal(&ask(&fx, &retry, elicitation()).await).0, -32602);
    assert!(
        fx.meta
            .continuation
            .ledger()
            .consume(&payload.jti, payload.expires_at, now)
            .await,
        "the refusal came before the spend"
    );

    // Positive control: a grant whose hold is still live is granted.
    let (live, _) = accepted_challenge(&fx).await;
    assert!(matches!(
        ask(&fx, &live, elicitation()).await,
        TaskConfirmation::Granted(_)
    ));
}

/// Mutant: the spent check removed, so one grant is redeemed twice.
#[tokio::test]
async fn a_grant_already_spent_is_refused_and_a_fresh_one_is_granted_once() {
    let fx = fixture(BackendConfig::default(), Some(Hint::Destructive)).await;
    let (retry, payload) = accepted_challenge(&fx).await;
    let now = crate::protocol::continuation::now_unix_secs();
    assert!(
        fx.meta
            .continuation
            .ledger()
            .consume(&payload.jti, payload.expires_at, now)
            .await
    );
    assert_eq!(refusal(&ask(&fx, &retry, elicitation()).await).0, -32602);

    // Positive control: an unspent grant is granted, and only once.
    let (retry, _) = accepted_challenge(&fx).await;
    assert!(matches!(
        ask(&fx, &retry, elicitation()).await,
        TaskConfirmation::Granted(_)
    ));
    assert_eq!(refusal(&ask(&fx, &retry, elicitation()).await).0, -32602);
}

/// Mutant: a caller with no routed owner is treated as having an
/// already-admitted task, or replay recognition is dropped for everyone.
#[test]
fn an_unattributable_caller_is_never_an_admitted_replay() {
    let admission = ExecutionAdmission::new(Arc::new(|| 1_000));
    let (arguments, retry) = (json!({ "id": 1 }), fresh());
    let alice = identity().stable_actor_id();
    // The same operation, held under the routed owner's key.
    let owned = super::task_admission_request(alice.clone(), KEY.to_owned(), TOOL, &arguments);
    let _held = admission.admit_task(owned.borrow());
    let request = |owner| TaskConfirmationRequest {
        id: RequestId::Number(7),
        tool_name: TOOL,
        arguments: &arguments,
        task: None,
        retry: &retry,
        verified_identity: None,
        principal: Some("bound".to_string()),
        quota: Some(crate::protocol::continuation::QuotaKey::for_test("bound")),
        owner,
        input_capabilities: Declared::NONE,
        is_modern: true,
        admission: &admission,
    };
    assert!(
        MetaMcp::already_admitted(&request(&alice), KEY),
        "control: the routed owner's operation is recognised"
    );
    assert!(!MetaMcp::already_admitted(&request(""), KEY));
    assert!(!MetaMcp::already_admitted(
        &request("credential:other"),
        KEY
    ));
}

/// MIK-8202 (#3616 regression): a destructive call on a clock before 1970 is
/// refused, never challenged: no confirmation is minted against a time the
/// gateway cannot read. Control: the real clock challenges the same call.
#[tokio::test]
async fn a_destructive_call_on_a_clock_before_the_epoch_is_refused() {
    let fx = fixture(BackendConfig::default(), Some(Hint::Destructive)).await;
    let refused = {
        let _clock = crate::clock::test_clock::before_epoch();
        ask(&fx, &fresh(), elicitation()).await
    };
    let TaskConfirmation::Answer(response) = &refused else {
        panic!("a clock before 1970 challenged a destructive call: {refused:?}");
    };
    let error = response.error.as_ref().expect("a refusal is an error");
    assert_eq!(error.code, -32003, "{error:?}");
    assert!(response.result.is_none(), "a refusal carries no challenge");

    challenge(&ask(&fx, &fresh(), elicitation()).await);
}

/// S6b (MIK-8311 CSL.1): a task confirmation whose envelope mint fails gives
/// its slot back. The keyring refuses every envelope, so the gate takes a
/// slot, cannot seal the grant, and refuses; the slot must not stay held for
/// the envelope's lifetime. Red on base: the slot count grows by one.
/// Mutant m8: the release on the mint-failure path removed.
#[tokio::test]
async fn s6b_a_refused_confirmation_mint_gives_its_slot_back() {
    let mut fx = fixture(BackendConfig::default(), Some(Hint::Destructive)).await;
    fx.meta.set_continuation_for_test(
        crate::protocol::continuation::ContinuationState::mint_refusing_for_test(),
    );
    let now = crate::protocol::continuation::now_unix_secs();
    let before = fx.meta.continuation.in_flight().len(now).await;

    let outcome = ask(&fx, &fresh(), elicitation()).await;
    let TaskConfirmation::Answer(response) = &outcome else {
        panic!("setup: the gate did not answer: {outcome:?}");
    };
    assert!(
        response.error.is_some(),
        "setup: a refused mint must refuse, got {response:?}"
    );

    let after = fx.meta.continuation.in_flight().len(now).await;
    assert_eq!(
        after, before,
        "the refused confirmation kept its slot: {before} held before, {after} after"
    );
}

/// S3d (SLOTQ.3, SLOTQ.5): one verified identity has one cap across a tool
/// call and both confirmation gates. Alice's 64 `gateway_invoke` rounds hold
/// her cap; a task confirmation and an in-band meta confirmation, on the same
/// continuation store, are then both refused. Red on base: both are asked.
/// Mutant m6: a confirmation site keys the cap on its sealed principal.
#[tokio::test]
async fn s3d_one_identity_has_one_cap_across_invoke_and_both_confirmations() {
    let fx = fixture(BackendConfig::default(), Some(Hint::Destructive)).await;
    fx.wire.asks.store(true, Ordering::SeqCst);
    let alice = identity();
    let declared = crate::protocol::meta::classify_request(
        Some(&json!({"_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}}
        }})),
        Some("2026-07-28"),
    )
    .declared_capabilities();
    let no_retry = RetryFields::default();
    let caller = || crate::gateway::meta_mcp::MetaMcpCallerContext {
        verified_identity: Some(&alice),
        authentication: crate::gateway::meta_mcp::Authentication::Authenticated,
        input_capabilities: declared,
        retry: &no_retry,
        ..crate::gateway::meta_mcp::anonymous_caller()
    };
    let args = json!({"server": SERVER, "tool": TOOL, "arguments": {"id": 1}});
    for i in 0..64 {
        let asked = fx.meta.invoke_tool_for_test(&args, None, &caller()).await;
        assert!(
            asked
                .as_ref()
                .is_ok_and(|v| v.get("resultType") == Some(&json!("input_required"))),
            "setup: invoke {i} was not asked: {asked:?}"
        );
    }
    let now = crate::protocol::continuation::now_unix_secs();
    assert_eq!(
        fx.meta.continuation.in_flight().len(now).await,
        64,
        "setup: alice's rounds are held"
    );

    let task = ask(&fx, &fresh(), elicitation()).await;
    let TaskConfirmation::Answer(task_answer) = &task else {
        panic!("setup: the task gate did not answer: {task:?}");
    };
    let task_refused = task_answer.error.is_some();

    let mut meta_caller = caller();
    meta_caller.confirmation =
        crate::gateway::destructive_confirmation::ConfirmationChannel::InBand {
            continuation: &fx.meta.continuation,
        };
    // The in-band gate answers a challenge as `GateOutcome::Refuse` carrying a
    // success (`confirmation.rs`), so its outcome cannot say whether a slot was
    // taken; the slot count can.
    let before_meta = fx.meta.continuation.in_flight().len(now).await;
    let _meta_gate = crate::gateway::meta_mcp::destructive_confirmation_gate(
        &RequestId::Number(9),
        "gateway_kill_server",
        &json!({"server": "brave"}),
        None,
        &meta_caller,
    )
    .await;
    let meta_refused = fx.meta.continuation.in_flight().len(now).await == before_meta;
    assert!(
        task_refused && meta_refused,
        "alice took slots past her cap: task confirmation refused = {task_refused}, \
         meta confirmation refused = {meta_refused}"
    );
}
