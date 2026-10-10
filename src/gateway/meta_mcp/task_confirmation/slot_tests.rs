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
    fixture_on(SERVER, config, shared).await
}

/// [`fixture`] with the backend under a chosen name.
async fn fixture_on(server: &str, config: BackendConfig, shared: Option<Hint>) -> Fixture {
    let wire = Canned::new(shared.unwrap_or(Hint::Harmless));
    // A zero TTL, so a second fetch re-reads the wire instead of the cache.
    let backend = Arc::new(Backend::new(
        server,
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

/// A caller that may invoke everything: these rows test the gate's binding,
/// not visibility (MIK-8326 has its own rows).
fn open_scope() -> crate::gateway::meta_mcp::InvokeScope<'static> {
    crate::gateway::meta_mcp::InvokeScope {
        authorizer: &crate::gateway::authz::AllowAll,
        is_admin: true,
        api_key_name: None,
        agent_id: None,
        grant_subject: None,
    }
}

async fn ask_as(
    fx: &Fixture,
    retry: &RetryFields,
    declared: Declared,
    who: Option<&VerifiedIdentity>,
) -> TaskConfirmation {
    let actor = who.map(VerifiedIdentity::stable_actor_id);
    let principal = crate::protocol::mrtr::PrincipalSource::Credential(who);
    ask_principal(fx, retry, declared, (principal, actor.as_deref())).await
}

/// [`ask_as`] for any principal X14 binds (stdio's `Stdio { nonce }` among
/// them), with the admission actor its tasks are admitted under.
async fn ask_principal(
    fx: &Fixture,
    retry: &RetryFields,
    declared: Declared,
    (principal, actor): (crate::protocol::mrtr::PrincipalSource<'_>, Option<&str>),
) -> TaskConfirmation {
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
            principal,
            admission_actor: actor,
            scope: open_scope(),
            session_id: None,
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
    while let Some(key) = table.hold("filler", now + 300, now).await {
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

/// Mutant: a caller with no verified identity is treated as having an
/// already-admitted task, or replay recognition is dropped for everyone.
#[test]
fn an_unattributable_caller_is_never_an_admitted_replay() {
    let admission = ExecutionAdmission::new(Arc::new(|| 1_000));
    let (arguments, retry) = (json!({ "id": 1 }), fresh());
    let alice = identity();
    // The same operation, held under the verified owner's key.
    let owned =
        super::task_admission_request(alice.stable_actor_id(), KEY.to_owned(), TOOL, &arguments);
    let _held = admission.admit_task(owned.borrow());
    let alice_actor = alice.stable_actor_id();
    let alice_request = TaskConfirmationRequest {
        id: RequestId::Number(7),
        tool_name: TOOL,
        arguments: &arguments,
        task: None,
        retry: &retry,
        principal: crate::protocol::mrtr::PrincipalSource::Credential(None),
        admission_actor: Some(&alice_actor),
        scope: open_scope(),
        session_id: None,
        input_capabilities: Declared::NONE,
        is_modern: true,
        admission: &admission,
    };
    assert!(
        MetaMcp::already_admitted(&alice_request, KEY),
        "control: the verified owner's operation is recognised"
    );
    let unattributed = TaskConfirmationRequest {
        admission_actor: None,
        ..alice_request
    };
    assert!(!MetaMcp::already_admitted(&unattributed, KEY));
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

/// Two stdio processes: each draws its own nonce (`StdioNonce::process`).
const PROCESS_A: [u8; 32] = [0xA1; 32];
const PROCESS_B: [u8; 32] = [0xB2; 32];

/// [`ask_principal`] as the stdio process holding `nonce`, admitting its tasks
/// under the local operator as `stdio_tasks::intent` does.
async fn ask_stdio(fx: &Fixture, retry: &RetryFields, nonce: &[u8; 32]) -> TaskConfirmation {
    let principal = crate::protocol::mrtr::PrincipalSource::Stdio { nonce };
    let actor = Some(crate::gateway::meta_mcp::LOCAL_OPERATOR_PRINCIPAL);
    ask_principal(fx, retry, elicitation(), (principal, actor)).await
}

/// The retry that answers `outcome`'s challenge with `accept`.
fn accepting(outcome: &TaskConfirmation) -> RetryFields {
    let (_, issued_key, state) = challenge(outcome);
    RetryFields {
        input_responses: Some(json!({ issued_key: { "action": "accept" } })),
        request_state: Some(state),
        ..fresh()
    }
}

/// MIK-8160.X14.1 (P3, lead ruling 1): a stdio caller is challenged, bound
/// to its own process. Another stdio process cannot answer the grant; the
/// process that asked can, once.
#[tokio::test]
async fn a_stdio_grant_answers_only_the_process_that_asked() {
    let fx = fixture(BackendConfig::default(), Some(Hint::Destructive)).await;
    let retry = accepting(&ask_stdio(&fx, &fresh(), &PROCESS_A).await);
    assert!(
        !matches!(
            ask_stdio(&fx, &retry, &PROCESS_B).await,
            TaskConfirmation::Granted(_)
        ),
        "another stdio process answered this process's grant"
    );
    assert!(matches!(
        ask_stdio(&fx, &retry, &PROCESS_A).await,
        TaskConfirmation::Granted(_)
    ));
}

/// P3: a grant does not cross between stdio and HTTP in either direction;
/// each owner then redeems its own.
#[tokio::test]
async fn a_grant_does_not_cross_between_stdio_and_http() {
    let fx = fixture(BackendConfig::default(), Some(Hint::Destructive)).await;
    let stdio_grant = accepting(&ask_stdio(&fx, &fresh(), &PROCESS_A).await);
    assert!(
        !matches!(
            ask(&fx, &stdio_grant, elicitation()).await,
            TaskConfirmation::Granted(_)
        ),
        "an HTTP caller answered a stdio grant"
    );
    let http_grant = accepting(&ask(&fx, &fresh(), elicitation()).await);
    assert!(
        !matches!(
            ask_stdio(&fx, &http_grant, &PROCESS_A).await,
            TaskConfirmation::Granted(_)
        ),
        "a stdio caller answered an HTTP grant"
    );
    assert!(matches!(
        ask(&fx, &http_grant, elicitation()).await,
        TaskConfirmation::Granted(_)
    ));
    assert!(matches!(
        ask_stdio(&fx, &stdio_grant, &PROCESS_A).await,
        TaskConfirmation::Granted(_)
    ));
}

/// P3 replay row: a stdio retry of a destructive task this gateway already
/// admitted, carrying no grant, is let through to admission (which returns the
/// task it owns), not challenged again. Pins `already_admitted` reading the
/// owner stdio admits under (`LOCAL_OPERATOR_PRINCIPAL`), never the nonce.
#[tokio::test]
async fn a_stdio_retry_of_an_admitted_task_is_not_asked_again() {
    let fx = fixture(BackendConfig::default(), Some(Hint::Destructive)).await;
    let arguments = json!({ "id": 1 });
    let owned = super::task_admission_request(
        crate::gateway::meta_mcp::LOCAL_OPERATOR_PRINCIPAL.to_owned(),
        KEY.to_owned(),
        TOOL,
        &arguments,
    );
    let _held = fx.admission.admit_task(owned.borrow());
    assert!(
        matches!(
            ask_stdio(&fx, &fresh(), &PROCESS_A).await,
            TaskConfirmation::Granted(_)
        ),
        "an admitted stdio task was challenged again"
    );
}

/// MIK-8326.X14.4 (WH.4): X14 never classifies a surfaced name this caller may
/// not invoke, whoever calls it. Defence in depth behind the route stage's
/// withheld-name answer: a challenge would confirm the tool exists. Control:
/// the same call from a caller who may invoke it is challenged.
#[tokio::test]
async fn x14_does_not_classify_a_name_the_caller_may_not_invoke() {
    let fx = fixture(BackendConfig::default(), Some(Hint::Destructive)).await;
    let (arguments, task, retry) = (json!({ "id": 1 }), json!({ "ttl": 60_000 }), fresh());
    let alice = identity();
    let actor = alice.stable_actor_id();
    let denied = crate::gateway::meta_mcp::InvokeScope {
        authorizer: &crate::gateway::authz::DenyAll,
        ..open_scope()
    };
    let outcome = fx
        .meta
        .confirm_destructive_task(&TaskConfirmationRequest {
            id: RequestId::Number(7),
            tool_name: TOOL,
            arguments: &arguments,
            task: Some(&task),
            retry: &retry,
            principal: crate::protocol::mrtr::PrincipalSource::Credential(Some(&alice)),
            admission_actor: Some(&actor),
            scope: denied,
            session_id: None,
            input_capabilities: elicitation(),
            is_modern: true,
            admission: &fx.admission,
        })
        .await;
    assert!(
        matches!(outcome, TaskConfirmation::NotRequired),
        "X14 decided a withheld tool: {outcome:?}"
    );
    assert!(
        matches!(
            ask(&fx, &fresh(), elicitation()).await,
            TaskConfirmation::Answer(_)
        ),
        "control: a caller who may invoke it is challenged"
    );
}
