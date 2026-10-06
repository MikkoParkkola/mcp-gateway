// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7810: `gateway_invoke` decides on the backend it captured at the start
//! of the credential stage, not on whatever the registry holds under that name
//! when a later check runs. A reload that swaps the backend while the mint is
//! awaited must not change which backend's rules (the OAuth-isolation guard)
//! apply, nor which backend the call is dispatched through.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use crate::backend::{Backend, BackendRegistry, PoolKey};
use crate::config::{BackendConfig, FailsafeConfig, OAuthConfig};
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::{Authentication, InvokeScope, MetaMcp, MetaMcpCallerContext};
use crate::gateway::router::CallerStanding;
use crate::identity_propagation::{
    BackendDescriptor, CallerProof, CallerProvenance, IdentityPropagation,
    IdentityPropagationConfig, PropagatedCredential, PropagationError, PropagationStrategyKind,
    SessionMode,
};
use crate::key_server::oidc::VerifiedIdentity;
use crate::protocol::RequestId;
use crate::security::audit::CredentialKind;
use crate::transport::Transport;

/// Answers `tools/list` and every `tools/call`, counting the calls it served.
struct Counting(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl Transport for Counting {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        if method == "tools/list" {
            return Ok(crate::protocol::JsonRpcResponse::success_serialized(
                RequestId::Number(1),
                json!({"tools": [{"name": "read", "inputSchema": {"type": "object"}}]}),
            ));
        }
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(crate::protocol::JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            json!({"content": [{"type": "text", "text": "ok"}], "isError": false}),
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

/// Counts only the `tools/list` requests it served: a cold-slot schema check
/// lists the backend as the caller, with the caller's headers.
struct Listing(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl Transport for Listing {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        if method == "tools/list" {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        Ok(crate::protocol::JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            json!({"tools": [{"name": "read", "inputSchema": {"type": "object"}}]}),
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

/// Swaps the registered backend while the credential is being minted (a config
/// reload landing in the await), then fails the mint, so the optional
/// propagation falls back to the static credential and the call carries on.
struct SwapDuringMint {
    registry: Arc<BackendRegistry>,
    replacement: Arc<Backend>,
    /// The mint fails as an account that is not connected, not a plain refusal.
    not_connected: bool,
}

#[async_trait::async_trait]
impl IdentityPropagation for SwapDuringMint {
    async fn propagate(
        &self,
        _identity: &VerifiedIdentity,
        _backend: &BackendDescriptor,
    ) -> Result<PropagatedCredential, PropagationError> {
        assert!(self.registry.remove("alpha"), "alpha was registered");
        assert!(
            self.registry.register(Arc::clone(&self.replacement)),
            "the reload registers the replacement"
        );
        Err(if self.not_connected {
            PropagationError::AccountNotConnected("connect the account".to_string())
        } else {
            PropagationError::Refuse("the mint failed".to_string())
        })
    }
}

/// A reload's `old.stop()` landing in the mint await: stops the backend the
/// call captured, registers its replacement, then fails the mint so the
/// optional propagation carries on. Fires once; the retry's mint only fails.
struct StopDuringMint {
    registry: Arc<BackendRegistry>,
    captured: Arc<Backend>,
    replacement: Arc<Backend>,
    fired: AtomicBool,
}

#[async_trait::async_trait]
impl IdentityPropagation for StopDuringMint {
    async fn propagate(
        &self,
        _identity: &VerifiedIdentity,
        _backend: &BackendDescriptor,
    ) -> Result<PropagatedCredential, PropagationError> {
        if !self.fired.swap(true, Ordering::SeqCst) {
            self.captured.stop().await.expect("stop never fails");
            assert!(self.registry.remove("alpha"), "alpha was registered");
            assert!(
                self.registry.register(Arc::clone(&self.replacement)),
                "the reload registers the replacement"
            );
        }
        Err(PropagationError::Refuse("the mint failed".to_string()))
    }
}

fn backend(config: BackendConfig, served: &Arc<AtomicUsize>) -> Arc<Backend> {
    let backend = Arc::new(Backend::new(
        "alpha",
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(Counting(Arc::clone(served))));
    backend
}

fn optional_propagation() -> BackendConfig {
    BackendConfig {
        identity_propagation: Some(IdentityPropagationConfig {
            strategy: PropagationStrategyKind::SignedAssertion,
            audience: "alpha".to_string(),
            required: false,
            session_mode: SessionMode::PerUser,
            token_exchange_endpoint: None,
            token_exchange_scope: None,
        }),
        ..BackendConfig::default()
    }
}

fn shared_login() -> BackendConfig {
    BackendConfig {
        oauth: Some(OAuthConfig {
            enabled: true,
            scopes: vec![],
            client_id: None,
            client_secret: None,
            callback_host: None,
            callback_port: None,
            callback_path: None,
            token_refresh_buffer_secs: 300,
            shared_account: false,
        }),
        ..BackendConfig::default()
    }
}

/// An authenticated OIDC caller invoking `alpha`'s `read` through the meta route.
async fn call_alpha(
    meta: &MetaMcp,
    retry: &crate::protocol::mrtr::RetryFields,
) -> crate::Result<Value> {
    let identity = VerifiedIdentity {
        subject: "alice".to_string(),
        email: "alice@example.invalid".to_string(),
        name: None,
        groups: vec![],
        issuer: "https://idp.example.invalid".to_string(),
    };
    let actor = identity.stable_actor_id();
    let principal = crate::gateway::auth::principal_of(&actor);
    let context = MetaMcpCallerContext {
        signing: None,
        execution: None,
        credential_principal: Some(principal.as_str()),
        authentication: Authentication::Authenticated,
        credential_kind: CredentialKind::OidcBearer,
        is_modern: false,
        protocol_revision: Some(crate::protocol::PROTOCOL_VERSION),
        authorizer: &AllowAll,
        api_key_name: Some(actor.as_str()),
        agent_id: None,
        agent_declared: None,
        grant_subject: Some(crate::identity_grants::GrantSubject::new(
            "https://idp.example.invalid",
            "alice",
            None,
        )),
        stdio_nonce: None,
        caller_key: None,
        verified_identity: Some(&identity),
        is_admin: false,
        input_capabilities: crate::protocol::meta::Declared::NONE,
        retry,
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
        task: None,
        era: crate::protocol::meta::Era::Legacy,
        channel: &crate::gateway::input_bridge::NoClientChannel,
    };

    meta.invoke_tool(
        &json!({"server": "alpha", "tool": "read", "arguments": {}}),
        None,
        &context,
    )
    .await
}

/// The captured backend has no gateway-held login, so the multi-user guard
/// passes for it and the call is served by it. The replacement the reload
/// registered mid-mint does hold one. Mutant: the guard (or the dispatch)
/// looked up by name judges or reaches the replacement: the call is refused as
/// if the shared login were the captured backend's, or it is served by the
/// replacement's transport.
#[tokio::test]
async fn a_reload_during_the_mint_does_not_change_the_backend_a_call_is_judged_or_served_by() {
    let (captured_calls, replacement_calls) =
        (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let registry = Arc::new(BackendRegistry::new());
    assert!(
        registry.register(backend(optional_propagation(), &captured_calls)),
        "registration"
    );
    let meta = MetaMcp::new(Arc::clone(&registry));
    meta.set_multi_user(true);
    meta.set_identity_propagation(Arc::new(SwapDuringMint {
        registry: Arc::clone(&registry),
        replacement: backend(shared_login(), &replacement_calls),
        not_connected: false,
    }));

    let answer = call_alpha(&meta, &crate::protocol::mrtr::NO_RETRY).await;

    assert!(
        answer.is_ok(),
        "the captured backend has no shared login: the reload must not refuse its call: {answer:?}"
    );
    assert_eq!(
        (
            captured_calls.load(Ordering::SeqCst),
            replacement_calls.load(Ordering::SeqCst)
        ),
        (1, 0),
        "the call must be served by the backend it was judged on"
    );
}

/// MIK-7948 MINTRACE.1/.2, MIK-7900 RELOAD.2 (mid-mint): a reload stops the
/// captured backend between capture and dispatch. The dispatch on the stopped
/// instance is refused before anything is sent (`BackendNotFound`), so
/// the key is released and the same-key retry runs once, on the replacement.
/// Schema enforcement is off so no cold `tools/list` refuses first. Mutant: a
/// stopped instance's refusal settled terminal serves the retry that refusal,
/// and the replacement never runs.
#[tokio::test]
async fn a_reload_that_stops_the_captured_backend_mid_mint_frees_the_key() {
    let (captured_calls, replacement_calls) =
        (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let config = || BackendConfig {
        input_schema_enforcement: crate::config::InputSchemaEnforcement::Off,
        ..optional_propagation()
    };
    let captured = backend(config(), &captured_calls);
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(Arc::clone(&captured)), "registration");
    let mut meta = MetaMcp::new(Arc::clone(&registry));
    meta.enable_idempotency(
        Arc::new(crate::idempotency::IdempotencyCache::new()),
        Duration::from_secs(300),
    );
    meta.set_multi_user(true);
    meta.set_identity_propagation(Arc::new(StopDuringMint {
        registry: Arc::clone(&registry),
        captured,
        replacement: backend(config(), &replacement_calls),
        fired: AtomicBool::new(false),
    }));
    let keyed = crate::protocol::mrtr::RetryFields {
        idempotency_key: Some("mint-race".to_owned()),
        ..Default::default()
    };

    let first = call_alpha(&meta, &keyed).await.expect("an answer");
    assert_eq!(first["isError"], true, "{first}");
    assert!(
        first.to_string().contains("Backend not found: alpha"),
        "refused before dispatch as the retired instance: {first}"
    );
    let retry = call_alpha(&meta, &keyed).await.expect("an answer");

    assert_eq!(
        (
            captured_calls.load(Ordering::SeqCst),
            replacement_calls.load(Ordering::SeqCst)
        ),
        (0, 1),
        "the stopped instance sent nothing, and the retry ran once on the replacement: {retry}"
    );
    assert_eq!(retry["isError"], false, "{retry}");
}

/// The schema check lists a cold slot as the caller, with the caller's minted
/// headers. It lists the backend the call was judged on. Mutant: the check
/// looks the name up again and sends those headers to the replacement.
#[tokio::test]
async fn the_schema_check_lists_the_captured_backend_not_the_replacement() {
    let (captured_lists, replacement_lists) =
        (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let registry = Arc::new(BackendRegistry::new());
    let make = |config, lists: &Arc<AtomicUsize>| {
        let backend = Arc::new(Backend::new(
            "alpha",
            config,
            &FailsafeConfig::default(),
            Duration::from_secs(300),
        ));
        let wire = Arc::new(Listing(Arc::clone(lists))) as Arc<dyn Transport>;
        backend.set_transport_for_test(Arc::clone(&wire));
        backend.set_pooled_transport_for_test(
            &PoolKey::PerUser {
                binding: "alice@alpha".to_owned(),
            },
            wire,
        );
        backend
    };
    let captured = make(optional_propagation(), &captured_lists);
    assert!(registry.register(Arc::clone(&captured)));
    // The reload: the registry now answers `alpha` with another backend.
    assert!(registry.remove("alpha"));
    assert!(registry.register(make(optional_propagation(), &replacement_lists)));
    let meta = MetaMcp::new(Arc::clone(&registry));

    let refusal = meta
        .undeclared_key_refusal(
            ("alpha", Some(&captured)),
            "read",
            &json!({"invented": 1}),
            Some("alice@alpha"),
            &[("Authorization".to_string(), "Bearer minted".to_string())],
            (InvokeScope::allow_all(CallerStanding::Standard), None),
        )
        .await;

    assert!(refusal.is_ok(), "the check itself answers: {refusal:?}");
    assert_eq!(
        (
            captured_lists.load(Ordering::SeqCst),
            replacement_lists.load(Ordering::SeqCst)
        ),
        (1, 0),
        "the caller's headers must reach only the backend the call was judged on"
    );
}

/// A mint that fails as "account not connected" is answered with the connect
/// offer for the account the captured backend names. The reload registered a
/// replacement bound to another account mid-mint. Mutant: the marking looks
/// the name up again and offers the replacement's account.
#[tokio::test]
async fn a_not_connected_refusal_offers_the_account_of_the_backend_it_was_judged_on() {
    let calls = Arc::new(AtomicUsize::new(0));
    let bound = |account: &str, required: bool| {
        let mut config = optional_propagation();
        config.account = Some(account.to_string());
        if let Some(propagation) = config.identity_propagation.as_mut() {
            propagation.required = required;
        }
        config
    };
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(backend(bound("acct-captured", true), &calls)));
    let meta = MetaMcp::new(Arc::clone(&registry));
    meta.set_multi_user(true);
    // An account-bound backend mints through its own installed strategy.
    meta.set_backend_identity_propagation(
        "alpha",
        Arc::new(SwapDuringMint {
            registry: Arc::clone(&registry),
            replacement: backend(bound("acct-replacement", true), &calls),
            not_connected: true,
        }),
    );

    // Straight at the resolver: the dispatch sites unmark an undecorated
    // refusal, so the mark is only observable here.
    let captured = registry.get("alpha").expect("registered");
    let idp_cfg = captured
        .identity_propagation_config()
        .cloned()
        .expect("propagation is configured");
    let identity = VerifiedIdentity {
        subject: "alice".to_string(),
        email: "alice@example.invalid".to_string(),
        name: None,
        groups: vec![],
        issuer: "https://idp.example.invalid".to_string(),
    };
    let caller = CallerProof::new(Some(&identity), CallerProvenance::Anonymous);

    let refused = meta
        .resolve_caller_credential_as("alpha", Some(&captured), &idp_cfg, caller)
        .await
        .expect_err("the mint failed");

    let marked = crate::personal_accounts::refusal::marked(&refused).expect("a marked refusal");
    assert_eq!(
        marked.account_id, "acct-captured",
        "the offer names the account of the backend the call was judged on"
    );
}

/// A chained backend's answer is never cached (D7). Whether the call is chained
/// is read off the backend it was judged on: the reload registered a chained
/// replacement under the same name. Mutant: the check looks the name up again.
#[test]
fn chain_eligibility_is_read_off_the_backend_the_call_was_judged_on() {
    let served = Arc::new(AtomicUsize::new(0));
    let chain = |mode| BackendConfig {
        signature_chain: mode,
        ..BackendConfig::default()
    };
    let registry = Arc::new(BackendRegistry::new());
    let captured = backend(chain(crate::config::ChainMode::Off), &served);
    assert!(registry.register(backend(chain(crate::config::ChainMode::Require), &served)));
    let mut meta = MetaMcp::new(Arc::clone(&registry));
    meta.set_chain_signer(
        crate::security::signature_chain::ChainSigner::from_seed(&[7; 32], "gw-test")
            .expect("signer"),
        crate::config::ChainEmit::OnRequest,
    );

    assert!(
        !meta.is_chained(Some(&captured)),
        "the captured backend is unchained, whatever the registry now holds"
    );
    assert!(
        meta.is_chained(registry.get("alpha").as_deref()),
        "a chained backend is chained"
    );
    assert!(!meta.is_chained(None), "no backend, no chain");
}
