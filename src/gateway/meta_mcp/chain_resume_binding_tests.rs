// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8137 BIND (chain rows R5, R6, R8): a chain resume binds its caller the
//! way the step that asked was bound when it minted, so a caller who can be
//! stopped can also come back.
//!
//! Before, the step minted under `principal_source(dispatch_binding)` while the
//! resume re-derived an identity-only fingerprint: a key-only caller was
//! refused -32602 ("requires a verified caller identity"), and a step behind an
//! identity-propagating backend was bound one way and opened another.
//! R7 (an identity-only step resumes) is
//! `mrtr_12_resume_applies_the_answers_to_the_pending_step`.
use super::*;

use crate::gateway::meta_mcp::Authentication;
use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};

/// A caller who declared elicitation, named by `who` and/or the key principal
/// `credential`.
fn ctx<'a>(
    who: Option<&'a VerifiedIdentity>,
    credential: Option<&'a str>,
    caps: &'a crate::protocol::meta::Declared,
    retry: &'a crate::protocol::mrtr::RetryFields,
) -> MetaMcpCallerContext<'a> {
    let base = match who {
        Some(who) => resuming_ctx(who, caps, retry),
        None => MetaMcpCallerContext {
            verified_identity: None,
            ..resuming_ctx(&IDLE, caps, retry)
        },
    };
    MetaMcpCallerContext {
        credential_principal: credential,
        authentication: if credential.is_some() {
            Authentication::Authenticated
        } else {
            base.authentication
        },
        credential_kind: if credential.is_some() {
            crate::security::audit::CredentialKind::ApiKey
        } else {
            base.credential_kind
        },
        ..base
    }
}

/// Only borrowed to build a context and then removed from it.
static IDLE: std::sync::LazyLock<VerifiedIdentity> = std::sync::LazyLock::new(identity);

async fn run(meta: &MetaMcp, id: i64, caller: MetaMcpCallerContext<'_>) -> Value {
    run_chain(meta, id, &chain(), caller).await
}

/// One `gateway_execute` of `chain`, as JSON.
async fn run_chain(
    meta: &MetaMcp,
    id: i64,
    chain: &Value,
    caller: MetaMcpCallerContext<'_>,
) -> Value {
    let response = Box::pin(meta.handle_tools_call(
        RequestId::Number(id),
        "gateway_execute",
        json!({ "chain": chain }),
        None,
        caller,
    ))
    .await;
    serde_json::to_value(&response).expect("response is JSON")
}

/// The resume reached the step that asked, with the answers.
fn resumed_the_pending_step(stub: &AsksOnce, resumed: &Value) {
    let asks = stub.calls_to("ask");
    assert_eq!(
        asks.len(),
        2,
        "the pending step runs once more on resume; resume said {resumed}"
    );
    assert!(
        asks[1].get("inputResponses").is_some(),
        "the answers reach the step that asked: {}",
        asks[1]
    );
}

/// R5: a key-only caller (no identity, an authenticated key) is stopped by a
/// step that asks and resumes it.
#[tokio::test]
async fn a_key_only_caller_resumes_a_chain_it_was_stopped_in() {
    let stub = Arc::new(AsksOnce::default());
    let meta = meta_over(Arc::clone(&stub));
    let caps = elicitation_caps();
    let no_retry = &crate::protocol::mrtr::NO_RETRY;
    let stop = run(&meta, 1, ctx(None, Some("cafe0001"), &caps, no_retry)).await;
    // Minted: a refusal here is a fixture accident, not this row's defect.
    let retry = answers(&handle_in(&stop));
    let resumed = run(&meta, 2, ctx(None, Some("cafe0001"), &caps, &retry)).await;
    assert!(resumed.get("error").is_none(), "{resumed}");
    resumed_the_pending_step(&stub, &resumed);
}

/// R8: the handle is refused to a caller who is not the one it was minted for:
/// another key, and another identity. Nothing reaches the backend, and the
/// refusal spends nothing: the owner still resumes with the same handle.
#[tokio::test]
async fn a_chain_handle_is_refused_to_another_principal() {
    type Who<'a> = (Option<&'a VerifiedIdentity>, Option<&'a str>);
    let caps = elicitation_caps();
    let no_retry = &crate::protocol::mrtr::NO_RETRY;
    let (alice, mut bob) = (identity(), identity());
    bob.subject = "bob".to_string();
    let cases: [(&str, Who<'_>, Who<'_>); 2] = [
        (
            "another key",
            (None, Some("cafe0001")),
            (None, Some("cafe0002")),
        ),
        ("another identity", (Some(&alice), None), (Some(&bob), None)),
    ];
    for (case, owner, other) in cases {
        let stub = Arc::new(AsksOnce::default());
        let meta = meta_over(Arc::clone(&stub));
        let stop = run(&meta, 1, ctx(owner.0, owner.1, &caps, no_retry)).await;
        let retry = answers(&handle_in(&stop));
        let stolen = run(&meta, 2, ctx(other.0, other.1, &caps, &retry)).await;
        assert_eq!(stolen["error"]["code"], json!(-32602), "{case}: {stolen}");
        assert_eq!(
            stub.calls_to("ask").len(),
            1,
            "{case}: resumed for a stranger"
        );
        let resumed = run(&meta, 3, ctx(owner.0, owner.1, &caps, &retry)).await;
        assert!(resumed.get("error").is_none(), "{case}: {resumed}");
        resumed_the_pending_step(&stub, &resumed);
    }
}

/// The per-user binding every propagated call in R6 dispatches under.
const BINDING: &str = "alice@https://srv.internal";

/// A propagation strategy that mints one fixed per-user binding, so the row
/// can seed the slot the call will use, and counts every mint.
struct FixedBinding(Arc<std::sync::atomic::AtomicUsize>);

#[async_trait::async_trait]
impl crate::identity_propagation::IdentityPropagation for FixedBinding {
    async fn propagate(
        &self,
        identity: &VerifiedIdentity,
        backend: &crate::identity_propagation::BackendDescriptor,
    ) -> Result<
        crate::identity_propagation::PropagatedCredential,
        crate::identity_propagation::PropagationError,
    > {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(crate::identity_propagation::PropagatedCredential {
            headers: vec![("Authorization".to_string(), "Bearer minted".to_string())],
            expires_at: i64::MAX,
            cache_binding: BINDING.to_string(),
            subject_key: identity.subject.clone(),
            audience: backend.audience.clone(),
            scopes: Vec::new(),
        })
    }
}

/// A gateway over one identity-propagating backend (stateless, required) whose
/// transport is `stub`: its calls dispatch under a per-user binding, so a
/// continuation is minted under that binding, not the identity. Returned with
/// the count of credentials minted.
fn propagating_meta_over(stub: Arc<AsksOnce>) -> (MetaMcp, Arc<std::sync::atomic::AtomicUsize>) {
    let registry = Arc::new(BackendRegistry::new());
    let config = BackendConfig {
        transport: crate::config::TransportConfig::Http {
            http_url: "https://srv.internal/mcp".to_string(),
            streamable_http: Some(true),
            protocol_version: None,
        },
        identity_propagation: Some(IdentityPropagationConfig {
            strategy: PropagationStrategyKind::SignedAssertion,
            audience: "https://srv.internal".to_string(),
            required: true,
            session_mode: SessionMode::Stateless,
            token_exchange_endpoint: None,
            token_exchange_scope: None,
        }),
        ..BackendConfig::r2_off()
    };
    let backend = Arc::new(Backend::new(
        "srv",
        config,
        &FailsafeConfig::default(),
        std::time::Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::clone(&stub) as Arc<dyn Transport>);
    // A propagated call runs on the caller's own slot, named by its binding.
    backend.set_pooled_transport_for_test(
        &crate::backend::PoolKey::PerUser {
            binding: BINDING.to_string(),
        },
        stub,
    );
    let _ = registry.register(backend);
    let mut meta = MetaMcp::new(registry);
    let mints = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    meta.set_identity_propagation(Arc::new(FixedBinding(Arc::clone(&mints))));
    // A required mint needs a durable audit record (MIK-6740).
    let log = tempfile::NamedTempFile::new().expect("tempfile");
    let path = log.path().to_string_lossy().to_string();
    std::mem::forget(log); // the logger appends to it for the whole test
    let config = Arc::new(crate::security::transparency_log::TransparencyLogConfig {
        enabled: true,
        path,
        key_id: "test".to_string(),
        ..Default::default()
    });
    meta.enable_transparency_log(Arc::new(
        crate::security::TransparencyLogger::open(config).expect("logger opens"),
    ));
    (meta, mints)
}

/// R6: a step behind an identity-propagating backend is minted under the
/// dispatch binding, and the resume opens it under that same binding.
#[tokio::test]
async fn a_chain_step_minted_under_a_dispatch_binding_resumes() {
    let stub = Arc::new(AsksOnce::default());
    let (meta, _) = propagating_meta_over(Arc::clone(&stub));
    let (who, caps) = (identity(), elicitation_caps());
    let no_retry = &crate::protocol::mrtr::NO_RETRY;
    let stop = run(&meta, 1, ctx(Some(&who), None, &caps, no_retry)).await;
    let handle = handle_in(&stop);
    // Premise: the binding is not the identity's, or this row is a copy of R7.
    let sealed = meta
        .continuation()
        .keyring()
        .open(&handle, crate::protocol::continuation::now_unix_secs())
        .expect("the handle is this gateway's own");
    assert_ne!(
        Some(sealed.principal_fingerprint),
        crate::protocol::mrtr::principal_fingerprint(Some(&who)),
        "premise: the step was minted under the dispatch binding"
    );
    let retry = answers(&handle);
    let resumed = run(&meta, 2, ctx(Some(&who), None, &caps, &retry)).await;
    assert!(resumed.get("error").is_none(), "{resumed}");
    resumed_the_pending_step(&stub, &resumed);
}

/// R13 (review, gpt HIGH): resolving a resume's binding can mint the caller's
/// credential, so nothing is minted for a step that is not the one that
/// stopped, nor for one the caller may not call. A handle presented with a
/// substituted chain, or by a caller the policy refuses, is refused with no
/// mint and no backend call; the owner's resume still runs afterwards.
#[tokio::test]
async fn a_resume_mints_nothing_for_a_substituted_chain_or_a_refused_caller() {
    use std::sync::atomic::Ordering;

    let stub = Arc::new(AsksOnce::default());
    let (meta, mints) = propagating_meta_over(Arc::clone(&stub));
    let (who, caps) = (identity(), elicitation_caps());
    let no_retry = &crate::protocol::mrtr::NO_RETRY;
    let stop = run(&meta, 1, ctx(Some(&who), None, &caps, no_retry)).await;
    let retry = answers(&handle_in(&stop));
    let minted = mints.load(Ordering::SeqCst);

    let substituted = json!([
        {"tool": "srv:other", "arguments": {}},
        {"tool": "srv:after", "arguments": {}}
    ]);
    let refused = run_chain(&meta, 2, &substituted, ctx(Some(&who), None, &caps, &retry)).await;
    assert_eq!(refused["error"]["code"], json!(-32602), "{refused}");
    // Only the pending step is denied, so the refusal is the step's policy,
    // not a refusal of `gateway_execute` itself.
    let denied = MetaMcpCallerContext {
        authorizer: &crate::gateway::authz::DenyOne { tool: "ask" },
        ..ctx(Some(&who), None, &caps, &retry)
    };
    let refused = run(&meta, 3, denied).await;
    assert!(
        refused
            .to_string()
            .contains("denied by test authorizer: 'ask'"),
        "{refused}"
    );
    assert_eq!(
        mints.load(Ordering::SeqCst),
        minted,
        "a refused resume minted a credential"
    );
    assert_eq!(
        stub.calls_to("ask").len(),
        1,
        "a refused resume reached the backend"
    );

    let resumed = run(&meta, 4, ctx(Some(&who), None, &caps, &retry)).await;
    assert!(resumed.get("error").is_none(), "{resumed}");
    resumed_the_pending_step(&stub, &resumed);
}
