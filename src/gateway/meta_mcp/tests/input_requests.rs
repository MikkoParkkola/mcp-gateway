// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Input requests, destructive confirmation and hidden-tool disclosure.

use super::*;

/// A caller context that permits everything and declares the given input
/// capabilities.
///
/// Separate from [`allow_all_ctx_named`] rather than a parameter added to it:
/// every existing call site passes no declaration, and a widened signature
/// would make each of them state a value it has no opinion about.
fn allow_all_ctx_declaring(
    declared: crate::protocol::meta::Declared,
) -> crate::gateway::meta_mcp::MetaMcpCallerContext<'static> {
    crate::gateway::meta_mcp::MetaMcpCallerContext {
        signing: None,
        execution: None,
        credential_principal: None,
        authentication: crate::gateway::meta_mcp::Authentication::Anonymous,
        credential_kind: crate::security::audit::CredentialKind::None,
        is_modern: false,
        protocol_revision: Some(crate::protocol::PROTOCOL_VERSION),
        authorizer: &ALLOW_ALL,
        api_key_name: None,
        agent_id: None,
        agent_declared: None,
        grant_subject: None,
        stdio_nonce: None,
        caller_key: None,
        verified_identity: Some(&NAMED_CALLER),
        is_admin: false,
        surface_request: crate::gateway::recovery::SurfaceRequest::Configured,
        input_capabilities: declared,
        retry: &crate::protocol::mrtr::NO_RETRY,
        confirmation: ConfirmationChannel::Unavailable,
        task: None,
        // Fail-closed: a helper that declared nothing is a 2025 client, the
        // same reasoning that puts `Declared::NONE` on the line above.
        era: crate::protocol::meta::Era::Legacy,
        channel: &crate::gateway::input_bridge::NoClientChannel,
    }
}

/// The same caller, unnameable: no API key, no agent, no verified identity.
fn anonymous_ctx_declaring(
    declared: crate::protocol::meta::Declared,
) -> crate::gateway::meta_mcp::MetaMcpCallerContext<'static> {
    crate::gateway::meta_mcp::MetaMcpCallerContext {
        verified_identity: None,
        ..allow_all_ctx_declaring(declared)
    }
}

/// A backend that answers every `tools/call` with an interim result asking for
/// an elicitation.
fn backend_asking_for_elicitation() -> Arc<BackendRegistry> {
    use crate::backend::Backend;
    use crate::config::{BackendConfig, FailsafeConfig};
    use crate::transport::Transport;

    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        "booking",
        BackendConfig::r2_off(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    let transport: Arc<dyn Transport> = Arc::new(ToolCallTestTransport {
        result: json!({
            "resultType": "input_required",
            "inputRequests": {
                "confirm": {
                    "method": "elicitation/create",
                    "params": { "message": "Charge the card?" }
                }
            },
            "requestState": "backend-opaque"
        }),
    });
    backend.set_transport_for_test(transport);
    let _ = registry.register(backend);
    registry
}

fn book_flight() -> serde_json::Value {
    json!({ "server": "booking", "tool": "book_flight", "arguments": {} })
}

// The other half of the same gate: it must not be a blanket refusal of every
// interim result. A declared capability passes through.
//
// MRTR.2 rides on the same call, because the two are one observable event: the
// question reaches the client, and what it carries as `requestState` is the
// gateway's sealed envelope rather than the backend's own string. Asserting
// only `resultType` here would have passed unchanged the day minting landed —
// a case that cannot fail is worse than one that breaks.
#[tokio::test]
async fn a_declared_input_request_passes_the_gateway_gate() {
    let meta = MetaMcp::new(backend_asking_for_elicitation());

    let result = meta
        .invoke_tool(
            &book_flight(),
            Some("session-1"),
            &allow_all_ctx_declaring(declaring(&json!({"elicitation": {}}))),
        )
        .await
        .expect("a declared capability must not be refused");
    assert_eq!(
        result["resultType"], "input_required",
        "the interim result must reach the client intact: {result:#}"
    );

    let state = result["requestState"]
        .as_str()
        .expect("an interim result must carry a requestState for the client to echo");
    assert_ne!(
        state, "backend-opaque",
        "the backend's own state must never reach the client: {result:#}"
    );

    let payload = meta
        .continuation()
        .keyring()
        .open(state, crate::protocol::continuation::now_unix_secs())
        .expect("the envelope must open on the replica that minted it");
    assert_eq!(
        payload.backend_request_state.as_deref(),
        Some("backend-opaque"),
        "the backend's state must be recoverable from the envelope, or the retry \
         cannot carry it back"
    );
    payload
        .redeemable_by(
            &crate::protocol::mrtr::principal_fingerprint(Some(&NAMED_CALLER))
                .expect("a named caller has a fingerprint"),
            // The target binds the backend object that asked (MIK-8168): the
            // name, length-prefixed, and that object's instance.
            &crate::protocol::mrtr::original_request_digest(
                &format!(
                    "7:booking:{}",
                    meta.backends.get("booking").expect("registered").instance()
                ),
                "book_flight",
                &json!({}),
            ),
        )
        .expect("the envelope must be bound to this caller and this request");
}

// MRTR.8, plan row 309. Abandonment costs nothing *because minting stores
// nothing*, so this asserts on the collection a mint could wrongly touch,
// taken after a mint that demonstrably happened. Opening the envelope is what
// makes the emptiness mean something: an empty ledger is also what a build
// that minted nothing at all looks like.
//
// The ledger and not `in_flight`: a mint and an opened exchange are distinct
// events, and this one call is both. `ConsumedLedger` records *spent* tokens,
// so an unretried mint must leave it empty; the in-flight slot the same call
// occupies is `ac_mrtr_8_an_exchange_the_gateway_opened_occupies_a_slot`'s
// property, in the opposite direction. Asserting "nothing anywhere" here would
// contradict that row the day the hold is wired.
//
// Falsifier probe run 2026-09-03: staging a `ledger().consume(...)` between the
// mint and the assertion turned it red on its own comparison (left 1, right 0),
// and removing the stage turned it green again. That establishes the assertion
// reads the ledger it names. It does NOT reproduce the production defect it
// guards against — recording the jti at mint time would need `mint_continuation`
// (`src/gateway/meta_mcp/invoke.rs:372`) to become async, an edit larger than the
// defect, so the probe stages the effect rather than the cause.
#[tokio::test]
async fn a_continuation_that_is_never_retried_stores_nothing_gateway_side() {
    let meta = MetaMcp::new(backend_asking_for_elicitation());

    let result = meta
        .invoke_tool(
            &book_flight(),
            Some("session-1"),
            &allow_all_ctx_declaring(declaring(&json!({"elicitation": {}}))),
        )
        .await
        .expect("a declared capability must not be refused");
    let state = result["requestState"]
        .as_str()
        .expect("an interim result must carry a requestState");
    meta.continuation()
        .keyring()
        .open(state, crate::protocol::continuation::now_unix_secs())
        .expect("the mint must have happened, or the emptiness below proves nothing");

    assert_eq!(
        meta.continuation().ledger().len().await,
        0,
        "a continuation nobody retried must not be recorded as spent; the \
         ledger holds redeemed tokens, and minting one is not redeeming it"
    );
}

// The third thing that must not survive the refusal: the idempotency key.
// After dispatch the gateway settles the key as completed so that a
// post-dispatch gate cannot readmit a retry that would repeat the side effect.
// An interim result is the backend stating it has *not* acted, so there is no
// side effect to protect here — and settling one is not merely redundant, it is
// permanent and false: the stored placeholder reads "side effect executed", so
// a client that declared the capability it was missing and retried under the
// same key would be served that sentence in place of its question, forever.
#[tokio::test]
async fn a_refused_input_request_leaves_the_idempotency_key_retryable() {
    let mut meta = MetaMcp::new(backend_asking_for_elicitation());
    meta.enable_idempotency(
        Arc::new(crate::idempotency::IdempotencyCache::new()),
        Duration::from_secs(300),
    );
    let retry = crate::protocol::mrtr::RetryFields {
        idempotency_key: Some("client-chosen-key".to_string()),
        ..Default::default()
    };
    let mut ctx = allow_all_ctx_declaring(crate::protocol::meta::Declared::NONE);
    ctx.retry = &retry;

    // The second attempt is the assertion. It stands for the client that read
    // the refusal, declared the capability and came back with the same key: it
    // must be judged on its merits rather than answered from what the first
    // attempt left behind.
    for attempt in ["first", "second"] {
        let err = meta
            .invoke_tool(&book_flight(), Some("session-1"), &ctx)
            .await
            .expect_err("a refusal must not be replaced by a stored result");
        assert_eq!(
            err.to_rpc_code(),
            -32021,
            "the {attempt} attempt must be refused as an undeclared capability"
        );
    }
}

// MRTR.9 end-to-end: the refusal happens on the live invoke path, not only in
// the protocol type. A client that declared no input capability is never handed
// an `inputRequests` entry it has no handler for.
#[tokio::test]
async fn an_undeclared_input_request_is_refused_at_the_gateway() {
    let meta = MetaMcp::new(backend_asking_for_elicitation());
    let err = meta
        .invoke_tool(
            &book_flight(),
            Some("session-1"),
            &allow_all_ctx_declaring(crate::protocol::meta::Declared::NONE),
        )
        .await
        .expect_err("a client that declared nothing must not be asked");

    assert_eq!(
        err.to_rpc_code(),
        -32021,
        "the refusal must reuse the gateway's undeclared-capability code"
    );
    let message = err.to_string();
    assert!(
        message.contains("elicitation"),
        "the refusal must name the capability the client would have had to \
         declare, so it can act on it: {message}"
    );
}

// The refusal's payload has to survive the response boundary, which is a
// different question from whether the refusal builds one. `invoke_tool` hands
// its error to `error_response_preserving_status`, and that function is the
// sole author of `data` on the way out — so a payload built correctly upstream
// is still lost unless the boundary forwards it. The two assertions below are
// the two halves that must both hold and neither implies the other: the
// client's recovery payload arrives, and the status key the gateway reserves
// for itself does not ride along with it.
#[tokio::test]
async fn a_refusals_required_capabilities_survive_the_response_boundary() {
    let meta = MetaMcp::new(backend_asking_for_elicitation());
    let err = meta
        .invoke_tool(
            &book_flight(),
            Some("session-1"),
            &allow_all_ctx_declaring(crate::protocol::meta::Declared::NONE),
        )
        .await
        .expect_err("a client that declared nothing must not be asked");

    let response = error_response_preserving_status(RequestId::Number(1), &err);
    let data = response
        .error
        .expect("a refusal must serialise as an error")
        .data
        .expect("the refusal names a capability, so its payload must reach the client");

    assert_eq!(
        data.get("requiredCapabilities"),
        Some(&serde_json::json!(["elicitation"])),
        "the client is told which capability to declare, not merely that it \
         failed to declare one: {data}"
    );
    assert!(
        data.get(crate::gateway::authz::HTTP_STATUS_DATA_KEY)
            .is_none(),
        "the boundary forwards the recovery key alone; the status key stays \
         the gateway's to set: {data}"
    );
}

// MRTR.2's refusal, which is the half a passing mint cannot demonstrate. A
// caller the gateway cannot name would have to be bound to a fingerprint every
// other unnameable caller also holds — which is not a binding — so the
// exchange is refused instead. Without this case the refusal ships unexercised
// and the choice between refusing and approximating is untested.
#[tokio::test]
async fn an_unnameable_caller_is_not_offered_an_interim_exchange() {
    let meta = MetaMcp::new(backend_asking_for_elicitation());

    let err = meta
        .invoke_tool(
            &book_flight(),
            Some("session-1"),
            &anonymous_ctx_declaring(declaring(&json!({"elicitation": {}}))),
        )
        .await
        .expect_err("a caller that cannot be bound must not be handed a continuation");
    assert_eq!(
        err.to_rpc_code(),
        -32003,
        "the refusal must reuse the gateway's existing refusal code"
    );
}

// ── destructive_confirmation_gate ─────────────────────────────────────

#[tokio::test]
async fn an_unconfirmable_destructive_call_is_refused_and_marked() {
    // GIVEN: a destructive call on a transport with nobody to ask
    let ctx = allow_all_ctx();
    // WHEN: the gate judges it
    let refusal = super::destructive_confirmation_gate(
        &RequestId::Number(1),
        "gateway_kill_server",
        &json!({"server": "brave"}),
        None,
        &ctx,
    )
    .await;
    let super::GateOutcome::Refuse(refusal) = refusal else {
        panic!("a destructive call nobody can confirm is refused");
    };

    let error = refusal.error.expect("a refusal carries an error");
    assert_eq!(error.code, -32001);
    assert!(
        error.message.contains("kill server 'brave'"),
        "the refusal must say what was refused: {}",
        error.message
    );
    // AND: marked, so the accounting tail does not book a working gate as a
    // client failure.
    assert!(
        refusal.confirmation_refusal,
        "a refusal is the gate working, not the caller failing"
    );
}

#[tokio::test]
async fn a_non_destructive_call_is_not_judged_by_this_gate() {
    // GIVEN: the same unaskable transport, and a tool the gate does not govern
    let ctx = allow_all_ctx();

    assert!(matches!(
        super::destructive_confirmation_gate(
            &RequestId::Number(1),
            "gateway_list_servers",
            &json!({}),
            None,
            &ctx,
        )
        .await,
        super::GateOutcome::Proceed
    ));
}

/// S6a (MIK-8311 CSL.1): an in-band confirmation whose envelope mint fails
/// gives its slot back. The keyring refuses every envelope, so the gate takes
/// a slot, cannot seal the question, and refuses; the slot must not stay held
/// for the envelope's lifetime. Red on base: the slot count grows by one.
/// Mutant m7: the release on the mint-failure path removed.
#[tokio::test]
async fn s6a_a_refused_confirmation_mint_gives_its_slot_back() {
    let continuation = std::sync::Arc::new(
        crate::protocol::continuation::ContinuationState::mint_refusing_for_test(),
    );
    let mut ctx = super::allow_all_ctx_named(Some("k-confirm"), None);
    ctx.confirmation = crate::gateway::destructive_confirmation::ConfirmationChannel::InBand {
        continuation: &continuation,
    };
    let now = crate::protocol::continuation::now_unix_secs();
    let before = continuation.in_flight().len(now).await;

    let outcome = super::destructive_confirmation_gate(
        &RequestId::Number(1),
        "gateway_kill_server",
        &json!({"server": "brave"}),
        None,
        &ctx,
    )
    .await;
    assert!(
        matches!(outcome, super::GateOutcome::Refuse(_)),
        "setup: a refused mint must refuse the call"
    );

    let after = continuation.in_flight().len(now).await;
    assert_eq!(
        after, before,
        "the refused confirmation kept its slot: {before} held before, {after} after"
    );
}

#[test]
fn every_confirmation_refusal_is_marked_by_construction() {
    let refusal = super::confirmation_refusal_response(
        &RequestId::Number(7),
        "Operator declined: kill server 'brave'".to_string(),
    );
    // THEN: code, message and marker all come from the one constructor both
    // refusal branches return through, so neither can lose the marker alone.
    let error = refusal.error.expect("a refusal carries an error");
    assert_eq!(error.code, -32001);
    assert_eq!(error.message, "Operator declined: kill server 'brave'");
    assert!(refusal.confirmation_refusal);
}

// ── hidden-tool disclosure via the sibling routes ────────────────────────

/// A near miss of a hidden tool's name must not be answered with that name.
///
/// The exact-name route was closed by wording the hidden refusal like the
/// unrecognised one. This is the route beside it: a caller who mistypes a
/// hidden tool by one character falls through to the suggester, and a
/// suggester drawing from every meta-tool that exists would answer with the
/// name the allow-list is hiding. Both reviewers found this independently.
#[tokio::test]
async fn a_near_miss_of_a_hidden_tool_is_not_answered_with_its_name() {
    // GIVEN: a gateway exposing one tool, hiding the destructive ones
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()))
        .with_exposed_meta_tools(&["gateway_search".to_string()]);
    // WHEN: a caller mistypes a HIDDEN tool by one character
    let response = Box::pin(meta.handle_tools_call(
        RequestId::Number(1),
        "gateway_kill_serve",
        json!({}),
        None,
        allow_all_ctx(),
    ))
    .await;
    // THEN: the refusal names neither the hidden tool nor any other hidden one
    let message = response
        .error
        .expect("an unrecognised tool is refused")
        .message;
    assert!(
        !message.contains("gateway_kill_server"),
        "a suggestion must not name a tool the allow-list hides: {message}"
    );
    assert!(
        !message.contains("gateway_revive_server"),
        "nor any other hidden neighbour: {message}"
    );
}

/// The suggester still helps when the near miss is of an EXPOSED tool.
///
/// Without this, filtering the pool to nothing would pass the test above while
/// silently removing the feature -- the failure mode of every fix that works by
/// deleting a capability.
#[tokio::test]
async fn a_near_miss_of_an_exposed_tool_still_gets_its_suggestion() {
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()))
        .with_exposed_meta_tools(&["gateway_search".to_string()]);
    let response = Box::pin(meta.handle_tools_call(
        RequestId::Number(1),
        "gateway_searh",
        json!({}),
        None,
        allow_all_ctx(),
    ))
    .await;
    let message = response
        .error
        .expect("an unrecognised tool is refused")
        .message;
    assert!(
        message.contains("gateway_search"),
        "an exposed neighbour is still suggested: {message}"
    );
}

/// The router asks this before its own admin pre-check.
#[test]
fn exposure_answers_for_a_hidden_admin_tool_before_admin_does() {
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()))
        .with_exposed_meta_tools(&["gateway_search".to_string()]);
    // THEN: the hidden admin tool is not confirmed, and the exposed one is
    assert!(!meta.exposes_meta_tool("gateway_kill_server"));
    assert!(meta.exposes_meta_tool("gateway_search"));
}

// ===========================================================================
// MIK-7212.MRTR.9a — the refusal a client actually receives.
//
// A mode refusal and a capability refusal reach the client through the same
// boundary and must not read the same. The client here DID declare
// elicitation, so repeating that capability back to it would be a recovery
// instruction it has already followed — which is why the payload carries the
// mode instead, and why the message may not claim the capability was missing.
// ===========================================================================

fn backend_asking_in_url_mode() -> Arc<BackendRegistry> {
    backend_asking_with_elicitation_params(&json!({
        "mode": "url",
        "url": "https://backend.invalid/ui/set_api_key",
        "message": "Please provide your API key to continue."
    }))
}

/// A backend whose one interim request carries `params` verbatim, so a test can
/// choose what the client is asked in.
fn backend_asking_with_elicitation_params(params: &serde_json::Value) -> Arc<BackendRegistry> {
    use crate::backend::Backend;
    use crate::config::{BackendConfig, FailsafeConfig};
    use crate::transport::Transport;

    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        "booking",
        BackendConfig::r2_off(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    let transport: Arc<dyn Transport> = Arc::new(ToolCallTestTransport {
        result: json!({
            "resultType": "input_required",
            "inputRequests": {
                "api_key": {
                    "method": "elicitation/create",
                    "params": params
                }
            },
            "requestState": "backend-opaque"
        }),
    });
    backend.set_transport_for_test(transport);
    let _ = registry.register(backend);
    registry
}

/// The caller's own mode string is the one thing a refusal must not repeat: it
/// reaches the client verbatim, and the gateway names only modes it can render
/// from its own vocabulary. Today that is a comment beside the write site; this
/// pins it as behaviour.
#[tokio::test]
async fn an_unreadable_mode_is_refused_without_echoing_what_the_backend_sent() {
    // Distinctive but inert: an injection-shaped string would also trip the
    // content classifier, and this test would then pass for a reason that has
    // nothing to do with the mode gate.
    const BACKEND_MODE: &str = "mode-only-the-backend-knows";

    let meta = MetaMcp::new(backend_asking_with_elicitation_params(&json!({
        "mode": BACKEND_MODE,
        "message": "Please provide your API key to continue."
    })));
    let err = meta
        .invoke_tool(
            &book_flight(),
            Some("session-1"),
            &allow_all_ctx_declaring(form_only_client()),
        )
        .await
        .expect_err(
            "a mode the gateway cannot read is a mode no client can have declared, so the \
             request must not be relayed",
        );

    assert_eq!(
        err.to_rpc_code(),
        -32021,
        "an unreadable mode is refused in the same class as any other undeclared request"
    );

    let message = err.to_string();
    assert!(
        !message.contains(BACKEND_MODE),
        "the refused mode is the backend's string; repeating it puts backend-authored \
         text in front of the client: {message}"
    );
    assert!(
        !message.contains("'elicitation' capability"),
        "this client declared elicitation; the refusal is about the mode: {message}"
    );
    assert!(
        message.contains("does not recognise"),
        "without this the test would pass on any refusal at all, including the \
         capability refusal it is here to rule out: {message}"
    );

    let response = error_response_preserving_status(RequestId::Number(1), &err);
    let data = response
        .error
        .expect("a refusal must serialise as an error")
        .data;
    assert!(
        data.is_none(),
        "there is nothing a client could add to its declaration to make an unreadable \
         mode acceptable, so a payload here would only invite a retry: {data:?}"
    );
}

/// A client that declared elicitation, in form mode and only form mode.
fn form_only_client() -> crate::protocol::meta::Declared {
    declaring(&json!({ "elicitation": { "form": {} } }))
}

#[tokio::test]
async fn a_mode_refusal_carries_the_mode_and_not_a_capability_the_client_already_declared() {
    let meta = MetaMcp::new(backend_asking_in_url_mode());
    let err = meta
        .invoke_tool(
            &book_flight(),
            Some("session-1"),
            &allow_all_ctx_declaring(form_only_client()),
        )
        .await
        .expect_err("a url-mode request to a form-only client must not be relayed");

    assert_eq!(
        err.to_rpc_code(),
        -32021,
        "a mode refusal reuses the undeclared code; it is the same class of refusal"
    );

    let response = error_response_preserving_status(RequestId::Number(1), &err);
    let data = response
        .error
        .expect("a refusal must serialise as an error")
        .data
        .expect("the refusal names the mode, so its payload must reach the client");

    assert_eq!(
        data.get(super::invoke::UNSUPPORTED_ELICITATION_MODE_DATA_KEY),
        Some(&json!("url")),
        "the client is told which MODE it was asked in, which is the only thing it \
         could act on here: {data}"
    );
    assert!(
        data.get(super::invoke::REQUIRED_CAPABILITIES_DATA_KEY)
            .is_none(),
        "this client declared elicitation; naming it again is a false recovery \
         instruction, not a hint: {data}"
    );
}

#[tokio::test]
async fn a_mode_refusal_does_not_claim_the_capability_was_undeclared() {
    let meta = MetaMcp::new(backend_asking_in_url_mode());
    let err = meta
        .invoke_tool(
            &book_flight(),
            Some("session-1"),
            &allow_all_ctx_declaring(form_only_client()),
        )
        .await
        .expect_err("a url-mode request to a form-only client must not be relayed");

    let message = err.to_string();
    assert!(
        !message.contains("'elicitation' capability"),
        "the client declared that capability; saying otherwise is false and sends it \
         to fix something that is not broken: {message}"
    );
    assert!(
        message.contains("url"),
        "the message must name the mode that was refused, or the client cannot tell \
         which of its modes the backend wanted: {message}"
    );
}

/// A `booking` backend answering every call with `result`.
fn backend_answering(result: serde_json::Value) -> Arc<BackendRegistry> {
    use crate::backend::Backend;
    use crate::config::{BackendConfig, FailsafeConfig};
    use crate::transport::Transport;

    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        "booking",
        BackendConfig::r2_off(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    let transport: Arc<dyn Transport> = Arc::new(ToolCallTestTransport { result });
    backend.set_transport_for_test(transport);
    let _ = registry.register(backend);
    registry
}

/// `MIK-8117.MALFORMED.1`: a result that claims `input_required` but which
/// `InputRequired::from_result` declines (a non-string `requestState` beside a
/// valid `inputRequests` object) is still refused by MRTR.9 when it asks a
/// question the client never declared, with the refusal its well-formed twin
/// gets: same code, message and data. Mutant: the gate reading only the parsed
/// interim.
#[tokio::test]
async fn a_malformed_round_asking_an_undeclared_question_is_refused_alike() {
    let answer = |state: serde_json::Value| {
        json!({
            "resultType": "input_required",
            "inputRequests": {
                "confirm": {
                    "method": "elicitation/create",
                    "params": { "message": "Charge the card?" }
                }
            },
            "requestState": state
        })
    };
    let refusal = |state| async move {
        let meta = MetaMcp::new(backend_answering(answer(state)));
        let ctx = allow_all_ctx_declaring(crate::protocol::meta::Declared::NONE);
        let err = meta
            .invoke_tool(&book_flight(), Some("session-1"), &ctx)
            .await
            .expect_err("a client that declared nothing must not be asked");
        let wire = crate::gateway::meta_mcp::error_response_preserving_status(
            crate::protocol::RequestId::Number(1),
            &err,
        );
        serde_json::to_value(wire.error).expect("an error serializes")
    };
    let well_formed = refusal(json!("backend-opaque")).await;
    for state in [json!(7), json!({"k": 1}), json!(null)] {
        assert_eq!(
            refusal(state.clone()).await,
            well_formed,
            "a malformed round ({state}) must be refused as its well-formed twin is"
        );
    }
}

/// `MIK-8117.MALFORMED.1` control: the malformed-round fallback reads only a
/// result that claims `input_required`. A completed result carrying an
/// `inputRequests` object and a malformed `requestState` (no `resultType`, or
/// another one) is relayed, never refused. Mutant: the fallback ignoring
/// `resultType`.
#[tokio::test]
async fn a_completed_result_carrying_input_requests_is_not_refused() {
    for result_type in [None, Some("complete")] {
        let mut result = json!({
            "content": [{ "type": "text", "text": "booked" }],
            "inputRequests": {
                "confirm": {
                    "method": "elicitation/create",
                    "params": { "message": "Charge the card?" }
                }
            },
            "requestState": 7
        });
        if let Some(kind) = result_type {
            result["resultType"] = json!(kind);
        }
        let meta = MetaMcp::new(backend_answering(result));
        let ctx = allow_all_ctx_declaring(crate::protocol::meta::Declared::NONE);
        let outcome = meta
            .invoke_tool(&book_flight(), Some("session-1"), &ctx)
            .await;
        let relayed = outcome.unwrap_or_else(|error| {
            panic!("a completed result ({result_type:?}) must be relayed: {error}")
        });
        assert!(
            relayed.to_string().contains("booked"),
            "the relayed result keeps its payload: {relayed}"
        );
    }
}
