// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7272.OWNER.3: stdio results are keyed by the transport, not by a name.
//!
//! Test plan: `docs/design/2026-09-30-sub4-stdio-owner-test-plan.md` (I1).
//!
//! The stdio transport marks the contexts it builds with its process nonce.
//! A context carrying the same principal text but no nonce was not built by
//! the transport, so it must not share the operator's retained results in
//! either store: the admission ledger or the idempotency cache.

use serde_json::{Value, json};

use super::signing_nonce_allocations_support::{BACKEND, Fixture, SESSION, TOOL, invoke};
use crate::gateway::authz::ToolPolicyAuthorizer;
use crate::gateway::meta_mcp::MetaMcpCallerContext;
use crate::gateway::meta_mcp::admission::SyncAdmission;
use crate::protocol::mrtr::RetryFields;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::audit::CredentialKind;

/// The marker a completed admission carries, read back only by a replay.
const MARKER: &str = "operator-result";

fn keyed_retry(key: &str) -> RetryFields {
    RetryFields {
        idempotency_key: Some(key.to_string()),
        ..RetryFields::default()
    }
}

/// The context the stdio transport builds, carrying `retry`.
fn transport<'a>(
    authorizer: &'a ToolPolicyAuthorizer<'a>,
    retry: &'a RetryFields,
) -> MetaMcpCallerContext<'a> {
    super::super::stdio_caller_context(authorizer, crate::protocol::meta::Era::Modern)
        .with_retry(retry)
}

/// The same context with the transport's nonce removed: the principal text is
/// still the stdio constant, but the transport did not build it.
fn named<'a>(
    authorizer: &'a ToolPolicyAuthorizer<'a>,
    retry: &'a RetryFields,
) -> MetaMcpCallerContext<'a> {
    MetaMcpCallerContext {
        stdio_nonce: None,
        ..transport(authorizer, retry)
    }
}

/// As [`named`], presenting as an API-key credential.
fn named_as_api_key<'a>(
    authorizer: &'a ToolPolicyAuthorizer<'a>,
    retry: &'a RetryFields,
) -> MetaMcpCallerContext<'a> {
    MetaMcpCallerContext {
        credential_kind: CredentialKind::ApiKey,
        ..named(authorizer, retry)
    }
}

fn invoke_arguments() -> Value {
    json!({"server": BACKEND, "tool": TOOL, "arguments": {"note": "owner-3"}})
}

fn admit(
    fixture: &Fixture,
    caller: &MetaMcpCallerContext<'_>,
    id: i64,
) -> crate::Result<SyncAdmission> {
    fixture.meta.admit_meta_sync(
        crate::gateway::meta_mcp::AdmissionOwner::for_test(caller.owner_principal()),
        caller,
        "gateway_invoke",
        &invoke_arguments(),
        Some(SESSION),
        &RequestId::Number(id),
    )
}

/// Admit under `caller` and complete the lease with `marker`, as a dispatched
/// call would.
fn complete_with(fixture: &Fixture, caller: &MetaMcpCallerContext<'_>, marker: &str) {
    let Ok(SyncAdmission::Owned(lease)) = admit(fixture, caller, 1) else {
        panic!("the first keyed admission under a fresh key must be owned");
    };
    lease.mark_dispatched();
    lease.complete_secured(&JsonRpcResponse::success(
        RequestId::Number(1),
        json!({"marker": marker}),
    ));
}

/// What a later admission under the same key received.
fn outcome(result: crate::Result<SyncAdmission>) -> String {
    match result {
        Ok(SyncAdmission::Owned(_)) => "owned".to_string(),
        Ok(SyncAdmission::Unprotected) => "unprotected".to_string(),
        Ok(SyncAdmission::Replay(response, _)) => format!("replay of {:?}", response.result),
        Err(error) => format!("refused: {error}"),
    }
}

// ── Admission ledger ─────────────────────────────────────────────────────────

/// T3.1. The transport's completed result is not handed to a context that
/// only shares its principal text, whatever credential kind it presents.
#[tokio::test]
async fn stdio_results_are_keyed_by_transport_not_by_name() {
    let fixture = Fixture::start_mutating().await;
    let authorizer = ToolPolicyAuthorizer {
        tool_policy: &fixture.tool_policy,
    };
    let retry = keyed_retry("owner-3-ledger");
    complete_with(&fixture, &transport(&authorizer, &retry), MARKER);

    for (label, caller) in [
        (
            "the stdio text without the transport",
            named(&authorizer, &retry),
        ),
        (
            "the stdio text as an API key",
            named_as_api_key(&authorizer, &retry),
        ),
    ] {
        let seen = outcome(admit(&fixture, &caller, 2));
        assert_eq!(
            seen, "owned",
            "{label} must get its own admission, not the transport's result"
        );
    }

    // "The real stdio owner works": the transport still replays its own.
    let own = outcome(admit(&fixture, &transport(&authorizer, &retry), 3));
    assert!(
        own.starts_with("replay") && own.contains(MARKER),
        "the transport must replay its own completed result: {own}"
    );
}

/// T3.2. The reverse order: a result completed under the principal text alone
/// is not handed to the transport.
#[tokio::test]
async fn a_named_context_does_not_seed_the_stdio_operators_results() {
    let fixture = Fixture::start_mutating().await;
    let authorizer = ToolPolicyAuthorizer {
        tool_policy: &fixture.tool_policy,
    };
    let retry = keyed_retry("owner-3-reverse");
    complete_with(&fixture, &named(&authorizer, &retry), "named-result");

    let seen = outcome(admit(&fixture, &transport(&authorizer, &retry), 2));
    assert_eq!(
        seen, "owned",
        "the transport must get its own admission, not the named context's result"
    );
}

/// `invoke` carrying `key` in `_meta`, where the stdio dispatcher reads it.
fn keyed_request(id: &str, key: &str) -> Value {
    let mut request = invoke(id, None, json!({"note": "owner-3"}));
    request["params"]["_meta"][crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    request
}

/// The production stdio entry point, called as `run_stdio` calls it.
async fn dispatch(fixture: &Fixture, request: Value) -> Value {
    super::super::Gateway::dispatch_single_with_sink(
        &fixture.meta,
        &fixture.tool_policy,
        &fixture.mtls_policy,
        request,
        super::super::StdioClient {
            session_id: SESSION,
            channel: &crate::gateway::input_bridge::NoClientChannel,
            handshake_capabilities: crate::protocol::meta::Declared::NONE,
            tasks: None,
            modern: false,
        },
        &super::super::StdioTelemetry::default(),
    )
    .await
    .expect("a request carrying an id must produce a response")
}

// ── Idempotency cache ────────────────────────────────────────────────────────

/// T3.4. A keyed stdio call leaves its result in the idempotency cache. The
/// same key and arguments under the principal text alone, through the entry
/// the HTTP route calls after its own admission, must reach the backend
/// rather than that entry.
#[tokio::test]
async fn stdio_idempotency_entries_are_keyed_by_transport() {
    let fixture = Fixture::start_mutating().await;
    let first = dispatch(&fixture, keyed_request("c1", "owner-3-cache")).await;
    assert!(
        first.get("error").is_none(),
        "the stdio call must succeed: {first}"
    );
    assert_eq!(fixture.backend.tools_call_count(), 1);

    let authorizer = ToolPolicyAuthorizer {
        tool_policy: &fixture.tool_policy,
    };
    let retry = keyed_retry("owner-3-cache");
    let _ = fixture
        .meta
        .handle_tools_call(
            RequestId::Number(2),
            "gateway_invoke",
            invoke_arguments(),
            Some(SESSION),
            named(&authorizer, &retry),
        )
        .await;

    assert_eq!(
        fixture.backend.tools_call_count(),
        2,
        "the named context must reach the backend, not the transport's cached entry"
    );
}

/// T3.5. A batched stdio call is the transport too: its result lands under
/// the transport's key, not the principal text's.
#[tokio::test]
async fn batched_stdio_calls_are_keyed_by_transport() {
    let fixture = Fixture::start_mutating().await;
    let responses = super::super::Gateway::dispatch_batch_with_sink(
        &fixture.meta,
        &fixture.tool_policy,
        &fixture.mtls_policy,
        json!([keyed_request("b1", "owner-3-batch")]),
        SESSION,
        &super::super::StdioTelemetry::default(),
    )
    .await;
    assert!(
        responses
            .iter()
            .all(|response| response.get("error").is_none()),
        "the batched call must succeed: {responses:?}"
    );
    assert_eq!(fixture.backend.tools_call_count(), 1);

    let authorizer = ToolPolicyAuthorizer {
        tool_policy: &fixture.tool_policy,
    };
    let retry = keyed_retry("owner-3-batch");
    let seen = outcome(admit(&fixture, &named(&authorizer, &retry), 2));
    assert_eq!(
        seen, "owned",
        "the named context must not replay the batched call's result"
    );
}

/// T3.7. A chain step rebuilds its context through `with_retry`; the
/// transport's mark must survive it.
#[tokio::test]
async fn a_chain_step_keeps_the_stdio_tag() {
    let fixture = Fixture::start_mutating().await;
    let authorizer = ToolPolicyAuthorizer {
        tool_policy: &fixture.tool_policy,
    };
    let retry = keyed_retry("owner-3-chain");
    let step = transport(&authorizer, &retry).with_retry(&retry);
    assert!(
        step.stdio_nonce.is_some(),
        "a chain step lost the transport's mark"
    );
}

// ── Reserved spelling ────────────────────────────────────────────────────────

/// A context that did not come from the transport but spells the reserved
/// operator principal. Its text is dropped, never keyed.
fn reserved_spelling<'a>(
    authorizer: &'a ToolPolicyAuthorizer<'a>,
    retry: &'a RetryFields,
) -> MetaMcpCallerContext<'a> {
    MetaMcpCallerContext {
        credential_principal: Some("\0local-operator.v1"),
        ..named(authorizer, retry)
    }
}

/// T3.8. Text in the reserved space gets no owner key at all rather than an
/// empty or shared one: a keyed call is refused before admission (-32003),
/// so no two such callers can share a replay bucket, and the operator's
/// result is not reachable through it.
#[tokio::test]
async fn reserved_owner_text_is_refused_not_pooled() {
    let fixture = Fixture::start_mutating().await;
    let authorizer = ToolPolicyAuthorizer {
        tool_policy: &fixture.tool_policy,
    };
    let retry = keyed_retry("owner-3-reserved");
    complete_with(&fixture, &transport(&authorizer, &retry), MARKER);

    for id in [2, 3] {
        let seen = outcome(admit(&fixture, &reserved_spelling(&authorizer, &retry), id));
        assert!(
            seen.starts_with("refused") && seen.contains("verified execution principal"),
            "reserved owner text must be refused, not keyed: {seen}"
        );
    }
}

/// T3.9. The same text through the invoke entry keeps no idempotency entry:
/// each keyed call reaches the backend.
#[tokio::test]
async fn reserved_owner_text_keeps_no_idempotency_entry() {
    let fixture = Fixture::start_mutating().await;
    let authorizer = ToolPolicyAuthorizer {
        tool_policy: &fixture.tool_policy,
    };
    let retry = keyed_retry("owner-3-reserved-cache");
    for id in [1, 2] {
        let _ = fixture
            .meta
            .handle_tools_call(
                RequestId::Number(id),
                "gateway_invoke",
                invoke_arguments(),
                Some(SESSION),
                reserved_spelling(&authorizer, &retry),
            )
            .await;
    }
    assert_eq!(
        fixture.backend.tools_call_count(),
        2,
        "reserved owner text must not be served from a shared entry"
    );
}
