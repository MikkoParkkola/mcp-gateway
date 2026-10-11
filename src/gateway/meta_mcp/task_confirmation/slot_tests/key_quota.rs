// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A key-only caller's confirmations (MIK-8137 binds them) are charged to the
//! same cap as that key's calls on every other route (MIK-8293), and two keys
//! never share one.

use super::*;

/// What the HTTP edge hands over for a caller authenticated by a key alone.
fn keyed<'a>(
    (principal, name): (&'a str, &'a str),
    retry: &'a RetryFields,
) -> crate::gateway::meta_mcp::MetaMcpCallerContext<'a> {
    crate::gateway::meta_mcp::MetaMcpCallerContext {
        credential_principal: Some(principal),
        // As the HTTP edge fills it; the quota still keys on the credential.
        api_key_name: Some(name),
        authentication: crate::gateway::meta_mcp::Authentication::Authenticated,
        retry,
        // As S3d: a modern request that can be asked, so a refused round is
        // the cap's doing, not a missing capability.
        input_capabilities: crate::protocol::meta::classify_request(
            Some(&json!({"_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}}
            }})),
            Some("2026-07-28"),
        )
        .declared_capabilities(),
        ..crate::gateway::meta_mcp::anonymous_caller()
    }
}

/// One task confirmation for `caller`, its binding and quota derived as the
/// edge derives them. A distinct idempotency key per call, so each is a new
/// operation.
async fn confirm(
    fx: &Fixture,
    caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
    n: usize,
) -> TaskConfirmation {
    let (arguments, task) = (json!({ "id": 1 }), json!({ "ttl": 60_000 }));
    let retry = RetryFields {
        idempotency_key: Some(format!("{KEY}-{n}")),
        ..fresh()
    };
    let owner = caller.owner_principal().unwrap_or_default();
    fx.meta
        .confirm_destructive_task(&TaskConfirmationRequest {
            id: RequestId::Number(7),
            tool_name: TOOL,
            arguments: &arguments,
            task: Some(&task),
            retry: &retry,
            verified_identity: None,
            principal: crate::protocol::mrtr::source_fingerprint(caller.principal_source(None)),
            quota: caller.quota_key(),
            owner,
            scope: super::open_scope(),
            session_id: None,
            input_capabilities: elicitation(),
            is_modern: true,
            admission: &fx.admission,
        })
        .await
}

/// Whether an invoke round was asked (a slot taken).
fn asked<E>(round: &Result<Value, E>) -> bool {
    round
        .as_ref()
        .is_ok_and(|v| v.get("resultType") == Some(&json!("input_required")))
}

/// Whether `outcome` is a challenge (a slot taken), not a refusal.
fn challenged(outcome: &TaskConfirmation) -> bool {
    matches!(outcome, TaskConfirmation::Answer(r) if r.error.is_none())
}

/// MIK-8137 x MIK-8293: key A's confirmations are challenged up to the cap and
/// never refused as unbindable; the next is refused; key A's `gateway_invoke`
/// round is then refused too (one cap across routes), while key B is still
/// challenged on both routes (no shared cap). Mutants: quota built from the
/// verified identity only (A refused unbindable at once); quota keyed on the
/// sealed principal (the invoke round is still asked); one key for all keys
/// (B refused).
#[tokio::test]
async fn a_key_only_caller_confirms_on_its_keys_one_cap() {
    let fx = fixture(BackendConfig::default(), Some(Hint::Destructive)).await;
    fx.wire.asks.store(true, Ordering::SeqCst);
    let no_retry = RetryFields::default();
    let (a, b) = (
        keyed(("key-digest-a", "key-a"), &no_retry),
        keyed(("key-digest-b", "key-b"), &no_retry),
    );
    let cap = crate::protocol::continuation::PRINCIPAL_SLOTS;
    let now = crate::protocol::continuation::now_unix_secs();

    for n in 0..cap {
        let outcome = confirm(&fx, &a, n).await;
        assert!(
            challenged(&outcome),
            "key A's confirmation {n} was refused under its cap: {outcome:?}"
        );
    }
    assert_eq!(
        fx.meta.continuation.in_flight().len(now).await,
        cap,
        "setup: A holds its cap"
    );
    let over = confirm(&fx, &a, cap).await;
    assert!(
        !challenged(&over),
        "key A was challenged past its cap: {over:?}"
    );
    assert_eq!(
        fx.meta.continuation.in_flight().len(now).await,
        cap,
        "A took a slot past its cap"
    );

    let args = json!({"server": SERVER, "tool": TOOL, "arguments": {"id": 1}});
    let a_invoke = fx.meta.invoke_tool_for_test(&args, None, &a).await;
    assert!(
        !asked(&a_invoke),
        "key A's invoke round was asked: its confirmations hold a cap of their own"
    );

    // The in-band meta confirmation gate draws on the same cap: with A's
    // full, it takes no slot for A (its outcome cannot say so; the count can).
    let in_band = |key: (&'static str, &'static str)| {
        let mut caller = keyed(key, &no_retry);
        caller.confirmation =
            crate::gateway::destructive_confirmation::ConfirmationChannel::InBand {
                continuation: &fx.meta.continuation,
            };
        caller
    };
    let before = fx.meta.continuation.in_flight().len(now).await;
    let _gate = crate::gateway::meta_mcp::destructive_confirmation_gate(
        &RequestId::Number(9),
        "gateway_kill_server",
        &json!({"server": "brave"}),
        None,
        &in_band(("key-digest-a", "key-a")),
    )
    .await;
    assert_eq!(
        fx.meta.continuation.in_flight().len(now).await,
        before,
        "key A's in-band confirmation took a slot past its cap"
    );

    let b_confirm = confirm(&fx, &b, cap + 1).await;
    assert!(
        challenged(&b_confirm),
        "key B shares key A's cap: {b_confirm:?}"
    );
    let b_invoke = fx.meta.invoke_tool_for_test(&args, None, &b).await;
    assert!(
        asked(&b_invoke),
        "key B's invoke round was refused: {b_invoke:?}"
    );
}
