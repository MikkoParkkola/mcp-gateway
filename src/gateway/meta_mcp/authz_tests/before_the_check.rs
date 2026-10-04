// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! AUTHZ.7, 12 and 20: nothing happens before the check.

use super::*;

// ===========================================================================
// AUTHZ.7 / 12 / 20 — nothing happens before the check.
//
// These were previously justified by reading: the check sits at the top of
// `invoke_tool_traced`, above the nonce store, the cache and the budget. That
// proves PLACEMENT, not behaviour. A client `gateway_invoke` is the shape that
// can prove behaviour, because it carries no `_full` — that directive is
// injected only by `internal_invoke_args`, and it skips the cache and
// idempotency entirely, so a playbook step could never exercise them.
// ===========================================================================

/// AUTHZ.12 — a refused caller is not served a cached result.
///
/// The scenario the design calls authoritative: the router allowed a call,
/// policy changed, and the chokepoint must refuse before the cache is read.
#[tokio::test]
async fn authz_12_refused_caller_is_not_served_a_cached_result() {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::with_features(
        registry,
        Some(Arc::new(crate::cache::ResponseCache::new())),
        None,
        None,
        Duration::from_secs(300),
    );

    // Prime the cache as a permitted caller.
    let primed = meta
        .invoke_tool(&invoke_args("alpha", "read"), None, &ctx(&AllowAll))
        .await;
    assert!(primed.is_ok(), "priming call must succeed: {primed:?}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the backend was called once"
    );

    // AUTHZ.12a — the cache is real and reachable, so the refusal below is not
    // just an empty cache.
    let hit = meta
        .invoke_tool(&invoke_args("alpha", "read"), None, &ctx(&AllowAll))
        .await;
    assert!(hit.is_ok(), "a second permitted call must succeed");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "and must be served from cache — if it reaches the backend again the \
         cache is not primed and AUTHZ.12 proves nothing"
    );

    // Now refuse the same target.
    let refused = meta
        .invoke_tool(&invoke_args("alpha", "read"), None, &ctx(&DenyAll))
        .await;
    let refusal = refused.expect_err("a refused caller must not be served the cached payload");
    assert!(
        matches!(refusal, crate::Error::Forbidden { .. }),
        "and must be refused AS a denial, not fail for some other reason: {refusal:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "and must not dispatch either"
    );
}

/// AUTHZ.20 — a refused call consumes no nonce.
///
/// Replay admission is `prepare_signing_invocation` (`signing.rs:169`), which
/// registers the nonce only after policy, and only for a captured external
/// `gateway_invoke`. `invoke_tool` with `caller.signing = None` never reaches
/// the store, so a third call would succeed and this case would pass for the
/// wrong reason. Each step captures from a raw envelope the way the adapters
/// do.
#[tokio::test]
async fn authz_20_refused_call_consumes_no_nonce() {
    const NONCE: &str = "nonce-used-once";

    let (registry, _calls) = counted_backend("alpha");
    let mut meta = MetaMcp::new(registry);
    meta.enable_message_signing(
        crate::security::message_signing::MessageSigner::new(
            b"a-test-secret-of-sufficient-length".to_vec(),
            None,
            "test-key".to_string(),
        ),
        Duration::from_secs(300),
        false,
    );

    let (mut denied_signing, denied_args) = captured_external_gateway_invoke(NONCE);
    let refused =
        meta.prepare_signing_invocation(&mut denied_signing, &denied_args, None, &ctx(&DenyAll));
    assert!(refused.is_err(), "the call must be refused");

    // The same nonce must still be usable: the refusal happened before it was
    // registered. A new capture is a new request carrying that nonce, which
    // is how a retry arrives on the wire.
    let (mut allowed_signing, allowed_args) = captured_external_gateway_invoke(NONCE);
    meta.prepare_signing_invocation(&mut allowed_signing, &allowed_args, None, &ctx(&AllowAll))
        .expect("a refused call must not burn the nonce");
    let mut allowed_caller = ctx(&AllowAll);
    allowed_caller.signing = Some(&allowed_signing);
    let allowed = meta.invoke_tool(&allowed_args, None, &allowed_caller).await;
    assert!(
        allowed.is_ok(),
        "a refused call must not burn the nonce — the honest retry is being \
         rejected as a replay: {allowed:?}"
    );

    // And the nonce IS a real one: replaying it now must fail at admission.
    let (mut replay_signing, replay_args) = captured_external_gateway_invoke(NONCE);
    let replayed =
        meta.prepare_signing_invocation(&mut replay_signing, &replay_args, None, &ctx(&AllowAll));
    let replay_error = replayed.expect_err("a replayed nonce must be rejected");
    assert!(
        replay_error.to_string().to_lowercase().contains("nonce")
            || replay_error.to_string().to_lowercase().contains("replay"),
        "and rejected AS a replay — any other error would mean the nonce store \
         is not live and the assertion above passed for the wrong reason: \
         {replay_error}"
    );
}

/// AUTHZ.13a — a surfaced tool is refused when the authorizer denies.
///
/// The fifth dispatch shape, and the last one without a case. A surfaced tool
/// is dispatched by its bare name rather than through `gateway_invoke`, so it
/// takes a different branch at the top of `handle_tools_call` — covering the
/// other four proves nothing about this one.
#[tokio::test]
async fn authz_13a_surfaced_tool_denied() {
    let (registry, calls) = counted_backend("alpha");
    let meta =
        MetaMcp::new(registry).with_surfaced_tools(vec![crate::config::SurfacedToolConfig {
            server: "alpha".to_string(),
            tool: "surfaced_read".to_string(),
        }]);

    let response = Box::pin(meta.handle_tools_call(
        crate::protocol::RequestId::Number(1),
        "surfaced_read",
        json!({}),
        None,
        ctx(&DenyAll),
    ))
    .await;

    assert!(
        response.error.is_some(),
        "a denied surfaced tool must be refused: {response:?}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0, "no backend call");
}

/// The allow counterpart, without which 13a passes if surfaced dispatch never
/// reaches a backend for some unrelated reason.
#[tokio::test]
async fn authz_13a_surfaced_tool_allowed_reaches_the_backend() {
    let (registry, calls) = counted_backend("alpha");
    let meta =
        MetaMcp::new(registry).with_surfaced_tools(vec![crate::config::SurfacedToolConfig {
            server: "alpha".to_string(),
            tool: "surfaced_read".to_string(),
        }]);

    let response = Box::pin(meta.handle_tools_call(
        crate::protocol::RequestId::Number(1),
        "surfaced_read",
        json!({}),
        None,
        ctx(&AllowAll),
    ))
    .await;

    assert!(
        response.error.is_none(),
        "an allowed surfaced tool must run: {response:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "and must actually reach the backend"
    );
}
