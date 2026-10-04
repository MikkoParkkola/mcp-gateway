// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! AUTHZ.13a-13d: gateway_invoke and code-mode dispatch shapes.

use super::*;

// ===========================================================================
// AUTHZ.13a-13e — every meta-layer dispatch shape is refused when the
// authorizer denies. The chokepoint claim itself, and five independent cases
// on purpose: one case asserting five shapes stops at the first failure and
// reports one defect where there may be four.
// ===========================================================================

#[tokio::test]
async fn authz_13b_gateway_invoke_denied() {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::new(registry);

    let result = meta
        .invoke_tool(&invoke_args("alpha", "read"), None, &ctx(&DenyAll))
        .await;

    assert!(result.is_err(), "a denied gateway_invoke must be refused");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "a refused call must never reach the backend"
    );
}

#[tokio::test]
async fn authz_13b_gateway_invoke_allowed() {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::new(registry);

    let result = meta
        .invoke_tool(&invoke_args("alpha", "read"), None, &ctx(&AllowAll))
        .await;

    assert!(result.is_ok(), "an allowed invoke must succeed: {result:?}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the allow path must actually reach the backend, or the refusal above \
         proves nothing about authorization"
    );
}

#[tokio::test]
async fn authz_13c_code_mode_single_denied() {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::new(registry).with_code_mode(true);

    let result = meta
        .code_mode_execute(
            &json!({ "tool": "alpha:read", "arguments": {} }),
            None,
            &ctx(&DenyAll),
        )
        .await;

    assert!(result.is_err(), "a denied code-mode call must be refused");
    assert_eq!(calls.load(Ordering::SeqCst), 0, "no backend call");
}

#[tokio::test]
async fn authz_13d_code_mode_chain_step_denied() {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::new(registry).with_code_mode(true);

    let result = meta
        .code_mode_execute(
            &json!({ "chain": [ { "tool": "alpha:read", "arguments": {} } ] }),
            None,
            &ctx(&DenyAll),
        )
        .await;

    let err = result.expect_err("a denied chain step must be refused");
    assert!(
        matches!(err, crate::Error::Forbidden { .. }),
        "a chain must report a denial AS a denial, not flatten it into an \
         internal error: {err:?}"
    );
    assert!(
        err.to_string().contains("refused"),
        "and must say which step: {err}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0, "no backend call");
}

/// The allow counterpart. Without it, 13c and 13d pass vacuously if code-mode
/// dispatch never reaches a backend for some unrelated reason.
#[tokio::test]
async fn authz_13cd_code_mode_allowed_reaches_the_backend() {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::new(registry).with_code_mode(true);

    let single = meta
        .code_mode_execute(
            &json!({ "tool": "alpha:read", "arguments": {} }),
            None,
            &ctx(&AllowAll),
        )
        .await;
    assert!(
        single.is_ok(),
        "an allowed code-mode call must run: {single:?}"
    );

    let chain = meta
        .code_mode_execute(
            &json!({ "chain": [ { "tool": "alpha:read", "arguments": {} } ] }),
            None,
            &ctx(&AllowAll),
        )
        .await;
    assert!(chain.is_ok(), "an allowed chain must run: {chain:?}");

    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "both allowed shapes must actually reach the backend, or the two \
         refusals above prove nothing about authorization"
    );
}
