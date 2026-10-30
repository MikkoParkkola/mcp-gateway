// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A same-key retry of a completed chain runs none of its steps again: the
//! call's execution lease holds the client's key above the steps, whose own
//! invocations carry no key.

use super::*;

/// Fail-fast row: a two-step chain completes under a key; the same call again
/// under that key is answered without a second send for either step.
#[tokio::test]
async fn a_same_key_retry_of_a_completed_chain_does_not_run_its_steps_again() {
    let fx = meta_fixture(Setup::default(), None).await;
    let chain = json!({"chain": [
        {"tool": "alpha:send", "arguments": {"text": "first"}},
        {"tool": "alpha:send", "arguments": {"text": "second"}}
    ]});
    let first = post(
        &fx,
        Some("a"),
        "gateway_execute",
        &chain,
        &keyed("key-chain"),
    )
    .await;
    assert_eq!(first.0, 200, "{}", first.1);
    assert!(envelope(&first.1).get("error").is_none(), "{}", first.1);
    assert_eq!(fx.sends(), 2, "premise: both steps were sent: {}", first.1);

    let again = post(
        &fx,
        Some("a"),
        "gateway_execute",
        &chain,
        &keyed("key-chain"),
    )
    .await;
    assert_eq!(again.0, 200, "{}", again.1);
    assert!(envelope(&again.1).get("error").is_none(), "{}", again.1);
    assert_eq!(
        fx.sends(),
        2,
        "a same-key retry of a completed chain ran its steps again: {}",
        again.1
    );
}
