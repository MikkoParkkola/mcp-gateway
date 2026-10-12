// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The in-band confirmation gate under the per-caller slot cap (MIK-8293)
//! and its release on a refused envelope mint (MIK-8311).

use serde_json::json;

use crate::protocol::RequestId;

/// One fresh in-band confirmation of a destructive meta tool as `ctx`.
async fn confirm(ctx: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>) {
    let arguments = json!({"server": "brave"});
    let _ = super::destructive_confirmation_gate(
        &RequestId::Number(1),
        "gateway_kill_server",
        &arguments,
        None,
        ctx,
    )
    .await;
}

/// S3a (SLOTQ.3, green pin): two API keys that share a display name are two
/// callers with two caps. Each takes its 64 in-band confirmations on one
/// store, every one taking a slot, and each is then refused its 65th. A cap
/// keyed on anything coarser than the key itself refuses the second key
/// early. Asserts slot counts only, never how a confirmation is sealed.
/// Mutant m6: the confirmation site keys the cap on its sealed principal.
#[tokio::test]
async fn s3a_two_keys_sharing_a_name_have_two_caps() {
    let continuation = std::sync::Arc::new(crate::protocol::continuation::ContinuationState::new());
    let now = crate::protocol::continuation::now_unix_secs();
    for (n, principal) in ["digest-key-a", "digest-key-b"].into_iter().enumerate() {
        let mut ctx = super::allow_all_ctx_named(Some("shared-label"), None);
        ctx.credential_principal = Some(principal);
        ctx.authentication = crate::gateway::meta_mcp::Authentication::Authenticated;
        ctx.confirmation = crate::gateway::destructive_confirmation::ConfirmationChannel::InBand {
            continuation: &continuation,
        };
        for i in 0..crate::protocol::continuation::PRINCIPAL_SLOTS {
            let before = continuation.in_flight().len(now).await;
            confirm(&ctx).await;
            assert_eq!(
                continuation.in_flight().len(now).await,
                before + 1,
                "key {n} confirmation {i} took no slot: the two keys share a cap"
            );
        }
        let before = continuation.in_flight().len(now).await;
        confirm(&ctx).await;
        assert_eq!(
            continuation.in_flight().len(now).await,
            before,
            "key {n}'s 65th confirmation took a slot past its cap"
        );
    }
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
