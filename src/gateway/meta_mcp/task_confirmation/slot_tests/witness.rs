// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8353 S1-b and S1-c: X14 hands a signed call's refund witness back on
//! every arm that consumed nothing, and drops it where it spends a grant, so no
//! refusal after that spend can give the nonce back.

use serde_json::json;

use super::{
    Fixture, Hint, TaskConfirmation, TaskConfirmationRequest, accepted_challenge, elicitation,
    fixture, fresh, identity, open_scope,
};
use crate::config::BackendConfig;
use crate::gateway::meta_mcp::refund_witness::RefundWitness;
use crate::key_server::oidc::VerifiedIdentity;
use crate::protocol::RequestId;
use crate::protocol::mrtr::RetryFields;

/// [`super::ask`] carrying `witness` through X14.
async fn ask_with(
    fx: &Fixture,
    retry: &RetryFields,
    witness: Option<RefundWitness>,
) -> (TaskConfirmation, Option<RefundWitness>) {
    let who = identity();
    let caller = crate::gateway::meta_mcp::MetaMcpCallerContext {
        verified_identity: Some(&who),
        ..crate::gateway::meta_mcp::anonymous_caller()
    };
    let owner = VerifiedIdentity::stable_actor_id(&who);
    let arguments = json!({ "id": 1 });
    let task = json!({ "ttl": 60_000 });
    let principal = crate::protocol::mrtr::source_fingerprint(caller.principal_source(None));
    fx.meta
        .confirm_destructive_task_with(
            &TaskConfirmationRequest {
                id: RequestId::Number(7),
                tool_name: super::TOOL,
                arguments: &arguments,
                task: Some(&task),
                retry,
                verified_identity: caller.verified_identity,
                principal,
                quota: caller.quota_key(),
                owner: &owner,
                scope: open_scope(),
                session_id: None,
                input_capabilities: elicitation(),
                is_modern: true,
                admission: &fx.admission,
            },
            witness,
        )
        .await
}

/// S1-c: a challenge consumes nothing, so the witness comes back with it.
/// Mutant: the challenge arm drops the witness.
#[tokio::test]
async fn a_challenge_hands_the_witness_back() {
    let fx = fixture(BackendConfig::default(), Some(Hint::Destructive)).await;
    let (outcome, witness) = ask_with(&fx, &fresh(), Some(RefundWitness::at_capture())).await;
    assert!(
        matches!(outcome, TaskConfirmation::Answer(_)),
        "premise: X14 asked"
    );
    assert!(witness.is_some(), "a challenge dropped the witness");
}

/// S1-b: redeeming an accepted grant spends it, so the witness is gone and no
/// later refusal can give the nonce back. Mutants mF-x14 and mH2-x14: X14
/// returns its witness after the consume.
#[tokio::test]
async fn a_spent_grant_drops_the_witness() {
    let fx = fixture(BackendConfig::default(), Some(Hint::Destructive)).await;
    let (retry, _) = accepted_challenge(&fx).await;
    let (outcome, witness) = ask_with(&fx, &retry, Some(RefundWitness::at_capture())).await;
    assert!(
        matches!(outcome, TaskConfirmation::Granted(_)),
        "premise: the grant was redeemed"
    );
    assert!(witness.is_none(), "a spent grant handed the witness back");
}
