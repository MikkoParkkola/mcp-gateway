// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8392 F4 at the pre-pass seam: a cold per-user view whose target the
//! caller's invocation policy refuses is never claimed, so a doomed stored
//! read resolves no credential. Driven at the seam because no HTTP fixture
//! can narrow a per-user caller's policy after its task ran (grants bind the
//! capability provider only; profiles and the tool policy are fixed at
//! build).

use super::super::InvokeScope;
use super::super::catalogue_per_caller_tests::identity;
use super::super::identified_caller;
use super::super::slot_verdict_fixture::{
    BACKEND, CallerSlot, PerUser, Surfaced, TOOL, Warmth, per_user, valid,
};
use crate::config::InputSchemaEnforcement;
use crate::gateway::authz::{AllowAll, DenyOne, ToolAuthorizer};

/// alpha's cold view settled under `authorizer`: the resolutions it made.
async fn resolutions(fx: &PerUser, authorizer: &(dyn ToolAuthorizer + Sync)) -> usize {
    let alpha = identity("alpha");
    let caller = identified_caller(&alpha);
    let scope = InvokeScope {
        authorizer,
        ..caller.scope()
    };
    let before = fx.mints();
    if let Some(fill) = fx.meta.claim_caller_view(BACKEND, TOOL, scope, None).await {
        fill.run().await;
    }
    fx.mints() - before
}

fn cold() -> PerUser {
    per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Cold,
        InputSchemaEnforcement::Closed,
        Surfaced::Yes,
    )
}

/// F4 `may_invoke` (MIK-8392): the caller's policy refuses the target, so the
/// cold claim is skipped: 0 resolutions, no backend traffic. The control
/// (an open policy) claims and resolves once on the same fixture. Red with
/// the `may_invoke` clause dropped from `refused_without_catalogue`.
#[tokio::test]
async fn f4_a_cold_view_refused_by_the_invocation_policy_resolves_nothing() {
    let open = cold();
    assert_eq!(
        resolutions(&open, &AllowAll).await,
        1,
        "control: an open policy claims the cold view and resolves once"
    );
    let fx = cold();
    let lists = fx.caller.lists();
    assert_eq!(
        resolutions(&fx, &DenyOne { tool: TOOL }).await,
        0,
        "F4: a policy-refused read resolves nothing"
    );
    assert_eq!(fx.caller.lists(), lists, "F4: no backend traffic");
}
