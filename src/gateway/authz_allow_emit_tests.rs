// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A decision names its allowing check only when emitted under audit: a
//! silent pass (a listing, the send recheck) leaves the call's notes exactly
//! as another check of the same invocation left them.

use super::{Decision, Emit};
use crate::gateway::meta_mcp::invoke::audit::{preload_allow_for_test, with_dispatch_scope};
use crate::security::decision_record::{Allow, AllowRank, Noted};
use crate::security::rule_id::{RuleId, RuleKey};

fn id(name: &str) -> RuleId {
    RuleId::of("mtls", &RuleKey::from_derived([5; 32]), name.as_bytes())
}

/// The weakest attribution, so any leak of a stronger allow would show.
fn preload() -> Allow {
    Allow::by(AllowRank::FirewallAllow, Some(id("another invocation's")))
}

/// The notes after `emit`ting an mTLS allow inside a scope preloaded with
/// [`preload`], and the notes with the preload alone.
async fn notes_after(emit: Emit) -> (Noted, Noted) {
    let ((), alone) = with_dispatch_scope(async { preload_allow_for_test(preload()) }).await;
    let (verdict, emitted) = with_dispatch_scope(async {
        preload_allow_for_test(preload());
        Decision::of(Ok(()))
            .allowing(Some(Allow::by(AllowRank::Mtls, Some(id("agent-a")))))
            .emit(emit)
    })
    .await;
    assert!(verdict.is_ok(), "premise: allowed");
    (
        emitted.decision_for_test().clone(),
        alone.decision_for_test().clone(),
    )
}

/// R27 (ATTR.1). A silent emit inside an open scope holding another
/// invocation's attribution changes nothing. Kills M10 (noting under Silent).
#[tokio::test]
async fn a_silent_pass_notes_nothing() {
    let (emitted, alone) = notes_after(Emit::Silent).await;
    assert_eq!(emitted, alone);
}

/// R27 control (ATTR.1). The same decision emitted under audit does note its
/// allow over the weaker preload, so the silent row can fail.
#[tokio::test]
async fn an_audited_pass_notes_its_allow() {
    let (emitted, alone) = notes_after(Emit::Audit).await;
    assert_ne!(emitted, alone, "the audited allow was not noted");
}
