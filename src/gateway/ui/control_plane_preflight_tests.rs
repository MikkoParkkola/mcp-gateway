// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202 part 2 (P2), T15: the control-plane approve/deny and grant/policy
//! handlers authorize and refuse without applying anything, so the audit event
//! they build is validation-only. Its id is fixed and reads no clock; on a
//! clock before 1970 it is the same fixed id.

use super::mutations::PREFLIGHT_EVENT_IDS;
use super::{
    Decision, DecisionRequest, GRANT_WRITES_REFUSED, apply_mutation, resolve_decision_core,
};
use crate::control_plane::{
    ControlPlaneAction, ControlPlaneActor, ControlPlaneDecisionTargetKind, ControlPlaneRole,
    ControlPlaneRollbackPlan, ControlPlaneStore, InMemoryControlPlaneStore,
};
use axum::http::StatusCode;
use std::sync::Arc;

/// The one id a validation-only preflight uses, with or without a clock.
const FIXED_PREFLIGHT_ID: &str = "cpa-validation-only";

fn actor(role: ControlPlaneRole) -> ControlPlaneActor {
    ControlPlaneActor {
        actor_id: "gateway-client:tester".to_string(),
        display_name: "tester".to_string(),
        role,
        group_ids: vec!["g".to_string()],
    }
}

fn rollback() -> ControlPlaneRollbackPlan {
    ControlPlaneRollbackPlan {
        summary: "revert".to_string(),
        step: "restore prior grant".to_string(),
    }
}

fn store() -> Arc<dyn ControlPlaneStore> {
    Arc::new(InMemoryControlPlaneStore::new())
}

fn mutate(role: ControlPlaneRole) -> StatusCode {
    apply_mutation(
        Ok(&store()),
        &actor(role),
        ControlPlaneAction::MutateGrant,
        "grant-1".to_string(),
        "upsert".to_string(),
        "MIK-1".to_string(),
        rollback(),
        &GRANT_WRITES_REFUSED,
    )
    .status()
}

fn decide(role: ControlPlaneRole) -> StatusCode {
    resolve_decision_core(
        Ok(&store()),
        &actor(role),
        DecisionRequest {
            target_kind: ControlPlaneDecisionTargetKind::Grant,
            target_id: "grant-1".to_string(),
            decision: Decision::Approve,
            reason: "MIK-1".to_string(),
            rollback: rollback(),
        },
    )
    .status()
}

fn recorded_ids() -> Vec<String> {
    PREFLIGHT_EVENT_IDS.with(|ids| ids.borrow().clone())
}

/// MIK-8202 RECORDER (audit id) rule, P2 row 16: both preflights build their
/// event with the fixed id on a clock before 1970. Mutant: id from
/// `Utc::now()`.
#[test]
fn t15_both_preflights_use_the_fixed_event_id_on_an_unreadable_clock() {
    PREFLIGHT_EVENT_IDS.with(|ids| ids.borrow_mut().clear());
    let _clock = crate::clock::test_clock::before_epoch();
    mutate(ControlPlaneRole::Admin);
    decide(ControlPlaneRole::Admin);
    assert_eq!(recorded_ids(), [FIXED_PREFLIGHT_ID, FIXED_PREFLIGHT_ID]);
}

/// T15 source check: the production constant is that literal and neither
/// preflight calls a clock.
#[test]
fn t15_the_preflights_read_no_clock_and_carry_the_fixed_id() {
    let source = include_str!("control_plane/mutations.rs");
    assert!(source.contains(&format!("\"{FIXED_PREFLIGHT_ID}\"")));
    for clock_call in ["Utc::now", "timestamp_millis", "crate::clock", "SystemTime"] {
        assert!(
            !source.contains(clock_call),
            "`{clock_call}` in mutations.rs"
        );
    }
}

/// T15 (guard): RBAC's 403 and the 409 refusal are unchanged on that clock.
#[test]
fn t15_control_the_403_and_409_answers_hold_on_an_unreadable_clock() {
    let _clock = crate::clock::test_clock::before_epoch();
    assert_eq!(mutate(ControlPlaneRole::Admin), StatusCode::CONFLICT);
    assert_eq!(mutate(ControlPlaneRole::Auditor), StatusCode::FORBIDDEN);
    assert_eq!(decide(ControlPlaneRole::Admin), StatusCode::CONFLICT);
    assert_eq!(decide(ControlPlaneRole::Auditor), StatusCode::FORBIDDEN);
}
