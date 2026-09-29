// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D4 classifier cells: every `denied` arm of D1's outcome has a reason, and
//! the two routes agree on the same refusal.

use serde_json::json;

use super::{DenialReason, direct_denial, meta_denial};
use crate::Error;
use crate::security::audit::AuditOutcome;

fn forbidden(code: i32) -> crate::Result<serde_json::Value> {
    Err(Error::Forbidden {
        code,
        status: 403,
        message: "no".into(),
    })
}

fn rpc(code: i32) -> crate::Result<serde_json::Value> {
    Err(Error::JsonRpc {
        code,
        message: "no".into(),
        data: None,
    })
}

#[test]
fn every_meta_denied_arm_has_its_reason() {
    assert_eq!(
        meta_denial(&forbidden(-32003)),
        Some(DenialReason::BackendScope)
    );
    assert_eq!(
        meta_denial(&forbidden(-32600)),
        Some(DenialReason::RequestPolicy)
    );
    assert_eq!(meta_denial(&rpc(-32004)), Some(DenialReason::IdentityGrant));
    assert_eq!(
        meta_denial(&rpc(-32001)),
        Some(DenialReason::GatewayRefusal)
    );
    assert_eq!(
        meta_denial(&Err(Error::ResponseFirewallRefused)),
        Some(DenialReason::ResponseFirewall)
    );
}

#[test]
fn meta_non_denials_are_not_counted() {
    assert_eq!(meta_denial(&Ok(json!({}))), None);
    assert_eq!(meta_denial(&rpc(-32602)), None);
    assert_eq!(meta_denial(&Err(Error::AuditUnavailable)), None);
    assert_eq!(meta_denial(&Err(Error::Transport("x".into()))), None);
}

#[test]
fn direct_reasons_follow_the_same_table() {
    let denied = |code| AuditOutcome::Denied(code);
    let body = |code: i32| json!({"error": {"code": code, "message": "no"}});
    assert_eq!(
        direct_denial(denied(-32003), &body(-32003)),
        Some(DenialReason::BackendScope)
    );
    let offer = json!({"error": {"code": -32003, "message": "no",
                                 "data": {"account_id": "a", "error": "x"}}});
    assert_eq!(
        direct_denial(denied(-32003), &offer),
        Some(DenialReason::AccountNotUsable)
    );
    assert_eq!(
        direct_denial(denied(-32600), &body(-32600)),
        Some(DenialReason::RequestPolicy)
    );
    assert_eq!(
        direct_denial(denied(-32099), &body(-32099)),
        Some(DenialReason::Other)
    );
    assert_eq!(direct_denial(AuditOutcome::Ok, &json!({})), None);
    assert_eq!(
        direct_denial(AuditOutcome::Invalid(-32602), &body(-32602)),
        None
    );
}
