// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8507: the per-key cost name is narrower than the display name.
//!
//! `cost_key` is the API key's name for an API-key credential and `None` for
//! any other, so a display name another credential carries (`bearer`,
//! `dashboard`, an OIDC actor id) never selects a key's budget. The display
//! name itself is untouched: the audit record's `account`, the relay audit
//! label and the response-correlation caller all read `api_key_name`, and
//! must keep naming the caller.

use super::{MetaMcpCallerContext, anonymous_caller};
use crate::security::audit::{AuditWho, CredentialKind};

const ACTOR: &str = "oidc:24:https://issuer.example:5:alice";

#[test]
fn only_an_api_key_has_a_cost_key_and_every_caller_keeps_its_audit_account() {
    let rows = [
        (CredentialKind::StaticBearer, "bearer", None),
        (CredentialKind::ApiKey, "bearer", Some("bearer")),
        (CredentialKind::DashboardSession, "dashboard", None),
        (CredentialKind::KeyServerToken, ACTOR, None),
        (CredentialKind::OidcBearer, ACTOR, None),
        (CredentialKind::LocalTransport, "stdio", None),
    ];
    for (kind, name, cost) in rows {
        let caller = MetaMcpCallerContext {
            api_key_name: Some(name),
            credential_kind: kind,
            ..anonymous_caller()
        };
        assert_eq!(caller.cost_key(), cost, "{kind:?}: cost key");
        assert_eq!(
            caller.api_key_name,
            Some(name),
            "{kind:?}: the display name survives for relay and correlation"
        );
        assert_eq!(
            AuditWho::from_caller(&caller).account,
            name,
            "{kind:?}: the audit account still names the caller"
        );
    }
}

#[test]
fn a_caller_with_no_name_has_no_cost_key() {
    let caller = MetaMcpCallerContext {
        credential_kind: CredentialKind::ApiKey,
        ..anonymous_caller()
    };
    assert_eq!(caller.cost_key(), None);
}
