// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7689: the passthrough slot budget is keyed on a credential-unique
//! principal, so two callers who share a display label do not share it.

use super::slot_principal;
use crate::gateway::auth::QuotaPrincipal;
use crate::gateway::oauth::AgentIdentity;
use crate::mtls::CertIdentity;

fn agent(client_id: &str) -> AgentIdentity {
    AgentIdentity {
        quota_principal: Some(QuotaPrincipal::oauth_client(client_id)),
        client_id: client_id.to_string(),
        agent_name: "same display name".to_string(),
        scopes: Vec::new(),
        raw_scopes: Vec::new(),
    }
}

fn cert(der: &[u8]) -> CertIdentity {
    CertIdentity {
        display_name: "same display name".to_string(),
        quota_principal: Some(QuotaPrincipal::client_certificate(der)),
        ..CertIdentity::default()
    }
}

#[test]
fn two_agents_sharing_a_display_name_get_separate_slot_budgets() {
    let (one, two) = (agent("client-one"), agent("client-two"));
    assert_ne!(
        slot_principal(None, Some(&one), None),
        slot_principal(None, Some(&two), None)
    );
}

#[test]
fn two_certificates_sharing_a_display_name_get_separate_slot_budgets() {
    let (one, two) = (cert(b"certificate one"), cert(b"certificate two"));
    assert_ne!(
        slot_principal(None, None, Some(&one)),
        slot_principal(None, None, Some(&two))
    );
}
