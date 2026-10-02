// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7688: which principal owns a caller's keyed calls. A credential always
//! wins (no existing record re-keys); only a credential-less caller proven by
//! an OAuth agent or a certificate falls back to its subject key.

use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::authz_tests::ctx;
use crate::identity_grants::GrantSubject;

const AGENT_KEY: &str = "subject:11:agent_oauth:7:agent-a";

#[test]
fn a_credential_wins_over_a_proven_subject() {
    let mut caller = ctx(&AllowAll);
    caller.credential_principal = Some("0123456789ab");
    caller.grant_subject = Some(GrantSubject::new("agent_oauth", "agent-a", None));
    caller.caller_key = Some(AGENT_KEY);
    assert_eq!(caller.owner_principal(), Some("0123456789ab"));
}

#[test]
fn a_credential_less_agent_owns_by_its_subject_key() {
    for principal in [None, Some("")] {
        let mut caller = ctx(&AllowAll);
        caller.credential_principal = principal;
        caller.grant_subject = Some(GrantSubject::new("agent_oauth", "agent-a", None));
        caller.caller_key = Some(AGENT_KEY);
        assert_eq!(caller.owner_principal(), Some(AGENT_KEY), "{principal:?}");
    }
}

#[test]
fn a_header_identity_is_no_owner() {
    let mut caller = ctx(&AllowAll);
    caller.credential_principal = Some("");
    caller.grant_subject = Some(GrantSubject::new("proxy.example", "alice", None));
    caller.caller_key = Some("subject:13:proxy.example:5:alice");
    assert_eq!(caller.owner_principal(), None);
}
