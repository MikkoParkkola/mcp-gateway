// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The scope the control-plane snapshot is read by, for each client shape.
//! No route reaches the unauthenticated shapes (the snapshot route refuses
//! them first), so they are pinned here.

use super::snapshot::{is_scoped, snapshot_scope};
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::authz::BackendGrant;

fn client(admin: bool, authenticated: bool, backends: &[&str]) -> AuthenticatedClient {
    AuthenticatedClient {
        principal: crate::gateway::record_principal::InternalPrincipal::new(String::new()),
        quota_principal: None,
        name: "c".to_string(),
        rate_limit: 0,
        backends: backends.iter().map(|b| (*b).to_string()).collect(),
        allowed_tools: None,
        denied_tools: None,
        admin,
        authenticated,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
    }
}

#[test]
fn only_an_authenticated_client_has_a_snapshot_scope() {
    assert_eq!(snapshot_scope(None), BackendGrant::Empty);
    let anonymous = client(false, false, &["*"]);
    assert_eq!(snapshot_scope(Some(&anonymous)), BackendGrant::Empty);
    let anonymous_admin = client(true, false, &[]);
    assert_eq!(snapshot_scope(Some(&anonymous_admin)), BackendGrant::Empty);

    let every = client(false, true, &["*"]);
    assert_eq!(snapshot_scope(Some(&every)), BackendGrant::Unscoped);
    let ui_admin = client(true, true, &[]);
    assert_eq!(snapshot_scope(Some(&ui_admin)), BackendGrant::Unscoped);
    let scoped_admin = client(true, true, &["alpha"]);
    assert!(matches!(
        snapshot_scope(Some(&scoped_admin)),
        BackendGrant::Scoped(_)
    ));

    assert!(is_scoped(None) && is_scoped(Some(&anonymous)) && is_scoped(Some(&scoped_admin)));
    assert!(!is_scoped(Some(&every)) && !is_scoped(Some(&ui_admin)));
}
