// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every `Admin` and `AdminSplit` route of the UI access table refuses an
//! admin credential scoped to some backends, and admits an unscoped admin
//! (`*`, an admin key with no backends, the static bearer). Read from the
//! table itself, so a route added later is covered without editing this.

use super::access_table::{Need, ROWS};
use super::guard::decide;
use crate::gateway::auth::AuthenticatedClient;
use crate::security::audit::CredentialKind;

fn client(admin: bool, backends: &[&str], kind: CredentialKind) -> AuthenticatedClient {
    AuthenticatedClient {
        principal: crate::gateway::record_principal::InternalPrincipal::new(String::new()),
        quota_principal: None,
        name: "c".to_string(),
        rate_limit: 0,
        backends: backends.iter().map(|b| (*b).to_string()).collect(),
        allowed_tools: None,
        denied_tools: None,
        admin,
        authenticated: true,
        credential_kind: kind,
    }
}

#[test]
fn every_admin_route_refuses_a_backend_scoped_admin() {
    let admitted = [
        ("admin key, *", client(true, &["*"], CredentialKind::ApiKey)),
        ("admin key, []", client(true, &[], CredentialKind::ApiKey)),
        (
            "static bearer",
            client(true, &["*"], CredentialKind::StaticBearer),
        ),
    ];
    let scoped = client(true, &["alpha"], CredentialKind::ApiKey);
    let mut wrong = Vec::new();
    let mut rows = 0;
    for row in ROWS {
        if !matches!(row.need, Need::Admin(_) | Need::AdminSplit) {
            continue;
        }
        rows += 1;
        let at = format!("{:?} {}", row.method, row.path);
        for (who, c) in &admitted {
            if decide(row.need, Some(c)).is_err() {
                wrong.push(format!("{at}: {who} refused"));
            }
        }
        if decide(row.need, Some(&scoped)).is_ok() {
            wrong.push(format!("{at}: admin key, [alpha] admitted"));
        }
    }
    assert!(rows > 0, "the access table has admin rows");
    assert!(
        wrong.is_empty(),
        "{} cells:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// The stream's admin parts, the full status view and the `reload` kind, are
/// gateway-wide: an unscoped admin gets both, a backend-scoped admin neither.
#[test]
fn the_stream_gives_a_backend_scoped_admin_no_admin_view() {
    let cells = [
        (
            "admin key, *",
            client(true, &["*"], CredentialKind::ApiKey),
            true,
        ),
        (
            "admin key, []",
            client(true, &[], CredentialKind::ApiKey),
            true,
        ),
        (
            "admin key, [alpha]",
            client(true, &["alpha"], CredentialKind::ApiKey),
            false,
        ),
        (
            "standard key, *",
            client(false, &["*"], CredentialKind::ApiKey),
            false,
        ),
    ];
    let mut wrong = Vec::new();
    for (who, c, admin) in &cells {
        let want: &[&str] = if *admin {
            &["status", "reload"]
        } else {
            &["status"]
        };
        let kinds = super::stream::kinds_for(c);
        if kinds != want {
            wrong.push(format!("{who}: kinds {kinds:?}, want {want:?}"));
        }
        if super::is_admin(Some(c)) != *admin {
            wrong.push(format!("{who}: full status view {}, want {admin}", !admin));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
