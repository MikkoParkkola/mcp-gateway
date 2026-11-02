// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A grant that installs a token tells the backend's sign-in status, so a
//! backend that works stops reading as needing a sign-in.

use std::sync::Arc;

use super::authorize_tests::{approve, client, token_endpoint};
use super::sign_in::{SignIn, SignInStatus};

fn a_cell() -> Arc<SignInStatus> {
    Arc::new(SignInStatus::new(SignIn::NeverSignedIn))
}

/// A command-line or startup login that saves its token publishes
/// `SignedIn`. Red today: the install in `authorize_until_by` publishes
/// nothing, so the cell keeps its old value.
#[tokio::test]
async fn a_cli_login_publishes_signed_in() {
    let dir = tempfile::tempdir().unwrap();
    let (issuer, _forms) = token_endpoint(Some("access-a")).await;
    let cell = a_cell();
    let mut login = client(dir.path(), Some(&issuer)).with_sign_in_status(Arc::clone(&cell));

    let (outcome, _) = approve(&mut login, &issuer).await;

    outcome.expect("the flow completes");
    assert!(
        matches!(cell.snapshot(), SignIn::SignedIn { .. }),
        "{:?}",
        cell.snapshot()
    );
}

/// A client-credentials grant that saves its token publishes `SignedIn`.
/// Red today for the same reason: `try_client_credentials` installs the token
/// and publishes nothing.
#[tokio::test]
async fn a_client_credentials_grant_publishes_signed_in() {
    let dir = tempfile::tempdir().unwrap();
    let (issuer, _forms) = token_endpoint(Some("cc-access")).await;
    let cell = a_cell();
    let mut login = client(dir.path(), Some(&issuer)).with_sign_in_status(Arc::clone(&cell));
    login.auth_metadata = Some(
        serde_json::from_value(serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "grant_types_supported": ["client_credentials"],
        }))
        .unwrap(),
    );

    login
        .try_client_credentials(login.issuer_current().unwrap())
        .await
        .expect("the grant is issued");

    assert!(
        matches!(cell.snapshot(), SignIn::SignedIn { .. }),
        "{:?}",
        cell.snapshot()
    );
}
