// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7642 PR.C: a `/mcp` cancel key's owner is the caller key, so two
//! certificates naming no subject never share one owner.

use serde_json::json;

use super::mcp_cancel_key;
use crate::gateway::auth::{AuthenticatedClient, anonymous_client, principal_of};
use crate::identity_grants::GrantSubject;
use crate::mtls::CertIdentity;

fn credential(secret: &str) -> AuthenticatedClient {
    AuthenticatedClient {
        name: "key".to_owned(),
        principal: principal_of(secret),
        authenticated: true,
        ..anonymous_client()
    }
}

/// Two certificates with neither a SAN URI nor a CN resolve to the same
/// display-name grant subject. Keyed on that, either caller could cancel the
/// other's call; keyed on the caller key, each is its credential, and with no
/// credential there is no owner at all. Mutant: the certificate not passed
/// to the caller key (the display name becomes the owner).
#[test]
fn certificates_naming_no_subject_never_share_a_cancel_owner() {
    let cert = CertIdentity {
        display_name: "<unknown>".to_owned(),
        ..Default::default()
    };
    let shown = GrantSubject::new("mtls", "<unknown>", None);
    let (one, two) = (credential("k1"), credential("k2"));
    let key = |client| mcp_cancel_key((Some(&shown), Some(&cert), client), "", &json!(7));
    assert_ne!(
        key(Some(&one)),
        key(Some(&two)),
        "each is its own credential"
    );
    assert!(key(Some(&one)).is_some());
    assert_eq!(
        key(None),
        None,
        "no subject and no credential: never registered"
    );
}
