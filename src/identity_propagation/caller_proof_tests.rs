// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Oracles for the classifier itself.
//!
//! WHY HERE AND NOT IN THE VAULT TESTS. The vault tests construct `CallerProof`
//! variants directly, so they exercise what the account boundary does WITH an
//! answer and never how that answer is produced. An oracle that does not call
//! the function under test cannot fail for the right reason: when `classify`
//! silently became a catch-all, every one of those tests would still have
//! passed. These call `classify`.

use super::{CallerProof, CallerProvenance};
use crate::gateway::STDIO_CREDENTIAL_PRINCIPAL;

/// THE ARM A CATCH-ALL MAKES UNREACHABLE, and the reason this file exists.
///
/// A public path's caller reaches tool dispatch with an `AuthenticatedClient`
/// whose `principal` is empty — "Empty for an identity that presented no
/// credential" (`gateway/auth.rs`) — which arrives here as `Some("")`, NOT as
/// `None`. Classifying that as anything but `Anonymous` hands an anonymous
/// caller the deployment's stored OAuth grants, and the shipped starter config
/// lists `/mcp` under `public_paths`, so this is the default install's shape
/// rather than an exotic one.
#[test]
fn an_empty_credential_principal_is_anonymous_not_authentication() {
    assert_eq!(
        CallerProvenance::classify(Some("")),
        CallerProvenance::Anonymous,
        "an empty principal means no credential was presented"
    );
    assert!(
        !CallerProof::new(None, CallerProvenance::classify(Some(""))).established(),
        "and it must not survive into an operator-level proof"
    );
}

#[test]
fn a_missing_credential_principal_is_anonymous() {
    assert_eq!(
        CallerProvenance::classify(None),
        CallerProvenance::Anonymous
    );
}

/// A validated secret's digest is a credential, and is NOT the trusted
/// transport. Keeping these two distinguishable is the whole reason
/// `CallerProvenance` has three variants rather than being a boolean.
#[test]
fn a_validated_secret_is_a_credential_and_not_a_local_transport() {
    let provenance = CallerProvenance::classify(Some("a1b2c3-digest-of-a-validated-secret"));

    assert_eq!(provenance, CallerProvenance::Credential);
    assert_ne!(provenance, CallerProvenance::LocalTransport);
}

/// The stdio admission identifier is matched by VALUE, against the one constant
/// the transport actually sets. Written as a guard rather than a pattern: a
/// constant in pattern position degrades into a catch-all binding if its path
/// stops resolving, and this test is what notices.
#[test]
fn the_stdio_identifier_is_a_local_transport() {
    assert_eq!(
        CallerProvenance::classify(Some(STDIO_CREDENTIAL_PRINCIPAL)),
        CallerProvenance::LocalTransport
    );
    // The catch-all falsifier: if the guard ever became a binding, this input
    // would classify as `LocalTransport` too, and the assertion above would
    // still pass on its own.
    assert_ne!(
        CallerProvenance::classify(Some("not-the-stdio-identifier")),
        CallerProvenance::LocalTransport,
        "only the stdio constant itself may be a trusted transport"
    );
}

/// A verified identity outranks provenance, including the anonymous one: an
/// identity provider already validated a token, and letting a provenance bit
/// veto it would change how OIDC callers are served today.
#[test]
fn a_verified_identity_outranks_every_provenance() {
    let identity = crate::key_server::oidc::VerifiedIdentity {
        subject: "alice".into(),
        email: "alice@example.com".into(),
        name: None,
        groups: Vec::new(),
        issuer: "https://identity.example".into(),
    };

    for provenance in [
        CallerProvenance::Anonymous,
        CallerProvenance::LocalTransport,
        CallerProvenance::Credential,
    ] {
        assert!(
            CallerProof::new(Some(&identity), provenance)
                .verified()
                .is_some(),
            "{provenance:?} must not veto a verified identity"
        );
    }
}

/// Anonymous is the `Default`, so a construction site that does not know
/// refuses rather than mints.
#[test]
fn the_default_provenance_is_anonymous() {
    assert_eq!(CallerProvenance::default(), CallerProvenance::Anonymous);
    assert!(!CallerProof::new(None, CallerProvenance::default()).established());
}
