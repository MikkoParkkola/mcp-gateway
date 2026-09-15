// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::*;

const ISSUER: &str = "https://identity.example";
const SUBJECT: &str = "alice-subject-8f21";

#[track_caller]
fn refuse_scaffold<T>(
    result: Result<T, IdentityBindingError>,
    what: &str,
) -> Result<T, IdentityBindingError> {
    match result {
        Err(IdentityBindingError::RuntimeNotImplemented) => {
            panic!("{what}: RuntimeNotImplemented is the scaffold, not a domain outcome")
        }
        other => other,
    }
}

#[track_caller]
fn domain_err<T>(result: Result<T, IdentityBindingError>, what: &str) -> IdentityBindingError {
    refuse_scaffold(result, what).err().expect(what)
}

/// A verified principal exactly as the request path produces it.
fn identity() -> VerifiedIdentity {
    VerifiedIdentity {
        subject: SUBJECT.into(),
        email: "alice@example.com".into(),
        name: Some("Alice Example".into()),
        groups: vec!["engineering".into()],
        issuer: ISSUER.into(),
    }
}

/// The configured descriptor. `descriptor_id` is the `accounts.descriptors` map
/// key, which the approved table makes the account key's `backend_id`.
fn descriptor() -> AccountDescriptor {
    AccountDescriptor {
        descriptor_id: "google-workspace-personal".into(),
        provider: "google".into(),
        resource: "https://www.googleapis.com/drive/v3".into(),
        issuer: "https://accounts.google.com".into(),
    }
}

#[track_caller]
fn digest_of(identity: &VerifiedIdentity, descriptor: &AccountDescriptor, what: &str) -> String {
    refuse_scaffold(account_key(Some(identity), descriptor), what)
        .expect(what)
        .digest()
        .expect("a constructed account key is well formed")
}

#[test]
fn account_key_binds_verified_principal_and_configured_descriptor() {
    let key = refuse_scaffold(
        account_key(Some(&identity()), &descriptor()),
        "positive binding",
    )
    .expect("a verified principal and a configured descriptor bind");

    assert_eq!(key.principal_authority, ISSUER, "inbound IdP issuer");
    assert_eq!(key.principal_subject, SUBJECT, "the sub claim");
    assert_eq!(
        key.backend_id, "google-workspace-personal",
        "backend_id is the descriptors MAP KEY, not a backend registry id"
    );
    assert_eq!(key.resource, "https://www.googleapis.com/drive/v3");
    assert_eq!(
        key.oauth_issuer, "https://accounts.google.com",
        "the downstream provider issuer, never the inbound authority"
    );
    assert_ne!(
        key.principal_authority, key.oauth_issuer,
        "inbound authority and downstream issuer are different fields"
    );
    key.digest().expect("the approved digest accepts this key");
}

/// The isolation test. A rename, a new address or a group change must not move
/// a user's custody; a different person must never land on it.
#[test]
fn display_fields_never_enter_the_key_but_issuer_and_subject_always_do() {
    let base = digest_of(&identity(), &descriptor(), "base");

    for (label, mutated) in [
        (
            "email",
            VerifiedIdentity {
                email: "alice.example@other.test".into(),
                ..identity()
            },
        ),
        (
            "name",
            VerifiedIdentity {
                name: Some("Alice Renamed".into()),
                ..identity()
            },
        ),
        (
            "name cleared",
            VerifiedIdentity {
                name: None,
                ..identity()
            },
        ),
        (
            "groups",
            VerifiedIdentity {
                groups: vec!["finance".into()],
                ..identity()
            },
        ),
        (
            "groups cleared",
            VerifiedIdentity {
                groups: Vec::new(),
                ..identity()
            },
        ),
    ] {
        assert_eq!(
            digest_of(&mutated, &descriptor(), label),
            base,
            "{label} is a mutable display field and must not change the account key"
        );
    }

    for (label, mutated) in [
        (
            "issuer",
            VerifiedIdentity {
                issuer: "https://other-idp.example".into(),
                ..identity()
            },
        ),
        (
            "subject",
            VerifiedIdentity {
                subject: "bob-subject-3c07".into(),
                ..identity()
            },
        ),
    ] {
        assert_ne!(
            digest_of(&mutated, &descriptor(), label),
            base,
            "{label} is part of the principal and must change the account key"
        );
    }
}

/// Every one of the five tuple fields must be load-bearing. A field that can be
/// moved without moving the digest is a field that is not isolating anything.
#[test]
fn each_of_the_five_tuple_fields_changes_the_digest() {
    let base = digest_of(&identity(), &descriptor(), "base");
    let mut seen = vec![base.clone()];

    let variants = [
        (
            "principal_authority",
            VerifiedIdentity {
                issuer: "https://other-idp.example".into(),
                ..identity()
            },
            descriptor(),
        ),
        (
            "principal_subject",
            VerifiedIdentity {
                subject: "carol-subject-11ab".into(),
                ..identity()
            },
            descriptor(),
        ),
        (
            "backend_id",
            identity(),
            AccountDescriptor {
                descriptor_id: "google-workspace-secondary".into(),
                ..descriptor()
            },
        ),
        (
            "resource",
            identity(),
            AccountDescriptor {
                resource: "https://www.googleapis.com/calendar/v3".into(),
                ..descriptor()
            },
        ),
        (
            "oauth_issuer",
            identity(),
            AccountDescriptor {
                issuer: "https://login.microsoftonline.com/common/v2.0".into(),
                ..descriptor()
            },
        ),
    ];
    for (label, who, what) in variants {
        let digest = digest_of(&who, &what, label);
        assert!(
            !seen.contains(&digest),
            "{label} must be part of the key: its digest collided with an earlier one"
        );
        seen.push(digest);
    }
    assert_eq!(
        seen.len(),
        6,
        "one base plus five distinct single-field moves"
    );
}

/// Two consumers naming the same descriptor id are one account, on purpose:
/// an MCP backend `account` and a REST capability `auth.account` that reference
/// the same descriptor share custody. The provider name alone must not join them.
#[test]
fn two_consumer_references_to_one_descriptor_id_are_the_same_account() {
    let shared = descriptor();
    let from_mcp_backend = digest_of(&identity(), &shared, "mcp backend account reference");
    let from_rest_capability = digest_of(&identity(), &shared, "rest capability auth.account");
    assert_eq!(
        from_mcp_backend, from_rest_capability,
        "explicit references to the same descriptor id are intentionally one account"
    );

    // Same provider, different descriptor id: a different account. Joining on
    // provider name alone is what row 431 forbids.
    let sibling = AccountDescriptor {
        descriptor_id: "google-workspace-secondary".into(),
        ..descriptor()
    };
    assert_eq!(sibling.provider, shared.provider);
    assert_ne!(
        digest_of(&identity(), &sibling, "same provider, other descriptor"),
        from_mcp_backend,
        "same provider must not auto-join two descriptors"
    );
}

#[test]
fn a_request_without_a_verified_principal_is_refused_not_inferred() {
    assert_eq!(
        domain_err(
            account_key(None, &descriptor()),
            "missing verified principal"
        ),
        IdentityBindingError::MissingVerifiedPrincipal,
        "no principal means no account key; nothing is inferred from the request"
    );
}
