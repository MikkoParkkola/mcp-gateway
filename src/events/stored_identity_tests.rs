// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A stored row's observed identity comes back only through the checked
//! constructor: one that names nobody observes as no one, and the on-disk
//! shape of an identity that does name someone is unchanged.
//!
//! Every row builds its stored identity from hand-written JSON, never from
//! the code's own writer, so a renamed field fails here rather than
//! round-tripping through itself.

use super::{ObsRefusal, binding, observe_row};
use crate::events::records::Subscription;
use crate::events::stored_identity_fixture::{config, identity, per_user_row};
use serde_json::Value;

/// A per-user row on `signed` whose stored identity is `identity`, as the
/// events store reads it back from disk.
fn stored_row(identity: &Value) -> Subscription {
    per_user_row("backend.signed.tools_changed", identity)
}

/// A stored identity naming nobody (empty or blank issuer or subject) is
/// what `checked` refuses: the row observes as no one and holds no key.
#[test]
fn a_stored_identity_naming_nobody_observes_as_no_one() {
    for (case, stored) in [
        ("empty subject", identity("https://idp", "")),
        ("empty issuer", identity("", "p")),
        ("blank subject", identity("https://idp", "  ")),
        ("blank issuer", identity(" ", "p")),
    ] {
        let row = stored_row(&stored);
        assert!(
            row.observed_as().is_none(),
            "{case}: observes as no one, got {:?}",
            row.observed_as().map(|i| i.stable_actor_id())
        );
        assert_eq!(
            observe_row(&config(), "signed", &row),
            Err(ObsRefusal::NoIdentity),
            "{case}: holds no key"
        );
    }
}

/// Control: a stored identity that names someone observes as that person,
/// under the key a subscribe for them derives.
#[test]
fn a_stored_identity_that_checks_observes_as_its_subject() {
    let row = stored_row(&identity("https://idp", "p"));
    let observed = row.observed_as().expect("names someone");
    let expected = crate::key_server::oidc::VerifiedIdentity::checked(
        "https://idp".into(),
        "p".into(),
        "q@h".into(),
        None,
        Vec::new(),
    )
    .expect("names someone");
    assert_eq!(observed.stable_actor_id(), expected.stable_actor_id());
    let key = binding(&config(), "signed")
        .expect("identity-bound")
        .observe(&expected)
        .expect("observes");
    assert_eq!(observe_row(&config(), "signed", &row), Ok(Some(key)));
}

/// The identity a row writes is the shape rows on disk already have: these
/// field names are written out by hand, so a renamed or dropped field fails.
#[test]
fn the_stored_identity_json_is_unchanged() {
    let without_name =
        r#"{"subject":"p","email":"p@example.com","groups":["g"],"issuer":"https://idp"}"#;
    let with_name = r#"{"subject":"p","email":"p@example.com","name":"P","groups":["g"],"issuer":"https://idp"}"#;
    for literal in [without_name, with_name] {
        let expected: Value = serde_json::from_str(literal).expect("literal parses");
        let row = stored_row(&expected);
        let written = serde_json::to_value(&row).expect("row serializes");
        assert_eq!(written["observed_identity"], expected, "{literal}");
    }
}

/// A row written before this change loads, field for field, including one
/// whose identity has no `name` and no `groups` member at all.
#[test]
fn a_stored_identity_written_by_an_older_gateway_loads() {
    let old = [
        (
            r#"{"subject":"p","email":"p@example.com","issuer":"https://idp"}"#,
            None,
            Vec::<String>::new(),
        ),
        (
            r#"{"subject":"p","email":"p@example.com","name":"P","groups":["g"],"issuer":"https://idp"}"#,
            Some("P"),
            vec!["g".to_owned()],
        ),
    ];
    for (literal, name, groups) in old {
        let row = stored_row(&serde_json::from_str(literal).expect("literal parses"));
        let observed = row.observed_as().expect("names someone");
        assert_eq!(observed.subject(), "p", "{literal}");
        assert_eq!(observed.email(), "p@example.com", "{literal}");
        assert_eq!(observed.issuer(), "https://idp", "{literal}");
        assert_eq!(observed.name(), name, "{literal}");
        assert_eq!(observed.groups(), groups.as_slice(), "{literal}");
    }
}

/// The production writer: an identity the gateway verified, stored through
/// `StoredIdentity::from`, writes the hand-written shape with every field,
/// `name` and `groups` included, so the conversion drops nothing.
#[test]
fn a_verified_identity_is_stored_in_the_on_disk_shape() {
    let verified = crate::key_server::oidc::VerifiedIdentity::checked(
        "https://idp".into(),
        "p".into(),
        "p@h".into(),
        Some("P".into()),
        vec!["g".into(), "h".into()],
    )
    .expect("names someone");
    let stored = crate::events::records::StoredIdentity::from(&verified);
    assert_eq!(
        serde_json::to_value(&stored).expect("serializes"),
        serde_json::from_str::<Value>(
            r#"{"subject":"p","email":"p@h","name":"P","groups":["g","h"],"issuer":"https://idp"}"#
        )
        .expect("literal parses")
    );
}
