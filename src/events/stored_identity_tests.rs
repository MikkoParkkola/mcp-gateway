// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A stored row's observed identity comes back only through the checked
//! constructor: one that names nobody observes as no one, and the on-disk
//! shape of an identity that does name someone is unchanged.
//!
//! Every row builds its stored identity from hand-written JSON, never from
//! the code's own writer, so a renamed field fails here rather than
//! round-tripping through itself.

use super::{ObsRefusal, binding, observe_row, observe_subscriber};
use crate::config::Config;
use crate::events::records::Subscription;
use serde_json::{Value, json};

fn config() -> Config {
    crate::yaml::from_str(
        "backends:\n  \
         signed:\n    http_url: https://h/mcp\n    identity_propagation:\n      \
         strategy: signed_assertion\n      audience: https://mail\n      session_mode: per_user\n",
    )
    .expect("config parses")
}

/// A per-user row on `signed` whose stored identity is `identity`, as the
/// events store reads it back from disk.
fn stored_row(identity: &Value) -> Subscription {
    let config = config();
    let witness = crate::key_server::oidc::VerifiedIdentity::checked(
        "https://idp".into(),
        "witness".into(),
        "witness@example.com".into(),
        None,
        Vec::new(),
    )
    .expect("names someone");
    let basis = observe_subscriber(&config, "signed", Some(&witness))
        .expect("observes")
        .expect("per-user");
    serde_json::from_value(json!({
        "v": 1, "id": "i", "principal": "p", "api_key": null, "url": "https://cb",
        "name": "backend.signed.tools_changed", "arguments": {}, "secret": "s",
        "previous_secret": null, "previous_until": null,
        "granted_at": "2026-10-25T00:00:00Z", "expires_at": null, "active": true,
        "failed_since": null, "last_delivery_at": null, "last_error": null,
        "observed_identity": identity,
        "obs_basis": serde_json::to_value(basis).expect("basis serializes"),
    }))
    .expect("a stored row loads")
}

fn identity(issuer: &str, subject: &str) -> Value {
    json!({
        "subject": subject, "email": "someone@example.com",
        "groups": [], "issuer": issuer,
    })
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
        "someone@example.com".into(),
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
        let as_json = serde_json::to_value(&observed).expect("serializes");
        assert_eq!(as_json["subject"], "p", "{literal}");
        assert_eq!(as_json["email"], "p@example.com", "{literal}");
        assert_eq!(as_json["issuer"], "https://idp", "{literal}");
        assert_eq!(
            as_json.get("name").and_then(Value::as_str),
            name,
            "{literal}"
        );
        assert_eq!(as_json["groups"], json!(groups), "{literal}");
    }
}
