// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A grant subject that names no one cannot be read from bytes, alone or
//! inside whatever holds it, and today's valid payloads read back unchanged.

use super::GrantSubject;

const NAMELESS: [&str; 3] = [
    r#"{"authority":"","subject":"alice"}"#,
    r#"{"authority":"api_key","subject":""}"#,
    r#"{"authority":"","subject":""}"#,
];

#[test]
fn a_subject_naming_no_one_is_refused_on_deserialize() {
    for body in NAMELESS {
        assert!(
            serde_json::from_str::<GrantSubject>(body).is_err(),
            "{body}"
        );
    }
}

#[test]
fn a_nested_subject_naming_no_one_is_refused() {
    #[derive(Debug, serde::Deserialize)]
    struct Holder {
        #[serde(rename = "who")]
        _who: GrantSubject,
    }
    use serde::Deserialize as De;
    #[derive(Debug, De)]
    struct Aliased {
        #[serde(rename = "who")]
        _who: GrantSubject,
    }
    for body in NAMELESS {
        let held = format!(r#"{{"who":{body}}}"#);
        assert!(serde_json::from_str::<Holder>(&held).is_err(), "{held}");
        assert!(
            serde_json::from_str::<Aliased>(&held).is_err(),
            "aliased derive: {held}"
        );
        assert!(
            serde_json::from_str::<Option<GrantSubject>>(body).is_err(),
            "Option: {body}"
        );
        let list = format!("[{body}]");
        assert!(
            serde_json::from_str::<Vec<GrantSubject>>(&list).is_err(),
            "Vec: {list}"
        );
    }
}

#[test]
fn a_valid_subject_payload_reads_back_unchanged() {
    for body in [
        r#"{"authority":"api_key","subject":"alice"}"#,
        r#"{"authority":"local","subject":"alice-sub","label":"alice"}"#,
    ] {
        let read: GrantSubject = serde_json::from_str(body).expect(body);
        assert_eq!(serde_json::to_string(&read).unwrap(), body);
    }
}

fn grants_yaml(subject: &str, owner: &str) -> String {
    format!(
        "schema_version: identity_grants.v1\ngrants:\n- grant_id: g-empty\n  subject:\n    authority: api_key\n    subject: \"{subject}\"\n  agent: any\n  capability: calendar_read\n  scope: execute\n  owner:\n    authority: api_key\n    subject: \"{owner}\"\n  provenance: mcp-gateway identity grants grant\n  reason: empty\n"
    )
}

/// An empty subject or owner in a grants file grants nothing, so loading it
/// refuses, naming the path and the rule id.
#[tokio::test]
async fn a_grants_yaml_naming_no_one_is_refused_with_its_path_and_rule_id() {
    for (subject, owner) in [("", "alice"), ("alice", "")] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.yaml");
        crate::gateway::test_helpers::write_owner_only(&path, grants_yaml(subject, owner)).unwrap();
        let error = super::read_identity_grants_file(&path)
            .await
            .expect_err("a rule naming no one must not load");
        assert!(error.contains(&path.display().to_string()), "path: {error}");
        assert!(error.contains("g-empty"), "rule id: {error}");
    }
}

#[test]
fn new_refuses_a_subject_naming_no_one_and_names_the_empty_part() {
    use super::EmptyIdentity;
    assert_eq!(
        GrantSubject::new("", "alice", None).unwrap_err(),
        EmptyIdentity::Authority
    );
    assert_eq!(
        GrantSubject::new("api_key", "", None).unwrap_err(),
        EmptyIdentity::Subject
    );
    assert_eq!(
        GrantSubject::new("", "", None).unwrap_err(),
        EmptyIdentity::Authority
    );
}

/// A value of only spaces names no one, like an empty one; any other value is
/// kept exactly as written, so `" admin "` stays a different subject from
/// `admin`.
#[test]
fn blank_names_no_one_and_other_values_stay_verbatim() {
    use super::EmptyIdentity;
    assert_eq!(
        GrantSubject::new("   ", "alice", None).unwrap_err(),
        EmptyIdentity::Authority
    );
    assert_eq!(
        GrantSubject::new("api_key", " \t ", None).unwrap_err(),
        EmptyIdentity::Subject
    );
    assert!(serde_json::from_str::<GrantSubject>(r#"{"authority":" ","subject":"x"}"#).is_err());
    let kept = GrantSubject::new("api_key", " admin ", None).expect("names someone");
    assert_eq!(kept.subject(), " admin ");
}

/// Golden: the whole refusal for a grants file whose only defect is a row
/// naming no one.
#[tokio::test]
async fn the_nameless_file_refusal_reads_exactly() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("grants.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, grants_yaml("", "alice")).unwrap();
    let error = super::read_identity_grants_file(&path).await.unwrap_err();
    let head = format!(
        "failed to parse identity grants file {}: 1 row(s) name no one: grant 'g-empty' \
         (empty subject). Such a row matches no caller, so it grants nothing; delete it from \
         the file",
        path.display()
    );
    assert!(error.starts_with(&head), "{error}");
}

/// Golden: a file with a bare agent id and a row naming no one names the
/// bare row, then says what still fails once it is set aside.
#[tokio::test]
async fn a_nameless_row_behind_a_bare_one_is_the_remainder_error() {
    let row = |id: &str, subject: &str, agent: &str| {
        format!(
            r#"{{"grant_id":"{id}","subject":{{"authority":"api_key","subject":"{subject}"}},"agent":{agent},"capability":"calendar_read","scope":"execute","provenance":"p","reason":"r"}}"#
        )
    };
    let body = format!(
        r#"{{"schema_version":"identity_grants.v1","grants":[{},{}]}}"#,
        row("g-bare", "alice", r#"{"exact":"agent-1"}"#),
        row("g-empty", "", r#""any""#),
    );
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("grants.json");
    crate::gateway::test_helpers::write_owner_only(&path, body).unwrap();
    let error = super::read_identity_grants_file(&path).await.unwrap_err();
    let head = format!(
        "identity grants file {} keys 1 agent binding(s) by a bare id, which does not say \
         which proof source it came from: grant 'g-bare' (exact agent-1).",
        path.display()
    );
    assert!(error.starts_with(&head), "{error}");
    assert!(
        error.ends_with(
            "The gateway will not choose. Apart from those rows the file also fails to parse: \
             1 row(s) name no one: grant 'g-empty' (empty subject). Such a row matches no \
             caller, so it grants nothing; delete it from the file"
        ),
        "{error}"
    );
}

/// A capability whose owner names no one is refused, saying which part is
/// empty; the loader names the file beside this error.
#[test]
fn a_capability_owner_naming_no_one_is_refused() {
    for (owner, part) in [
        ("{authority: api_key, subject: \"\"}", "subject"),
        ("{authority: \" \", subject: alice}", "authority"),
    ] {
        let yaml = format!(
            "name: owned\ndescription: d\nmetadata:\n  exposure: personal\n  identity_owner: {owner}\n\
             cache:\n  ttl: 60\n  strategy: memory\nproviders:\n  primary:\n    service: rest\n    config:\n      base_url: https://api.invalid\n      path: /x\n"
        );
        let error = crate::capability::parse_capability(&yaml)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("Failed to parse capability YAML")
                && error.contains(&format!("the identity's {part} is empty")),
            "{owner}: {error}"
        );
    }
}

/// Every row naming no one is named, with each empty field, in one refusal.
#[tokio::test]
async fn every_nameless_row_is_named_in_one_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("grants.yaml");
    let both = grants_yaml("", "").replace("g-empty", "g-both");
    let body = format!(
        "{}{}",
        grants_yaml("", "alice"),
        &both[both.find("- grant_id").unwrap()..]
    );
    crate::gateway::test_helpers::write_owner_only(&path, body).unwrap();
    let error = super::read_identity_grants_file(&path).await.unwrap_err();
    assert!(
        error.contains(
            "2 row(s) name no one: grant 'g-empty' (empty subject), grant 'g-both' (empty \
             subject and owner)."
        ),
        "{error}"
    );
}

/// The refusal comes from the loader's own typed parse, so a row the loader
/// refuses for another reason (here a field written twice) is refused the
/// same way beside a nameless one: nothing parses the file a second way.
#[tokio::test]
async fn a_duplicated_field_beside_a_nameless_row_is_the_loaders_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("grants.json");
    let body = r#"{"schema_version":"identity_grants.v1","grants":[{"grant_id":"g-ok","subject":{"authority":"api_key","subject":"alice"},"agent":"any","capability":"c","scope":"execute","revoked_at":"2026-01-01T00:00:00Z","revoked_at":null,"provenance":"p","reason":"r"},{"grant_id":"g-empty","subject":{"authority":"api_key","subject":""},"agent":"any","capability":"c","scope":"execute","provenance":"p","reason":"r"}]}"#;
    crate::gateway::test_helpers::write_owner_only(&path, body).unwrap();
    let error = super::read_identity_grants_file(&path).await.unwrap_err();
    assert!(error.contains("duplicate field `revoked_at`"), "{error}");
}

/// A nameless row sharing its id with another rule may have been shadowing
/// it (the gateway kept the last row per id), so the refusal says deleting
/// it makes the other one active.
#[tokio::test]
async fn a_nameless_row_sharing_its_id_is_flagged() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("grants.yaml");
    let valid = grants_yaml("alice", "alice");
    let body = format!(
        "{valid}{}",
        &grants_yaml("", "alice")[valid.find("- grant_id").unwrap()..]
    );
    crate::gateway::test_helpers::write_owner_only(&path, body).unwrap();
    let error = super::read_identity_grants_file(&path).await.unwrap_err();
    assert!(
        error.contains("another rule uses this id and may take effect once this one is deleted"),
        "{error}"
    );
}

/// A nameless row sharing its id with a row the file also refuses for a bare
/// agent binding is still flagged: setting the bare binding aside keeps the
/// row, so deletion advice never hides the rule it would reactivate.
#[tokio::test]
async fn a_nameless_row_sharing_its_id_with_a_bare_row_is_flagged() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("grants.yaml");
    let valid = grants_yaml("alice", "alice").replace("agent: any", "agent: !exact runner");
    let body = format!(
        "{valid}{}",
        &grants_yaml("", "alice")[valid.find("- grant_id").unwrap()..]
    );
    crate::gateway::test_helpers::write_owner_only(&path, body).unwrap();
    let error = super::read_identity_grants_file(&path).await.unwrap_err();
    assert!(error.contains("by a bare id"), "{error}");
    assert!(
        error.contains("another rule uses this id and may take effect once this one is deleted"),
        "{error}"
    );
}
