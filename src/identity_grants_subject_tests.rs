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
/// refuses, naming the path and the rule id; `gateway upgrade` removes such rows.
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
