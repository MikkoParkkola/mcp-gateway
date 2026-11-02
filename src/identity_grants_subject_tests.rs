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
