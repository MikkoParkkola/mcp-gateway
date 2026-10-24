// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! STREAM.2 (MIK-8774): [`check`] accepts exactly what
//! `serde_json::from_str::<Value>` accepts, row by row, and flags the
//! raw-value token instead of following it.

use super::*;
use serde_json::Value;

fn esc(hex: &str) -> String {
    format!("{}u{hex}", '\\')
}

fn agrees(text: &str) {
    let value = serde_json::from_str::<Value>(text);
    let checked = check(text);
    assert_eq!(checked.is_some(), value.is_ok(), "{text}: {value:?}");
    if let (Some(doc), Ok(value)) = (checked, value) {
        let walkable = value.is_object() || value.is_array() || value.is_string();
        assert_eq!(doc.walkable, walkable, "{text}");
        assert!(!doc.raw_value_token, "{text}");
    }
}

#[test]
fn v1_agrees_with_value() {
    let nested = |depth: usize| format!("{}1{}", "[".repeat(depth), "]".repeat(depth));
    let rows = [
        format!(r#"["{}"]"#, esc("d800")),
        format!(r#"["{}"]"#, esc("dc00")),
        format!(r#"["{}{}"]"#, esc("dc00"), esc("d800")),
        format!(r#"["{}{}"]"#, esc("d83d"), esc("de00")),
        format!(r#"["{}x"]"#, esc("d83d")),
        "[1e400]".to_owned(),
        "[-1e400]".to_owned(),
        "[1e-400]".to_owned(),
        "[18446744073709551615]".to_owned(),
        "[18446744073709551616]".to_owned(),
        "[-9223372036854775808]".to_owned(),
        "[-9223372036854775809]".to_owned(),
        "[01]".to_owned(),
        "[1.]".to_owned(),
        "[tru]".to_owned(),
        "[1,]".to_owned(),
        "[1] x".to_owned(),
        "[1] ".to_owned(),
        "\"tab\tin\"".to_owned(),
        r#"["esc\"aped\n"]"#.to_owned(),
        r#"{"a":1,"a":2}"#.to_owned(),
        r#"{"a" 1}"#.to_owned(),
        r#"{1:2}"#.to_owned(),
        String::new(),
        "  ".to_owned(),
        "3".to_owned(),
        "null".to_owned(),
        r#""s""#.to_owned(),
        nested(127),
        nested(128),
        nested(129),
    ];
    for row in rows {
        agrees(&row);
    }
}

#[test]
fn v2_the_raw_value_token_is_flagged_not_followed() {
    let token = "$serde_json::private::RawValue";
    for text in [
        format!(r#"{{"{token}":"[1]"}}"#),
        format!(r#"{{"{token}":null}}"#),
        format!(r#"[[{{"{token}":"{{}}","b":1}}]]"#),
        format!(r#"{{"$serde_json::private::Raw{}alue":1}}"#, esc("0056")),
    ] {
        let doc = check(&text).unwrap_or_else(|| panic!("{text}"));
        assert!(doc.raw_value_token, "{text}");
    }
    let later = format!(r#"{{"a":1,"{token}":"[1]"}}"#);
    assert_eq!(
        check(&later),
        Some(Document {
            walkable: true,
            raw_value_token: false
        })
    );
}
