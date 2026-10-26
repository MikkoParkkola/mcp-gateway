// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The document gate reads without building a tree, and must route every
//! text exactly as the `Value` read it replaced: same parser, same failures.

use super::*;

/// The gate as it was: a `Value` read, kept when it is an object, an array
/// or a string.
fn value_gate(text: &str) -> bool {
    let opens = matches!(
        text.trim_start().as_bytes().first(),
        Some(b'{' | b'[' | b'"')
    );
    opens
        && serde_json::from_str::<serde_json::Value>(text)
            .is_ok_and(|value| value.is_object() || value.is_array() || value.is_string())
}

fn routes_alike(text: &str) {
    assert_eq!(
        json_literal::is_document(text),
        value_gate(text),
        "{text:?}"
    );
}

#[test]
fn g1_every_edge_routes_as_the_value_read_did() {
    let token = "$serde_json::private::RawValue";
    let mut cases: Vec<String> = [
        // Shapes, and bytes after the document.
        "{}",
        "[]",
        r#""s""#,
        "1",
        "null",
        "true",
        "  {}",
        "\n[1]",
        "{} x",
        "{}}",
        "[] ",
        "{}\n",
        "[]]",
        r#""a""b""#,
        "{}\u{0}",
        "",
        " ",
        "{",
        "[1,]",
        r#"{"a":1,}"#,
        // Surrogate escapes: lone, reversed, paired, in keys and values.
        r#"["\ud800"]"#,
        r#"["\udc00"]"#,
        r#"["😀"]"#,
        r#"{"\ud800":1}"#,
        r#""\ud800""#,
        r#"["\ud800A"]"#,
        r#"["\ud800x"]"#,
        r#"["\ude00\ud83d"]"#,
        r#"["é"]"#,
        r#"["\x"]"#,
        r#"["\u12"]"#,
        // Duplicate keys.
        r#"{"a":1,"a":2}"#,
        r#"{"a":{"b":1},"a":[2]}"#,
        // Numbers at and past the edges of what parses.
        "[1e308]",
        "[1e309]",
        "[-1e400]",
        "[1e-400]",
        "[18446744073709551615]",
        "[18446744073709551616]",
        "[-9223372036854775809]",
        "[1.7976931348623157e308]",
        "[0.1e999999999999]",
        "[01]",
        "[1.]",
        "[-]",
        "[1e]",
        "[-0]",
        "[1E+2]",
        // Raw control characters inside a string, and a byte-order mark.
        "[\"a\u{1}b\"]",
        "[\"a\tb\"]",
        "\u{feff}{}",
        "\u{feff}[1]",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    // The raw-value key the parser's feature gives meaning to.
    for body in [
        r#""{}""#,
        r#""1""#,
        r#""[1""#,
        r#""\"x\"""#,
        "5",
        r#""[]""#,
        r#""{\"a\":1}""#,
    ] {
        cases.push(format!(r#"{{"{token}":{body}}}"#));
        cases.push(format!(r#"{{"{token}":{body},"b":1}}"#));
        cases.push(format!(r#"{{"b":1,"{token}":{body}}}"#));
        cases.push(format!(r#"[{{"{token}":{body}}}]"#));
        cases.push(format!(r#"{{"$serde_json::private::RawValue":{body}}}"#));
    }
    // Nesting at and past the parser's recursion limit.
    for depth in 120..=132 {
        cases.push(format!("{}{}", "[".repeat(depth), "]".repeat(depth)));
        cases.push(format!(
            "{}1{}",
            r#"{"a":"#.repeat(depth),
            "}".repeat(depth)
        ));
        cases.push(format!("{}{{}}{}", "[".repeat(depth), "]".repeat(depth)));
    }
    for case in &cases {
        routes_alike(case);
    }
}

/// Every prefix of a document holding each kind of value, so every way a
/// read can stop short routes alike.
#[test]
fn g2_every_prefix_routes_as_the_value_read_did() {
    let doc = r#" {"a":[1,-2.5e3,true,false,null,"x😀\né"],"$serde_json::private::RawValue":"{}","b":{"c":{}},"d":"\ud800"} "#;
    for end in (0..=doc.len()).filter(|&at| doc.is_char_boundary(at)) {
        routes_alike(&doc[..end]);
        routes_alike(&doc[end..]);
    }
}
