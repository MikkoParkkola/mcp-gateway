// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The cheaper paths of the keyed walk against the ones they replaced: the
//! document gate reads without building a tree and must route every text as
//! the `Value` read did; the per-key cache and the crossed-only exempt check
//! must decide exactly what deciding every pair and every value decided.

use super::*;

/// A JSON `\u` escape, built at run time so no source line holds one.
fn esc(hex: &str) -> String {
    format!("{}u{hex}", '\\')
}

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
        json_valid::walkable(text) == Some(true),
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
    // Escapes: lone, reversed and paired surrogates, in keys and values, a
    // broken escape and a short one.
    let (hi, lo) = (esc("d83d"), esc("de00"));
    cases.extend([
        format!(r#"["{}"]"#, esc("d800")),
        format!(r#"["{}"]"#, esc("dc00")),
        format!(r#"["{hi}{lo}"]"#),
        format!(r#"["{lo}{hi}"]"#),
        format!(r#"{{"{}":1}}"#, esc("d800")),
        format!(r#""{}""#, esc("d800")),
        format!(r#"["{}{}"]"#, esc("d800"), esc("0041")),
        format!(r#"["{hi}x"]"#),
        format!(r#"["{}"]"#, esc("00e9")),
        format!(r#"["{}"]"#, esc("12")),
        format!(r#"["{}x"]"#, '\\'),
    ]);
    // The raw-value key the parser's feature gives meaning to, plain and
    // spelled with an escape.
    let escaped_token = format!("{}serde_json::private::RawValue", esc("0024"));
    for body in [
        r#""{}""#,
        r#""1""#,
        r#""[1""#,
        r#""\"x\"""#,
        "5",
        r#""[]""#,
        r#""{\"a\":1}""#,
    ] {
        for key in [token, escaped_token.as_str()] {
            cases.push(format!(r#"{{"{key}":{body}}}"#));
            cases.push(format!(r#"{{"{key}":{body},"b":1}}"#));
            cases.push(format!(r#"{{"b":1,"{key}":{body}}}"#));
            cases.push(format!(r#"[{{"{key}":{body}}}]"#));
        }
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

/// Every prefix and suffix of two documents holding each kind of value, one
/// that reads and one that does not, so every way a read can stop short
/// routes alike.
#[test]
fn g2_every_prefix_routes_as_the_value_read_did() {
    let text = format!(
        r#""x{}{}{}n{}""#,
        esc("d83d"),
        esc("de00"),
        '\\',
        esc("00e9")
    );
    let valid = format!(r#" {{"a":[1,-2.5e3,true,false,null,{text}],"b":{{"c":{{}}}},"d":"q"}} "#);
    let invalid = format!(
        r#" {{"a":[1,{text}],"$serde_json::private::RawValue":"{{}}","b":{{}},"d":"{}"}} "#,
        esc("d800")
    );
    assert_eq!(json_valid::walkable(&valid), Some(true), "{valid}");
    for doc in [&valid, &invalid] {
        for end in (0..=doc.len()).filter(|&at| doc.is_char_boundary(at)) {
            routes_alike(&doc[..end]);
            routes_alike(&doc[end..]);
        }
    }
}

/// The member values deciding every pair found: each key decoded and each
/// value checked, with no cache.
fn every_pair(r: &Redactor, text: &str, exempt: &dyn Fn(&str) -> bool) -> Vec<(usize, Family)> {
    let literals = json_literal::string_literals(text);
    literals
        .windows(2)
        .filter(|pair| pair[0].key && !pair[1].key)
        .filter(|pair| text[pair[0].end() + 1..pair[1].start() - 1].trim() == ":")
        .filter_map(
            |pair| match (decoded(text, &pair[0]), decoded(text, &pair[1])) {
                (Some(key), Some(value)) if !exempt(&value) => r
                    .credential_member(&key, &value)
                    .map(|family| (pair[1].start(), family)),
                _ => None,
            },
        )
        .collect()
}

/// Repeated, escaped and undecodable keys, credential-named and not, with
/// values that pass and fail: the cache keeps every decision.
#[test]
fn g3_the_key_cache_decides_as_every_pair_did() {
    let pass = "hunter2-long-enough";
    let underscore = esc("005f");
    let lone = esc("d800");
    let docs = [
        format!(
            r#"[{{"api_key":"{pass}","full_name":"o/r"}},{{"api_key":"x","full_name":"{pass}"}}]"#
        ),
        format!(
            r#"{{"password":"{pass}","password":"","PASSWORD":"{pass}","pass word":"{pass}"}}"#
        ),
        format!(
            r#"{{"api{underscore}key":"{pass}","api_key":"{pass}","{lone}":"{pass}","token":"${{TOKEN}}"}}"#
        ),
        format!(
            r#"{{"secret":"{pass}","secret":"{{{{x}}}}","openaiApiKey":"{pass}","authtoken":"{pass}"}}"#
        ),
        format!(
            r#"{{"a":{{"client_secret":"{pass}"}},"client_secret":"{pass}","b":["client_secret","{pass}"]}}"#
        ),
        format!(
            r#"{{"next_token":"{pass}","page_token":"{pass}","token":"{pass}","token" : "{pass}"}}"#
        ),
        format!(r#"{{"api_key":"{lone}","api_key":"{pass}","token":"{pass}{lone}"}}"#),
    ];
    let r = redactor();
    let exempts: [&dyn Fn(&str) -> bool; 3] =
        [&|_| false, &|v| v.starts_with("hunter"), &|v| v.len() < 5];
    for doc in &docs {
        let literals = json_literal::string_literals(doc);
        for exempt in exempts {
            let cached: Vec<(usize, Family)> = r
                .member_values(doc, &literals, exempt)
                .into_iter()
                .map(|(lit, family)| (lit.start(), family))
                .collect();
            assert_eq!(cached, every_pair(&r, doc, exempt), "{doc}");
        }
    }
}

/// Seeded random spans over a document of empty and short values: what each
/// pattern keeps, and whether it crosses an exempt value, come out the same
/// from the crossed-only exempt list as from the list of every exempt value.
#[test]
fn g4_crossed_exempt_values_decide_as_every_exempt_value_did() {
    let text = r#"{"k":"","a":"ab","":"e","b":["","cdef","e","",""],"c":"eee","d":""}"#;
    let literals = json_literal::string_literals(text);
    let exempt = |v: &str| v.is_empty() || v.contains('e');
    let every: Vec<(usize, usize)> = (literals.iter())
        .filter(|lit| !lit.key && decoded(text, lit).is_some_and(|v| exempt(&v)))
        .map(|lit| (lit.start(), lit.end()))
        .collect();
    // xorshift64: a fixed seed, so a failure reproduces.
    let mut state = 0x2545_f491_4f6c_dd1d_u64;
    let mut next = |below: usize| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        usize::try_from(state % u64::try_from(below).expect("fits")).expect("fits")
    };
    let crosses = |found: &[(usize, usize)], holes: &[(usize, usize)]| {
        (found.iter()).any(|&(start, end)| holes.iter().any(|&(a, b)| a < end && start < b))
    };
    for case in 0..3000 {
        let found_by: Vec<(usize, Vec<(usize, usize)>)> = (0..=next(3))
            .map(|idx| {
                let mut found: Vec<(usize, usize)> = (0..next(5))
                    .map(|_| {
                        let start = next(text.len());
                        (start, start + 1 + next(text.len() - start))
                    })
                    .collect();
                found.sort_unstable();
                (idx, found)
            })
            .collect();
        let crossed = exempt_crossed(text, &literals, &found_by, &exempt);
        for (_, found) in &found_by {
            assert_eq!(
                without(found, &crossed),
                without(found, &every),
                "case {case}"
            );
            assert_eq!(
                crosses(found, &crossed),
                crosses(found, &every),
                "case {case}"
            );
        }
    }
}
