// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8425 B3, gate G2: no YAML error from the adapter prints the value that caused it (CWE-532).

#[path = "common/yaml.rs"]
mod yaml;

use std::fmt::Write as _;

const SENTINEL: &str = "MIK8425-SENTINEL-7f3a";
const NUMBER: &str = "424242424242";

fn assert_redacted(what: &str, err: &yaml::Error, secret: &str, reason: &str) {
    let display = err.to_string();
    let debug = format!("{err:?}");
    assert!(
        !display.contains(secret),
        "{what}: Display prints the value: {display:?}"
    );
    assert!(
        !debug.contains(secret),
        "{what}: Debug prints the value: {debug:?}"
    );
    assert!(
        display.contains(reason),
        "{what}: refused for the wrong reason: {display:?}, expected {reason:?}"
    );
    assert!(
        std::error::Error::source(err).is_none(),
        "{what}: source() must be None"
    );
}

#[derive(serde::Deserialize)]
struct Port {
    port: u16,
}

#[derive(serde::Deserialize)]
struct Small {
    n: u8,
}

#[derive(serde::Deserialize)]
struct Flag {
    on: bool,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum Mode {
    Fast,
    Slow,
}

#[derive(serde::Deserialize)]
struct HasMode {
    mode: Mode,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum Agent {
    Exact { source: String, id: String },
}

#[derive(serde::Deserialize)]
struct HasAgent {
    agent: Agent,
}

#[test]
fn a_type_error_does_not_print_the_value() {
    let text = format!("port: {SENTINEL}\n");
    let err = match yaml::from_str::<Port>(&text) {
        Ok(v) => panic!("accepted; expected a refusal for {text:?}, got {}", v.port),
        Err(e) => e,
    };
    assert_redacted("type error", &err, SENTINEL, "port: invalid type");
    let control = yaml::from_str::<Port>("port: 8080\n").expect("control loads");
    assert_eq!(control.port, 8080);
}

#[test]
fn an_out_of_range_number_does_not_print_it() {
    let text = format!("n: {NUMBER}\n");
    let err = match yaml::from_str::<Small>(&text) {
        Ok(v) => panic!("accepted; expected a refusal for {text:?}, got {}", v.n),
        Err(e) => e,
    };
    assert_redacted("out-of-range number", &err, NUMBER, "n: invalid value");
    let control = yaml::from_str::<Small>("n: 7\n").expect("control loads");
    assert_eq!(control.n, 7);
}

#[test]
fn a_number_of_the_wrong_type_does_not_print_it() {
    let text = format!("on: {NUMBER}\n");
    let err = match yaml::from_str::<Flag>(&text) {
        Ok(v) => panic!("accepted; expected a refusal for {text:?}, got {}", v.on),
        Err(e) => e,
    };
    assert_redacted(
        "wrong-type number",
        &err,
        NUMBER,
        "on: invalid type: integer",
    );
    let control = yaml::from_str::<Flag>("on: true\n").expect("control loads");
    assert!(control.on);
}

#[test]
fn a_bad_variant_does_not_print_it() {
    let text = format!("mode: {SENTINEL}\n");
    let Err(err) = yaml::from_str::<HasMode>(&text) else {
        panic!("accepted; expected a refusal for {text:?}");
    };
    assert_redacted("bad variant", &err, SENTINEL, "mode: unknown variant");
    let control = yaml::from_str::<HasMode>("mode: fast\n").expect("control loads");
    match control.mode {
        Mode::Fast => {}
        Mode::Slow => panic!("control is fast"),
    }
    let slow = yaml::from_str::<HasMode>("mode: slow\n").expect("slow control loads");
    match slow.mode {
        Mode::Slow => {}
        Mode::Fast => panic!("slow control is slow"),
    }
}

#[test]
fn a_tagged_scalar_does_not_print_it() {
    let text = format!("agent: !exact {SENTINEL}\n");
    let Err(err) = yaml::from_str::<HasAgent>(&text) else {
        panic!("accepted; expected a refusal for {text:?}");
    };
    assert_redacted("tagged scalar", &err, SENTINEL, "agent: invalid type");
    let control =
        yaml::from_str::<HasAgent>("agent: !exact {source: a, id: b}\n").expect("control loads");
    match control.agent {
        Agent::Exact { source, id } => {
            assert_eq!(source, "a");
            assert_eq!(id, "b");
        }
    }
}

#[test]
fn a_syntax_error_does_not_print_it() {
    let text = format!("a: \"unterminated {SENTINEL}\n");
    let err = match yaml::from_str::<yaml::Value>(&text) {
        Ok(v) => panic!("accepted; expected a refusal for {text:?}, got {v:?}"),
        Err(e) => e,
    };
    assert_redacted(
        "syntax error",
        &err,
        SENTINEL,
        "while scanning a quoted scalar",
    );
    let control = yaml::from_str::<yaml::Value>("a: \"closed\"\n").expect("control loads");
    assert_eq!(
        control.get("a").and_then(yaml::Value::as_str),
        Some("closed")
    );
}

#[test]
fn a_duplicate_key_does_not_print_its_value() {
    let text = format!("a: {SENTINEL}\na: other\n");
    let err = match yaml::from_str::<yaml::Value>(&text) {
        Ok(v) => panic!("accepted; expected a refusal for {text:?}, got {v:?}"),
        Err(e) => e,
    };
    assert_redacted("duplicate key", &err, SENTINEL, "duplicate entry with key");
    let control = yaml::from_str::<yaml::Value>("a: one\n").expect("control loads");
    assert_eq!(control.get("a").and_then(yaml::Value::as_str), Some("one"));
}

#[test]
fn a_depth_refusal_does_not_print_it() {
    let deep = format!("{}{}{}", "[".repeat(129), SENTINEL, "]".repeat(129));
    let Err(err) = yaml::from_str::<yaml::Value>(&deep) else {
        panic!("accepted 129-deep nesting; expected a recursion refusal");
    };
    assert_redacted("depth refusal", &err, SENTINEL, "recursion limit exceeded");
    let shallow = format!("{}{}{}", "[".repeat(128), SENTINEL, "]".repeat(128));
    let control = yaml::from_str::<yaml::Value>(&shallow).expect("128-deep control loads");
    assert!(control.is_sequence());
}

fn fanout(levels: usize) -> String {
    let mut doc = format!("a0: &a0 [{}]\n", [SENTINEL; 10].join(", "));
    for level in 1..=levels {
        let prev = format!("*a{}", level - 1);
        let items = [prev.as_str(); 10].join(", ");
        writeln!(doc, "a{level}: &a{level} [{items}]").expect("fanout builds its fixture");
    }
    doc
}

#[test]
fn an_alias_bomb_refusal_does_not_print_it() {
    let bad = fanout(4);
    let Err(err) = yaml::from_str::<yaml::Value>(&bad) else {
        panic!("accepted a level-4 fan-out; expected a repetition refusal");
    };
    assert_redacted("alias bomb", &err, SENTINEL, "repetition limit exceeded");
    let good = fanout(3);
    let control = yaml::from_str::<yaml::Value>(&good).expect("level-3 control loads");
    assert!(control.is_mapping());
}

#[test]
fn every_reader_redacts() {
    // Typed readers refuse the type error. Untyped readers (`from_str_loose`,
    // `documents`) accept any value by design, so they cannot refuse it; they
    // are proven with a syntax error carrying the same sentinel instead, per
    // the plan's "every function that can produce it".
    let typed_text = format!("port: {SENTINEL}\n");
    let tree = yaml::from_str::<yaml::Value>(&typed_text).expect("tree parses");
    let err = match yaml::from_value::<Port>(tree) {
        Ok(v) => panic!(
            "accepted; expected a refusal for {typed_text:?}, got {}",
            v.port
        ),
        Err(e) => e,
    };
    assert_redacted("from_value", &err, SENTINEL, "invalid type");

    // Untyped readers accept the typed value (no refusal, hence nothing to
    // leak there); the redaction proof below uses a refusal they can produce.
    let loose_typed = yaml::from_str_loose(&typed_text).expect("loose accepts any value");
    assert_eq!(
        serde_json::to_value(&loose_typed).expect("a Dict serializes"),
        serde_json::json!({"port": SENTINEL})
    );
    let typed_docs: Vec<_> = yaml::documents(&typed_text).collect();
    assert_eq!(typed_docs.len(), 1);
    assert!(typed_docs[0].is_ok());

    let syntax_text = format!("a: \"unterminated {SENTINEL}\n");
    let Err(err) = yaml::from_str_loose(&syntax_text) else {
        panic!("loose reader accepted an unterminated scalar");
    };
    assert_redacted(
        "from_str_loose",
        &err,
        SENTINEL,
        "while scanning a quoted scalar",
    );

    let Some(err) = yaml::documents(&syntax_text).find_map(Result::err) else {
        panic!("documents accepted an unterminated scalar; expected a refusal");
    };
    assert_redacted(
        "documents",
        &err,
        SENTINEL,
        "while scanning a quoted scalar",
    );

    let control = yaml::from_str::<Port>("port: 8080\n").expect("typed control loads");
    assert_eq!(control.port, 8080);
    let loose = yaml::from_str_loose("a: \"closed\"\n").expect("loose control loads");
    assert_eq!(
        serde_json::to_value(&loose).expect("a Dict serializes"),
        serde_json::json!({"a": "closed"})
    );
    let docs: Vec<_> = yaml::documents("a: \"closed\"\n").collect();
    assert_eq!(docs.len(), 1);
    assert!(docs[0].is_ok());
}

#[derive(serde::Serialize)]
struct Wait {
    #[serde(with = "mcp_gateway::config::humantime_serde")]
    d: std::time::Duration,
}

#[derive(serde::Deserialize)]
struct Timeout {
    #[serde(with = "mcp_gateway::config::humantime_serde")]
    timeout: std::time::Duration,
}

#[test]
fn a_bad_duration_read_does_not_print_it() {
    let text = format!("timeout: {SENTINEL}\n");
    let Err(err) = yaml::from_str::<Timeout>(&text) else {
        panic!("accepted; expected a refusal for {text:?}");
    };
    assert_redacted("bad duration", &err, SENTINEL, "invalid duration");
    let control = yaml::from_str::<Timeout>("timeout: 30s\n").expect("control loads");
    assert_eq!(control.timeout, std::time::Duration::from_secs(30));
}

#[test]
fn the_location_is_kept() {
    let Err(err) = yaml::from_str::<Port>("port: abc\n") else {
        panic!("accepted; expected a refusal for port: abc");
    };
    let Some(loc) = err.location() else {
        panic!("location is None");
    };
    assert_eq!(loc.line(), 1);
    assert_eq!(loc.column(), 7);
    let display = err.to_string();
    assert!(
        display.ends_with("at line 1 column 7"),
        "location lost: {display:?}"
    );
    assert!(
        display.contains(&format!("at line {} column {}", loc.line(), loc.column())),
        "location lost: {display:?}"
    );
}

#[test]
fn a_too_long_duration_write_does_not_print_its_seconds() {
    let w = Wait {
        d: std::time::Duration::from_secs(424_242_424_242 * 10),
    };
    let err = match yaml::to_string(&w) {
        Ok(s) => panic!("accepted a too-long duration; wrote {s:?}"),
        Err(e) => e,
    };
    let display = err.to_string();
    let debug = format!("{err:?}");
    assert!(
        !display.contains("4242424242420"),
        "Display prints the seconds: {display:?}"
    );
    assert!(
        !debug.contains("4242424242420"),
        "Debug prints the seconds: {debug:?}"
    );
    assert!(
        display.contains("this duration is longer than 100 years"),
        "wrong reason: {display:?}"
    );
    let Err(value_err) = yaml::to_value(&w) else {
        panic!("accepted a too-long duration via to_value");
    };
    let value_display = value_err.to_string();
    let value_debug = format!("{value_err:?}");
    assert!(
        !value_display.contains("4242424242420"),
        "Display prints the seconds: {value_display:?}"
    );
    assert!(
        !value_debug.contains("4242424242420"),
        "Debug prints the seconds: {value_debug:?}"
    );
    assert!(
        value_display.contains("this duration is longer than 100 years"),
        "wrong reason: {value_display:?}"
    );
    let ok = Wait {
        d: std::time::Duration::from_secs(30),
    };
    let text = yaml::to_string(&ok).expect("control writes");
    assert!(text.contains("30s"), "control writes 30s: {text:?}");
}

fn collect_rs(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let entries = std::fs::read_dir(dir).expect("test reads src");
    for entry in entries {
        let entry = entry.expect("test reads a dir entry");
        let path = entry.path();
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().is_some_and(|x| x == "rs") {
            out.push(path);
        }
    }
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn normal_string_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i = start + 1;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 1;
            if i < bytes.len() {
                i += 1;
            } else {
                return None;
            }
        } else if bytes[i] == b'"' {
            return Some(i + 1);
        } else {
            i += 1;
        }
    }
    None
}

fn raw_open_hashes(bytes: &[u8], start: usize) -> Option<usize> {
    if bytes.get(start) != Some(&b'r') {
        return None;
    }
    let mut i = start + 1;
    let mut hashes = 0usize;
    while i < bytes.len() && bytes[i] == b'#' {
        hashes += 1;
        i += 1;
    }
    if i < bytes.len() && bytes[i] == b'"' {
        Some(hashes)
    } else {
        None
    }
}

fn raw_string_end(bytes: &[u8], start: usize, hashes: usize) -> Option<usize> {
    let mut i = start + 1 + hashes + 1;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            let mut j = i + 1;
            let mut count = 0usize;
            while count < hashes && j < bytes.len() && bytes[j] == b'#' {
                count += 1;
                j += 1;
            }
            if count == hashes {
                return Some(j);
            }
        }
        i += 1;
    }
    None
}

fn char_literal_end(bytes: &[u8], start: usize) -> Option<usize> {
    if bytes.get(start) != Some(&b'\'') {
        return None;
    }
    if bytes.get(start + 1) != Some(&b'\\') {
        if bytes.get(start + 2) == Some(&b'\'') {
            return Some(start + 3);
        }
        return None;
    }
    if bytes.get(start + 2) == Some(&b'u') {
        let mut i = start + 3;
        while i < bytes.len() {
            if bytes[i] == b'\'' {
                return Some(i + 1);
            }
            i += 1;
        }
        return None;
    }
    if bytes.get(start + 2) == Some(&b'x') {
        if bytes.get(start + 5) == Some(&b'\'') {
            return Some(start + 6);
        }
        return None;
    }
    if bytes.get(start + 3) == Some(&b'\'') {
        return Some(start + 4);
    }
    None
}

fn raw_skip(bytes: &[u8], i: usize) -> Option<usize> {
    if bytes.get(i) != Some(&b'r') {
        return None;
    }
    if i > 0 && is_ident_byte(bytes[i - 1]) {
        return None;
    }
    let hashes = raw_open_hashes(bytes, i)?;
    raw_string_end(bytes, i, hashes)
}

fn normal_skip(bytes: &[u8], i: usize) -> Option<usize> {
    if bytes.get(i) != Some(&b'"') {
        return None;
    }
    normal_string_end(bytes, i)
}

fn char_skip(bytes: &[u8], i: usize) -> Option<usize> {
    if bytes.get(i) != Some(&b'\'') {
        return None;
    }
    char_literal_end(bytes, i)
}

fn matching_paren(text: &str, open: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    if bytes.get(open) != Some(&b'(') {
        return None;
    }
    let mut depth = 0usize;
    let mut i = open;
    while i < bytes.len() {
        if let Some(end) = raw_skip(bytes, i) {
            i = end;
            continue;
        }
        if let Some(end) = normal_skip(bytes, i) {
            i = end;
            continue;
        }
        if let Some(end) = char_skip(bytes, i) {
            i = end;
            continue;
        }
        if bytes[i] == b'(' {
            depth += 1;
        } else if bytes[i] == b')' {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn custom_argument(text: &str, at: usize) -> Option<&str> {
    let open = at + "::custom".len();
    if text.as_bytes().get(open) != Some(&b'(') {
        return None;
    }
    let close = matching_paren(text, open)?;
    Some(&text[open + 1..close])
}

fn has_single_brace(content: &str) -> bool {
    let bytes = content.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'{' {
                i += 2;
            } else {
                return true;
            }
        } else {
            i += 1;
        }
    }
    false
}

fn first_literal_content(arg: &str, paren: usize) -> Option<&str> {
    let bytes = arg.as_bytes();
    let mut i = paren + 1;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    if let Some(hashes) = raw_open_hashes(bytes, i) {
        let end = raw_string_end(bytes, i, hashes)?;
        let content_start = i + 1 + hashes + 1;
        let content_end = end - 1 - hashes;
        return Some(&arg[content_start..content_end]);
    }
    if bytes[i] == b'"' {
        let end = normal_string_end(bytes, i)?;
        return Some(&arg[i + 1..end - 1]);
    }
    None
}

fn is_single_plain_string_literal(inner: &str) -> bool {
    let trimmed = inner.trim();
    let core = trimmed.strip_suffix(',').map_or(trimmed, str::trim);
    if core.is_empty() {
        return false;
    }
    let bytes = core.as_bytes();
    if let Some(hashes) = raw_open_hashes(bytes, 0) {
        let Some(end) = raw_string_end(bytes, 0, hashes) else {
            return false;
        };
        return core[end..].trim().is_empty();
    }
    if bytes[0] == b'"' {
        let Some(end) = normal_string_end(bytes, 0) else {
            return false;
        };
        return core[end..].trim().is_empty();
    }
    false
}

fn macro_paren(bytes: &[u8], i: usize, name: &str) -> Option<usize> {
    let name_bytes = name.as_bytes();
    if bytes.len() < i + name_bytes.len() + 1 {
        return None;
    }
    if &bytes[i..i + name_bytes.len()] != name_bytes {
        return None;
    }
    if i > 0 && is_ident_byte(bytes[i - 1]) {
        return None;
    }
    if bytes[i + name_bytes.len()] != b'!' {
        return None;
    }
    let mut j = i + name_bytes.len() + 1;
    while j < bytes.len() && bytes[j].is_ascii_whitespace() {
        j += 1;
    }
    if j < bytes.len() && bytes[j] == b'(' {
        Some(j)
    } else {
        None
    }
}

fn call_paren(bytes: &[u8], i: usize, name: &str) -> Option<usize> {
    let name_bytes = name.as_bytes();
    if bytes.len() < i + name_bytes.len() + 1 {
        return None;
    }
    if &bytes[i..i + name_bytes.len()] != name_bytes {
        return None;
    }
    if i > 0 && is_ident_byte(bytes[i - 1]) {
        return None;
    }
    let mut j = i + name_bytes.len();
    while j < bytes.len() && bytes[j].is_ascii_whitespace() {
        j += 1;
    }
    if j < bytes.len() && bytes[j] == b'(' {
        Some(j)
    } else {
        None
    }
}

fn formats_a_value(arg: &str) -> bool {
    let bytes = arg.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if let Some(end) = raw_skip(bytes, i) {
            i = end;
            continue;
        }
        if let Some(end) = normal_skip(bytes, i) {
            i = end;
            continue;
        }
        if let Some(end) = char_skip(bytes, i) {
            i = end;
            continue;
        }
        if let Some(paren) =
            macro_paren(bytes, i, "format_args").or_else(|| macro_paren(bytes, i, "format"))
        {
            if let Some(content) = first_literal_content(arg, paren)
                && has_single_brace(content)
            {
                return true;
            }
        } else if let Some(paren) = call_paren(bytes, i, "too_long") {
            let Some(close) = matching_paren(arg, paren) else {
                return true;
            };
            let inner = &arg[paren + 1..close];
            if !is_single_plain_string_literal(inner) {
                return true;
            }
        }
        i += 1;
    }
    false
}

#[test]
fn custom_errors_never_format_a_value() {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    collect_rs(&manifest.join("src"), &mut files);
    let mut hits = Vec::new();
    for path in &files {
        let text = std::fs::read_to_string(path).expect("test reads src files");
        for (at, _) in text.match_indices("::custom(") {
            if text[..at].ends_with("Policy") {
                continue;
            }
            let Some(arg) = custom_argument(&text, at) else {
                panic!("unbalanced ::custom( in {}", path.display());
            };
            if formats_a_value(arg) {
                let line = text[..at].matches('\n').count() + 1;
                let rel = path
                    .strip_prefix(&manifest)
                    .map_or_else(|_| path.clone(), std::path::Path::to_path_buf);
                hits.push(format!("{}:{}", rel.display(), line));
            }
        }
    }
    assert!(hits.is_empty(), "custom errors formatting values: {hits:?}");
}

#[test]
fn the_guard_catches_the_tricky_forms() {
    for text in [
        r#"Error::custom(format!("bad \"{}\"", x))"#,
        r#"Error::custom(format! ("{x}"))"#,
        r##"Error::custom(format!(r#"v {}"#, x))"##,
        r#"Error::custom(too_long(&format!("{}s", n)))"#,
        "Error::custom(too_long(&name))",
        r#"Error::custom(format!("a ) b {}", x))"#,
    ] {
        let Some(at) = text.find("::custom(") else {
            panic!("fixture lacks ::custom(: {text:?}");
        };
        let Some(arg) = custom_argument(text, at) else {
            panic!("unbalanced ::custom( in fixture: {text:?}");
        };
        assert!(
            formats_a_value(arg),
            "guard missed a value: {text:?} -> {arg:?}"
        );
    }
    for text in [
        r#"Error::custom("fixed text")"#,
        r#"Error::custom(too_long("this duration"))"#,
        r#"Error::custom(format!("{{literal}}"))"#,
        r#"Error::custom("a ( b")"#,
    ] {
        let Some(at) = text.find("::custom(") else {
            panic!("fixture lacks ::custom(: {text:?}");
        };
        let Some(arg) = custom_argument(text, at) else {
            panic!("unbalanced ::custom( in fixture: {text:?}");
        };
        assert!(
            !formats_a_value(arg),
            "guard flagged a fixed string: {text:?} -> {arg:?}"
        );
    }
}
