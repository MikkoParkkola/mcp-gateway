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
    assert_redacted("syntax error", &err, SENTINEL, "unclosed quote");
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
    assert_redacted(
        "depth refusal",
        &err,
        SENTINEL,
        "nesting deeper than 128 levels",
    );
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
    assert_redacted("from_str_loose", &err, SENTINEL, "unclosed quote");

    let Some(err) = yaml::documents(&syntax_text).find_map(Result::err) else {
        panic!("documents accepted an unterminated scalar; expected a refusal");
    };
    assert_redacted("documents", &err, SENTINEL, "unclosed quote");

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
    assert!(
        !display.contains("abc"),
        "location pin prints the scalar: {display:?}"
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
    assert_redacted(
        "to_string",
        &err,
        "4242424242420",
        "this duration is longer than 100 years",
    );
    let Err(value_err) = yaml::to_value(&w) else {
        panic!("accepted a too-long duration via to_value");
    };
    assert_redacted(
        "to_value",
        &value_err,
        "4242424242420",
        "this duration is longer than 100 years",
    );
    let ok = Wait {
        d: std::time::Duration::from_secs(30),
    };
    let text = yaml::to_string(&ok).expect("control writes");
    assert!(text.contains("30s"), "control writes 30s: {text:?}");
    let tree = yaml::to_value(&ok).expect("control value writes");
    assert_eq!(tree.get("d").and_then(yaml::Value::as_str), Some("30s"));
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

/// Whether `text` holds a format placeholder: a `{` not doubled as `{{`.
fn has_placeholder(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            if bytes.get(i + 1) != Some(&b'{') {
                return true;
            }
            i += 1;
        }
        i += 1;
    }
    false
}

/// Whether `func` calls a `...::custom` error constructor.
fn is_custom_call(func: &syn::Expr) -> bool {
    let syn::Expr::Path(called) = func else {
        return false;
    };
    let mut segments = called.path.segments.iter().rev();
    let Some(last) = segments.next() else {
        return false;
    };
    if last.ident != "custom" {
        return false;
    }
    // `Policy::custom` takes a closure, not a message (reqwest redirect).
    segments.next().is_none_or(|prev| prev.ident != "Policy")
}

/// Whether a `format!`/`format_args!` macro formats a value into its message:
/// its first argument is a string literal holding a placeholder. Tokens that
/// do not parse flag too (fail closed).
fn macro_formats_a_value(mac: &syn::Macro) -> bool {
    let is_format = mac
        .path
        .segments
        .last()
        .is_some_and(|segment| segment.ident == "format" || segment.ident == "format_args");
    if !is_format {
        return false;
    }
    let parsed = syn::parse::Parser::parse2(
        syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated,
        mac.tokens.clone(),
    );
    let Ok(args) = parsed else {
        return true;
    };
    match args.first() {
        Some(syn::Expr::Lit(literal)) => match &literal.lit {
            syn::Lit::Str(text) => has_placeholder(&text.value()),
            _ => true,
        },
        _ => true,
    }
}

/// Whether a `too_long(...)` call carries anything but one plain string literal.
fn too_long_formats_a_value(call: &syn::ExprCall) -> bool {
    let syn::Expr::Path(called) = call.func.as_ref() else {
        return false;
    };
    let is_too_long = called
        .path
        .segments
        .last()
        .is_some_and(|segment| segment.ident == "too_long");
    if !is_too_long {
        return false;
    }
    let mut args = call.args.iter();
    !matches!(
        (args.next(), args.next()),
        (Some(syn::Expr::Lit(literal)), None) if matches!(literal.lit, syn::Lit::Str(_))
    )
}

/// Flags any value formatting inside one `custom` argument, walking into
/// nested expressions (closures, blocks, method calls) to find it.
struct FormatsAValue {
    hit: bool,
}

impl<'ast> syn::visit::Visit<'ast> for FormatsAValue {
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if macro_formats_a_value(mac) {
            self.hit = true;
        }
        syn::visit::visit_macro(self, mac);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if too_long_formats_a_value(node) {
            self.hit = true;
        }
        syn::visit::visit_expr_call(self, node);
    }
}

/// The `...::custom(` calls in `file` that format a value into the message.
///
/// Covers every `...::custom(` call in `src/` parsed by syn, including
/// inside closures and nested calls. Fails closed on any `format!`/`format_args!`
/// whose format string is not a literal. Boundary: only what cannot be decided
/// statically from the parsed source is not seen: a `custom` reached through
/// a `use` alias under another name, or a call generated inside another macro's body.
///
/// One entry per hit. Spans carry no line here (`span-locations` is not
/// enabled, and the guard adds no features), so the caller reports the
/// file path only.
fn value_formatting_custom_calls(file: &syn::File) -> Vec<usize> {
    struct CustomCalls {
        hits: Vec<usize>,
    }

    impl<'ast> syn::visit::Visit<'ast> for CustomCalls {
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if is_custom_call(&node.func) {
                let mut argument = FormatsAValue { hit: false };
                for arg in &node.args {
                    syn::visit::Visit::visit_expr(&mut argument, arg);
                }
                if argument.hit {
                    // Hits name the file only: proc-macro2's `span-locations` is off,
                    // and the guard adds no features.
                    self.hits.push(0);
                }
            }
            syn::visit::visit_expr_call(self, node);
        }
    }

    let mut calls = CustomCalls { hits: Vec::new() };
    syn::visit::Visit::visit_file(&mut calls, file);
    calls.hits
}

#[test]
fn custom_errors_never_format_a_value() {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    collect_rs(&manifest.join("src"), &mut files);
    let mut hits = Vec::new();
    for path in &files {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) => panic!("cannot read {}: {error}", path.display()),
        };
        let parsed = match syn::parse_file(&text) {
            Ok(parsed) => parsed,
            Err(error) => panic!("cannot parse {}: {error}", path.display()),
        };
        let rel = path
            .strip_prefix(&manifest)
            .map_or_else(|_| path.clone(), std::path::Path::to_path_buf);
        for _hit in value_formatting_custom_calls(&parsed) {
            hits.push(rel.display().to_string());
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
        r#"Error::custom(format!(/* why */ "bad {x}"))"#,
        r#"Error::custom(format!("bad {}", /* ) */ x))"#,
        r#"Error::custom(format!("bad \x7b}", x))"#,
        r#"Error::custom(format![ "bad {}", x ])"#,
        r#"Error::custom(format!{ "bad {}", x })"#,
        r#"Error::custom(format!(concat!("bad ", "{}"), x))"#,
        "Error::custom(format!(TEMPLATE, x))",
    ] {
        let source = format!("fn f() {{ {text}; }}");
        let parsed = match syn::parse_file(&source) {
            Ok(parsed) => parsed,
            Err(error) => panic!("fixture does not parse: {text:?}: {error}"),
        };
        assert!(
            !value_formatting_custom_calls(&parsed).is_empty(),
            "guard missed a value: {text:?}"
        );
    }
    for text in [
        r#"Error::custom("fixed text")"#,
        r#"Error::custom(too_long("this duration"))"#,
        r#"Error::custom(format!("{{literal}}"))"#,
        r#"Error::custom("a ( b")"#,
    ] {
        let source = format!("fn f() {{ {text}; }}");
        let parsed = match syn::parse_file(&source) {
            Ok(parsed) => parsed,
            Err(error) => panic!("fixture does not parse: {text:?}: {error}"),
        };
        assert!(
            value_formatting_custom_calls(&parsed).is_empty(),
            "guard flagged a fixed string: {text:?}"
        );
    }
}
