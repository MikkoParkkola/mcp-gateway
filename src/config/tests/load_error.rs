// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8375: a config load error names the key, the place and the expected
//! type, never the value. Every leak row plants a unique sentinel where a
//! secret would sit and requires it absent from what the operator is shown.

use super::*;
use crate::config::load_error::{from_figment, redact_message};
use figment::error::{Actual, Kind};

/// A 0600 `gateway.yaml` in `dir` holding `yaml`.
fn config_file(dir: &std::path::Path, yaml: &str) -> std::path::PathBuf {
    let path = dir.join("gateway.yaml");
    write_owner_only(&path, yaml).expect("write config");
    path
}

/// The error text `serve`'s loader and the tolerant loader report for `yaml`.
fn load_errors(yaml: &str) -> [String; 2] {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = config_file(dir.path(), yaml);
    let tolerant = Config::load(Some(&path)).expect_err("the tolerant loader refuses");
    let serving = Config::load_evaluated(Some(&path)).expect_err("serve's loader refuses");
    [tolerant.to_string(), serving.to_string()]
}

fn assert_free_of(texts: &[String], sentinel: &str) {
    for text in texts {
        assert!(!text.contains(sentinel), "the value leaked: {text}");
    }
}

/// CFGLEAK.2, type mismatch (docsfix probe 1): a string where a number goes.
#[test]
fn a_type_mismatch_names_the_key_and_type_not_the_value() {
    let sentinel = "cfgleak-sentinel-r1";
    let texts = load_errors(&format!("server:\n  port: {sentinel}\n"));
    assert_free_of(&texts, sentinel);
    for text in &texts {
        assert!(
            text.contains("server.port") && text.contains("u16"),
            "{text}"
        );
    }
}

/// CFGLEAK.2, tagged scalar (docsfix probe 2): YAML itself refuses the value,
/// and `serde_yaml`'s message quotes it.
#[test]
fn a_tagged_scalar_names_the_key_and_place_not_the_value() {
    let sentinel = "cfgleak-sentinel-r2";
    let texts = load_errors(&format!("auth:\n  bearer_token: !!int {sentinel}\n"));
    assert_free_of(&texts, sentinel);
    for text in &texts {
        assert!(
            text.contains("auth.bearer_token")
                && text.contains("line ")
                && text.contains("column "),
            "{text}"
        );
    }
}

/// CFGLEAK.2 through the env overlay: an env value of the wrong type is a
/// structured error whose actual value figment would print.
#[test]
fn an_env_override_of_the_wrong_type_does_not_print_its_value() {
    let sentinel = "cfgleak-sentinel-r3";
    let dir = tempfile::tempdir().expect("tempdir");
    let env = dir.path().join("leak.env");
    write_owner_only(&env, format!("MCP_GATEWAY_SERVER__PORT={sentinel}\n")).expect("env file");
    let path = config_file(
        dir.path(),
        &format!("env_files:\n  - '{}'\n", env.display()),
    );

    let texts = [
        Config::load(Some(&path)).expect_err("refused").to_string(),
        Config::load_evaluated(Some(&path))
            .expect_err("refused")
            .to_string(),
    ];
    assert_free_of(&texts, sentinel);
    for text in &texts {
        assert!(text.contains("server.port"), "{text}");
    }
}

/// CFGLEAK.2, the write path: a comment-keeping write proves its edited text
/// loads through `from_file_text`.
#[test]
fn a_write_path_load_does_not_print_the_value() {
    let sentinel = "cfgleak-sentinel-r5";
    let text = Config::from_file_text(&format!("server:\n  port: {sentinel}\n"))
        .expect_err("refused")
        .to_string();
    assert_free_of(std::slice::from_ref(&text), sentinel);
    assert!(text.contains("server.port"), "{text}");
}

/// CFGLEAK.2, a deserializer of the gateway's own: a bare `known_agents`
/// entry was quoted three times in its refusal.
#[test]
fn a_bare_known_agent_does_not_print_the_entry() {
    let sentinel = "cfgleak-sentinel-r15";
    let texts = load_errors(&format!(
        "security:\n  agent_identity:\n    known_agents: [{sentinel}]\n"
    ));
    assert_free_of(&texts, sentinel);
    for text in &texts {
        assert!(text.contains("known_agents"), "{text}");
    }
}

/// CFGLEAK.3: a YAML syntax error has no value to hide and keeps its place.
#[test]
fn a_syntax_error_keeps_its_line_and_column() {
    for text in load_errors("auth:\n  bearer_token: \"unterminated\n") {
        assert!(
            text.contains("line ") && text.contains("column ") && text.contains("gateway.yaml"),
            "{text}"
        );
    }
}

/// CFGLEAK.3: a wrong collection type names the key and the type it found.
#[test]
fn a_wrong_collection_type_keeps_its_key_and_type() {
    let yaml = "auth:\n  enabled: true\n  api_keys:\n    - name: a\n      key_sha256: [1, 2]\n";
    for text in load_errors(yaml) {
        assert!(
            text.contains("auth.api_keys.0.key_sha256") && text.contains("sequence"),
            "{text}"
        );
    }
}

/// CFGLEAK.2, a duration field: the parser's own message quoted the text.
#[test]
fn a_bad_duration_does_not_print_its_text() {
    let sentinel = "cfgleak-sentinel-r11";
    let texts = load_errors(&format!("meta_mcp:\n  cache_ttl: {sentinel}\n"));
    assert_free_of(&texts, sentinel);
    for text in &texts {
        assert!(text.contains("meta_mcp.cache_ttl"), "{text}");
    }
}

/// CFGLEAK.2, an over-long duration in each spelling: the refusal printed the
/// number or the text it refused.
#[test]
fn an_over_long_duration_does_not_print_its_value() {
    for (yaml, sentinel) in [
        ("meta_mcp:\n  cache_ttl: 900000h\n", "900000"),
        (
            "auth:\n  dashboard_session:\n    idle_timeout_secs: 3155760001\n",
            "3155760001",
        ),
        ("tasks:\n  default_ttl_ms: 3155760000001\n", "3155760000001"),
    ] {
        let texts = load_errors(yaml);
        assert_free_of(&texts, sentinel);
        for text in &texts {
            assert!(text.contains("100 years"), "{text}");
        }
    }
}

/// CFGLEAK.1, the rule itself on a chain of two errors. The embedded value
/// carries a `, expected ` of its own with the sentinel after it, so a cut at
/// the first delimiter leaks.
#[test]
fn every_error_in_a_chain_is_redacted() {
    let sentinel = "cfgleak-sentinel-r8";
    let structured = figment::Error::from(Kind::InvalidValue(
        Actual::Str(sentinel.into()),
        "an integer".into(),
    ));
    let message = figment::Error::from(format!(
        "x: invalid value: string \"x, expected {sentinel}\", expected an integer at line 1 column 4"
    ));
    let text = from_figment(structured.chain(message)).to_string();
    assert_free_of(std::slice::from_ref(&text), sentinel);
    assert_eq!(
        text.lines()
            .filter(|line| line.contains("expected an integer"))
            .count(),
        2,
        "both errors in the chain must still be reported: {text}"
    );
    assert_eq!(
        redact_message(&format!(
            "x: invalid value: string \"x, expected {sentinel}\", expected an integer at line 1 column 4"
        )),
        "x: invalid value: string, expected an integer at line 1 column 4"
    );
}

/// CFGLEAK.1, every structured kind that carries a value.
#[test]
fn every_value_carrying_kind_is_redacted() {
    let s = "cfgleak-sentinel-r13";
    let kinds = [
        Kind::InvalidType(Actual::Str(s.into()), "u16".into()),
        Kind::InvalidType(Actual::Signed(-31_337_013), "a string".into()),
        Kind::InvalidValue(Actual::Bytes(s.as_bytes().to_vec()), "a string".into()),
        Kind::InvalidValue(Actual::Unsigned(31_337_013), "a port".into()),
        Kind::InvalidValue(Actual::Other(s.into()), "a port".into()),
        Kind::Unsupported(Actual::Str(s.into())),
        Kind::UnsupportedKey(Actual::Str(s.into()), "a string".into()),
        Kind::UnknownVariant(s.into(), &["a", "b"]),
        Kind::ISizeOutOfRange(-31_337_013),
        Kind::USizeOutOfRange(31_337_013),
    ];
    for kind in kinds {
        let shown = kind.to_string();
        let text = from_figment(figment::Error::from(kind)).to_string();
        for leak in [s, "31337013", "99, 102"] {
            assert!(!text.contains(leak), "{shown} became {text}");
        }
    }
}

/// CFGLEAK.1, the edges of serde's message formats.
#[test]
fn message_edges_drop_the_value() {
    let s = "cfgleak-sentinel-r14";
    for (message, redacted) in [
        (
            format!("x: unknown variant `{s}`, expected `a` or `b`"),
            "x: unknown variant, expected `a` or `b`".to_owned(),
        ),
        (
            format!("x: unknown variant `{s}`, there are no variants"),
            "x: unknown variant".to_owned(),
        ),
        (
            format!("invalid type: {s}, expected a string"),
            "invalid type: a value, expected a string".to_owned(),
        ),
        (
            format!("invalid type: {s}'x, expected a string"),
            "invalid type: a value, expected a string".to_owned(),
        ),
        (
            format!(
                "x: invalid value: string \"{s} invalid type: q, expected r\", expected an integer at line 1 column 4"
            ),
            "x: invalid value: string, expected an integer at line 1 column 4".to_owned(),
        ),
        (
            "found unexpected end of stream at line 4 column 1".to_owned(),
            "found unexpected end of stream at line 4 column 1".to_owned(),
        ),
    ] {
        assert_eq!(redact_message(&message), redacted);
    }
}

/// No config extract formats a raw error: every one goes through
/// `load_error::from_figment`.
#[test]
fn no_config_site_formats_a_raw_figment_error() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/config");
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read src/config") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let shown = path.to_string_lossy();
            if !shown.ends_with(".rs") || shown.contains("test") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read source");
            for (n, line) in text.lines().enumerate() {
                assert!(
                    !(line.contains("Error::Config(") && line.contains(".to_string())")),
                    "{}:{}: {line}",
                    path.display(),
                    n + 1
                );
            }
        }
    }
}
