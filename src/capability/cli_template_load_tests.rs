// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7926.FIX.3: a malformed CLI argv template is refused when the
//! capability is validated, not on its first call. The rules are the call
//! path's own (`executor/cli_argv.rs`), run without parameters.

use super::{parse_capability, validate_capability};
use crate::capability::CapabilityDefinition;

/// A CLI capability whose primary provider has `args` (YAML flow list) and,
/// when given, a `stdin` template; `extra` adds providers.
fn cli_capability(args: &str, stdin: Option<&str>, extra: &str) -> CapabilityDefinition {
    let stdin = stdin.map_or_else(String::new, |s| format!("\n      stdin: '{s}'"));
    parse_capability(&format!(
        "
name: template_probe
description: probe
providers:
  primary:
    service: cli
    config:
      command: gws
      args: {args}{stdin}
{extra}"
    ))
    .expect("the definition parses; only validation may refuse it")
}

fn refused(cap: &CapabilityDefinition, needle: &str) {
    let err = validate_capability(cap).expect_err("a malformed CLI template must be refused");
    let text = err.to_string();
    assert!(text.contains(needle), "{needle:?} not named in: {text}");
}

#[test]
fn two_placeholders_in_one_element_are_refused_at_load() {
    refused(&cli_capability(r#"["--a={x}{y}"]"#, None, ""), "--a={x}{y}");
}

#[test]
fn an_unbound_parameter_before_the_separator_is_refused_at_load() {
    refused(&cli_capability(r#"["{x}"]"#, None, ""), "{x}");
}

#[test]
fn an_operand_after_the_separator_loads() {
    let cap = cli_capability(r#"["--", "{x}"]"#, None, "");
    validate_capability(&cap).expect("an operand after \"--\" is allowed");
}

#[test]
fn an_unbound_each_template_is_refused_at_load() {
    refused(
        &cli_capability(r#"[{each: files, arg: "{item}"}]"#, None, ""),
        "{item}",
    );
}

/// A conditional "--" never switches to operands at call time
/// (`build_cli_invocation`), so the load check must not either.
#[test]
fn a_conditional_separator_does_not_admit_a_later_operand() {
    refused(
        &cli_capability(r#"[{arg: "--", if: x}, "{y}"]"#, None, ""),
        "{y}",
    );
}

#[test]
fn a_malformed_conditional_template_is_refused_at_load() {
    refused(
        &cli_capability(r#"[{arg: "--a={x}{y}", if: x}]"#, None, ""),
        "--a={x}{y}",
    );
}

#[test]
fn a_json_value_with_two_placeholders_is_refused_at_load() {
    refused(
        &cli_capability(
            r#"[{json: "--params=", value: {outer: [{q: "{x}{y}"}]}}]"#,
            None,
            "",
        ),
        "{x}{y}",
    );
}

#[test]
fn a_stdin_template_with_two_placeholders_is_refused_at_load() {
    refused(&cli_capability(r#"["send"]"#, Some("{x}{y}"), ""), "{x}{y}");
}

#[test]
fn a_fallback_providers_template_is_checked_too() {
    let fallback = "  fallback:
    service: cli
    config:
      command: gws
      args: [\"--a={x}{y}\"]";
    refused(&cli_capability(r#"["ok"]"#, None, fallback), "fallback");
}

/// Registration is a public entry point of its own (`register_capability`).
#[test]
fn registration_refuses_a_malformed_cli_template() {
    let executor = std::sync::Arc::new(crate::capability::CapabilityExecutor::new());
    let backend = crate::capability::CapabilityBackend::new("test", executor);
    let err = backend
        .register_capability(cli_capability(r#"["--a={x}{y}"]"#, None, ""))
        .expect_err("registration must refuse a malformed CLI template");
    assert!(err.to_string().contains("--a={x}{y}"), "{err}");
}

/// The search index offers only what loading would accept.
#[tokio::test]
async fn the_registry_index_leaves_out_a_malformed_cli_capability() {
    let dir = tempfile::tempdir().expect("temp dir");
    std::fs::write(
        dir.path().join("broken.yaml"),
        "name: broken_cli
description: probe
providers:
  primary:
    service: cli
    config:
      command: gws
      args: [\"--a={x}{y}\"]
",
    )
    .expect("fixture written");
    let index = crate::registry::Registry::new(dir.path())
        .build_index()
        .await
        .expect("index builds");
    assert!(
        index.find("broken_cli").is_none(),
        "a capability loading would refuse must not be offered"
    );
}

/// Every shipped capability file validates, checked one file at a time: a
/// directory load or the search index would skip a refused file silently.
#[tokio::test]
async fn every_shipped_capability_file_validates() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("capabilities");
    let mut checked = 0;
    for entry in walkdir::WalkDir::new(&root)
        .into_iter()
        .filter_map(Result::ok)
    {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
            continue;
        }
        let Ok(cap) = super::parse_capability_file(path).await else {
            // Not every YAML file under capabilities/ is a definition; the
            // ones that parse are the ones loading would admit or refuse.
            continue;
        };
        validate_capability(&cap)
            .unwrap_or_else(|e| panic!("{} is refused at load: {e}", path.display()));
        checked += 1;
    }
    assert!(checked >= 35, "only {checked} shipped definitions found");
}
