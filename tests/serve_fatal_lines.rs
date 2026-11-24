// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A gateway that cannot start says why on stderr, in one escaped line, whatever its log settings: text quoted from
//! gateway.yaml never starts a line of its own there, and a fatal error is never silent, not even at
//! `--log-level off`. Driven through the built binary, because the printing is wired in `main`.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::process::Output;

/// A load error that quotes a raw line feed: an extra key under a section that refuses extra keys. Nothing but the
/// printer can keep it off a line of its own (the server-name refusal never sees this key).
const QUOTED_KEY: &str = "idempotency:\n  \"x\\nFORGED y\": 1\n";

/// The ticket's case: a server name holding a line feed.
const BAD_NAME: &str = "backends:\n  \"ok\\nFORGED x/y\":\n    command: \"true\"\n";

/// How the quoted key reads once escaped.
const ESCAPED_KEY: &str = "x\\nFORGED y";

/// The fatal message every row looks for.
const LOAD_FAILED: &str = "Failed to load configuration";

#[derive(Clone, Copy)]
enum Mode {
    Stdio,
    Http,
}

/// Runs `serve` on `yaml` with only the given extra environment and arguments, and returns the outcome.
fn serve(mode: Mode, yaml: &str, env: &[(&str, &str)], extra_args: &[&str]) -> Output {
    let home = tempfile::tempdir().expect("a home");
    std::fs::write(home.path().join("version.stamp"), env!("CARGO_PKG_VERSION")).expect("stamp");
    let config = home.path().join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(&config, yaml).expect("config");
    let mut command = gateway_bin::command(home.path(), gateway_bin::Inherit::Nothing);
    command.envs(gateway_bin::checked_env(env.iter().copied()));
    command
        .arg("--config")
        .arg(&config)
        .args(extra_args)
        .arg("serve");
    if matches!(mode, Mode::Stdio) {
        command.arg("--stdio");
    }
    command
        .stdin(std::process::Stdio::null())
        .output()
        .expect("the gateway runs")
}

fn stderr_lines(out: &Output) -> Vec<String> {
    String::from_utf8_lossy(&out.stderr)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(str::to_owned)
        .collect()
}

/// The checks every row makes: the start failed, no stderr line is forged, and the fatal line appears exactly once,
/// with the quoted text escaped. Returns the stderr lines for row-specific checks.
fn one_escaped_fatal_line(out: &Output, escaped: &str) -> Vec<String> {
    let lines = stderr_lines(out);
    assert!(!out.status.success(), "the start must fail: {lines:#?}");
    assert!(
        !lines.iter().any(|line| line.starts_with("FORGED")),
        "text from gateway.yaml forged a line: {lines:#?}"
    );
    let fatal: Vec<&String> = lines
        .iter()
        .filter(|line| line.contains(LOAD_FAILED))
        .collect();
    assert_eq!(fatal.len(), 1, "the fatal line, exactly once: {lines:#?}");
    assert!(
        fatal[0].contains(escaped),
        "the fatal line should hold {escaped:?}: {lines:#?}"
    );
    lines
}

/// L1, the ticket's case end to end: a server name with a line feed, on stdio.
#[test]
fn a_server_name_with_a_line_feed_cannot_forge_a_stderr_line() {
    let out = serve(Mode::Stdio, BAD_NAME, &[], &[]);
    one_escaped_fatal_line(&out, "ok\\nFORGED x/y");
}

/// L1b, the printing route alone: a load error that quotes a raw line feed, on stdio.
#[test]
fn a_quoted_line_feed_in_a_stdio_load_error_is_escaped() {
    let out = serve(Mode::Stdio, QUOTED_KEY, &[], &[]);
    let lines = one_escaped_fatal_line(&out, ESCAPED_KEY);
    assert!(
        lines.iter().any(|line| line.contains("unknown field")),
        "the load error should be serde's extra-key refusal: {lines:#?}"
    );
}

/// F1: at `--log-level off` a stdio start that fails still prints its reason, once and escaped, and nothing else.
#[test]
fn a_fatal_stdio_error_is_printed_at_log_level_off() {
    let out = serve(Mode::Stdio, QUOTED_KEY, &[], &["--log-level", "off"]);
    let lines = one_escaped_fatal_line(&out, ESCAPED_KEY);
    assert_eq!(lines.len(), 1, "only the fatal line: {lines:#?}");
}

/// F2: the same on the HTTP path, which logged its fatal errors but went silent when logging was off.
#[test]
fn a_fatal_http_error_is_printed_at_log_level_off() {
    let out = serve(Mode::Http, QUOTED_KEY, &[], &["--log-level", "off"]);
    let lines = one_escaped_fatal_line(&out, ESCAPED_KEY);
    assert_eq!(lines.len(), 1, "only the fatal line: {lines:#?}");
}

/// F3: with logging on, the fatal line is the log's own line, written once.
#[test]
fn a_fatal_error_is_written_once_when_logging_is_on() {
    let out = serve(Mode::Stdio, QUOTED_KEY, &[], &[]);
    one_escaped_fatal_line(&out, ESCAPED_KEY);
}

/// F3j: the same in the JSON log format: one JSON line, no plain-text copy beside it.
#[test]
fn a_fatal_error_is_one_json_line_in_the_json_format() {
    let out = serve(Mode::Stdio, QUOTED_KEY, &[], &["--log-format", "json"]);
    let lines = stderr_lines(&out);
    assert!(!out.status.success(), "the start must fail: {lines:#?}");
    let fatal: Vec<&String> = lines
        .iter()
        .filter(|line| line.contains(LOAD_FAILED))
        .collect();
    assert_eq!(fatal.len(), 1, "the fatal line, exactly once: {lines:#?}");
    let parsed: serde_json::Value = serde_json::from_str(fatal[0])
        .unwrap_or_else(|e| panic!("not a JSON line ({e}): {}", fatal[0]));
    assert_eq!(parsed["level"], "ERROR", "{parsed}");
    assert!(
        !lines.iter().any(|line| line.starts_with("FORGED")),
        "a forged line: {lines:#?}"
    );
}

/// F4: `RUST_LOG=off` with no `--log-level` silences the log through the environment filter, and the fatal line is
/// still printed.
#[test]
fn a_fatal_error_is_printed_when_rust_log_is_off() {
    let out = serve(Mode::Stdio, QUOTED_KEY, &[("RUST_LOG", "off")], &[]);
    let lines = one_escaped_fatal_line(&out, ESCAPED_KEY);
    assert_eq!(lines.len(), 1, "only the fatal line: {lines:#?}");
}

/// F5: a filter that enables the gateway's errors only for events carrying a field the fatal event lacks. The event
/// is filtered out, so the fallback must print it. A probe that ignored the event's fields would see the directive
/// match, answer "enabled", and print nothing.
#[test]
fn a_fatal_error_filtered_by_a_field_directive_is_still_printed() {
    let filter = "off,mcp_gateway[{other_field}]=error";
    let out = serve(Mode::Stdio, QUOTED_KEY, &[("RUST_LOG", filter)], &[]);
    one_escaped_fatal_line(&out, ESCAPED_KEY);
}

/// F6: the opposite filter: the gateway's errors are on, and the field directive switches off only events with a
/// field the fatal event lacks. The event is written; a probe that ignored the fields would answer "disabled" and
/// print it a second time.
#[test]
fn a_fatal_error_enabled_beside_a_field_directive_is_written_once() {
    let filter = "error,mcp_gateway[{other_field}]=off";
    let out = serve(Mode::Stdio, QUOTED_KEY, &[("RUST_LOG", filter)], &[]);
    one_escaped_fatal_line(&out, ESCAPED_KEY);
}
