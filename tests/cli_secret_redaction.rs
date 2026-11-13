// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! End-to-end redaction tests for backend inspection commands.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::path::Path;
use std::process::Output;

const ENV_SECRET: &str = "SENTINEL_CLI_ENV_37a1";
const HEADER_SECRET: &str = "SENTINEL_CLI_HEADER_84dc";
const ARG_SECRET: &str = "SENTINEL_CLI_ARG_b515";
const URL_USER_SECRET: &str = "SENTINEL_CLI_URL_USER_6d9b";
const URL_QUERY_SECRET: &str = "SENTINEL_CLI_URL_QUERY_efe2";
const URL_FRAGMENT_SECRET: &str = "SENTINEL_CLI_URL_FRAGMENT_d209";
/// Webhook-style: the secret IS the path. Slack and Discord both work this way,
/// and an origin+path sanitiser — the conventional one — leaks it whole.
const URL_PATH_SECRET: &str = "SENTINEL_CLI_URL_PATH_c0f4";

fn run_gateway(config: &Path, args: &[&str]) -> Output {
    gateway_bin::command(
        config.parent().expect("the config sits in a temp dir"),
        gateway_bin::Inherit::Environment,
    )
    .args(args)
    .arg("--config")
    .arg(config)
    .output()
    .expect("run mcp-gateway")
}

fn combined_output(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn backend_inspection_commands_never_print_config_secrets() {
    let dir = tempfile::tempdir().expect("create CLI redaction workspace");
    let config = dir.path().join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &config,
        format!(
            r#"backends:
  stdio-secret:
    command: "/usr/bin/example --token '{ARG_SECRET}' --mode safe"
    env:
      SAFE_ENV_NAME: "{ENV_SECRET}"
      FROM_KEYCHAIN: "keychain:gw.cli-ref"
    headers:
      Authorization: "{HEADER_SECRET}"
      X-Token: "env:CLI_REF_TOKEN"
  http-secret:
    http_url: "https://user:{URL_USER_SECRET}@svc.example.com/services/{URL_PATH_SECRET}?token={URL_QUERY_SECRET}#{URL_FRAGMENT_SECRET}"
"#
        ),
    )
    .expect("write CLI redaction config");

    let outputs = [
        run_gateway(&config, &["get", "stdio-secret"]),
        run_gateway(&config, &["get", "http-secret"]),
        run_gateway(&config, &["list", "--json"]),
    ];
    for output in &outputs {
        assert!(
            output.status.success(),
            "CLI failed: {}",
            combined_output(output)
        );
    }
    let combined = outputs.iter().map(combined_output).collect::<String>();

    for sentinel in [
        ENV_SECRET,
        HEADER_SECRET,
        ARG_SECRET,
        URL_USER_SECRET,
        URL_QUERY_SECRET,
        URL_FRAGMENT_SECRET,
        URL_PATH_SECRET,
    ] {
        assert!(
            !combined.contains(sentinel),
            "CLI leaked {sentinel}: {combined}"
        );
    }
    assert!(combined.contains("SAFE_ENV_NAME=<set>"));
    assert!(combined.contains("Authorization=<set>"));
    // A secret reference is shown as written by `get` (ADR-028),
    // and `list --json` stays names-only.
    let get = combined_output(&outputs[0]);
    assert!(get.contains("FROM_KEYCHAIN=keychain:gw.cli-ref"), "{get}");
    assert!(get.contains("X-Token=env:CLI_REF_TOKEN"), "{get}");
    let list = combined_output(&outputs[2]);
    assert!(!list.contains("keychain:gw.cli-ref"), "{list}");
    assert!(!list.contains("env:CLI_REF_TOKEN"), "{list}");
    assert!(combined.contains("argument(s) redacted"));
    // The origin is kept so the endpoint is still identifiable; the path is not,
    // because that is where a webhook secret lives.
    assert!(combined.contains("https://svc.example.com"));
    assert!(
        !combined.contains("/services/"),
        "the path must not survive: {combined}"
    );
}

/// An email and a live page token as `audit lookup-email` would see them
/// typed by mistake as arguments.
const TYPED_EMAIL: &str = "Planted.Person@corp.invalid";
const TYPED_TOKEN: &str = "AQEBsealedPageTokenSENTINEL_c41a";

fn run_bare(args: &[&str]) -> Output {
    let home = tempfile::tempdir().expect("create an isolated home");
    gateway_bin::command(home.path(), gateway_bin::Inherit::Nothing)
        .args(args)
        .output()
        .expect("run mcp-gateway")
}

/// MIK-9456.CLI.1: `audit lookup-email` reads the email and the page token
/// from stdin only. A value typed as an argument anyway (positional, after
/// `--`, attached to a flag, given to another flag, or as a flag name) is
/// refused with a fixed message that never repeats it, in the parse phase and
/// the validation phase alike, so it cannot reach stderr or a log that
/// captures it.
/// Mutant: let the parser's own error through for this command.
#[test]
fn audit_lookup_email_never_repeats_a_value_typed_as_an_argument() {
    let email_attached = format!("--email-stdin={TYPED_EMAIL}");
    let token_attached = format!("--cursor-stdin={TYPED_TOKEN}");
    let old_cursor_attached = format!("--cursor={TYPED_TOKEN}");
    let limit_attached = format!("--limit={TYPED_TOKEN}");
    let token_as_flag = format!("--{TYPED_TOKEN}");
    for (shape, typed) in [
        (vec!["--email-stdin", TYPED_EMAIL], TYPED_EMAIL),
        (vec!["--cursor-stdin", TYPED_TOKEN], TYPED_TOKEN),
        (vec![TYPED_EMAIL], TYPED_EMAIL),
        (vec!["--cursor-stdin", "--", TYPED_TOKEN], TYPED_TOKEN),
        (vec![email_attached.as_str()], TYPED_EMAIL),
        (vec![token_attached.as_str()], TYPED_TOKEN),
        (vec![old_cursor_attached.as_str()], TYPED_TOKEN),
        (vec!["--cursor-stdin", limit_attached.as_str()], TYPED_TOKEN),
        (vec!["--cursor-stdin", "--limit", TYPED_TOKEN], TYPED_TOKEN),
        (vec!["--email-stdin", "--limit", "7777777"], "7777777"),
        (vec!["--cursor-stdin", token_as_flag.as_str()], TYPED_TOKEN),
        // Accepted by the parser as the URL, then refused in validation: no
        // source flag was given.
        (vec!["--url", TYPED_TOKEN], TYPED_TOKEN),
    ] {
        let mut argv = vec!["audit", "lookup-email"];
        argv.extend(&shape);
        let output = run_bare(&argv);
        let text = combined_output(&output);
        assert_eq!(output.status.code(), Some(2), "{shape:?}: {text}");
        assert!(!text.contains(typed), "{shape:?} repeated: {text}");
        assert!(text.contains("is not repeated"), "{shape:?}: {text}");
        assert!(text.contains("--email-stdin"), "{shape:?}: {text}");
    }
    // Typed before the command name: the parse stops before it reaches
    // `lookup-email`, and the names that follow still select the fixed message.
    for (argv, typed) in [
        (vec!["audit", TYPED_EMAIL, "lookup-email"], TYPED_EMAIL),
        (vec![TYPED_TOKEN, "audit", "lookup-email"], TYPED_TOKEN),
    ] {
        let output = run_bare(&argv);
        let text = combined_output(&output);
        assert_eq!(output.status.code(), Some(2), "{argv:?}: {text}");
        assert!(!text.contains(typed), "{argv:?} repeated: {text}");
        assert!(text.contains("is not repeated"), "{argv:?}: {text}");
    }
}

/// `hash-key` reads the API key from stdin only; a key typed as an argument
/// is refused without being repeated.
/// Mutant: drop `hash-key` from the stdin-secret commands.
#[test]
fn hash_key_never_repeats_a_key_typed_as_an_argument() {
    const TYPED_KEY: &str = "sk-live-SENTINEL_9d3e";
    for argv in [
        vec!["hash-key", TYPED_KEY],
        vec!["hash-key", "--", TYPED_KEY],
    ] {
        let output = run_bare(&argv);
        let text = combined_output(&output);
        assert_eq!(output.status.code(), Some(2), "{argv:?}: {text}");
        assert!(!text.contains(TYPED_KEY), "{argv:?} repeated: {text}");
        assert!(
            text.contains("The API key is read from stdin only"),
            "{text}"
        );
    }
}

/// MIK-9456.CLI.1: only the commands that read a secret from stdin get the
/// fixed message: a typo anywhere else still names what was typed, a
/// `--help` after a failing argument does not change that, and help itself
/// still prints.
/// Mutant: give every command the fixed message, match the path by prefix,
/// let a later `--help` decide the path, or replace help.
#[test]
fn other_parse_errors_and_help_keep_the_parsers_own_output() {
    for argv in [
        vec!["--no-such-root-flag-77c2"],
        vec!["no-such-command-77c2"],
        vec!["list", "--no-such-flag-77c2"],
        vec!["audit", "show", "--no-such-flag-77c2"],
        vec!["audit", "verify", "--no-such-flag-77c2", "--help"],
    ] {
        let output = run_bare(&argv);
        let text = combined_output(&output);
        assert_eq!(output.status.code(), Some(2), "{argv:?}: {text}");
        assert!(text.contains("77c2"), "{argv:?}: {text}");
        assert!(!text.contains("is not repeated"), "{argv:?}: {text}");
    }
    // `--path` takes a value and gets none: the parser's own message names it.
    let missing = run_bare(&["audit", "verify", "--path", "--help"]);
    let text = combined_output(&missing);
    assert_eq!(missing.status.code(), Some(2), "{text}");
    assert!(text.contains("--path"), "{text}");
    assert!(!text.contains("is not repeated"), "{text}");
    // Real help: the usage line and the credential's variable, which the
    // fixed message does not carry.
    let help = run_bare(&["audit", "lookup-email", "--help"]);
    assert_eq!(help.status.code(), Some(0), "{}", combined_output(&help));
    let stdout = String::from_utf8_lossy(&help.stdout);
    assert!(stdout.contains("Usage:"), "{stdout}");
    assert!(stdout.contains("MCP_GATEWAY_TOKEN"), "{stdout}");
    assert!(!stdout.contains("is not repeated"), "{stdout}");
}
