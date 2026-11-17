// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Flags hidden from `--help` still parse and still carry their value, so a script
//! that passes one keeps working. One row per hidden flag family; each passes a
//! sentinel value and finds it in the parsed command, so a flag that is accepted
//! but dropped fails as surely as one that no longer parses.

use super::*;

/// Parses `args` after the program name and returns the parsed command's debug
/// form, which names every field and its value.
fn parsed(args: &[&str]) -> String {
    use clap::Parser as _;
    let full: Vec<&str> = std::iter::once("mcp-gateway")
        .chain(args.iter().copied())
        .collect();
    let cli =
        Cli::try_parse_from(full).unwrap_or_else(|e| panic!("{args:?} no longer parses: {e}"));
    format!("{cli:?}")
}

fn assert_carries(args: &[&str], expected: &[&str]) {
    let debug = parsed(args);
    for want in expected {
        assert!(
            debug.contains(want),
            "{args:?} parsed without {want:?}: {debug}"
        );
    }
}

#[test]
fn hidden_global_flags_still_parse() {
    assert_carries(&["--host", "10.9.8.7"], &["host: Some(\"10.9.8.7\")"]);
    assert_carries(&["--log-format", "json"], &["log_format: Some(\"json\")"]);
    assert_carries(&["--no-meta-mcp"], &["no_meta_mcp: true"]);
}

#[test]
fn hidden_add_keep_as_text_still_parses() {
    assert_carries(
        &[
            "add",
            "demo",
            "--command",
            "echo",
            "--keep-as-text",
            "SENTINEL_KEY_9641",
        ],
        &["keep_as_text: [\"SENTINEL_KEY_9641\"]"],
    );
}

#[test]
fn hidden_remote_command_flags_still_parse() {
    assert_carries(
        &["api", "get", "/x", "--if-match", "sentinel-etag-9641"],
        &["if_match: Some(\"sentinel-etag-9641\")"],
    );
    assert_carries(
        &["audit", "lookup-email", "--email-stdin", "--limit", "17"],
        &["limit: Some(17)"],
    );
    assert_carries(
        &["events", "dead-letters", "list", "--reason", "reason-9641"],
        &["reason: Some(\"reason-9641\")"],
    );
}

#[test]
fn hidden_identity_grant_flags_still_parse() {
    assert_carries(
        &[
            "identity",
            "grants",
            "grant",
            "--grant-id",
            "g1",
            "--subject",
            "s1",
            "--capability",
            "c1",
            "--reason",
            "r1",
            "--subject-label",
            "subject-9641",
            "--owner-label",
            "owner-9641",
            "--ttl-seconds",
            "641",
            "--provenance",
            "provenance-9641",
        ],
        &[
            "subject_label: Some(\"subject-9641\")",
            "owner_label: Some(\"owner-9641\")",
            "ttl_seconds: Some(641)",
            "provenance: \"provenance-9641\"",
        ],
    );
    assert_carries(
        &[
            "identity",
            "grants",
            "revoke",
            "--grant-id",
            "g1",
            "--revoked-at",
            "2026-11-15T00:00:00Z",
        ],
        &["revoked_at: Some(\"2026-11-15T00:00:00Z\")"],
    );
}

#[test]
fn hidden_import_source_name_still_parses() {
    for verb in ["preview", "apply"] {
        assert_carries(
            &[
                "import",
                verb,
                "--kind",
                "openapi",
                "spec.yaml",
                "--source-name",
                "source-9641",
            ],
            &["source_name: Some(\"source-9641\")"],
        );
    }
}

#[test]
fn hidden_setup_flags_still_parse() {
    assert_carries(
        &[
            "setup",
            "export",
            "--mode",
            "stdio",
            "--name",
            "name-9641",
            "--watch",
        ],
        &["name: \"name-9641\"", "watch: true"],
    );
    assert_carries(
        &["setup", "export", "-m", "stdio", "-n", "short-9641", "-w"],
        &["name: \"short-9641\"", "watch: true"],
    );
}

#[test]
fn hidden_skills_and_tool_flags_still_parse() {
    assert_carries(
        &[
            "skills",
            "generate",
            "--server",
            "server-9641",
            "--category",
            "category-9641",
        ],
        &[
            "server: Some(\"server-9641\")",
            "category: Some(\"category-9641\")",
        ],
    );
    assert_carries(
        &["tool", "invoke", "t1", "--args", "{\"k\":9641}"],
        &["args: Some(\"{\\\"k\\\":9641}\")"],
    );
    assert_carries(
        &["tool", "invoke", "t1", "-a", "{}"],
        &["args: Some(\"{}\")"],
    );
}

#[test]
fn hidden_upgrade_and_validate_flags_still_parse() {
    assert_carries(&["upgrade", "--quiet"], &["quiet: true"]);
    assert_carries(&["upgrade", "-q"], &["quiet: true"]);
    assert_carries(
        &["validate", "a.yaml", "--severity", "fail"],
        &["severity: Fail"],
    );
    assert_carries(&["validate", "a.yaml", "-s", "fail"], &["severity: Fail"]);
}

/// The words of `help` that can be a flag or a value name.
fn help_words(path: &[&str]) -> Vec<String> {
    use clap::CommandFactory as _;
    let mut cmd = Cli::command();
    cmd.build();
    for name in path {
        cmd = cmd
            .find_subcommand(name)
            .unwrap_or_else(|| panic!("no subcommand {name:?} in {path:?}"))
            .clone();
    }
    let help = cmd.render_long_help().to_string();
    help.split(|c: char| !(c.is_alphanumeric() || c == '-' || c == '_' || c == '<' || c == '>'))
        .map(str::to_owned)
        .collect()
}

/// Each flag this pass hides is set hidden and left out of its command's
/// help, while flags the same command keeps are still shown: reverting one
/// `hide = true` fails here, and so does a help that renders nothing.
#[test]
fn hidden_flags_are_left_out_of_help_and_kept_flags_stay() {
    use clap::CommandFactory as _;
    // (command path, flags hidden by this pass, flags the command keeps)
    let table: &[(&[&str], &[&str], &[&str])] = &[
        (
            &[],
            &["--host", "--log-format", "--no-meta-mcp"],
            &["--port"],
        ),
        (&["add"], &["--keep-as-text"], &["--command"]),
        (&["api"], &["--if-match"], &["--data", "--url"]),
        (&["audit", "lookup-email"], &["--limit"], &["--email-stdin"]),
        (
            &["events", "dead-letters"],
            &["--reason"],
            &["--all", "--url", "--subscription"],
        ),
        (
            &["identity", "grants", "grant"],
            &[
                "--subject-label",
                "--owner-label",
                "--ttl-seconds",
                "--provenance",
            ],
            &["--grant-id"],
        ),
        (
            &["identity", "grants", "revoke"],
            &["--revoked-at"],
            &["--grant-id"],
        ),
        (&["import", "preview"], &["--source-name"], &["--kind"]),
        (&["import", "apply"], &["--source-name"], &["--kind"]),
        (&["init"], &[], &["--profile", "--with-examples"]),
        (
            &["setup", "export"],
            &["--mode", "--name", "--watch"],
            &["--target", "--dry-run"],
        ),
        (
            &["setup", "wizard"],
            &[],
            &["--configure-client", "--force"],
        ),
        (
            &["skills", "generate"],
            &["--server", "--category"],
            &["--out-dir"],
        ),
        (&["tool", "invoke"], &["--args"], &["<TOOL>"]),
        (&["upgrade"], &["--quiet"], &["--dry-run"]),
        (&["validate"], &["--severity"], &["--format"]),
    ];
    for (path, hidden, kept) in table {
        let words = help_words(path);
        let mut cmd = Cli::command();
        cmd.build();
        let mut found = &cmd;
        for name in *path {
            found = found.find_subcommand(name).expect("checked above");
        }
        for flag in *hidden {
            let long = flag.trim_start_matches("--");
            let arg = found
                .get_arguments()
                .find(|a| a.get_long() == Some(long))
                .unwrap_or_else(|| panic!("{path:?} has no {flag}"));
            assert!(arg.is_hide_set(), "{path:?} {flag} is not hidden");
            assert!(
                !words.iter().any(|w| w == flag),
                "{path:?} help still shows {flag}"
            );
        }
        for flag in *kept {
            assert!(
                words.iter().any(|w| w == flag),
                "{path:?} help lost {flag}: {words:?}"
            );
        }
    }
}
