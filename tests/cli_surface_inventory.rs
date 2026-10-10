// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `## Surface: cli` table lists exactly the CLI clap builds (MIK-8170).
//!
//! Gated on every CLI-gating feature (Cargo.toml `[[test]]`), so CI's
//! `--all-features` run sees every subcommand and a default run skips it.

#[path = "common/cli_inventory_walker.rs"]
mod walker;

use clap::{CommandFactory, Parser};

const DOC: &str = include_str!("../docs/design/surface-4.0.md");

#[test]
fn the_cli_inventory_lists_exactly_the_cli_clap_builds() {
    let w = walker::walk(&mcp_gateway::cli::Cli::command());
    let problems = walker::compare(&w, &walker::doc_rows(DOC));
    assert!(
        problems.is_empty(),
        "docs/design/surface-4.0.md `## Surface: cli` disagrees with clap ({} problems):\n{}",
        problems.len(),
        problems.join("\n")
    );
}

const HIDDEN_COMMANDS: [&str; 4] = ["kubernetes", "ranking", "runtime", "trust"];

/// First token of each row in a rendered help's `Commands:` section.
fn command_tokens(help: &str) -> Vec<String> {
    help.lines()
        .skip_while(|l| !l.starts_with("Commands:"))
        .skip(1)
        .take_while(|l| !l.trim().is_empty())
        .filter_map(|l| l.split_whitespace().next().map(str::to_owned))
        .collect()
}

fn built() -> clap::Command {
    let mut root = mcp_gateway::cli::Cli::command();
    root.build();
    root
}

/// The root `--help` lists no INTERNAL command (MIK-8044 SURF.3).
#[test]
fn the_root_help_lists_no_internal_command() {
    let help = built().render_help().to_string();
    let listed = command_tokens(&help);
    assert!(listed.iter().any(|t| t == "add"), "parse check: {listed:?}");
    for hidden in HIDDEN_COMMANDS {
        assert!(
            !listed.iter().any(|t| t == hidden),
            "{hidden} listed:\n{help}"
        );
    }
}

/// A hidden command run on purpose still documents itself and still parses
/// (lead ruling: SURF.3 governs help reachable from KEEP commands).
#[test]
fn a_hidden_command_still_runs_and_documents_its_children() {
    let mut root = built();
    let kubernetes = root.find_subcommand_mut("kubernetes").expect("kubernetes");
    let listed = command_tokens(&kubernetes.render_help().to_string());
    for child in ["plan", "apply-plan", "controller"] {
        assert!(
            listed.iter().any(|t| t == child),
            "{child} missing: {listed:?}"
        );
    }
    for hidden in HIDDEN_COMMANDS {
        let err = mcp_gateway::cli::Cli::try_parse_from(["mcp-gateway", hidden, "--help"])
            .expect_err("--help exits through clap's help path");
        assert_eq!(
            err.kind(),
            clap::error::ErrorKind::DisplayHelp,
            "{hidden}: {err}"
        );
    }
}

/// The AUTO `-C/--capabilities` flags are left out of help and still parse.
#[test]
fn the_auto_capabilities_flags_are_hidden_but_parse() {
    let paths: [&[&str]; 5] = [
        &["skills", "generate"],
        &["tool", "invoke"],
        &["tool", "list"],
        &["tool", "inspect"],
        &["tool", "completions"],
    ];
    for path in paths {
        let mut root = built();
        let mut cmd = &mut root;
        for name in path {
            cmd = cmd.find_subcommand_mut(name).expect("subcommand");
        }
        for help in [
            cmd.render_help().to_string(),
            cmd.render_long_help().to_string(),
        ] {
            assert!(
                !help.contains("--capabilities"),
                "{path:?} lists --capabilities:\n{help}"
            );
            assert!(!help.contains("-C,"), "{path:?} lists -C:\n{help}");
        }
        let mut argv = vec!["mcp-gateway"];
        argv.extend_from_slice(path);
        argv.extend(["-C", "somewhere", "--help"]);
        let err = mcp_gateway::cli::Cli::try_parse_from(&argv).expect_err("help path");
        assert_eq!(
            err.kind(),
            clap::error::ErrorKind::DisplayHelp,
            "{path:?}: {err}"
        );
    }
}
