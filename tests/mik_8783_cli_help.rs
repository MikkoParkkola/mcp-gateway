// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8783: help text for the settings sweep.
//! - AUTO.8: `verify`'s two receipt flags name two different cases.
//! - AUTO.6: the measurement-window flag is hidden from `--help` and still
//!   parses before any subcommand.

use clap::CommandFactory;

fn help_of(cmd: &mut clap::Command, flag: &str) -> String {
    cmd.get_arguments()
        .find(|a| a.get_long() == Some(flag))
        .and_then(|a| a.get_help().map(ToString::to_string))
        .unwrap_or_default()
}

/// T2.15: `--signature-only` is about a digest present but no result given;
/// `--accept-unbound` is about a receipt with no digest at all.
#[test]
fn verify_receipt_flags_name_their_own_case() {
    let mut root = mcp_gateway::cli::Cli::command();
    let verify = root
        .find_subcommand_mut("provenance")
        .and_then(|p| p.find_subcommand_mut("verify"))
        .expect("provenance verify subcommand");
    let signature_only = help_of(verify, "signature-only");
    let accept_unbound = help_of(verify, "accept-unbound");
    assert_ne!(signature_only, accept_unbound);
    assert!(
        signature_only.contains("carries a result digest") && signature_only.contains("no result"),
        "--signature-only: {signature_only:?}"
    );
    assert!(
        accept_unbound.contains("no result digest"),
        "--accept-unbound: {accept_unbound:?}"
    );
}

/// T2.16: hidden from `--help`, accepted before a subcommand.
#[test]
fn the_window_flag_is_hidden_and_parses_before_a_subcommand() {
    let mut root = mcp_gateway::cli::Cli::command();
    let help = root.render_long_help().to_string();
    assert!(
        !help.contains("protocol-revision-window"),
        "the flag must be hidden:\n{help}"
    );
    for argv in [
        &["mcp-gateway", "--protocol-revision-window", "record"][..],
        &[
            "mcp-gateway",
            "--protocol-revision-window",
            "record",
            "serve",
        ][..],
    ] {
        mcp_gateway::cli::Cli::command()
            .try_get_matches_from(argv)
            .unwrap_or_else(|e| panic!("{argv:?} must parse: {e}"));
    }
}
