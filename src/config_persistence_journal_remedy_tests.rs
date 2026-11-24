// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The settlement refusal names only commands this build ships. Every span it
//! writes in backticks is a command, with or without its `mcp-gateway` prefix,
//! and must parse with the CLI's own parser (`Cli::try_parse_from`), so a
//! subcommand, an option, a value or a positional this build lacks is refused
//! by the command tree itself, never by a list of phrases. A `<placeholder>`
//! is passed as the argument it stands for.

use clap::Parser as _;

use super::journal::SETTLEMENT_PENDING;

/// Why one backticked `span` is not a command the CLI accepts, or `None`. A
/// span without the `mcp-gateway` prefix is judged as if it had it.
fn unresolved(span: &str) -> Option<String> {
    let mut tokens: Vec<&str> = span.split_whitespace().collect();
    if tokens.first() != Some(&"mcp-gateway") {
        tokens.insert(0, "mcp-gateway");
    }
    crate::cli::Cli::try_parse_from(&tokens)
        .err()
        .map(|error| format!("`{span}`: {error}"))
}

/// Every problem with the commands `text` names: none named, `mcp-gateway`
/// named outside backticks, or a backticked span the CLI does not parse.
fn problems(text: &str) -> Vec<String> {
    let spans: Vec<&str> = text.split('`').skip(1).step_by(2).collect();
    let mut found: Vec<String> = spans.iter().copied().filter_map(unresolved).collect();
    if spans.is_empty() {
        found.push("names no command".to_owned());
    }
    // A command outside backticks has no boundary the check could read.
    let inside: usize = spans
        .iter()
        .map(|span| span.matches("mcp-gateway").count())
        .sum();
    if text.matches("mcp-gateway").count() != inside {
        found.push("names mcp-gateway outside backticks".to_owned());
    }
    found
}

#[test]
fn settlement_pending_names_only_shipped_commands() {
    assert_eq!(problems(SETTLEMENT_PENDING), Vec::<String>::new());
}

/// The check refuses each way a sentence can name what this build lacks, and
/// accepts the shipped remedy.
#[test]
fn the_command_tree_refuses_forms_this_build_lacks() {
    let refused = |text: &str, needle: &str| {
        let found = problems(text);
        assert!(
            found.iter().any(|p| p.contains(needle)),
            "{text:?} must be refused naming {needle:?}: {found:?}"
        );
    };
    // The sentence 4.0.0 shipped with: `audit` has no `settle`.
    refused(
        "Run `mcp-gateway audit settle --abandon <journal> --yes`.",
        "'settle'",
    );
    // The same, written without its prefix: still a command, still refused.
    refused("Run `audit settle --abandon <journal> --yes`.", "'settle'");
    refused("Run `mcp-gateway serve --settle`.", "'--settle'");
    refused("Run `mcp-gateway serve <journal>`.", "'<journal>'");
    // A flag that takes no value, given one.
    refused("Run `mcp-gateway serve --stdio=yes`.", "'yes'");
    // Help and version are parser exits, not a remedy.
    refused("Run `mcp-gateway --help`.", "`mcp-gateway --help`:");
    refused("Run `mcp-gateway --version`.", "`mcp-gateway --version`:");
    refused("Run mcp-gateway serve.", "outside backticks");
    refused("Start the gateway.", "names no command");
    assert_eq!(problems("Start `mcp-gateway serve`."), Vec::<String>::new());
}
