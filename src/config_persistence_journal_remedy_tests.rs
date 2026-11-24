// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The settlement refusal names only commands this build ships. Each command
//! it names is written in backticks and must parse with the CLI's own parser
//! (`Cli::try_parse_from`), so a subcommand, an option, a value or a positional
//! this build lacks is refused by the command tree itself, never by a list of
//! phrases. A `<placeholder>` is passed as the argument it stands for.

use clap::Parser as _;

use super::journal::SETTLEMENT_PENDING;

/// Why one backticked `command` is not a form the CLI accepts, or `None`.
fn unresolved(command: &str) -> Option<String> {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    if tokens.first() != Some(&"mcp-gateway") {
        return Some(format!("`{command}` does not start with mcp-gateway"));
    }
    crate::cli::Cli::try_parse_from(&tokens)
        .err()
        .map(|error| format!("`{command}`: {error}"))
}

/// Every problem with the commands `text` names: none named, a command named
/// outside backticks, or a backticked command the CLI does not parse.
fn problems(text: &str) -> Vec<String> {
    let commands: Vec<&str> = text
        .split('`')
        .skip(1)
        .step_by(2)
        .filter(|span| span.starts_with("mcp-gateway"))
        .collect();
    let mut found: Vec<String> = commands.iter().copied().filter_map(unresolved).collect();
    if commands.is_empty() {
        found.push("names no command".to_owned());
    }
    // A command outside backticks has no boundary the check could read.
    if text.matches("mcp-gateway").count() != commands.len() {
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
    refused("Run `mcp-gateway serve --settle`.", "'--settle'");
    refused("Run `mcp-gateway serve <journal>`.", "'<journal>'");
    // A flag that takes no value, given one.
    refused("Run `mcp-gateway serve --stdio=yes`.", "'yes'");
    refused("Run mcp-gateway serve.", "outside backticks");
    refused("Start the gateway.", "names no command");
    assert_eq!(problems("Start `mcp-gateway serve`."), Vec::<String>::new());
}
