// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The settlement refusal names only commands this build ships. Each command
//! it names is written in backticks, and every token in it must resolve in the
//! CLI's parsed command tree: a subcommand (or alias) of the command reached so
//! far, an option that command takes, or a `<placeholder>` where it takes a
//! positional. The tree is the oracle, never a list of phrases.

use clap::CommandFactory as _;

use super::journal::SETTLEMENT_PENDING;

/// Why one backticked `command` is not a form the CLI accepts, or `None`.
fn unresolved(command: &str) -> Option<String> {
    let mut tokens = command.split_whitespace();
    if tokens.next() != Some("mcp-gateway") {
        return Some(format!("`{command}` does not start with mcp-gateway"));
    }
    let mut root = crate::cli::Cli::command();
    // Global options reach the subcommands only once the tree is built.
    root.build();
    let mut at = &root;
    let mut positionals = 0;
    for token in tokens {
        let takes = |matches: &dyn Fn(&clap::Arg) -> bool| at.get_arguments().any(matches);
        let known = if let Some(long) = token.strip_prefix("--") {
            let long = long.split('=').next().unwrap_or_default();
            takes(&|arg| {
                arg.get_long() == Some(long)
                    || arg.get_all_aliases().is_some_and(|all| all.contains(&long))
            })
        } else if let Some(short) = token.strip_prefix('-') {
            let mut chars = short.chars();
            match (chars.next(), chars.next()) {
                (Some(c), None) => takes(&|arg| arg.get_short() == Some(c)),
                _ => false,
            }
        } else if token.starts_with('<') && token.ends_with('>') {
            positionals += 1;
            at.get_positionals().count() >= positionals
        } else if let Some(sub) = at.find_subcommand(token) {
            at = sub;
            positionals = 0;
            true
        } else {
            false
        };
        if !known {
            return Some(format!(
                "`{command}`: {token:?} is not a subcommand, option or positional of `{}`",
                at.get_name()
            ));
        }
    }
    None
}

/// Every problem with the commands `text` names: none named, a command named
/// outside backticks, or a backticked command the tree does not accept.
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
        "\"settle\"",
    );
    refused("Run `mcp-gateway serve --settle`.", "\"--settle\"");
    refused("Run `mcp-gateway serve <journal>`.", "\"<journal>\"");
    refused("Run mcp-gateway serve.", "outside backticks");
    refused("Start the gateway.", "names no command");
    assert_eq!(problems("Start `mcp-gateway serve`."), Vec::<String>::new());
}
