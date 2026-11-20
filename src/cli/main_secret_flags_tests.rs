// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! No CLI flag takes a secret's value: whatever is typed on a command line
//! shows up in process lists and shell history. Each argument whose name
//! sounds like a secret is listed here with what it really carries, so a new
//! one fails until someone decides that, and an entry the CLI no longer has
//! fails too, so the list cannot hide a stale name.

use std::collections::BTreeSet;

use super::*;

/// What a secret-sounding argument carries instead of the secret.
#[derive(Debug, Clone, Copy)]
enum Carries {
    /// A path to the file that holds it.
    FilePath,
    /// The name of a variable or key, never its value.
    Name,
    /// A reference the gateway resolves, such as `env:NAME`.
    Reference,
    /// Arguments passed on to a tool call; not a setting of the CLI itself.
    ToolInput,
}

/// Keyed by long name, or by the argument's id when it has no long name.
const CLASSED: &[(&str, Carries)] = &[
    ("auth-key", Carries::Reference),
    ("ca-key", Carries::FilePath),
    ("client-key", Carries::FilePath),
    ("keep-as-text", Carries::Name),
    ("kv_args", Carries::ToolInput),
];

const SECRET_WORDS: &[&str] = &["token", "secret", "password", "key", "bearer", "credential"];

fn sounds_secret(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    SECRET_WORDS.iter().any(|word| lower.contains(word))
}

/// Collects every value-taking argument in `cmd` and below whose long name or
/// value name sounds like a secret.
fn collect(cmd: &clap::Command, found: &mut BTreeSet<String>) {
    for arg in cmd.get_arguments() {
        if !arg.get_action().takes_values() {
            continue;
        }
        let long = arg.get_long();
        let value_names = arg.get_value_names().unwrap_or_default();
        let named_secret = long.is_some_and(sounds_secret)
            || value_names.iter().any(|name| sounds_secret(name.as_str()));
        if named_secret {
            found.insert(long.unwrap_or(arg.get_id().as_str()).to_owned());
        }
    }
    for sub in cmd.get_subcommands() {
        collect(sub, found);
    }
}

#[test]
fn no_flag_takes_a_secret_value() {
    use clap::CommandFactory as _;
    let mut found = BTreeSet::new();
    collect(&Cli::command(), &mut found);
    assert!(
        found.contains("client-key"),
        "the walk must reach flattened and nested arguments, or it proves nothing: {found:?}"
    );
    let classed: BTreeSet<String> = CLASSED.iter().map(|(name, _)| (*name).to_owned()).collect();
    let unclassed: Vec<&String> = found.difference(&classed).collect();
    assert!(
        unclassed.is_empty(),
        "these take a secret-sounding value: class each one here (file path, name, reference or \
         tool input), or read the value from a prompt, stdin, a file or the environment: {unclassed:?}"
    );
    let stale: Vec<&String> = classed.difference(&found).collect();
    assert!(
        stale.is_empty(),
        "classed arguments the CLI no longer has: {stale:?}"
    );
}
