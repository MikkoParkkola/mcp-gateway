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
    /// A path to the file that holds it: the value parses as a `PathBuf`.
    FilePath,
    /// The name of a variable or key, never its value: value name `KEY`.
    Name,
    /// A reference the gateway resolves, such as `env:NAME`: value name
    /// `REFERENCE`.
    Reference,
    /// Arguments passed on to a tool call, not a setting of the CLI itself:
    /// positional, value name `KEY=VALUE`.
    ToolInput,
}

/// Keyed by the command path and the argument's id, so a same-named argument
/// on another command is classed on its own.
const CLASSED: &[(&str, &str, Carries)] = &[
    ("add", "keep_as_text", Carries::Name),
    ("api", "client_key", Carries::FilePath),
    ("audit lookup-email", "client_key", Carries::FilePath),
    ("cap import", "auth_key", Carries::Reference),
    ("dashboard-link", "client_key", Carries::FilePath),
    ("events dead-letters", "client_key", Carries::FilePath),
    ("tls issue-client", "ca_key", Carries::FilePath),
    ("tls issue-server", "ca_key", Carries::FilePath),
    ("tool invoke", "kv_args", Carries::ToolInput),
];

/// The ceiling of this walk: only these substrings select an argument, so
/// `passwd`, `pwd` or `authorization` in a name would pass unseen.
const SECRET_WORDS: &[&str] = &["token", "secret", "password", "key", "bearer", "credential"];

fn sounds_secret(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    SECRET_WORDS.iter().any(|word| lower.contains(word))
}

/// Whether `arg` shows the property its class names.
fn class_holds(arg: &clap::Arg, class: Carries) -> bool {
    let value_names = arg.get_value_names().unwrap_or_default();
    let named = |want: &str| value_names.iter().any(|name| name.as_str() == want);
    match class {
        Carries::FilePath => {
            arg.get_value_parser().type_id() == std::any::TypeId::of::<std::path::PathBuf>()
        }
        Carries::Name => named("KEY"),
        Carries::Reference => named("REFERENCE"),
        Carries::ToolInput => arg.get_long().is_none() && named("KEY=VALUE"),
    }
}

/// Every value-taking argument in `cmd` and below whose long name or value
/// name sounds like a secret, keyed by command path and argument id, with
/// whether each listed class holds for it.
fn collect(
    cmd: &clap::Command,
    path: &str,
    found: &mut BTreeSet<(String, String)>,
    wrong_class: &mut Vec<String>,
) {
    for arg in cmd.get_arguments() {
        if !arg.get_action().takes_values() {
            continue;
        }
        let long = arg.get_long();
        let value_names = arg.get_value_names().unwrap_or_default();
        let named_secret = long.is_some_and(sounds_secret)
            || value_names.iter().any(|name| sounds_secret(name.as_str()));
        if !named_secret {
            continue;
        }
        let id = arg.get_id().as_str();
        found.insert((path.to_owned(), id.to_owned()));
        if let Some((_, _, class)) = CLASSED.iter().find(|(p, i, _)| *p == path && *i == id)
            && !class_holds(arg, *class)
        {
            wrong_class.push(format!("{path} {id} is not {class:?}"));
        }
    }
    for sub in cmd.get_subcommands() {
        let name = sub.get_name();
        let child = if path.is_empty() {
            name.to_owned()
        } else {
            format!("{path} {name}")
        };
        collect(sub, &child, found, wrong_class);
    }
}

#[test]
fn no_flag_takes_a_secret_value() {
    use clap::CommandFactory as _;
    let mut cli = Cli::command();
    cli.build();
    let (mut found, mut wrong_class) = (BTreeSet::new(), Vec::new());
    collect(&cli, "", &mut found, &mut wrong_class);
    assert!(
        found.contains(&("api".to_owned(), "client_key".to_owned())),
        "the walk must reach flattened and nested arguments, or it proves nothing: {found:?}"
    );
    let classed: BTreeSet<(String, String)> = CLASSED
        .iter()
        .map(|(path, id, _)| ((*path).to_owned(), (*id).to_owned()))
        .collect();
    let unclassed: Vec<&(String, String)> = found.difference(&classed).collect();
    assert!(
        unclassed.is_empty(),
        "these take a secret-sounding value: class each one here (file path, name, reference or \
         tool input), or read the value from a prompt, stdin, a file or the environment: {unclassed:?}"
    );
    let stale: Vec<&(String, String)> = classed.difference(&found).collect();
    assert!(
        stale.is_empty(),
        "classed arguments the CLI no longer has: {stale:?}"
    );
    assert!(
        wrong_class.is_empty(),
        "classed, but the argument does not carry what its class says: {wrong_class:?}"
    );
}
