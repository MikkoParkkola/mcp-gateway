// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A parse error for a command that reads a secret from stdin never repeats
//! what was typed.
//!
//! The parser's own errors quote the offending text: a stray positional
//! value, a value attached to a flag that takes none, a bad value for a flag.
//! For `audit lookup-email` that text can be the email it looks up (personal
//! data) or a live page token typed as an argument by mistake; quoted back, it
//! reaches stderr and any log that captures it. Those commands get a fixed
//! message instead. Every other command keeps the parser's own message.

use std::ffi::OsString;

use clap::CommandFactory as _;
use clap::error::ErrorKind;
use mcp_gateway::cli::Cli;

/// Subcommand paths whose secrets come from stdin, with the hint their fixed
/// message gives.
const STDIN_SECRET_COMMANDS: &[(&[&str], &str)] = &[
    (
        &["audit", "lookup-email"],
        "The email and the page token are read from stdin only: --email-stdin \
         (first page) or --cursor-stdin (next page)",
    ),
    (&["hash-key"], "The API key is read from stdin only"),
];

/// `error` as it is printed for `args`: unchanged, or, for a command that
/// reads a secret from stdin, a message of the same kind that never repeats
/// what was typed.
pub(crate) fn quiet_for_secret_commands(args: &[OsString], error: clap::Error) -> clap::Error {
    // Help and version print no typed value.
    if matches!(
        error.kind(),
        ErrorKind::DisplayHelp
            | ErrorKind::DisplayVersion
            | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
    ) {
        return error;
    }
    let hint = match subcommand_path(args) {
        Some(path) => {
            let Some((_, hint)) = STDIN_SECRET_COMMANDS
                .iter()
                .find(|(secret, _)| mutant!("E7", secret.first() != Some(&"hash-key") && names(secret, &path, args), names(secret, &path, args)))
            else {
                return error;
            };
            *hint
        }
        // Cannot fire with clap 4.6.7 (errors ignored, help and version off:
        // the parse returns Ok); kept so a later clap that errs repeats nothing.
        None => mutant!("E5", return error, "The arguments are not valid"),
    };
    let what = error
        .kind()
        .as_str()
        .unwrap_or("the arguments are not valid");
    clap::Error::raw(
        error.kind(),
        format!("{what}; what was typed is not repeated here. {hint}; see --help.\n"),
    )
}

/// Whether the command line names `secret`: the parse recorded exactly that
/// path, or it stopped earlier (something typed before the command name, such
/// as `audit <email> lookup-email`) and the remaining names still follow, in
/// order, later in `args`.
///
/// Accepted residual: a later argument spelled like a remaining name also
/// matches, so `audit --bogus verify --path lookup-email` gets the fixed
/// message instead of the parser's note about `--bogus`. That hides detail but
/// never repeats typed text; telling a name from a value here would need a
/// third parse on this path.
fn names(secret: &[&str], path: &[String], args: &[OsString]) -> bool {
    if path.len() > secret.len() || mutant!("E8", false, !path.iter().zip(secret).all(|(p, s)| p.as_str() == *s)) {
        return false;
    }
    let mut rest = secret.iter().skip(path.len());
    let mut want = rest.next();
    for arg in args.iter().skip(1) {
        if want.is_some_and(|name| arg.to_str() == Some(*name)) {
            want = rest.next();
        }
    }
    mutant!("E9", true, want.is_none())
}

/// The subcommand names `args` selects, read by a second parse that ignores
/// errors: the parser then records a subcommand even when that subcommand's
/// own arguments failed. Help and version are switched off for it, so a
/// `--help` after the failing argument (`--path --help`) cannot end this parse
/// with a help request instead of a path.
fn subcommand_path(args: &[OsString]) -> Option<Vec<String>> {
    let matches = Cli::command()
        .ignore_errors(true)
        .disable_help_flag(true)
        .disable_help_subcommand(true)
        .disable_version_flag(true)
        .try_get_matches_from(args)
        .ok()?;
    let mut path = Vec::new();
    let mut at = &matches;
    while let Some((name, sub)) = at.subcommand() {
        path.push(name.to_owned());
        at = mutant!("E6", break, sub);
    }
    Some(path)
}
