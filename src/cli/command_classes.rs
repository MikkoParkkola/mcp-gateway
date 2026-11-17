// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every leaf command's output class and error-conversion state (design D7).
//!
//! Two families of named lists, each a partition of the CLI's leaf commands, keyed by the full command path as
//! typed. The classes: `JSON_CAPABLE`, `JSON_DEFAULT`, `PENDING_JSON` (the JSON-forms follow-up, `MIK-9764.JSONF.2`, empties it), `ACTION`, `SCRIPT`. The
//! errors: `REMOTE_ON_SHARED_ERRORS` and `PENDING_SHARED_ERRORS` (the local-errors follow-up, `MIK-9765.LERR.2`, empties it). A row walks the real clap
//! tree and fails on a leaf missing from a family, a leaf in two lists of one family, a list naming no command, or a
//! class its arguments contradict, so a new command cannot ship off the output contract unnoticed.

/// Leaves with a JSON form: a `json` flag, or a `format` argument that accepts `json`.
pub(crate) const JSON_CAPABLE: &[&str] = &[];
/// Leaves whose stdout is JSON with no flag; their errors stay human text on stderr (design D10).
pub(crate) const JSON_DEFAULT: &[&str] = &[];
/// Leaves that print data with no JSON form yet; each entry cites `MIK-9764.JSONF.2`.
pub(crate) const PENDING_JSON: &[&str] = &[];
/// Leaves that act and print status only.
pub(crate) const ACTION: &[&str] = &[];
/// Leaves that print a script.
pub(crate) const SCRIPT: &[&str] = &[];
/// Leaves whose failures go through the shared exit table and error shape.
pub(crate) const REMOTE_ON_SHARED_ERRORS: &[&str] = &[];
/// Leaves not yet on the shared error shape; each entry cites `MIK-9765.LERR.2`.
pub(crate) const PENDING_SHARED_ERRORS: &[&str] = &[];
/// JSON_CAPABLE leaves whose `format` is free text (no declared values): each is classed JSON-capable only because
/// a row runs it with `--format json` and parses its stdout (the lead, 2026-11-17: no inference).
pub(crate) const FORMAT_RUN_PROVEN: &[&str] = &[];

/// One family: named lists that must partition the leaves.
pub(crate) struct Family<'a> {
    pub(crate) name: &'a str,
    pub(crate) lists: &'a [(&'a str, &'a [&'a str])],
}

/// The two families checked against the real tree.
pub(crate) fn families() -> [Family<'static>; 2] {
    [
        Family {
            name: "classes",
            lists: &[
                ("JSON_CAPABLE", JSON_CAPABLE),
                ("JSON_DEFAULT", JSON_DEFAULT),
                ("PENDING_JSON", PENDING_JSON),
                ("ACTION", ACTION),
                ("SCRIPT", SCRIPT),
            ],
        },
        Family {
            name: "errors",
            lists: &[
                ("REMOTE_ON_SHARED_ERRORS", REMOTE_ON_SHARED_ERRORS),
                ("PENDING_SHARED_ERRORS", PENDING_SHARED_ERRORS),
            ],
        },
    ]
}

/// Every leaf of `root` by its full path ("events dead-letters"), skipping clap's generated `help` nodes. `root`
/// is built first, so the generated nodes exist and can be skipped by name.
pub(crate) fn leaf_paths(root: &clap::Command) -> Vec<(String, clap::Command)> {
    fn walk(command: &clap::Command, prefix: &str, out: &mut Vec<(String, clap::Command)>) {
        let subs: Vec<&clap::Command> = command
            .get_subcommands()
            .filter(|sub| sub.get_name() != "help")
            .collect();
        if subs.is_empty() {
            out.push((prefix.to_string(), command.clone()));
            return;
        }
        for sub in subs {
            let path = if prefix.is_empty() {
                sub.get_name().to_string()
            } else {
                format!("{prefix} {}", sub.get_name())
            };
            walk(sub, &path, out);
        }
    }
    let mut root = root.clone();
    root.build();
    let mut out = Vec::new();
    walk(&root, "", &mut out);
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Every defect of `families` against `root`'s leaves, sorted; `Ok` when there is none.
///
/// Red scaffold: accepts everything until the checker lands.
pub(crate) fn check(
    root: &clap::Command,
    families: &[Family<'_>],
    format_run_proven: &[&str],
) -> Result<(), Vec<String>> {
    let _ = (root, families, format_run_proven);
    Ok(())
}

#[cfg(test)]
#[path = "command_classes_tests.rs"]
mod tests;
