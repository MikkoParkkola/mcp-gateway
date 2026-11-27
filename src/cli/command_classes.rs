// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every leaf command's output class (design D7), and the four remote leaves on the shared error shape.
//!
//! One family of named lists partitions the leaf commands, keyed by the full command path as
//! typed. The classes: `JSON_CAPABLE`, `JSON_DEFAULT`, `PENDING_JSON` (empty; a new data command without a JSON form goes there), `ACTION`, `SCRIPT`. `REMOTE_ON_SHARED_ERRORS` is a plain list, not a family: the local-errors behaviour table
//! (tests/cli_local_errors.rs) checks every other leaf. A row walks the real clap
//! tree and fails on a leaf missing from a family, a leaf in two lists of one family, a list naming no command, or a
//! class its arguments contradict, so a new command cannot ship off the output contract unnoticed.

/// Leaves with a JSON form: a `json` flag, or a `format` argument that accepts `json`.
pub(crate) const JSON_CAPABLE: &[&str] = &[
    "api",
    "audit verify",
    "cap discover",
    "cap list",
    "cap registry-list",
    "cap search",
    "cap test",
    "cap validate",
    "dashboard-link",
    "doctor",
    "get",
    "hash-key",
    "identity grants grant",
    "identity grants list",
    "identity grants revoke",
    "import apply",
    "import preview",
    "kubernetes apply-plan",
    "kubernetes controller",
    "kubernetes plan",
    "list",
    "provenance verify",
    "ranking eval",
    "skills list",
    "skills search",
    "skills show",
    "stats",
    "tool inspect",
    "tool invoke",
    "tool list",
    "trust generate",
    "trust inspect",
    "trust lab evaluate",
    "trust validate",
    "validate",
];
/// Leaves whose stdout is JSON with no flag; their errors stay human text on stderr (design D10).
pub(crate) const JSON_DEFAULT: &[&str] = &[
    "audit lookup-email",
    "audit show",
    "events dead-letters",
    "provenance public-key",
    #[cfg(feature = "runtime-substrate")]
    "runtime compile",
];
/// Leaves that print data with no JSON form yet: none, since every data command has one (`MIK-9764.JSONF.2`).
pub(crate) const PENDING_JSON: &[&str] = &[];
/// Leaves that act and print status only.
pub(crate) const ACTION: &[&str] = &[
    "accounts init-store",
    "accounts migrate-credentials",
    "add",
    "cap import",
    "cap import-url",
    "cap install",
    "cap pin",
    "init",
    "remove",
    "serve",
    "setup export",
    "setup wizard",
    "skills generate",
    "skills import",
    "skills remove",
    "tls init-ca",
    "tls issue-client",
    "tls issue-server",
    "upgrade",
];
/// Leaves that print a script.
pub(crate) const SCRIPT: &[&str] = &["tool completions"];
/// The remote leaves, which keep the remote error shape; the behaviour table subtracts them.
pub(crate) const REMOTE_ON_SHARED_ERRORS: &[&str] = &[
    "api",
    "audit lookup-email",
    "dashboard-link",
    "events dead-letters",
];
/// `JSON_CAPABLE` leaves whose `format` is free text (no declared values): each is classed JSON-capable only because
/// a row runs it with `--format json` and parses its stdout (the lead, 2026-11-17: no inference).
pub(crate) const FORMAT_RUN_PROVEN: &[&str] = &["cap discover"];

/// One family: named lists that must partition the leaves.
pub(crate) struct Family<'a> {
    pub(crate) name: &'a str,
    pub(crate) lists: &'a [(&'a str, &'a [&'a str])],
}

/// The family checked against the real tree.
pub(crate) fn families() -> [Family<'static>; 1] {
    [Family {
        name: "classes",
        lists: &[
            ("JSON_CAPABLE", JSON_CAPABLE),
            ("JSON_DEFAULT", JSON_DEFAULT),
            ("PENDING_JSON", PENDING_JSON),
            ("ACTION", ACTION),
            ("SCRIPT", SCRIPT),
        ],
    }]
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

/// Every defect of `families` against `root`'s leaves, sorted; `Ok` when there is none. A family's lists must
/// partition the leaves; a class must match its leaf's arguments: `JSON_CAPABLE` needs a `json` flag or a `format`
/// accepting `json` (a free-text `format` only when `format_run_proven` names the leaf), and `PENDING_JSON` and
/// `JSON_DEFAULT` must have neither.
pub(crate) fn check(
    root: &clap::Command,
    families: &[Family<'_>],
    format_run_proven: &[&str],
) -> Result<(), Vec<String>> {
    let leaves = leaf_paths(root);
    let mut defects = Vec::new();
    for family in families {
        let name = family.name;
        for (path, _) in &leaves {
            let homes: Vec<&str> = family
                .lists
                .iter()
                .filter(|(_, members)| members.contains(&path.as_str()))
                .map(|(list, _)| *list)
                .collect();
            match homes.as_slice() {
                [] => defects.push(format!("{name}: {path} is in no list")),
                [_] => {}
                [first, second, ..] => {
                    defects.push(format!("{name}: {path} is in both {first} and {second}"));
                }
            }
        }
        for (list, members) in family.lists {
            for member in *members {
                if !leaves.iter().any(|(path, _)| path == member) {
                    defects.push(format!(
                        "{name}: {list} names {member}, which is not a command"
                    ));
                }
            }
        }
        for (list, members) in family.lists {
            for (path, leaf) in leaves
                .iter()
                .filter(|(path, _)| members.contains(&path.as_str()))
            {
                let json = leaf
                    .get_arguments()
                    .any(|arg| arg.get_id() == "json" || arg.get_long() == Some("json"));
                let format = leaf
                    .get_arguments()
                    .find(|arg| arg.get_long() == Some("format"));
                match *list {
                    "JSON_CAPABLE" if json => {}
                    "JSON_CAPABLE" => match format.map(clap::Arg::get_possible_values) {
                        None => {
                            defects.push(format!("{list}: {path} has no json or format argument"));
                        }
                        Some(values) if values.is_empty() => {
                            if !format_run_proven.contains(&path.as_str()) {
                                defects.push(format!(
                                    "{list}: {path} has a free-text format argument with no row proving json"
                                ));
                            }
                        }
                        Some(values) => {
                            if !values.iter().any(|value| value.get_name() == "json") {
                                defects.push(format!(
                                    "{list}: {path} has a format argument without the value json"
                                ));
                            }
                        }
                    },
                    "PENDING_JSON" | "JSON_DEFAULT" => {
                        if json {
                            defects.push(format!("{list}: {path} has a json argument"));
                        }
                        if format.is_some() {
                            defects.push(format!("{list}: {path} has a format argument"));
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    defects.sort();
    if defects.is_empty() {
        Ok(())
    } else {
        Err(defects)
    }
}

#[cfg(tp1)]
#[cfg(test)]
#[path = "command_classes_tests.rs"]
mod tests;

#[cfg(tp1)]
#[cfg(test)]
#[path = "raw_exit_scan_tests.rs"]
mod raw_exit_scan_tests;
