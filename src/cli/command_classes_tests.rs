// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for MIK-9680.CLIUX.18 and .19 (test plan T1-T4): every leaf command is classed, the classes match the
//! leaves' real arguments, the checker names each defect, and the CLI reference matches the lists.

use super::*;
use clap::{Arg, ArgAction, CommandFactory as _};

/// The leaf commands at the base, as typed: 60 with the `runtime-substrate` feature, 59 without (A3: an empty
/// tree cannot pass).
const LEAVES: &[&str] = &[
    "accounts init-store",
    "accounts migrate-credentials",
    "add",
    "api",
    "audit lookup-email",
    "audit show",
    "audit verify",
    "cap discover",
    "cap import",
    "cap import-url",
    "cap install",
    "cap list",
    "cap pin",
    "cap registry-list",
    "cap search",
    "cap test",
    "cap validate",
    "dashboard-link",
    "doctor",
    "events dead-letters",
    "get",
    "hash-key",
    "identity grants grant",
    "identity grants list",
    "identity grants revoke",
    "import apply",
    "import preview",
    "init",
    "kubernetes apply-plan",
    "kubernetes controller",
    "kubernetes plan",
    "list",
    "provenance public-key",
    "provenance verify",
    "ranking eval",
    "remove",
    #[cfg(feature = "runtime-substrate")]
    "runtime compile",
    "serve",
    "setup export",
    "setup wizard",
    "skills generate",
    "skills import",
    "skills list",
    "skills remove",
    "skills search",
    "skills show",
    "stats",
    "tls init-ca",
    "tls issue-client",
    "tls issue-server",
    "tool completions",
    "tool inspect",
    "tool invoke",
    "tool list",
    "trust generate",
    "trust inspect",
    "trust lab evaluate",
    "trust validate",
    "upgrade",
    "validate",
];

/// The reviewed members of `JSON_CAPABLE` (design D7, inventory.md).
const WANT_JSON_CAPABLE: &[&str] = &[
    "api",
    "cap discover",
    "doctor",
    "identity grants grant",
    "identity grants list",
    "identity grants revoke",
    "import apply",
    "import preview",
    "kubernetes apply-plan",
    "kubernetes controller",
    "kubernetes plan",
    "list",
    "ranking eval",
    "tool inspect",
    "tool invoke",
    "tool list",
    "trust generate",
    "trust inspect",
    "trust lab evaluate",
    "trust validate",
    "validate",
];

/// The reviewed members of `JSON_DEFAULT` (design D7, inventory.md).
const WANT_JSON_DEFAULT: &[&str] = &[
    "audit lookup-email",
    "events dead-letters",
    "provenance public-key",
    #[cfg(feature = "runtime-substrate")]
    "runtime compile",
];

/// The reviewed members of `PENDING_JSON` (design D7, inventory.md).
const WANT_PENDING_JSON: &[&str] = &[
    "audit show",
    "audit verify",
    "cap list",
    "cap registry-list",
    "cap search",
    "cap test",
    "cap validate",
    "dashboard-link",
    "get",
    "hash-key",
    "provenance verify",
    "skills list",
    "skills search",
    "skills show",
    "stats",
];

/// The reviewed members of `ACTION` (design D7, inventory.md).
const WANT_ACTION: &[&str] = &[
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

/// The reviewed members of `SCRIPT` (design D7, inventory.md).
const WANT_SCRIPT: &[&str] = &["tool completions"];

/// The four commands on the shared error shape.
const WANT_REMOTE_ON_SHARED_ERRORS: &[&str] = &[
    "api",
    "audit lookup-email",
    "dashboard-link",
    "events dead-letters",
];

/// Every other leaf, until `MIK-9765.LERR.2`.
const WANT_PENDING_SHARED_ERRORS: &[&str] = &[
    "accounts init-store",
    "accounts migrate-credentials",
    "add",
    "audit show",
    "audit verify",
    "cap discover",
    "cap import",
    "cap import-url",
    "cap install",
    "cap list",
    "cap pin",
    "cap registry-list",
    "cap search",
    "cap test",
    "cap validate",
    "doctor",
    "get",
    "hash-key",
    "identity grants grant",
    "identity grants list",
    "identity grants revoke",
    "import apply",
    "import preview",
    "init",
    "kubernetes apply-plan",
    "kubernetes controller",
    "kubernetes plan",
    "list",
    "provenance public-key",
    "provenance verify",
    "ranking eval",
    "remove",
    #[cfg(feature = "runtime-substrate")]
    "runtime compile",
    "serve",
    "setup export",
    "setup wizard",
    "skills generate",
    "skills import",
    "skills list",
    "skills remove",
    "skills search",
    "skills show",
    "stats",
    "tls init-ca",
    "tls issue-client",
    "tls issue-server",
    "tool completions",
    "tool inspect",
    "tool invoke",
    "tool list",
    "trust generate",
    "trust inspect",
    "trust lab evaluate",
    "trust validate",
    "upgrade",
    "validate",
];

fn real_leaves() -> Vec<String> {
    leaf_paths(&crate::cli::Cli::command())
        .into_iter()
        .map(|(path, _)| path)
        .collect()
}

fn sorted(items: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = items.iter().map(|s| (*s).to_string()).collect();
    out.sort();
    out
}

/// T1, T3: the leaves are the literal 60; each list holds exactly its reviewed members; the checker accepts the
/// real tree.
#[test]
fn command_classes_cover_the_real_tree() {
    assert_eq!(real_leaves(), sorted(LEAVES), "the tree's leaf commands");
    let want: [(&str, &[&str], &[&str]); 7] = [
        ("JSON_CAPABLE", JSON_CAPABLE, WANT_JSON_CAPABLE),
        ("JSON_DEFAULT", JSON_DEFAULT, WANT_JSON_DEFAULT),
        ("PENDING_JSON", PENDING_JSON, WANT_PENDING_JSON),
        ("ACTION", ACTION, WANT_ACTION),
        ("SCRIPT", SCRIPT, WANT_SCRIPT),
        (
            "REMOTE_ON_SHARED_ERRORS",
            REMOTE_ON_SHARED_ERRORS,
            WANT_REMOTE_ON_SHARED_ERRORS,
        ),
        (
            "PENDING_SHARED_ERRORS",
            PENDING_SHARED_ERRORS,
            WANT_PENDING_SHARED_ERRORS,
        ),
    ];
    for (name, list, members) in want {
        assert_eq!(sorted(list), sorted(members), "{name}");
    }
    assert_eq!(
        sorted(FORMAT_RUN_PROVEN),
        sorted(&["cap discover"]),
        "FORMAT_RUN_PROVEN"
    );
    assert_eq!(
        check(&crate::cli::Cli::command(), &families(), FORMAT_RUN_PROVEN),
        Ok(())
    );
}

/// T1: each pending entry cites the ticket that empties its list, on its own source line.
#[test]
fn pending_entries_cite_their_tickets() {
    let source = include_str!("command_classes.rs");
    for (list, members, ticket) in [
        ("PENDING_JSON", WANT_PENDING_JSON, "// MIK-9764.JSONF.2"),
        (
            "PENDING_SHARED_ERRORS",
            WANT_PENDING_SHARED_ERRORS,
            "// MIK-9765.LERR.2",
        ),
    ] {
        let start = source
            .find(&format!("const {list}: &[&str] = &["))
            .unwrap_or_else(|| panic!("{list} is not in command_classes.rs"));
        let block = &source[start..start + source[start..].find("];").expect("the list ends")];
        for member in members {
            let line = block
                .lines()
                .find(|line| line.trim_start().starts_with(&format!("\"{member}\",")))
                .unwrap_or_else(|| panic!("{list}: no line for {member:?}"));
            assert!(
                line.trim_end().ends_with(ticket),
                "{list}: {member:?} must cite {ticket}: {line:?}"
            );
        }
    }
}

fn json_flag() -> Arg {
    Arg::new("json").long("json").action(ArgAction::SetTrue)
}

fn format_arg(values: [&'static str; 2]) -> Arg {
    Arg::new("format").long("format").value_parser(values)
}

/// A root with leaves `a` (given `args`) and `b` (no arguments).
fn tree(args: Vec<Arg>) -> clap::Command {
    clap::Command::new("root")
        .subcommand(clap::Command::new("a").args(args))
        .subcommand(clap::Command::new("b"))
}

/// One family holding the five classes, with `a` in `class_of_a` and `b` in ACTION.
fn classes<'a>(
    class_of_a: &'a str,
    extra: &'a [(&'a str, &'a [&'a str])],
) -> Vec<(&'a str, Vec<&'a str>)> {
    let mut lists: Vec<(&str, Vec<&str>)> = [
        "JSON_CAPABLE",
        "JSON_DEFAULT",
        "PENDING_JSON",
        "ACTION",
        "SCRIPT",
    ]
    .into_iter()
    .map(|name| (name, Vec::new()))
    .collect();
    for (name, members) in &mut lists {
        if *name == class_of_a {
            members.push("a");
        }
        if *name == "ACTION" {
            members.push("b");
        }
    }
    for (name, more) in extra {
        let entry = lists
            .iter_mut()
            .find(|(n, _)| n == name)
            .expect("a class name");
        entry.1.extend_from_slice(more);
    }
    lists
}

fn check_one(root: &clap::Command, lists: &[(&str, Vec<&str>)]) -> Result<(), Vec<String>> {
    check_proven(root, lists, &[])
}

fn check_proven(
    root: &clap::Command,
    lists: &[(&str, Vec<&str>)],
    proven: &[&str],
) -> Result<(), Vec<String>> {
    let borrowed: Vec<(&str, &[&str])> = lists.iter().map(|(n, m)| (*n, m.as_slice())).collect();
    check(
        root,
        &[Family {
            name: "classes",
            lists: &borrowed,
        }],
        proven,
    )
}

fn refused(message: &str) -> Result<(), Vec<String>> {
    Err(vec![message.to_string()])
}

/// T2: each defect, staged alone on a synthetic tree, is named by the checker; a clean tree passes.
#[test]
fn class_checker_names_each_defect() {
    let plain = tree(vec![]);
    // (a) a leaf in no list: `a` is left out of every class.
    assert_eq!(
        check_one(&plain, &classes("none", &[])),
        refused("classes: a is in no list")
    );
    // (b) a list entry with no leaf.
    assert_eq!(
        check_one(
            &tree(vec![json_flag()]),
            &classes("JSON_CAPABLE", &[("ACTION", &["zz"][..])])
        ),
        refused("classes: ACTION names zz, which is not a command")
    );
    // (c) a leaf in two lists of one family.
    assert_eq!(
        check_one(
            &tree(vec![json_flag()]),
            &classes("JSON_CAPABLE", &[("ACTION", &["a"][..])])
        ),
        refused("classes: a is in both JSON_CAPABLE and ACTION")
    );
    // (d) JSON_CAPABLE with neither argument.
    assert_eq!(
        check_one(&plain, &classes("JSON_CAPABLE", &[])),
        refused("JSON_CAPABLE: a has no json or format argument")
    );
    // (e) a format argument whose values lack json.
    assert_eq!(
        check_one(
            &tree(vec![format_arg(["table", "plain"])]),
            &classes("JSON_CAPABLE", &[])
        ),
        refused("JSON_CAPABLE: a has a format argument without the value json")
    );
    // (f), (g) PENDING_JSON with either argument.
    assert_eq!(
        check_one(&tree(vec![json_flag()]), &classes("PENDING_JSON", &[])),
        refused("PENDING_JSON: a has a json argument")
    );
    assert_eq!(
        check_one(
            &tree(vec![format_arg(["json", "table"])]),
            &classes("PENDING_JSON", &[])
        ),
        refused("PENDING_JSON: a has a format argument")
    );
    // (h), (i) JSON_DEFAULT with either argument.
    assert_eq!(
        check_one(&tree(vec![json_flag()]), &classes("JSON_DEFAULT", &[])),
        refused("JSON_DEFAULT: a has a json argument")
    );
    assert_eq!(
        check_one(
            &tree(vec![format_arg(["json", "table"])]),
            &classes("JSON_DEFAULT", &[])
        ),
        refused("JSON_DEFAULT: a has a format argument")
    );
    // (k) a free-text format (no declared values) with no row proving json (the lead, 2026-11-17).
    let free = tree(vec![Arg::new("format").long("format")]);
    assert_eq!(
        check_one(&free, &classes("JSON_CAPABLE", &[])),
        refused("JSON_CAPABLE: a has a free-text format argument with no row proving json")
    );
    // (l) the same leaf, on the proven list, passes.
    assert_eq!(
        check_proven(&free, &classes("JSON_CAPABLE", &[]), &["a"]),
        Ok(())
    );
    // (j) the permitted side: each class with the arguments it allows.
    assert_eq!(
        check_one(&tree(vec![json_flag()]), &classes("JSON_CAPABLE", &[])),
        Ok(())
    );
    assert_eq!(
        check_one(
            &tree(vec![format_arg(["json", "table"])]),
            &classes("JSON_CAPABLE", &[])
        ),
        Ok(())
    );
    assert_eq!(check_one(&plain, &classes("PENDING_JSON", &[])), Ok(()));
    assert_eq!(check_one(&plain, &classes("JSON_DEFAULT", &[])), Ok(()));
}

/// The rows of the markdown table under `heading` in `doc`, cells trimmed and backticks removed; header and
/// separator rows skipped.
fn table_rows(doc: &str, heading: &str) -> Vec<Vec<String>> {
    let Some(start) = doc.find(&format!("\n{heading}\n")) else {
        return Vec::new();
    };
    let section = &doc[start + heading.len() + 2..];
    let section = &section[..section.find("\n## ").unwrap_or(section.len())];
    section
        .lines()
        .filter(|line| line.trim_start().starts_with('|'))
        .map(|line| {
            line.trim()
                .trim_matches('|')
                .split('|')
                .map(|cell| cell.trim().trim_matches('`').to_string())
                .collect::<Vec<String>>()
        })
        .filter(|cells| {
            !cells
                .iter()
                .all(|c| c.chars().all(|ch| matches!(ch, '-' | ':')))
        })
        .skip(1)
        .collect()
}

/// T4: the CLI reference holds the exit table, the class of every leaf, and the JSON-default contract.
#[test]
fn cli_reference_matches_the_code() {
    let doc = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/CLI.md"))
        .unwrap_or_default();
    let exits: Vec<Vec<String>> = [
        ("0", "ok"),
        ("1", "local failure"),
        ("2", "usage"),
        ("3", "auth refused"),
        ("4", "not found"),
        ("5", "network"),
        ("6", "gateway"),
        ("7", "declined (reserved)"),
        ("8", "uncertain outcome"),
        ("130", "interrupted (reserved)"),
    ]
    .iter()
    .map(|(code, meaning)| vec![(*code).to_string(), (*meaning).to_string()])
    .collect();
    assert_eq!(
        table_rows(&doc, "## Exit codes"),
        exits,
        "docs/CLI.md exit table"
    );
    let mut classes: Vec<Vec<String>> = [
        ("JSON_CAPABLE", WANT_JSON_CAPABLE),
        ("JSON_DEFAULT", WANT_JSON_DEFAULT),
        ("PENDING_JSON", WANT_PENDING_JSON),
        ("ACTION", WANT_ACTION),
        ("SCRIPT", WANT_SCRIPT),
    ]
    .iter()
    .flat_map(|(class, members)| {
        members
            .iter()
            .map(move |m| vec![(*m).to_string(), (*class).to_string()])
    })
    .collect();
    // The page documents every command of a full build, the feature-gated one included.
    if !cfg!(feature = "runtime-substrate") {
        classes.push(vec![
            "runtime compile".to_string(),
            "JSON_DEFAULT".to_string(),
        ]);
    }
    classes.sort();
    let mut documented = table_rows(&doc, "## Command classes");
    documented.sort();
    assert_eq!(documented, classes, "docs/CLI.md class table");
    assert!(
        doc.contains(
            "stdout is JSON, errors are human text on stderr, and a script reads the exit code"
        ),
        "docs/CLI.md states the JSON-default contract"
    );
}
