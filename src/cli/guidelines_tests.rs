// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the CLI's help, naming, man page and version (MIK-9681.CLIUX.18-.20; test plan r3, frozen). Gated on the
//! features that add CLI commands, so CI's `--all-features` lib run walks every command.

use clap::CommandFactory;

const SURFACE: &str = include_str!("../../docs/design/surface-4.0.md");

/// The real tree, built, so generated parts and bin names exist.
fn built() -> clap::Command {
    let mut root = crate::cli::Cli::command();
    root.build();
    root
}

/// Every command with its path below the root (`""` for the root), hidden ones included, clap's generated `help`
/// subcommands left out.
fn walk(cmd: &clap::Command, path: &mut Vec<String>, out: &mut Vec<(String, clap::Command)>) {
    out.push((path.join(" "), cmd.clone()));
    for sub in cmd.get_subcommands() {
        if sub.get_name() == "help" {
            continue;
        }
        path.push(sub.get_name().to_owned());
        walk(sub, path, out);
        path.pop();
    }
}

fn all_commands() -> Vec<(String, clap::Command)> {
    let mut out = Vec::new();
    walk(&built(), &mut Vec::new(), &mut out);
    out
}

/// The command paths `## Surface: cli` lists (rows naming only words), clap's `help` rows left out, plus the root.
fn surface_paths() -> std::collections::BTreeSet<String> {
    let section = SURFACE
        .split("\n## Surface: cli")
        .nth(1)
        .and_then(|rest| rest.split("\n## ").next())
        .expect("the surface doc has a `## Surface: cli` section");
    let mut paths: std::collections::BTreeSet<String> = section
        .lines()
        .filter_map(|line| line.strip_prefix("| `mcp-gateway "))
        .filter_map(|rest| rest.split_once('`').map(|(entry, _)| entry))
        .filter(|entry| {
            entry.split(' ').all(|word| {
                !word.is_empty()
                    && word
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            })
        })
        .filter(|entry| entry.split(' ').next_back() != Some("help"))
        .map(str::to_owned)
        .collect();
    paths.insert(String::new());
    paths
}

/// What H1 checks on one command's two renders: an about text that both show, a usage line, an options section, and
/// in the long render an `Examples:` section with at least one `mcp-gateway ...` line.
fn help_problems(path: &str, cmd: &clap::Command) -> Vec<String> {
    let mut problems = Vec::new();
    let about = cmd.get_about().map(ToString::to_string).unwrap_or_default();
    if about.trim().is_empty() {
        problems.push(format!("`{path}`: no about text"));
    }
    let short = cmd.clone().render_help().to_string();
    let long = cmd.clone().render_long_help().to_string();
    for (name, text) in [("-h", &short), ("--help", &long)] {
        if !about.trim().is_empty() && !text.lines().any(|l| l.trim() == about.trim()) {
            problems.push(format!("`{path}` {name}: the about text is not a line"));
        }
        if !text.lines().any(|l| l.starts_with("Usage: ")) {
            problems.push(format!("`{path}` {name}: no `Usage: ` line"));
        }
        if !text.lines().any(|l| l == "Options:") {
            problems.push(format!("`{path}` {name}: no `Options:` line"));
        }
    }
    if example_lines(&long).is_empty() {
        problems.push(format!(
            "`{path}` --help: no `Examples:` section with an `mcp-gateway` line"
        ));
    }
    problems
}

/// The `mcp-gateway ...` lines under `Examples:` in a long render.
fn example_lines(long: &str) -> Vec<String> {
    long.lines()
        .skip_while(|l| l.trim() != "Examples:")
        .skip(1)
        .take_while(|l| !l.trim().is_empty())
        .map(str::trim)
        .filter(|l| l.starts_with("mcp-gateway "))
        .map(str::to_owned)
        .collect()
}

/// H2 on one command: every example splits; at least one is actionable (not `--help`, `-h` or `--version` alone) and
/// parses to the command itself or, for a group, to one of its descendants.
fn example_problems(root: &clap::Command, path: &str, long: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let mut actionable = false;
    for line in example_lines(long) {
        let Some(words) = shlex::split(&line) else {
            problems.push(format!("`{path}`: cannot split `{line}`"));
            continue;
        };
        let rest = &words[1..];
        if matches!(rest, [one] if one == "--help" || one == "-h" || one == "--version") {
            continue;
        }
        let Ok(matches) = root.clone().try_get_matches_from(&words) else {
            continue;
        };
        let mut matched = Vec::new();
        let mut at = &matches;
        while let Some((name, sub)) = at.subcommand() {
            matched.push(name.to_owned());
            at = sub;
        }
        let visited: Vec<&str> = if path.is_empty() {
            Vec::new()
        } else {
            path.split(' ').collect()
        };
        if matched.len() >= visited.len() && matched.iter().zip(&visited).all(|(m, v)| m == v) {
            actionable = true;
        }
    }
    if !actionable {
        problems.push(format!("`{path}`: no actionable example parses to it"));
    }
    problems
}

/// H1 (MIK-9681.CLIUX.18): every command, hidden ones included, has an about text, a usage line, an options section
/// and an examples section; the walk covers exactly the commands the surface doc lists, each once.
#[test]
fn every_command_has_help_with_examples() {
    let commands = all_commands();
    let visited: Vec<&str> = commands.iter().map(|(p, _)| p.as_str()).collect();
    let unique: std::collections::BTreeSet<String> =
        visited.iter().map(|p| (*p).to_owned()).collect();
    assert_eq!(unique.len(), visited.len(), "a command was visited twice");
    assert_eq!(
        unique,
        surface_paths(),
        "the walk and `## Surface: cli` disagree"
    );
    let problems: Vec<String> = commands
        .iter()
        .flat_map(|(p, c)| help_problems(p, c))
        .collect();
    assert_eq!(problems, Vec::<String>::new());
}

/// H1's negative proof: a command with no about text is reported.
#[test]
fn a_command_without_about_is_reported() {
    let mut cmd = clap::Command::new("bare").after_long_help("Examples:\n  mcp-gateway bare\n");
    cmd.build();
    assert!(help_problems("bare", &cmd).contains(&"`bare`: no about text".to_owned()));
}

/// H2 (MIK-9681.CLIUX.18): every command has an example that parses to it.
#[test]
fn every_command_has_an_actionable_example() {
    let root = built();
    let problems: Vec<String> = all_commands()
        .iter()
        .flat_map(|(p, c)| example_problems(&root, p, &c.clone().render_long_help().to_string()))
        .collect();
    assert_eq!(problems, Vec::<String>::new());
}

/// H2's checker on a synthetic tree, one fault per case.
#[test]
fn the_example_checker_names_each_fault() {
    let root = clap::Command::new("mcp-gateway")
        .subcommand(clap::Command::new("a").arg(clap::Arg::new("x")))
        .subcommand(clap::Command::new("b"));
    let check =
        |examples: &str| example_problems(&root, "a", &format!("Examples:\n  {examples}\n"));
    assert_eq!(
        check("mcp-gateway b"),
        ["`a`: no actionable example parses to it"]
    );
    assert_eq!(
        check("mcp-gateway --help"),
        ["`a`: no actionable example parses to it"]
    );
    assert_eq!(
        check(r#"mcp-gateway a '{"city": "Oulu"}'"#),
        Vec::<String>::new()
    );
    assert_eq!(
        check("mcp-gateway a 'open"),
        [
            "`a`: cannot split `mcp-gateway a 'open`",
            "`a`: no actionable example parses to it"
        ]
    );
}

/// H3 (MIK-9681.CLIUX.18): a mistyped command suggests the closest one, from clap's own error context.
#[test]
fn a_mistyped_command_suggests_the_closest_match() {
    use clap::error::{ContextKind, ContextValue, ErrorKind};
    for (argv, suggested) in [
        (vec!["mcp-gateway", "stast"], "stats"),
        (vec!["mcp-gateway", "cap", "lsit"], "list"),
    ] {
        let err = built()
            .try_get_matches_from(&argv)
            .expect_err("a typo is refused");
        assert_eq!(err.kind(), ErrorKind::InvalidSubcommand, "{argv:?}");
        match err.get(ContextKind::SuggestedSubcommand) {
            Some(ContextValue::Strings(list)) => {
                assert_eq!(list, &vec![suggested.to_owned()], "{argv:?}")
            }
            other => panic!("{argv:?}: no suggestion: {other:?}"),
        }
    }
    let rendered = built()
        .try_get_matches_from(["mcp-gateway", "stast"])
        .unwrap_err()
        .to_string();
    assert!(
        rendered
            .lines()
            .any(|l| l == "  tip: a similar subcommand exists: 'stats'"),
        "{rendered}"
    );
}

// ── N rows: one meaning per flag name (CLIUX.19) ──────────────────────────────

/// What N1 reads from clap for one flag on one leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Signature {
    short: Option<char>,
    takes_value: bool,
    value_name: Option<String>,
    repeated: bool,
    required: bool,
    env: Option<String>,
    possible: Vec<String>,
}

fn signature(arg: &clap::Arg) -> Signature {
    Signature {
        short: arg.get_short(),
        takes_value: arg.get_action().takes_values(),
        value_name: arg
            .get_value_names()
            .and_then(|n| n.first())
            .map(ToString::to_string),
        repeated: matches!(
            arg.get_action(),
            clap::ArgAction::Append | clap::ArgAction::Count
        ),
        required: arg.is_required_set(),
        env: arg.get_env().map(|e| e.to_string_lossy().into_owned()),
        possible: arg
            .get_possible_values()
            .iter()
            .map(|v| v.get_name().to_owned())
            .collect(),
    }
}

/// Every visible leaf's long flags: (long name, leaf path, signature, help first line, default). A global argument
/// counts once, at the command that defines it; aliases count as their primary flag.
fn leaf_flags(root: &clap::Command) -> Vec<(String, String, Signature, String, Option<String>)> {
    let mut commands = Vec::new();
    walk(root, &mut Vec::new(), &mut commands);
    let mut out = Vec::new();
    for (path, cmd) in commands {
        if cmd.has_subcommands() && !path.is_empty() {
            continue;
        }
        for arg in cmd.get_arguments() {
            let Some(long) = arg.get_long() else { continue };
            if arg.is_hide_set() || long == "help" || long == "version" {
                continue;
            }
            if arg.is_global_set() && !path.is_empty() {
                continue;
            }
            let help = arg.get_help().map(ToString::to_string).unwrap_or_default();
            let first = help.lines().next().unwrap_or_default().to_owned();
            let default = arg
                .get_default_values()
                .first()
                .map(|v| v.to_string_lossy().into_owned());
            out.push((
                format!("--{long}"),
                path.clone(),
                signature(arg),
                first,
                default,
            ));
        }
    }
    out
}

/// The ruled meaning and signature of a flag name used on two or more leaves.
struct Ruled {
    long: &'static str,
    meaning: &'static str,
    signature: fn() -> Signature,
}

/// A leaf whose use of a shared flag means something else, until the ticket that ends it.
struct Exception {
    long: &'static str,
    leaf: &'static str,
    meaning: &'static str,
    ticket: &'static str,
}

/// N1's checker: for every flag on two or more leaves, a ruled entry (or an exception for that leaf), the same
/// signature on every leaf, the ruled meaning as each leaf's help first line, and the leaf's literal default. A short
/// letter reused for two long names is a finding. Findings name the flag, the leaf, the field and both values.
fn flag_problems(
    observed: &[(String, String, Signature, String, Option<String>)],
    ruled: &[Ruled],
    exceptions: &[Exception],
    defaults: &[(&str, &str, Option<&str>)],
) -> Vec<String> {
    use std::collections::BTreeMap;
    let mut by_flag: BTreeMap<&str, Vec<&(String, String, Signature, String, Option<String>)>> =
        BTreeMap::new();
    for row in observed {
        by_flag.entry(row.0.as_str()).or_default().push(row);
    }
    let mut problems = Vec::new();
    let mut shorts: BTreeMap<char, std::collections::BTreeSet<&str>> = BTreeMap::new();
    for row in observed {
        if let Some(c) = row.2.short {
            shorts.entry(c).or_default().insert(row.0.as_str());
        }
    }
    for (c, longs) in &shorts {
        if longs.len() > 1 {
            problems.push(format!("-{c}: one short letter for {longs:?}"));
        }
    }
    for (flag, rows) in &by_flag {
        let exception_leaves: Vec<&Exception> =
            exceptions.iter().filter(|e| e.long == *flag).collect();
        if rows.len() < 2 && exception_leaves.is_empty() {
            continue;
        }
        for e in &exception_leaves {
            if e.ticket.is_empty() {
                problems.push(format!(
                    "{flag} on `{}`: an exception names no ticket",
                    e.leaf
                ));
            }
        }
        let rule = ruled.iter().find(|r| r.long == *flag);
        let leaves: Vec<&str> = rows.iter().map(|r| r.1.as_str()).collect();
        for (_, leaf, sig, first, default) in rows.iter().map(|r| (&r.0, &r.1, &r.2, &r.3, &r.4)) {
            if let Some(e) = exception_leaves.iter().find(|e| e.leaf == leaf) {
                if first != e.meaning {
                    problems.push(format!(
                        "{flag} on `{leaf}`: help `{first}`, exception says `{}`",
                        e.meaning
                    ));
                }
                continue;
            }
            let Some(rule) = rule else {
                problems.push(format!("{flag}: no entry (leaves {leaves:?})"));
                break;
            };
            let expected = (rule.signature)();
            if *sig != expected {
                problems.push(format!(
                    "{flag} on `{leaf}`: signature {sig:?}, ruled {expected:?}"
                ));
            }
            if first != rule.meaning {
                problems.push(format!(
                    "{flag} on `{leaf}`: help `{first}`, ruled `{}`",
                    rule.meaning
                ));
            }
            let want = defaults
                .iter()
                .find(|(f, l, _)| f == flag && l == leaf)
                .map(|(_, _, d)| *d);
            if want != Some(default.as_deref()) {
                problems.push(format!(
                    "{flag} on `{leaf}`: default {default:?}, ruled {want:?}"
                ));
            }
        }
    }
    problems
}

/// The ruled table (N1). Each entry: the flag, its one meaning sentence, its signature; exceptions per leaf with
/// the ticket that ends them; and each leaf's literal default.
const RULED: &[Ruled] = &[];
const EXCEPTIONS: &[Exception] = &[];
const DEFAULTS: &[(&str, &str, Option<&str>)] = &[];

/// N1 (MIK-9681.CLIUX.19): one meaning per flag name across the tree. On failure it also prints what it observed for
/// every shared flag, so a reviewer can read the table against the tree.
#[test]
fn a_flag_name_means_one_thing_on_every_leaf() {
    let observed = leaf_flags(&built());
    let problems = flag_problems(&observed, RULED, EXCEPTIONS, DEFAULTS);
    let mut counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for row in &observed {
        *counts.entry(row.0.as_str()).or_default() += 1;
    }
    let shared: std::collections::BTreeSet<&str> = counts
        .iter()
        .filter(|(_, n)| **n > 1)
        .map(|(f, _)| *f)
        .collect();
    let mut keys: std::collections::BTreeSet<&str> = RULED.iter().map(|r| r.long).collect();
    keys.extend(EXCEPTIONS.iter().map(|e| e.long));
    let observed_dump: Vec<String> = observed
        .iter()
        .filter(|r| shared.contains(r.0.as_str()))
        .map(|r| format!("{} | {} | {:?} | {} | {:?}", r.0, r.1, r.2, r.3, r.4))
        .collect();
    assert_eq!(
        keys,
        shared,
        "the table's flags and the shared flags differ\n{}",
        observed_dump.join("\n")
    );
    assert_eq!(
        problems,
        Vec::<String>::new(),
        "\n{}",
        observed_dump.join("\n")
    );
}

/// A synthetic tree: one root with leaves `a` and `b`, each given `args`.
fn synthetic(
    a: Vec<clap::Arg>,
    b: Vec<clap::Arg>,
) -> Vec<(String, String, Signature, String, Option<String>)> {
    let mut root = clap::Command::new("mcp-gateway")
        .subcommand(clap::Command::new("a").args(a))
        .subcommand(clap::Command::new("b").args(b));
    root.build();
    leaf_flags(&root)
}

fn plain_value() -> Signature {
    Signature {
        short: None,
        takes_value: true,
        value_name: Some("X".into()),
        repeated: false,
        required: false,
        env: None,
        possible: vec![],
    }
}

/// N2-N4: the checker names each fault on a synthetic tree, one fault per case; a clean tree gives nothing.
#[test]
fn the_flag_checker_names_each_fault() {
    let ruled = [Ruled {
        long: "--x",
        meaning: "The x.",
        signature: plain_value,
    }];
    let defaults = [("--x", "a", None), ("--x", "b", None)];
    let arg = |name: &str| {
        clap::Arg::new("x")
            .long("x")
            .value_name(name)
            .help("The x.")
    };
    // control
    assert_eq!(
        flag_problems(
            &synthetic(vec![arg("X")], vec![arg("X")]),
            &ruled,
            &[],
            &defaults
        ),
        Vec::<String>::new()
    );
    // N2: different value names
    assert_eq!(
        flag_problems(
            &synthetic(vec![arg("X")], vec![arg("Y")]),
            &ruled,
            &[],
            &defaults
        ),
        [format!(
            "--x on `b`: signature {:?}, ruled {:?}",
            Signature {
                value_name: Some("Y".into()),
                ..plain_value()
            },
            plain_value()
        )]
    );
    // N3: no entry
    assert_eq!(
        flag_problems(
            &synthetic(vec![arg("X")], vec![arg("X")]),
            &[],
            &[],
            &defaults
        ),
        [r#"--x: no entry (leaves ["a", "b"])"#.to_owned()]
    );
    // N4: one short letter for two long names
    let short = |long: &'static str| {
        clap::Arg::new(long)
            .long(long)
            .short('q')
            .action(clap::ArgAction::SetTrue)
            .help("Q.")
    };
    assert_eq!(
        flag_problems(
            &synthetic(vec![short("one")], vec![short("two")]),
            &[],
            &[],
            &[]
        ),
        [r#"-q: one short letter for {"--one", "--two"}"#.to_owned()]
    );
}

/// N5 (MIK-9681.CLIUX.19): tls `--out` becomes `--output`; `--out`, `--out=` and `-o` still parse to the same directory,
/// and help shows `--output` and no `--out` token.
#[test]
fn tls_output_keeps_out_as_a_hidden_alias() {
    let leaves: [&[&str]; 3] = [
        &["tls", "init-ca", "--cn", "x"],
        &[
            "tls",
            "issue-server",
            "--ca-cert",
            "a",
            "--ca-key",
            "b",
            "--cn",
            "x",
        ],
        &[
            "tls",
            "issue-client",
            "--ca-cert",
            "a",
            "--ca-key",
            "b",
            "--cn",
            "x",
        ],
    ];
    for leaf in leaves {
        for spelling in [
            &["--out", "D"][..],
            &["--out=D"],
            &["-o", "D"],
            &["--output", "D"],
        ] {
            let mut argv = vec!["mcp-gateway"];
            argv.extend_from_slice(leaf);
            argv.extend_from_slice(spelling);
            let matches = built()
                .try_get_matches_from(&argv)
                .unwrap_or_else(|e| panic!("{argv:?}: {e}"));
            let mut at = &matches;
            while let Some((_, sub)) = at.subcommand() {
                at = sub;
            }
            let dir = at
                .get_one::<std::path::PathBuf>("output")
                .map(|p| p.display().to_string());
            assert_eq!(dir.as_deref(), Some("D"), "{argv:?}");
        }
        let mut cmd = built();
        let mut node = &mut cmd;
        for name in &leaf[..2] {
            node = node.find_subcommand_mut(name).expect("leaf");
        }
        let arg = node
            .get_arguments()
            .find(|a| a.get_long() == Some("output"))
            .expect("--output");
        assert_eq!(arg.get_visible_aliases(), None, "{leaf:?}");
        let help = node.clone().render_long_help().to_string();
        let tokens: Vec<&str> = help
            .split(|c: char| c.is_whitespace() || c == ',')
            .collect();
        assert!(tokens.contains(&"--output"), "{leaf:?}: {help}");
        assert!(
            !tokens
                .iter()
                .any(|t| *t == "--out" || t.starts_with("--out=")),
            "{leaf:?}: {help}"
        );
    }
}

// ── M1: the man page renderer (CLIUX.20) ──────────────────────────────────────

/// The 25 visible top-level commands, written here (the row also checks the tree agrees).
const TOP_LEVEL: [&str; 25] = [
    "accounts",
    "add",
    "api",
    "audit",
    "cap",
    "dashboard-link",
    "doctor",
    "events",
    "get",
    "hash-key",
    "help",
    "identity",
    "import",
    "init",
    "list",
    "provenance",
    "remove",
    "serve",
    "setup",
    "skills",
    "stats",
    "tls",
    "tool",
    "upgrade",
    "validate",
];

/// M1: the page's `.TH` line names the package version (read from Cargo.toml), it has NAME and SYNOPSIS, and its
/// SUBCOMMANDS entries are exactly the visible top-level commands; hidden commands are checked only as entries.
#[test]
fn the_man_page_lists_the_top_level_commands() {
    let version = include_str!("../../Cargo.toml")
        .lines()
        .find_map(|l| l.strip_prefix("version = \""))
        .and_then(|r| r.strip_suffix('"'))
        .expect("package version");
    let visible: std::collections::BTreeSet<String> = built()
        .get_subcommands()
        .filter(|c| !c.is_hide_set())
        .map(|c| c.get_name().to_owned())
        .collect();
    let listed: std::collections::BTreeSet<String> =
        TOP_LEVEL.iter().map(|s| (*s).to_owned()).collect();
    assert_eq!(
        visible, listed,
        "the written list and the tree's visible top-level commands differ"
    );
    let page = super::man_page_render::render(crate::cli::Cli::command());
    assert!(
        page.lines()
            .any(|l| l == format!(".TH mcp-gateway 1  \"mcp-gateway {version}\"")),
        "{page}"
    );
    assert!(
        page.lines().any(|l| l == ".SH NAME") && page.lines().any(|l| l == ".SH SYNOPSIS"),
        "{page}"
    );
    let lines: Vec<&str> = page.lines().collect();
    let entries: std::collections::BTreeSet<String> = lines
        .windows(2)
        .filter(|w| w[0] == ".TP")
        .filter_map(|w| {
            w[1].replace("\\-", "-")
                .strip_prefix("mcp-gateway-")
                .map(str::to_owned)
        })
        .filter_map(|e| e.strip_suffix("(1)").map(str::to_owned))
        .collect();
    assert_eq!(entries, listed, "{page}");
}
