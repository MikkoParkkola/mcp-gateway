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

/// As [`walk`], without hidden commands or anything under them: N1 judges the flags a user can see (lead ruling
/// 2026-11-19).
fn walk_visible(
    cmd: &clap::Command,
    path: &mut Vec<String>,
    out: &mut Vec<(String, clap::Command)>,
) {
    out.push((path.join(" "), cmd.clone()));
    for sub in cmd
        .get_subcommands()
        .filter(|sub| !sub.is_hide_set() && sub.get_name() != "help")
    {
        path.push(sub.get_name().to_owned());
        walk_visible(sub, path, out);
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
                    && !word.starts_with('-')
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
    // clap wraps a description at the help width and shows `long_about`, when a command has one, in `--help`: compare
    // with runs of whitespace collapsed, against the description each render shows.
    let flat = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
    let long_about = cmd
        .get_long_about()
        .map_or_else(|| about.clone(), ToString::to_string);
    for (name, text, description) in [("-h", &short, &about), ("--help", &long, &long_about)] {
        if !description.trim().is_empty() && !flat(text).contains(&flat(description)) {
            problems.push(format!("`{path}` {name}: the description is not shown"));
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
    // clap wraps the examples at the help width: a line in the section that does not start a new `mcp-gateway`
    // command continues the one before it.
    let mut examples: Vec<String> = Vec::new();
    for line in long
        .lines()
        .skip_while(|l| l.trim() != "Examples:")
        .skip(1)
        .take_while(|l| !l.trim().is_empty())
        .map(str::trim)
    {
        if line.starts_with("mcp-gateway ") {
            examples.push(line.to_owned());
        } else if let Some(open) = examples.last_mut() {
            open.push(' ');
            open.push_str(line);
        }
    }
    examples
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
    // An example clap wrapped onto a second line is read whole: alone, the first line is the case above.
    assert_eq!(check("mcp-gateway a 'open\nend'"), Vec::<String>::new());
}

// H3 (a typo suggests only visible commands) runs against the real binary: tests/cli_output_rows.rs.

#[path = "guidelines_flag_tests.rs"]
mod flags;

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
    // clap_mangen ends the `.TH` line with a space (an empty trailing field).
    assert!(
        page.lines()
            .any(|l| l.trim_end() == format!(".TH mcp-gateway 1  \"mcp-gateway {version}\"")),
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
