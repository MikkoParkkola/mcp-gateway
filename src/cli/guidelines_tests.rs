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
    if mutant!("h1b", false, about.trim().is_empty()) {
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
        } else if let Some(open) = mutant!("h2w", None, examples.last_mut()) {
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
            mutant!("h2s", (), problems.push(format!("`{path}`: cannot split `{line}`")));
            continue;
        };
        let rest = &words[1..];
        if mutant!("h2h", false, matches!(rest, [one] if one == "--help" || one == "-h" || one == "--version")) {
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
        if mutant!("h2p", true, matched.len() >= visited.len() && matched.iter().zip(&visited).all(|(m, v)| m == v)) {
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
    walk_visible(root, &mut Vec::new(), &mut commands);
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
        if mutant!("n4", false, longs.len() > 1) {
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
                mutant!("n3", (), problems.push(format!("{flag}: no entry (leaves {leaves:?})")));
                break;
            };
            let expected = (rule.signature)();
            if mutant!("n2", false, *sig != expected) {
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
// N1's table (lead ruling 2026-11-19): visible commands only; one ruled meaning and signature per shared flag;
// per-leaf exceptions where a flag really means something else there, each with its own meaning line.
const RULED: &[Ruled] = &[
    Ruled {
        long: "--ca-cert",
        meaning: "PEM CA the gateway's server certificate must chain to; replaces the built-in roots. Without it, a config-derived URL on an mTLS listener trusts only `mtls.ca_cert`",
        signature: sig_ca_cert,
    },
    Ruled {
        long: "--ca-key",
        meaning: "Path to the CA private key file",
        signature: sig_ca_key,
    },
    Ruled {
        long: "--capabilities",
        meaning: "Root directory containing capability definitions to index",
        signature: sig_capabilities,
    },
    Ruled {
        long: "--client-cert",
        meaning: "PEM client certificate for a listener that requires one (`mtls.require_client_cert`); pair with `--client-key`",
        signature: sig_client_cert,
    },
    Ruled {
        long: "--client-key",
        meaning: "PEM private key for `--client-cert`",
        signature: sig_client_key,
    },
    Ruled {
        long: "--cn",
        meaning: "Common Name of the certificate",
        signature: sig_cn,
    },
    Ruled {
        long: "--config",
        meaning: "Path to the gateway configuration file (YAML)",
        signature: sig_config,
    },
    Ruled {
        long: "--context-integrity-profile",
        meaning: "Context-integrity profile attached to generated draft policy defaults",
        signature: sig_context_integrity_profile,
    },
    Ruled {
        long: "--dry-run",
        meaning: "Show what would change without writing anything",
        signature: sig_dry_run,
    },
    Ruled {
        long: "--file",
        meaning: "Local JSON or YAML grant file",
        signature: sig_file,
    },
    Ruled {
        long: "--fix",
        meaning: "Fix the issues found, where possible",
        signature: sig_fix,
    },
    Ruled {
        long: "--force",
        meaning: "Overwrite what is already there",
        signature: sig_force,
    },
    Ruled {
        long: "--format",
        meaning: "Output format",
        signature: sig_format,
    },
    Ruled {
        long: "--grant-id",
        meaning: "The grant id",
        signature: sig_grant_id,
    },
    Ruled {
        long: "--kind",
        meaning: "Source format to import",
        signature: sig_kind,
    },
    Ruled {
        long: "--path",
        meaning: "Path to the log (default: ~/.mcp-gateway/transparency/transparency.jsonl)",
        signature: sig_path,
    },
    Ruled {
        long: "--prefix",
        meaning: "String prepended to every generated capability name (e.g. \"stripe\")",
        signature: sig_prefix,
    },
    Ruled {
        long: "--registry",
        meaning: "Registry file path (defaults to ~/.mcp-gateway/skills.json)",
        signature: sig_registry,
    },
    Ruled {
        long: "--validity-days",
        meaning: "Validity period in days",
        signature: sig_validity_days,
    },
];
const EXCEPTIONS: &[Exception] = &[
    Exception {
        long: "--ca-cert",
        leaf: "tls issue-server",
        meaning: "Path to the CA certificate file",
        ticket: "ruled 2026-11-19: different meaning, kept",
    },
    Exception {
        long: "--ca-cert",
        leaf: "tls issue-client",
        meaning: "Path to the CA certificate file",
        ticket: "ruled 2026-11-19: different meaning, kept",
    },
    Exception {
        long: "--cn",
        leaf: "tls init-ca",
        meaning: "Common Name of the certificate",
        ticket: "ruled 2026-11-19: optional here (it has a default), kept",
    },
    Exception {
        long: "--config",
        leaf: "setup export",
        meaning: "Gateway config file to read",
        ticket: "ruled 2026-11-19: different meaning, kept",
    },
    Exception {
        long: "--config",
        leaf: "doctor",
        meaning: "Gateway config file to inspect (auto-detected when omitted)",
        ticket: "ruled 2026-11-19: different meaning, kept",
    },
    Exception {
        long: "--format",
        leaf: "cap discover",
        meaning: "Output format: \"table\" (human-readable), \"json\", or \"yaml\"",
        ticket: "ruled 2026-11-19: same meaning, value set differs, kept",
    },
    Exception {
        long: "--format",
        leaf: "validate",
        meaning: "Output format",
        ticket: "ruled 2026-11-19: same meaning, value set differs, kept",
    },
    Exception {
        long: "--json",
        leaf: "api",
        meaning: "Emit errors as one structured JSON object on stderr. Successful responses retain the gateway's native JSON or raw bytes",
        ticket: "ruled 2026-11-19: different meaning, kept; MIK-9822.FLAG.1",
    },
    Exception {
        long: "--json",
        leaf: "list",
        meaning: "Output as JSON (codex-compatible)",
        ticket: "ruled 2026-11-19: different meaning, kept; MIK-9822.FLAG.1",
    },
    Exception {
        long: "--output",
        leaf: "cap import",
        meaning: "Directory to write the generated capability files into",
        ticket: "ruled 2026-11-19: different meaning, kept",
    },
    Exception {
        long: "--output",
        leaf: "cap install",
        meaning: "Local directory to save the downloaded capability into",
        ticket: "ruled 2026-11-19: different meaning, kept",
    },
    Exception {
        long: "--output",
        leaf: "cap import-url",
        meaning: "Directory to write the generated capability files into",
        ticket: "ruled 2026-11-19: different meaning, kept",
    },
    Exception {
        long: "--output",
        leaf: "import apply",
        meaning: "Directory to write generated draft files into",
        ticket: "ruled 2026-11-19: different meaning, kept",
    },
    Exception {
        long: "--output",
        leaf: "tls init-ca",
        meaning: "Directory to write `ca.crt` and `ca.key` into",
        ticket: "ruled 2026-11-19: different meaning, kept",
    },
    Exception {
        long: "--output",
        leaf: "tls issue-server",
        meaning: "Directory to write `server.crt` and `server.key`",
        ticket: "ruled 2026-11-19: different meaning, kept",
    },
    Exception {
        long: "--output",
        leaf: "tls issue-client",
        meaning: "Directory to write `<cn>.crt` and `<cn>.key`",
        ticket: "ruled 2026-11-19: different meaning, kept",
    },
    Exception {
        long: "--output",
        leaf: "init",
        meaning: "File path to write the generated configuration to",
        ticket: "ruled 2026-11-19: different meaning, kept",
    },
    Exception {
        long: "--output",
        leaf: "setup wizard",
        meaning: "Path to write (or update) the gateway configuration file",
        ticket: "ruled 2026-11-19: different meaning, kept",
    },
    Exception {
        long: "--shadow",
        leaf: "cap discover",
        meaning: "Emit a passive `ShadowRadar` report for servers that are NOT registered in the gateway config",
        ticket: "ruled 2026-11-19: different meaning, kept; MIK-9822.FLAG.1",
    },
    Exception {
        long: "--shadow",
        leaf: "doctor",
        meaning: "Emit operator-facing DLP/firewall regex rules for network-layer MCP detection instead of running the normal health checks",
        ticket: "ruled 2026-11-19: different meaning, kept; MIK-9822.FLAG.1",
    },
    Exception {
        long: "--url",
        leaf: "stats",
        meaning: "Base URL of the running gateway (without /mcp suffix)",
        ticket: "MIK-9683.CLIUX.24 (one --gateway flag)",
    },
    Exception {
        long: "--url",
        leaf: "dashboard-link",
        meaning: "Gateway base URL (default as for `stats`)",
        ticket: "MIK-9683.CLIUX.24 (one --gateway flag)",
    },
    Exception {
        long: "--url",
        leaf: "events dead-letters",
        meaning: "Gateway base URL (default as for `dashboard-link`)",
        ticket: "MIK-9683.CLIUX.24 (one --gateway flag)",
    },
    Exception {
        long: "--url",
        leaf: "api",
        meaning: "Gateway base URL (default as for `dashboard-link`)",
        ticket: "MIK-9683.CLIUX.24 (one --gateway flag)",
    },
    Exception {
        long: "--url",
        leaf: "add",
        meaning: "HTTP URL for the server (streamable HTTP / SSE transport)",
        ticket: "MIK-9683.CLIUX.24 (one --gateway flag)",
    },
    Exception {
        long: "--url",
        leaf: "audit lookup-email",
        meaning: "Gateway base URL (default as for `dashboard-link`)",
        ticket: "MIK-9683.CLIUX.24 (one --gateway flag)",
    },
];
const DEFAULTS: &[(&str, &str, Option<&str>)] = &[
    ("--ca-cert", "dashboard-link", None),
    ("--ca-cert", "events dead-letters", None),
    ("--ca-cert", "api", None),
    ("--ca-cert", "audit lookup-email", None),
    (
        "--ca-key",
        "tls issue-server",
        Some("/etc/mcp-gateway/tls/ca.key"),
    ),
    (
        "--ca-key",
        "tls issue-client",
        Some("/etc/mcp-gateway/tls/ca.key"),
    ),
    ("--capabilities", "cap search", Some("capabilities")),
    ("--capabilities", "cap registry-list", Some("capabilities")),
    ("--client-cert", "dashboard-link", None),
    ("--client-cert", "events dead-letters", None),
    ("--client-cert", "api", None),
    ("--client-cert", "audit lookup-email", None),
    ("--client-key", "dashboard-link", None),
    ("--client-key", "events dead-letters", None),
    ("--client-key", "api", None),
    ("--client-key", "audit lookup-email", None),
    ("--cn", "tls issue-server", None),
    ("--cn", "tls issue-client", None),
    ("--config", "", None),
    (
        "--context-integrity-profile",
        "import preview",
        Some("imported_tool_baseline"),
    ),
    (
        "--context-integrity-profile",
        "import apply",
        Some("imported_tool_baseline"),
    ),
    ("--dry-run", "cap import-url", Some("false")),
    ("--dry-run", "skills generate", Some("false")),
    ("--dry-run", "setup export", Some("false")),
    ("--dry-run", "upgrade", Some("false")),
    (
        "--file",
        "identity grants list",
        Some("~/.mcp-gateway/identity-grants.yaml"),
    ),
    (
        "--file",
        "identity grants grant",
        Some("~/.mcp-gateway/identity-grants.yaml"),
    ),
    (
        "--file",
        "identity grants revoke",
        Some("~/.mcp-gateway/identity-grants.yaml"),
    ),
    ("--fix", "validate", Some("false")),
    ("--fix", "doctor", Some("false")),
    ("--force", "cap discover", Some("false")),
    ("--force", "import apply", Some("false")),
    ("--force", "setup wizard", Some("false")),
    ("--force", "add", Some("false")),
    ("--force", "remove", Some("false")),
    ("--format", "import preview", Some("table")),
    ("--format", "import apply", Some("table")),
    ("--format", "identity grants list", Some("table")),
    ("--format", "identity grants grant", Some("table")),
    ("--format", "identity grants revoke", Some("table")),
    ("--format", "tool invoke", Some("json")),
    ("--format", "tool list", Some("table")),
    ("--format", "tool inspect", Some("table")),
    ("--format", "doctor", Some("table")),
    ("--grant-id", "identity grants grant", None),
    ("--grant-id", "identity grants revoke", None),
    ("--kind", "import preview", None),
    ("--kind", "import apply", None),
    ("--path", "audit verify", None),
    ("--path", "audit show", None),
    ("--prefix", "cap import", None),
    ("--prefix", "cap import-url", None),
    ("--registry", "skills import", None),
    ("--registry", "skills list", None),
    ("--registry", "skills search", None),
    ("--registry", "skills show", None),
    ("--registry", "skills remove", None),
    ("--validity-days", "tls init-ca", Some("3650")),
    ("--validity-days", "tls issue-server", Some("365")),
    ("--validity-days", "tls issue-client", Some("1")),
];

fn sig_ca_cert() -> Signature {
    Signature {
        short: None,
        takes_value: true,
        value_name: Some("CA_CERT".into()),
        repeated: false,
        required: false,
        env: Some("MCP_GATEWAY_CA_CERT".into()),
        possible: vec![],
    }
}

fn sig_ca_key() -> Signature {
    Signature {
        short: None,
        takes_value: true,
        value_name: Some("CA_KEY".into()),
        repeated: false,
        required: false,
        env: None,
        possible: vec![],
    }
}

fn sig_capabilities() -> Signature {
    Signature {
        short: Some('C'),
        takes_value: true,
        value_name: Some("CAPABILITIES".into()),
        repeated: false,
        required: false,
        env: None,
        possible: vec![],
    }
}

fn sig_client_cert() -> Signature {
    Signature {
        short: None,
        takes_value: true,
        value_name: Some("CLIENT_CERT".into()),
        repeated: false,
        required: false,
        env: Some("MCP_GATEWAY_CLIENT_CERT".into()),
        possible: vec![],
    }
}

fn sig_client_key() -> Signature {
    Signature {
        short: None,
        takes_value: true,
        value_name: Some("CLIENT_KEY".into()),
        repeated: false,
        required: false,
        env: Some("MCP_GATEWAY_CLIENT_KEY".into()),
        possible: vec![],
    }
}

fn sig_cn() -> Signature {
    Signature {
        short: None,
        takes_value: true,
        value_name: Some("CN".into()),
        repeated: false,
        required: true,
        env: None,
        possible: vec![],
    }
}

fn sig_config() -> Signature {
    Signature {
        short: Some('c'),
        takes_value: true,
        value_name: Some("CONFIG".into()),
        repeated: false,
        required: false,
        env: Some("MCP_GATEWAY_CONFIG".into()),
        possible: vec![],
    }
}

fn sig_context_integrity_profile() -> Signature {
    Signature {
        short: None,
        takes_value: true,
        value_name: Some("CONTEXT_INTEGRITY_PROFILE".into()),
        repeated: false,
        required: false,
        env: None,
        possible: vec![],
    }
}

fn sig_dry_run() -> Signature {
    Signature {
        short: None,
        takes_value: false,
        value_name: Some("DRY_RUN".into()),
        repeated: false,
        required: false,
        env: None,
        possible: vec![],
    }
}

fn sig_file() -> Signature {
    Signature {
        short: None,
        takes_value: true,
        value_name: Some("FILE".into()),
        repeated: false,
        required: false,
        env: None,
        possible: vec![],
    }
}

fn sig_fix() -> Signature {
    Signature {
        short: None,
        takes_value: false,
        value_name: Some("FIX".into()),
        repeated: false,
        required: false,
        env: None,
        possible: vec![],
    }
}

fn sig_force() -> Signature {
    Signature {
        short: None,
        takes_value: false,
        value_name: Some("FORCE".into()),
        repeated: false,
        required: false,
        env: None,
        possible: vec![],
    }
}

fn sig_format() -> Signature {
    Signature {
        short: Some('f'),
        takes_value: true,
        value_name: Some("FORMAT".into()),
        repeated: false,
        required: false,
        env: None,
        possible: vec!["json".into(), "table".into(), "plain".into()],
    }
}

fn sig_grant_id() -> Signature {
    Signature {
        short: None,
        takes_value: true,
        value_name: Some("GRANT_ID".into()),
        repeated: false,
        required: true,
        env: None,
        possible: vec![],
    }
}

fn sig_kind() -> Signature {
    Signature {
        short: None,
        takes_value: true,
        value_name: Some("KIND".into()),
        repeated: false,
        required: true,
        env: None,
        possible: vec![
            "openapi".into(),
            "graphql".into(),
            "postman".into(),
            "oci-mcp-package".into(),
        ],
    }
}

fn sig_path() -> Signature {
    Signature {
        short: None,
        takes_value: true,
        value_name: Some("PATH".into()),
        repeated: false,
        required: false,
        env: None,
        possible: vec![],
    }
}

fn sig_prefix() -> Signature {
    Signature {
        short: None,
        takes_value: true,
        value_name: Some("PREFIX".into()),
        repeated: false,
        required: false,
        env: None,
        possible: vec![],
    }
}

fn sig_registry() -> Signature {
    Signature {
        short: None,
        takes_value: true,
        value_name: Some("REGISTRY".into()),
        repeated: false,
        required: false,
        env: Some("MCP_GATEWAY_SKILLS_REGISTRY".into()),
        possible: vec![],
    }
}

fn sig_validity_days() -> Signature {
    Signature {
        short: None,
        takes_value: true,
        value_name: Some("VALIDITY_DAYS".into()),
        repeated: false,
        required: false,
        env: None,
        possible: vec![],
    }
}

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
    let arg = |name: &'static str| {
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
        // clap answers Some([]) when every alias is hidden; the rule is that none is visible.
        assert_eq!(
            arg.get_visible_aliases().unwrap_or_default(),
            Vec::<&str>::new(),
            "{leaf:?}"
        );
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

/// N1 ruling (2026-11-19): `--prefix` keeps `-p` as a hidden short alias, so `-p` names `--port` alone in help. On
/// each import command `-p` still sets the prefix, and the long help shows `--prefix` without `-p`.
#[test]
fn prefix_keeps_p_as_a_hidden_alias() {
    let leaves: [(&str, &[&str]); 2] = [
        ("import", &["./openapi.yaml"]),
        ("import-url", &["https://api.example.com"]),
    ];
    let mut checked = 0;
    for (leaf, positional) in leaves {
        // import-url exists only with the discovery feature.
        let Some(node) = built()
            .find_subcommand("cap")
            .and_then(|c| c.find_subcommand(leaf))
            .cloned()
        else {
            continue;
        };
        let mut argv = vec!["mcp-gateway", "cap", leaf];
        argv.extend_from_slice(positional);
        argv.extend_from_slice(&["-p", "stripe"]);
        let matches = built()
            .try_get_matches_from(&argv)
            .unwrap_or_else(|e| panic!("{argv:?}: {e}"));
        let (_, cap) = matches.subcommand().expect("cap");
        let (_, at) = cap.subcommand().expect("leaf");
        assert_eq!(
            at.get_one::<String>("prefix").map(String::as_str),
            Some("stripe"),
            "{argv:?}"
        );
        let help = node.clone().render_long_help().to_string();
        assert!(help.contains("--prefix"), "{leaf}: {help}");
        assert!(!help.contains("-p, --prefix"), "{leaf}: {help}");
        checked += 1;
    }
    assert!(checked >= 1, "cap import is always built");
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
