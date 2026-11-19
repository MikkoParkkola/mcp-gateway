// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Completion rows (MIK-9681.CLIUX.20; completions r2-final): bash and zsh are clap_complete's own output, fish and
//! PowerShell come from this module's generator, and only values `completion_safe` accepts are offered there.

use super::{CompletionShell, Generated, completion_safe, completion_tree, generate};

const TOOLS: [&str; 2] = ["good_cap", "other_cap"];

fn tools() -> Vec<String> {
    TOOLS.iter().map(|s| (*s).to_owned()).collect()
}

fn script(shell: CompletionShell) -> String {
    generate(shell, completion_tree(&tools())).script
}

/// C0: bash and zsh are clap_complete's own output for the completion copy, byte for byte.
#[test]
fn bash_and_zsh_are_clap_completes_own() {
    for (shell, clap_shell) in [
        (CompletionShell::Bash, clap_complete::Shell::Bash),
        (CompletionShell::Zsh, clap_complete::Shell::Zsh),
    ] {
        let mut tree = completion_tree(&tools());
        let mut want = Vec::new();
        clap_complete::generate(clap_shell, &mut tree, "mcp-gateway", &mut want);
        assert!(!want.is_empty(), "{shell:?}");
        assert_eq!(
            script(shell),
            String::from_utf8(want).expect("utf-8"),
            "{shell:?}"
        );
    }
}

/// C1a: the values bash and zsh carry, each in its own context (fragments copied from clap_complete's output).
#[test]
fn bash_and_zsh_carry_the_closed_lists() {
    let bash = script(CompletionShell::Bash);
    let case = |name: &str| -> String {
        let head = format!("        {name})\n");
        let start = bash
            .find(&head)
            .unwrap_or_else(|| panic!("no bash case {name}"));
        let rest = &bash[start + head.len()..];
        rest[..rest.find("\n            ;;\n").unwrap_or(rest.len())].to_owned()
    };
    for leaf in ["invoke", "inspect"] {
        let body = case(&format!(
            "mcp__subcmd__gateway__subcmd__tool__subcmd__{leaf}"
        ));
        assert!(body.contains("good_cap other_cap"), "{leaf}: {body}");
    }
    assert!(
        case("mcp__subcmd__gateway__subcmd__tool__subcmd__completions")
            .contains("bash zsh fish powershell")
    );
    let grant = case("mcp__subcmd__gateway__subcmd__identity__subcmd__grants__subcmd__grant");
    assert!(
        grant.contains("--grant-id") && grant.contains("--scope"),
        "{grant}"
    );
    assert!(
        grant.contains(r#"compgen -W "read execute any""#),
        "{grant}"
    );
    assert!(
        bash.contains(r#"COMPREPLY=($(compgen -W "trace debug info warn error" -- "${cur}"))"#),
        "no log-level values in bash"
    );
    assert!(
        bash.contains("compopt -o filenames"),
        "no file hint in bash"
    );
    let zsh = script(CompletionShell::Zsh);
    // clap_complete's zsh positional spec is `'<cardinality>:<id> -- <help>:<values>'`.
    for leaf in ["invoke", "inspect"] {
        assert!(
            zsh.contains(&format!(
                "':tool -- Tool name to {leaf}:(good_cap other_cap)'"
            )),
            "zsh tool values for {leaf}"
        );
    }
    // The option spec is `'--long=[help]:<value name>:<values>'`; the value name is clap's, the values are the rule.
    let spec = |long: &str| -> String {
        zsh.lines()
            .map(str::trim)
            .find(|l| l.starts_with(&format!("'--{long}=[")))
            .unwrap_or_else(|| panic!("no zsh spec for --{long}"))
            .to_owned()
    };
    let log_level = spec("log-level");
    assert!(
        log_level
            .starts_with("'--log-level=[Minimum log level\\: trace, debug, info, warn, or error]:")
            && log_level.contains(":(trace debug info warn error)'"),
        "zsh log-level values: {log_level}"
    );
    let config = spec("config");
    assert!(
        config.starts_with("'--config=[Path to the gateway configuration file (YAML)]:")
            && config.contains(":_files'"),
        "zsh file hint: {config}"
    );
    assert!(zsh.contains(":(read execute any)'"), "zsh scope values");
}

/// C3a: the loader's name rule refuses a hostile capability name: the directory load leaves the file out, and the
/// rule itself (`validate_capability`, which the directory load runs on each parsed file) refuses it with the rule's
/// error (a guard: the rule exists today; its red proof is the mutant with the rule removed).
#[tokio::test]
async fn the_loader_refuses_a_hostile_tool_name() {
    let dir = tempfile::tempdir().expect("dir");
    let cap = |name: &str| {
        format!(
            "name: \"{name}\"\ndescription: A capability\nschema:\n  input:\n    type: object\nproviders:\n  primary:\n    \
             service: rest\n    config:\n      base_url: https://example.invalid\n      path: /x\n      method: GET\n"
        )
    };
    std::fs::write(dir.path().join("good.yaml"), cap("good_cap")).expect("write");
    let bad = dir.path().join("bad.yaml");
    std::fs::write(&bad, cap("bad'$(touch x) cap")).expect("write");
    let loaded =
        crate::capability::CapabilityLoader::load_directory(dir.path().to_str().expect("utf-8"))
            .await
            .expect("directory");
    let names: Vec<&str> = loaded.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, ["good_cap"]);
    let parsed = crate::capability::parse_capability_file(&bad)
        .await
        .expect("the file parses; the name rule is checked after parsing");
    let err =
        crate::capability::validate_capability(&parsed).expect_err("the hostile name is refused");
    assert!(
        err.to_string()
            .contains("must contain only alphanumeric characters and underscores"),
        "{err}"
    );
}

/// C7: every real value passes the generators' own predicate: every possible value in the tree, the lists the
/// completion copy adds, and the loader's capability-name characters one by one.
#[test]
fn every_real_value_is_completion_safe() {
    let mut values = std::collections::BTreeSet::new();
    let mut root = <crate::cli::Cli as clap::CommandFactory>::command();
    root.build();
    let mut stack = vec![root];
    while let Some(cmd) = stack.pop() {
        for arg in cmd.get_arguments().filter(|a| !a.is_hide_set()) {
            for v in arg.get_possible_values() {
                values.insert(v.get_name().to_owned());
            }
        }
        stack.extend(cmd.get_subcommands().filter(|c| !c.is_hide_set()).cloned());
    }
    for named in [
        "json",
        "table",
        "plain",
        "local",
        "minimal",
        "read",
        "execute",
        "any",
        "claude-code",
        "oci-mcp-package",
    ] {
        assert!(values.contains(named), "the tree read lacks {named}");
    }
    values.extend(
        [
            "trace",
            "debug",
            "info",
            "warn",
            "error",
            "bash",
            "zsh",
            "fish",
            "powershell",
        ]
        .map(str::to_owned),
    );
    let refused: Vec<&String> = values.iter().filter(|v| !completion_safe(v)).collect();
    assert_eq!(refused, Vec::<&String>::new());
    let loader_accepts = |name: &str| {
        let yaml = format!(
            "name: \"{name}\"\ndescription: A capability\nschema:\n  input:\n    type: object\nproviders:\n  primary:\n    \
             service: rest\n    config:\n      base_url: https://example.invalid\n      path: /x\n      method: GET\n"
        );
        crate::capability::parse_capability(&yaml)
            .is_ok_and(|cap| crate::capability::validate_capability(&cap).is_ok())
    };
    let letters = ('a'..='z')
        .chain('A'..='Z')
        .chain('0'..='9')
        .chain(['_', 'é', 'λ', 'ж', '字', '٣']);
    for c in letters {
        for name in [c.to_string(), format!("a{c}")] {
            assert!(loader_accepts(&name), "{name}: the loader refuses it");
            assert!(
                completion_safe(&name),
                "{name}: the loader accepts it, the predicate must too"
            );
        }
    }
    for wider in ["a-b", "a.b"] {
        assert!(!loader_accepts(wider), "{wider}: the loader accepts it");
        assert!(
            completion_safe(wider),
            "{wider}: the predicate is wider than the loader"
        );
    }
    let source = include_str!("completion.rs");
    assert!(
        source.matches("completion_safe(").count() >= 3,
        "the generators call the predicate"
    );
}

/// The fish table's entries: `(path, kind, name, extra)` from the one `printf` in `__fish_mcp_gateway_table`.
fn fish_table(script: &str) -> Vec<(String, String, String, String)> {
    let Some(start) = script.find("function __fish_mcp_gateway_table") else {
        return Vec::new();
    };
    let end = script[start..]
        .find("\nend")
        .map_or(script.len(), |e| start + e);
    script[start..end]
        .split('\'')
        .skip(1)
        .step_by(2)
        .filter(|entry| entry.matches('|').count() == 3)
        .map(|entry| {
            let f: Vec<&str> = entry.split('|').collect();
            (
                f[0].to_owned(),
                f[1].to_owned(),
                f[2].to_owned(),
                f[3].to_owned(),
            )
        })
        .collect()
}

fn is_pwsh_quote(c: char) -> bool {
    matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}')
}

/// The PowerShell table's entries, each `@('<path>', '<kind>', ...)` line split into its unquoted fields (two quote
/// characters of the five read as one).
fn pwsh_table(script: &str) -> Vec<Vec<String>> {
    script
        .lines()
        .filter_map(|l| {
            l.trim()
                .strip_prefix("@(")
                .and_then(|r| r.strip_suffix(')'))
        })
        .filter(|inner| inner.starts_with("'mcp-gateway"))
        .map(|inner| {
            let mut fields = Vec::new();
            let mut cur = String::new();
            let mut quoted = false;
            let mut chars = inner.chars().peekable();
            while let Some(c) = chars.next() {
                if is_pwsh_quote(c) && quoted && chars.peek().copied().is_some_and(is_pwsh_quote) {
                    cur.push(c);
                    chars.next();
                } else if is_pwsh_quote(c) {
                    quoted = !quoted;
                } else if c == ',' && !quoted {
                    fields.push(std::mem::take(&mut cur));
                } else if quoted {
                    cur.push(c);
                }
            }
            fields.push(cur);
            fields
        })
        .collect()
}

/// The visible tree, read independently of the completion copy: `(path words, command)` for every visible command,
/// not descending into clap's generated `help` subcommands.
fn visible_commands() -> Vec<(Vec<String>, clap::Command)> {
    let mut root = <crate::cli::Cli as clap::CommandFactory>::command();
    root.build();
    let mut out = Vec::new();
    let mut stack = vec![(Vec::new(), root)];
    while let Some((path, cmd)) = stack.pop() {
        for sub in cmd
            .get_subcommands()
            .filter(|c| !c.is_hide_set() && c.get_name() != "help")
        {
            let mut p = path.clone();
            p.push(sub.get_name().to_owned());
            stack.push((p, sub.clone()));
        }
        out.push((path, cmd));
    }
    out
}

/// How an argument takes a value, in the tables' words.
fn value_kind(arg: &clap::Arg) -> &'static str {
    if !arg.get_action().takes_values() {
        "switch"
    } else if arg.get_num_args().is_some_and(|n| n.min_values() == 0) {
        "optional"
    } else {
        "required"
    }
}

fn pwsh_path(p: &str) -> String {
    if p.is_empty() {
        "mcp-gateway".to_owned()
    } else {
        format!("mcp-gateway;{}", p.replace(' ', ";"))
    }
}

/// C1b: fish and PowerShell carry the tree's commands, flags and closed lists; fish's table and lines, its printer
/// and PowerShell's table each match the tree on their own, with named members.
#[test]
fn fish_and_powershell_carry_the_tree() {
    use std::collections::BTreeSet;
    let fish = script(CompletionShell::Fish);
    let pwsh = script(CompletionShell::Powershell);
    let mut subs = BTreeSet::new();
    let mut flags = BTreeSet::new();
    for (path, cmd) in visible_commands() {
        let p = path.join(" ");
        for sub in cmd.get_subcommands().filter(|c| !c.is_hide_set()) {
            subs.insert((p.clone(), sub.get_name().to_owned()));
        }
        for arg in cmd.get_arguments().filter(|a| !a.is_hide_set()) {
            if let Some(long) = arg.get_long() {
                flags.insert((p.clone(), format!("--{long}"), value_kind(arg).to_owned()));
            }
        }
    }
    assert!(
        subs.contains(&("identity grants".to_owned(), "grant".to_owned())),
        "the tree read"
    );
    assert!(flags.contains(&(
        "identity grants grant".to_owned(),
        "--grant-id".to_owned(),
        "required".to_owned()
    )));
    let table = fish_table(&fish);
    let fish_subs: BTreeSet<_> = table
        .iter()
        .filter(|e| e.1 == "sub")
        .map(|e| (e.0.clone(), e.2.clone()))
        .collect();
    let fish_flags: BTreeSet<_> = table
        .iter()
        .filter(|e| e.1 == "flag")
        .map(|e| (e.0.clone(), e.2.clone(), e.3.clone()))
        .collect();
    assert_eq!(fish_subs, subs, "fish table subcommands");
    assert_eq!(fish_flags, flags, "fish table flags");
    for (p, name) in &subs {
        let at = if p.is_empty() {
            "0".to_owned()
        } else {
            format!("{p} 0")
        };
        let head = format!(
            "complete -c mcp-gateway -f -n \"__fish_mcp_gateway_at {at}\" -a '{name}' -d '"
        );
        assert!(fish.contains(&head), "fish line for {p:?} {name}");
    }
    assert!(fish.contains(
        "complete -c mcp-gateway -f -n \"__fish_mcp_gateway_at tool invoke 0\" -a '(__fish_mcp_gateway_values tool invoke 0)'"
    ));
    assert!(
        fish.contains("printf '%s\\n' 'good_cap' 'other_cap'"),
        "fish printer for the tool names"
    );
    assert!(
        fish.contains("printf '%s\\n' 'read' 'execute' 'any'"),
        "fish printer for --scope"
    );
    let entries = pwsh_table(&pwsh);
    let pwsh_subs: BTreeSet<_> = entries
        .iter()
        .filter(|e| e.get(1).is_some_and(|k| k == "sub"))
        .map(|e| (e[0].clone(), e[2].clone()))
        .collect();
    let want_subs: BTreeSet<_> = subs
        .iter()
        .map(|(p, n)| (pwsh_path(p), n.clone()))
        .collect();
    assert_eq!(pwsh_subs, want_subs, "PowerShell subcommands");
    let pwsh_flags: BTreeSet<_> = entries
        .iter()
        .filter(|e| e.get(1).is_some_and(|k| k == "flag") && e.len() == 5)
        .map(|e| (e[0].clone(), e[2].clone(), e[4].clone()))
        .collect();
    let want_flags: BTreeSet<_> = flags
        .iter()
        .map(|(p, f, k)| (pwsh_path(p), f.clone(), k.clone()))
        .collect();
    assert_eq!(pwsh_flags, want_flags, "PowerShell flags");
    for v in TOOLS {
        let want: Vec<String> = ["mcp-gateway;tool;invoke", "pos", "0", v, v]
            .map(str::to_owned)
            .to_vec();
        assert!(entries.contains(&want), "PowerShell tool value {v}");
    }
    for v in ["read", "execute", "any"] {
        let want: Vec<String> = ["mcp-gateway;identity;grants;grant", "val", "--scope", v, v]
            .map(str::to_owned)
            .to_vec();
        assert!(entries.contains(&want), "PowerShell --scope value {v}");
    }
}

/// Every hidden command path and hidden argument of the full tree: `(path, long or command name, global)`.
fn hidden_items() -> (Vec<String>, Vec<(String, String, bool)>) {
    let mut root = <crate::cli::Cli as clap::CommandFactory>::command();
    root.build();
    let mut commands = Vec::new();
    let mut args = Vec::new();
    let mut stack = vec![(String::new(), root)];
    while let Some((path, cmd)) = stack.pop() {
        for arg in cmd.get_arguments().filter(|a| a.is_hide_set()) {
            if let Some(long) = arg.get_long() {
                args.push((path.clone(), format!("--{long}"), arg.is_global_set()));
            }
        }
        for sub in cmd.get_subcommands().filter(|c| c.get_name() != "help") {
            let p = if path.is_empty() {
                sub.get_name().to_owned()
            } else {
                format!("{path} {}", sub.get_name())
            };
            if sub.is_hide_set() {
                commands.push(p);
            } else {
                stack.push((p, sub.clone()));
            }
        }
    }
    (commands, args)
}

/// C2: no hidden command, argument or alias reaches any script, checked per context; the visible `cap list
/// --capabilities` stays.
#[test]
fn no_hidden_item_reaches_a_script() {
    let (commands, args) = hidden_items();
    for sentinel in ["kubernetes", "ranking", "runtime", "trust"] {
        assert!(
            commands.iter().any(|c| c == sentinel),
            "hidden command {sentinel} in the tree"
        );
    }
    for (path, long) in [
        ("", "--log-format"),
        ("", "--host"),
        ("", "--no-meta-mcp"),
        ("", "--protocol-revision-window"),
        ("identity grants grant", "--subject-label"),
        ("tool completions", "--capabilities"),
    ] {
        assert!(
            args.iter().any(|(p, l, _)| p == path && l == long),
            "hidden {long} at `{path}` in the tree"
        );
    }
    let fish = fish_table(&script(CompletionShell::Fish));
    let pwsh = pwsh_table(&script(CompletionShell::Powershell));
    for hidden in &commands {
        let (parent, name) = hidden.rsplit_once(' ').unwrap_or(("", hidden));
        assert!(
            !fish
                .iter()
                .any(|e| e.1 == "sub" && e.0 == parent && e.2 == name),
            "fish offers {hidden}"
        );
        assert!(
            !fish
                .iter()
                .any(|e| e.0 == *hidden || e.0.starts_with(&format!("{hidden} "))),
            "fish context {hidden}"
        );
        assert!(
            !pwsh.iter().any(|e| e[0] == pwsh_path(hidden)
                || e[0].starts_with(&format!("{};", pwsh_path(hidden))))
        );
        assert!(!pwsh.iter().any(|e| e.get(1).is_some_and(|k| k == "sub")
            && e[0] == pwsh_path(parent)
            && e[2] == name));
    }
    for (path, long, global) in &args {
        let at = |p: &str| *global || p == path;
        assert!(
            !fish
                .iter()
                .any(|e| e.1 == "flag" && e.2 == *long && at(&e.0)),
            "fish {long} at `{path}`"
        );
        assert!(
            !pwsh.iter().any(|e| e.get(1).is_some_and(|k| k == "flag")
                && e[2] == *long
                && at(&e[0]
                    .replacen("mcp-gateway", "", 1)
                    .trim_start_matches(';')
                    .replace(';', " "))),
            "pwsh {long}"
        );
    }
    // The visible counterpart (A1): `cap search` has its own visible `--capabilities`, which stays.
    assert!(
        fish.iter()
            .any(|e| e.0 == "cap search" && e.1 == "flag" && e.2 == "--capabilities"),
        "visible --capabilities"
    );
    let bash = script(CompletionShell::Bash);
    for hidden in &commands {
        let label = format!(
            "mcp__subcmd__gateway__subcmd__{})",
            hidden.replace(' ', "__subcmd__")
        );
        assert!(!bash.contains(&label), "bash case for {hidden}");
    }
    let tokens = |s: &str| -> std::collections::BTreeSet<String> {
        s.split(|c: char| c.is_whitespace() || "\"'()[]=:".contains(c))
            .map(str::to_owned)
            .collect()
    };
    for shell in [CompletionShell::Bash, CompletionShell::Zsh] {
        let t = tokens(&script(shell));
        for (_, long, global) in &args {
            if *global || long == "--subject-label" || long == "--host" {
                assert!(!t.contains(long), "{shell:?} carries {long}");
            }
        }
    }
    for shell in [
        CompletionShell::Bash,
        CompletionShell::Zsh,
        CompletionShell::Fish,
        CompletionShell::Powershell,
    ] {
        let t = tokens(&script(shell));
        assert!(
            !t.contains("--out"),
            "{shell:?} carries the hidden alias --out"
        );
    }
}

/// C3b: through the command's own load, a clean directory's capability names are exactly the tool values each shell
/// offers at `tool invoke`.
#[tokio::test]
async fn the_tool_values_are_exactly_the_directory_names() {
    let dir = tempfile::tempdir().expect("dir");
    for name in TOOLS {
        std::fs::write(
            dir.path().join(format!("{name}.yaml")),
            format!(
                "name: {name}\ndescription: A capability\nschema:\n  input:\n    type: object\nproviders:\n  primary:\n    \
                 service: rest\n    config:\n      base_url: https://example.invalid\n      path: /x\n      method: GET\n"
            ),
        )
        .expect("write");
    }
    let dirs = crate::commands::capability_dirs::CapabilityDirs::Override(dir.path().to_path_buf());
    let mut names: Vec<String> = crate::commands::capability_dirs::load(&dirs)
        .await
        .expect("load")
        .all()
        .iter()
        .map(|c| c.name.clone())
        .collect();
    names.sort();
    let tree = || completion_tree(&names);
    assert!(
        generate(CompletionShell::Bash, tree())
            .script
            .contains("good_cap other_cap")
    );
    assert!(
        generate(CompletionShell::Zsh, tree())
            .script
            .contains("':tool -- Tool name to invoke:(good_cap other_cap)'")
    );
    assert!(
        generate(CompletionShell::Fish, tree())
            .script
            .contains("printf '%s\\n' 'good_cap' 'other_cap'")
    );
    let pwsh = pwsh_table(&generate(CompletionShell::Powershell, tree()).script);
    let values: Vec<&str> = pwsh
        .iter()
        .filter(|e| e[0] == "mcp-gateway;tool;invoke" && e.get(1).is_some_and(|k| k == "pos"))
        .map(|e| e[3].as_str())
        .collect();
    assert_eq!(values, TOOLS);
}

// The help's command substitution names its own file: the refused value `$(touch canary)` must reach no script, and
// a help string holding that same text would make the substring check below unpassable.
const HOSTILE_HELP: &str =
    "say 'hi' $(touch help_canary) a\\'b ~x *y \u{2018}a\u{2019} \u{201a}b\u{201b} \\`";
const SAFE: [&str; 6] = ["good_cap", "café", "x.y-z", "_private", "9", "2fa_check"];
const REFUSED: [&str; 14] = [
    "a b",
    "a'b",
    "a\"b",
    "$(touch canary)",
    "a`b",
    "a;b",
    "a\\b",
    "a\u{2019}b",
    "-dash",
    ".dot",
    "a\tb",
    "a\nb",
    "a\u{1b}b",
    "a\u{7f}b",
];

/// The C4 tree: `tool invoke` with a positional carrying the safe and refused values, and a `--note` flag whose help
/// is the hostile text.
fn c4_tree() -> clap::Command {
    let values: Vec<&'static str> = SAFE.iter().chain(REFUSED.iter()).copied().collect();
    clap::Command::new("mcp-gateway").subcommand(
        clap::Command::new("tool").about("Tools").subcommand(
            clap::Command::new("invoke")
                .about("Invoke a tool")
                .arg(
                    clap::Arg::new("tool")
                        .value_parser(clap::builder::PossibleValuesParser::new(values)),
                )
                .arg(
                    clap::Arg::new("note")
                        .long("note")
                        .action(clap::ArgAction::SetTrue)
                        .help(HOSTILE_HELP),
                ),
        ),
    )
}

/// C4: only safe values are offered, refused ones are returned in order, and display text is escaped per shell.
#[test]
fn only_safe_values_are_offered_and_display_text_is_escaped() {
    for value in SAFE {
        assert!(completion_safe(value), "{value:?} is safe");
    }
    for value in REFUSED {
        assert!(!completion_safe(value), "{value:?} is refused");
    }
    let fish = generate(CompletionShell::Fish, c4_tree());
    assert_eq!(fish.left_out, REFUSED.map(str::to_owned).to_vec());
    assert!(
        fish.script
            .contains("printf '%s\\n' 'good_cap' 'café' 'x.y-z' '_private' '9' '2fa_check'"),
        "{}",
        fish.script
    );
    let fish_help = HOSTILE_HELP.replace('\\', "\\\\").replace('\'', "\\'");
    assert!(
        fish.script.contains(&format!("-l note -d '{fish_help}'")),
        "{}",
        fish.script
    );
    let pwsh = generate(CompletionShell::Powershell, c4_tree());
    assert_eq!(pwsh.left_out, REFUSED.map(str::to_owned).to_vec());
    let entries = pwsh_table(&pwsh.script);
    let offered: Vec<(String, String)> = entries
        .iter()
        .filter(|e| e[0] == "mcp-gateway;tool;invoke" && e.get(1).is_some_and(|k| k == "pos"))
        .map(|e| (e[3].clone(), e[4].clone()))
        .collect();
    let want: Vec<(String, String)> = SAFE
        .iter()
        .map(|v| {
            (
                (*v).to_owned(),
                if v.starts_with(|c: char| c.is_ascii_digit()) {
                    format!("'{v}'")
                } else {
                    (*v).to_owned()
                },
            )
        })
        .collect();
    assert_eq!(offered, want);
    let doubled: String = HOSTILE_HELP
        .chars()
        .flat_map(|c| {
            if is_pwsh_quote(c) {
                vec![c, c]
            } else {
                vec![c]
            }
        })
        .collect();
    assert!(
        pwsh.script.contains(&format!("'{doubled}'")),
        "{}",
        pwsh.script
    );
    for script in [&fish.script, &pwsh.script] {
        for value in ["a b", "$(touch canary)", "a;b", "a\u{1b}b", "a\u{7f}b"] {
            assert!(!script.contains(value), "{value:?} reached a script");
        }
    }
}

/// C4b: the print step names each left-out value on stderr in `{:?}` form, with no raw control byte, and the scripts
/// never write to stderr.
#[test]
fn left_out_values_are_named_escaped_on_stderr() {
    let tree = || {
        clap::Command::new("mcp-gateway").subcommand(clap::Command::new("tool").subcommand(
            clap::Command::new("invoke").arg(clap::Arg::new("tool").value_parser(
                clap::builder::PossibleValuesParser::new(["good_cap", "a\u{1b}b\nc", "d\u{7f}e"]),
            )),
        ))
    };
    for shell in [CompletionShell::Fish, CompletionShell::Powershell] {
        let generated = generate(shell, tree());
        let (mut out, mut err) = (Vec::new(), Vec::new());
        super::write_completions(&generated, &mut out, &mut err).expect("write");
        let out = String::from_utf8(out).expect("utf-8");
        assert!(out.contains("good_cap"), "{shell:?}");
        assert!(
            !out.contains("a\u{1b}b") && !out.contains("d\u{7f}e"),
            "{shell:?}"
        );
        let text = String::from_utf8(err.clone()).expect("utf-8");
        assert!(
            text.contains(r#""a\u{1b}b\nc""#) && text.contains(r#""d\u{7f}e""#),
            "{shell:?}: {text}"
        );
        assert!(
            err.iter()
                .all(|b| *b == b'\n' || (*b >= 0x20 && *b != 0x7f)),
            "{shell:?}: raw control byte"
        );
        for write in [
            ">&2",
            "Write-Error",
            "Write-Warning",
            "Write-Host",
            "[Console]::Error",
        ] {
            assert!(
                !out.contains(write),
                "{shell:?}: the script writes to stderr ({write})"
            );
        }
    }
}

/// The arguments C8 refuses: more than one value per occurrence, hyphen-led values, trailing variadic positionals.
fn unmodelled(root: &clap::Command, allowed: &[(&str, &str)]) -> Vec<String> {
    let mut found = Vec::new();
    let mut stack = vec![(String::new(), root.clone())];
    while let Some((path, cmd)) = stack.pop() {
        for arg in cmd.get_arguments().filter(|a| !a.is_hide_set()) {
            let multi = arg.get_num_args().is_some_and(|n| n.max_values() > 1);
            let shape = multi
                || arg.is_allow_hyphen_values_set()
                || arg.is_trailing_var_arg_set()
                || arg.is_last_set();
            let id = arg.get_id().as_str();
            if shape && !allowed.iter().any(|(p, a)| *p == path && *a == id) {
                found.push(format!("`{path}` {id}"));
            }
        }
        for sub in cmd
            .get_subcommands()
            .filter(|c| !c.is_hide_set() && c.get_name() != "help")
        {
            let p = if path.is_empty() {
                sub.get_name().to_owned()
            } else {
                format!("{path} {}", sub.get_name())
            };
            stack.push((p, sub.clone()));
        }
    }
    found
}

/// C8: no visible argument takes a shape the walker does not model, apart from three opaque variadic tails.
#[test]
fn no_argument_takes_an_unmodelled_shape() {
    let allowed = [
        ("validate", "paths"),
        ("add", "trailing_command"),
        ("tool invoke", "kv_args"),
    ];
    let mut root = <crate::cli::Cli as clap::CommandFactory>::command();
    root.build();
    let mut names = std::collections::BTreeSet::new();
    let mut stack = vec![root.clone()];
    while let Some(cmd) = stack.pop() {
        names.extend(
            cmd.get_arguments()
                .filter_map(|a| a.get_long().map(|l| format!("--{l}"))),
        );
        stack.extend(cmd.get_subcommands().cloned());
    }
    for named in ["--config", "--log-level", "--format", "--scope"] {
        assert!(names.contains(named), "the traversal read {named}");
    }
    for (path, id) in allowed {
        let mut node = root.clone();
        for word in path.split(' ') {
            node = node.find_subcommand(word).expect(path).clone();
        }
        let arg = node
            .get_arguments()
            .find(|a| a.get_id().as_str() == id)
            .unwrap_or_else(|| panic!("{path} {id}"));
        assert!(
            arg.get_possible_values().is_empty(),
            "{path} {id} has no closed list"
        );
    }
    assert_eq!(unmodelled(&root, &allowed), Vec::<String>::new());
    let mut synthetic = clap::Command::new("mcp-gateway").subcommand(
        clap::Command::new("s")
            .arg(clap::Arg::new("multi").long("multi").num_args(2))
            .arg(
                clap::Arg::new("hyphen")
                    .long("hyphen")
                    .allow_hyphen_values(true),
            )
            .arg(clap::Arg::new("tail").num_args(1..).trailing_var_arg(true)),
    );
    synthetic.build();
    let mut got = unmodelled(&synthetic, &[]);
    got.sort();
    assert_eq!(got, ["`s` hyphen", "`s` multi", "`s` tail"]);
}
