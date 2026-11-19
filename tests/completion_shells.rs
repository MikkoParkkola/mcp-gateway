// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Executed completions (MIK-9681.CLIUX.20; completions r2-final, rows C5 and C6): the generated fish and PowerShell
//! scripts loaded in the real shells. Runs on the Linux integration job, which installs fish and has pwsh; a missing
//! shell fails the row there, never skips it.

#![cfg(target_os = "linux")]

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::path::Path;
use std::process::Command;

const TOOLS: [&str; 2] = ["good_cap", "other_cap"];

fn capability(dir: &Path, name: &str) {
    std::fs::write(
        dir.join(format!("{name}.yaml")),
        format!(
            "name: {name}\ndescription: A capability\nschema:\n  input:\n    type: object\nproviders:\n  primary:\n    \
             service: rest\n    config:\n      base_url: https://example.invalid\n      path: /x\n      method: GET\n"
        ),
    )
    .expect("capability");
}

/// The binary's script for `shell`, from a directory holding the two tool names.
fn generated(home: &Path, shell: &str) -> String {
    let caps = home.join("caps");
    std::fs::create_dir_all(&caps).expect("caps");
    for name in TOOLS {
        capability(&caps, name);
    }
    let out = gateway_bin::command(home, gateway_bin::Inherit::Nothing)
        .args(["tool", "completions", shell, "-C"])
        .arg(&caps)
        .output()
        .expect("run");
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf-8")
}

/// fish's candidates for `line`: the first field of each `complete -C` line; stderr must be empty.
fn fish(dir: &Path, script: &Path, line: &str) -> Vec<String> {
    let out = Command::new("fish")
        .current_dir(dir)
        .args(["--no-config", "-c"])
        .arg(format!(
            "source {}; and complete -C {}",
            script.display(),
            shell_words(line)
        ))
        .output()
        .expect("fish must be installed on this job");
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "",
        "fish stderr for {line:?}"
    );
    let mut got: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.split('\t').next().unwrap_or_default().to_owned())
        .collect();
    got.sort();
    got
}

/// PowerShell's completion texts for `line`; `register` false asks with no completer registered.
fn pwsh(dir: &Path, script: &Path, line: &str, register: bool) -> Vec<String> {
    let load = if register {
        format!(". '{}'; ", script.display())
    } else {
        String::new()
    };
    let quoted = line.replace('\'', "''");
    let out = Command::new("pwsh")
        .current_dir(dir)
        .args(["-NoProfile", "-NonInteractive", "-Command"])
        .arg(format!(
            "{load}(TabExpansion2 -inputScript '{quoted}' -cursorColumn {}).CompletionMatches | ForEach-Object {{ $_.CompletionText }}",
            line.chars().count()
        ))
        .output()
        .expect("pwsh must be on this job");
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "",
        "pwsh stderr for {line:?}"
    );
    let mut got: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_owned)
        .collect();
    got.sort();
    got
}

fn shell_words(line: &str) -> String {
    format!("'{}'", line.replace('\\', "\\\\").replace('\'', "\\'"))
}

fn sorted(items: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = items.iter().map(|s| (*s).to_owned()).collect();
    v.sort();
    v
}

/// C5: each command line gets exactly its expected candidates in fish and PowerShell.
#[test]
fn completions_bind_values_to_their_argument() {
    let home = tempfile::tempdir().expect("home");
    let work = tempfile::tempdir().expect("work");
    std::fs::write(work.path().join("planted.yaml"), "x").expect("planted");
    let fish_script = home.path().join("mcp-gateway.fish");
    std::fs::write(&fish_script, generated(home.path(), "fish")).expect("fish script");
    let pwsh_script = home.path().join("mcp-gateway.ps1");
    std::fs::write(&pwsh_script, generated(home.path(), "powershell")).expect("pwsh script");
    let both = |line: &str, want: &[&str]| {
        assert_eq!(
            fish(work.path(), &fish_script, line),
            sorted(want),
            "fish: {line:?}"
        );
        assert_eq!(
            pwsh(work.path(), &pwsh_script, line, true),
            sorted(want),
            "pwsh: {line:?}"
        );
    };
    both("mcp-gateway tool invoke ", &TOOLS);
    both("mcp-gateway tool invoke g", &["good_cap"]);
    assert!(
        !fish(
            work.path(),
            &fish_script,
            "mcp-gateway tool invoke good_cap g"
        )
        .contains(&"good_cap".to_owned())
    );
    assert!(
        !pwsh(
            work.path(),
            &pwsh_script,
            "mcp-gateway tool invoke good_cap g",
            true
        )
        .contains(&"good_cap".to_owned())
    );
    both(
        "mcp-gateway tool invoke good_cap --log-level ",
        &["trace", "debug", "info", "warn", "error"],
    );
    both(
        "mcp-gateway identity grants grant --scope ",
        &["read", "execute", "any"],
    );
    both(
        "mcp-gateway identity grants --config grant ",
        &["list", "grant", "revoke", "help"],
    );
    both(
        "mcp-gateway tool --config invoke ",
        &["invoke", "list", "inspect", "completions", "help"],
    );
    both(
        "mcp-gateway tool --config=invoke ",
        &["invoke", "list", "inspect", "completions", "help"],
    );
    both(
        "mcp-gateway tool -cinvoke ",
        &["invoke", "list", "inspect", "completions", "help"],
    );
    both("mcp-gateway tool invoke --config planted.yaml ", &TOOLS);
    both("mcp-gateway init --profile ", &["local", "minimal"]);
    both(
        "mcp-gateway tool ",
        &["invoke", "list", "inspect", "completions", "help"],
    );
    for line in [
        "mcp-gateway tool invoke --config ",
        "mcp-gateway tool invoke -c ",
    ] {
        assert_eq!(
            fish(work.path(), &fish_script, line),
            ["planted.yaml"],
            "fish: {line:?}"
        );
        let default = pwsh(work.path(), &pwsh_script, line, false);
        assert!(
            !default.is_empty(),
            "PowerShell's own path completion found the planted file"
        );
        assert_eq!(
            pwsh(work.path(), &pwsh_script, line, true),
            default,
            "pwsh: {line:?}"
        );
    }
    assert_eq!(
        fish(
            work.path(),
            &fish_script,
            "mcp-gateway tool invoke --config="
        ),
        ["--config=planted.yaml"]
    );
    assert_eq!(
        pwsh(
            work.path(),
            &pwsh_script,
            "mcp-gateway tool invoke --log-level=d",
            true
        ),
        ["--log-level=debug"]
    );
    for (line, member) in [
        ("mcp-gateway tool invoke good_cap --", "--format"),
        ("mcp-gateway tool completions bash --", "--help"),
        ("mcp-gateway identity grants grant --", "--grant-id"),
        ("mcp-gateway init --with-examples --", "--profile"),
        ("mcp-gateway doctor --no-registry-check --", "--help"),
    ] {
        for got in [
            fish(work.path(), &fish_script, line),
            pwsh(work.path(), &pwsh_script, line, true),
        ] {
            assert!(got.contains(&member.to_owned()), "{line:?}: {got:?}");
            assert!(
                got.iter().all(|c| c.starts_with('-')),
                "{line:?}: only flags: {got:?}"
            );
        }
    }
    let upper = pwsh(work.path(), &pwsh_script, "mcp-gateway TOOL ", true);
    assert!(
        !upper.contains(&"invoke".to_owned()),
        "a finished word matches exactly: {upper:?}"
    );
    assert_eq!(
        pwsh(work.path(), &pwsh_script, "mcp-gateway to", true),
        ["tool"]
    );
    assert!(!pwsh(work.path(), &pwsh_script, "mcp-gateway TO", true).contains(&"tool".to_owned()));
    assert_eq!(
        pwsh(work.path(), &pwsh_script, "mcp-gateway t", true),
        ["tls", "tool"]
    );
    assert!(pwsh(work.path(), &pwsh_script, "mcp-gateway t*", true).is_empty());
    let upper_flag = pwsh(
        work.path(),
        &pwsh_script,
        "mcp-gateway tool invoke --LOG-LEVEL ",
        true,
    );
    assert_eq!(
        upper_flag,
        sorted(&TOOLS),
        "an uppercase option name is a flag word, not a waiting option"
    );
}

/// C5's red proof against clap_complete: its own fish and PowerShell scripts for the same tree get these cases wrong,
/// each in the named way (cases it gets right are not claimed).
#[test]
fn clap_completes_own_fish_and_powershell_get_the_named_cases_wrong() {
    let home = tempfile::tempdir().expect("home");
    let work = tempfile::tempdir().expect("work");
    std::fs::write(work.path().join("planted.yaml"), "x").expect("planted");
    let tools: Vec<String> = TOOLS.iter().map(|s| (*s).to_owned()).collect();
    let clap_script = |shell: clap_complete::Shell, file: &str| {
        let mut tree = mcp_gateway::cli::completion::completion_tree(&tools);
        let mut out = Vec::new();
        clap_complete::generate(shell, &mut tree, "mcp-gateway", &mut out);
        let path = home.path().join(file);
        std::fs::write(&path, out).expect("script");
        path
    };
    let fish_script = clap_script(clap_complete::Shell::Fish, "clap.fish");
    let pwsh_script = clap_script(clap_complete::Shell::PowerShell, "clap.ps1");
    assert!(
        pwsh(
            work.path(),
            &pwsh_script,
            "mcp-gateway tool invoke good_cap --",
            true
        )
        .is_empty()
    );
    let values = pwsh(
        work.path(),
        &pwsh_script,
        "mcp-gateway tool invoke good_cap --log-level ",
        true,
    );
    assert!(!values.contains(&"trace".to_owned()), "{values:?}");
    let config = pwsh(
        work.path(),
        &pwsh_script,
        "mcp-gateway tool invoke --config ",
        true,
    );
    assert!(
        config.contains(&"--format".to_owned()),
        "clap_complete offers flags, not paths: {config:?}"
    );
    let names = fish(work.path(), &fish_script, "mcp-gateway tool invoke ");
    assert!(
        !names.contains(&"good_cap".to_owned()) && !names.contains(&"other_cap".to_owned()),
        "{names:?}"
    );
    let subs = fish(
        work.path(),
        &fish_script,
        "mcp-gateway tool --config invoke ",
    );
    assert!(
        !subs.contains(&"inspect".to_owned()),
        "clap_complete reads `invoke` as seen: {subs:?}"
    );
}

/// C6: hostile values never reach the shells, hostile help text shows as written, every inserted value is one literal
/// argument, and nothing runs.
#[test]
fn hostile_input_stays_inert() {
    use mcp_gateway::cli::completion::{CompletionShell, generate};
    const HELP: &str =
        "say 'hi' $(touch canary) a\\'b ~x *y \u{2018}a\u{2019} \u{201a}b\u{201b} \\`";
    let safe = ["good_cap", "café", "x.y-z", "_private", "9", "2fa_check"];
    let refused = [
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
    let tree = || {
        let values: Vec<&'static str> = safe.iter().chain(refused.iter()).copied().collect();
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
                            .help(HELP),
                    ),
            ),
        )
    };
    let home = tempfile::tempdir().expect("home");
    let work = tempfile::tempdir().expect("work");
    let fish_gen = generate(CompletionShell::Fish, tree());
    let pwsh_gen = generate(CompletionShell::Powershell, tree());
    assert_eq!(fish_gen.left_out, refused.map(str::to_owned).to_vec());
    let fish_script = home.path().join("h.fish");
    std::fs::write(&fish_script, &fish_gen.script).expect("fish");
    let pwsh_script = home.path().join("h.ps1");
    std::fs::write(&pwsh_script, &pwsh_gen.script).expect("pwsh");
    let parse = Command::new("fish")
        .args(["--no-config", "-n"])
        .arg(&fish_script)
        .output()
        .expect("fish");
    assert!(
        parse.status.success(),
        "fish parses the whole script: {}",
        String::from_utf8_lossy(&parse.stderr)
    );
    let mut want: Vec<String> = safe.map(str::to_owned).to_vec();
    want.sort();
    assert_eq!(
        fish(work.path(), &fish_script, "mcp-gateway tool invoke "),
        want
    );
    let pwsh_list = Command::new("pwsh")
        .current_dir(work.path())
        .args(["-NoProfile", "-NonInteractive", "-Command"])
        .arg(format!(
            ". '{}'; (TabExpansion2 -inputScript 'mcp-gateway tool invoke ' -cursorColumn 24).CompletionMatches | ForEach-Object {{ $_.ListItemText }}",
            pwsh_script.display()
        ))
        .output()
        .expect("pwsh");
    let mut listed: Vec<String> = String::from_utf8_lossy(&pwsh_list.stdout)
        .lines()
        .map(str::to_owned)
        .collect();
    listed.sort();
    assert_eq!(listed, want);
    let fish_desc = Command::new("fish")
        .current_dir(work.path())
        .args(["--no-config", "-c"])
        .arg(format!(
            "source {}; and complete -C 'mcp-gateway tool invoke --n'",
            fish_script.display()
        ))
        .output()
        .expect("fish");
    assert_eq!(
        String::from_utf8_lossy(&fish_desc.stdout).trim_end(),
        format!("--note\t{HELP}")
    );
    let pwsh_tip = Command::new("pwsh")
        .current_dir(work.path())
        .args(["-NoProfile", "-NonInteractive", "-Command"])
        .arg(format!(
            ". '{}'; (TabExpansion2 -inputScript 'mcp-gateway tool invoke --n' -cursorColumn 27).CompletionMatches | ForEach-Object {{ $_.ToolTip }}",
            pwsh_script.display()
        ))
        .output()
        .expect("pwsh");
    assert_eq!(String::from_utf8_lossy(&pwsh_tip.stdout).trim_end(), HELP);
    for value in safe {
        let prefix = &value[..1];
        let line = format!("mcp-gateway tool invoke {prefix}");
        let escaped = Command::new("fish")
            .current_dir(work.path())
            .args(["--no-config", "-c"])
            .arg(format!(
                "source {}; and complete --escape -C {}",
                fish_script.display(),
                shell_words(&line)
            ))
            .output()
            .expect("fish");
        let inserted = String::from_utf8_lossy(&escaped.stdout)
            .lines()
            .map(|l| l.split('\t').next().unwrap_or_default().to_owned())
            .find(|c| c.trim_matches('\'') == value || c == value)
            .unwrap_or_else(|| panic!("fish offers {value}"));
        let printed = Command::new("fish")
            .args(["--no-config", "-c"])
            .arg(format!("printf '%s\\n' {inserted}"))
            .output()
            .expect("fish");
        assert_eq!(
            String::from_utf8_lossy(&printed.stdout),
            format!("{value}\n"),
            "fish inserts {value} as one word"
        );
        let text = if value.starts_with(|c: char| c.is_ascii_digit()) {
            format!("'{value}'")
        } else {
            value.to_owned()
        };
        let printed = Command::new("pwsh")
            .args(["-NoProfile", "-NonInteractive", "-Command"])
            .arg(format!("& {{ $args.Count; $args }} {text}"))
            .output()
            .expect("pwsh");
        assert_eq!(
            String::from_utf8_lossy(&printed.stdout),
            format!("1\n{value}\n"),
            "pwsh inserts {value} as one argument"
        );
    }
    assert!(
        !work.path().join("canary").exists() && !home.path().join("canary").exists(),
        "nothing ran"
    );
}
