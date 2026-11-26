// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A local command that fails says so in two stderr lines, `error: <what happened>` and then what to do, exits 1
//! (2 for a wrong invocation), and keeps stdout to what it printed before failing. The table holds one entry per
//! leaf of the real command tree except the four remote leaves, so a command added without an entry fails here.
//! Every leaf is checked through the built binary at `--log-level off`: a forced failure in the two-line shape, or,
//! for a leaf with no local failure to force, a plain run that exits 0; `serve` keeps its own fatal-line contract.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;
#[path = "cli_local_errors/guards.rs"]
mod guards;
#[path = "cli_local_errors/leaves_b.rs"]
mod leaves_b;
#[path = "common/provenance_fixture.rs"]
mod provenance_fixture;
#[path = "cli_local_errors/scenarios.rs"]
mod scenarios;

use std::path::Path;
use std::process::Output;

use clap::CommandFactory as _;

/// The remote leaves, which report on the remote error shape instead.
const REMOTE: [&str; 4] = [
    "api",
    "audit lookup-email",
    "dashboard-link",
    "events dead-letters",
];

/// What one stderr line must hold.
enum Pin {
    Exact(String),
    Has(String),
    Starts(&'static str),
    #[cfg_attr(
        not(feature = "discovery"),
        allow(
            dead_code,
            reason = "only the cap import-url row, built with discovery, uses it"
        )
    )]
    NonEmpty,
}

/// One forced failure: the arguments after the global flags, and what must come out.
struct Case {
    args: Vec<String>,
    exit: i32,
    stdout: String,
    first: Pin,
    second: Pin,
    /// Environment the row sets after the cleared one (only `cap discover` needs any).
    env: Vec<(&'static str, String)>,
}

/// What the table says about a leaf.
enum Expect {
    /// Converted: a forced failure built in the given scratch folder.
    TwoLines(fn(&Path) -> Case),
    /// No local failure to force; the row runs these arguments and the leaf must exit 0. The reason is read in review.
    CannotFail(fn(&Path) -> Vec<String>, &'static str),
    /// Out of scope, with the reason.
    Exempt(&'static str),
}

/// Every leaf path of the real command tree (clap's generated `help` nodes left out), sorted.
fn leaves() -> Vec<String> {
    let mut root = mcp_gateway::cli::Cli::command();
    root.build();
    let mut found = Vec::new();
    let mut todo: Vec<(String, &clap::Command)> = vec![(String::new(), &root)];
    while let Some((path, node)) = todo.pop() {
        let mut children = node
            .get_subcommands()
            .filter(|c| c.get_name() != "help")
            .peekable();
        if children.peek().is_none() {
            found.push(path);
            continue;
        }
        for child in children {
            let name = child.get_name();
            let joined = if path.is_empty() {
                name.to_owned()
            } else {
                format!("{path} {name}")
            };
            todo.push((joined, child));
        }
    }
    found.sort();
    found
}

fn text(path: &Path) -> String {
    path.display().to_string()
}

fn write(path: &Path, body: &str) {
    std::fs::create_dir_all(path.parent().expect("parent")).expect("dirs");
    std::fs::write(path, body).expect("write fixture");
    // Owner-only: the gateway refuses a config others can read, and the runner's umask decides that, so a
    // group-readable fixture would stop at that refusal before the row's own error.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("fixture mode");
    }
}

/// A loopback URL nothing can listen on: port 0 is never a listening port, so the connection is refused at once,
/// and no port is picked and released for a parallel test to take.
fn closed_url() -> String {
    "http://127.0.0.1:0".to_owned()
}

fn fail_case(args: Vec<String>, first: Pin, second: Pin) -> Case {
    Case {
        args,
        exit: 1,
        stdout: String::new(),
        first,
        second,
        env: Vec::new(),
    }
}

fn strings(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| (*s).to_owned()).collect()
}

/// A TLS output folder that already holds `name`, and the "already exists" pins for it.
fn tls_taken(p: &Path, name: &str) -> (String, Pin, Pin) {
    let out = p.join("out");
    write(&out.join(name), "taken\n");
    // Joined, not formatted with `/`: Windows writes the path with backslashes.
    let first = Pin::Exact(format!("error: {} already exists.", text(&out.join(name))));
    let second = Pin::Exact("Remove it first or choose a different --out.".to_owned());
    (text(&out), first, second)
}

fn tls_issue(p: &Path, leaf: &str, cn: &str, taken: &str) -> Case {
    let (out, first, second) = tls_taken(p, taken);
    let mut args = strings(&["tls", leaf, "--cn", cn]);
    args.extend([
        "--ca-cert".to_owned(),
        text(&p.join("none.crt")),
        "--ca-key".to_owned(),
        text(&p.join("none.key")),
        "--out".to_owned(),
        out,
    ]);
    fail_case(args, first, second)
}

fn config_case(p: &Path, leaf: &[&str], flag: &str) -> Case {
    let file = p.join("gateway.yaml");
    write(&file, "backends: [\n");
    config_at(&file, leaf, flag)
}

fn config_at(file: &Path, leaf: &[&str], flag: &str) -> Case {
    let mut args = strings(leaf);
    args.extend([flag.to_owned(), text(file)]);
    fail_case(
        args,
        Pin::Starts("error: "),
        // Quoted as the command line names it: a Windows path with backslashes comes out in quotes.
        Pin::Has(format!(
            "mcp-gateway doctor --config {}",
            shlex::try_quote(&text(file)).expect("a path without NUL")
        )),
    )
}

fn grants_case(p: &Path, tail: &[&str]) -> Case {
    let dir = p.join("grants-dir");
    std::fs::create_dir_all(&dir).expect("dir");
    let mut args = strings(&["identity", "grants"]);
    args.push(tail[0].to_owned());
    args.extend(["--file".to_owned(), text(&dir)]);
    args.extend(strings(&tail[1..]));
    fail_case(args, Pin::Starts("error: "), Pin::Has(text(&dir)))
}

fn missing_input(p: &Path, leaf: &[&str], name: &str, extra: &[&str]) -> Case {
    let file = p.join(name);
    let mut args = strings(leaf);
    args.push(text(&file));
    for part in extra {
        args.push(part.replace("{p}", &text(p)));
    }
    fail_case(args, Pin::Starts("error: "), Pin::Has(text(&file)))
}

/// The table: every local leaf, keyed by its path.
#[allow(clippy::too_many_lines, reason = "one entry per leaf of the real tree")]
fn table() -> Vec<(&'static str, Expect)> {
    let mut rows: Vec<(&'static str, Expect)> = vec![
        (
            "init",
            Expect::TwoLines(|p| {
                let file = p.join("gateway.yaml");
                write(&file, "x\n");
                fail_case(
                    strings(&["init", "--output", &text(&file)]),
                    Pin::Exact(format!("error: {} already exists.", text(&file))),
                    Pin::Exact(
                        "Remove it first or choose a different path with --output.".to_owned(),
                    ),
                )
            }),
        ),
        (
            "tls init-ca",
            Expect::TwoLines(|p| {
                let (out, first, second) = tls_taken(p, "ca.crt");
                fail_case(strings(&["tls", "init-ca", "--out", &out]), first, second)
            }),
        ),
        (
            "tls issue-server",
            Expect::TwoLines(|p| tls_issue(p, "issue-server", "gw", "server.crt")),
        ),
        (
            "tls issue-client",
            Expect::TwoLines(|p| tls_issue(p, "issue-client", "agent 1", "agent-1.crt")),
        ),
        (
            "doctor",
            Expect::TwoLines(|_| Case {
                env: Vec::new(),
                args: strings(&["doctor", "--shadow", "--shadow-format", "bogus"]),
                exit: 2,
                stdout: String::new(),
                first: Pin::Exact(
                    "error: unknown --shadow-format 'bogus'. Valid values: grep, nginx, yaml"
                        .to_owned(),
                ),
                second: Pin::Exact("Run 'mcp-gateway doctor --help' for usage.".to_owned()),
            }),
        ),
        (
            "ranking eval",
            Expect::TwoLines(|p| missing_input(p, &["ranking", "eval"], "missing.yaml", &[])),
        ),
        (
            "import preview",
            Expect::TwoLines(|p| {
                missing_input(
                    p,
                    &["import", "preview", "--kind", "openapi"],
                    "missing.json",
                    &[],
                )
            }),
        ),
        (
            "import apply",
            Expect::TwoLines(|p| {
                missing_input(
                    p,
                    &["import", "apply", "--kind", "openapi"],
                    "missing.json",
                    &["--output", "{p}/drafts"],
                )
            }),
        ),
        (
            "identity grants list",
            Expect::TwoLines(|p| grants_case(p, &["list"])),
        ),
        (
            "identity grants grant",
            Expect::TwoLines(|p| {
                grants_case(
                    p,
                    &[
                        "grant",
                        "--grant-id",
                        "g1",
                        "--subject",
                        // AUTHORITY:SUBJECT, so every argument is valid and the row reaches the file.
                        "api_key:s1",
                        "--any-agent",
                        "--capability",
                        "c1",
                        "--reason",
                        "r",
                    ],
                )
            }),
        ),
        (
            "identity grants revoke",
            Expect::TwoLines(|p| grants_case(p, &["revoke", "--grant-id", "g1"])),
        ),
        (
            "setup wizard",
            Expect::TwoLines(|p| Case {
                stdout: "MCP Gateway Setup\n=================\n\n".to_owned(),
                ..config_case(p, &["setup", "wizard", "--yes"], "--output")
            }),
        ),
        (
            "stats",
            Expect::TwoLines(|_| {
                let url = closed_url();
                fail_case(
                    strings(&["stats", "--gateway", &url]),
                    Pin::Starts("error: "),
                    Pin::Has(url),
                )
            }),
        ),
        (
            "upgrade",
            Expect::TwoLines(|p| {
                let file = p.join("missing.yaml");
                let data = p.join("data");
                fail_case(
                    strings(&[
                        "--config",
                        &text(&file),
                        "upgrade",
                        "--data-dir",
                        &text(&data),
                    ]),
                    Pin::Exact(format!(
                        "error: {} not found; nothing was upgraded.",
                        text(&file)
                    )),
                    Pin::Has(text(&file)),
                )
            }),
        ),
        (
            "serve",
            Expect::Exempt(
                "start failures keep the one escaped fatal line of tests/serve_fatal_lines.rs",
            ),
        ),
    ];
    #[cfg(feature = "config-export")]
    rows.push((
        "setup export",
        Expect::TwoLines(|p| config_case(p, &["setup", "export"], "--config")),
    ));
    #[cfg(feature = "discovery")]
    rows.push((
        "cap import-url",
        Expect::TwoLines(|p| Case {
            env: Vec::new(),
            args: vec![
                "cap".to_owned(),
                "import-url".to_owned(),
                "not-a-url".to_owned(),
                "--output".to_owned(),
                text(&p.join("caps")),
            ],
            exit: 1,
            stdout: "Discovering API spec from not-a-url ...\n".to_owned(),
            first: Pin::Starts("error: "),
            second: Pin::NonEmpty,
        }),
    ));
    #[cfg(feature = "runtime-substrate")]
    rows.push((
        "runtime compile",
        Expect::TwoLines(|p| missing_input(p, &["runtime", "compile"], "missing.yaml", &[])),
    ));
    rows.extend(leaves_b::rows());
    rows
}

/// Runs the binary with `args` after `--log-level off`, in a throwaway home; at most 60 s.
fn run(args: &[String]) -> Output {
    run_env(args, &[], std::process::Stdio::null())
}

/// [`run`] with `env` set after the cleared environment.
fn run_env(args: &[String], env: &[(&'static str, String)], stdin: std::process::Stdio) -> Output {
    let home = tempfile::tempdir().expect("home");
    let mut command = gateway_bin::command(home.path(), gateway_bin::Inherit::Nothing);
    command.envs(env.iter().map(|(k, v)| (*k, v.as_str())));
    command
        .env("MCP_GATEWAY_CONFIG_DIR", home.path())
        .arg("--log-level")
        .arg("off")
        .args(args)
        .stdin(stdin)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    finish(command)
}

/// Starts `command` and waits up to 60 s for it; one that has not returned by then is killed, reaped, and fails the
/// row. Either way the child has exited before this returns, so no caller's folder is removed under it.
fn finish(mut command: std::process::Command) -> Output {
    let mut child = command.spawn().expect("start mcp-gateway"); // spawn-check: waits for exit: wait_with_output below, or kill then wait after 60 s
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while child.try_wait().expect("poll").is_none() {
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the command did not return within 60 s");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    child.wait_with_output().expect("output")
}

/// Every check of a converted leaf's failure, each message showing the whole stderr.
fn two_lines(label: &str, out: &Output, case: &Case) -> Vec<String> {
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let mut misses = Vec::new();
    let mut miss = |what: String| misses.push(format!("{label}: {what}\n  stderr: {stderr:?}"));
    if out.status.code() != Some(case.exit) {
        miss(format!("exit {:?}, want {}", out.status.code(), case.exit));
    }
    if out.stdout != case.stdout.as_bytes() {
        miss(format!(
            "stdout {:?}, want {:?}",
            String::from_utf8_lossy(&out.stdout),
            case.stdout
        ));
    }
    let utf8 = std::str::from_utf8(&out.stderr).is_ok();
    let lines: Vec<&str> = stderr.lines().collect();
    if !utf8 || !stderr.ends_with('\n') || stderr.ends_with("\n\n") || lines.len() != 2 {
        miss(format!(
            "want exactly two UTF-8 lines ending in one newline, got {}",
            lines.len()
        ));
        return misses;
    }
    if !lines[0].starts_with("error: ") {
        miss("the first line does not start with `error: `".to_owned());
    }
    if lines[1].is_empty() {
        miss("the second line is empty".to_owned());
    }
    for (which, line, pin) in [
        ("first", lines[0], &case.first),
        ("second", lines[1], &case.second),
    ] {
        let held = match pin {
            Pin::Exact(want) => line == want,
            Pin::Has(want) => line.contains(want.as_str()),
            Pin::Starts(want) => line.starts_with(want),
            Pin::NonEmpty => !line.is_empty(),
        };
        if !held {
            miss(format!("the {which} line {line:?} misses its pin"));
        }
    }
    for banned in ["Error:", "❌", " { "] {
        if stderr.contains(banned) {
            miss(format!("stderr holds {banned:?}"));
        }
    }
    misses
}

/// T0: the table covers exactly the local leaves of the real tree.
#[test]
fn the_table_covers_every_local_leaf() {
    let all = leaves();
    for known in ["init", "cap list", "audit verify", "tls issue-client"] {
        assert!(
            all.iter().any(|l| l == known),
            "the walk missed {known}: {all:?}"
        );
    }
    assert!(all.len() >= 59, "only {} leaves walked", all.len());
    let want: Vec<String> = all
        .iter()
        .filter(|l| !REMOTE.contains(&l.as_str()))
        .cloned()
        .collect();
    let rows = table();
    let mut keys: Vec<String> = rows.iter().map(|(k, _)| (*k).to_owned()).collect();
    keys.sort();
    let mut unique = keys.clone();
    unique.dedup();
    assert_eq!(unique, keys, "a leaf appears twice in the table");
    let missing: Vec<&String> = want.iter().filter(|l| !keys.contains(l)).collect();
    let extra: Vec<&String> = keys.iter().filter(|k| !want.contains(k)).collect();
    assert!(
        missing.is_empty(),
        "leaves with no table entry: {missing:?}"
    );
    assert!(extra.is_empty(), "table entries for no leaf: {extra:?}");
    // With the keys equal to the real leaves and the CannotFail and Exempt sets pinned below, every other key is a
    // TwoLines row: that set is fixed by these three checks, so it is not listed a second time.
    let mut cannot_fail: Vec<&str> = rows
        .iter()
        // A leaf with no failure to force counts only with its reason written down.
        .filter(|(_, e)| matches!(e, Expect::CannotFail(_, why) if !why.trim().is_empty()))
        .map(|(k, _)| *k)
        .collect();
    cannot_fail.sort_unstable();
    assert_eq!(
        cannot_fail,
        [
            "cap install",
            "cap registry-list",
            "cap search",
            "provenance verify"
        ]
    );
    let exempt: Vec<&str> = rows
        .iter()
        // An exemption counts only with its reason written down.
        .filter(|(_, e)| matches!(e, Expect::Exempt(why) if !why.trim().is_empty()))
        .map(|(k, _)| *k)
        .collect();
    assert_eq!(exempt, ["serve"]);
}

/// T1: every converted leaf fails in the two-line shape.
#[test]
fn local_errors_are_two_lines() {
    let mut misses = Vec::new();
    for (leaf, expect) in table() {
        let scratch = tempfile::tempdir().expect("scratch");
        match expect {
            Expect::TwoLines(build) => {
                let case = build(scratch.path());
                let out = run_env(&case.args, &case.env, std::process::Stdio::null());
                misses.extend(two_lines(leaf, &out, &case));
            }
            Expect::CannotFail(args, _) => {
                let out = run(&args(scratch.path()));
                if out.status.code() != Some(0) {
                    misses.push(format!(
                        "{leaf}: exit {:?}, want 0\n  stderr: {:?}",
                        out.status.code(),
                        String::from_utf8_lossy(&out.stderr)
                    ));
                }
            }
            Expect::Exempt(_) => {}
        }
    }
    assert!(misses.is_empty(), "{}", misses.join("\n"));
}

/// T2: a line break in a path is written as a space, so the error stays two lines.
#[cfg(unix)]
#[test]
fn a_line_break_in_a_path_keeps_two_lines() {
    let scratch = tempfile::tempdir().expect("scratch");
    let file = scratch.path().join("a\nb.yaml");
    write(&file, "x\n");
    let case = fail_case(
        strings(&["init", "--output", &text(&file)]),
        Pin::Exact(format!(
            "error: {}/a b.yaml already exists.",
            text(scratch.path())
        )),
        Pin::Exact("Remove it first or choose a different path with --output.".to_owned()),
    );
    let misses = two_lines("init (line break)", &run(&case.args), &case);
    assert!(misses.is_empty(), "{}", misses.join("\n"));
}

/// T3: a CA key path that is not UTF-8 is a wrong invocation: exit 2, after the line already printed.
#[cfg(unix)]
#[test]
fn a_bad_ca_key_path_is_a_usage_error() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt as _;
    let scratch = tempfile::tempdir().expect("scratch");
    let p = scratch.path();
    write(&p.join("ca.crt"), "not a pem\n");
    let mut key = text(p).into_bytes();
    key.extend_from_slice(b"/\xff.key");
    let home = tempfile::tempdir().expect("home");
    let mut command = gateway_bin::command(home.path(), gateway_bin::Inherit::Nothing);
    command
        .env("MCP_GATEWAY_CONFIG_DIR", home.path())
        .args([
            "--log-level",
            "off",
            "tls",
            "issue-server",
            "--cn",
            "gw",
            "--ca-cert",
        ])
        .arg(p.join("ca.crt"))
        .arg("--ca-key")
        .arg(OsString::from_vec(key))
        .arg("--out")
        .arg(p.join("out"))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let out = finish(command);
    let case = Case {
        args: Vec::new(),
        env: Vec::new(),
        exit: 2,
        stdout: "Issuing server certificate for: gw\n".to_owned(),
        first: Pin::Exact("error: CA key path is not valid UTF-8".to_owned()),
        second: Pin::Exact("Run 'mcp-gateway tls issue-server --help' for usage.".to_owned()),
    };
    let misses = two_lines("tls issue-server (non-UTF-8 key)", &out, &case);
    assert!(misses.is_empty(), "{}", misses.join("\n"));
}

/// T4: `--json` does not change a local error: still two human lines, nothing on stdout.
#[test]
fn local_errors_ignore_json() {
    let url = closed_url();
    let case = fail_case(
        strings(&["stats", "--gateway", &url, "--json"]),
        Pin::Starts("error: "),
        Pin::Has(url.clone()),
    );
    let misses = two_lines("stats --json", &run(&case.args), &case);
    assert!(misses.is_empty(), "{}", misses.join("\n"));
}
