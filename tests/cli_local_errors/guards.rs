// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Guards for the second half of the local-errors work: verdict exits keep their code and their text. These rows
//! are committed before any file they guard is converted, so the text they pin is today's.

use super::{Case, Pin, gateway_bin, run, strings, text, two_lines, write};

/// A wrong invocation of `leaf`: exit 2, `first` on line one, the leaf's help pointer on line two.
fn wrong_call(leaf: &str, args: Vec<String>, first: Pin) -> Case {
    Case {
        args,
        exit: 2,
        stdout: String::new(),
        first,
        second: Pin::Exact(format!("Run 'mcp-gateway {leaf} --help' for usage.")),
        env: Vec::new(),
    }
}

/// `args` after `--log-level off`, with `stdin` piped in and closed.
fn run_with_stdin(args: &[String], stdin: &[u8]) -> std::process::Output {
    let mut all = strings(&["--log-level", "off"]);
    all.extend(args.iter().cloned());
    let refs: Vec<&str> = all.iter().map(String::as_str).collect();
    gateway_bin::run_cli(&refs, &[], Some(stdin))
}

/// Fails with every miss of every case, each named.
fn check(cases: Vec<(&str, std::process::Output, Case)>) {
    let mut misses = Vec::new();
    for (label, out, case) in &cases {
        misses.extend(two_lines(label, out, case));
    }
    assert!(misses.is_empty(), "{}", misses.join("\n"));
}

/// A capability with no outcome verb in its name or description, so the validator reports a failure.
const VERDICT_CAPABILITY: &str = "name: zz\ndescription: Zz\nproviders:\n  primary:\n    service: rest\n    config:\n      base_url: https://gw.test\n      path: /x\n";

/// V3: validate on a file it cannot parse keeps its verdict code 2 and its text.
#[test]
fn validate_unparseable_keeps_its_verdict() {
    let scratch = tempfile::tempdir().expect("scratch");
    let file = scratch.path().join("bad.yaml");
    write(&file, "x: [\n");
    let out = run(&strings(&["validate", &text(&file)]));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {stderr:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "\nSummary: 0 passed, 0 warnings, 0 failures\n"
    );
    let want = format!("Parse error in {}: ", text(&file));
    assert!(stderr.starts_with(&want), "stderr: {stderr:?}");
    assert_eq!(stderr.lines().count(), 1, "stderr: {stderr:?}");
}

/// V4: validate on a capability with a finding keeps its verdict code 1 and its report.
#[test]
fn validate_finding_keeps_its_verdict() {
    let scratch = tempfile::tempdir().expect("scratch");
    let file = scratch.path().join("zz.yaml");
    write(&file, VERDICT_CAPABILITY);
    let out = run(&strings(&["validate", &text(&file)]));
    let stdout = String::from_utf8_lossy(&out.stdout).replace(&text(&file), "{file}");
    assert_eq!(out.status.code(), Some(1), "stdout: {stdout:?}");
    assert_eq!(String::from_utf8_lossy(&out.stderr), "");
    // Digest pin (copy guard blocks the literal; guard row 63): the structure below is readable, and the sha256 of
    // the complete report, with the scratch path written as {file}, keeps the pin byte-exact. The digest was
    // computed on Spark from the unconverted head; on a mismatch the whole report is printed.
    assert!(stdout.starts_with("\n--- {file} ---\n"), "stdout: {stdout}");
    for (marker, code) in [
        ("FAIL", "AX-001"),
        ("PASS", "AX-002"),
        ("FAIL", "AX-003"),
        ("PASS", "AX-004"),
        ("WARN", "AX-005"),
        ("PASS", "AX-006"),
        ("FAIL", "AX-007"),
        ("PASS", "AX-008"),
        ("PASS", "AX-009"),
        ("PASS", "AX-010"),
    ] {
        let line = format!("  [{marker}] [{code}] zz - ");
        assert!(
            stdout.lines().any(|l| l.starts_with(&line)),
            "{code} is not {marker}: {stdout}"
        );
    }
    assert!(
        stdout.ends_with("\nSummary: 6 passed, 1 warnings, 3 failures\n"),
        "stdout: {stdout}"
    );
    let digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(stdout.as_bytes()));
    assert_eq!(
        digest, "d8f5083ae522eef3d6acaf49885122a71136370b2d9d392b97d5c38bbf34cd13",
        "stdout: {stdout}"
    );
}

/// M1-M6: wrong invocations that exit 1 today move to 2, each with its help pointer.
#[test]
fn wrong_invocations_exit_two() {
    let scratch = tempfile::tempdir().expect("scratch");
    let p = scratch.path();
    write(&p.join("zz.yaml"), VERDICT_CAPABILITY);
    let dir = text(p);
    let cap = text(&p.join("zz.yaml"));
    // M5 names a baseline to write: the refusal must come before the evaluation writes it.
    let baseline = p.join("baseline.json");
    let cases = vec![
        (
            "kubernetes controller",
            strings(&[
                "kubernetes",
                "controller",
                &text(&p.join("r.yaml")),
                "--watch",
                "--interval-seconds",
                "0",
            ]),
            Pin::Exact("error: --watch requires --interval-seconds greater than 0".to_owned()),
        ),
        (
            "accounts migrate-credentials",
            strings(&[
                "accounts",
                "migrate-credentials",
                "--descriptor-id",
                "d",
                "--legacy-issuer",
                "https://issuer.test",
            ]),
            Pin::Starts("error: accounts migrate-credentials needs an explicit configuration"),
        ),
        (
            "accounts init-store",
            strings(&["accounts", "init-store"]),
            Pin::Starts("error: accounts init-store needs an explicit configuration"),
        ),
        (
            "cap test",
            strings(&["cap", "test", &cap, "--args", "{"]),
            Pin::Starts("error: Invalid JSON arguments"),
        ),
        (
            "trust lab evaluate",
            strings(&[
                "trust",
                "lab",
                "evaluate",
                "-C",
                &dir,
                "--update-baseline-registry",
                "--write-baseline",
                &text(&baseline),
            ]),
            Pin::Exact("error: --update-baseline-registry requires --baseline-registry".to_owned()),
        ),
        (
            "tool invoke",
            strings(&["tool", "invoke", "zz", "-C", &dir, "--args", "{"]),
            Pin::Starts("error: "),
        ),
    ];
    let results = cases
        .into_iter()
        .map(|(leaf, args, first)| {
            let out = run(&args);
            (leaf, out, wrong_call(leaf, args, first))
        })
        .collect();
    // Before the shape checks, so a red here names the write, not M5's exit code.
    assert!(
        !baseline.exists(),
        "trust lab evaluate wrote {} before refusing",
        baseline.display()
    );
    check(results);
}

/// B1, B2: `tool invoke`'s other argument refusals share the `--args` error arm but stay exit 1.
#[test]
fn tool_invoke_bad_stdin_and_pairs_stay_one() {
    let scratch = tempfile::tempdir().expect("scratch");
    let p = scratch.path();
    write(&p.join("zz.yaml"), VERDICT_CAPABILITY);
    let dir = text(p);
    let local = |args: Vec<String>| Case {
        args,
        exit: 1,
        stdout: String::new(),
        first: Pin::Starts("error: "),
        second: Pin::NonEmpty,
        env: Vec::new(),
    };
    let stdin_args = strings(&["tool", "invoke", "zz", "-C", &dir]);
    let pair_args = strings(&["tool", "invoke", "zz", "-C", &dir, "novalue"]);
    check(vec![
        (
            "stdin not JSON",
            run_with_stdin(&stdin_args, b"{"),
            local(stdin_args),
        ),
        ("a pair without =", run(&pair_args), local(pair_args)),
    ]);
}
/// X2-X10: every wrong invocation that exits 2 today still exits 2, now with the two lines and a help pointer
/// (X7, an unreadable --env-file, names the file instead).
#[test]
fn exits_that_were_two_stay_two() {
    let scratch = tempfile::tempdir().expect("scratch");
    let p = scratch.path();
    let config = text(&p.join("g.yaml"));
    let env_file = text(&p.join("missing.json"));
    let short = b"k-abc\n";
    let hash_key = strings(&["hash-key"]);
    let bad_verify = strings(&["hash-key", "--verify", "sha256:xyz"]);
    let env_args = strings(&[
        "--config",
        &config,
        "add",
        "x",
        "--command",
        "echo",
        "--env-file",
        &env_file,
    ]);
    let value_args = strings(&[
        "--config",
        &config,
        "add",
        "x",
        "--command",
        "echo",
        "-e",
        "FOO=bar",
    ]);
    let url_args = strings(&[
        "--config",
        &config,
        "add",
        "x",
        "--url",
        "https://u:p@gw.test/mcp",
    ]);
    let spec = text(&p.join("spec.json"));
    let auth_args = strings(&[
        "cap",
        "import",
        &spec,
        "--auth-key",
        "plain-text-not-a-reference",
    ]);
    let mut env_case = wrong_call("add", env_args.clone(), Pin::Starts("error: "));
    env_case.second = Pin::Has(env_file.clone());
    let mut cases = vec![
        (
            "too long",
            run_with_stdin(&hash_key, &vec![b'k'; 65537]),
            wrong_call("hash-key", hash_key.clone(), Pin::Starts("error: ")),
        ),
        (
            "too short",
            run_with_stdin(&hash_key, short),
            wrong_call(
                "hash-key",
                hash_key.clone(),
                Pin::Exact(
                    "error: the key is 5 bytes; a new key needs at least 20 bytes".to_owned(),
                ),
            ),
        ),
        (
            "bad --verify",
            run_with_stdin(&bad_verify, short),
            wrong_call(
                "hash-key",
                bad_verify.clone(),
                Pin::Starts("error: --verify takes sha256:"),
            ),
        ),
        ("--env-file unreadable", run(&env_args), env_case),
        (
            "-e with a value",
            run(&value_args),
            wrong_call("add", value_args.clone(), Pin::Starts("error: -e takes")),
        ),
        (
            "credential in the URL",
            run(&url_args),
            wrong_call("add", url_args.clone(), Pin::Starts("error: ")),
        ),
        (
            "--auth-key not a reference",
            run(&auth_args),
            wrong_call(
                "cap import",
                auth_args.clone(),
                Pin::Starts("error: --auth-key takes a credential reference"),
            ),
        ),
    ];
    // X2: stdin that cannot be read, a folder opened as stdin.
    #[cfg(unix)]
    {
        let folder = std::fs::File::open(p).expect("open the scratch folder");
        let out = super::run_env(&hash_key, &[], std::process::Stdio::from(folder));
        cases.push((
            "stdin unreadable",
            out,
            wrong_call("hash-key", hash_key.clone(), Pin::Starts("error: ")),
        ));
    }
    check(cases);
}

/// X1: hash-key with a terminal on stdin (no piped key) is a wrong invocation, exit 2.
#[cfg(target_os = "linux")]
#[test]
fn hash_key_on_a_terminal_is_a_wrong_call() {
    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
    let leader = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).expect("open a pseudo-terminal");
    grantpt(&leader).expect("grant");
    unlockpt(&leader).expect("unlock");
    let name = ptsname(&leader, Vec::new()).expect("follower name");
    let follower = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(name.to_str().expect("utf-8"))
        .expect("open the follower");
    let hash_key = strings(&["hash-key"]);
    let out = super::run_env(&hash_key, &[], std::process::Stdio::from(follower));
    check(vec![(
        "a terminal on stdin",
        out,
        wrong_call("hash-key", hash_key, Pin::Starts("error: ")),
    )]);
}

/// L1: a line break in a path keeps two lines when the error leaves through a built result (`cap test`).
#[cfg(unix)]
#[test]
fn a_line_break_in_a_built_error_keeps_two_lines() {
    let scratch = tempfile::tempdir().expect("scratch");
    let file = scratch.path().join("a\nb.yaml");
    let shown = format!("{}/a b.yaml", text(scratch.path()));
    let args = strings(&["cap", "test", &text(&file)]);
    let out = run(&args);
    let case = Case {
        args,
        exit: 1,
        stdout: String::new(),
        first: Pin::Has(shown),
        second: Pin::NonEmpty,
        env: Vec::new(),
    };
    check(vec![("cap test (line break)", out, case)]);
}

/// L2: a note printed before a failure stays, and the error and its remedy are the last two lines.
#[test]
fn local_errors_end_with_the_two_lines() {
    let scratch = tempfile::tempdir().expect("scratch");
    let missing = text(&scratch.path().join("missing"));
    let out = run(&strings(&["validate", &missing]));
    let stderr = String::from_utf8_lossy(&out.stderr);
    let lines: Vec<&str> = stderr.lines().collect();
    assert_eq!(out.status.code(), Some(2), "stderr: {stderr:?}");
    assert!(lines.len() >= 3, "the note and the two lines: {stderr:?}");
    let tail = &lines[lines.len() - 2..];
    assert_eq!(
        tail[0],
        "error: No YAML capability files found in the given paths."
    );
    assert_eq!(tail[1], "Run 'mcp-gateway validate --help' for usage.");
    assert!(
        !lines[..lines.len() - 2]
            .iter()
            .any(|l| l.starts_with("error: ")),
        "an earlier error line: {stderr:?}"
    );
}

/// D1: the upgrade notes name each move from 1 to 2 and say the error text changed.
#[test]
fn upgrade_notes_name_each_move() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut docs =
        vec![std::fs::read_to_string(root.join("docs/UPGRADING-4.0.md")).unwrap_or_default()];
    for entry in std::fs::read_dir(root.join("upgrading.d")).expect("upgrading.d") {
        docs.push(std::fs::read_to_string(entry.expect("entry").path()).unwrap_or_default());
    }
    let moves: [&[&str]; 6] = [
        &["kubernetes controller", "--watch", "--interval-seconds"],
        &["accounts migrate-credentials", "--config"],
        &["accounts init-store", "--config"],
        &["cap test", "JSON"],
        &[
            "trust lab evaluate",
            "--update-baseline-registry",
            "--baseline-registry",
        ],
        &["tool invoke", "--args", "JSON"],
    ];
    let names = |doc: &str, words: &[&str]| {
        doc.lines()
            .any(|line| words.iter().all(|w| line.contains(w)) && line.contains("1 becomes 2"))
    };
    let missing: Vec<&str> = moves
        .iter()
        .filter(|w| !docs.iter().any(|d| names(d, w)))
        .map(|w| w[0])
        .collect();
    assert!(
        missing.is_empty(),
        "upgrade notes name no 1-to-2 move for: {missing:?}"
    );
    let says_shape = docs.iter().any(|d| {
        moves.iter().all(|w| names(d, w))
            && d.split(['.', '\n'])
                .any(|s| s.contains("two") && s.contains("stderr"))
    });
    assert!(
        says_shape,
        "no note says the error text changed to two stderr lines"
    );
}
