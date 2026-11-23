// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test plan T6-T8, the input sites (split from `remote_exit_tests` for the file-size ceiling): events' action
//! combinations, lookup's stdin and window, and the order of checks. Every case is a usage or local error that
//! sends nothing, or the first failing check of a multi-fault run.

use super::*;

pub(super) const INPUT_REMEDY: &str =
    "Pass one email (or the page token from the previous page) on stdin.";

/// A stdin that fails on its first read.
pub(super) struct Unreadable;

impl std::io::Read for Unreadable {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("planted read failure"))
    }
}

pub(super) async fn lookup_reading(
    flags: &[&str],
    stdin: impl std::io::Read,
    token: Option<&str>,
) -> CliOutcome {
    let mut full = vec!["audit", "lookup-email"];
    if !flags.contains(&"--cursor-stdin") {
        full.push("--email-stdin");
    }
    full.extend_from_slice(flags);
    let Command::Audit(AuditCommand::LookupEmail(args)) = parse(&full) else {
        panic!("not lookup-email")
    };
    let token = token.map(str::to_string);
    super::super::audit_lookup::lookup_outcome(args, loaded, None, None, stdin, move |name| {
        (name == "MCP_GATEWAY_TOKEN")
            .then(|| token.clone())
            .flatten()
    })
    .await
}

/// T6, events' action combinations are usage errors (2) and send nothing.
#[tokio::test]
async fn events_action_combinations_are_usage_errors() {
    let gw = gateway(json(200, r#"{"items":[]}"#)).await;
    let any = "use `list`, `replay ID` or `replay --all --subscription S`";
    for (argv, what) in [
        (vec!["replay"], any),
        (vec!["replay", "--all"], "replay --all needs --subscription"),
        (vec!["list", "dl-1"], any),
        (vec!["list", "--all"], any),
        (vec!["replay", "dl-1", "--all", "--subscription", "s"], any),
    ] {
        let mut argv = argv;
        argv.extend_from_slice(&["--url", gw.base.as_str()]);
        let out = events(&argv, ok_token()).await;
        failed(
            &out,
            CliExit::Usage,
            what,
            "Use list, replay ID, or replay --all --subscription S.",
            &argv.join(" "),
        );
    }
    check_eq!(
        gw.requests(),
        Vec::<Seen>::new(),
        "no request for a refused combination"
    );
    finish();
}

/// T7, stdin in email and cursor modes: unreadable is 1; every malformed input is 2; nothing is sent.
#[tokio::test]
async fn lookup_stdin_faults_exit_1_or_2() {
    let gw = gateway(json(200, LOOKUP_ANSWER)).await;
    let email = ["--url", gw.base.as_str()];
    let cursor = ["--cursor-stdin", "--url", gw.base.as_str()];
    let out = lookup_reading(&email, Unreadable, Some(TOKEN)).await;
    failed(
        &out,
        CliExit::LocalFailure,
        "could not read the email from stdin",
        "Check stdin and retry.",
        "email",
    );
    let out = lookup_reading(&cursor, Unreadable, Some(TOKEN)).await;
    failed(
        &out,
        CliExit::LocalFailure,
        "could not read the page token from stdin",
        "Check stdin and retry.",
        "cursor",
    );
    let long_email = "a".repeat(2000); // over MAX_EMAIL_INPUT (1024): the read bound decides
    let long_cursor = "A".repeat(8192);
    for (argv, stdin, what) in [
        (
            &email[..],
            long_email.as_bytes(),
            "the email on stdin is too long",
        ),
        (
            &email[..],
            &b"\xff\xfe"[..],
            "the email on stdin is not UTF-8",
        ),
        (
            &email[..],
            &b"a@b.test\nc@d.test\n"[..],
            "stdin must hold one line: the email",
        ),
        (&email[..], &b""[..], "stdin held no email"),
        (
            &email[..],
            &b"a\x07@b.test"[..],
            "the email on stdin is not valid",
        ),
        (
            &cursor[..],
            long_cursor.as_bytes(),
            "the page token on stdin is too long",
        ),
        (
            &cursor[..],
            &b"\xff\xfe"[..],
            "the page token on stdin is not UTF-8",
        ),
        (
            &cursor[..],
            &b"AQEB\nAQEC\n"[..],
            "stdin must hold one line: the page token",
        ),
        (&cursor[..], &b""[..], "stdin held no page token"),
        (
            &cursor[..],
            &b"AQEB AQEC"[..],
            "the page token on stdin is not valid",
        ),
    ] {
        let out = lookup(argv, stdin, Some(TOKEN)).await;
        failed(&out, CliExit::Usage, what, INPUT_REMEDY, what);
    }
    check_eq!(
        gw.requests(),
        Vec::<Seen>::new(),
        "no request for refused stdin"
    );
    finish();
}

/// T7, the window: either time not RFC 3339, or --from after --to, is 2; --from equal to --to succeeds.
#[tokio::test]
async fn lookup_window_faults_and_the_equal_boundary() {
    let gw = gateway(json(200, LOOKUP_ANSWER)).await;
    let remedy = "Use RFC 3339 times with --from not after --to.";
    let t1 = "2026-11-17T10:00:00Z";
    let t2 = "2026-11-17T11:00:00Z";
    for (window, what) in [
        (
            ["--from", "yesterday", "--to", t2],
            "--from and --to must be RFC 3339 times",
        ),
        (
            ["--from", t1, "--to", "today"],
            "--from and --to must be RFC 3339 times",
        ),
        (["--from", t2, "--to", t1], "--from must not be after --to"),
    ] {
        let mut argv = vec!["--url", gw.base.as_str()];
        argv.extend_from_slice(&window);
        let out = lookup(&argv, EMAIL.as_bytes(), Some(TOKEN)).await;
        failed(&out, CliExit::Usage, what, remedy, &window.join(" "));
    }
    check_eq!(
        gw.requests(),
        Vec::<Seen>::new(),
        "no request for a refused window"
    );
    let out = lookup(
        &["--url", &gw.base, "--from", t1, "--to", t1],
        EMAIL.as_bytes(),
        Some(TOKEN),
    )
    .await;
    check_eq!(
        (out.exit(), out.stdout()),
        (CliExit::Ok, LOOKUP_PRINTED.as_bytes()),
        "from == to"
    );
    finish();
}

/// T8, check order (design D4): resolution, then the token, then the input; the first failing check decides and
/// no request is sent.
#[tokio::test]
async fn the_first_failing_check_decides() {
    use super::super::dashboard_link::TokenError;
    let broken = || -> Result<mcp_gateway::config::Config, String> { Err("planted".to_string()) };
    let what = "could not load the config (planted); pass --gateway";
    let Command::Audit(AuditCommand::LookupEmail(args)) =
        parse(&["audit", "lookup-email", "--email-stdin"])
    else {
        panic!()
    };
    let out =
        super::super::audit_lookup::lookup_outcome(args, broken, None, None, Unreadable, |_| None)
            .await;
    failed(
        &out,
        CliExit::Usage,
        what,
        SETTINGS_REMEDY,
        "lookup: an unloadable config before an unset token",
    );
    let Command::DashboardLink(args) = parse(&["dashboard-link"]) else {
        panic!()
    };
    let out = super::super::dashboard_link::dashboard_link_outcome(
        args,
        broken,
        None,
        None,
        Err(TokenError::Missing),
    )
    .await;
    failed(
        &out,
        CliExit::Usage,
        what,
        SETTINGS_REMEDY,
        "dashboard-link: an unloadable config before an unset token",
    );
    let off = "http://10.1.2.3:8080";
    let remedy = format!("{TOKEN_REMEDY_PREFIX}{off}, then retry.");
    let out = link(&["--url", off], Err(TokenError::Missing)).await;
    failed(
        &out,
        CliExit::AuthRefused,
        "No gateway credential is available.",
        &remedy,
        "dashboard-link: token before URL",
    );
    let gw = gateway(json(200, r#"{"items":[]}"#)).await;
    let out = events(&["replay", "--url", &gw.base], Err(TokenError::Missing)).await;
    let remedy = format!("{TOKEN_REMEDY_PREFIX}{}, then retry.", gw.base);
    failed(
        &out,
        CliExit::AuthRefused,
        "No gateway credential is available.",
        &remedy,
        "events: token before action",
    );
    let out = lookup_reading(&["--url", &gw.base], Unreadable, None).await;
    failed(
        &out,
        CliExit::AuthRefused,
        "No gateway credential is available.",
        &remedy,
        "lookup: token before stdin",
    );
    let out = lookup(
        &["--url", &gw.base, "--from", "yesterday"],
        b"",
        Some(TOKEN),
    )
    .await;
    failed(
        &out,
        CliExit::Usage,
        "stdin held no email",
        INPUT_REMEDY,
        "lookup: stdin before window",
    );
    check_eq!(
        gw.requests(),
        Vec::<Seen>::new(),
        "no request in any order case"
    );
    finish();
}
