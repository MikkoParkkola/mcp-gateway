// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `audit lookup-email`: stdin only, bounded, typed answer, nonzero on any
//! failure, no file written.

use clap::Parser;
use mcp_gateway::cli::Cli;
use mcp_gateway::cli::audit_lookup::LookupEmailArgs;
use serde_json::json;

use super::{MAX_EMAIL_INPUT, read_email, request_body};

const EMAIL: &str = "Planted.Person@corp.invalid";

fn parse(extra: &[&str]) -> Result<LookupEmailArgs, clap::Error> {
    let mut argv = vec!["mcp-gateway", "audit", "lookup-email"];
    argv.extend_from_slice(extra);
    match Cli::try_parse_from(argv)?.command {
        Some(mcp_gateway::cli::Command::Audit(mcp_gateway::cli::AuditCommand::LookupEmail(a))) => {
            Ok(a)
        }
        other => panic!("not lookup-email: {other:?}"),
    }
}

/// MIK-9456.CLI.1: the email is never an argument: no positional email, no
/// `--email VALUE`, and `--email-stdin` is required.
/// Mutant: accept a positional email, add `--email`, or drop `required`.
#[test]
fn the_email_is_never_an_argument() {
    assert!(parse(&["--email-stdin"]).is_ok());
    assert!(parse(&[]).is_err(), "stdin must be asked for");
    assert!(parse(&["--email-stdin", EMAIL]).is_err(), "no positional email");
    assert!(parse(&["--email", EMAIL]).is_err(), "no --email VALUE");
    assert!(parse(&["--email-stdin", "--email", EMAIL]).is_err());
}

/// MIK-9456.CLI.1: the read is bounded and takes one email-sized line.
/// Mutant: read without a bound, or accept an empty or multi-line input.
#[test]
fn stdin_is_read_bounded_and_trimmed_to_one_line() {
    assert_eq!(read_email(format!("{EMAIL}\n").as_bytes()).as_deref(), Ok(EMAIL));
    assert_eq!(read_email(format!("{EMAIL}\r\n").as_bytes()).as_deref(), Ok(EMAIL));
    assert_eq!(read_email(EMAIL.as_bytes()).as_deref(), Ok(EMAIL), "no newline needed");
    assert!(read_email(&b""[..]).is_err(), "empty");
    assert!(read_email(&b"\n"[..]).is_err(), "blank");
    assert!(read_email(&b"a@b.invalid\nsecond\n"[..]).is_err(), "two lines");
    assert!(read_email(&b"a\0b@c.invalid"[..]).is_err(), "control byte");
    assert!(read_email(&[0xff, 0xfe][..]).is_err(), "not UTF-8");
    let long = "a".repeat(MAX_EMAIL_INPUT + 1);
    assert!(read_email(long.as_bytes()).is_err(), "over the bound");
    // A reader that never ends is cut off at the bound, not read to the end.
    let endless = std::io::repeat(b'a');
    assert!(read_email(endless).is_err());
}

/// MIK-9456.CLI.1: the body is built in memory from the email and the flags,
/// and carries only what was asked for.
/// Mutant: send the email in a query, drop a flag, or add a field.
#[test]
fn the_body_carries_the_email_and_only_the_flags_given() {
    let bare = parse(&["--email-stdin"]).expect("parses");
    assert_eq!(request_body(EMAIL, &bare), json!({"email": EMAIL}));
    let full = parse(&[
        "--email-stdin",
        "--limit",
        "7",
        "--cursor",
        "tok",
        "--from",
        "2026-11-01T00:00:00Z",
        "--to",
        "2026-11-02T00:00:00Z",
    ])
    .expect("parses");
    assert_eq!(
        request_body(EMAIL, &full),
        json!({"email": EMAIL, "limit": 7, "cursor": "tok",
               "from": "2026-11-01T00:00:00Z", "to": "2026-11-02T00:00:00Z"})
    );
    assert!(parse(&["--email-stdin", "--limit", "0"]).is_err());
    assert!(parse(&["--email-stdin", "--limit", "201"]).is_err());
}
