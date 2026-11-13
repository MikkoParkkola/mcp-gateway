// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `audit lookup-email` rows for the page token: never an argument, read
//! bounded from stdin, sent alone in the body.

use serde_json::json;

use super::{
    Counting, EMAIL, MAX_CURSOR_INPUT, PAGE, by_cursor, by_email, parse, read_cursor, request_body,
};

/// MIK-9456.CLI.1: the page token is never an argument either: no
/// `--cursor VALUE`, no positional token; the next page asks for stdin.
/// Mutant: keep the argv `--cursor`, or accept a positional token.
#[test]
fn a_page_token_is_never_an_argument() {
    assert!(parse(&["--cursor-stdin"]).is_ok());
    assert!(
        parse(&["--email-stdin", "--cursor", PAGE]).is_err(),
        "no --cursor VALUE"
    );
    assert!(parse(&["--cursor", PAGE]).is_err(), "no --cursor VALUE");
    assert!(
        parse(&["--cursor-stdin", PAGE]).is_err(),
        "no positional token"
    );
    assert!(parse(&["--cursor-stdin", "--cursor", PAGE]).is_err());
}

/// MIK-9456.CLI.1: a page token typed after the removed `--cursor` is refused
/// by the parser without printing the token back (a typed secret would
/// otherwise land in the terminal scrollback and any captured stderr).
/// Mutant: define `--cursor` again, or add a handler that prints the value.
#[test]
fn a_typed_cursor_flag_is_refused_without_echoing_the_token() {
    for argv in [
        vec!["--cursor", PAGE],
        vec!["--email-stdin", "--cursor", PAGE],
        vec!["--cursor-stdin", "--cursor", PAGE],
    ] {
        let message = parse(&argv).expect_err("no --cursor VALUE").to_string();
        assert!(!message.contains(PAGE), "{argv:?}: {message}");
    }
    let message = parse(&["--email-stdin", &format!("--cursor={PAGE}")])
        .expect_err("no --cursor=VALUE")
        .to_string();
    assert!(!message.contains(PAGE), "{message}");
}

/// MIK-9456.CLI.1: exactly one of the two stdin sources; a page token
/// carries its own window, so a window flag beside it is refused here, before
/// the gateway charges a lookup for the 400 it would answer.
/// Mutant: drop the group, or drop a conflict.
#[test]
fn exactly_one_stdin_source_and_no_window_beside_a_token() {
    assert!(parse(&["--email-stdin"]).is_ok());
    assert!(parse(&["--cursor-stdin"]).is_ok());
    assert!(parse(&[]).is_err(), "one source is required");
    assert!(
        parse(&["--email-stdin", "--cursor-stdin"]).is_err(),
        "both sources"
    );
    assert!(parse(&["--cursor-stdin", "--from", "2026-11-01T00:00:00Z"]).is_err());
    assert!(parse(&["--cursor-stdin", "--to", "2026-11-02T00:00:00Z"]).is_err());
    assert!(
        parse(&["--cursor-stdin", "--limit", "7"]).is_ok(),
        "a page size may change"
    );
    assert!(
        parse(&[
            "--email-stdin",
            "--from",
            "2026-11-01T00:00:00Z",
            "--to",
            "2026-11-02T00:00:00Z"
        ])
        .is_ok()
    );
}

/// MIK-9456.CLI.1: the token line is read bounded, one line, no spaces or
/// control bytes, and every refusal is a fixed message that never echoes it.
/// Mutant: read without a bound, accept a second line or inner space, echo the
/// input in the message, or move the bound.
#[test]
fn the_token_line_is_read_bounded_and_never_echoed() {
    assert_eq!(
        read_cursor(format!("{PAGE}\n").as_bytes()).as_deref(),
        Ok(PAGE)
    );
    assert_eq!(
        read_cursor(format!("{PAGE}\r\n").as_bytes()).as_deref(),
        Ok(PAGE)
    );
    assert_eq!(
        read_cursor(PAGE.as_bytes()).as_deref(),
        Ok(PAGE),
        "no newline needed"
    );
    assert_eq!(
        read_cursor(format!("  {PAGE} \n").as_bytes()).as_deref(),
        Ok(PAGE),
        "ends are trimmed"
    );
    for (name, bad) in [
        ("empty", Vec::new()),
        ("blank", b"\n".to_vec()),
        ("two lines", format!("{PAGE}\nsecond\n").into_bytes()),
        ("inner space", format!("{PAGE} {PAGE}").into_bytes()),
        ("control byte", format!("{PAGE}\0").into_bytes()),
        ("not UTF-8", vec![0xff, 0xfe]),
        (
            "over the bound",
            "a".repeat(MAX_CURSOR_INPUT + 1).into_bytes(),
        ),
    ] {
        let message = read_cursor(bad.as_slice()).expect_err(name);
        assert!(
            !message.contains(PAGE) && !message.contains("second"),
            "{name}: {message}"
        );
        assert!(!message.contains(&"a".repeat(8)), "{name}: {message}");
    }
    assert_eq!(
        MAX_CURSOR_INPUT, 2048,
        "the gateway's own limit on a page token"
    );
    let at_limit = "a".repeat(MAX_CURSOR_INPUT);
    assert_eq!(
        read_cursor(at_limit.as_bytes()).as_deref(),
        Ok(at_limit.as_str())
    );
    // A long input is cut off one byte past the bound and a `\r\n` line end,
    // not read to the end.
    let read = std::cell::Cell::new(0);
    assert!(read_cursor(Counting(&read, 1 << 20)).is_err());
    assert!(
        read.get() <= MAX_CURSOR_INPUT + 3,
        "read {} bytes",
        read.get()
    );
}

/// MIK-9456.CLI.1: the 2048-byte bound is on the token, not on its line end:
/// a full-length token piped by `jq -r` (which ends it with `\n`) or saved
/// with `\r\n` is accepted, and one byte more is refused however it ends.
/// Mutant: count the line end toward the bound, drop the token's bound, or
/// read no byte past the bound.
#[test]
fn a_full_length_token_with_its_line_end_is_accepted() {
    let full = "a".repeat(MAX_CURSOR_INPUT);
    for end in ["\n", "\r\n"] {
        assert_eq!(
            read_cursor(format!("{full}{end}").as_bytes()).as_deref(),
            Ok(full.as_str()),
            "{end:?}"
        );
    }
    let over = "a".repeat(MAX_CURSOR_INPUT + 1);
    for end in ["", "\n", "\r\n"] {
        assert_eq!(
            read_cursor(format!("{over}{end}").as_bytes()),
            Err("the page token on stdin is too long".to_string()),
            "{end:?}"
        );
    }
    // A read cut at the bound must not drop what follows the line end.
    for tail in ["\nx", "\r\nx"] {
        assert!(
            read_cursor(format!("{full}{tail}").as_bytes()).is_err(),
            "{tail:?}"
        );
    }
}

/// MIK-9456.CLI.1: a value typed as an argument (positional, or attached to a
/// source flag) is refused by the parser; a source flag takes no value, so
/// `=false` cannot switch a source off. That the refusal never repeats the
/// value is proven on the binary, whose parse entry replaces the message
/// (`tests/cli_secret_redaction.rs`).
/// Mutant: accept a positional value, or let a source flag take a value.
#[test]
fn a_value_typed_as_an_argument_is_refused_by_the_parser() {
    use clap::error::ErrorKind;
    let email_attached = format!("--email-stdin={EMAIL}");
    let page_attached = format!("--cursor-stdin={PAGE}");
    for (argv, kind) in [
        (vec!["--email-stdin", EMAIL], ErrorKind::UnknownArgument),
        (vec!["--cursor-stdin", PAGE], ErrorKind::UnknownArgument),
        (vec![email_attached.as_str()], ErrorKind::TooManyValues),
        (vec![page_attached.as_str()], ErrorKind::TooManyValues),
        (vec!["--email-stdin=false"], ErrorKind::TooManyValues),
        (vec!["--cursor-stdin=false"], ErrorKind::TooManyValues),
    ] {
        let error = parse(&argv).expect_err("a typed value");
        assert_eq!(error.kind(), kind, "{argv:?}");
    }
}

/// MIK-9456.CLI.1: the input's debug form never prints the email or the
/// token, so a future log line or panic message cannot carry either.
/// Mutant: derive `Debug` again.
#[test]
fn the_input_debug_form_hides_the_email_and_the_token() {
    for (input, secret) in [(by_email(), EMAIL), (by_cursor(), PAGE)] {
        let shown = format!("{input:?}");
        assert!(!shown.contains(secret), "{shown}");
    }
    assert_ne!(format!("{:?}", by_email()), format!("{:?}", by_cursor()));
}

/// MIK-9456.CLI.1: a next-page body is exactly the token and the page size;
/// a first-page body never carries a token.
/// Mutant: add the email or a window beside the token, or send a token in a
/// first-page body.
#[test]
fn the_cursor_body_is_the_token_and_only_the_limit() {
    let bare = parse(&["--cursor-stdin"]).expect("parses");
    assert_eq!(request_body(&by_cursor(), &bare), json!({"cursor": PAGE}));
    let sized = parse(&["--cursor-stdin", "--limit", "7"]).expect("parses");
    assert_eq!(
        request_body(&by_cursor(), &sized),
        json!({"cursor": PAGE, "limit": 7})
    );
    let first = parse(&["--email-stdin", "--limit", "7"]).expect("parses");
    assert_eq!(
        request_body(&by_email(), &first),
        json!({"email": EMAIL, "limit": 7})
    );
}
