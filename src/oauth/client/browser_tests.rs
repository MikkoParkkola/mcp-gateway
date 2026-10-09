// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8197: the authorization URL reaches the browser as one verbatim
//! argument, through no shell, and only when it is https or loopback http.

use super::{launch_command, launchable, open_browser};

const AUTHORIZE: &str =
    "https://as.example/authorize?response_type=code&client_id=c&state=s&echo=pwned&c=%41^x,y%22";

/// `MIK-8197.SCHEME`: a scheme a platform handler would act on (a file, a
/// script, a registered protocol) or cleartext off this machine is refused
/// before any launcher runs, on every platform, whatever the metadata
/// check upstream already did.
#[test]
fn a_url_that_is_not_https_or_loopback_http_is_never_launched() {
    for url in [
        "file:///etc/passwd",
        "javascript:alert(1)",
        "ms-settings:privacy",
        "http://as.example/authorize",
        "",
        "not a url",
    ] {
        assert!(launchable(url).is_err(), "{url} must not reach a launcher");
        assert!(!open_browser(url), "{url} was handed to a launcher");
    }
}

#[test]
fn an_https_or_loopback_http_url_is_launched_unchanged() {
    assert_eq!(launchable(AUTHORIZE).unwrap().as_str(), AUTHORIZE);
    let loopback = "http://127.0.0.1:8080/authorize?a=1&b=2";
    assert_eq!(launchable(loopback).unwrap().as_str(), loopback);
}

/// `MIK-8197.QUOTE`: the argument a launcher gets never holds what makes
/// Rust's Windows quoting wrap it (a space, tab, newline or quote): those
/// are percent-encoded by the parse, so the handler receives the URL byte
/// for byte.
#[test]
fn the_launched_argument_carries_nothing_that_would_be_quoted() {
    let url = launchable("https://as.example/a b\"c?d=e\tf").unwrap();
    let command = launch_command(&url);
    let argument = command.get_args().last().unwrap().to_str().unwrap();
    assert_eq!(argument, url.as_str(), "the launcher gets the parsed URL");
    assert!(
        !argument.contains([' ', '\t', '\n', '"']),
        "nothing to quote: {argument}"
    );
}

/// `MIK-8197.WINDOWS`: no cmd.exe, so `&`, `^`, `%` and `,` stay part of
/// the URL instead of becoming shell syntax.
#[cfg(target_os = "windows")]
#[test]
fn windows_opens_the_url_without_a_shell() {
    let url = launchable(AUTHORIZE).unwrap();
    let command = launch_command(&url);
    assert_eq!(command.get_program(), "rundll32.exe");
    let args: Vec<_> = command.get_args().collect();
    assert_eq!(args, ["url.dll,FileProtocolHandler", AUTHORIZE]);
}

#[cfg(not(target_os = "windows"))]
#[test]
fn unix_hands_the_url_as_its_one_argument() {
    let url = launchable(AUTHORIZE).unwrap();
    let command = launch_command(&url);
    let expected = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    assert_eq!(command.get_program(), expected, "no shell as the launcher");
    let args: Vec<_> = command.get_args().collect();
    assert_eq!(args, [AUTHORIZE]);
}

/// `MIK-8197.PROMPT`: the "visit this URL" prompt is shown whether or not a
/// launcher started (one an endpoint-security tool stops leaves no failed
/// spawn), on stderr. clippy's `print_stdout` deny in grants.rs keeps it off
/// stdout; this pins that it is printed unconditionally, outside the
/// failed-launch branch.
#[test]
fn the_manual_prompt_is_always_printed() {
    let grants = include_str!("grants.rs");
    let launch = grants
        .find("(self.open_browser)(&auth_url_str)")
        .expect("the launch call");
    let rest = &grants[launch..];
    let branch_end = rest
        .find("\n        }\n")
        .expect("the failed-launch branch ends");
    let prompt = rest
        .find("eprintln!(\"\\nIf no browser opened, authorize this client by visiting:")
        .expect("the prompt");
    assert!(
        prompt > branch_end,
        "the prompt sits after the failed-launch branch, not inside it"
    );
}

/// `MIK-8197.INVARIANT`: whatever reaches `launchable`, a URL it accepts
/// serializes with no whitespace and no quote, the characters that would make
/// Rust's Windows quoting wrap the argument. It pins the parser's encoding:
/// a parser change that let one through fails here, not on a user's machine.
/// (`&`, `^` and `%` stay: they are URL syntax, and no shell reads them now.)
#[test]
fn every_launchable_url_holds_no_whitespace_or_quote() {
    let hostile = [
        "https://as.example/a b",
        "https://as.example/a\"b",
        "https://as.example/a\tb\nc\rd",
        "https://as.example/?q=a b&r=\"x\"",
        "https://as.example/#frag ment\"",
        "https://user name:pa\"ss@as.example/",
        "https://as.example/\u{a0}nbsp\u{2003}em",
        "http://127.0.0.1:9/ \" \t",
        "https://as.example/&calc^x%41,y",
    ];
    let mut accepted = 0;
    for input in hostile {
        if let Ok(url) = launchable(input) {
            accepted += 1;
            assert!(
                !url.as_str().contains([' ', '\t', '\n', '\r', '"']),
                "{input:?} launched as {:?}",
                url.as_str()
            );
        }
    }
    assert!(
        accepted >= 7,
        "the row checks accepted URLs, not refusals: {accepted}"
    );
}
