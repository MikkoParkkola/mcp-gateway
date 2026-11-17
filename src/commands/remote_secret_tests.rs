// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test plan T9b: the secret gate at each failure site reached after a valid token is read. Each case's
//! token is a value its site's text would contain (a word of the message or remedy, the HTTP number, or a reason
//! the stand-in echoes), so a site that bypasses `CliError::outcome` prints the raw token and fails its own case.
//! The expected text is the site's T5-T7 literal with the token's runs written as `[redacted]`.

use super::*;

/// The three commands with `token`, against `base` (events as a list).
async fn three(base: &str, token: &str) -> Vec<(&'static str, CliOutcome)> {
    let url = ["--url", base];
    vec![
        ("dashboard-link", link(&url, Ok(token.to_string())).await),
        (
            "events list",
            events(&["list", "--url", base], Ok(token.to_string())).await,
        ),
        ("lookup", lookup(&url, EMAIL.as_bytes(), Some(token)).await),
    ]
}

/// T9b, the sites every command shares.
#[tokio::test]
async fn shared_sites_redact_the_token() {
    // URL policy (2), before any request: "HTTPS" is a word of both lines.
    for (command, out) in three("http://10.1.2.3:8080", "HTTPS").await {
        failed(
            &out,
            CliExit::Usage,
            "Gateway URL must use [redacted] or loopback HTTP.",
            "Use an [redacted] gateway URL or a loopback HTTP URL.",
            &format!("{command} url policy"),
        );
    }
    // Connect (5).
    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        format!("http://{}", listener.local_addr().expect("addr"))
    };
    for (command, out) in three(&closed, "connect").await {
        failed(
            &out,
            CliExit::Network,
            "Could not [redacted] to the gateway.",
            "Check the gateway address and listener, then retry.",
            &format!("{command} connect"),
        );
    }
    // A refusal whose reason echoes the token (3).
    let gw = gateway(json(401, r#"{"message":"tok-echo denied"}"#)).await;
    for (command, out) in three(&gw.base, "tok-echo").await {
        failed(
            &out,
            CliExit::AuthRefused,
            "The gateway answered HTTP 401: [redacted] denied",
            &format!("{TOKEN_REMEDY_PREFIX}{}, then retry.", gw.base),
            &format!("{command} echoed reason"),
        );
    }
    check_eq!(gw.requests().len(), 3, "each echoed-reason request arrived");
    // The token equals the HTTP number (6).
    let gw = gateway(json(500, r#"{"message":"broke"}"#)).await;
    for (command, out) in three(&gw.base, "500").await {
        failed(
            &out,
            CliExit::Gateway,
            "The gateway answered HTTP [redacted]: broke",
            RESOLVE,
            &format!("{command} status number"),
        );
    }
    // A lost answer (5).
    let gw = gateway(Reply::Close).await;
    for (command, out) in three(&gw.base, "interrupted").await {
        let remedy = if command == "dashboard-link" {
            "Repeat the request; each run mints a new one-time link."
        } else {
            "Repeat the read request."
        };
        failed(
            &out,
            CliExit::Network,
            "Gateway response was [redacted].",
            remedy,
            &format!("{command} lost"),
        );
    }
    // An answer over 16 MiB (5).
    let gw = gateway(Reply::Http {
        status: 200,
        headers: vec![("content-type", "application/json".to_string())],
        body: vec![b' '; 16 * 1024 * 1024 + 1],
    })
    .await;
    for (command, out) in three(&gw.base, "MiB").await {
        failed(
            &out,
            CliExit::Network,
            "Gateway response exceeded 16 [redacted].",
            "Narrow the request or read the data in smaller pages.",
            &format!("{command} oversized"),
        );
    }
    // A 2xx without JSON (6).
    let gw = gateway(Reply::Http {
        status: 200,
        headers: vec![],
        body: b"not json".to_vec(),
    })
    .await;
    for (command, out) in three(&gw.base, "invalid").await {
        failed(
            &out,
            CliExit::Gateway,
            "The gateway returned an [redacted] response.",
            "Check the gateway response against UI API 1.",
            &format!("{command} unparsable"),
        );
    }
    // "error" is the prefix and a word of the fixed sentence: nothing prints, the exit stands (3).
    let gw = gateway(json(401, r#"{"message":"denied"}"#)).await;
    for (command, out) in three(&gw.base, "error").await {
        check_eq!(
            (out.exit, out.stderr.as_str(), out.stdout.as_slice()),
            (CliExit::AuthRefused, "", &b""[..]),
            "{command} prefix word"
        );
    }
    finish();
}

/// T9b, events' own sites: the action combination (2), a replay's uncertain 500 (8), and stdout still holding the
/// token (1).
#[tokio::test]
async fn events_sites_redact_the_token() {
    let gw = gateway(json(500, r#"{"message":"broke"}"#)).await;
    let out = events(&["replay", "--url", &gw.base], Ok("replay".to_string())).await;
    failed(
        &out,
        CliExit::Usage,
        "use `list`, `[redacted] ID` or `[redacted] --all --subscription S`",
        "Use list, [redacted] ID, or [redacted] --all --subscription S.",
        "action combination",
    );
    let out = events(
        &["replay", "dl-1", "--url", &gw.base],
        Ok("state".to_string()),
    )
    .await;
    failed(
        &out,
        CliExit::UncertainOutcome,
        "The gateway answered HTTP 500: broke",
        "Inspect the gateway [redacted] before retrying; this command did not retry.",
        "replay 500",
    );
    // A number keeps its "." through redaction, so stdout still holds the token.
    let gw = gateway(json(200, r#"{"items":[1.5]}"#)).await;
    let out = events(&["list", "--url", &gw.base], Ok(".".to_string())).await;
    failed(
        &out,
        CliExit::LocalFailure,
        "The response could not be printed safely[redacted]",
        "The response was received but could not be printed safely; inspect the gateway state before sending the request again[redacted]",
        "residual token",
    );
    finish();
}

/// T9b, lookup's own sites: stdin (1 and 2), the window (2), and a refusal echoing the email or the page token,
/// which are secrets of the diagnostics (design D5); the request carrying the body arrived.
#[tokio::test]
async fn lookup_sites_redact_the_token_email_and_cursor() {
    let gw = gateway(json(401, r#"{"message":"denied"}"#)).await;
    let url = ["--url", gw.base.as_str()];
    let out = lookup_reading(&url, Unreadable, Some("read")).await;
    failed(
        &out,
        CliExit::LocalFailure,
        "could not [redacted] the email from stdin",
        "Check stdin and retry.",
        "unreadable stdin",
    );
    let out = lookup(&url, b"a\x07@b.test", Some("valid")).await;
    failed(
        &out,
        CliExit::Usage,
        "the email on stdin is not [redacted]",
        INPUT_REMEDY,
        "invalid email",
    );
    let window = [
        "--from",
        "yesterday",
        "--to",
        "2026-11-17T11:00:00Z",
        "--url",
        gw.base.as_str(),
    ];
    let out = lookup(&window, EMAIL.as_bytes(), Some("RFC")).await;
    failed(
        &out,
        CliExit::Usage,
        "--from and --to must be [redacted] 3339 times",
        "Use [redacted] 3339 times with --from not after --to.",
        "window",
    );
    check_eq!(
        gw.requests().len(),
        0,
        "no request before the input is valid"
    );
    let remedy = |base: &str| format!("{TOKEN_REMEDY_PREFIX}{base}, then retry.");
    let gw = gateway(json(
        401,
        &format!(r#"{{"message":"no access for {EMAIL}"}}"#),
    ))
    .await;
    let out = lookup(&["--url", &gw.base], EMAIL.as_bytes(), Some(TOKEN)).await;
    failed(
        &out,
        CliExit::AuthRefused,
        "The gateway answered HTTP 401: no access for [redacted]",
        &remedy(&gw.base),
        "echoed email",
    );
    check_eq!(gw.requests().len(), 1, "the email request arrived");
    let gw = gateway(json(401, &format!(r#"{{"message":"bad page {CURSOR}"}}"#))).await;
    let out = lookup(
        &["--cursor-stdin", "--url", &gw.base],
        CURSOR.as_bytes(),
        Some(TOKEN),
    )
    .await;
    failed(
        &out,
        CliExit::AuthRefused,
        "The gateway answered HTTP 401: bad page [redacted]",
        &remedy(&gw.base),
        "echoed cursor",
    );
    check_eq!(gw.requests().len(), 1, "the cursor request arrived");
    finish();
}
