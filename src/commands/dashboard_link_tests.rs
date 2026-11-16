// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Rows for `dashboard-link` and `events`: token, target and link handling.

use super::{DashboardLinkTls, LinkTls, TOKEN_ENV, TokenError, read_token};

fn no_flags() -> DashboardLinkTls {
    DashboardLinkTls::default()
}

/// No TLS material: the pre-#1832 request.
async fn fetch_link(base: &str, token: &str) -> Result<String, String> {
    super::fetch_link(base, token, &LinkTls::default()).await
}

#[test]
fn the_base_url_never_falls_back_past_a_config_that_failed_to_load() {
    use super::dashboard_link_base;
    let explicit = dashboard_link_base(
        Some("http://h:1".into()),
        no_flags(),
        || Err("x".into()),
        None,
        None,
    );
    assert_eq!(
        explicit.map(|(base, _)| base).as_deref(),
        Ok("http://h:1"),
        "--url wins without a load"
    );

    let failed = dashboard_link_base(None, no_flags(), || Err("bad yaml".into()), None, None)
        .expect_err("a config that fails to load is not replaced by defaults");
    assert!(
        failed.contains("bad yaml") && failed.contains("--url"),
        "{failed}"
    );

    let mut config = mcp_gateway::config::Config::default();
    config.server.port = 4100;
    let plain = dashboard_link_base(None, no_flags(), || Ok(config.clone()), None, None);
    assert_eq!(
        plain.map(|(base, _)| base).as_deref(),
        Ok("http://127.0.0.1:4100")
    );
    config.mtls.enabled = true;
    config.mtls.require_client_cert = false;
    let tls = dashboard_link_base(None, no_flags(), || Ok(config.clone()), Some(4200), None);
    assert_eq!(
        tls.map(|(base, _)| base).as_deref(),
        Ok("https://127.0.0.1:4200")
    );
}

/// E5-T21: the credential never goes out in cleartext to the network.
#[test]
fn cleartext_is_refused_off_loopback() {
    use super::check_target;
    for refused in [
        "http://10.0.0.5:39400",
        "http://gateway.example",
        "HTTP://192.0.2.1:1",
    ] {
        let err = check_target(refused).expect_err(refused);
        assert!(err.contains("cleartext"), "{refused}: {err}");
    }
    for allowed in [
        "http://127.0.0.1:39400",
        "http://localhost:39400/",
        "http://[::1]:39400",
        "https://gateway.example",
    ] {
        assert_eq!(check_target(allowed), Ok(()), "{allowed}");
    }
    let odd = check_target("ftp://127.0.0.1:1").expect_err("an unknown scheme");
    assert!(odd.contains("unsupported scheme"), "{odd}");
}

/// E5-T21b: `fetch_link` refuses before sending anything: 192.0.2.1 is a
/// documentation address, so a request would hang, not answer.
#[tokio::test]
async fn fetch_link_refuses_cleartext_before_sending() {
    let out = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        fetch_link("http://192.0.2.1:9", "tok"),
    )
    .await
    .expect("refused at once, no connection attempted");
    let err = out.expect_err("cleartext target");
    assert!(err.contains("cleartext"), "{err}");
}

#[test]
fn the_token_comes_from_the_named_variable_only() {
    let token = read_token(|name| (name == TOKEN_ENV).then(|| "tok".to_string()));
    assert_eq!(token.as_deref(), Ok("tok"));

    let missing = read_token(|_| None).expect_err("no variable, no token");
    assert_eq!(missing, TokenError::Missing);
    assert!(missing.to_string().contains(TOKEN_ENV), "{missing}");

    for value in ["", "   "] {
        let blank = read_token(|_| Some(value.to_string())).expect_err("blank credential");
        assert_eq!(blank, TokenError::Blank);
        assert_eq!(blank.to_string(), "MCP_GATEWAY_TOKEN is empty.");
    }

    let padded = read_token(|_| Some(" tok ".to_string()));
    assert_eq!(
        padded.as_deref(),
        Ok(" tok "),
        "a credential is passed as given"
    );
}

/// An in-process gateway stand-in: answers the link only for `tok`.
async fn stand_in() -> String {
    use axum::http::{HeaderMap, StatusCode};
    let app = axum::Router::new().route(
        "/ui/api/dashboard-link",
        axum::routing::post(|headers: HeaderMap| async move {
            let ok =
                headers.get("authorization").and_then(|v| v.to_str().ok()) == Some("Bearer tok");
            if ok {
                Ok(axum::Json(serde_json::json!({
                    "link": "http://127.0.0.1:39400/dashboard?bootstrap=abc"
                })))
            } else {
                Err(StatusCode::FORBIDDEN)
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move { axum::serve(listener, app).await });
    format!("http://{addr}")
}

/// A `--url` carrying userinfo or a query token must not reach stderr.
#[tokio::test]
async fn errors_never_echo_url_credentials() {
    for base in [
        "http://user:PW1@10.0.0.5:9/x?token=Q1",
        "http://user:PW1@127.0.0.1:1/x?token=Q1",
        "ftp://user:PW1@h/x?token=Q1",
    ] {
        let err = fetch_link(base, "tok").await.expect_err(base);
        assert!(!err.contains("PW1") && !err.contains("Q1"), "{err}");
    }
    let err = super::check_target("not a url:PW1@?token=Q1").expect_err("unparseable");
    assert!(!err.contains("PW1") && !err.contains("Q1"), "{err}");
}

#[tokio::test]
async fn the_link_is_fetched_with_the_credential_as_a_bearer() {
    let base = stand_in().await;
    assert_eq!(
        fetch_link(&base, "tok").await.as_deref(),
        Ok("http://127.0.0.1:39400/dashboard?bootstrap=abc")
    );
    let refused = fetch_link(&format!("{base}/"), "wrong")
        .await
        .expect_err("a refused credential is an error");
    assert!(refused.contains("403"), "{refused}");
}

/// A redirect is never followed: the next hop was not checked by
/// `check_target`, and a same-host, same-port hop keeps the bearer.
#[tokio::test]
async fn a_redirect_is_not_followed() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&hits);
    let hop = axum::Router::new().fallback(move || {
        let seen = Arc::clone(&seen);
        async move {
            seen.fetch_add(1, Ordering::SeqCst);
            axum::Json(serde_json::json!({ "link": "http://127.0.0.1:1/dashboard" }))
        }
    });
    let hop_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let hop_url = format!(
        "http://{}/ui/api/dashboard-link",
        hop_listener.local_addr().expect("addr")
    );
    tokio::spawn(async move { axum::serve(hop_listener, hop).await });
    let redirector = axum::Router::new().fallback(move || {
        let location = hop_url.clone();
        async move {
            (
                axum::http::StatusCode::TEMPORARY_REDIRECT,
                [(axum::http::header::LOCATION, location)],
            )
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(async move { axum::serve(listener, redirector).await });

    let refused = fetch_link(&base, "tok")
        .await
        .expect_err("a redirect is an error, not a link");
    assert!(refused.contains("307"), "{refused}");
    assert_eq!(hits.load(Ordering::SeqCst), 0, "the redirect was followed");
}

/// A gateway that answers every request with `status` and `body`.
async fn answering(status: u16, body: String) -> String {
    let status = axum::http::StatusCode::from_u16(status).expect("status");
    let app = axum::Router::new().fallback(move || {
        let body = body.clone();
        async move { (status, [("content-type", "application/json")], body) }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move { axum::serve(listener, app).await });
    format!("http://{addr}")
}

/// What `dashboard-link` and `events dead-letters` print against `base`.
async fn both(base: &str, token: &str) -> [(&'static str, super::Printed); 2] {
    let list = mcp_gateway::cli::events::DeadLettersArgs {
        action: mcp_gateway::cli::events::DeadLetterAction::List,
        id: None,
        all: false,
        subscription: None,
        reason: None,
        url: None,
        tls: no_flags(),
    };
    let tls = LinkTls::default();
    [
        (
            "dashboard-link",
            super::dashboard_link_output(base, &tls, token).await,
        ),
        (
            "events",
            super::dead_letters_output(base, &tls, &list, token).await,
        ),
    ]
}

fn printed_nowhere(command: &str, token: &str, out: &super::Printed) {
    assert!(
        !out.stdout.contains(token) && !out.stderr.contains(token),
        "{command}, token {token:?}: {out:?}"
    );
}

/// MIK-9679.CLIUX.14: a token equal to the status text is never printed.
#[tokio::test]
async fn a_token_equal_to_the_status_text_is_never_printed() {
    for (token, status, body) in [
        ("404", 404, r#"{"error":"no such route"}"#),
        ("Not Found", 404, "{}"),
        ("Found", 302, "{}"),
        ("OK", 200, ""),
    ] {
        let base = answering(status, body.to_string()).await;
        for (command, out) in both(&base, token).await {
            printed_nowhere(command, token, &out);
            assert!(!out.ok, "{command}, token {token:?}: a failure");
            // Not the fixed fallback sentence: the report itself, redacted.
            assert!(
                out.stderr.contains("the gateway answered"),
                "{command}, token {token:?}: {}",
                out.stderr
            );
        }
    }
}

/// MIK-9679.CLIUX.26 (register row 1185): a token echoed in any of the
/// gateway's reason shapes is never printed; the status still is.
#[tokio::test]
async fn a_token_echoed_in_the_error_reason_is_never_printed() {
    let token = "tok-ECHOED-1185";
    for body in [
        serde_json::json!({ "message": format!("bad bearer {token}") }),
        serde_json::json!({ "error": { "message": token } }),
        serde_json::json!({ "error": token }),
        serde_json::json!({ "reason": token }),
    ] {
        let base = answering(400, body.to_string()).await;
        for (command, out) in both(&base, token).await {
            printed_nowhere(command, token, &out);
            assert!(!out.ok, "{command}: a failure");
            assert!(out.stderr.contains("400"), "{command}: {}", out.stderr);
        }
    }
}

/// MIK-9679.CLIUX.15: a token in the success answer, in a value, a key or the
/// link, is never printed; the rest of the answer is.
#[tokio::test]
async fn a_token_in_the_success_answer_is_never_printed() {
    let token = "tok-IN-ANSWER-9679";
    let mut body = serde_json::json!({
        "link": format!("http://127.0.0.1:1/dashboard?bootstrap={token}"),
        "items": [{ "id": "d1", "note": format!("held for {token}") }],
    });
    body[token] = serde_json::json!("a key");
    let base = answering(200, body.to_string()).await;
    let [(_, link), (_, events)] = both(&base, token).await;
    for (command, out) in [("dashboard-link", &link), ("events", &events)] {
        printed_nowhere(command, token, out);
        assert!(out.ok, "{command}: {out:?}");
        assert!(!out.stdout.is_empty(), "{command}: the answer is printed");
    }
    assert!(
        link.stdout
            .starts_with("http://127.0.0.1:1/dashboard?bootstrap=")
    );
    let printed: serde_json::Value = serde_json::from_str(&events.stdout).expect("JSON");
    assert_eq!(printed["items"][0]["id"], "d1");
}

/// MIK-9679.CLIUX.15: an answer whose redaction would merge two entries is
/// refused, not printed short.
#[tokio::test]
async fn an_answer_that_loses_an_entry_to_redaction_is_refused() {
    // `[redacted]` is the shared redactor's first marker: renaming the key
    // `#` to it collides with the existing key.
    let body = r##"{"link":"http://127.0.0.1:1/l","#":"first","[redacted]":"second"}"##;
    let base = answering(200, body.to_string()).await;
    for (command, out) in both(&base, "#").await {
        printed_nowhere(command, "#", &out);
        assert!(!out.ok, "{command}: refused");
        assert!(out.stdout.is_empty(), "{command}: nothing on stdout");
        assert!(
            out.stderr.contains("printed safely"),
            "{command}: {}",
            out.stderr
        );
    }
}

/// MIK-9679.CLIUX.15: the stdout backstop and the whole-stderr gate. A token
/// equal to JSON syntax, which the JSON redactor cannot mask, is refused; a
/// token equal to the note or the error prefix is masked there.
#[tokio::test]
async fn a_token_in_fixed_text_is_never_printed() {
    let base = answering(200, r#"{"link":"http://127.0.0.1:1/l","ok":1}"#.into()).await;
    let [(_, link), (_, events)] = both(&base, ":").await;
    printed_nowhere("dashboard-link", ":", &link);
    printed_nowhere("events", ":", &events);
    assert!(!events.ok && events.stdout.is_empty(), "{events:?}");
    let [(_, link), _] = both(&base, "once").await;
    assert!(link.ok, "{link:?}");
    printed_nowhere("dashboard-link", "once", &link);
    // The gate redacted the note; the fixed fallback sentence would not hold this.
    assert!(link.stderr.contains("from this machine only"), "{link:?}");
    let refused = answering(403, "{}".into()).await;
    let [_, (_, events)] = both(&refused, "events").await;
    printed_nowhere("events", "events", &events);
    assert!(
        events
            .stderr
            .contains("dead-letters: the gateway answered 403"),
        "{events:?}"
    );
}

fn dead_letters(
    action: mcp_gateway::cli::events::DeadLetterAction,
) -> mcp_gateway::cli::events::DeadLettersArgs {
    mcp_gateway::cli::events::DeadLettersArgs {
        action,
        id: None,
        all: false,
        subscription: None,
        reason: None,
        url: None,
        tls: no_flags(),
    }
}

/// MIK-9679.CLIUX.14: a config error that quotes the token is gated once a
/// token is set; it still comes before the token error.
#[tokio::test]
async fn a_config_error_quoting_the_token_is_never_printed() {
    let token = "tok-IN-CONFIG-9679";
    let load = || Err(format!("bad bearer_token value {token}"));
    let link = super::dashboard_link_args_output(
        mcp_gateway::cli::dashboard_link::DashboardLinkArgs {
            url: None,
            tls: no_flags(),
        },
        load,
        None,
        None,
        Ok(token.to_string()),
    )
    .await;
    let list = dead_letters(mcp_gateway::cli::events::DeadLetterAction::List);
    let events = super::events_args_output(&list, load, None, None, Ok(token.to_string())).await;
    for (command, out) in [("dashboard-link", &link), ("events", &events)] {
        printed_nowhere(command, token, out);
        assert!(
            !out.ok && out.stderr.contains("could not load the config"),
            "{out:?}"
        );
    }
    let unset = super::events_args_output(&list, load, None, None, Err(TokenError::Missing)).await;
    assert!(
        unset.stderr.contains("could not load the config"),
        "{unset:?}"
    );
    let unset = super::dashboard_link_args_output(
        mcp_gateway::cli::dashboard_link::DashboardLinkArgs {
            url: None,
            tls: no_flags(),
        },
        load,
        None,
        None,
        Err(TokenError::Missing),
    )
    .await;
    assert!(
        unset.stderr.contains("could not load the config"),
        "{unset:?}"
    );
}

/// MIK-9679.CLIUX.14: a usage error, a single character in the redaction
/// marker, and a token re-formed at a marker's edge are never printed.
#[tokio::test]
async fn usage_and_marker_edge_tokens_are_never_printed() {
    let base = answering(400, r#"{"error":"denied: Xd]zz"}"#.into()).await;
    let replay = dead_letters(mcp_gateway::cli::events::DeadLetterAction::Replay);
    let tls = LinkTls::default();
    let usage = super::dead_letters_output(&base, &tls, &replay, "replay").await;
    printed_nowhere("events", "replay", &usage);
    assert!(!usage.ok && !usage.stderr.is_empty(), "{usage:?}");
    for token in ["d", "d]z"] {
        for (command, out) in both(&base, token).await {
            printed_nowhere(command, token, &out);
            assert!(
                !out.ok && !out.stderr.is_empty(),
                "{command} {token:?}: {out:?}"
            );
        }
    }
}

/// MIK-9679.CLIUX.14 and CLIUX.26: `admin_call` itself returns its errors
/// redacted, status text included, for any caller that prints them.
#[tokio::test]
async fn admin_call_errors_never_hold_the_token() {
    for (token, status, body) in [
        ("404", 404, "{}".to_string()),
        ("OK", 200, String::new()),
        (
            "tok-ECHOED-1185",
            400,
            r#"{"reason":"tok-ECHOED-1185"}"#.to_string(),
        ),
    ] {
        let base = answering(status, body).await;
        let error = super::admin_call(
            reqwest::Method::GET,
            &base,
            "/ui/api/events/dead-letters",
            token,
            &LinkTls::default(),
        )
        .await
        .expect_err("an error");
        assert!(!error.contains(token), "token {token:?}: {error}");
        assert!(error.contains("the gateway answered"), "{error}");
    }
    // A token re-formed at the marker's edge: the shared backstop's sentence.
    let base = answering(400, r#"{"error":"denied: Xd]zz"}"#.into()).await;
    let error = super::admin_call(
        reqwest::Method::GET,
        &base,
        "/ui/api/events/dead-letters",
        "d]z",
        &LinkTls::default(),
    )
    .await
    .expect_err("an error");
    assert!(!error.contains("d]z"), "{error}");
}

/// Round 3: `fetch_link`'s own error is token-free for any caller, and the
/// gate checks stderr as printed, so a token ending in a newline cannot form
/// after the check.
#[tokio::test]
async fn fixed_text_and_the_final_newline_never_complete_the_token() {
    let base = answering(200, r#"{"items":[]}"#.into()).await;
    let error = fetch_link(&base, "link").await.expect_err("no link");
    assert!(!error.contains("link"), "{error}");
    let out = super::gate("dashboard-link", "given\n", Err("no reason given".into()));
    assert!(!out.stderr.contains("given\n"), "{out:?}");
    assert!(!out.ok && out.stdout.is_empty(), "{out:?}");
}

/// Run output goes through the CLI's `print!`, which exits cleanly when the
/// reader closes the pipe; std's panics, and the release build aborts.
#[test]
fn run_output_uses_the_cli_print() {
    assert!(include_str!("dashboard_link.rs").contains("\nuse crate::cli::stdout::print;\n"));
}
