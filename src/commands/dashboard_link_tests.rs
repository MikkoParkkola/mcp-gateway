// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Rows for `dashboard-link` and `events`: token, target and link handling.

use super::super::cli_exit::{CliError, CliExit, CliOutcome, Request};
use super::{DashboardLinkTls, LinkTls, Remedies, TOKEN_ENV, TokenError, read_token};

fn no_flags() -> DashboardLinkTls {
    DashboardLinkTls::default()
}

/// No TLS material: the pre-#1832 request. An error is returned as it would print.
async fn fetch_link(base: &str, token: &str) -> Result<String, String> {
    super::fetch_link(base, token, &LinkTls::default())
        .await
        .map_err(|error| printed(error, token))
}

/// What `error` prints for a run holding `token`.
fn printed(error: CliError, token: &str) -> String {
    error.outcome(false, &[token]).stderr().to_string()
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
        "--gateway wins without a load"
    );

    let failed = dashboard_link_base(None, no_flags(), || Err("bad yaml".into()), None, None)
        .expect_err("a config that fails to load is not replaced by defaults");
    assert!(
        failed.contains("bad yaml") && failed.contains("--gateway"),
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
    assert_eq!(
        err,
        "error: Gateway URL must use HTTPS or loopback HTTP.\nUse an HTTPS gateway URL or a loopback HTTP URL.\n"
    );
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

/// What `dashboard-link` and `events dead-letters` (a list) print against `base`, through their entry points.
async fn both(base: &str, token: &str) -> [(&'static str, CliOutcome); 2] {
    let link = mcp_gateway::cli::dashboard_link::DashboardLinkArgs {
        gateway: mcp_gateway::cli::dashboard_link::GatewayArg {
            url: Some(base.to_string()),
        },
        tls: no_flags(),
        json: false,
    };
    let mut list = dead_letters(mcp_gateway::cli::events::DeadLetterAction::List);
    list.gateway.url = Some(base.to_string());
    let unused = || Err("not loaded".to_string());
    [
        (
            "dashboard-link",
            super::dashboard_link_outcome(link, unused, None, None, Ok(token.to_string())).await,
        ),
        (
            "events",
            super::events_outcome(&list, unused, None, None, Ok(token.to_string())).await,
        ),
    ]
}

fn printed_nowhere(command: &str, token: &str, out: &CliOutcome) {
    assert!(
        !String::from_utf8_lossy(out.stdout()).contains(token) && !out.stderr().contains(token),
        "{command}, token {token:?}: {:?} {:?}",
        out.exit(),
        out.stderr()
    );
}

fn failed(out: &CliOutcome) -> bool {
    out.exit() != CliExit::Ok
}

/// A token equal to the status text is never printed.
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
            assert!(failed(&out), "{command}, token {token:?}: a failure");
            // Not the fixed fallback sentence: the report itself, redacted.
            assert!(
                out.stderr().starts_with("error: The gateway "),
                "{command}, token {token:?}: {}",
                out.stderr()
            );
        }
    }
}

/// A token echoed in any of the
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
            assert!(failed(&out), "{command}: a failure");
            assert!(out.stderr().contains("400"), "{command}: {}", out.stderr());
        }
    }
}

/// A token in the success answer, in a value, a key or the
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
        assert!(!failed(out), "{command}: {}", out.stderr());
        assert!(!out.stdout().is_empty(), "{command}: the answer is printed");
    }
    assert!(
        link.stdout()
            .starts_with(b"http://127.0.0.1:1/dashboard?bootstrap=")
    );
    let printed: serde_json::Value = serde_json::from_slice(events.stdout()).expect("JSON");
    assert_eq!(printed["items"][0]["id"], "d1");
}

/// An answer whose redaction would merge two entries is
/// refused, not printed short.
#[tokio::test]
async fn an_answer_that_loses_an_entry_to_redaction_is_refused() {
    // `[redacted]` is the shared redactor's first marker: renaming the key
    // `#` to it collides with the existing key.
    let body = r##"{"link":"http://127.0.0.1:1/l","#":"first","[redacted]":"second"}"##;
    let base = answering(200, body.to_string()).await;
    for (command, out) in both(&base, "#").await {
        printed_nowhere(command, "#", &out);
        assert!(failed(&out), "{command}: refused");
        assert!(out.stdout().is_empty(), "{command}: nothing on stdout");
        assert!(
            out.stderr().contains("printed safely"),
            "{command}: {}",
            out.stderr()
        );
    }
}

/// The stdout backstop and the gate. A token equal to JSON syntax, which the JSON redactor cannot mask, is
/// refused; a token equal to a word of the note or the error is masked there.
#[tokio::test]
async fn a_token_in_fixed_text_is_never_printed() {
    let base = answering(200, r#"{"link":"http://127.0.0.1:1/l","ok":1}"#.into()).await;
    let [(_, link), (_, events)] = both(&base, ":").await;
    printed_nowhere("dashboard-link", ":", &link);
    printed_nowhere("events", ":", &events);
    assert!(
        failed(&events) && events.stdout().is_empty(),
        "{}",
        events.stderr()
    );
    let [(_, link), _] = both(&base, "once").await;
    assert!(!failed(&link), "{}", link.stderr());
    printed_nowhere("dashboard-link", "once", &link);
    // The gate redacted the note; the fixed fallback sentence would not hold this.
    assert!(
        link.stderr().contains("from this machine only"),
        "{}",
        link.stderr()
    );
    let refused = answering(403, "{}".into()).await;
    let [_, (_, events)] = both(&refused, "permitted").await;
    printed_nowhere("events", "permitted", &events);
    assert!(
        events.stderr().contains("The gateway answered HTTP 403"),
        "{}",
        events.stderr()
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
        gateway: mcp_gateway::cli::dashboard_link::GatewayArg::default(),
        tls: no_flags(),
    }
}

/// A config error that quotes the token is gated once a
/// token is set; it still comes before the token error.
#[tokio::test]
async fn a_config_error_quoting_the_token_is_never_printed() {
    let token = "tok-IN-CONFIG-9679";
    let load = || Err(format!("bad bearer_token value {token}"));
    let args = || mcp_gateway::cli::dashboard_link::DashboardLinkArgs {
        gateway: mcp_gateway::cli::dashboard_link::GatewayArg::default(),
        tls: no_flags(),
        json: false,
    };
    let link = super::dashboard_link_outcome(args(), load, None, None, Ok(token.to_string())).await;
    let list = dead_letters(mcp_gateway::cli::events::DeadLetterAction::List);
    let events = super::events_outcome(&list, load, None, None, Ok(token.to_string())).await;
    for (command, out) in [("dashboard-link", &link), ("events", &events)] {
        printed_nowhere(command, token, out);
        assert!(
            out.exit() == CliExit::Usage && out.stderr().contains("could not load the config"),
            "{}",
            out.stderr()
        );
    }
    let unset = super::events_outcome(&list, load, None, None, Err(TokenError::Missing)).await;
    assert!(
        unset.stderr().contains("could not load the config"),
        "{}",
        unset.stderr()
    );
    let unset =
        super::dashboard_link_outcome(args(), load, None, None, Err(TokenError::Missing)).await;
    assert!(
        unset.stderr().contains("could not load the config"),
        "{}",
        unset.stderr()
    );
}

/// A usage error, single characters in the redaction markers, and a token
/// that would re-form at a marker's edge are never printed.
#[tokio::test]
async fn usage_and_marker_edge_tokens_are_never_printed() {
    let base = answering(400, r#"{"error":"denied: Xd]zz"}"#.into()).await;
    let mut replay = dead_letters(mcp_gateway::cli::events::DeadLetterAction::Replay);
    replay.gateway.url = Some(base.clone());
    let unused = || Err("not loaded".to_string());
    let usage = super::events_outcome(&replay, unused, None, None, Ok("replay".to_string())).await;
    printed_nowhere("events", "replay", &usage);
    assert!(
        usage.exit() == CliExit::Usage && !usage.stderr().is_empty(),
        "{}",
        usage.stderr()
    );
    // "d]z" would re-form at the first marker's edge, so the redactor takes the second; the report still prints.
    for (command, out) in both(&base, "d]z").await {
        printed_nowhere(command, "d]z", &out);
        assert!(
            failed(&out) && !out.stderr().is_empty(),
            "{command}: {}",
            out.stderr()
        );
    }
    // "r" is in the "error:" prefix and in the fixed sentence, which are never redacted: nothing prints, the
    // exit stands (the gate's rule, shared with api).
    for (command, out) in both(&base, "r").await {
        assert_eq!(
            (out.exit(), out.stderr(), out.stdout()),
            (CliExit::Gateway, "", &b""[..]),
            "{command}"
        );
    }
    // "d" is in every marker, so the redactor fails closed: nothing holding
    // it is printed, possibly nothing at all.
    for (command, out) in both(&base, "d").await {
        printed_nowhere(command, "d", &out);
        assert!(failed(&out) && out.stdout().is_empty(), "{command}");
    }
}

/// `admin_call`'s errors, as printed for any caller, never hold the token, status text included.
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
        // A token that would re-form at the first marker's edge takes the next.
        ("d]z", 400, r#"{"error":"denied: Xd]zz"}"#.to_string()),
    ] {
        let base = answering(status, body).await;
        let error = super::admin_call(
            reqwest::Method::GET,
            &base,
            "/ui/api/events/dead-letters",
            token,
            &LinkTls::default(),
            Request::Read,
            &Remedies::read(&base),
        )
        .await
        .expect_err("an error");
        let error = printed(error, token);
        assert!(!error.contains(token), "token {token:?}: {error}");
        assert!(error.starts_with("error: The gateway "), "{error}");
    }
}

/// `fetch_link`'s own error is token-free for any caller, and the gate checks stderr as printed, so a token
/// ending in a newline cannot form after the check.
#[tokio::test]
async fn fixed_text_and_the_final_newline_never_complete_the_token() {
    let base = answering(200, r#"{"items":[]}"#.into()).await;
    let error = fetch_link(&base, "link").await.expect_err("no link");
    assert!(!error.contains("link"), "{error}");
    let out =
        CliError::new(CliExit::Usage, "no reason given", "Retry.").outcome(false, &["given\n"]);
    assert!(!out.stderr().contains("given\n"), "{}", out.stderr());
    assert!(
        out.exit() == CliExit::Usage && out.stdout().is_empty(),
        "{}",
        out.stderr()
    );
}

/// Run output goes through the shared emitter, which ends with exit 0 when the reader closes the pipe (the
/// emitter rows prove it) instead of std's panic.
#[test]
fn run_output_uses_the_shared_emitter() {
    let source = include_str!("dashboard_link.rs");
    // events prints through `emit`; dashboard-link through its print step, which hands the run's form to `emit_to`.
    assert_eq!(source.matches("emit(&out, false, &[&secret])").count(), 1);
    assert_eq!(
        source.matches("let exit = print_dashboard_link(").count(),
        1
    );
    assert_eq!(
        source
            .matches("emit_to(&out, json, &[&secret], stdout, stderr)")
            .count(),
        1
    );
}

/// T3 (MIK-9764.JSONF.1, design D5): the command's path from its arguments to the shared emitter carries the run's
/// form, so a stdout write failure other than a broken pipe is the shared JSON error under `--json`, and the text
/// error without.
#[tokio::test]
async fn the_print_step_carries_the_json_form() {
    struct Failing;
    impl std::io::Write for Failing {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("disk full"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let base = answering(200, r#"{"link":"https://gw.test/ui/#k=abc123"}"#.to_owned()).await;
    let run = |json: bool| {
        let base = base.clone();
        async move {
            let args = mcp_gateway::cli::dashboard_link::DashboardLinkArgs {
                gateway: mcp_gateway::cli::dashboard_link::GatewayArg { url: Some(base) },
                tls: no_flags(),
                json,
            };
            let mut err = Vec::new();
            let exit = super::print_dashboard_link(
                args,
                || Err("not loaded".to_string()),
                None,
                None,
                Ok("tok-print-0123456789".to_owned()),
                &mut Failing,
                &mut err,
            )
            .await;
            (exit, String::from_utf8(err).expect("utf-8"))
        }
    };
    let (exit, err) = run(true).await;
    assert_eq!(exit, CliExit::LocalFailure);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&err).expect("one JSON error"),
        serde_json::json!({"schema_version": 1, "error": {
            "kind": "LocalFailure", "message": "Could not write command output.",
            "remedy": "Check the output destination before repeating the command.",
            "http_status": null, "request_id": null
        }})
    );
    assert_eq!(
        run(false).await,
        (
            CliExit::LocalFailure,
            "error: Could not write command output.\nCheck the output destination before repeating the command.\n"
                .to_owned()
        )
    );
}
