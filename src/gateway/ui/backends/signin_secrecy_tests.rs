// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a sign-in leaves in logs, the audit log, the backends read and the
//! callback page: never the link, the state, the verifier, the code or the
//! token. Also the flow-end audit records and the redirect URI's source.

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use serde_json::Value;

use super::fixture::Gw;
use crate::oauth::client::authorize_tests::{BACKEND, token_endpoint};

const CODE: &str = "fixture-code";
const TOKEN: &str = "access-a";

/// How a sign-in ends.
#[derive(Clone, Copy)]
enum End {
    Confirmed,
    FailedExchange,
    Cancelled,
    Expired,
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
}

/// Let every woken task run.
async fn settle() {
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }
}

/// Run a sign-in to `end`. Returns the sinks it wrote (name and text) and the
/// secrets that must be in none of them.
async fn run(end: End) -> (Vec<(&'static str, String)>, Vec<String>) {
    let answer = (!matches!(end, End::FailedExchange)).then_some(TOKEN);
    let (issuer, forms) = token_endpoint(answer).await;
    let gw = Gw::over(issuer, Arc::clone(&forms)).await;
    let owner = gw.session();
    let reply = gw.start(&owner).await;
    let (url, attempt) = Gw::link(&reply);
    let page = gw.approve(&url).await;
    match end {
        End::Confirmed => drop(gw.confirm(&owner, &attempt, "confirm").await),
        End::Cancelled => drop(gw.confirm(&owner, &attempt, "cancel").await),
        End::Expired => {
            tokio::time::pause();
            tokio::time::advance(Duration::from_secs(61)).await;
        }
        End::FailedExchange => {}
    }
    settle().await;
    let state = url::Url::parse(&url)
        .map(|link| {
            link.query_pairs()
                .find(|(k, _)| k == "state")
                .map(|(_, v)| v.into_owned())
        })
        .ok()
        .flatten()
        .unwrap_or_default();
    let verifier = forms
        .lock()
        .unwrap()
        .first()
        .and_then(|f| f.get("code_verifier").cloned());
    let secrets = [
        Some(url),
        Some(state),
        Some(CODE.to_owned()),
        Some(TOKEN.to_owned()),
        verifier,
    ];
    let sinks = vec![
        ("the callback page", page),
        ("the backends read", gw.row().await.to_string()),
        (
            "the audit log",
            Value::Array(gw.admin_actions()).to_string(),
        ),
    ];
    // The start answer carries the link by design, so it is not a sink.
    (sinks, secrets.into_iter().flatten().collect())
}

/// `run(end)` under a log capture; the log is the last sink.
fn trace(end: End) -> (Vec<(&'static str, String)>, Vec<String>) {
    let mut out = None;
    let records = crate::test_log_capture::records(|| out = Some(runtime().block_on(run(end))));
    let (mut sinks, secrets) = out.expect("the run finished");
    sinks.push(("the log", Value::Array(records).to_string()));
    (sinks, secrets)
}

// L3: each sink first proves it emitted, then holds no secret.
#[test]
fn canaries_never_reach_logs_audit_or_reads() {
    for end in [
        End::Confirmed,
        End::FailedExchange,
        End::Cancelled,
        End::Expired,
    ] {
        let (sinks, secrets) = trace(end);
        for (name, text) in &sinks {
            assert!(text.len() > 2 && text != "null", "{name} emitted nothing");
        }
        for (name, text) in &sinks {
            for secret in &secrets {
                assert!(
                    !text.contains(secret.as_str()),
                    "{secret} reached {name}: {text}"
                );
            }
        }
    }
}

// L6: a save that fails leaves no signed-in status and no stored token. The
// client's cached copy is not reachable from here.
#[cfg(unix)]
#[tokio::test]
async fn a_failed_save_after_conversion_leaves_no_plain_copy() {
    use std::os::unix::fs::PermissionsExt;
    let gw = Gw::new().await;
    let owner = gw.session();
    let (url, attempt) = Gw::link(&gw.start(&owner).await);
    let _ = gw.approve(&url).await;
    std::fs::set_permissions(gw.store.path(), std::fs::Permissions::from_mode(0o500)).unwrap();

    let reply = gw.confirm(&owner, &attempt, "confirm").await;
    std::fs::set_permissions(gw.store.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

    assert!(
        reply.status.is_server_error(),
        "{} {}",
        reply.status,
        reply.body
    );
    assert!(gw.saved().is_none());
    assert!(!matches!(
        gw.backend.sign_in(),
        crate::oauth::client::sign_in::SignIn::SignedIn { .. }
    ));
    assert!(
        gw.row().await["sign_in_flow"].is_null(),
        "no flow record keeps it"
    );
}

/// Poll the audit log until it holds more than `before` records.
async fn actions_after(gw: &Gw, before: usize) -> Vec<Value> {
    for _ in 0..50 {
        let records = gw.admin_actions();
        if records.len() > before {
            return records;
        }
        settle().await;
    }
    gw.admin_actions()
}

fn assert_flow_end(records: &[Value], before: usize, word: &str) {
    let ended = records.get(before..).unwrap_or_default();
    let text = Value::Array(ended.to_vec()).to_string();
    assert!(!ended.is_empty(), "a flow-end record is written");
    assert!(text.contains(BACKEND) && text.contains(word), "{text}");
    assert!(
        !text.contains(TOKEN) && !text.contains(CODE),
        "no secret in {text}"
    );
}

// A1
#[tokio::test]
async fn expiry_writes_a_flow_end_record() {
    let gw = Gw::new().await;
    let owner = gw.session();
    let (url, _) = Gw::link(&gw.start(&owner).await);
    let _ = gw.approve(&url).await;
    let before = gw.admin_actions().len();
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(61)).await;

    let records = actions_after(&gw, before).await;

    assert_flow_end(&records, before, "expired");
}

// A2
#[tokio::test]
async fn a_failed_exchange_writes_a_flow_end_record() {
    let (issuer, forms) = token_endpoint(None).await;
    let gw = Gw::over(issuer, forms).await;
    let (url, _) = Gw::link(&gw.start(&gw.session()).await);
    let before = gw.admin_actions().len();
    let _ = gw.approve(&url).await;

    let records = actions_after(&gw, before).await;

    assert_flow_end(&records, before, "failed");
}

// G3: the request's authority never reaches the redirect URI. The configured
// callback host is 127.0.0.1, so a start addressed as `localhost` or `[::1]`
// must still redirect to 127.0.0.1, in the link and in the exchange.
#[tokio::test]
async fn the_request_authority_never_reaches_the_redirect_uri() {
    for authority in ["localhost:39400", "[::1]:39400"] {
        let gw = Gw::new().await;
        let who = gw.session();
        let path = "/ui/api/backends/cov3-backend/signin";
        let reply = gw
            .send_from(authority, &who, "POST", path, "application/json", "{}")
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{authority}: {}", reply.body);
        let (url, attempt) = Gw::link(&reply);
        let link = url::Url::parse(&url).expect("a link");
        let redirect = link
            .query_pairs()
            .find(|(k, _)| k == "redirect_uri")
            .map(|(_, v)| v.into_owned());
        let redirect = redirect.expect("a redirect_uri");
        assert!(
            redirect.starts_with("http://127.0.0.1:"),
            "{authority}: {redirect}"
        );
        assert!(
            !url.contains("localhost") && !url.contains("%5B"),
            "{authority}: {url}"
        );

        let _ = gw.approve(&url).await;
        let confirm = gw.confirm(&who, &attempt, "confirm").await;
        assert_eq!(confirm.status, StatusCode::OK, "{}", confirm.body);
        let sent = gw
            .forms
            .lock()
            .unwrap()
            .first()
            .and_then(|f| f.get("redirect_uri").cloned());
        assert_eq!(
            sent.as_deref(),
            Some(redirect.as_str()),
            "{authority}: the exchange's redirect_uri"
        );
    }
}
