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

/// Wait, bounded, until the token endpoint has seen an exchange.
async fn wait_for_exchange(forms: &super::fixture::Forms) {
    let began = std::time::Instant::now();
    while forms.lock().unwrap().is_empty() {
        assert!(
            began.elapsed() < crate::test_wait::HANG_BOUND,
            "no exchange"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
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
    // The exchange runs after the callback page answers: wait for it, so no
    // case below can pass without an exchange having happened.
    match end {
        End::FailedExchange => wait_for_exchange(&forms).await,
        _ => gw.wait_until_held().await,
    }
    match end {
        End::Confirmed => {
            let reply = gw.confirm(&owner, &attempt, "confirm").await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        }
        End::Cancelled => {
            let reply = gw.confirm(&owner, &attempt, "cancel").await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        }
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
        .and_then(|f| f.get("code_verifier").cloned())
        .expect("an exchange was sent, and it carried a verifier");
    let secrets = [
        Some(url),
        Some(state),
        Some(CODE.to_owned()),
        Some(TOKEN.to_owned()),
        Some(verifier),
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
    gw.wait_until_held().await;
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
    assert!(
        gw.backend.installed_client_token_for_test().is_none(),
        "the client holds no copy"
    );
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
    gw.wait_until_held().await;
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

// G3: the request's authority never reaches the redirect URI, in either
// direction: the link and the exchange carry the configured callback host only.
#[tokio::test]
async fn the_request_authority_never_reaches_the_redirect_uri() {
    let cases = [
        ("localhost:39400", "127.0.0.1"),
        ("[::1]:39400", "127.0.0.1"),
        ("127.0.0.1:39400", "localhost"),
        ("[::1]:39400", "localhost"),
    ];
    for (authority, configured) in cases {
        let (issuer, forms) = token_endpoint(Some(TOKEN)).await;
        let gw = Gw::over_on(issuer, Arc::clone(&forms), configured).await;
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
            .map(|(_, v)| v.into_owned())
            .expect("a redirect_uri");
        let host = url::Url::parse(&redirect)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned));
        assert_eq!(host.as_deref(), Some(configured), "{authority}: {redirect}");

        let _ = gw.approve(&url).await;
        gw.wait_until_held().await;
        let confirm = gw.confirm(&who, &attempt, "confirm").await;
        assert_eq!(confirm.status, StatusCode::OK, "{}", confirm.body);
        let sent = forms
            .lock()
            .unwrap()
            .first()
            .and_then(|f| f.get("redirect_uri").cloned());
        assert_eq!(
            sent.as_deref(),
            Some(redirect.as_str()),
            "{authority}: exchange"
        );
    }
}

// L2: a UI-started flow shows its link to no terminal; the link goes only to
// the route's answer.
#[tokio::test]
async fn a_ui_flow_never_announces_the_link_at_the_terminal() {
    let gw = Gw::new().await;
    let who = gw.session();
    let (url, attempt) = Gw::link(&gw.start(&who).await);
    assert!(!url.is_empty(), "the flow started");
    let _ = gw.approve(&url).await;
    gw.wait_until_held().await;
    let _ = gw.confirm(&who, &attempt, "confirm").await;

    let announced = gw.announced.lock().unwrap().clone();
    assert!(announced.is_empty(), "{announced:?}");
}

// L2, other side: a CLI or startup flow announces its link once. Green on the
// base; it must stay green.
#[tokio::test]
async fn a_cli_flow_announces_the_link_once() {
    use crate::oauth::client::authorize_tests::{approve, client};
    let dir = tempfile::tempdir().unwrap();
    let (issuer, _forms) = token_endpoint(Some(TOKEN)).await;
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorder = Arc::clone(&seen);
    let mut cli = client(dir.path(), Some(&issuer)).with_announce(Arc::new(move |url: &str| {
        recorder.lock().unwrap().push(url.to_owned());
    }));

    let (outcome, query) = approve(&mut cli, &issuer).await;

    outcome.expect("the flow completes");
    assert_eq!(*seen.lock().unwrap(), vec![query["__url"].clone()]);
}
