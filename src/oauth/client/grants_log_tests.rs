// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What the authorization flow writes to the operator's log about the link it
//! sends the browser to.

use super::authorize_tests::{approve, client, token_endpoint};

/// L1: the link carries the state, the PKCE challenge and the redirect URI, so
/// the log line that announces it keeps only the endpoint and path.
// Current-thread on purpose: `capture()` is thread-local.
#[tokio::test(flavor = "current_thread")]
async fn the_authorization_url_is_logged_redacted() {
    let (guard, buffer) = crate::oauth::callback::tests::capture();
    let dir = tempfile::tempdir().unwrap();
    let (issuer, _forms) = token_endpoint(Some("access-a")).await;
    let mut client = client(dir.path(), Some(&issuer));

    let (outcome, query) = approve(&mut client, &issuer).await;
    drop(guard);

    outcome.expect("the flow completes");
    let log = String::from_utf8(buffer.lock().unwrap().clone()).unwrap();
    let line = log
        .lines()
        .find(|line| line.contains("Opening browser for authorization"))
        .unwrap_or_else(|| panic!("the flow announces the link:\n{log}"));
    assert!(
        line.contains(&format!("{issuer}/authorize")),
        "the line keeps the endpoint: {line}"
    );
    for secret in [
        "state=",
        "code_challenge=",
        "redirect_uri=",
        query["state"].as_str(),
    ] {
        assert!(
            !line.contains(secret),
            "{secret} must not be logged: {line}"
        );
    }
}
