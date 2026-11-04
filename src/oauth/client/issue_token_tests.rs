// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Exits of a login's code-issuing step that no other library row drives: a
//! callback server that cannot bind, and a provider that answers the callback
//! with an error.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::authorize_tests::{client, token_endpoint};
use crate::test_wait::HANG_BOUND;

/// A callback port some other listener already holds ends the login at once,
/// before any link is shown or any browser opens.
#[tokio::test]
async fn a_callback_server_that_cannot_bind_ends_the_login_before_any_browser() {
    let busy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = busy.local_addr().unwrap().port();
    let dir = tempfile::tempdir().unwrap();
    let (issuer, _forms) = token_endpoint(Some("access-a")).await;
    let mut login = client(dir.path(), Some(&issuer));
    login.callback_port = Some(port);
    let opened = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&opened);
    login.open_browser = Box::new(move |_| {
        flag.store(true, Ordering::SeqCst);
        true
    });

    let outcome = tokio::time::timeout(HANG_BOUND, login.authorize())
        .await
        .expect("the login ends at once");

    let error = outcome.expect_err("a held port is a failed login");
    assert!(error.to_string().contains("callback server"), "{error}");
    assert!(!opened.load(Ordering::SeqCst), "no browser opened");
}

/// A provider that answers the callback with an error code (and the right
/// state) ends the login with that code, and no code is ever redeemed.
#[tokio::test]
async fn a_provider_error_at_the_callback_ends_the_login_with_its_code() {
    let dir = tempfile::tempdir().unwrap();
    let (issuer, forms) = token_endpoint(Some("access-a")).await;
    let mut login = client(dir.path(), Some(&issuer));
    let (url_tx, mut url_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    login.open_browser = Box::new(move |url| {
        let _ = url_tx.send(url.to_owned());
        true
    });
    let person = async {
        let link = url_rx.recv().await.expect("a link is shown");
        let query: HashMap<String, String> = url::Url::parse(&link)
            .unwrap()
            .query_pairs()
            .into_owned()
            .collect();
        let callback = url::Url::parse_with_params(
            &query["redirect_uri"],
            &[
                ("error", "access_denied"),
                ("state", query["state"].as_str()),
            ],
        )
        .unwrap();
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .get(callback)
            .send()
            .await
            .expect("the callback answers");
    };

    let (outcome, ()) = tokio::time::timeout(HANG_BOUND, async {
        tokio::join!(login.authorize(), person)
    })
    .await
    .expect("the login ends");

    let error = outcome.expect_err("a provider error is a failed login");
    assert!(error.to_string().contains("access_denied"), "{error}");
    assert!(forms.lock().unwrap().is_empty(), "no code was redeemed");
}
