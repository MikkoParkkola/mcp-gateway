// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8617: `get_token_detached`, the token step of an interactive HTTP
//! backend request (`transport/http/requests.rs`; a non-interactive request
//! takes `get_token`), answers a refresh the SSRF policy refused with that
//! refusal and starts no authorization (MIK-7701). The same rule on
//! `get_token` is pinned by
//! `tests::get_token_surfaces_a_refused_refresh_without_authorizing`.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use super::tests::{client_with_refused_refresh, count_browsers};
use crate::oauth::login_gate::{LoginGate, SetOut};

/// With a login gate attached and the step's epoch, cohort and deadline
/// taken from it, as the request path's `detach_token_step` takes them, so
/// the gated refresh branch is the one exercised.
#[tokio::test]
async fn get_token_detached_surfaces_a_refused_refresh_without_authorizing() {
    let dir = tempfile::tempdir().unwrap();
    let gate = Arc::new(LoginGate::default());
    let mut client = client_with_refused_refresh(dir.path())
        .await
        .with_login_gate(Arc::clone(&gate));
    let opened = count_browsers(&mut client);
    let SetOut {
        since,
        cohort,
        deadline,
    } = gate.set_out_now();
    let outcome = tokio::time::timeout(
        Duration::from_secs(10),
        client.get_token_detached(true, since, &cohort, deadline),
    )
    .await;
    assert_eq!(opened.load(Ordering::SeqCst), 0, "no authorization starts");
    let error = outcome
        .expect("answered promptly")
        .expect_err("a refused refresh must surface");
    assert!(error.to_string().contains("SSRF blocked"), "{error}");
    assert_eq!(error.to_rpc_code(), -32600, "{error}");
}
