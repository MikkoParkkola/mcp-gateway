// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The sign-in start and confirm routes, through the real router with
//! dashboard sessions and a real flow against a loopback issuer. Time-based
//! rows are in `signin_timing_tests.rs`, secrecy rows in
//! `signin_secrecy_tests.rs`.

use std::sync::atomic::Ordering;
use std::time::Duration;

use axum::http::StatusCode;

use super::fixture::{Gw, Reply, Who};
use crate::oauth::client::sign_in::SignIn;

fn assert_refusal(reply: &Reply, status: StatusCode, code: &str) {
    assert_eq!(reply.status, status, "{}", reply.body);
    assert_eq!(reply.json()["error"], code, "{}", reply.body);
}

/// A started flow for `who`: the link and the attempt id.
async fn started(gw: &Gw, who: &Who) -> (String, String) {
    let reply = gw.start(who).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    Gw::link(&reply)
}

/// A flow `who` started and the person approved: waiting for the confirm.
async fn approved(gw: &Gw, who: &Who) -> String {
    let (url, attempt) = started(gw, who).await;
    gw.approve(&url).await;
    attempt
}

// R1
#[tokio::test]
async fn a_non_admin_gets_the_same_refusal_for_any_name() {
    let gw = Gw::new().await;
    let existing = gw.start_named(&Who::Standard, "cov3-backend").await;
    let missing = gw.start_named(&Who::Standard, "no-such-backend").await;

    assert_eq!(existing.status, StatusCode::FORBIDDEN, "{}", existing.body);
    assert_eq!(
        (existing.status, &existing.body),
        (missing.status, &missing.body)
    );
}

// R2: a missing, an expired and a never-issued handle all refuse.
#[tokio::test]
async fn a_bearer_only_admin_cannot_start_or_confirm() {
    let gw = Gw::new().await;
    let expired = gw.session();
    if let Who::Dashboard(handle) = &expired {
        gw.state
            .dashboard_bootstrap
            .backdate(handle, Duration::from_secs(9 * 3600));
    }
    let forged = Who::Dashboard("never-issued-handle".to_owned());
    for who in [Who::BearerOnly, expired, forged] {
        let start = gw.start(&who).await;
        assert_refusal(&start, StatusCode::FORBIDDEN, "dashboard_session_required");
        let confirm = gw.confirm(&who, "any-attempt", "confirm").await;
        assert_refusal(
            &confirm,
            StatusCode::FORBIDDEN,
            "dashboard_session_required",
        );
    }
    assert!(gw.row().await["sign_in_flow"].is_null(), "no flow started");
}

// R3
#[tokio::test]
async fn a_form_post_is_refused() {
    let gw = Gw::new().await;
    let who = gw.session();
    let path = "/ui/api/backends/cov3-backend/signin";
    let reply = gw
        .send(
            &who,
            "POST",
            path,
            "application/x-www-form-urlencoded",
            "x=1",
        )
        .await;

    assert!(
        reply.status.is_client_error(),
        "{} {}",
        reply.status,
        reply.body
    );
}

// R4: the stream's frames are covered by the secrecy rows' sinks.
#[tokio::test]
async fn start_returns_the_link_once_with_no_store() {
    let gw = Gw::new().await;
    let reply = gw.start(&gw.session()).await;

    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let body = reply.json();
    for key in ["authorization_url", "expires_at", "attempt_id"] {
        assert!(body[key].is_string(), "{key}: {body}");
    }
    let cache = reply
        .headers
        .get("cache-control")
        .and_then(|v| v.to_str().ok());
    assert_eq!(cache, Some("no-store"));
    let read = gw.row().await.to_string();
    assert!(
        !read.contains(body["authorization_url"].as_str().unwrap_or("-")),
        "{read}"
    );
}

// R5: another session and the same session both get the in-progress answer.
#[tokio::test]
async fn a_second_start_gets_in_progress_without_a_link() {
    let gw = Gw::new().await;
    let first = gw.session();
    let _ = started(&gw, &first).await;
    for who in [gw.session(), first.clone()] {
        let reply = gw.start(&who).await;
        assert_refusal(&reply, StatusCode::CONFLICT, "sign_in_in_progress");
        let body = reply.json();
        assert!(
            body["expires_at"].is_string() && body["retry_after_secs"].is_u64(),
            "{body}"
        );
        assert!(!reply.body.contains("authorization_url"), "{}", reply.body);
    }
    assert_eq!(
        gw.row().await["sign_in_flow"]["phase"],
        "awaiting_callback",
        "the first flow survives"
    );
}

// R6: no early Cancelled: the flow holds the gate through callback and exchange.
#[tokio::test]
async fn the_flow_keeps_the_login_gate_after_the_route_returns() {
    let gw = Gw::new().await;
    let _ = approved(&gw, &gw.session()).await;

    let again = gw.start(&gw.session()).await;
    assert_refusal(&again, StatusCode::CONFLICT, "sign_in_in_progress");
    assert_eq!(gw.row().await["sign_in_flow"]["phase"], "awaiting_confirm");
}

// R7: the client's cached token is not reachable from here; the store and the
// status stand in for it.
#[tokio::test]
async fn nothing_is_saved_before_confirm() {
    let gw = Gw::new().await;
    let _ = approved(&gw, &gw.session()).await;

    assert!(gw.saved().is_none(), "no token on disk before confirm");
    assert_eq!(gw.row().await["sign_in_flow"]["phase"], "awaiting_confirm");
    assert!(
        !matches!(gw.backend.sign_in(), SignIn::SignedIn { .. }),
        "the status is unchanged"
    );
}

// R8
#[tokio::test]
async fn owner_confirm_saves_and_clears_its_wait() {
    let gw = Gw::new().await;
    gw.backend
        .shared_entry_for_test()
        .auth_wait
        .store(true, Ordering::Relaxed);
    let owner = gw.session();
    let attempt = approved(&gw, &owner).await;

    let reply = gw.confirm(&owner, &attempt, "confirm").await;

    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(
        gw.saved().map(|t| t.access_token),
        Some("access-a".to_owned())
    );
    assert!(matches!(gw.backend.sign_in(), SignIn::SignedIn { .. }));
    assert!(
        !gw.backend
            .shared_entry_for_test()
            .auth_wait
            .load(Ordering::Relaxed)
    );
}

// R9: a wait recorded after the callback outlives the confirm.
#[tokio::test]
async fn a_newer_wait_survives_confirm() {
    let gw = Gw::new().await;
    gw.backend
        .shared_entry_for_test()
        .auth_wait
        .store(true, Ordering::Relaxed);
    let owner = gw.session();
    let attempt = approved(&gw, &owner).await;
    gw.backend.note_auth_wait();

    let reply = gw.confirm(&owner, &attempt, "confirm").await;

    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert!(
        gw.backend
            .shared_entry_for_test()
            .auth_wait
            .load(Ordering::Relaxed)
    );
}

// R10: the other session presents the owner's real attempt id, so only the
// owner compare can refuse it.
#[tokio::test]
async fn another_session_cannot_confirm_or_cancel() {
    let gw = Gw::new().await;
    let owner = gw.session();
    let attempt = approved(&gw, &owner).await;
    let other = gw.session();
    for decision in ["confirm", "cancel"] {
        let reply = gw.confirm(&other, &attempt, decision).await;
        assert_refusal(&reply, StatusCode::NOT_FOUND, "no_sign_in");
    }

    let reply = gw.confirm(&owner, &attempt, "confirm").await;

    assert_eq!(
        reply.status,
        StatusCode::OK,
        "the owner can still confirm: {}",
        reply.body
    );
}

// R11: a cancelled attempt's id cannot approve a later login.
#[tokio::test]
async fn a_stale_attempt_id_cannot_confirm() {
    let gw = Gw::new().await;
    let owner = gw.session();
    let (_, stale) = started(&gw, &owner).await;
    let cancel = gw.confirm(&owner, &stale, "cancel").await;
    assert_eq!(cancel.status, StatusCode::OK, "{}", cancel.body);
    let _later = approved(&gw, &owner).await;

    let reply = gw.confirm(&owner, &stale, "confirm").await;

    assert_refusal(&reply, StatusCode::NOT_FOUND, "no_sign_in");
    assert!(gw.saved().is_none());
}

// R12
#[tokio::test]
async fn confirm_before_the_callback_is_not_ready() {
    let gw = Gw::new().await;
    let owner = gw.session();
    let (_, attempt) = started(&gw, &owner).await;

    let reply = gw.confirm(&owner, &attempt, "confirm").await;

    assert_refusal(&reply, StatusCode::CONFLICT, "sign_in_not_ready");
    assert!(reply.json()["retry_after_secs"].is_u64(), "{}", reply.body);
}

// R13
#[tokio::test]
async fn owner_cancel_discards_the_pending_token() {
    let gw = Gw::new().await;
    let owner = gw.session();
    let attempt = approved(&gw, &owner).await;

    let cancel = gw.confirm(&owner, &attempt, "cancel").await;

    assert_eq!(cancel.status, StatusCode::OK, "{}", cancel.body);
    assert!(gw.saved().is_none(), "nothing saved");
    let again = gw.start(&owner).await;
    assert_eq!(
        again.status,
        StatusCode::OK,
        "the gate is released: {}",
        again.body
    );
}

// R14: a store that refuses the write. Unix only: it removes write access.
#[cfg(unix)]
#[tokio::test]
async fn a_failed_save_discards_the_pending_token() {
    use std::os::unix::fs::PermissionsExt;
    let gw = Gw::new().await;
    let owner = gw.session();
    let attempt = approved(&gw, &owner).await;
    std::fs::set_permissions(gw.store.path(), std::fs::Permissions::from_mode(0o500)).unwrap();

    let reply = gw.confirm(&owner, &attempt, "confirm").await;
    std::fs::set_permissions(gw.store.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

    assert!(
        reply.status.is_server_error() && reply.status != StatusCode::NOT_IMPLEMENTED,
        "{} {}",
        reply.status,
        reply.body
    );
    assert!(gw.saved().is_none());
    let retry = gw.confirm(&owner, &attempt, "confirm").await;
    assert_refusal(&retry, StatusCode::NOT_FOUND, "no_sign_in");
}

// R15: the pending token lives in memory only, so a new process has none.
#[tokio::test]
async fn restart_drops_the_pending_token() {
    let first = Gw::new().await;
    let attempt = approved(&first, &first.session()).await;
    drop(first);

    let second = Gw::new().await;
    let reply = second.confirm(&second.session(), &attempt, "confirm").await;

    assert_refusal(&reply, StatusCode::NOT_FOUND, "no_sign_in");
    assert!(second.saved().is_none());
    assert!(second.row().await["sign_in_flow"].is_null());
}

// R16: green on the base and it stays green: no sink, so the exchange saves.
#[tokio::test]
async fn cli_and_startup_flows_still_save_on_exchange() {
    use crate::oauth::client::authorize_tests::{approve, client, token_endpoint};
    let dir = tempfile::tempdir().unwrap();
    let (issuer, _forms) = token_endpoint(Some("access-cli")).await;
    let mut cli = client(dir.path(), Some(&issuer));

    let (outcome, _) = approve(&mut cli, &issuer).await;

    assert_eq!(outcome.expect("the flow completes"), "access-cli");
    assert!(cli.has_valid_token(), "saved and cached on exchange");
}
