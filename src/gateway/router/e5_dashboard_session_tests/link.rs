// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! E5 sign-in and re-entry: cookie lifetime, redemption past a dead cookie,
//! and minting a fresh link (MIK-7570.SESSION.1).

use super::*;

// ── Sign-in and re-entry ───────────────────────────────────────────────

/// E5-T6: the cookie's lifetime is the absolute limit the server enforces,
/// including a configured one.
#[tokio::test]
async fn cookie_max_age_equals_absolute_timeout() {
    let (state, _dir) = fixture().await;
    let value = state.dashboard_bootstrap.peek().expect("startup value");
    let out = send(&state, redeem(&value, None)).await;
    assert_eq!(out.status, StatusCode::SEE_OTHER, "{}", out.body);
    assert!(
        out.set_cookie().contains("Max-Age=28800"),
        "{}",
        out.set_cookie()
    );

    let (state, _dir) = fixture().await;
    reload(&state, |c| {
        c.auth.dashboard_session.absolute_timeout_secs = 3600;
    });
    let value = state.dashboard_bootstrap.peek().expect("startup value");
    let out = send(&state, redeem(&value, None)).await;
    assert_eq!(out.status, StatusCode::SEE_OTHER, "{}", out.body);
    assert!(
        out.set_cookie().contains("Max-Age=3600"),
        "{}",
        out.set_cookie()
    );
}

/// E5-T18: a fresh link works even while the browser still holds a dead
/// cookie; that is exactly when an operator uses one.
#[tokio::test]
async fn bootstrap_redeems_past_a_dead_cookie() {
    let (state, _dir) = fixture().await;
    let dead = issue(&state);
    age(&state, &dead, IDLE + MIN);
    let value = state.dashboard_bootstrap.peek().expect("startup value");
    let out = send(&state, redeem(&value, Some(&dead))).await;
    assert_eq!(out.status, StatusCode::SEE_OTHER, "{}", out.body);
    assert!(
        out.set_cookie().contains(&format!("{SESSION_COOKIE}=")) && !out.clears_cookie(),
        "a new session cookie is set: {}",
        out.set_cookie()
    );
    let fresh = out
        .set_cookie()
        .split(';')
        .next()
        .and_then(|c| c.strip_prefix(&format!("{SESSION_COOKIE}=")))
        .expect("the new handle")
        .to_string();
    assert!(is_admin_view(
        &send(&state, get(STATUS, Some(&fresh))).await
    ));
}

/// The link the dashboard-link endpoint returned, for `credential`.
async fn mint(state: &Arc<AppState>, credential: Option<&str>, cookie: Option<&str>) -> Reply {
    send(state, request("POST", LINK, cookie, credential, false)).await
}

fn bootstrap_value(link: &str) -> String {
    link.split_once("/dashboard?bootstrap=")
        .map(|(_, v)| v.to_string())
        .unwrap_or_default()
}

/// E5-T7: an admin credential re-arms a fresh single-use link without a
/// restart; the replaced value is dead.
#[tokio::test]
async fn rearm_issues_fresh_single_use_link() {
    let (state, _dir) = fixture().await;
    let old = state.dashboard_bootstrap.peek().expect("startup value");

    let out = mint(&state, Some(ADMIN_KEY), None).await;
    assert_eq!(out.status, StatusCode::OK, "{}", out.body);
    let link = out.json()["link"].as_str().unwrap_or_default().to_string();
    assert!(link.starts_with("http://127.0.0.1:"), "{link}");
    let new = bootstrap_value(&link);
    assert!(!new.is_empty(), "{link}");
    assert_ne!(new, old, "a fresh value");

    assert_eq!(
        send(&state, redeem(&old, None)).await.status,
        StatusCode::UNAUTHORIZED,
        "the replaced value no longer redeems"
    );
    assert_eq!(
        send(&state, redeem(&new, None)).await.status,
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        send(&state, redeem(&new, None)).await.status,
        StatusCode::UNAUTHORIZED,
        "single use"
    );

    let by_bearer = mint(&state, Some(BEARER), None).await;
    assert_eq!(
        by_bearer.status,
        StatusCode::OK,
        "the static bearer may mint"
    );
}

/// E5-T7 (refusals): only a credential that redemption itself accepts may
/// mint a link; a session cannot renew itself past the absolute cap.
#[tokio::test]
async fn only_a_static_admin_credential_may_mint_a_link() {
    let (state, _dir) = fixture().await;
    let before = state.dashboard_bootstrap.peek();

    let standard = mint(&state, Some(STANDARD_KEY), None).await;
    assert_eq!(standard.status, StatusCode::FORBIDDEN, "{}", standard.body);

    let h = issue(&state);
    let by_session = mint(&state, None, Some(&h)).await;
    assert_eq!(
        by_session.status,
        StatusCode::FORBIDDEN,
        "a dashboard session may not mint a link: {}",
        by_session.body
    );
    assert_eq!(
        state.dashboard_bootstrap.peek(),
        before,
        "a refused mint changes nothing"
    );
}

/// A gateway bound to a network address cannot hand out a link: redemption
/// needs a loopback peer, so the link could never open.
#[tokio::test]
async fn no_link_is_minted_for_a_network_bind() {
    let (state, _dir) = fixture().await;
    let mut running = (*state.live_config.get()).clone();
    running.server.host = "10.0.0.5".to_string();
    let state = with_running(state, running);
    let before = state.dashboard_bootstrap.peek();
    let out = mint(&state, Some(ADMIN_KEY), None).await;
    assert_eq!(out.status, StatusCode::CONFLICT, "{}", out.body);
    assert_eq!(state.dashboard_bootstrap.peek(), before, "nothing re-armed");
}

/// A wildcard bind, in any spelling, mints a loopback link a browser here can
/// open; `localhost` keeps its name.
#[tokio::test]
async fn a_wildcard_bind_mints_a_loopback_link() {
    for (bind, host) in [
        ("0.0.0.0", "127.0.0.1"),
        ("::", "[::1]"),
        ("0:0:0:0:0:0:0:0", "[::1]"),
        ("localhost", "localhost"),
    ] {
        let (state, _dir) = fixture().await;
        let mut running = (*state.live_config.get()).clone();
        running.server.host = bind.to_string();
        let state = with_running(state, running);
        let out = mint(&state, Some(ADMIN_KEY), None).await;
        assert_eq!(out.status, StatusCode::OK, "{bind}: {}", out.body);
        let link = out.json()["link"].as_str().unwrap_or_default().to_string();
        assert!(
            link.starts_with(&format!("http://{host}:")),
            "{bind}: {link}"
        );
    }
}

/// Session limits apply on reload, so a reload that changes only them is not
/// reported as waiting for a restart; any other `auth` change still is.
#[test]
fn session_limits_are_not_reported_as_restart_only() {
    let live = crate::config_reload::LiveConfig::new(crate::config::Config::default());
    let mut wanted = crate::config::Config::default();
    wanted.auth.dashboard_session.idle_timeout_secs = 600;
    live.set(wanted.clone());
    assert!(
        !live.pending_restart_fields().contains(&"auth"),
        "{:?}",
        live.pending_restart_fields()
    );
    wanted.auth.enabled = true;
    live.set(wanted);
    assert!(live.pending_restart_fields().contains(&"auth"));
}

/// A reload that edits the restart-only listener fields changes nothing about
/// the link: it names the address and scheme this process actually serves.
#[tokio::test]
async fn the_link_names_the_running_listener_not_a_pending_reload() {
    let (state, _dir) = fixture().await;
    let port = state.live_config.running().server.port;
    reload(&state, |c| {
        c.server.host = "10.0.0.5".to_string();
        c.server.port = port.wrapping_add(1);
        c.mtls.enabled = true;
    });
    let out = mint(&state, Some(ADMIN_KEY), None).await;
    assert_eq!(out.status, StatusCode::OK, "{}", out.body);
    let link = out.json()["link"].as_str().unwrap_or_default().to_string();
    assert!(
        link.starts_with(&format!("http://127.0.0.1:{port}/dashboard?bootstrap=")),
        "{link}"
    );
}

/// Adding an HTTPS `public_url` by reload marks new cookies `Secure`, and
/// removing it stops, so a link minted over plain HTTP still signs in.
#[tokio::test]
async fn cookie_security_follows_a_reloaded_public_url() {
    let (state, _dir) = fixture().await;
    // Built once, before the reloads, as the server builds it at startup.
    let router = create_router(Arc::clone(&state));
    reload(&state, |c| {
        c.server.public_url = Some("https://gw.example".to_string());
    });
    let value = state.dashboard_bootstrap.peek().expect("startup value");
    let out = send_to(router.clone(), redeem(&value, None)).await;
    assert!(out.set_cookie().contains("Secure"), "{}", out.set_cookie());

    reload(&state, |c| c.server.public_url = None);
    let link = send_to(
        router.clone(),
        request("POST", LINK, None, Some(ADMIN_KEY), false),
    )
    .await;
    assert_eq!(link.status, StatusCode::OK, "{}", link.body);
    let value = bootstrap_value(link.json()["link"].as_str().unwrap_or_default());
    let out = send_to(router, redeem(&value, None)).await;
    assert_eq!(out.status, StatusCode::SEE_OTHER, "{}", out.body);
    assert!(!out.set_cookie().contains("Secure"), "{}", out.set_cookie());
}
