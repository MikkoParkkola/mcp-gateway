// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A refused dashboard link answers the same whether or not the guess was the
//! live value, so a refusal never tells a caller they guessed right. The value
//! is compared in one place, in constant time, and an empty slot still pays
//! for the compare.

use axum::http::StatusCode;

use super::*;

const LOCAL: [u8; 4] = [127, 0, 0, 1];
const REMOTE: [u8; 4] = [198, 51, 100, 7];

/// A wrong value of the live value's length (43 base64url characters), so a
/// compare that stopped at a length mismatch could not pass these rows.
static GUESS: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| "B".repeat(43));

/// Status, every header (sorted) and the body: what a caller can observe.
fn observe(
    state: &AuthState,
    value: &str,
    peer: [u8; 4],
) -> (StatusCode, Vec<(String, String)>, String) {
    let request = Request::builder()
        .uri(format!("/dashboard?bootstrap={value}"))
        .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            peer, 12345,
        ))))
        .body(Body::empty())
        .expect("request builds");
    let response = try_dashboard_bootstrap(state, state.live_config.generation().auth(), &request)
        .expect("a bootstrap link is always answered here");
    let status = response.status();
    let mut headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    headers.sort();
    let body = futures::executor::block_on(axum::body::to_bytes(response.into_body(), usize::MAX))
        .expect("body");
    (status, headers, String::from_utf8_lossy(&body).into_owned())
}

/// R8: refused from elsewhere, the live value and a wrong one look the same,
/// though only the live value is spent.
#[test]
fn r8_a_refusal_from_elsewhere_is_identical_for_the_live_value_and_a_guess() {
    let (live_state, printed) = bootstrap_state(Some("bearer"), vec![]);
    let (guess_state, guess_printed) = bootstrap_state(Some("bearer"), vec![]);
    let live = observe(&live_state, &printed, REMOTE);
    let guess = observe(&guess_state, &GUESS, REMOTE);
    assert_eq!(
        live, guess,
        "the refusal must not say whether the guess was live"
    );
    assert_eq!(
        observe(&live_state, &printed, LOCAL).0,
        StatusCode::UNAUTHORIZED,
        "the live value was spent"
    );
    assert_eq!(
        observe(&guess_state, &guess_printed, LOCAL).0,
        StatusCode::SEE_OTHER,
        "a wrong guess spends nothing"
    );
}

/// R9: on a clock before 1970 the live value and a wrong one look the same,
/// and the live value is kept for when the clock is set.
#[test]
fn r9_a_clock_refusal_is_identical_for_the_live_value_and_a_guess() {
    let (state, printed) = bootstrap_state(Some("bearer"), vec![]);
    {
        let _clock = crate::clock::test_clock::before_epoch();
        let live = observe(&state, &printed, LOCAL);
        let guess = observe(&state, &GUESS, LOCAL);
        assert_eq!(
            live, guess,
            "the clock refusal must not say whether the guess was live"
        );
    }
    assert_eq!(
        observe(&state, &printed, LOCAL).0,
        StatusCode::SEE_OTHER,
        "the live value was kept"
    );
}

/// R14: an empty slot still runs the constant-time compare, so whether a live
/// link is outstanding cannot be timed.
#[test]
fn r14_an_empty_slot_still_runs_the_compare() {
    let (state, printed) = bootstrap_state(Some("bearer"), vec![]);
    assert_eq!(
        observe(&state, &printed, LOCAL).0,
        StatusCode::SEE_OTHER,
        "spends the live value"
    );
    let before = crate::gateway::auth::dashboard::ct_compares_for_test();
    let _ = observe(&state, &GUESS, LOCAL);
    assert!(
        crate::gateway::auth::dashboard::ct_compares_for_test() > before,
        "the empty slot skipped the compare"
    );
}

/// R14 (code): with no handoff code outstanding, a code still pays for the
/// compare.
#[cfg(feature = "webui")]
#[test]
fn r14_an_empty_code_slot_still_runs_the_compare() {
    let (state, _) = bootstrap_state(Some("bearer"), vec![]);
    let before = crate::gateway::auth::dashboard::ct_compares_for_test();
    assert!(
        state
            .dashboard_bootstrap
            .take_handoff(
                &GUESS,
                crate::gateway::auth::Now::read(),
                &crate::gateway::auth::ResolvedAuthConfig::from_config(
                    &crate::config::AuthConfig::default(),
                    crate::gateway::record_principal::TEST_RECORD_KEY,
                )
            )
            .is_none()
    );
    assert!(
        crate::gateway::auth::dashboard::ct_compares_for_test() > before,
        "the empty code slot skipped the compare"
    );
}

/// R13: no plain `==`/`!=` compares a candidate with the secret, and no
/// printed value feeds a comparison. The constant-time compare is the only one.
#[test]
fn r13_no_plain_compare_of_the_secret_remains() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/gateway");
    let mut hits = Vec::new();
    for file in ["auth_bootstrap.rs", "auth_handoff.rs", "auth_dashboard.rs"] {
        let text = std::fs::read_to_string(root.join(file)).expect("source readable");
        for (n, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            let compares = code.contains("==") || code.contains("!=") || code.contains(".eq(");
            let secret =
                code.contains("candidate") || code.contains(".peek()") || code.contains("reveal()");
            if compares && secret {
                hits.push(format!("{file}:{} {}", n + 1, line.trim()));
            }
        }
    }
    assert!(hits.is_empty(), "plain compares of the secret: {hits:#?}");
    // `Secret` has no `==`, so the compiler refuses a plain compare; this scan
    // is the backstop. Its one way out, `reveal()`, serves printing only.
    let dashboard =
        std::fs::read_to_string(root.join("auth_dashboard.rs")).expect("source readable");
    let reveals: Vec<&str> = dashboard
        .lines()
        .filter(|l| {
            l.contains("reveal()") && !l.trim_start().starts_with("//") && !l.contains("fn reveal")
        })
        .collect();
    assert_eq!(
        reveals.len(),
        1,
        "reveal() is for printing the link only: {reveals:#?}"
    );
}

/// R10: without the dashboard there is no hand-off, so an HTTPS `public_url`
/// on this plain-HTTP listener refuses every value as a wrong one: the live
/// value and a guess look the same, nothing is spent, and only the operator's
/// log names the deployment.
#[cfg(not(feature = "webui"))]
#[test]
fn r10_an_https_front_without_a_handoff_answers_every_value_as_a_wrong_one() {
    let (mut state, printed) = bootstrap_state(Some("bearer"), vec![]);
    let mut config = crate::config::Config::default();
    config.server.public_url = Some("https://gw.example".to_string());
    state.live_config = std::sync::Arc::new(crate::config_reload::LiveConfig::with_auth(
        config,
        std::sync::Arc::clone(state.live_config.generation().auth()),
    ));
    let live = observe(&state, &printed, LOCAL);
    let guess = observe(&state, &GUESS, LOCAL);
    assert_eq!(
        live, guess,
        "the deployment refusal must not say whether the guess was live"
    );
    assert_eq!(live.0, StatusCode::UNAUTHORIZED);
    assert!(
        state.dashboard_bootstrap.peek().is_some(),
        "nothing was spent"
    );
}

/// R7 (B): with no admin credential configured, even a browser navigation
/// keeps today's 401 and its words. The router fixtures always configure a
/// credential, so this is pinned at the function that decides the refusal.
#[test]
fn r7b_no_admin_credential_keeps_its_401_for_a_browser() {
    let (state, printed) = bootstrap_state(None, vec![]);
    let request = Request::builder()
        .uri(format!("/dashboard?bootstrap={printed}"))
        .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            LOCAL, 12345,
        ))))
        .header("sec-fetch-mode", "navigate")
        .header("sec-fetch-dest", "document")
        .body(Body::empty())
        .expect("request builds");
    let response = try_dashboard_bootstrap(&state, state.live_config.generation().auth(), &request)
        .expect("answered");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        response
            .headers()
            .get(axum::http::header::LOCATION)
            .is_none()
    );
    let body = futures::executor::block_on(axum::body::to_bytes(response.into_body(), usize::MAX))
        .expect("body");
    assert!(
        String::from_utf8_lossy(&body).contains("No admin credential is configured."),
        "{}",
        String::from_utf8_lossy(&body)
    );
    assert!(
        state.dashboard_bootstrap.peek().is_some(),
        "nothing was spent"
    );
}
