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
    let response =
        try_dashboard_bootstrap(state, &request).expect("a bootstrap link is always answered here");
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
    let guess = observe(&guess_state, "not-the-value", REMOTE);
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
        let guess = observe(&state, "not-the-value", LOCAL);
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
    let before = crate::gateway::auth_dashboard::ct_compares_for_test();
    let _ = observe(&state, "not-the-value", LOCAL);
    assert!(
        crate::gateway::auth_dashboard::ct_compares_for_test() > before,
        "the empty slot skipped the compare"
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
            let compares = code.contains("==") || code.contains("!=");
            if compares && (code.contains("candidate") || code.contains(".peek()")) {
                hits.push(format!("{file}:{} {}", n + 1, line.trim()));
            }
        }
    }
    assert!(hits.is_empty(), "plain compares of the secret: {hits:#?}");
}
