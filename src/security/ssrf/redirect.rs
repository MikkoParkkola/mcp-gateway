// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Redirect-chain SSRF re-validation policy.
//!
//! Redirect chains are an SSRF bypass vector: an initial request to a
//! public URL returns a 30x redirect to an internal address.  Every hop
//! in the chain must pass the SSRF check before the gateway follows it.

use super::SsrfDenied;
use super::validate_url_not_ssrf;

/// Maximum number of redirects followed before a fetch is abandoned.
pub(crate) const MAX_REDIRECT_HOPS: usize = 5;

/// Decision for a single redirect hop, extracted from the redirect policy so
/// its fail-closed behavior is directly unit-testable without standing up a
/// live server (the initial-URL SSRF guard rejects any loopback test target
/// before a redirect could ever fire).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RedirectDecision {
    /// Too many hops — stop following (treated as a non-redirect response).
    Stop,
    /// Next hop is refused: abort with this message.
    Reject(String),
    /// Next hop is safe — follow it.
    Follow,
}

/// Whether a redirect with `previous` URLs already visited is past the budget. reqwest records the previous URL before asking, so on redirect k `previous == k`: `>` follows exactly `MAX_REDIRECT_HOPS` redirects and refuses the next. (MIK-8660 seam)
pub(crate) fn hop_budget_spent(previous: usize) -> bool {
    previous > MAX_REDIRECT_HOPS
}

/// Decide whether a redirect hop to `next_url` may be followed. Re-validates
/// every hop against the SSRF deny list so a public URL cannot redirect into
/// an internal address (DNS-rebinding / open-redirect SSRF). Shared by the
/// `OpenAPI` converter (`convert_url`) and the Web-UI spec importer
/// (`fetch_spec`) so both fetch paths enforce one policy.
pub(crate) fn redirect_decision(previous_hops: usize, next_url: &str) -> RedirectDecision {
    if hop_budget_spent(previous_hops) {
        return RedirectDecision::Stop;
    }
    match validate_url_not_ssrf(next_url) {
        Err(crate::Error::Protocol(m)) => RedirectDecision::Reject(m),
        Err(e) => RedirectDecision::Reject(e.to_string()),
        Ok(()) => RedirectDecision::Follow,
    }
}

/// Refuse a redirect hop as a destination-policy refusal. Typed
/// [`SsrfDenied`], so a send site maps it to `-32600 SSRF blocked`
/// ([`super::ssrf_denial`]): a policy answer no retry or fallback walks past,
/// not a transport fault. Every redirect closure refusing a destination goes
/// through here.
pub(crate) fn refuse_hop(
    attempt: reqwest::redirect::Attempt<'_>,
    reason: String,
) -> reqwest::redirect::Action {
    attempt.error(SsrfDenied::new(reason))
}

/// SSRF re-validating redirect policy shared by the spec fetch paths. (MIK-8660 seam)
pub(crate) fn ssrf_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        match redirect_decision(attempt.previous().len(), attempt.url().as_str()) {
            RedirectDecision::Stop => attempt.stop(),
            RedirectDecision::Reject(m) => refuse_hop(attempt, m),
            RedirectDecision::Follow => attempt.follow(),
        }
    })
}

#[cfg(test)]
#[path = "redirect_policy_scan_tests.rs"]
mod redirect_policy_scan;

// MIK-8660 T1e: reqwest's `previous()` already holds the first URL, so the
// budget check must be `>`: a `>=` follows one redirect fewer than
// MAX_REDIRECT_HOPS, which is what every site did before.
#[cfg(test)]
mod hop_budget_tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn a_policy_on_the_hop_budget_follows_max_redirect_hops() {
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        let app = axum::Router::new().route(
            "/{n}",
            axum::routing::get(move |axum::extract::Path(n): axum::extract::Path<usize>| {
                counter.fetch_add(1, Ordering::SeqCst);
                async move { axum::response::Redirect::temporary(&format!("/{}", n + 1)) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move { axum::serve(listener, app).await });
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::custom(|a| {
                if super::hop_budget_spent(a.previous().len()) {
                    a.stop()
                } else {
                    a.follow()
                }
            }))
            .build()
            .expect("client");
        tokio::time::timeout(
            crate::test_wait::HANG_BOUND,
            client.get(format!("http://{addr}/0")).send(),
        )
        .await
        .expect("bounded")
        .expect("the chain ends in a 3xx");
        // One initial request plus one per redirect followed.
        assert_eq!(hits.load(Ordering::SeqCst) - 1, super::MAX_REDIRECT_HOPS);
    }

    #[test]
    fn redirect_decision_follows_the_fifth_redirect_and_stops_the_sixth() {
        assert_eq!(
            super::redirect_decision(5, "https://1.1.1.1/x"),
            super::RedirectDecision::Follow
        );
        assert_eq!(
            super::redirect_decision(6, "https://1.1.1.1/x"),
            super::RedirectDecision::Stop
        );
    }
}
