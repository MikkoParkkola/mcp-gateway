// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Redirect-chain SSRF re-validation policy.
//!
//! Redirect chains are an SSRF bypass vector: an initial request to a
//! public URL returns a 30x redirect to an internal address.  Every hop
//! in the chain must pass the SSRF check before the gateway follows it.

use super::SSRF_BLOCKED;
use super::validate_url_not_ssrf;
use crate::Error;
use crate::Result;

/// Validate every URL in a redirect chain against SSRF rules.
///
/// # Arguments
///
/// * `chain` — ordered slice of URL strings representing the redirect path,
///   starting with the initial request URL and ending with the final URL.
///
/// # Errors
///
/// Returns `Error::Protocol` with the offending hop number and URL if any
/// hop targets a blocked range.
pub fn validate_redirect_chain(chain: &[&str]) -> Result<()> {
    for (i, url) in chain.iter().enumerate() {
        validate_url_not_ssrf(url)
            .map_err(|e| Error::Protocol(format!("{SSRF_BLOCKED} at redirect hop {i}: {e}")))?;
    }
    Ok(())
}

/// Maximum number of redirect hops followed before a fetch is abandoned.
pub(crate) const MAX_REDIRECT_HOPS: usize = 5;

/// Decision for a single redirect hop, extracted from the redirect policy so
/// its fail-closed behavior is directly unit-testable without standing up a
/// live server (the initial-URL SSRF guard rejects any loopback test target
/// before a redirect could ever fire).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RedirectDecision {
    /// Too many hops — stop following (treated as a non-redirect response).
    Stop,
    /// Next hop targets an SSRF-blocked address — abort with this message.
    Block(String),
    /// Next hop is safe — follow it.
    Follow,
}

/// Decide whether a redirect hop to `next_url` may be followed. Re-validates
/// every hop against the SSRF deny list so a public URL cannot redirect into
/// an internal address (DNS-rebinding / open-redirect SSRF). Shared by the
/// `OpenAPI` converter (`convert_url`) and the Web-UI spec importer
/// (`fetch_spec`) so both fetch paths enforce one policy.
pub(crate) fn redirect_decision(previous_hops: usize, next_url: &str) -> RedirectDecision {
    if previous_hops >= MAX_REDIRECT_HOPS {
        return RedirectDecision::Stop;
    }
    match validate_url_not_ssrf(next_url) {
        Err(e) => RedirectDecision::Block(e.to_string()),
        Ok(()) => RedirectDecision::Follow,
    }
}

#[cfg(test)]
#[path = "redirect_policy_scan_tests.rs"]
mod redirect_policy_scan;

// T1e (MIK-8660, lane-written red probe): reqwest's `previous()` already holds
// the first URL, so `>= MAX_REDIRECT_HOPS` follows one hop fewer than the doc.
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
                if a.previous().len() >= super::MAX_REDIRECT_HOPS {
                    a.stop()
                } else {
                    a.follow()
                }
            }))
            .build()
            .expect("client");
        client
            .get(format!("http://{addr}/0"))
            .send()
            .await
            .expect("the chain ends in a 3xx");
        // One initial request plus one per redirect followed.
        assert_eq!(hits.load(Ordering::SeqCst) - 1, super::MAX_REDIRECT_HOPS);
    }
}
