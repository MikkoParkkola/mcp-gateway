// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The redirect rule of every remote (`https://`) OIDC fetch: discovery and
//! JWKS (MIK-8281).

/// A redirect from an `https://` fetch may only move to `https://`.
pub(super) fn remote_hop_allowed(next: &url::Url) -> bool {
    next.scheme() == "https"
}

/// The redirect policy of every remote (`https://`) OIDC fetch; one value,
/// so a test drives the policy production uses.
pub(super) fn remote_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() > 5 {
            attempt.error("OIDC fetch exceeded 5 redirects")
        } else if remote_hop_allowed(attempt.url()) {
            attempt.follow()
        } else {
            attempt.error("OIDC refuses a redirect to a non-HTTPS URL")
        }
    })
}
