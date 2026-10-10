// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The redirect rule of every remote (`https://`) OIDC fetch, discovery and
//! JWKS alike: no hop off the fetched URL's origin (MIK-8281).

/// A redirect may only stay on the origin (scheme, host, port) of the URL
/// first fetched. `Url::origin` fills in the scheme's default port, so
/// `https://idp` and `https://idp:443` count as one origin.
pub(super) fn remote_hop_allowed(fetched: &url::Url, next: &url::Url) -> bool {
    fetched.origin() == next.origin()
}

/// The redirect policy of every remote (`https://`) OIDC fetch; one value,
/// so a test drives the policy production uses.
pub(super) fn remote_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        let allowed = attempt
            .previous()
            .first()
            .is_some_and(|fetched| remote_hop_allowed(fetched, attempt.url()));
        if attempt.previous().len() > 5 {
            attempt.error("OIDC fetch exceeded 5 redirects")
        } else if allowed {
            attempt.follow()
        } else {
            attempt.error("OIDC refuses a redirect off the fetched URL's origin")
        }
    })
}
