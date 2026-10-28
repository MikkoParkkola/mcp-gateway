// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The redirect policy of the transport's HTTP client: hop cap, the backend's
//! destination policy, and same-origin.

use url::Url;

use super::{same_origin, sanitize_url_for_diagnostics};
use crate::security::ssrf::{DestinationPolicy, RedirectDecision};

/// Decide whether to follow a single redirect on the SSE/message client.
///
/// Three guards, each of which a hop must clear:
/// 1. **Hop cap** — five redirects followed, matching the prior policy.
/// 2. **SSRF** — the target must not resolve to an internal/metadata range
///    ([`DestinationPolicy::check_configured_url`]).
/// 3. **Same-origin** — the target must share the base URL's origin. The SSE
///    message POST carries the per-user `Authorization: Bearer <assertion>`
///    (MIK-6704); without this guard a legitimate same-origin backend could
///    answer with `30x Location: https://evil.example/…` — a *public* host
///    that clears the SSRF check — and reqwest would replay the bearer
///    cross-origin, defeating the same-origin guard `resolve_message_url`
///    added. MCP message endpoints are same-origin by spec, so this rejects
///    nothing legitimate.
#[cfg(test)]
pub(super) fn evaluate_redirect(
    base: &Url,
    target: &Url,
    previous_hops: usize,
) -> RedirectDecision {
    evaluate_redirect_for(DestinationPolicy::Public, base, target, previous_hops)
}

/// [`evaluate_redirect`] under the backend's policy: a backend listed in
/// `security.hardened.private_backends` may follow a hop to an address its
/// policy allows; every other backend keeps the full URL validation.
pub(super) fn evaluate_redirect_for(
    destination: DestinationPolicy,
    base: &Url,
    target: &Url,
    previous_hops: usize,
) -> RedirectDecision {
    if crate::security::ssrf::hop_budget_spent(previous_hops) {
        return RedirectDecision::Stop;
    }
    match destination.check_configured_url(target.as_str()) {
        // The bare message, so the refusal still reads `SSRF blocked`.
        Err(crate::Error::Protocol(m)) => return RedirectDecision::Reject(m),
        Err(e) => return RedirectDecision::Reject(e.to_string()),
        Ok(()) => {}
    }
    if !same_origin(base, target) {
        return RedirectDecision::Reject(format!(
            "redirect target is cross-origin to the transport base URL; \
             refusing to replay per-user credentials to a different origin \
             (base={}, target={})",
            sanitize_url_for_diagnostics(base.as_str()),
            sanitize_url_for_diagnostics(target.as_str())
        ));
    }
    RedirectDecision::Follow
}

/// Whether the gateway's HTTP transport would follow this redirect: a
/// response with `status` from `base` pointing at `target`, for the backend
/// `backend_name` under `config`. One hop only, as `doctor` sees it; the
/// chain after it is not followed here.
///
/// The verdict is [`evaluate_redirect_for`] under the backend's own
/// destination policy ([`DestinationPolicy::for_backend`]), plus the statuses
/// reqwest follows at all (301, 302, 303, 307, 308; any other 3xx is returned
/// as the final response). Public only for the binary's `doctor` command, so
/// that it reports the gateway's decision instead of a copy of it; not a
/// stable API.
#[doc(hidden)]
#[must_use]
pub fn transport_follows_redirect(
    config: &crate::config::Config,
    backend_name: &str,
    status: u16,
    base: &Url,
    target: &Url,
) -> bool {
    if !matches!(status, 301 | 302 | 303 | 307 | 308) {
        return false;
    }
    let listed = config
        .security
        .hardened
        .private_backends
        .iter()
        .any(|name| name == backend_name);
    let policy = DestinationPolicy::for_posture(config.security.posture).for_backend(listed);
    evaluate_redirect_for(policy, base, target, 0) == RedirectDecision::Follow
}
