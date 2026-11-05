// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The fixtures with the production firewall installed, by what they arm
//! besides it. Moved out of the shared fixture to keep it under the
//! file-size ceiling.

use super::*;

/// [`fixture`] with the production firewall installed on both the router and
/// the Meta-MCP (request scanning, response scanning, credential redaction),
/// as `server/mod.rs` wires it.
#[cfg(feature = "firewall")]
pub(crate) async fn fixture_firewalled(answer: Answer) -> Fx {
    fixture_inner(answer, true, |meta| meta).await
}

/// [`fixture_firewalled`] with `build` arming the `MetaMcp` (for
/// example a key budget on the firewalled fixture, for the give-back rows).
#[cfg(feature = "firewall")]
pub(crate) async fn fixture_firewalled_built(
    answer: Answer,
    build: impl FnOnce(crate::gateway::meta_mcp::MetaMcp) -> crate::gateway::meta_mcp::MetaMcp,
) -> Fx {
    fixture_inner(answer, true, build).await
}

/// [`fixture_firewalled`] with both firewalls writing their audit rows to
/// `audit` (the chokepoint's `dispatch` rows).
#[cfg(feature = "firewall")]
pub(crate) async fn fixture_firewalled_audited(answer: Answer, audit: std::path::PathBuf) -> Fx {
    AUDIT_LOG.with(|a| *a.borrow_mut() = Some(audit));
    let fx = fixture_inner(answer, true, |meta| meta).await;
    AUDIT_LOG.with(|a| *a.borrow_mut() = None);
    fx
}

/// [`fixture_firewalled_audited`], arming the replaced `MetaMcp` with `build`
/// (the route x check matrix's surfaced-name route).
#[cfg(feature = "firewall")]
pub(crate) async fn fixture_firewalled_audited_built(
    answer: Answer,
    audit: std::path::PathBuf,
    build: impl FnOnce(MetaMcp) -> MetaMcp,
) -> Fx {
    AUDIT_LOG.with(|a| *a.borrow_mut() = Some(audit));
    let fx = fixture_inner(answer, true, build).await;
    AUDIT_LOG.with(|a| *a.borrow_mut() = None);
    fx
}

/// [`fixture_firewalled`] with a firewall rule for `read` and a client
/// circuit breaker that opens after one counted failure, so a cell can tell a
/// refusal the gateway excludes from client accounting from one it charges.
#[cfg(feature = "firewall")]
pub(crate) async fn fixture_firewalled_with(
    answer: Answer,
    rule: Option<crate::security::firewall::FirewallAction>,
    breaker: bool,
) -> Fx {
    FIREWALL_RULE.with(|r| r.set(rule));
    CLIENT_BREAKER.with(|b| b.set(breaker));
    let fx = fixture_inner(answer, true, |meta| meta).await;
    FIREWALL_RULE.with(|r| r.set(None));
    CLIENT_BREAKER.with(|b| b.set(false));
    fx
}

/// [`fixture_firewalled_with`], with no breaker, arming the `MetaMcp` with
/// `build` (a redacting rule beside the provenance signers).
#[cfg(feature = "firewall")]
pub(crate) async fn fixture_firewalled_with_built(
    answer: Answer,
    rule: Option<crate::security::firewall::FirewallAction>,
    build: impl FnOnce(MetaMcp) -> MetaMcp,
) -> Fx {
    FIREWALL_RULE.with(|r| r.set(rule));
    let fx = fixture_inner(answer, true, build).await;
    FIREWALL_RULE.with(|r| r.set(None));
    fx
}

/// [`fixture_firewalled_with_built`] with `log` as the state's transparency
/// log; `build` arms the same log on the `MetaMcp`, so both routes record
/// their deliveries in one file.
#[cfg(feature = "firewall")]
pub(crate) async fn fixture_firewalled_logged(
    answer: Answer,
    rule: Option<crate::security::firewall::FirewallAction>,
    log: Arc<crate::security::TransparencyLogger>,
    build: impl FnOnce(MetaMcp) -> MetaMcp,
) -> Fx {
    STATE_LOG.with(|l| *l.borrow_mut() = Some(log));
    let fx = fixture_firewalled_with_built(answer, rule, build).await;
    STATE_LOG.with(|l| *l.borrow_mut() = None);
    fx
}

/// [`fixture_firewalled`] with sequence-anomaly blocking armed: `read` was only
/// ever followed by `other`, so a second `read` in one session scores as a
/// never-seen transition and is blocked.
#[cfg(feature = "firewall")]
pub(crate) async fn fixture_firewalled_anomaly(answer: Answer) -> Fx {
    ANOMALY.with(|a| a.set(true));
    let fx = fixture_inner(answer, true, |meta| meta).await;
    ANOMALY.with(|a| a.set(false));
    fx
}
