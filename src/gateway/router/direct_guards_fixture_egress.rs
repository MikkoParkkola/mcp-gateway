// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The egress matrix's hooks into the shared fixture (design
//! `2026-10-08-one-egress-scan.md`): a planted transport in place of the
//! scripted backend, a Warn rule, an audit log, an inspection-only gateway.

use std::sync::Arc;

use super::{AUDIT_LOG, Answer, FIREWALL_RULE, Fx, META_FIREWALL, TRANSPORT, fixture_inner};
use crate::transport::Transport;

/// [`super::fixture_firewalled_with`] with `transport` answering for both backends
/// in place of the scripted one (the egress matrix's planted backend).
#[cfg(feature = "firewall")]
pub(crate) async fn fixture_firewalled_on(
    transport: Arc<dyn Transport>,
    rule: Option<crate::security::firewall::FirewallAction>,
) -> Fx {
    TRANSPORT.with(|t| *t.borrow_mut() = Some(transport));
    FIREWALL_RULE.with(|r| r.set(rule));
    let fx = fixture_inner(Answer::Ok, true, |meta| meta).await;
    FIREWALL_RULE.with(|r| r.set(None));
    TRANSPORT.with(|t| *t.borrow_mut() = None);
    fx
}

/// [`fixture_firewalled_on`] with both firewalls writing their verdicts to
/// the audit log at `audit`.
#[cfg(feature = "firewall")]
pub(crate) async fn fixture_audited_on(
    transport: Arc<dyn Transport>,
    audit: std::path::PathBuf,
) -> Fx {
    AUDIT_LOG.with(|a| *a.borrow_mut() = Some(audit));
    let fx = fixture_firewalled_on(transport, None).await;
    AUDIT_LOG.with(|a| *a.borrow_mut() = None);
    fx
}

/// `transport` behind no firewall, with response inspection in action mode:
/// only the content inspection can withhold what it answers.
pub(crate) async fn fixture_inspecting_on(transport: Arc<dyn Transport>) -> Fx {
    TRANSPORT.with(|t| *t.borrow_mut() = Some(transport));
    let fx = fixture_inner(Answer::Ok, false, |mut meta| {
        meta.enable_response_inspection_action_mode();
        meta
    })
    .await;
    TRANSPORT.with(|t| *t.borrow_mut() = None);
    fx
}

/// The firewall the last firewalled fixture on this thread gave its Meta-MCP
/// (the router holds its own, on `state.firewall`).
#[cfg(feature = "firewall")]
pub(crate) fn meta_firewall() -> Option<Arc<crate::security::firewall::Firewall>> {
    META_FIREWALL.with(|f| f.borrow().clone())
}
