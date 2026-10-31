// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which check decided a call (MIK-8914.API2A.1): noted by the gates, read by
//! the record writers.

use std::cell::RefCell;

use super::DispatchNotes;
use crate::gateway::meta_mcp::MetaMcp;

/// Note the gate that refused this call; the first refusal wins. Inside a
/// dispatch it is the call's; before one (the router's pre-check) it is the
/// request route stage's.
pub(crate) fn note_refused_by(
    kind: crate::security::decision_record::DecisionKind,
    rule_id: Option<String>,
) {
    note_decision(|noted| noted.refused(kind, rule_id));
}

/// A managed account's answer to an upstream 401, noted when it turns the
/// call into an account refusal (a reconnect): the caller's identity standing
/// (MIK-8914.API2A.13), which no kind names yet. The upstream's own rejection,
/// relayed, is the backend's answer and is not noted.
pub(crate) async fn after_upstream_401(
    managed: &crate::personal_accounts::ManagedLease,
    error: crate::Error,
) -> crate::Error {
    let answer = managed.after_upstream_401(error).await;
    if crate::personal_accounts::refusal::marked(&answer).is_some() {
        note_refused_by(
            crate::security::decision_record::DecisionKind::Unrecorded,
            None,
        );
    }
    answer
}

/// A refusal raised at the send (a lent-only slot the call brought no
/// credential for, a lent credential failing its per-send recheck), noted
/// wherever a sent call's error is settled: it is about the caller's own
/// credential, which no decision kind names yet, so it is noted unrecorded,
/// as an account's answer to a 401 is, and the record says refused. The
/// first noted kind wins, so a gate that refused earlier keeps its own.
pub(crate) fn note_send_refusal(error: &crate::Error) {
    if matches!(error, crate::Error::Forbidden { .. }) {
        note_refused_by(
            crate::security::decision_record::DecisionKind::Unrecorded,
            None,
        );
    }
}

fn note_decision(f: impl FnOnce(&mut crate::security::decision_record::Noted)) {
    if super::NOTES.try_with(|_| ()).is_ok() {
        super::note(|notes| f(&mut notes.decision));
    } else {
        let _ = ROUTE.try_with(|route| f(&mut route.borrow_mut()));
    }
}

tokio::task_local! {
    /// The router pre-check's decision for this request, before any dispatch.
    static ROUTE: RefCell<crate::security::decision_record::Noted>;
}

/// The check noted as refusing so far: the dispatch's, read (it is this
/// call's), else the route stage's, taken, so the next target of the same
/// request starts from nothing and never inherits this one's check.
pub(crate) fn take_refusal_kind() -> Option<crate::security::decision_record::DecisionKind> {
    // Taken first, always: a dispatch that noted its own check must not
    // leave the route's note for the next target.
    let route = take_route_noted().refusal_kind();
    super::NOTES
        .try_with(|notes| notes.borrow().decision.refusal_kind())
        .ok()
        .flatten()
        .or(route)
}

/// Run a request's route stage with a decision scope of its own.
///
/// A plain `fn`, not an `async fn`: an async wrapper's state holds `future`
/// twice (as its argument, then inside the scope), which doubled the boxed
/// stdio `tools/call` dispatch.
pub(crate) fn with_route_scope<F: std::future::Future>(
    future: F,
) -> impl std::future::Future<Output = F::Output> {
    ROUTE.scope(
        RefCell::new(crate::security::decision_record::Noted::default()),
        future,
    )
}

/// The route stage's decision so far, taken: the next target of the same
/// request starts from nothing, so its record never names another target's
/// check. Empty outside a route scope.
pub(crate) fn take_route_noted() -> crate::security::decision_record::Noted {
    ROUTE
        .try_with(|route| std::mem::take(&mut *route.borrow_mut()))
        .unwrap_or_default()
}

impl DispatchNotes {
    /// The check the request's memo kept for a withheld target: it names
    /// the refusal the record's outcome code came from.
    pub(crate) fn refused_by_memo(&mut self, kind: crate::security::decision_record::DecisionKind) {
        self.decision.refused_by_memo(kind);
    }

    /// The decision object for this call's record: a cache hit ran no gate,
    /// so it was not decided again.
    pub(crate) fn decided(
        &self,
        meta: &MetaMcp,
        outcome: crate::security::audit::AuditOutcome,
    ) -> crate::security::decision_record::Decision {
        use crate::security::decision_record::{Decided, Noted};
        let live = meta.live_config();
        if self.cached {
            Noted::not_redecided().decision(
                Decided::CacheHitNotRedecided,
                crate::security::decision_record::Refused::No,
                live.as_deref(),
            )
        } else {
            self.decision.decision(
                Decided::Fresh,
                crate::security::decision_record::Refused::of(outcome),
                live.as_deref(),
            )
        }
    }
}
