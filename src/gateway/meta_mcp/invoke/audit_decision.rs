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

/// Note an explicit allow; the earliest in check order wins.
#[expect(
    dead_code,
    reason = "wired with the explicit-allow rule ids, this PR; removed before push"
)]
pub(crate) fn note_allowed_by(
    kind: crate::security::decision_record::DecisionKind,
    rule_id: Option<String>,
) {
    note_decision(|noted| noted.allowed(kind, rule_id));
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

/// The check noted as refusing so far: the dispatch's, else the route
/// stage's. Read, not taken.
pub(crate) fn current_refusal_kind() -> Option<crate::security::decision_record::DecisionKind> {
    super::NOTES
        .try_with(|notes| notes.borrow().decision.refusal_kind())
        .ok()
        .flatten()
        .or_else(|| {
            ROUTE
                .try_with(|route| route.borrow().refusal_kind())
                .ok()
                .flatten()
        })
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
