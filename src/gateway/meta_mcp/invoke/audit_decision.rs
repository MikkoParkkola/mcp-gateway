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
pub(crate) fn note_refusal(
    kind: crate::security::decision_record::DecisionKind,
    rule_id: Option<String>,
) {
    note_decision(|noted| noted.refused(kind, rule_id));
}

/// Note an explicit allow; the earliest in check order wins.
pub(crate) fn note_allow(
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

/// Run a request's route stage with a decision scope of its own.
pub(crate) async fn with_route_scope<F: std::future::Future>(future: F) -> F::Output {
    ROUTE
        .scope(
            RefCell::new(crate::security::decision_record::Noted::default()),
            future,
        )
        .await
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
    /// The decision object for this call's record: a cache hit ran no gate,
    /// so it was not decided again.
    pub(crate) fn decided(&self, meta: &MetaMcp) -> crate::security::decision_record::Decision {
        use crate::security::decision_record::{Decided, Noted};
        let live = meta.live_config();
        if self.cached {
            Noted::not_redecided().decision(Decided::CacheHitNotRedecided, live.as_deref())
        } else {
            self.decision.decision(Decided::Fresh, live.as_deref())
        }
    }
}
