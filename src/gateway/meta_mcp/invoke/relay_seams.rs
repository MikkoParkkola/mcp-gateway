// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8113`: seams between plan steps. Two short fields of two steps
//! delivered side by side are text the caller received contiguously; no
//! step receipt holds a fingerprint across them. After the step receipts are
//! kept to the final answer, the answer's value leaves are read in order,
//! each owned by the step that produced it (plan-time provenance, confirmed
//! by the step's receipt keeping the leaf whole), and every fingerprint over
//! text of two or more steps is recorded once for the delivery: under the
//! one contributing source's own identity, or under one composite receipt
//! per set of contributing sources.

use std::cell::RefCell;
use std::future::Future;

tokio::task_local! {
    /// Which member of a plan's decoded answer each plan step produced: (a
    /// JSON pointer into the answer, the step's label).
    static PLAN_MEMBERS: RefCell<Vec<(String, u32)>>;
}

/// Run `delivery` with a record of its plan's answer members.
pub(super) fn scope<F: Future>(delivery: F) -> impl Future<Output = F::Output> {
    PLAN_MEMBERS.scope(RefCell::new(Vec::new()), delivery)
}

/// Note that the member of the plan's decoded answer at `pointer` (RFC 6901)
/// is what the step labelled `label` produced. Only the delivery's own plan
/// notes: a plan run as one step of another names members of an answer the
/// caller never receives as such.
pub(crate) fn note_plan_member(pointer: String, label: u32) {
    if super::PLAN_STEP.try_with(|_| ()).is_ok() {
        return;
    }
    let _ = PLAN_MEMBERS.try_with(|members| members.borrow_mut().push((pointer, label)));
}

/// `key` as one RFC 6901 reference token.
pub(crate) fn pointer_token(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

/// Run `delivery` with a record of plan members and return what it noted
/// (tests only).
#[cfg(test)]
pub(crate) async fn noting_plan_members<F: Future>(delivery: F) -> (F::Output, Vec<(String, u32)>) {
    PLAN_MEMBERS
        .scope(RefCell::new(Vec::new()), async {
            let out = delivery.await;
            (out, PLAN_MEMBERS.with(|m| m.borrow().clone()))
        })
        .await
}

#[cfg(feature = "firewall")]
pub(super) use with_firewall::add_seams;

#[cfg(feature = "firewall")]
#[path = "relay_seams_record.rs"]
mod with_firewall;
