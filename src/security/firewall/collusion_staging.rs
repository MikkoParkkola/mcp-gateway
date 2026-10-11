// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! What one delivery's plan has staged so far (MIK-7992), and for whom
//! (`MIK-8066.BIG.3`, design r5.1 F3).

use std::cell::{Cell, RefCell};

/// A plan delivery's staging state. `baseline` is what the release line has
/// always counted, the receipts' own bytes: it alone decides whether a step is
/// staged whole or capped now, and when a plan's receipts are dropped. `total`
/// adds the fingerprint attachments of steps past the plan bound; it governs
/// only their admission and eviction (F3), so an attachment never changes
/// how a later step is staged.
#[derive(Debug, Default)]
pub(crate) struct PlanStaging {
    baseline: Cell<usize>,
    total: Cell<usize>,
    caller: RefCell<Option<String>>,
}

impl PlanStaging {
    /// A plan whose earlier steps already staged `baseline` bytes (tests only).
    #[cfg(test)]
    pub(crate) fn starting_at(baseline: usize) -> Self {
        let staging = Self::default();
        staging.baseline.set(baseline);
        staging.total.set(baseline);
        staging
    }

    /// The caller the delivery stages for, known once the route has it.
    pub(crate) fn set_caller(&self, key: &str) {
        *self.caller.borrow_mut() = Some(key.to_owned());
    }

    /// The caller the delivery stages for, if set.
    pub(crate) fn caller(&self) -> Option<String> {
        self.caller.borrow().clone()
    }

    /// The receipts' own staged bytes.
    pub(crate) fn baseline(&self) -> usize {
        self.baseline.get()
    }

    /// The receipts plus their fingerprint attachments.
    pub(crate) fn total(&self) -> usize {
        self.total.get()
    }

    /// Charge `bytes` of receipt; a receipt's bytes count toward both.
    pub(super) fn add_baseline(&self, bytes: usize) {
        self.baseline.set(self.baseline.get().saturating_add(bytes));
        self.total.set(self.total.get().saturating_add(bytes));
    }

    /// Charge `bytes` of fingerprint attachments: the total only, so an
    /// attachment never changes how a later step is staged (F3).
    pub(super) fn add_attachment(&self, bytes: usize) {
        self.total.set(self.total.get().saturating_add(bytes));
    }

    /// Marks the delivery's plan drop as counted (`MIK-8094`): past every bound.
    pub(super) fn mark_dropped(&self) -> bool {
        let first = self.baseline.get() != usize::MAX;
        self.baseline.set(usize::MAX);
        self.total.set(usize::MAX);
        first
    }
}

impl super::Firewall {
    /// `MIK-8066.BIG.3`: a plan step capped at staging (past the plan bound,
    /// or over it) keeps fingerprint attachments in place of its text, while
    /// the plan's total room and the sketch store allow. A step that finds no
    /// room is skipped, counted and marked (F5): its holder's refusal names
    /// lost room. A step staged whole keeps the release line's path.
    pub(super) fn attach_big(
        &self,
        mut digest: super::DeliveryDigest,
        (server, tool): (&str, &str),
        result: &serde_json::Value,
        staged: &PlanStaging,
    ) -> super::DeliveryDigest {
        if digest.is_deferred() {
            return digest;
        }
        let (Some(detector), Some(caller)) = (
            self.relay.detector.as_ref().filter(|_| self.config.enabled),
            staged.caller(),
        ) else {
            return digest;
        };
        let source = format!("{server}:{tool}");
        let (leaves, values) = super::delivery_parts(result);
        let joins = super::key_path_joins(result);
        let Some(fps) = self.fps_of_leaves(&leaves, values, &joins) else {
            return digest;
        };
        let room = super::PLAN_STAGED_CAP.saturating_sub(staged.total());
        let Some(big) =
            super::super::collusion::big::BigStep::new(detector, (&source, &caller), &fps, room)
        else {
            return digest;
        };
        staged.add_attachment(big.bytes());
        digest.big = Some(Box::new(big));
        digest
    }
}
