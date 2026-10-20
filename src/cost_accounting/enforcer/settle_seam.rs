// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test seam for MIK-7903: check a budget from inside a settle on this
//! thread, after it has let the ledger go and before it returns. The caller
//! still holds its admission there, so a path that settled no reservation
//! shows the call twice (spent and still held) and a path that did, once.

use std::sync::{Arc, Mutex};

use super::{AFTER_SETTLE, BudgetEnforcer};

/// The answer of a check made inside a settle.
pub(crate) struct SettleCheck(Arc<Mutex<Option<bool>>>);

impl SettleCheck {
    /// Whether the check admitted its call. Panics if no settle ran on this
    /// thread after the check was armed.
    pub(crate) fn admitted(self) -> bool {
        let answer = *self.0.lock().unwrap();
        answer.expect("no settle ran on this thread")
    }
}

/// What the armed check asks about.
type Target = (Arc<BudgetEnforcer>, String, Option<String>);

impl BudgetEnforcer {
    /// Arm a check for `tool` and `key` inside the next settle on this thread.
    pub(crate) fn check_inside_next_settle(
        self: &Arc<Self>,
        tool: &str,
        key: Option<&str>,
    ) -> SettleCheck {
        self.check_inside_settle_after(0, tool, key)
    }

    /// As [`Self::check_inside_next_settle`], but inside the settle that
    /// follows `skip` others on this thread.
    pub(crate) fn check_inside_settle_after(
        self: &Arc<Self>,
        skip: usize,
        tool: &str,
        key: Option<&str>,
    ) -> SettleCheck {
        let slot: Arc<Mutex<Option<bool>>> = Arc::default();
        let target = (Arc::clone(self), tool.to_owned(), key.map(str::to_owned));
        arm(skip, target, Arc::clone(&slot));
        SettleCheck(slot)
    }
}

/// Set the hook; a skipped settle re-arms it for the next one.
fn arm(skip: usize, target: Target, slot: Arc<Mutex<Option<bool>>>) {
    AFTER_SETTLE.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            if skip > 0 {
                arm(skip - 1, target, slot);
                return;
            }
            let (enforcer, tool, key) = target;
            let admitted = enforcer.check(&tool, key.as_deref()).allowed;
            *slot.lock().unwrap() = Some(admitted);
        }));
    });
}
