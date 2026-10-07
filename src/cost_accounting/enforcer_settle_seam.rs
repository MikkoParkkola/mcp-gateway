// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test seam for MIK-7903: start a competing check inside the next settle on
//! this thread, after the spend is added and before the ledger lock is let go.

use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use super::{AFTER_SPEND_ADDED, BudgetEnforcer};

/// A check started inside a settle. It waits for the ledger, so it sees the
/// settled call exactly as every later check will.
pub(crate) struct CompetingCheck(Arc<Mutex<Option<JoinHandle<bool>>>>);

impl CompetingCheck {
    /// Whether the competing check admitted its call. Panics if no settle ran
    /// on this thread after the check was armed.
    pub(crate) fn admitted(self) -> bool {
        let handle = self.0.lock().unwrap().take();
        handle
            .expect("no settle ran on this thread")
            .join()
            .unwrap()
    }
}

impl BudgetEnforcer {
    /// Arm a check for `tool` and `key` that runs, on another thread, inside
    /// the next settle on this thread.
    pub(crate) fn check_during_next_settle(
        self: &Arc<Self>,
        tool: &str,
        key: Option<&str>,
    ) -> CompetingCheck {
        self.check_during_settle_after(0, tool, key)
    }

    /// As [`Self::check_during_next_settle`], but inside the settle that
    /// follows `skip` others on this thread.
    pub(crate) fn check_during_settle_after(
        self: &Arc<Self>,
        skip: usize,
        tool: &str,
        key: Option<&str>,
    ) -> CompetingCheck {
        let slot: Arc<Mutex<Option<JoinHandle<bool>>>> = Arc::default();
        let target = (Arc::clone(self), tool.to_owned(), key.map(str::to_owned));
        arm(skip, target, Arc::clone(&slot));
        CompetingCheck(slot)
    }
}

type Target = (Arc<BudgetEnforcer>, String, Option<String>);

/// Set the hook; a skipped settle re-arms it for the next one.
fn arm(skip: usize, target: Target, slot: Arc<Mutex<Option<JoinHandle<bool>>>>) {
    AFTER_SPEND_ADDED.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            if skip > 0 {
                arm(skip - 1, target, slot);
                return;
            }
            let (enforcer, tool, key) = target;
            let check = std::thread::spawn(move || enforcer.check(&tool, key.as_deref()).allowed);
            *slot.lock().unwrap() = Some(check);
        }));
    });
}
