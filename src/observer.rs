// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A hook a component calls after a state change it made, for one observer
//! attached at startup (the gateway operational events source, MIK-7720).
//! Unset, a call is one atomic load and changes nothing.

use std::sync::{Arc, OnceLock};

/// What an observer is handed: one change, owned.
pub(crate) type ObserverFn<A> = Arc<dyn Fn(A) + Send + Sync>;

/// The observer slot. Set once; a later set is ignored.
pub(crate) struct Observer<A>(OnceLock<ObserverFn<A>>);

impl<A> Default for Observer<A> {
    fn default() -> Self {
        Self(OnceLock::new())
    }
}

impl<A> std::fmt::Debug for Observer<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.get().is_some() {
            "Observer(set)"
        } else {
            "Observer(unset)"
        })
    }
}

impl<A> Observer<A> {
    /// Attach `observer`, unless one already is.
    pub(crate) fn set(&self, observer: ObserverFn<A>) {
        let _ = self.0.set(observer);
    }

    /// The attached observer, for a component that hands it on.
    pub(crate) fn get(&self) -> Option<ObserverFn<A>> {
        self.0.get().cloned()
    }

    /// Whether an observer is attached, so a caller can skip building a change.
    /// Only the cost enforcer asks, so it compiles with that feature alone.
    #[cfg(feature = "cost-governance")]
    pub(crate) fn is_set(&self) -> bool {
        self.0.get().is_some()
    }

    /// Tell the observer, if any. Call it with no lock held.
    pub(crate) fn call(&self, change: A) {
        if let Some(observer) = self.0.get() {
            observer(change);
        }
    }
}
