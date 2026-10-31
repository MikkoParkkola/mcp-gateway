// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend hidden from the caller is a lookup miss in the caller's view.
//!
//! Under an mTLS policy or agent auth, a backend whose every tool the caller's
//! policy refuses is left out of the caller's listings. A call naming it must
//! then answer as a call naming an unregistered backend does, or the answer
//! tells the caller which hidden names are registered. So the caller's scoped
//! view ([`super::scoped_backends::ScopedBackends`]) misses on a hidden name
//! exactly as on an unregistered one, and every per-caller stage meets the
//! miss it would meet for that name.
//!
//! Hiding is judged from the caller's identity, never cached as a verdict: a
//! caller-carrying context (a route's intake, a task worker's run) installs
//! the caller here, and each lookup judges live. A read with no caller
//! installed (listing, discovery, background, admin) hides nothing, so it can
//! never judge with someone else's identity.

use std::cell::Cell;
use std::sync::{Arc, OnceLock};

/// One caller's hiding judgment, from its identity.
pub(crate) trait CallerHiding: Send + Sync {
    /// Whether `server` is registered, known, and refused to this caller
    /// outright. Must not read through the scoped view it feeds.
    fn hides(&self, server: &str) -> bool;
}

tokio::task_local! {
    /// The caller installed for this request or task run, set once.
    static CALLER: OnceLock<Arc<dyn CallerHiding>>;
}

thread_local! {
    /// Set while a judgment runs, so a lookup it makes cannot re-enter it.
    static JUDGING: Cell<bool> = const { Cell::new(false) };
}

/// Clears [`JUDGING`] however a judgment ends.
struct Judging;

impl Drop for Judging {
    fn drop(&mut self) {
        JUDGING.with(|flag| flag.set(false));
    }
}

/// Run `request` with an empty caller slot its intake fills once identities
/// are known ([`record_caller`]). A slot already open is kept.
pub(crate) async fn with_caller_slot<F: Future>(request: F) -> F::Output {
    if CALLER.try_with(|_| ()).is_ok() {
        return request.await;
    }
    CALLER.scope(OnceLock::new(), request).await
}

/// Run `run` as `caller`'s: a task worker's run, which has no intake.
pub(crate) async fn with_caller<F: Future>(caller: Arc<dyn CallerHiding>, run: F) -> F::Output {
    let slot = OnceLock::new();
    let _ = slot.set(caller);
    CALLER.scope(slot, run).await
}

/// Install the caller of the open slot. The first caller wins: a later
/// record (a nested route) cannot replace the identity a request began with.
pub(crate) fn record_caller(caller: Arc<dyn CallerHiding>) {
    let _ = CALLER.try_with(|slot| slot.set(caller));
}

/// Whether `server` is hidden from this request's caller. `false` with no
/// caller installed, and inside a judgment (a lookup the judgment makes is
/// never itself judged).
pub(crate) fn hidden(server: &str) -> bool {
    let Some(caller) = CALLER.try_with(|slot| slot.get().cloned()).ok().flatten() else {
        return false;
    };
    if JUDGING.with(Cell::get) {
        debug_assert!(false, "a hiding judgment re-entered the caller's view");
        return false;
    }
    JUDGING.with(|flag| flag.set(true));
    let _judging = Judging;
    caller.hides(server)
}

#[cfg(test)]
#[path = "hiding_tests.rs"]
mod tests;

/// What the listing reads of one backend's catalogue now.
pub(crate) enum ListedCatalogue {
    /// The tool names it holds, and whether they are the whole catalogue.
    Tools { names: Vec<String>, complete: bool },
    /// Not registered, or no fresh catalogue held.
    NotHeld,
}

impl super::MetaMcp {
    /// The tools `gateway_list_servers` judges `server` by: the shared
    /// catalogue with blocked tools removed (`get_cached_tools_snapshot`), or
    /// the capability provider's own list, read only while held and fresh.
    /// Hidden means not listed, so the hiding judgment reads exactly this.
    pub(crate) fn listed_catalogue(&self, server: &str) -> ListedCatalogue {
        use super::scoped_backends::Unscoped;
        let Some(backend) = self.registry().get_for(Unscoped::Visibility, server) else {
            return self
                .get_capabilities()
                .filter(|cap| cap.name == server)
                .map_or(ListedCatalogue::NotHeld, |cap| ListedCatalogue::Tools {
                    names: cap.get_tools().into_iter().map(|t| t.name).collect(),
                    complete: true,
                });
        };
        let (cached, truncated, _, fresh) = backend.cached_tools_view(None);
        if cached.is_none() || !fresh {
            return ListedCatalogue::NotHeld;
        }
        ListedCatalogue::Tools {
            names: backend
                .get_cached_tools_snapshot()
                .iter()
                .map(|t| t.name.clone())
                .collect(),
            complete: !truncated,
        }
    }
}
