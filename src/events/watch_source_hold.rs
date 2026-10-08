// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8122: a watch that is not watchable now is held, never withdrawn.
//! A row's recorded class governs its poller, hold and resume.

use chrono::Utc;

use serde_json::Value;

use super::super::store::Store;
use super::{
    Catalogue, Charge, CredentialUse, EventSource, EventsHub, Held, Judged, Run, Subscription,
    Target, WatchClass, WatchSource, event_name, is_watch, unread,
};

impl Charge {
    /// The charge a poller of `class` polls under.
    pub(super) const fn of(class: WatchClass) -> Self {
        match class {
            WatchClass::Free => Self::Global,
            WatchClass::Keyed => Self::Holder,
        }
    }
}

/// The class a watch of `target` is admitted under; `None` for an account
/// credential, which no watch uses.
pub(super) const fn class_of_target(target: &Target) -> Option<WatchClass> {
    match target.credential {
        CredentialUse::Free => Some(WatchClass::Free),
        CredentialUse::Keyed => Some(WatchClass::Keyed),
        CredentialUse::Account => None,
    }
}

/// Why the capability of watch type `name` is not watchable in `catalogue`.
fn why_not_watchable(catalogue: &Catalogue, name: &str) -> Held {
    let named = catalogue
        .targets
        .iter()
        .find(|t| event_name(&t.capability) == name);
    Held {
        reason: match named {
            None => "capability not offered; the subscription resumes if it returns",
            Some(t) if !t.read_only => {
                "capability no longer read-only; the subscription resumes if it is again"
            }
            Some(_) => {
                "capability moved to another credential class; unsubscribe, then subscribe again to follow it"
            }
        },
        key: None,
    }
}

impl Run {
    /// Why this poller's capability is not watchable in `catalogue`.
    pub(super) fn why_not_watchable(&self, catalogue: &Catalogue) -> Held {
        why_not_watchable(catalogue, &self.name)
    }

    /// Hold (`Some`) or resume (`None`) the live rows this poller polls for.
    /// A row written before its class was recorded belongs to the poller
    /// whose key it matches, and takes that poller's class once it is
    /// watchable again.
    pub(super) fn judge_rows(&self, hub: &EventsHub, held: Option<&Held>) {
        let class = match self.charge {
            Charge::Global => WatchClass::Free,
            Charge::Holder => WatchClass::Keyed,
        };
        let written = if held.is_none() {
            hub.store.backfill_watch_class(&self.name, class)
        } else {
            Ok(())
        };
        let judge = |s: &Subscription| {
            self.owns(s).then(|| Judged {
                held: held.cloned(),
                ..Judged::default()
            })
        };
        if let Err(error) =
            written.and_then(|()| hub.store.apply_holds(&judge, Utc::now(), hub.hold_bound()))
        {
            tracing::warn!(%error, "events: a watch hold stamp was not written; retried at the next poll");
        }
    }

    /// Whether row `s` is this poller's: its type, its key, and its recorded
    /// class (a row without one goes by its key).
    pub(super) fn owns(&self, s: &Subscription) -> bool {
        s.name == self.name
            && self.key_of(s) == self.key
            && s.watch_class
                .is_none_or(|class| Charge::of(class) == self.charge)
    }
}

impl WatchSource {
    /// The class a new subscribe's key polls under: what the catalogue
    /// admits the capability under now, else (a held watch) a stored row's
    /// class, else keyed. A held row keeps its own key (`row_key`),
    /// so a key started here for another class finds no row and retires.
    pub(super) fn class_for(&self, principal: &str, name: &str, arguments: &Value) -> WatchClass {
        self.watch_class(name)
            .or_else(|| {
                let hub = self.hub.upgrade()?;
                Self::rows(&hub, principal, name, arguments)
                    .first()
                    .map(|row| self.effective_class(row))
            })
            .unwrap_or(WatchClass::Keyed)
    }

    /// A row's class: recorded, else (a watch written before the class was
    /// recorded) what the catalogue admits its capability under now, else
    /// keyed, so one principal's credential never answers for another.
    pub(super) fn effective_class(&self, row: &Subscription) -> WatchClass {
        row.watch_class
            .or_else(|| self.watch_class(&row.name))
            .unwrap_or(WatchClass::Keyed)
    }

    /// Record the class of every watch row written before it was recorded:
    /// what the catalogue admits its capability under now. A row whose
    /// capability the catalogue does not name yet waits for a later replay;
    /// the worker's sweep runs one (MIK-8151). Meanwhile a whole, settled
    /// read that offers its capability under no class holds it, bounded like
    /// any watch hold, with no class recorded; it starts, and its poller
    /// resumes it, once a class is offered.
    pub(super) fn pin_classes(&self, store: &Store) {
        let mut names: Vec<String> = store
            .subscriptions()
            .into_iter()
            .filter(|s| s.watch_class.is_none() && is_watch(&s.name))
            .map(|s| s.name)
            .collect();
        names.sort();
        names.dedup();
        // Read once, and only when a row's capability offers no class.
        let mut read = None;
        for name in names {
            let Some(class) = self.watch_class(&name) else {
                let read = read.get_or_insert_with(|| self.host.catalogue());
                if self.host.catalogue_generation() == read.generation && !unread(read, &name) {
                    self.hold_unclassed(store, &name, &why_not_watchable(read, &name));
                }
                continue;
            };
            if let Err(error) = store.backfill_watch_class(&name, class) {
                tracing::warn!(%error, "events: a watch class was not recorded; retried at the next replay");
            }
        }
    }

    /// Hold the live rows of `name` that have no recorded class.
    fn hold_unclassed(&self, store: &Store, name: &str, why: &Held) {
        let Some(hub) = self.hub.upgrade() else {
            return;
        };
        let judge = |s: &Subscription| {
            (s.name == name && s.watch_class.is_none()).then(|| Judged {
                held: Some(why.clone()),
                ..Judged::default()
            })
        };
        if let Err(error) = store.apply_holds(&judge, Utc::now(), hub.hold_bound()) {
            tracing::warn!(%error, "events: a watch hold stamp was not written; retried at the next replay");
        }
    }
}
