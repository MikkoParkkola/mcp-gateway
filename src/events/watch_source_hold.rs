// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8122: a watch that is not watchable now is held, never withdrawn.
//! A row's recorded class governs its poller, hold and resume.

use chrono::Utc;

use super::{
    Catalogue, Charge, CredentialUse, EventsHub, Held, Judged, Run, Subscription, Target,
    WatchClass, event_name,
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

impl Run {
    /// Why this poller's capability is not watchable in `catalogue`.
    pub(super) fn why_not_watchable(&self, catalogue: &Catalogue) -> Held {
        let named = catalogue
            .targets
            .iter()
            .find(|t| event_name(&t.capability) == self.name);
        Held {
            reason: match named {
                None => "capability not offered; the subscription resumes if it returns",
                Some(t) if !t.read_only => {
                    "capability no longer read-only; the subscription resumes if it is again"
                }
                Some(_) => {
                    "capability moved to another credential class; subscribe again to follow it"
                }
            },
            key: None,
        }
    }

    /// Hold (`Some`) or resume (`None`) the live rows this poller polls for.
    /// A row written before its class was recorded belongs to the poller
    /// whose key it matches, and takes that poller's class once it is
    /// watchable again.
    pub(super) fn judge_rows(&self, hub: &EventsHub, held: Option<Held>) {
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
                held: held.clone(),
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
