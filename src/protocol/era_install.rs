// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A build-first restart's era (MIK-8012): a probe of the candidate run without
//! the cache's lock, and the lock it is installed under as the candidate is
//! published.

use super::{
    Era, EraCache, EraObservation, EraSource, ProbeOutcome, ProbeTrigger, classify, determination,
    install_always,
};

impl EraCache {
    /// Run `probe` without taking this cache's lock, and record nothing.
    ///
    /// A build-first restart (MIK-8012) probes its candidate while the old
    /// transport still serves from this cache: probed as a restart probes, the
    /// verdict would be discarded first, and the old transport would read none
    /// (`cached_now`) for the whole probe and shape every call legacy. The
    /// outcome is installed as the candidate is published, before it is
    /// reachable ([`EraInstall::install`], `Backend::publish`).
    pub(crate) async fn probe_detached<F, Fut>(probe: F) -> DetachedProbe
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = ProbeOutcome>,
    {
        let started = std::time::Instant::now();
        let outcome = probe().await;
        DetachedProbe {
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            outcome,
        }
    }

    /// Take the lock a [`DetachedProbe`] is installed under. Taken BEFORE the
    /// candidate is published, so the swap and the install happen without an
    /// await between them: no reader sees the new transport with the old
    /// transport's verdict.
    pub(crate) async fn lock_for_install(&self) -> EraInstall<'_> {
        EraInstall {
            cache: self,
            guard: self.observation.lock().await,
        }
    }

    /// Record what one probe decided, as a restart's probe records it. The
    /// caller owns the lock.
    pub(super) fn store<I>(
        &self,
        guard: &mut determination::Guard<'_>,
        trigger: ProbeTrigger,
        probe: DetachedProbe,
        install: I,
    ) -> Era
    where
        I: FnOnce(&mut dyn FnMut()) -> bool,
    {
        let DetachedProbe {
            outcome,
            duration_ms,
        } = probe;
        let observation = EraObservation::observed_now(&outcome, trigger);

        if !install(&mut || guard.set(observation)) {
            // The probed peer is gone: what it said is about a process no longer on
            // the wire. Same fields as the probe record, minus `error_code`, plus why.
            tracing::info!(
                target: "mcp_gateway::observed",
                backend = %self.name,
                slot = self.slot,
                reason = "transport_replaced",
                outcome = outcome.outcome_label(observation.era),
                evidence = observation.evidence.as_str(),
                duration_ms,
                trigger = trigger.as_str(),
            );
            // What this probe decided, not what the cache holds: the caller asked
            // about its own peer (MIK-8056).
            return observation.era;
        }

        // Two call sites rather than an optional field: `error_code` is absent
        // on the non-error rows, and `tracing` has no way to omit a field.
        if let ProbeOutcome::Error(code) = &outcome {
            tracing::info!(
                target: "mcp_gateway::observed",
                backend = %self.name,
                slot = self.slot,
                outcome = outcome.outcome_label(observation.era),
                evidence = observation.evidence.as_str(),
                error_code = code,
                duration_ms,
                trigger = trigger.as_str(),
            );
        } else {
            tracing::info!(
                target: "mcp_gateway::observed",
                backend = %self.name,
                slot = self.slot,
                outcome = outcome.outcome_label(observation.era),
                evidence = observation.evidence.as_str(),
                duration_ms,
                trigger = trigger.as_str(),
            );
        }

        observation.era
    }
}

/// A probe run without the cache's lock: what it found and how long it took,
/// not yet recorded ([`EraCache::probe_detached`]).
pub(crate) struct DetachedProbe {
    pub(super) outcome: ProbeOutcome,
    pub(super) duration_ms: u64,
}

impl DetachedProbe {
    /// The era this probe decided, for the start's own handshake decision.
    pub(crate) fn era(&self) -> Era {
        classify(&self.outcome)
    }
}

/// The cache's lock, held from before a build-first swap to the install of
/// the candidate's probe (MIK-8012).
pub(crate) struct EraInstall<'a> {
    pub(super) cache: &'a EraCache,
    pub(super) guard: determination::Guard<'a>,
}

impl EraInstall<'_> {
    /// Replace the old transport's verdict with the candidate's, recorded as
    /// a restart records it: the discard of the old verdict, the miss, then
    /// the probe. Dropping this without installing leaves the old verdict.
    ///
    /// One write, with no "never probed" in between: a reader that cannot
    /// wait (`cached_now`) sees the old era or the new one, never none. The
    /// caller runs this before the candidate is reachable (`Backend::publish`),
    /// so no request on the candidate is shaped in its predecessor's dialect,
    /// and keeps `self` (the lock) until the candidate is in the slot: an old
    /// transport's contradiction queued on the lock then finds its transport
    /// replaced and discards nothing.
    pub(crate) fn install(&mut self, probe: DetachedProbe) -> Era {
        let cache = self.cache;
        if self.guard.source == EraSource::Probed {
            tracing::info!(
                target: "mcp_gateway::observed",
                backend = %cache.name,
                slot = cache.slot,
                reason = "restart",
            );
        }
        tracing::info!(target: "mcp_gateway::observed", backend = %cache.name, slot = cache.slot, hit = false);
        cache.store(&mut self.guard, ProbeTrigger::Start, probe, install_always)
    }
}
