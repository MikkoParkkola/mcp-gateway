// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One published configuration and every view a request is judged against
//! (ADR-023, amended): built in full before a reload changes anything, then
//! published in one swap. A request takes one when it arrives and keeps it,
//! so no request mixes two configurations.

use std::sync::Arc;

use crate::config::Config;

/// The configuration a request is judged against, from arrival to response.
#[derive(Debug)]
pub struct Generation {
    config: Arc<Config>,
    /// `security.firewall`'s rules and redaction switch, compiled once per
    /// generation (ADR-029, amended): every check judged under this
    /// generation reads them, so one request never mixes two rule sets.
    #[cfg(feature = "firewall")]
    firewall: Arc<crate::security::firewall::FirewallPolicy>,
    /// The relay detector this gateway runs, fixed at startup and carried
    /// forward by every generation.
    #[cfg(feature = "firewall")]
    detector: crate::security::firewall::DetectorParams,
    /// The collusion fields in effect under this generation (ADR-029, amended,
    /// item 2): this config's when the detector runs it
    /// ([`crate::security::firewall::DetectorParams::runs`]), else the
    /// previous generation's, never the startup's.
    #[cfg(feature = "firewall")]
    collusion: Arc<crate::security::firewall::CollusionView>,
}

impl Generation {
    /// Build the generation for `config`. Runs before a reload touches
    /// backends, so a refusal here leaves everything as it was.
    ///
    /// # Errors
    ///
    /// A view that cannot be built from `config` (none in this slice; the
    /// key table and budgets join it later).
    pub fn prepare(config: Config, previous: &Self) -> Result<Self, String> {
        #[cfg(test)]
        if let Some(reason) = refuse_hook::take() {
            return Err(reason);
        }
        Ok(Self::after(config, previous))
    }

    /// The startup seed: its config builds the running detector.
    pub(super) fn of(config: Config) -> Self {
        Self {
            #[cfg(feature = "firewall")]
            firewall: Arc::new(crate::security::firewall::FirewallPolicy::compile(
                &config.security.firewall,
            )),
            #[cfg(feature = "firewall")]
            detector: crate::security::firewall::DetectorParams::of(&config.security.firewall),
            #[cfg(feature = "firewall")]
            collusion: Arc::new(crate::security::firewall::CollusionView::compile(
                &config.security.firewall.collusion,
            )),
            config: Arc::new(config),
        }
    }

    /// The generation that follows `previous` for a config that needs no
    /// checking ([`super::LiveConfig::set`] while no view can refuse, and
    /// [`Self::prepare`] once it has).
    #[cfg_attr(not(feature = "firewall"), expect(unused_variables))]
    pub(super) fn after(config: Config, previous: &Self) -> Self {
        Self {
            #[cfg(feature = "firewall")]
            firewall: Arc::new(crate::security::firewall::FirewallPolicy::compile(
                &config.security.firewall,
            )),
            #[cfg(feature = "firewall")]
            detector: previous.detector,
            #[cfg(feature = "firewall")]
            collusion: Arc::new(crate::security::firewall::CollusionView::compile(
                &config.security.firewall.collusion,
            )),
            config: Arc::new(config),
        }
    }

    /// The published configuration.
    #[must_use]
    pub fn config(&self) -> &Arc<Config> {
        &self.config
    }

    /// The firewall policy compiled from this generation's config.
    #[cfg(feature = "firewall")]
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "read by the firewall checks once they judge under the request's generation"
        )
    )]
    #[must_use]
    pub(crate) fn firewall_policy(&self) -> &crate::security::firewall::FirewallPolicy {
        &self.firewall
    }

    /// The collusion fields in effect under this generation.
    #[cfg(feature = "firewall")]
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "read by the relay gate once it judges under the witness's generation"
        )
    )]
    #[must_use]
    pub(crate) fn collusion_view(&self) -> &crate::security::firewall::CollusionView {
        &self.collusion
    }

    /// `security.sanitize_input` as published.
    #[must_use]
    pub fn sanitize_input(&self) -> bool {
        self.config.security.sanitize_input
    }

    /// `security.ssrf_protection` as published; the hardened posture already
    /// forced it on at load.
    #[must_use]
    pub fn ssrf_protection(&self) -> bool {
        self.config.security.ssrf_protection
    }

    /// The operator's name for this gateway's environment, when set.
    #[must_use]
    pub fn environment(&self) -> Option<&str> {
        self.config.environment.as_deref()
    }
}

/// G6: make the next `prepare` on this thread refuse, so a test can show a
/// refused build changes nothing. `arm` returns a flag the refusal sets; the
/// test asserts it, so a hook that never fired (another thread, a blocking
/// pool) fails the test instead of passing it.
#[cfg(test)]
pub(crate) mod refuse_hook {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    thread_local! {
        static NEXT: std::cell::RefCell<Option<(String, Arc<AtomicBool>)>> =
            const { std::cell::RefCell::new(None) };
    }

    pub(crate) fn arm(reason: &str) -> Arc<AtomicBool> {
        let fired = Arc::new(AtomicBool::new(false));
        NEXT.with(|n| *n.borrow_mut() = Some((reason.to_owned(), Arc::clone(&fired))));
        fired
    }

    pub(super) fn take() -> Option<String> {
        let (reason, fired) = NEXT.with(|n| n.borrow_mut().take())?;
        fired.store(true, Ordering::SeqCst);
        Some(reason)
    }
}
