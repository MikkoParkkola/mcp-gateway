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
}

impl Generation {
    /// Build the generation for `config`. Runs before a reload touches
    /// backends, so a refusal here leaves everything as it was.
    ///
    /// # Errors
    ///
    /// A view that cannot be built from `config` (none in this slice; the
    /// key table and budgets join it later).
    pub fn prepare(config: Config) -> Result<Self, String> {
        #[cfg(test)]
        if let Some(reason) = refuse_hook::take() {
            return Err(reason);
        }
        Ok(Self::of(config))
    }

    /// The generation for a config that needs no checking: the startup seed,
    /// and [`super::LiveConfig::set`] while no view can refuse.
    pub(super) fn of(config: Config) -> Self {
        Self {
            #[cfg(feature = "firewall")]
            firewall: Arc::new(crate::security::firewall::FirewallPolicy::compile(
                &config.security.firewall,
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
