// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One published configuration and every view a request is judged against
//! (ADR-023, amended): built in full before a reload changes anything, then
//! published in one swap. A request takes one when it arrives and keeps it,
//! so no request mixes two configurations.

use std::sync::Arc;

use crate::config::{Config, EnvOverlay};
use crate::gateway::auth::ResolvedAuthConfig;

/// The configuration a request is judged against, from arrival to response.
#[derive(Debug)]
pub struct Generation {
    config: Arc<Config>,
    /// The resolved API key table, with the running restart-only `auth`
    /// settings and the shared per-client store.
    auth: Arc<ResolvedAuthConfig>,
}

impl Generation {
    /// Build the generation for `config`. Runs before a reload touches
    /// backends, so a refusal here leaves everything as it was.
    ///
    /// `running` is the published generation's auth: the key table is
    /// rebuilt from `config` against `overlay`, and every other `auth`
    /// setting is the running one, since those apply only at a restart.
    ///
    /// # Errors
    ///
    /// A view that cannot be built from `config`: a key the startup build
    /// would refuse.
    pub fn prepare(
        config: Config,
        overlay: &EnvOverlay,
        running: &ResolvedAuthConfig,
    ) -> Result<Self, String> {
        #[cfg(test)]
        if let Some(reason) = refuse_hook::take() {
            return Err(reason);
        }
        let auth = running
            .with_keys_of(&config.auth, overlay)
            .map_err(|e| format!("auth.api_keys: {e}"))?;
        Ok(Self {
            config: Arc::new(config),
            auth: Arc::new(auth),
        })
    }

    /// The startup generation: `auth` is the startup build of `config.auth`
    /// against the startup overlay, so the startup keys authenticate before
    /// any reload.
    pub(super) fn startup(config: Config, auth: Arc<ResolvedAuthConfig>) -> Self {
        Self {
            config: Arc::new(config),
            auth,
        }
    }

    /// The published configuration.
    #[must_use]
    pub fn config(&self) -> &Arc<Config> {
        &self.config
    }

    /// The API key table and the running `auth` settings this generation
    /// judges with.
    #[must_use]
    pub fn auth(&self) -> &Arc<ResolvedAuthConfig> {
        &self.auth
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
