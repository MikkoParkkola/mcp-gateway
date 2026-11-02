// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One published configuration and every view a request is judged against
//! (ADR-023, amended): built in full before a reload changes anything, then
//! published in one swap. A request takes one when it arrives and keeps it
//! for every request-side check, so no request mixes two configurations
//! there; its answer is judged under that one and the one published at scan
//! time, the stronger result standing (ADR-029, amended, item 5).

use std::sync::Arc;

use crate::config::{Config, EnvOverlay};
use crate::gateway::auth::ResolvedAuthConfig;

/// The configuration a request is judged against on arrival: every request-side
/// check, and half of the answer side's pair.
#[derive(Debug)]
pub struct Generation {
    config: Arc<Config>,
    /// The resolved API key table, with the running restart-only `auth`
    /// settings and the shared per-client store.
    auth: Arc<ResolvedAuthConfig>,
    /// `security.tool_policy`, compiled once per generation (ADR-029, amended):
    /// every authorizer judged under this generation reads it.
    tool_policy: Arc<crate::security::ToolPolicy>,
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
    /// `running` is what the process runs: the startup config, whose
    /// restart-only settings judge the new keys, and the published
    /// generation's auth. The key table is rebuilt from `config` against
    /// `overlay`; every other `auth` setting is the running one, since those
    /// apply only at a restart.
    ///
    /// # Errors
    ///
    /// A view that cannot be built from `config`: a key the startup build
    /// would refuse, or a key list that would flip the running multi-user
    /// status.
    pub(super) fn prepare(
        config: Config,
        overlay: &EnvOverlay,
        (running, published): (&Config, &Self),
    ) -> Result<Self, String> {
        #[cfg(test)]
        if let Some(reason) = refuse_hook::take() {
            return Err(reason);
        }
        refuse_multi_user_flip(running, &config.auth)?;
        let auth = published
            .auth
            .with_keys_of(&config.auth, overlay)
            .map_err(|e| format!("auth.api_keys: {e}"))?;
        Ok(Self::following(config, Arc::new(auth), published))
    }

    /// The startup generation: `auth` is the startup build of `config.auth`
    /// against the startup overlay, which ran the same key resolution and
    /// collision checks `prepare` runs, so the startup keys authenticate
    /// before any reload.
    pub(crate) fn prepare_startup(config: Config, auth: Arc<ResolvedAuthConfig>) -> Self {
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
            tool_policy: Arc::new(crate::security::ToolPolicy::from_config(
                &config.security.tool_policy,
            )),
            config: Arc::new(config),
            auth,
        }
    }

    /// The generation that follows `previous` for `config`, with `auth`
    /// already built: it carries the running detector forward and keeps the
    /// previous collusion view for an edit the detector cannot run.
    #[cfg_attr(not(feature = "firewall"), expect(unused_variables))]
    pub(super) fn following(
        config: Config,
        auth: Arc<ResolvedAuthConfig>,
        previous: &Self,
    ) -> Self {
        Self {
            #[cfg(feature = "firewall")]
            firewall: Arc::new(crate::security::firewall::FirewallPolicy::compile(
                &config.security.firewall,
            )),
            #[cfg(feature = "firewall")]
            detector: previous.detector,
            #[cfg(feature = "firewall")]
            collusion: if previous.detector.runs(&config.security.firewall) {
                Arc::new(crate::security::firewall::CollusionView::compile(
                    &config.security.firewall.collusion,
                ))
            } else {
                Arc::clone(&previous.collusion)
            },
            tool_policy: Arc::new(crate::security::ToolPolicy::from_config(
                &config.security.tool_policy,
            )),
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

    /// The tool policy compiled from this generation's config.
    #[must_use]
    pub(crate) fn tool_policy(&self) -> &crate::security::ToolPolicy {
        &self.tool_policy
    }

    /// The firewall policy compiled from this generation's config.
    #[cfg(feature = "firewall")]
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

/// Refuse a key list that would change whether the gateway is multi-user,
/// in either direction. Multi-user status is declared once, at startup, and
/// guards held OAuth tokens (ADR-008 INV-2), so a reload may not change it.
/// Judged on the RUNNING settings (`enabled`, `single_user`, the bearer,
/// OIDC) with the new keys: the file's restart-only settings apply only at
/// a restart.
fn refuse_multi_user_flip(
    running: &Config,
    wanted: &crate::config::AuthConfig,
) -> Result<(), String> {
    let oidc = !running.key_server.oidc.is_empty();
    let after = crate::config::AuthConfig {
        api_keys: wanted.api_keys.clone(),
        ..running.auth.clone()
    };
    let flips = running.auth.implies_multi_user(oidc) != after.implies_multi_user(oidc)
        || running.auth.grants_single_user_principal(oidc)
            != after.grants_single_user_principal(oidc);
    if !flips {
        return Ok(());
    }
    // Named by what changed: multi-user status, else the sole-operator grant.
    let multi = if after.implies_multi_user(oidc) == running.auth.implies_multi_user(oidc) {
        !after.grants_single_user_principal(oidc)
    } else {
        after.implies_multi_user(oidc)
    };
    let now = if multi { "multi-user" } else { "single-user" };
    Err(format!(
        "auth.api_keys: this key list would make the gateway {now}, which applies only at a \
         restart; the running keys stay in force until then."
    ))
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
