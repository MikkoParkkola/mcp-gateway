// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `security.posture`: one switch that raises a set of controls together.
//!
//! `standard` (the default) changes nothing. `hardened` is resolved once, when
//! the config is loaded for use (startup, `validate`, reload), and never on the
//! literal load a config rewrite round-trips, so a rewrite cannot persist a
//! forced value into the operator's file.
//!
//! What `hardened` enforces in this version:
//! - the context-integrity preset is at least `team_shared`
//!   (`enterprise_strict` is kept) and `non_bypassable` is on;
//! - the firewall and anomaly detection are on, and an anomaly score at or
//!   above the block threshold (1.0 unless set within `[0.9, 1.0]`; below
//!   0.9 refuses start) blocks;
//! - a call whose transition cannot be learned because the learned-pair map
//!   is full is refused rather than passed unscored;
//! - `ssrf_protection` is on and `trust_configured_backends` off, and every
//!   HTTP and WebSocket backend connects under
//!   [`crate::security::ssrf::DestinationPolicy::Public`]: names are resolved
//!   once and pinned, private literals are refused before anything connects,
//!   OAuth URLs are checked before use, and proxy environment variables are
//!   ignored. The policy is stamped by the backend registry, so a backend
//!   used with no config at all has no posture and none is enforced;
//! - message signing is on, so a start without a signing secret of at least
//!   32 bytes is refused; every successful `tools/call` result on both routes
//!   is signed;
//! - a legacy client must declare elicitation, and an unconfirmable legacy
//!   destructive call is refused;
//! - startup is refused on a build without the `firewall` feature.
//!
//! Changing the posture needs a restart; a reload that changes it is refused.
//!
//! A multi-user deployment (see [`crate::config::AuthConfig::implies_multi_user`])
//! that runs `standard` gets one startup warning and a `doctor` finding; both
//! come from [`unhardened_multi_user_warning`], so they cannot disagree.

use serde::{Deserialize, Serialize};

use crate::config::{Config, ContextIntegrityPresetConfig as Preset};
use crate::{Error, Result};

/// Gateway security posture (`security.posture`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SecurityPosture {
    /// Every control keeps its own setting. The default.
    #[default]
    Standard,
    /// Raise the controls listed in the module docs, whatever they are set to.
    Hardened,
}

/// Whether this binary was built with the `firewall` feature.
///
/// A parameter rather than a `cfg!` inside [`resolve`], so the refusal on a
/// build without the feature is testable from the default build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FirewallBuild {
    /// The feature is compiled in.
    Compiled,
    /// The feature is absent.
    Absent,
}

impl FirewallBuild {
    /// The build this binary is.
    pub(crate) const CURRENT: Self = if cfg!(feature = "firewall") {
        Self::Compiled
    } else {
        Self::Absent
    };
}

/// Apply the posture to a config loaded for use.
///
/// # Errors
///
/// Returns [`Error::ConfigValidation`] when `hardened` cannot be honoured.
pub(crate) fn resolve(config: &mut Config, build: FirewallBuild) -> Result<()> {
    if config.security.posture == SecurityPosture::Standard {
        return Ok(());
    }
    if build == FirewallBuild::Absent {
        return Err(Error::ConfigValidation(
            "security.posture=hardened needs the `firewall` feature, and this binary was built \
             without it; use a default build or set security.posture: standard"
                .to_string(),
        ));
    }
    // #1881: the egress proxy is a route out the destination policy cannot see.
    if config.capabilities.egress_proxy.is_some() {
        return Err(Error::ConfigValidation(
            "security.posture=hardened refuses capabilities.egress_proxy: capability traffic \
             through a proxy bypasses the destination policy; remove the key or set \
             security.posture: standard"
                .to_string(),
        ));
    }
    let context_integrity = &mut config.security.context_integrity;
    if matches!(
        context_integrity.preset,
        Preset::MonitorOnly | Preset::LocalDeveloper | Preset::AuditOnly
    ) {
        context_integrity.preset = Preset::TeamShared;
    }
    context_integrity.non_bypassable = true;
    config.security.ssrf_protection = true;
    config.security.trust_configured_backends = false;
    // Before `message_signing.resolve_with_env`, which every caller runs
    // after this, so an env-only secret resolves and a missing one refuses.
    config.security.message_signing.enabled = true;
    #[cfg(feature = "firewall")]
    force_anomaly_blocking(&mut config.security.firewall)?;
    Ok(())
}

/// The lowest block threshold `hardened` accepts (maintainer decision M4).
#[cfg(feature = "firewall")]
const BLOCK_THRESHOLD_FLOOR: f64 = 0.9;

/// Firewall and anomaly detection on; block at 1.0 unless set in
/// `[0.9, 1.0]`. At 1.0 only a transition never seen after a warmed
/// predecessor blocks. A value above 1.0 is left for the range check that the
/// now-enabled detection runs, which refuses it.
#[cfg(feature = "firewall")]
fn force_anomaly_blocking(firewall: &mut crate::security::firewall::FirewallConfig) -> Result<()> {
    firewall.enabled = true;
    firewall.anomaly_detection = true;
    match firewall.anomaly_block_threshold {
        None => firewall.anomaly_block_threshold = Some(1.0),
        Some(block) if block < BLOCK_THRESHOLD_FLOOR => {
            return Err(Error::ConfigValidation(format!(
                "security.posture=hardened needs security.firewall.anomaly_block_threshold \
                 of at least {BLOCK_THRESHOLD_FLOOR}, got {block}; remove it to use 1.0"
            )));
        }
        Some(_) => {}
    }
    Ok(())
}

/// The reload refusal when `candidate` changes the running posture.
pub(crate) fn reload_refusal(running: &Config, candidate: &Config) -> Option<String> {
    (running.security.posture != candidate.security.posture)
        .then(|| "config reload refused: security.posture requires restart".to_string())
}

/// The warning for a multi-user deployment running the `standard` posture,
/// or `None`.
///
/// The single source of the startup warning and the `doctor` finding, which
/// uses this text verbatim. Public only for the binary's `doctor` command;
/// not a stable API.
#[doc(hidden)]
#[must_use]
pub fn unhardened_multi_user_warning(config: &Config) -> Option<&'static str> {
    let unhardened = config.security.posture == SecurityPosture::Standard
        && config
            .auth
            .implies_multi_user(!config.key_server.oidc.is_empty());
    unhardened.then_some(
        "multi-user deployment running security.posture=standard; set security.posture: \
         hardened (restart required)",
    )
}

/// Log the posture once at startup.
///
/// `hardened`: one info line with the effective value of every control it
/// enforces. A multi-user `standard` deployment: one warning.
pub(crate) fn log_startup(config: &Config) {
    if config.security.posture == SecurityPosture::Hardened {
        let context_integrity = &config.security.context_integrity;
        let preset = serde_json::to_value(context_integrity.preset).unwrap_or_default();
        #[cfg(feature = "firewall")]
        let firewall = {
            let fw = &config.security.firewall;
            format!(
                " firewall.enabled={} anomaly_detection={} anomaly_block_threshold={}",
                fw.enabled,
                fw.anomaly_detection,
                fw.anomaly_block_threshold.unwrap_or_default()
            )
        };
        #[cfg(not(feature = "firewall"))]
        let firewall = String::new();
        tracing::info!(
            "security.posture=hardened enforcing: context_integrity preset={} \
             non_bypassable={} ssrf_protection={} trust_configured_backends={} \
             message_signing.enabled={}{firewall}",
            preset.as_str().unwrap_or_default(),
            context_integrity.non_bypassable,
            config.security.ssrf_protection,
            config.security.trust_configured_backends,
            config.security.message_signing.enabled
        );
    } else if let Some(warning) = unhardened_multi_user_warning(config) {
        tracing::warn!("{warning}");
    }
}

#[cfg(test)]
#[path = "posture_tests.rs"]
pub(crate) mod tests;
