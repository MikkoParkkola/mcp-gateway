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
//! - startup is refused on a build without the `firewall` feature.
//!
//! Changing the posture needs a restart; a reload that changes it is refused.
//!
//! A multi-user deployment (see [`crate::config::AuthConfig::implies_multi_user`])
//! that runs `standard` gets one startup warning and a `doctor` finding; both
//! come from [`unhardened_multi_user`], so they cannot disagree.

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
    let context_integrity = &mut config.security.context_integrity;
    if matches!(
        context_integrity.preset,
        Preset::MonitorOnly | Preset::LocalDeveloper | Preset::AuditOnly
    ) {
        context_integrity.preset = Preset::TeamShared;
    }
    context_integrity.non_bypassable = true;
    Ok(())
}

/// The reload refusal when `candidate` changes the running posture.
pub(crate) fn reload_refusal(running: &Config, candidate: &Config) -> Option<String> {
    (running.security.posture != candidate.security.posture)
        .then(|| "config reload refused: security.posture requires restart".to_string())
}

/// A multi-user deployment running the `standard` posture.
///
/// The single source of the startup warning and the `doctor` finding. Public
/// only for the binary's `doctor` command; not a stable API.
#[doc(hidden)]
#[must_use]
pub fn unhardened_multi_user(config: &Config) -> bool {
    config.security.posture == SecurityPosture::Standard
        && config
            .auth
            .implies_multi_user(!config.key_server.oidc.is_empty())
}

/// Log the posture once at startup.
///
/// `hardened`: one info line with the effective value of every control it
/// enforces. A multi-user `standard` deployment: one warning.
pub(crate) fn log_startup(config: &Config) {
    if config.security.posture == SecurityPosture::Hardened {
        let context_integrity = &config.security.context_integrity;
        let preset = serde_json::to_value(context_integrity.preset).unwrap_or_default();
        tracing::info!(
            "security.posture=hardened enforcing: context_integrity preset={} non_bypassable={}",
            preset.as_str().unwrap_or_default(),
            context_integrity.non_bypassable
        );
    } else if unhardened_multi_user(config) {
        tracing::warn!(
            "multi-user deployment running security.posture=standard; set security.posture: \
             hardened (see `mcp-gateway doctor`, row security-posture)"
        );
    }
}

#[cfg(test)]
#[path = "posture_tests.rs"]
pub(crate) mod tests;
