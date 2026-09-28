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

use crate::Result;
use crate::config::Config;

/// Gateway security posture (`security.posture`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
#[allow(dead_code)] // red stub: unwired until the implementation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FirewallBuild {
    /// The feature is compiled in.
    Compiled,
    /// The feature is absent.
    Absent,
}

#[allow(dead_code)] // red stub: unwired until the implementation
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
#[allow(dead_code)] // red stub: unwired until the implementation
pub(crate) fn resolve(config: &mut Config, build: FirewallBuild) -> Result<()> {
    let _ = (config, build);
    Ok(())
}

/// A multi-user deployment running the `standard` posture.
///
/// The single source of the startup warning and the `doctor` finding.
#[must_use]
pub fn unhardened_multi_user(config: &Config) -> bool {
    let _ = config;
    false
}

/// Log the posture once at startup.
#[allow(dead_code)] // red stub: unwired until the implementation
pub(crate) fn log_startup(config: &Config) {
    let _ = config;
}

#[cfg(test)]
#[path = "posture_tests.rs"]
pub(crate) mod tests;
