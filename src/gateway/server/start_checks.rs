// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Checks a start makes before it opens a store or binds: [`clock`] for every
//! transport, run first by `Gateway::new_evaluated` (here, with the check it
//! starts with), and [`http`] only for an HTTP start.

use std::sync::Arc;

use crate::Result;
use crate::config::Config;

/// Refuse to start on a clock that reads before 1970 (MIK-8202 D7): every
/// expiry the gateway judges would be judged against a time it cannot read.
/// Refusing here, once, keeps a box that boots with a dead clock from serving
/// at all; a clock that steps back later is handled at each check.
pub(super) fn clock() -> Result<()> {
    crate::clock::unix_secs().map(drop).map_err(|_| {
        crate::Error::Config(
            "system clock reads before 1970; set the clock and restart (MIK-8202)".to_owned(),
        )
    })
}

/// Refuse an HTTP start whose configuration cannot work over HTTP.
#[cfg_attr(
    not(feature = "firewall"),
    allow(unused_variables, clippy::unnecessary_wraps)
)]
pub(super) fn http(config: &Config) -> Result<()> {
    #[cfg(feature = "firewall")]
    crate::security::firewall::anomaly_config::refuse_keyless_http_anomaly(config)
        .map_err(crate::Error::Config)?;
    Ok(())
}

impl super::Gateway {
    /// Create a gateway from an already evaluated config and the environment it
    /// was evaluated against, bringing up managed account custody if the config
    /// asks for one.
    ///
    /// The constructor a deployment uses: the ordinary construction every
    /// caller gets, against THIS environment rather than the process
    /// environment, plus one further step. `new_with_path` stays as it was for
    /// callers that build a `Config` in memory and want no custody — it is the
    /// same construction with an empty overlay. The further step is what makes a
    /// gateway READY: it returns only after every managed descriptor's issuer
    /// metadata has been validated and pinned AND the custody store's two
    /// exclusive locks are held.
    ///
    /// # Errors
    ///
    /// Returns an error if backend registration fails, if the `accounts` block
    /// is invalid, if a managed descriptor's issuer metadata is unacceptable, or
    /// if custody cannot be brought up — a store another owner holds is a
    /// startup failure, never a degraded start.
    pub async fn new_evaluated(
        config: Config,
        env: Arc<crate::config::LiveEnv>,
        config_path: Option<std::path::PathBuf>,
    ) -> Result<Self> {
        clock()?;
        Self::new_evaluated_inner(
            config,
            env,
            config_path,
            #[cfg(test)]
            None,
        )
        .await
    }
}
