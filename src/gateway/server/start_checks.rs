// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Checks a start makes before it opens a store or binds: [`clock`] for every
//! transport, [`http`] only for an HTTP start.

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
