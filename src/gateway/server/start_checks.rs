// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Checks only an HTTP start makes; stdio has its own entry and skips them.

use crate::Result;
use crate::config::Config;

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
