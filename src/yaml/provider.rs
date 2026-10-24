// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! figment's view of a YAML config: `Dict` with last-wins at every level.

use super::*;
use figment::Provider as _;
use figment::providers::{Format as _, Yaml};
use figment::value::{Dict, Map};

/// Parse `text` as figment's `Dict`, the way the config loader reads it: a
/// repeated key keeps its last value at every level.
pub(crate) fn from_str_loose(text: &str) -> Result<Dict, Error> {
    guard(text)?;
    Yaml::from_str(text).map_err(Error::backend)
}

/// The config file's data as figment's YAML provider gives it: the
/// document under its profile, or the provider's own error.
#[allow(
    clippy::result_large_err,
    reason = "figment's own `Provider::data` signature, which the config loader returns"
)]
pub(crate) fn figment_data(text: &str) -> figment::Result<Map<figment::Profile, Dict>> {
    guard(text).map_err(|err| figment::Error::from(err.to_string()))?;
    Yaml::string(text).data()
}
