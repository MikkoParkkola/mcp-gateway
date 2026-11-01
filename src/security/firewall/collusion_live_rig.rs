// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test rig for relay detection that follows the published configuration
//! (ADR-029, amended): a firewall and the `LiveConfig` a gateway would run
//! it under, built from ONE configuration, so a fixture never pairs a
//! `block` detector with a generation that says `off`.
//!

use std::sync::Arc;
use std::time::Duration;

use crate::config_reload::LiveConfig;

use super::{Firewall, FirewallConfig};

/// A firewall built from `firewall`, and a `LiveConfig` whose published
/// configuration carries that same firewall section over `live`'s other
/// settings and its resolved keys.
///
/// Keeping `live`'s keys matters: a fresh `LiveConfig::new` resolves
/// authentication from the configuration alone, and a fixture's keyed
/// callers would then carry no verified principal.
pub(crate) fn paired(firewall: FirewallConfig, live: &LiveConfig) -> (Firewall, LiveConfig) {
    let mut config = (*live.get()).clone();
    config.security.firewall = firewall.clone();
    let auth = Arc::clone(live.generation().auth());
    (
        Firewall::from_config(firewall, None),
        LiveConfig::with_auth(config, auth),
    )
}

/// The firewall's receipt clock frozen at the call: a window of a second
/// cannot age out on a slow run, and only `advance_collusion_clock_for_test`
/// moves it.
pub(crate) fn freeze(firewall: &Firewall) {
    firewall.advance_collusion_clock_for_test(Duration::ZERO);
}
