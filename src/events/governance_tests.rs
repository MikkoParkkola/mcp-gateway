// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use std::sync::Arc;

use super::*;
use crate::config::Config;
use crate::config_reload::LiveConfig;
use crate::events::services::LiveCredentials;

fn services(firewall: bool) -> Services {
    let _ = firewall;
    Services {
        live: Arc::new(LiveConfig::new(Config::default())),
        #[cfg(feature = "firewall")]
        firewall: None,
        audit: None,
        provenance: None,
        #[cfg(feature = "cost-governance")]
        budget: None,
        credentials: LiveCredentials::default(),
    }
}

/// Without a running firewall the verdict says so, whatever the scan said.
#[test]
fn no_firewall_means_the_verdict_is_none() {
    let s = services(false);
    assert_eq!(s.firewall_verdict(Scan::Pass, false), "none");
    assert_eq!(s.firewall_verdict(Scan::Pass, true), "none");
}

#[cfg(feature = "firewall")]
#[test]
fn a_running_firewall_names_block_redacted_or_pass() {
    let mut s = services(true);
    s.firewall = Some(Arc::new(crate::security::firewall::Firewall::from_config(
        crate::security::firewall::FirewallConfig::default(),
        None,
    )));
    assert_eq!(s.firewall_verdict(Scan::Block, true), "block");
    assert_eq!(s.firewall_verdict(Scan::Pass, true), "redacted");
    assert_eq!(s.firewall_verdict(Scan::Pass, false), "pass");
}
