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
        public_provenance: None,
        #[cfg(feature = "cost-governance")]
        budget: None,
        credentials: LiveCredentials::default(),
        record_key: Some(crate::gateway::record_principal::test_key_arc()),
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

/// MIK-8794: a replay's verdict. The fresh scan decides `block`; a fresh
/// `pass` over a stored body that was redacted and still holds the marker
/// stays `redacted`; a stored verdict adds nothing otherwise.
#[test]
fn a_replay_verdict_carries_a_redaction_forward() {
    for (fresh, stored, holds_marker, want) in [
        ("block", Some("redacted"), true, "block"),
        ("block", Some("pass"), false, "block"),
        ("redacted", Some("pass"), false, "redacted"),
        ("pass", Some("redacted"), true, "redacted"),
        ("pass", Some("block"), true, "redacted"),
        ("pass", Some("block"), false, "pass"),
        ("pass", Some("redacted"), false, "pass"),
        ("pass", Some("pass"), true, "pass"),
        ("pass", None, true, "pass"),
        ("none", Some("redacted"), true, "none"),
    ] {
        assert_eq!(
            carried(fresh, stored, holds_marker),
            want,
            "fresh {fresh}, stored {stored:?}, marker {holds_marker}"
        );
    }
}

/// Without a firewall a replay records `none`, whatever was stored.
#[test]
fn a_replay_without_a_firewall_records_none() {
    let s = services(false);
    let body = br#"{"data":"[REDACTED:credential]"}"#;
    assert_eq!(
        s.replay_verdict(Scan::Pass, false, Some("redacted"), body),
        "none"
    );
}
