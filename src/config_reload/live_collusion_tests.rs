// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Restart classification once the relay gate judges with the generation's
//! view (ADR-029, amended, item 6): the four live collusion fields apply on
//! reload, so an edit to only them is not restart-pending; the detector's
//! own window and thresholds are fixed at startup, so an edit to them is.

use super::LiveConfig;
use crate::config::Config;
use crate::security::firewall::{AllowedFlow, CollusionAction};

type Edit = fn(&mut Config);

/// The restart-pending sections after publishing `wanted` over `running`.
fn pending(running: &Config, wanted: Config) -> Vec<&'static str> {
    let live = LiveConfig::new(running.clone());
    live.set(wanted);
    live.pending_restart_fields()
}

const LIVE: [(&str, Edit); 4] = [
    ("action", |c| {
        c.security.firewall.collusion.action = CollusionAction::Block;
    }),
    ("sources", |c| {
        c.security.firewall.collusion.sources.push("mail:*".into());
    }),
    ("non_egress", |c| {
        c.security
            .firewall
            .collusion
            .non_egress
            .push("mail:send".into());
    }),
    ("allowed_flows", |c| {
        c.security
            .firewall
            .collusion
            .allowed_flows
            .push(AllowedFlow {
                source: "mail:*".into(),
                egress: "mail:send".into(),
            });
    }),
];

const DETECTOR: [(&str, Edit); 3] = [
    ("window_secs", |c| {
        c.security.firewall.collusion.window_secs += 1;
    }),
    ("min_matches", |c| {
        c.security.firewall.collusion.min_matches += 1;
    }),
    ("common_principals", |c| {
        c.security.firewall.collusion.common_principals += 1;
    }),
];

/// F6.1: each live collusion field alone is not restart-pending. RED on
/// base: the flag that says the gate reads them live is off.
#[test]
fn f6_1_a_live_collusion_field_alone_is_not_restart_pending() {
    for (name, edit) in LIVE {
        let running = Config::default();
        let mut wanted = running.clone();
        edit(&mut wanted);
        assert!(
            !pending(&running, wanted).contains(&"security"),
            "F6.1: a change to collusion.{name} alone is restart-pending"
        );
    }
}

/// F6.2: a detector parameter, alone or beside a live field, needs a
/// restart. GREEN pin on base.
#[test]
fn f6_2_a_detector_parameter_stays_restart_pending() {
    for (name, edit) in DETECTOR {
        let running = Config::default();
        let mut alone = running.clone();
        edit(&mut alone);
        assert!(
            pending(&running, alone).contains(&"security"),
            "F6.2: collusion.{name} alone is not restart-pending"
        );
        let mut beside = running.clone();
        edit(&mut beside);
        LIVE[1].1(&mut beside);
        assert!(
            pending(&running, beside).contains(&"security"),
            "F6.2: collusion.{name} beside a live field is not restart-pending"
        );
    }
}

/// F6.3: with the firewall off, the detector does not run the edit, so a live
/// field still needs a restart. GREEN pin on base.
#[test]
fn f6_3_a_live_field_with_the_firewall_off_is_restart_pending() {
    let mut running = Config::default();
    running.security.firewall.enabled = false;
    let mut wanted = running.clone();
    LIVE[1].1(&mut wanted);
    assert!(
        pending(&running, wanted).contains(&"security"),
        "F6.3: a live field applied with the firewall off"
    );
}
