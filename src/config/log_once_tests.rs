// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The port-0 warning is logged once, not on every reload (#1286).

use std::sync::atomic::AtomicBool;

use super::warn_port_zero;
use crate::test_log_capture::{count, records};

/// L1: a failed reload retried five times warns about port 0 once.
#[test]
fn l1_the_port_zero_warning_is_logged_once_across_reloads() {
    let warned = AtomicBool::new(false);
    let logs = records(|| {
        for _ in 0..5 {
            warn_port_zero(0, &warned);
        }
    });
    assert_eq!(count(&logs, "WARN", "Server port is 0"), 1);
}

/// L2: a non-zero port never warns.
#[test]
fn l2_a_set_port_does_not_warn() {
    let warned = AtomicBool::new(false);
    let logs = records(|| warn_port_zero(8080, &warned));
    assert_eq!(count(&logs, "WARN", "Server port is 0"), 0);
}

/// L5: a role-mapping rule that grants admin, validated on every retried
/// reload, announces the widening once.
#[test]
fn l5_the_role_mapping_admin_widening_is_logged_once_across_reloads() {
    let mapping: crate::control_plane::role_mapping::ControlPlaneRoleMappingConfig =
        serde_yaml::from_str(
            "rules: [{issuer: 'https://l5.issuer.example', group: admins, role: admin}]",
        )
        .expect("rule parses");
    let logs = records(|| {
        for _ in 0..3 {
            mapping.validate().expect("valid");
        }
    });
    assert_eq!(count(&logs, "WARN", "https://l5.issuer.example"), 1);
}

/// L6: dormant declared agent entries, validated on every retried reload,
/// are warned about once.
#[test]
fn l6_dormant_declared_agents_are_logged_once_across_reloads() {
    let identity: crate::security::agent_identity::AgentIdentityConfig =
        serde_yaml::from_str("enabled: false\nknown_agents: [{source: declared, id: l6-agent}]")
            .expect("config parses");
    let logs = records(|| {
        for _ in 0..3 {
            identity.validate().expect("valid");
        }
    });
    assert_eq!(count(&logs, "WARN", "dormant while"), 1);
}
