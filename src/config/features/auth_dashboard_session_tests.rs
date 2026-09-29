// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! E5-T9 (MIK-7570.SESSION.1): dashboard session limits that cannot work
//! refuse to load, and the refusal names the bound it broke.

use super::DashboardSessionConfig;

fn refusal(idle: u64, absolute: u64) -> String {
    let mut config = crate::config::Config::default();
    config.auth.dashboard_session = DashboardSessionConfig {
        idle_timeout_secs: idle,
        absolute_timeout_secs: absolute,
    };
    config
        .validate()
        .expect_err("these limits must not load")
        .to_string()
}

#[test]
fn zero_or_inverted_timeouts_fail_to_load() {
    let zero_idle = refusal(0, 28_800);
    assert!(
        zero_idle.contains("auth.dashboard_session.idle_timeout_secs"),
        "{zero_idle}"
    );
    let zero_absolute = refusal(1800, 0);
    assert!(
        zero_absolute.contains("auth.dashboard_session.absolute_timeout_secs"),
        "{zero_absolute}"
    );
    let inverted = refusal(3600, 1800);
    assert!(
        inverted.contains("idle_timeout_secs") && inverted.contains("absolute_timeout_secs"),
        "{inverted}"
    );
}

#[test]
fn defaults_are_thirty_minutes_and_eight_hours() {
    let d = DashboardSessionConfig::default();
    assert_eq!(
        (d.idle_timeout_secs, d.absolute_timeout_secs),
        (1800, 28_800)
    );
    crate::config::Config::default()
        .validate()
        .expect("the defaults load");
}

#[test]
fn a_misspelled_limit_is_refused() {
    let parsed: Result<DashboardSessionConfig, _> = serde_yaml::from_str("idle_timeout: 60\n");
    assert!(
        parsed.is_err(),
        "an unknown key must not silently keep the default"
    );
}
