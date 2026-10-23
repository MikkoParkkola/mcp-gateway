// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `stale_check_secs` parsing and default (MIK-8651 HEAL.1).

use super::*;

/// MIK-8651.HEAL.1: the stale-catalogue check defaults to 60 s, an old config
/// without the key parses unchanged, and 0 turns the check off.
#[test]
fn stale_check_secs_config() {
    assert_eq!(CapabilityConfig::default().stale_check_secs, 60);
    let old: CapabilityConfig =
        crate::yaml::from_str("enabled: true\nname: gateway\ndirectories:\n  - capabilities\n")
            .expect("an old config without the key parses");
    assert_eq!(old.stale_check_secs, 60);
    let off: CapabilityConfig =
        crate::yaml::from_str("stale_check_secs: 0\n").expect("stale_check_secs: 0 parses");
    assert_eq!(off.stale_check_secs, 0);
}
