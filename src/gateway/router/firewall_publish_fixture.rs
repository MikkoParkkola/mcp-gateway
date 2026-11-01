// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A router test fixture's firewall, published as the live config's.

/// Publish `firewall`'s config as the live config's, so the checks that judge
/// under a generation (every answer, ADR-029, amended, item 5) read the rules
/// the fixture built the firewall with.
pub(crate) fn publish_firewall(
    state: &super::AppState,
    firewall: &crate::security::firewall::Firewall,
) {
    let mut config = (*state.live_config.get()).clone();
    config.security.firewall = firewall.config_for_test().clone();
    state.live_config.set(config);
}
