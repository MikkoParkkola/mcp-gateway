// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202 part 2 (P2), T1: the startup warning that lists expired API keys,
//! on a host clock that reads before 1970. The listing is advisory, so a clock
//! that cannot date a key lists nothing and says why, once. Key admission is
//! an access check and already fails closed (PR1); it is not what this pins.

use super::ResolvedAuthConfig;
use crate::config::AuthConfig;
use crate::test_log_capture::capture_warnings;

const EXPIRED_NOTICE: &str = "has expired and will be refused";

/// A config with one key that lapsed in 2001.
fn config_with_a_lapsed_key() -> AuthConfig {
    serde_json::from_value(serde_json::json!({
        "enabled": true,
        "api_keys": [{
            "name": "lapsed-key",
            "key_sha256": format!("sha256:{}", crate::hashing::sha256_hex(b"k-lapsed")),
            "backends": ["*"],
            "expires_at": "2001-01-01T00:00:00Z"
        }]
    }))
    .expect("auth config fixture deserializes")
}

/// The WARN lines startup logs while resolving `config`.
fn startup_warnings(config: &AuthConfig) -> String {
    let (resolved, warnings) = capture_warnings(|| {
        ResolvedAuthConfig::try_from_config(config, &crate::config::EnvOverlay::none())
    });
    resolved.expect("the config resolves");
    warnings
}

/// MIK-8202 rule RECORDER/ADVISORY (P2 row 1): on a clock before 1970 the
/// listing names no key and warns once that the clock cannot be read. Mutants:
/// list the key at epoch 0 or at a 1969 date; warn nothing.
#[test]
fn t1_expired_key_listing_on_an_unreadable_clock_lists_nothing_and_names_the_clock() {
    // GIVEN: a lapsed key and a host clock before 1970
    let config = config_with_a_lapsed_key();
    let _clock = crate::clock::test_clock::before_epoch();
    // WHEN
    let warnings = startup_warnings(&config);
    // THEN
    assert!(
        !warnings.contains(EXPIRED_NOTICE),
        "no key is listed as expired on a clock that cannot date it: {warnings}"
    );
    let about_the_clock = warnings
        .lines()
        .filter(|line| line.to_lowercase().contains("clock"))
        .count();
    assert_eq!(
        about_the_clock, 1,
        "one warning names the clock: {warnings}"
    );
}

/// Positive control for T1: on a readable clock the same lapsed key is listed
/// by name, so the row above cannot pass by never listing anything.
#[test]
fn t1_control_a_readable_clock_still_lists_the_expired_key() {
    let warnings = startup_warnings(&config_with_a_lapsed_key());
    assert!(warnings.contains(EXPIRED_NOTICE), "{warnings}");
    assert!(warnings.contains("lapsed-key"), "{warnings}");
}
