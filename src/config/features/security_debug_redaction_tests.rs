// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Debug output of the security configuration never carries a secret (CWE-532).

use super::*;

const SENTINEL: &str = "SENTINEL_SECRET_a1b2c3";

// TransparencyLogConfig::Debug must never surface the HMAC shared secret.
#[test]
fn transparency_log_config_debug_redacts_shared_secret() {
    let cfg = TransparencyLogConfig {
        shared_secret: SENTINEL.to_string(),
        ..TransparencyLogConfig::default()
    };
    let dbg = format!("{cfg:?}");
    assert!(!dbg.contains(SENTINEL), "leaked shared_secret: {dbg}");
    assert!(
        dbg.contains("<redacted>"),
        "missing redaction marker: {dbg}"
    );
}

// MessageSigningConfig::Debug must redact both the current and previous
// rotation secrets.
#[test]
fn message_signing_config_debug_redacts_both_secrets() {
    let cfg = MessageSigningConfig {
        shared_secret: SENTINEL.to_string(),
        previous_secret: format!("{SENTINEL}-prev"),
        ..MessageSigningConfig::default()
    };
    let dbg = format!("{cfg:?}");
    assert!(!dbg.contains(SENTINEL), "leaked signing secret: {dbg}");
    assert!(
        dbg.contains("<redacted>"),
        "missing redaction marker: {dbg}"
    );
}
