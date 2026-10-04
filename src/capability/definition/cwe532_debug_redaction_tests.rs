// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;

const SENTINEL: &str = "SENTINEL_SECRET_a1b2c3";

// WebhookDefinition::Debug must never surface the HMAC verification secret.
#[test]
fn webhook_definition_debug_redacts_secret() {
    let w = WebhookDefinition {
        path: "/linear/webhook".to_string(),
        method: "POST".to_string(),
        secret: Some(SENTINEL.to_string()),
        signature_header: Some("X-Linear-Signature".to_string()),
        notify: true,
        transform: WebhookTransform::default(),
        event: None,
    };
    let dbg = format!("{w:?}");
    assert!(!dbg.contains(SENTINEL), "leaked webhook secret: {dbg}");
    assert!(
        dbg.contains("<redacted>"),
        "missing redaction marker: {dbg}"
    );
    assert!(
        dbg.contains("/linear/webhook"),
        "path should stay visible: {dbg}"
    );
}
