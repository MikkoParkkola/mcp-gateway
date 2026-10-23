// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8745 E1: a redacted `wrap_tool_success` answer is still the gateway's
//! own printing, so `delivered_value` reads it decoded. E2, the receipt staged
//! from that value, is pinned end to end by the relay rows in
//! `relay_plan_route.rs` (MIK-7998 DECODE.1 and DECODE.2).

use serde_json::json;

use super::delivered_value;
use crate::security::firewall::redactor::Redactor;

#[test]
fn a_redacted_pretty_wrapper_is_read_decoded() {
    let url = format!("{}://{}:{}@{}", "postgres", "u", "pw", "db.local:5432/app");
    let text = serde_json::to_string_pretty(&json!({ "dsn": url, "rows": 3 })).unwrap();
    let mut delivered = json!({ "content": [{ "type": "text", "text": text }] });
    Redactor::new().scan_and_redact(&mut delivered);
    let read = delivered_value(&delivered);
    assert!(
        matches!(read, std::borrow::Cow::Owned(_)),
        "the redacted block must stay the gateway's printing: {delivered}"
    );
    assert_eq!(*read, json!({ "dsn": "[REDACTED:credential]", "rows": 3 }));
}
