// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8745 E1/E2: a redacted `wrap_tool_success` answer is still the
//! gateway's own printing, so `delivered_value` reads it decoded and the final
//! receipt is staged from the redacted value the caller reads.

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
