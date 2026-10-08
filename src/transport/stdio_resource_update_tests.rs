// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Resource-update relay over stdio, split out of `stdio_tests.rs` to keep it
//! under the file-size ceiling.

use super::*;

/// MIK-7570.ATTEST.1 (owner ruling, option A): the gateway relays no backend
/// `notifications/resources/updated` to any caller, even with a call open, so
/// a `resources/subscribe` attested under enforce grants no data flow for the
/// token's expiry to end. If this ever starts delivering, subscription expiry
/// needs a design (an attested subscription must stop at the token's `exp`).
#[tokio::test]
async fn stdio_relays_no_resource_update_so_attestation_expiry_has_nothing_to_end() {
    let t = make_transport("cat");
    let update = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/resources/updated",
        "params": { "uri": "file:///a" }
    })
    .to_string();

    let ((), drained) = crate::transport::notification_sink::collect(async {
        let _ = t.register_progress_token("tok-open-call");
        t.handle_response(&update).unwrap();
    })
    .await;

    assert!(
        drained.is_empty(),
        "a resource update must reach no caller: {drained:?}"
    );
}
