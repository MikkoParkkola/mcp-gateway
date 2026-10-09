// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8014 design item 3: the dispatch tail wraps its answer in a grant slot
//! only when that opens one. With no log, or with a slot already open (the
//! HTTP handler opens it), the wrap boxes the future and clones the id for
//! nothing.

use std::borrow::Cow;
use std::sync::Arc;

use serde_json::json;

use super::grant_audit::{grant_bookkeeping_for_test, with_grant_slot};
use super::session_inflight_tests::context;
use crate::protocol::RequestId;

async fn dispatch(meta: &super::MetaMcp) {
    let retry = crate::protocol::mrtr::RetryFields::default();
    let response = meta
        .dispatch_below_gate(
            RequestId::Number(1),
            "gateway_list_servers",
            Cow::Owned(json!({})),
            Some("s"),
            &context(&retry),
            false,
        )
        .await;
    assert!(response.error.is_none(), "{response:?}");
}

fn idle_wraps() -> usize {
    grant_bookkeeping_for_test().idle_wraps
}

#[tokio::test(flavor = "current_thread")]
async fn no_log_no_slot_wrap() {
    let meta = super::MetaMcp::new(Arc::new(crate::backend::BackendRegistry::new()));
    let before = idle_wraps();
    dispatch(&meta).await;
    assert_eq!(
        idle_wraps() - before,
        0,
        "with no log the dispatch tail wrapped a slot that opens nothing"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn an_open_slot_is_not_wrapped_again() {
    let file = tempfile::NamedTempFile::new().expect("log file");
    let config = crate::security::TransparencyLogConfig {
        enabled: true,
        path: file.path().to_string_lossy().to_string(),
        key_id: "wrap".to_string(),
        ..crate::security::TransparencyLogConfig::default()
    };
    let logger =
        Arc::new(crate::security::TransparencyLogger::open(Arc::new(config)).expect("logger"));
    let mut meta = super::MetaMcp::new(Arc::new(crate::backend::BackendRegistry::new()));
    meta.enable_transparency_log(Arc::clone(&logger));
    let before = idle_wraps();
    // The HTTP handler's slot, opened first.
    let ((), written, _) = with_grant_slot(Some(&logger), dispatch(&meta)).await;
    written.expect("slot write");
    assert_eq!(
        idle_wraps() - before,
        0,
        "the dispatch tail wrapped again inside an open slot"
    );
}
