// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What each caller of the shared removal does when its directory sync fails:
//! the owner's unsubscribe answers an internal error and records nothing; the
//! withdraw reports a row it could not remove; a revoke leaves the row live.

use std::sync::Arc;

use serde_json::json;

use super::super::Services;
use super::super::rpc::subscription_id;
use super::super::types::RpcError;
use super::{NAME, Probe, caller, seed_verified, services, subscribe, url};
use crate::events::EventsHub;
use crate::events::records::sync_fault;

/// A hub on `dir` offering the probe's type, its lifecycle records written to
/// `audit` (an audit log, so a record that was never made can be counted).
fn hub_at(dir: &std::path::Path, audit: &std::path::Path) -> Arc<EventsHub> {
    let config = crate::config::EventsConfig::default();
    let hub = EventsHub::open(&config, dir).expect("hub");
    hub.register_source(Arc::new(Probe::default()));
    let log = crate::security::TransparencyLogConfig {
        enabled: true,
        path: audit.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let log = crate::security::TransparencyLogger::open(Arc::new(log)).expect("audit log");
    let _ = hub.runtime.services.set(Arc::new(Services {
        audit: Some(Arc::new(log)),
        ..services()
    }));
    hub
}

/// `p`'s subscription to the probe type, as `subscribe` makes it.
async fn subscribed(hub: &Arc<EventsHub>) -> String {
    seed_verified(hub, &crate::config::EventsConfig::default(), "p");
    subscribe(hub, "p").await;
    subscription_id("p", &url("p"), NAME, &json!({"k": "v"}))
}

async fn unsubscribe(hub: &Arc<EventsHub>) -> Result<serde_json::Value, RpcError> {
    let params = json!({"name": NAME, "arguments": {"k": "v"}, "delivery": {"url": url("p")}});
    hub.unsubscribe(&caller("p"), Some(&params)).await
}

/// The `detail` of each `events.unsubscribe` record in `audit`, waiting until
/// `want` of them have been written.
async fn unsubscribe_details(audit: &std::path::Path, want: usize) -> Vec<String> {
    let mut details = Vec::new();
    for _ in 0..100 {
        let text = std::fs::read_to_string(audit).unwrap_or_default();
        details = text
            .lines()
            .filter(|line| line.contains("events.unsubscribe"))
            .map(|line| {
                if line.contains("\"absent\"") {
                    "absent"
                } else if line.contains("\"removed\"") {
                    "removed"
                } else {
                    "?"
                }
                .to_owned()
            })
            .collect();
        if details.len() >= want {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    details
}

/// The owner hears an internal error, not `{}`, and nothing is recorded for
/// the failed call; the retry removes. After a failed call and a restart, the
/// owner's retry finds the row durably gone and answers `{}` ("absent").
#[tokio::test]
async fn unsub2_the_owner_hears_an_error_not_success() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let audit = dir.path().join("audit.jsonl");
    let subs = dir.path().join("subs");
    let hub = hub_at(dir.path(), &audit);
    let id = subscribed(&hub).await;
    sync_fault::arm(&subs, 1);
    let failed = unsubscribe(&hub).await;
    assert_eq!(
        failed.as_ref().err().map(|e| e.code),
        Some(RpcError::internal().code),
        "{failed:?}"
    );
    assert_eq!(
        sync_fault::armed(&subs),
        0,
        "the armed failure was not reached"
    );
    assert!(
        hub.store.get(&id).is_some(),
        "the row left memory on a failed sync"
    );
    assert_eq!(unsubscribe(&hub).await.expect("retry"), json!({}));
    assert_eq!(
        unsubscribe_details(&audit, 1).await,
        ["removed"],
        "the failed call was recorded"
    );

    let dir = crate::test_dir_keep::kept_tempdir();
    let subs = dir.path().join("subs");
    {
        let hub = hub_at(dir.path(), &dir.path().join("first.jsonl"));
        subscribed(&hub).await;
        sync_fault::arm(&subs, 1);
        assert!(unsubscribe(&hub).await.is_err());
    }
    let audit = dir.path().join("second.jsonl");
    let hub = hub_at(dir.path(), &audit);
    assert_eq!(unsubscribe(&hub).await.expect("after a restart"), json!({}));
    assert_eq!(unsubscribe_details(&audit, 1).await, ["absent"]);
}

/// Whether any captured log record carries `text`.
fn logged(records: &[serde_json::Value], text: &str) -> bool {
    records
        .iter()
        .any(|record| record.to_string().contains(text))
}

/// The withdraw and the revoke take the error too: the withdraw reports the
/// row it could not remove and warns, the revoke leaves it live and announces
/// nothing; each finishes on a second run whose sync succeeds. A plain test on
/// its own current-thread runtime, so the capture (thread-local) sees the logs.
#[test]
fn unsub2_withdraw_and_revoke_take_the_error() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let dir = crate::test_dir_keep::kept_tempdir();
    let subs = dir.path().join("subs");
    let hub = hub_at(dir.path(), &dir.path().join("audit.jsonl"));
    let id = rt.block_on(subscribed(&hub));
    let row = hub.store.get(&id).expect("row");
    sync_fault::arm(&subs, 1);
    let mut withdrawn = true;
    let logs = crate::test_log_capture::records(|| {
        withdrawn = hub.withdraw_rows(std::slice::from_ref(&row));
    });
    assert!(!withdrawn, "a failed sync reported as withdrawn");
    assert!(
        logged(&logs, "withdrawn subscription not removed"),
        "the failed withdraw did not warn: {logs:?}"
    );
    assert_eq!(sync_fault::armed(&subs), 0);
    assert!(
        hub.store.get(&id).is_some(),
        "the withdraw dropped the row on a failed sync"
    );
    assert!(hub.withdraw_rows(&[row]));
    assert!(hub.store.get(&id).is_none());

    let dir = crate::test_dir_keep::kept_tempdir();
    let subs = dir.path().join("subs");
    let hub = hub_at(dir.path(), &dir.path().join("audit.jsonl"));
    let id = rt.block_on(subscribed(&hub));
    let row = hub.store.get(&id).expect("row");
    sync_fault::arm(&subs, 1);
    let logs = crate::test_log_capture::records(|| rt.block_on(hub.revoke(&row)));
    assert_eq!(
        sync_fault::armed(&subs),
        0,
        "the revoke never reached the removal"
    );
    assert!(
        hub.store.get(&id).is_some(),
        "the revoke dropped the row on a failed sync"
    );
    assert!(
        !logged(&logs, "subscription revoked"),
        "a revoke whose removal failed announced it: {logs:?}"
    );
    // The control: the same capture sees the announcement once the removal holds.
    let logs = crate::test_log_capture::records(|| rt.block_on(hub.revoke(&row)));
    assert!(hub.store.get(&id).is_none());
    assert!(
        logged(&logs, "subscription revoked"),
        "the capture missed the revoke announcement: {logs:?}"
    );
}
