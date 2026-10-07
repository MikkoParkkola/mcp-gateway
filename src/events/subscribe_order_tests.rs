// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7944 `D6.EVENTS_MISC.4`: subscribe and refresh audits follow the order
//! of the commits they record.

use std::sync::Arc;
use std::time::Duration;

use super::{EventsHub, Probe, seed_verified, services, subscribe};
use crate::events::test_pause::within;

/// The lifecycle actions in the audit log, in log order.
fn lifecycle_actions(dir: &std::path::Path) -> Vec<String> {
    std::fs::read_to_string(dir.join("audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|r| r["action"].as_str().map(str::to_owned))
        .filter(|a| a == "events.subscribe" || a == "events.refresh")
        .collect()
}

/// Two subscribes for one subscription race: the first commits (an insert)
/// and stops before its audit; the second (a refresh) runs meanwhile. The
/// log still records the insert before the refresh.
#[tokio::test]
async fn a_racing_refresh_is_audited_after_the_insert_it_follows() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig::default();
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    hub.register_source(Arc::new(Probe::default()));
    let log = Arc::new(
        crate::security::TransparencyLogger::open(Arc::new(
            crate::security::TransparencyLogConfig {
                enabled: true,
                path: dir
                    .path()
                    .join("audit.jsonl")
                    .to_string_lossy()
                    .into_owned(),
                ..crate::security::TransparencyLogConfig::default()
            },
        ))
        .expect("log"),
    );
    let mut audited = services();
    audited.audit = Some(log);
    assert!(hub.runtime.services.set(Arc::new(audited)).is_ok());
    seed_verified(&hub, &config, "p");

    let (reached, release) = hub.after_commit.arm();
    let first = tokio::spawn({
        let hub = Arc::clone(&hub);
        async move { subscribe(&hub, "p").await }
    });
    within("the insert's pause", reached.notified()).await;
    let second = tokio::spawn({
        let hub = Arc::clone(&hub);
        async move { subscribe(&hub, "p").await }
    });
    // The refresh waits on the lifecycle lock the insert holds until its
    // audit is written; without that order it would finish here first.
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        while !second.is_finished() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    release.notify_one();
    within("the insert", first).await.expect("first");
    within("the refresh", second).await.expect("second");
    assert_eq!(
        lifecycle_actions(dir.path()),
        ["events.subscribe", "events.refresh"],
        "audit order follows commit order"
    );
}
