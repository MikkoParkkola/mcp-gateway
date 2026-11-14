// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A delivery's last write is its subscription's status line, which settling
//! rewrites on the blocking pool after the record is gone. A test that has
//! seen its callback can end while that write is still pending; the row's
//! folder must outlive it, or the write lands while the folder is removed and
//! leaves a lone `subs/` file in the temp root.

use super::fixtures::{counting_callback, delivery_hub, logged_services, offer, queued};
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_settle_still_writing_when_the_test_ends_keeps_the_folder() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let root = dir.path().to_owned();
    let hub = delivery_hub(&dir);
    // The audit log is the services' file, open until they drop, and Windows
    // cannot remove a folder holding an open file: it lives in its own folder,
    // so this one holds only what the delivery writes.
    let audit = crate::test_dir_keep::kept_tempdir();
    let services = logged_services(audit.path());
    let (port, _accepted) = counting_callback().await;
    offer(&hub, &["webhook.c.r.received"]);
    queued(&hub, port, "evt_late");
    let (reached, release) = hub.store.before_touch.arm();
    let attempt = tokio::spawn({
        let hub = Arc::clone(&hub);
        async move { hub.attempt(&services, "evt_late").await }
    });
    crate::test_pause::within("the settle's status write", reached.notified()).await;

    // The test body ends: its own share of the folder and its hub go first.
    drop(dir);
    drop(hub);
    let kept = root.exists();
    release.notify_one();
    crate::test_pause::within("the attempt", attempt)
        .await
        .expect("the attempt finishes");
    assert!(
        kept,
        "the folder went while the settle's status write was still pending"
    );
    assert!(
        !root.exists(),
        "the folder outlived the delivery's last handle"
    );
}
