// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The real-watcher rows for a Capistrano-style release-directory link: its
//! retarget is followed whether it is done by rename or by unlink and
//! re-create. Moved from `watch_chain_tests.rs` for the file-size ceiling.

use super::real_watcher::{capistrano, start};
use super::*;

/// T11: a Capistrano `current` retarget (by rename) is followed.
#[tokio::test]
async fn t11_a_release_directory_link_retarget_is_followed() {
    let (_root, r) = capistrano();
    let mut h = start(&r.join("current").join("cfg.yaml"));
    h.wait_wakes_above(0).await;
    assert!(
        h.chain.watched().contains(&canonical(&r)),
        "R is not watched"
    );
    retarget(&r.join("current"), Path::new("rel2"));
    h.wait_watched(&r.join("rel2")).await;
    h.drain_idle().await;
    std::fs::write(r.join("rel2").join("cfg.yaml"), "b: 2\n").unwrap();
    assert!(
        h.triggered_within(10).await,
        "a write to the new release reloaded nothing"
    );
    let _ = h.shutdown.send(());
}

/// T13: the same retarget done as unlink then re-create.
#[tokio::test]
async fn t13_a_non_atomic_release_link_retarget_is_followed() {
    let (_root, r) = capistrano();
    let mut h = start(&r.join("current").join("cfg.yaml"));
    h.wait_wakes_above(0).await;
    let seen = h.wakes();
    std::fs::remove_file(r.join("current")).unwrap();
    h.wait_wakes_above(seen).await;
    assert_eq!(
        h.chain.watched(),
        set(&[&r, &r.join("rel1")]),
        "the last good set was dropped"
    );
    symlink("rel2", r.join("current")).unwrap();
    h.wait_watched(&r.join("rel2")).await;
    h.drain_idle().await;
    std::fs::write(r.join("rel2").join("cfg.yaml"), "b: 2\n").unwrap();
    assert!(
        h.triggered_within(10).await,
        "a write to the new release reloaded nothing"
    );
    let _ = h.shutdown.send(());
}
