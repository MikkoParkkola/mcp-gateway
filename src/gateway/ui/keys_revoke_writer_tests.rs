// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! R5/R6: red until DELETE, `KeyRevoke` and lock-held receipt markers land.
use super::super::keys_create_fixture_tests::{item, root_item, yaml_of};
use super::keys_revoke_target_tests::{tag, target_setup};
use super::*;
use crate::config_persistence::{
    journal,
    lock::{NotLocked, lock_config},
};
use crate::config_reload::{ConfigWriteError, write_order};
use std::{
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};

fn revoke(fx: &Fixture, rev: &str) -> Sent {
    send_delete(
        fx,
        "target",
        Call::new(&json!({
            "revision": rev, "expected_key_tag": tag("target-secret")
        })),
        None,
    )
}

fn ordered(steps: &[&str], expected: &[&str]) {
    let positions: Vec<_> = expected
        .iter()
        .map(|e| steps.iter().position(|s| s == e))
        .collect();
    assert!(
        positions.iter().all(Option::is_some),
        "missing markers: {steps:?}"
    );
    assert!(
        positions.windows(2).all(|p| p[0] < p[1]),
        "wrong order: {steps:?}"
    );
}

#[test]
fn revoke_writes_through_the_audited_writer() {
    let mut setup = target_setup();
    setup
        .text
        .push_str(&item("survivor", "survivor-secret", "      # keep me\n"));
    setup.text.insert_str(0, "# preserve config comments\n");
    let fx = Fixture::new(setup);
    let before = fx.text();
    let target = crate::identity_grants::journal::resolved(&fx.path());
    let audit = fx.dir.path().join("audit.jsonl");
    let durable = Arc::new(Mutex::new(false));
    let seen = Arc::clone(&durable);
    write_order::on(
        &target,
        "intent",
        Arc::new(move || {
            *seen.lock().unwrap() = std::fs::read_to_string(&audit)
                .unwrap_or_default()
                .contains("config_key_revoke_intent");
        }),
    );
    let sent = revoke(&fx, &revision(&fx));
    let steps = write_order::take(&target);
    // RED: missing DELETE and IntentKind::KeyRevoke / config_key_revoke_intent.
    assert_eq!(sent.status, StatusCode::OK, "{}", sent.body);
    let records = fx.records("config_key_revoke_intent");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["who"], fx.who(&admin_client()));
    assert_eq!(records[0]["subject"], "target");
    assert!(
        *durable.lock().unwrap(),
        "intent must already be durable at its marker"
    );
    assert!(steps.contains(&"target_compute")); // Positive control for the stale row.
    ordered(&steps, &["intent", "commit", "reload"]); // RED: reload marker missing.
    assert_eq!(
        fx.bytes(),
        before
            .replacen(&item("target", "target-secret", ""), "", 1)
            .as_bytes()
    );
}

#[test]
fn pending_recovery_runs_before_the_revision_check() {
    let fx = Fixture::new(target_setup());
    let target = crate::identity_grants::journal::resolved(&fx.path());
    let original = fx.bytes();
    journal::stage_original(&target, &original).unwrap();
    journal::begin(&target, fx.revision()).unwrap();
    std::fs::write(&target, format!("{}\n# crashed rename\n", fx.text())).unwrap();
    let stale = revision(&fx);
    let sent = revoke(&fx, &stale);
    let steps = write_order::take(&target);
    // RED: missing DELETE; recovery must restore bytes before declaring stale.
    assert_eq!(sent.status, StatusCode::CONFLICT, "{}", sent.body);
    assert_eq!(
        sent.json(),
        json!({"error": "stale", "current": fx.revision()})
    );
    assert_eq!(fx.bytes(), original);
    assert_eq!(fx.records("config_recovery_intent").len(), 1);
    assert!(!journal::journal_path(&target).exists());
    assert!(fx.records("config_key_revoke_intent").is_empty());
    // RED: target_compute marker required at entry to revoke's compute closure.
    assert!(
        !steps.contains(&"target_compute"),
        "stale reached target compute"
    );
}

#[test]
fn an_unchanged_byte_reconciliation_still_audits_and_reloads() {
    let mut setup = target_setup();
    setup.text = yaml_of(&[root_item()]);
    let fx = Fixture::new(setup);
    let before = fx.bytes();
    assert!(
        fx.live
            .generation()
            .auth()
            .validate_token("target-secret")
            .is_some()
    );
    let matched = revision(&fx);
    let sent = revoke(&fx, &matched);
    // RED: missing DELETE and KeyRevoke; unchanged bytes still require publication.
    assert_eq!(sent.status, StatusCode::OK, "{}", sent.body);
    assert_eq!(
        sent.json(),
        json!({"name": "target", "revoked": true, "revision": matched})
    );
    assert_eq!(fx.bytes(), before);
    assert_eq!(fx.records("config_key_revoke_intent").len(), 1);
    assert!(
        fx.live
            .generation()
            .auth()
            .validate_token("target-secret")
            .is_none()
    );
}

#[test]
fn the_receipt_is_taken_with_both_locks_held() {
    let fx = Fixture::new(target_setup());
    let target = crate::identity_grants::journal::resolved(&fx.path());
    let registry = Arc::clone(&fx.state.backends);
    let (arrived, reached) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let released = Mutex::new(released);
    // RED: writer must record reload after publication, immediately before receipt.
    // Bounded writer-thread pause, like the test pause hook; never assert while parked.
    write_order::on(
        &target,
        "reload",
        Arc::new(move || {
            let _ = arrived.send(());
            let _ = released
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(30));
        }),
    );
    let request = std::thread::spawn(move || {
        let sent = revoke(&fx, &revision(&fx));
        (fx, sent)
    });
    let parked = reached.recv_timeout(Duration::from_secs(10)).is_ok();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (reload_busy, file_busy) = rt.block_on(async {
        #[allow(
            clippy::disallowed_methods,
            reason = "Test directly probes the reload lock"
        )]
        let reload = tokio::time::timeout(Duration::ZERO, registry.lock_reload())
            .await
            .map_err(|_| ConfigWriteError::Busy);
        let busy = matches!(reload, Err(ConfigWriteError::Busy));
        drop(reload);
        let file = lock_config(&target, Instant::now()).await;
        (busy, matches!(file, Err(NotLocked::Busy)))
    });
    let _ = release.send(()); // Always release before join or any assertion.
    let (fx, sent) = request.join().unwrap();
    let steps = write_order::take(&target);
    assert!(parked, "RED: missing DELETE/post-reload receipt pause");
    assert!(reload_busy, "reload lock was released before receipt");
    assert!(file_busy, "sidecar lock was released before receipt");
    assert_eq!(sent.status, StatusCode::OK, "{}", sent.body);
    assert_eq!(sent.json()["revoked"], true);
    ordered(
        &steps,
        &[
            "intent",
            "commit",
            "reload",
            "receipt",
            "file_unlock",
            "reload_unlock",
        ],
    );
    assert!(
        fx.live
            .generation()
            .auth()
            .validate_token("target-secret")
            .is_none()
    );
}

#[test]
fn no_receipt_while_the_published_generation_still_accepts_the_key() {
    let mut setup = target_setup();
    setup.split_live = Some(setup.running.clone());
    let fx = Fixture::new(setup);
    let sent = revoke(&fx, &revision(&fx));
    // RED: missing DELETE; require a landed removal so a 404 cannot pass this row.
    assert_eq!(fx.bytes(), yaml_of(&[root_item()]).as_bytes());
    assert!(
        fx.live
            .generation()
            .auth()
            .validate_token("target-secret")
            .is_some()
    );
    assert_ne!(sent.json()["revoked"], true);
}
