// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The record around the first capability publish, loaded through the real
//! config loader.
//!
//! The covered id is `config_revision` over the loader's inputs with the
//! literal part substituted. It is not a revision the live config published.

use std::sync::Arc;
use std::time::Duration;

use super::{Coverage, Decided, Decision, Noted, Refused};
use crate::config::Config;
use crate::config_reload::LiveConfig;
use crate::config_reload::revision::{AppliedInputs, CapabilityPart, PartDigest, config_revision};
use crate::gateway::test_helpers::write_owner_only;

fn part() -> CapabilityPart<PartDigest> {
    CapabilityPart::Loaded(vec![("caps/a.yaml".to_owned(), [0x11; 32])])
}

fn record(live: &LiveConfig) -> Decision {
    Noted::default().decision(
        Decided::Fresh,
        Refused::No,
        Some(live),
        crate::security::audit::CredentialKind::None,
    )
}

/// A step that takes the publish locks. A deadlock fails at 30s. The bound
/// is the channel's own timeout.
fn within_30s(step: impl FnOnce() + Send + 'static) {
    let (done, wait) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        step();
        let _ = done.send(());
    });
    match wait.recv_timeout(Duration::from_secs(30)) {
        Ok(()) => worker.join().expect("the step panicked"),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!("hung past 30s"),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            std::panic::resume_unwind(worker.join().expect_err("the step ended without reporting"));
        }
    }
}

/// Before the first publish the record says `not_loaded` and names an id other
/// than the first covered one. The first record after the publish says covered.
#[test]
fn r1x_record_around_the_first_capability_publish() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(
        &path,
        "capabilities:\n  enabled: true\n  directories:\n    - caps\n",
    )
    .expect("write gateway.yaml");
    let mut evaluated = Config::load_evaluated(Some(&path)).expect("the loader reads the file");
    assert!(
        evaluated.config.capabilities.enabled,
        "the file enables capabilities"
    );
    assert_eq!(
        evaluated.config.capabilities.directories,
        vec!["caps".to_owned()],
        "the loader read this file"
    );

    let record_key = crate::gateway::record_principal::test_record_key();
    let revision_key = record_key.config_revision_key();
    let raw = std::mem::take(&mut evaluated.inputs);
    let mut covered = AppliedInputs::digest(&revision_key, raw.clone());
    covered.capabilities = part();
    let covered_id = config_revision(&revision_key, &covered);

    let live = LiveConfig::new(evaluated.config).with_startup_revision(&record_key, Some(raw));
    let before = record(&live);
    assert!(
        before.config_revision.is_some(),
        "the startup load published a revision"
    );
    assert_eq!(
        before.config_revision_capabilities,
        Some(Coverage::NotLoaded),
        "before the first publish the record says not_loaded"
    );
    assert_ne!(
        before.config_revision.as_deref(),
        Some(covered_id.as_str()),
        "that id is not the first covered id"
    );

    let live = Arc::new(live);
    let step = Arc::clone(&live);
    within_30s(move || step.set_capabilities(1, part()));
    let after = record(&live);
    assert_eq!(
        after.config_revision_capabilities,
        Some(Coverage::Covered),
        "the first record after the publish says covered"
    );
    assert_eq!(
        after.config_revision.as_deref(),
        Some(covered_id.as_str()),
        "that id is the startup inputs with the published capability part"
    );
}
