// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Capability publish on the live config: sequence order, and the running
//! revision after a gateway.yaml reload.
//!
//! Expected ids are `config_revision` over inputs built here from the literal
//! bytes and parts. For a loaded part that is the base encoder.
//!
//! A stale publish that arrives after attach is not here: nothing in this
//! file attaches.

use std::sync::Arc;
use std::time::Duration;

use super::LiveConfig;
use crate::config::Config;
use crate::config_reload::revision::{
    AppliedInputs, CapabilityPart, PartDigest, RawBytes, RawInputs, config_revision, part_digest,
};

const YAML: &[u8] = b"server:\n  port: 1\n";
const RELOADED: &[u8] = b"server:\n  port: 2\n";

fn key() -> [u8; 32] {
    crate::gateway::record_principal::test_record_key().config_revision_key()
}

fn part_a() -> CapabilityPart<PartDigest> {
    CapabilityPart::Loaded(vec![("caps/a.yaml".to_owned(), [0xa1; 32])])
}

fn part_b() -> CapabilityPart<PartDigest> {
    CapabilityPart::Loaded(vec![("caps/b.yaml".to_owned(), [0xb2; 32])])
}

/// The id of `yaml` with `part` and nothing else. Built from those literals,
/// not from a revision the live config published.
fn id_of(yaml: &[u8], part: CapabilityPart<PartDigest>) -> String {
    config_revision(
        &key(),
        &AppliedInputs {
            gateway_yaml: part_digest(&key(), yaml),
            capabilities: part,
            ..AppliedInputs::default()
        },
    )
}

fn started(yaml: &[u8], capabilities: CapabilityPart<RawBytes>) -> LiveConfig {
    LiveConfig::new(Config::default())
        .with_revision_key(key())
        .with_applied(RawInputs {
            gateway_yaml: yaml.to_vec(),
            capabilities,
            ..RawInputs::default()
        })
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

fn published_id(live: &LiveConfig) -> String {
    live.applied_now()
        .published
        .expect("a revision is published")
        .revision
        .clone()
}

/// Seq 2 then seq 1: seq 2's id stays.
#[test]
fn l1_an_older_seq_does_not_replace() {
    let live = Arc::new(started(YAML, CapabilityPart::default()));
    let step = Arc::clone(&live);
    within_30s(move || {
        step.set_capabilities(2, part_a());
        step.set_capabilities(1, part_b());
    });
    let id = published_id(&live);
    assert_eq!(id, id_of(YAML, part_a()), "seq 2's id stays");
    assert_ne!(id, id_of(YAML, part_b()), "seq 1 is not published");
}

/// The same seq twice publishes once: the id is A's, and the second call
/// does not publish again.
#[test]
fn l1_the_same_seq_twice_publishes_once() {
    let live = Arc::new(started(YAML, CapabilityPart::default()));
    let step = Arc::clone(&live);
    within_30s(move || step.set_capabilities(2, part_a()));
    let once = live
        .applied_now()
        .published
        .expect("a revision is published");
    assert_eq!(
        once.revision,
        id_of(YAML, part_a()),
        "seq 2 publishes A's id"
    );
    let step = Arc::clone(&live);
    within_30s(move || step.set_capabilities(2, part_a()));
    let twice = live
        .applied_now()
        .published
        .expect("a revision is published");
    assert!(
        Arc::ptr_eq(&once, &twice),
        "the second call publishes nothing"
    );
    assert_eq!(twice.revision, id_of(YAML, part_a()), "the id stays A's");
}

/// A gateway.yaml reload while the capability part is still NotLoaded, then
/// the first capability publish. `set_applied` is the publish that reload makes.
#[test]
fn r2x_yaml_reload_then_first_capability_publish() {
    let part = part_a();
    let running_id = id_of(YAML, part.clone());
    let reloaded_id = id_of(RELOADED, part.clone());
    assert_ne!(
        running_id, reloaded_id,
        "the two files must name different revisions"
    );

    let live = Arc::new(started(YAML, CapabilityPart::NotLoaded));
    let generation = Arc::new(
        live.prepare(Config::default(), &crate::config::EnvOverlay::none())
            .expect("the reloaded config prepares"),
    );
    let step = Arc::clone(&live);
    let published_part = part.clone();
    within_30s(move || {
        step.set_applied(
            generation,
            RawInputs {
                gateway_yaml: RELOADED.to_vec(),
                capabilities: CapabilityPart::NotLoaded,
                ..RawInputs::default()
            },
            &[],
        );
        step.set_capabilities(1, published_part);
    });

    let now = live.applied_now();
    let running = now.running.as_deref();
    let published = now
        .published
        .as_ref()
        .map(|applied| applied.revision.as_str());
    assert!(
        running.is_some() && published.is_some(),
        "applied_now returns both"
    );
    assert_eq!(
        running,
        Some(running_id.as_str()),
        "running is the startup inputs with the published capability part"
    );
    assert_ne!(
        running, published,
        "running differs from the published revision"
    );
    assert_eq!(
        published,
        Some(reloaded_id.as_str()),
        "published is the reloaded gateway.yaml with the capability part"
    );
}
