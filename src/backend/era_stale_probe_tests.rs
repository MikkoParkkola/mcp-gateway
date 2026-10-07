// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7217.ERA.1 / ERA.2 / ERA.3: a re-probe's answer from a replaced transport is refused.
//!
//! Design: `docs/design/2026-09-30-era-1-2-stale-probe-refusal.md`. The probe holds the era
//! lock while it waits, so reading the era observation after the peer has answered blocks until
//! the detached task has decided: that is the completion barrier, never a sleep.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};
use tokio::sync::oneshot;

use super::era::with_serving;
use super::*;
use crate::Result;
use crate::config::TransportConfig;
use crate::protocol::era::{Era, EraObservation, EraSource, METHOD_NOT_FOUND_CODE};
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::transport::Transport;

pub(super) const DISCOVER: &str = "server/discover";
/// A failure bound, never a synchronisation delay: nothing waits this long when the code works.
pub(super) const WAIT: Duration = Duration::from_secs(20);

/// What a peer answers `server/discover` with.
#[derive(Clone, Copy)]
pub(super) enum Answer {
    Modern,
    MethodNotFound,
}

/// A peer whose `server/discover` can be held mid-flight once armed.
pub(super) struct Peer {
    answer: Answer,
    /// While false, `server/discover` answers at once (the priming probe).
    pub(super) hold: AtomicBool,
    started: std::sync::Mutex<Option<oneshot::Sender<()>>>,
    release: std::sync::Mutex<Option<oneshot::Receiver<()>>>,
}

pub(super) struct Handles {
    pub(super) started: oneshot::Receiver<()>,
    pub(super) release: oneshot::Sender<()>,
}

impl Peer {
    pub(super) fn new(answer: Answer) -> (Arc<Self>, Handles) {
        let (started_tx, started) = oneshot::channel();
        let (release, release_rx) = oneshot::channel();
        let peer = Arc::new(Self {
            answer,
            hold: AtomicBool::new(false),
            started: std::sync::Mutex::new(Some(started_tx)),
            release: std::sync::Mutex::new(Some(release_rx)),
        });
        (peer, Handles { started, release })
    }
}

#[async_trait]
impl Transport for Peer {
    async fn request(&self, method: &str, _params: Option<Value>) -> Result<JsonRpcResponse> {
        if method == DISCOVER && self.hold.load(Ordering::SeqCst) {
            if let Some(tx) = self.started.lock().unwrap().take() {
                let _ = tx.send(());
            }
            let rx = self.release.lock().unwrap().take();
            if let Some(rx) = rx {
                let _ = rx.await;
            }
        }
        let id = RequestId::Number(1);
        Ok(match (method, self.answer) {
            (DISCOVER, Answer::Modern) => JsonRpcResponse::success_serialized(
                id,
                json!({
                    "supportedVersions": [crate::protocol::meta::MODERN_VERSIONS[0]],
                    "capabilities": {},
                }),
            ),
            (DISCOVER, Answer::MethodNotFound) => {
                JsonRpcResponse::error(Some(id), METHOD_NOT_FOUND_CODE, "method not found")
            }
            _ => JsonRpcResponse::success_serialized(id, json!({})),
        })
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

/// A gateway-owned backend whose command cannot spawn, so a restart takes the old transport out
/// and its replacement start fails at once; what happens to the era is settled before that.
fn backend() -> Arc<Backend> {
    let config = BackendConfig {
        transport: TransportConfig::Stdio {
            command: "/nonexistent-mcp-binary".to_string(),
            cwd: None,
            protocol_version: None,
        },
        ..BackendConfig::default()
    };
    Arc::new(Backend::new(
        "era-stale-probe",
        config,
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ))
}

fn discarded(records: &[Value]) -> Vec<&Value> {
    records
        .iter()
        .filter(|record| record["fields"]["reason"] == "transport_replaced")
        .collect()
}

/// The refused record is about the old peer's real answer, not a timeout.
fn assert_about_the_modern_answer(records: &[Value]) {
    let fields = &discarded(records)[0]["fields"];
    assert_eq!(fields["evidence"], "discover_modern", "{fields}");
    assert_eq!(fields["trigger"], "reprobe", "{fields}");
}

/// Modern is cached from `peer`, then a `-32601` to `server/discover` contradicts it and a
/// re-probe of `peer` starts and is held mid-flight. Returns once the probe is on the wire.
async fn contradicted_and_probing(
    backend: &Arc<Backend>,
    peer: &Arc<Peer>,
    handles: &mut Handles,
) -> Arc<dyn Transport> {
    let transport: Arc<dyn Transport> = peer.clone();
    backend.set_transport_for_test(Arc::clone(&transport));
    backend.resolve_era_for_test(&transport).await;
    assert_eq!(backend.cached_era().await, Some(Era::Modern), "primed");

    peer.hold.store(true, Ordering::SeqCst);
    backend
        .reprobe_if_code_contradicts(DISCOVER, METHOD_NOT_FOUND_CODE, &transport)
        .await;
    tokio::time::timeout(WAIT, &mut handles.started)
        .await
        .expect("the re-probe reached the peer in time")
        .expect("the re-probe reaches the peer");
    transport
}

fn run(body: impl std::future::Future<Output = ()>) -> Vec<Value> {
    crate::test_log_capture::records(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(body);
    })
}

/// ERA.1 + ERA.2: `force_restart` takes the transport out while the re-probe waits; the late
/// answer from the old peer is refused and the refusal is reported with its reason.
#[test]
fn a_restart_mid_reprobe_refuses_the_old_peers_answer() {
    let records = run(async {
        let backend = backend();
        let (peer, mut handles) = Peer::new(Answer::Modern);
        contradicted_and_probing(&backend, &peer, &mut handles).await;

        let _ = backend.force_restart().await;
        assert!(
            backend.shared_transport().is_none(),
            "the restart took the old transport out of its slot"
        );

        // Delivered, or the probe cap expired first and the refusal below would be about
        // silence, not about the old peer's modern answer.
        handles
            .release
            .send(())
            .expect("the held probe is still waiting");
        let observed = tokio::time::timeout(WAIT, backend.era_observation())
            .await
            .expect("the detached re-probe decided");
        assert_eq!(
            observed,
            EraObservation::never_probed(),
            "the old peer's answer must not touch the observation once its transport was replaced"
        );
    });
    assert_eq!(
        discarded(&records).len(),
        1,
        "one era_probe_discarded record naming the reason: {records:?}"
    );
    assert_about_the_modern_answer(&records);
}

/// ERA.1 with a successful replacement: the old peer's answer is refused, and the era is then
/// whatever the new peer's own probe answers.
#[test]
fn the_era_after_a_replacement_is_the_new_peers_own_answer() {
    let records = run(async {
        let backend = backend();
        let (old, mut handles) = Peer::new(Answer::Modern);
        contradicted_and_probing(&backend, &old, &mut handles).await;

        let (new, _unused) = Peer::new(Answer::MethodNotFound);
        let new: Arc<dyn Transport> = new;
        backend.set_transport_for_test(Arc::clone(&new));

        handles
            .release
            .send(())
            .expect("the held probe is still waiting");
        let observed = tokio::time::timeout(WAIT, backend.era_observation())
            .await
            .expect("the detached re-probe decided");
        assert_eq!(
            observed,
            EraObservation::never_probed(),
            "the old peer's modern answer must not survive the replacement"
        );

        backend.resolve_era_for_test(&new).await;
        assert_eq!(backend.cached_era().await, Some(Era::Legacy));
    });
    assert_eq!(discarded(&records).len(), 1, "{records:?}");
    assert_about_the_modern_answer(&records);
}

/// ERA.3: with no replacement the re-probe's answer is committed and nothing is reported.
#[test]
fn without_a_restart_the_reprobe_answer_is_committed() {
    let records = run(async {
        let backend = backend();
        let (peer, mut handles) = Peer::new(Answer::Modern);
        contradicted_and_probing(&backend, &peer, &mut handles).await;

        handles
            .release
            .send(())
            .expect("the held probe is still waiting");
        let observed = tokio::time::timeout(WAIT, backend.era_observation())
            .await
            .expect("the detached re-probe decided");
        assert_eq!(observed.source, EraSource::Probed, "{observed:?}");
        assert_eq!(observed.era, Era::Modern);
    });
    assert!(
        discarded(&records).is_empty(),
        "nothing was refused: {records:?}"
    );
}

/// The installer runs `store` with the slot's read guard held, so a replacement cannot land
/// between its check and the write. A version that dropped the guard first would leave the
/// slot writable during `store`, and this assertion would fail.
#[test]
fn the_installer_holds_the_slot_guard_while_it_stores() {
    let entry = PooledEntry::new("held", &crate::config::FailsafeConfig::default());
    let (peer, _handles) = Peer::new(Answer::Modern);
    let served: Arc<dyn Transport> = peer;
    *entry.transport.write() = Some(Arc::clone(&served));

    let mut stored = false;
    let installed = with_serving(&entry, &served, &mut || {
        assert!(
            entry.transport.try_write().is_none(),
            "the slot must not be writable while the answer is stored"
        );
        stored = true;
    });
    assert!(installed && stored);

    // Replaced by a successful start: refused, `store` never runs.
    let (other, _handles) = Peer::new(Answer::MethodNotFound);
    *entry.transport.write() = Some(other as Arc<dyn Transport>);
    assert!(!with_serving(&entry, &served, &mut || panic!(
        "a replaced transport's answer must not be stored"
    )));

    // Evicted but still referenced: the taken transport reads as none, and refuses.
    entry.transport.write().take();
    assert!(!with_serving(&entry, &served, &mut || panic!(
        "an evicted slot's answer must not be stored"
    )));
}

/// A contradiction that arrives over a transport the slot no longer holds says nothing about
/// the peer now in service: its verdict survives and no probe starts.
#[test]
fn a_contradiction_over_a_replaced_transport_leaves_the_current_verdict() {
    let records = run(async {
        let backend = backend();
        let (old, _handles) = Peer::new(Answer::MethodNotFound);
        let old: Arc<dyn Transport> = old;
        let (new, _handles) = Peer::new(Answer::Modern);
        let new: Arc<dyn Transport> = new;
        backend.set_transport_for_test(Arc::clone(&new));
        backend.resolve_era_for_test(&new).await;
        assert_eq!(backend.cached_era().await, Some(Era::Modern));

        backend
            .reprobe_if_code_contradicts(DISCOVER, METHOD_NOT_FOUND_CODE, &old)
            .await;

        assert_eq!(
            backend.cached_era().await,
            Some(Era::Modern),
            "the replaced peer's refusal must not erase the current peer's verdict"
        );
    });
    assert!(discarded(&records).is_empty(), "{records:?}");
}
