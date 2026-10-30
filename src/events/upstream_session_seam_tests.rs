// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The listener's session choice (MIK-8835): an identity credential never
//! falls back to the shared transport (C4), and an own session runs legacy
//! (S10b). A per-user listener emits with no catalogue snapshot.

use super::*;
use crate::events::upstream_need::WINDOW;
use crate::transport::upstream_tap::ListenerCredential;

/// C4 (MIK-8835.SSE.4, design B6): an identity credential on a transport with
/// no session of its own fails closed; it never falls back to the shared
/// transport. A shared credential uses the transport itself.
#[test]
fn c4_an_identity_credential_never_falls_back_to_the_shared_transport() {
    struct Plain;
    #[async_trait::async_trait]
    impl UpstreamListen for Plain {
        async fn listen(self: Arc<Self>, _: Requested) -> Result<FrameStream, Refused> {
            Err(Refused::Unsupported)
        }
        async fn unsolicited(self: Arc<Self>, _: Watched) -> Result<FrameStream, Refused> {
            Err(Refused::Unsupported)
        }
        async fn legacy_interest(
            self: Arc<Self>,
            _: crate::transport::upstream_tap::LegacyPin,
            _: &str,
            _: bool,
        ) -> crate::Result<crate::protocol::JsonRpcResponse> {
            Err(crate::Error::Transport("unused".to_owned()))
        }
    }
    struct Source;
    impl crate::transport::upstream_tap::CredentialSource for Source {
        fn with_credential<'a>(
            &'a self,
            send: crate::transport::upstream_tap::CredentialedSend<'a>,
        ) -> futures::future::BoxFuture<'a, crate::Result<reqwest::Response>> {
            send(zeroize::Zeroizing::default())
        }
        fn identity_key(&self) -> Option<&str> {
            Some("k")
        }
    }
    let strong: Arc<dyn UpstreamListen> = Arc::new(Plain);
    let handle = Arc::downgrade(&strong);
    let shared = pick_session(&handle, ListenerCredential::shared()).expect("shared listens");
    assert!(
        shared.0.is_none() && Weak::ptr_eq(&shared.1, &handle),
        "on the transport itself"
    );
    let identity = ListenerCredential {
        identity_key: Some("k".to_owned()),
        source: Some(Arc::new(Source)),
    };
    assert!(pick_session(&handle, identity).is_none(), "fails closed");
}

/// S10b (MIK-8835.SSE.3, design B12): an own session runs legacy even when
/// the slot's cached era is modern (a modern slot that fell back to SSE);
/// without one, the era decides.
#[test]
fn s10b_an_own_session_always_runs_legacy() {
    assert!(!runs_modern(true, PeerEra::Modern));
    assert!(!runs_modern(true, PeerEra::Legacy));
    assert!(runs_modern(false, PeerEra::Modern));
    assert!(!runs_modern(false, PeerEra::Legacy));
}

/// A per-user listener reads no catalogue, so its snapshot stays empty: its
/// watched URIs are emitted, not held back for a snapshot that never comes.
#[tokio::test]
async fn a_per_user_listener_emits_without_a_snapshot() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = EventsHub::open(&crate::config::EventsConfig::default(), dir.path()).expect("hub");
    let mut intake = hub.runtime.intake.lock().take().expect("intake");
    let weak = Arc::downgrade(&hub);
    let shared = super::tests::shared_keyed(
        crate::events::upstream_listener::ListenerKey {
            backend: "b".to_owned(),
            obs: Some("o".to_owned()),
        },
        Arc::new(std::collections::BTreeSet::new),
    );
    shared
        .need
        .lock()
        .add(&crate::events::upstream_need::Interest::ResourceUpdated(
            "file:///a".to_owned(),
        ))
        .expect("room");
    let mut state = State::new(&shared, PeerEra::Legacy);
    state.note(
        UpstreamNote::Notice {
            kind: NoteKind::ResourceUpdated,
            uri: Some("file:///a".to_owned()),
        },
        false,
    );
    state.flush_at(&weak, std::time::Instant::now() + WINDOW);
    assert!(intake.try_recv().is_ok(), "emitted with no snapshot");
}
