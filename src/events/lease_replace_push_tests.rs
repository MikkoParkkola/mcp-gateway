// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! ISO-T6 through the real push: the credential-change watcher.

use super::*;

/// ISO-T6, the watcher: a real `credentials_changed()` signal reaches the
/// task `EventsHub::start` spawns (`watch_credentials`), which revokes a
/// subscriber who lost admission and closes its listener's session. The
/// fixture starts no worker, so no sweep can run, and nothing calls
/// `reconcile_backend`: only the signal can have closed the session.
#[tokio::test]
async fn iso_t6_a_credentials_changed_signal_closes_the_listener_without_the_sweep() {
    use crate::events::services::{AccessVerdict, forced_verdict};
    let p_token = token(Some(in_an_hour()));
    let mut peer =
        two_token_peer([p_token.to_string(), token(Some(in_an_hour())).to_string()]).await;
    let (f, _handle, (listeners, _backend)) = leased_listener(&mut peer, p_token).await;
    let mut intake = f.hub.take_intake();
    let changed = crate::events::CREDENTIALS_CHANGED.subscribe();
    let watcher = tokio::spawn(crate::events::runtime::watch_credentials(
        Arc::downgrade(&f.hub),
        changed,
    ));
    let _refused = forced_verdict::answer(AccessVerdict::Refuses);
    crate::events::credentials_changed();
    assert_eq!(
        peer.next().await,
        Some(Stream::Closed(0)),
        "the signal closed the session with no sweep running"
    );
    assert!(f.hub.store.subscriptions().is_empty(), "p's row is revoked");
    assert!(!peer.push_tools_changed(0), "no stream is left to read on");
    assert!(intake.try_recv().is_err(), "nothing was read for p");
    assert!(
        listeners
            .entry_for(&crate::events::upstream_listener::ListenerKey {
                backend: "pt".into(),
                obs: Some(lease_key(&f, "p").obs),
            })
            .is_none(),
        "no listener is left for p"
    );
    watcher.abort();
}
