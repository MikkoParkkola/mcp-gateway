// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every change to the tool set reaches `announce_tools_changed` (F24).
//!
//! The HTTP server advertises `tools.listChanged: true`, so every path that
//! changes the tool set has to announce. They all feed one channel:
//! `BackendRegistry::register` and `remove` (config reload, and the admin UI's
//! add and remove, which reload) and the capability file watcher. One drain
//! announces each, so no path can be forgotten and none announces twice.

use std::sync::Arc;

use crate::gateway::router::AppState;

/// Announce every name sent on `rx` to both eras' listeners, until the senders
/// go or `shutdown` fires. The registry inside `AppState` keeps a sender, so
/// without the shutdown branch the task and the state it holds outlive the
/// server (#2260).
pub(super) fn spawn_drain(
    state: Arc<AppState>,
    rx: tokio::sync::mpsc::UnboundedReceiver<String>,
    shutdown: tokio::sync::broadcast::Receiver<()>,
) {
    tokio::spawn(drain_until(rx, shutdown, move |backend: String| {
        let state = Arc::clone(&state);
        async move { state.announce_tools_changed(&backend).await }
    }));
}

async fn drain_until<F, Fut>(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<String>,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
    mut announce: F,
) where
    F: FnMut(String) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    loop {
        tokio::select! {
            _ = shutdown.recv() => break,
            next = rx.recv() => match next {
                Some(backend) => announce(backend).await,
                None => break,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // #2260: the task must drop what it holds when shutdown fires, even though
    // a sender (the registry's) is still alive.
    #[tokio::test]
    async fn drain_releases_its_state_on_shutdown_while_a_sender_lives() {
        let state = Arc::new(());
        let weak = Arc::downgrade(&state);
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let (sd_tx, sd_rx) = tokio::sync::broadcast::channel(1);
        let held = Arc::clone(&state);
        let task = tokio::spawn(drain_until(rx, sd_rx, move |_| {
            let _keep = Arc::clone(&held);
            async {}
        }));
        drop(state);
        tx.send("a".into()).unwrap();
        assert!(weak.upgrade().is_some(), "state is held while running");
        sd_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("drain exits on shutdown")
            .unwrap();
        assert!(weak.upgrade().is_none(), "state dropped after shutdown");
        drop(tx);
    }
}
