// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The stdio half of the tools-changed drain (MIK-8278): the same decision
//! as HTTP's ([`super::decide_on`]), told to stdio's one client as a
//! `notifications/tools/list_changed` frame on the stdout writer queue.
//!
//! Three parts, owned by one [`StdioAnnouncer`] the stdio serve loop holds:
//! - the drain keeps consuming and deciding nudges whatever stdout does, and
//!   sets a one-frame latch on any decision to announce; a decision made
//!   before the session sent `notifications/initialized` is held and set on
//!   it, so a change between a client's first list and that notification is
//!   still told;
//! - the sender turns the latch into at most one queued frame, so a burst
//!   while stdout is slow collapses to one notification and the nudge channel
//!   never backs up;
//! - a stop the serve loop fires at EOF, before it joins the writer, after
//!   which nothing is enqueued. Dropping the announcer stops and aborts both
//!   tasks on every other exit path (cancellation, writer death).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::{Notify, broadcast, mpsc, watch};

use super::{Announced, decide_on};
use crate::backend::BackendRegistry;
use crate::backend::tools_nudge::ToolsNudge;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::outbound::OutboundFrame;
use crate::gateway::server::background::AbortOnDrop;

/// The drain, the sender and their stop, for one stdio session.
pub(in crate::gateway::server) struct StdioAnnouncer {
    initialized: watch::Sender<bool>,
    /// A decision made before `notifications/initialized`, not yet told.
    held: Arc<AtomicBool>,
    pending: Arc<Notify>,
    /// Set by `stop`. Held across the sender's final check and enqueue, so
    /// once `stop` returns nothing more is queued.
    stopping: Arc<parking_lot::Mutex<bool>>,
    stop: broadcast::Sender<()>,
    _drain: AbortOnDrop,
    _sender: AbortOnDrop,
    /// A token only the drain task holds: dead once it ends.
    #[cfg(test)]
    alive: std::sync::Weak<()>,
}

impl StdioAnnouncer {
    /// Start deciding `rx`'s nudges for the client behind `writer`.
    pub(in crate::gateway::server) fn start(
        (backends, meta_mcp): (Arc<BackendRegistry>, Arc<MetaMcp>),
        rx: mpsc::UnboundedReceiver<ToolsNudge>,
        writer: mpsc::Sender<OutboundFrame>,
    ) -> Self {
        let (stop, _) = broadcast::channel(1);
        let (initialized, ready) = watch::channel(false);
        let stopping = Arc::new(parking_lot::Mutex::new(false));
        let pending = Arc::new(Notify::new());
        let held = Arc::new(AtomicBool::new(false));
        #[cfg(test)]
        let token = Arc::new(());
        #[cfg(test)]
        let alive = Arc::downgrade(&token);
        let drain = {
            let (pending, held) = (Arc::clone(&pending), Arc::clone(&held));
            let announced = parking_lot::Mutex::new(Announced::default());
            let shutdown = stop.subscribe();
            let ready = ready.clone();
            tokio::spawn(async move {
                super::drain_until(rx, shutdown, |nudge: ToolsNudge| {
                    // Every nudge is decided, so the record of what was last
                    // announced stays current. One client, one view: a shared
                    // or a per-user change is the same notification to it.
                    if decide_on((&backends, &meta_mcp), &announced, nudge).is_some() {
                        #[cfg(test)]
                        crate::gateway::server::stdio_seams::decided();
                        if *ready.borrow() {
                            pending.notify_one();
                        } else {
                            // Held for `initialized`; rechecked after the
                            // store, so a race with it cannot lose the change.
                            held.store(true, Ordering::SeqCst);
                            if *ready.borrow() && held.swap(false, Ordering::SeqCst) {
                                pending.notify_one();
                            }
                        }
                    }
                    std::future::ready(())
                })
                .await;
                // Held for the task's life: dead once it ends or is aborted.
                #[cfg(test)]
                drop(token);
            })
        };
        let sender = tokio::spawn(send_when_ready(
            (Arc::clone(&pending), Arc::clone(&stopping)),
            stop.subscribe(),
            writer,
        ));
        Self {
            initialized,
            held,
            pending,
            stopping,
            stop,
            _drain: AbortOnDrop::new(drain),
            _sender: AbortOnDrop::new(sender),
            #[cfg(test)]
            alive,
        }
    }

    /// The client sent `notifications/initialized`: a change held since
    /// before it is announced now, and changes decided from now on as made.
    pub(in crate::gateway::server) fn initialized(&self) {
        self.initialized.send_replace(true);
        if self.held.swap(false, Ordering::SeqCst) {
            self.pending.notify_one();
        }
    }

    /// A receiver for the session's stop, for the watchers it owns.
    pub(in crate::gateway::server) fn shutdown(&self) -> broadcast::Receiver<()> {
        self.stop.subscribe()
    }

    /// Stop announcing: nothing is enqueued after this returns.
    pub(in crate::gateway::server) fn stop(&self) {
        *self.stopping.lock() = true;
        drop(self.stop.send(()));
    }
}

impl Drop for StdioAnnouncer {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Turn the latch into frames, one per wake. The latch is only ever set for
/// an initialized session, so the sender needs no gate of its own.
async fn send_when_ready(
    (pending, stopping): (Arc<Notify>, Arc<parking_lot::Mutex<bool>>),
    mut stop: broadcast::Receiver<()>,
    writer: mpsc::Sender<OutboundFrame>,
) {
    loop {
        tokio::select! {
            _ = stop.recv() => return,
            () = pending.notified() => {}
        }
        #[cfg(test)]
        if writer.capacity() == 0 {
            crate::gateway::server::stdio_seams::sender_found_queue_full();
        }
        let permit = tokio::select! {
            _ = stop.recv() => return,
            permit = writer.reserve() => match permit {
                Ok(permit) => permit,
                Err(_) => return, // the writer is gone
            },
        };
        // Checked after the permit and enqueued under the lock `stop` takes,
        // so a stop either precedes the check or follows the enqueue.
        let stopped = stopping.lock();
        if *stopped {
            return;
        }
        #[cfg(test)]
        crate::gateway::server::stdio_seams::final_send_pause(Arc::as_ptr(&stopping) as usize);
        permit.send(OutboundFrame::gateway_stdio(serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/tools/list_changed",
        })));
        drop(stopped);
    }
}

/// Test support: whether a session's drain task is still running.
#[cfg(test)]
impl StdioAnnouncer {
    /// Dead once the drain task has ended or been aborted.
    pub(in crate::gateway::server) fn drain_alive(&self) -> std::sync::Weak<()> {
        self.alive.clone()
    }
}

#[cfg(test)]
#[path = "stdio_tests.rs"]
mod tests;
