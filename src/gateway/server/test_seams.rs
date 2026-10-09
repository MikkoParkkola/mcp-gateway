// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What an in-process test may set on a [`super::Gateway`] before `run`:
//! where its data lives, a channel for the port it binds, and a trigger for
//! the graceful shutdown a signal starts in production.

use std::path::PathBuf;

use tokio::sync::oneshot;

#[derive(Default)]
pub(super) struct TestSeams {
    /// The test's tempdir (`with_data_dir`); `None` is the standard one.
    pub(super) data_dir: Option<PathBuf>,
    bound_port: Option<oneshot::Sender<u16>>,
    /// Starts the graceful shutdown as Ctrl+C or SIGTERM would (MIK-8156).
    #[cfg(test)]
    shutdown: Option<oneshot::Receiver<()>>,
    /// Receives `run`'s in-flight request gate, so a test can hold a request
    /// open across the drain (MIK-8156).
    #[cfg(test)]
    inflight: Option<oneshot::Sender<std::sync::Arc<tokio::sync::Semaphore>>>,
    /// Receives the stdio session's Meta-MCP, so a test can read the
    /// continuation table that session holds (MIK-8176). A mutex because
    /// `run_stdio_on` reports it through `&self`.
    #[cfg(test)]
    stdio_meta_mcp: std::sync::Mutex<
        Option<oneshot::Sender<std::sync::Arc<crate::gateway::meta_mcp::MetaMcp>>>,
    >,
}

impl TestSeams {
    pub(super) fn data_dir(&self) -> PathBuf {
        self.data_dir
            .clone()
            .unwrap_or_else(super::persistence::standard_data_dir)
    }

    /// Send the port `listener` holds to the test that asked for it.
    pub(super) fn report_bound_port(&mut self, listener: &tokio::net::TcpListener) {
        if let (Some(sender), Ok(bound)) = (self.bound_port.take(), listener.local_addr()) {
            // A test that stopped waiting has dropped its receiver; nothing to do.
            sender.send(bound.port()).ok();
        }
    }

    /// The test's shutdown trigger, taken once by `run`.
    #[cfg(test)]
    pub(super) fn take_shutdown_trigger(&mut self) -> Option<oneshot::Receiver<()>> {
        self.shutdown.take()
    }

    /// Hand the stdio session's Meta-MCP to the test that asked for it.
    #[cfg(test)]
    pub(super) fn report_stdio_meta_mcp(
        &self,
        meta_mcp: &std::sync::Arc<crate::gateway::meta_mcp::MetaMcp>,
    ) {
        let sender = self
            .stdio_meta_mcp
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(sender) = sender {
            sender.send(std::sync::Arc::clone(meta_mcp)).ok();
        }
    }

    /// Hand `run`'s in-flight request gate to the test that asked for it.
    #[cfg(test)]
    pub(super) fn report_inflight(&mut self, inflight: &std::sync::Arc<tokio::sync::Semaphore>) {
        if let Some(sender) = self.inflight.take() {
            sender.send(std::sync::Arc::clone(inflight)).ok();
        }
    }
}

/// `shutdown_signal`, also started by a test's trigger. Test builds only, so
/// the production signal handler is the unchanged `support::shutdown_signal`.
#[cfg(test)]
pub(super) async fn shutdown_signal_or_trigger(
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
    trigger: Option<oneshot::Receiver<()>>,
) {
    let on_trigger = shutdown_tx.clone();
    tokio::select! {
        () = super::support::shutdown_signal(shutdown_tx) => {},
        () = async {
            match trigger {
                // A dropped sender starts it too: the test is over either way.
                Some(trigger) => {
                    trigger.await.ok();
                }
                None => std::future::pending::<()>().await,
            }
        } => {
            on_trigger.send(()).ok();
        },
    }
}

impl super::Gateway {
    /// The port `run` binds, for a test that configured `server.port: 0`, so
    /// no port is picked and dropped before the gateway binds it (MIK-7984).
    pub(super) fn bound_port_for_test(&mut self) -> oneshot::Receiver<u16> {
        let (sender, receiver) = oneshot::channel();
        self.test_seams.bound_port = Some(sender);
        receiver
    }

    /// `run`'s in-flight request gate, sent once `run` builds it.
    #[cfg(test)]
    pub(super) fn inflight_for_test(
        &mut self,
    ) -> oneshot::Receiver<std::sync::Arc<tokio::sync::Semaphore>> {
        let (sender, receiver) = oneshot::channel();
        self.test_seams.inflight = Some(sender);
        receiver
    }

    /// The stdio session's Meta-MCP, sent once `run_stdio_on` builds it.
    #[cfg(test)]
    pub(super) fn stdio_meta_mcp_for_test(
        &mut self,
    ) -> oneshot::Receiver<std::sync::Arc<crate::gateway::meta_mcp::MetaMcp>> {
        let (sender, receiver) = oneshot::channel();
        *self
            .test_seams
            .stdio_meta_mcp
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(sender);
        receiver
    }

    /// A trigger that starts `run`'s graceful shutdown, as a signal would.
    /// Sending, or dropping the sender, starts it.
    #[cfg(test)]
    pub(super) fn shutdown_trigger_for_test(&mut self) -> oneshot::Sender<()> {
        let (sender, receiver) = oneshot::channel();
        self.test_seams.shutdown = Some(receiver);
        sender
    }
}

#[cfg(test)]
#[path = "shutdown_order_tests.rs"]
mod shutdown_order_tests;
