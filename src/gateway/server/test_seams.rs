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
    shutdown: Option<oneshot::Receiver<()>>,
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
    pub(super) fn take_shutdown_trigger(&mut self) -> Option<oneshot::Receiver<()>> {
        self.shutdown.take()
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

    /// A trigger that starts `run`'s graceful shutdown, as a signal would.
    /// Sending, or dropping the sender, starts it.
    pub(super) fn shutdown_trigger_for_test(&mut self) -> oneshot::Sender<()> {
        let (sender, receiver) = oneshot::channel();
        self.test_seams.shutdown = Some(receiver);
        sender
    }
}

#[cfg(test)]
#[path = "shutdown_order_tests.rs"]
mod shutdown_order_tests;
