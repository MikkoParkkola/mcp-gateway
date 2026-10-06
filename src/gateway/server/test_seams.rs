// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What an in-process test may set on a [`super::Gateway`] before `run`:
//! where its data lives, and a channel for the port it binds.

use std::path::PathBuf;

use tokio::sync::oneshot;

#[derive(Default)]
pub(super) struct TestSeams {
    /// The test's tempdir (`with_data_dir`); `None` is the standard one.
    pub(super) data_dir: Option<PathBuf>,
    bound_port: Option<oneshot::Sender<u16>>,
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
}

impl super::Gateway {
    /// The port `run` binds, for a test that configured `server.port: 0`, so
    /// no port is picked and dropped before the gateway binds it (MIK-7984).
    pub(super) fn bound_port_for_test(&mut self) -> oneshot::Receiver<u16> {
        let (sender, receiver) = oneshot::channel();
        self.test_seams.bound_port = Some(sender);
        receiver
    }
}
