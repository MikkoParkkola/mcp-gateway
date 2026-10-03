// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Starting a stdio backend's transport (split from `lifecycle.rs`).

use std::sync::Arc;

use super::Backend;
use crate::Result;
use crate::transport::{StdioTransport, Transport, isolated_package_manager_env};

impl Backend {
    /// Spawn the backend's process and complete the MCP handshake.
    pub(super) async fn start_stdio_transport(
        &self,
        command: &str,
        cwd: Option<&String>,
        protocol_version: Option<&String>,
    ) -> Result<Arc<dyn Transport>> {
        let launch = self.resolve_stdio_runtime_launch(command)?;
        let transport = StdioTransport::new(
            &launch.command,
            isolated_package_manager_env(&self.name, &launch.command, launch.env),
            cwd.cloned(),
            self.config.timeout,
            protocol_version.cloned(),
        );
        if let Some(bytes) = self.config.max_frame_bytes {
            transport.set_max_frame_bytes(bytes);
        }
        transport.start().await?;
        Ok(transport)
    }
}
