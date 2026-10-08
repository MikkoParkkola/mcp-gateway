// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Starting a stdio backend's transport (split from `lifecycle.rs`).

use std::sync::Arc;

use super::Backend;
use crate::Result;
use crate::transport::{StdioTransport, assigned_package_cache_dir, isolated_package_manager_env};

impl Backend {
    /// Spawn the backend's process and complete the MCP handshake.
    pub(super) async fn start_stdio_transport(
        &self,
        command: &str,
        cwd: Option<&String>,
        protocol_version: Option<&String>,
    ) -> Result<Arc<StdioTransport>> {
        let launch = self.resolve_stdio_runtime_launch(command)?;
        // Read before the environment is built: this is what says the cache is
        // the gateway's to clear. A backend whose `env:` already names one gets
        // `None`, and the repair leaves that path alone.
        let assigned_cache = assigned_package_cache_dir(&self.name, &launch.command, &launch.env);
        let transport = StdioTransport::new_with_assigned_cache(
            &launch.command,
            isolated_package_manager_env(&self.name, &launch.command, launch.env),
            cwd.cloned(),
            self.config.timeout,
            protocol_version.cloned(),
            assigned_cache,
        );
        if let Some(bytes) = self.config.max_frame_bytes {
            transport.set_max_frame_bytes(bytes);
        }
        super::package_cache::start_with_repair(&transport).await?;
        Ok(transport)
    }
}
