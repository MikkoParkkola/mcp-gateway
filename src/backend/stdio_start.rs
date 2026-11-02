// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Starting a stdio backend's transport (split from `lifecycle.rs`).

use std::sync::Arc;

use super::Backend;
use crate::transport::{StdioTransport, isolated_env_and_assigned_cache};
use crate::{Error, Result};

impl Backend {
    /// Spawn the backend's process and complete the MCP handshake.
    pub(super) async fn start_stdio_transport(
        &self,
        command: &str,
        cwd: Option<&String>,
        protocol_version: Option<&String>,
    ) -> Result<Arc<StdioTransport>> {
        let launch = self.resolve_stdio_runtime_launch(command)?;
        // The child's environment and the cache the repair may clear come from
        // one assignment, so a write probe that answers differently between two
        // reads cannot hand the child a cache the repair does not own. A backend
        // whose `env:` already names one gets `None`, and the repair leaves that
        // path alone.
        let (env, assigned_cache) =
            isolated_env_and_assigned_cache(&self.name, &launch.command, launch.env);
        let transport = StdioTransport::new_with_assigned_cache(
            &launch.command,
            env,
            cwd.cloned(),
            self.config.timeout,
            protocol_version.cloned(),
            assigned_cache,
        );
        if let Some(bytes) = self.config.max_frame_bytes {
            transport.set_max_frame_bytes(bytes);
        }
        if let Some(needles) = self.needles.get() {
            transport.attach_needles(std::sync::Arc::clone(needles));
        }
        // Registered before anything is spawned, under the lock `stop` and
        // `retire_now` latch under: a retire either sees this transport or this
        // start sees `stopping` and spawns nothing (MIK-7923, design M1).
        {
            let mut cleanups = self.replaced_transport_cleanups.lock();
            if cleanups.stopping {
                return Err(Error::BackendNotFound(format!(
                    "backend {} is stopping",
                    self.name
                )));
            }
            cleanups.live.retain(|weak| weak.strong_count() > 0);
            let registered: Arc<dyn crate::transport::Transport> = transport.clone();
            cleanups.live.push(Arc::downgrade(&registered));
        }
        super::package_cache::start_with_repair(&transport).await?;
        Ok(transport)
    }
}
