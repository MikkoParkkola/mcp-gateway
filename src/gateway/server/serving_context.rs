// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Service-owned continuation lifetime and transport inputs.
//!
//! The nonoptional owner retains cleanup while either transport serves requests.
//! Stdio transport inputs are shared with the production loop extraction.

use std::sync::Arc;
use std::time::Duration;

use super::{AbortOnDrop, MetaMcp, MtlsPolicy, NotificationMultiplexer, ProxyManager, ToolPolicy};
use crate::protocol_revision_telemetry::DurableTelemetrySink;

pub(in crate::gateway) struct OwnedMetaMcp {
    meta: Arc<MetaMcp>,
    _cleanup: AbortOnDrop,
}

impl OwnedMetaMcp {
    pub(super) const fn new(meta: Arc<MetaMcp>, cleanup: AbortOnDrop) -> Self {
        Self {
            meta,
            _cleanup: cleanup,
        }
    }

    pub(in crate::gateway) const fn meta(&self) -> &Arc<MetaMcp> {
        &self.meta
    }
}

pub(super) struct HttpServeContext {
    pub(super) owner: OwnedMetaMcp,
}

pub(super) struct StdioServeContext {
    pub(super) owner: OwnedMetaMcp,
    pub(super) tool_policy: Arc<ToolPolicy>,
    pub(super) mtls_policy: Arc<MtlsPolicy>,
    pub(super) proxy: Arc<ProxyManager>,
    pub(super) multiplexer: Arc<NotificationMultiplexer>,
    pub(super) protocol_telemetry_sink: Option<DurableTelemetrySink>,
    pub(super) limits: StdioServeLimits,
}

pub(super) struct StdioServeLimits {
    pub(super) max_frame_bytes: usize,
    pub(super) shutdown_timeout: Duration,
    pub(super) max_inflight: usize,
    pub(super) pre_initialize_capacity: usize,
    pub(super) response_queue_capacity: usize,
}

#[cfg(test)]
mod tests;
