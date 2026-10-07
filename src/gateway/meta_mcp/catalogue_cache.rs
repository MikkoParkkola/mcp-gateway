// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The meta catalogue, built once per distinct input and then shared (MIK-7916).
//!
//! `tools/list` rebuilt the meta tool list on every call, so the trust-card
//! memo had to prove each repeat equal to the last one byte by byte. A list
//! served from here comes back as the same `Arc`, which the memo recognises by
//! address alone.
//!
//! The key decides what a caller is shown, so its completeness is an
//! authorization property: a hit served across two standings would list one
//! caller's tools to another. [`build_catalogue`] is therefore a free function
//! of the key and the instance's fixed exposure. It cannot read anything the
//! key does not carry, and it destructures the key with no `..`.

use std::collections::VecDeque;
use std::sync::Arc;

use parking_lot::Mutex;

use super::MetaMcp;
use crate::gateway::meta_mcp_helpers::build_code_mode_tools;
use crate::gateway::meta_mcp_tool_defs::{
    MetaToolExposure, MetaToolGates, ToolTotal, build_meta_tools_filtered,
    require_gateway_invoke_nonce,
};
use crate::gateway::router::CallerStanding;
use crate::protocol::Tool;

/// Everything a meta catalogue is built from that can differ between two
/// lists served by one gateway instance. The exposure allow-list is the one
/// other input, and it is fixed for the instance's life (set by its builder).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct MetaListKey {
    /// Code Mode's fixed two-tool surface in place of the meta-tools.
    pub(super) code_mode: bool,
    /// The meta-tools whose backing is attached right now.
    pub(super) gates: MetaToolGates,
    /// The caller's admitted (tool, server) counts, quoted in descriptions.
    pub(super) counts: (ToolTotal, usize),
    /// The caller's admin standing, which drops what it may not call.
    pub(super) standing: CallerStanding,
    /// `gateway_invoke` takes a nonce (signing on and nonces required).
    pub(super) nonce: bool,
}

/// The catalogue `key` describes, built from scratch.
pub(super) fn build_catalogue(key: MetaListKey, exposure: &MetaToolExposure) -> Vec<Tool> {
    #[cfg(test)]
    CATALOGUE_BUILDS.with(|n| n.set(n.get() + 1));
    let MetaListKey {
        code_mode,
        gates,
        counts: (tool_count, server_count),
        standing,
        nonce,
    } = key;
    let mut tools = if code_mode {
        exposure.filter(build_code_mode_tools())
    } else {
        build_meta_tools_filtered(gates, tool_count, server_count, exposure)
    };
    if nonce {
        require_gateway_invoke_nonce(&mut tools);
    }
    // The admin axis, applied to disclosure by the same predicate that
    // gates dispatch in `handle_tools_call`. Listing a tool the caller is
    // then refused is a catalogue entry that exists only to be denied.
    tools.retain(|tool| standing.permits(&tool.name));
    tools
}

/// Catalogues held by key, oldest first.
// ponytail: a linear scan; 64 keys of a few bytes each compare in well under
// a microsecond. A map if the bound ever needs to grow by orders.
#[derive(Default)]
pub(super) struct MetaCatalogues(Mutex<VecDeque<HeldCatalogue>>);

/// A key and the catalogue built for it.
type HeldCatalogue = (MetaListKey, Arc<[Tool]>);

/// Keys held per instance. Past it the oldest is dropped, so a gateway whose
/// counts drift over a long run keeps caching its current lists.
const HELD_KEYS: usize = 64;

impl MetaCatalogues {
    /// The catalogue for `key`, built only if none is held for it.
    pub(super) fn get_or_build(
        &self,
        key: MetaListKey,
        exposure: &MetaToolExposure,
    ) -> Arc<[Tool]> {
        let held = |key| {
            self.0
                .lock()
                .iter()
                .find(|(seen, _)| *seen == key)
                .map(|(_, tools)| Arc::clone(tools))
        };
        if let Some(tools) = held(key) {
            return tools;
        }
        // Built outside the lock, so a cold key does not stall a held one.
        let built: Arc<[Tool]> = build_catalogue(key, exposure).into();
        let mut held_now = self.0.lock();
        // A concurrent miss on the same key may have stored it meanwhile;
        // serve that one, so one key never maps to two lists.
        if let Some((_, tools)) = held_now.iter().find(|(seen, _)| *seen == key) {
            return Arc::clone(tools);
        }
        if held_now.len() == HELD_KEYS {
            held_now.pop_front();
        }
        held_now.push_back((key, Arc::clone(&built)));
        built
    }
}

impl MetaMcp {
    /// The meta-tools this caller is served, after the operator allow-list and
    /// the caller's standing have both had their say.
    ///
    /// The single authority for "what does this caller get to see": `tools/list`
    /// builds its answer here, and the gateway-owned guides are projected
    /// through the same set (`resources::try_serve_guide`) so no served text
    /// can name a tool the same caller's catalogue withholds.
    ///
    /// `counts` feed the descriptions: `tools/list` passes the caller's
    /// admitted counts; the guide projection reads names only.
    pub(super) fn meta_tools_for(
        &self,
        standing: CallerStanding,
        counts: (ToolTotal, usize),
    ) -> Arc<[Tool]> {
        let key = MetaListKey {
            code_mode: self.code_mode_enabled,
            gates: MetaToolGates {
                // The collector is always attached, so its presence was
                // never a gate. The operator opt-in is.
                stats: self.expose_stats_tool,
                reload: self.get_reload_context().is_some(),
                // Follows `cost_governance.enabled`, which is what decides
                // whether a registry is attached at all. Without the
                // feature there is nothing to report.
                #[cfg(feature = "cost-governance")]
                cost_report: self.cost_registry.is_some(),
                #[cfg(not(feature = "cost-governance"))]
                cost_report: false,
                // Attachment, not configuration: the registry is set after
                // construction and never over stdio, so this is read here
                // rather than passed in.
                webhook_status: self.get_webhook_registry().is_some(),
                playbooks: !self.playbook_engine.read().is_empty(),
                profiles: self.profile_registry.has_configured_profiles(),
            },
            counts,
            standing,
            nonce: self.signing_enabled() && self.require_nonce,
        };
        self.meta_catalogues
            .get_or_build(key, &self.meta_tool_exposure)
    }
}

#[cfg(test)]
thread_local! {
    /// Test-only: meta catalogues built on this thread.
    pub(super) static CATALOGUE_BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
#[path = "catalogue_cache_tests.rs"]
mod tests;
