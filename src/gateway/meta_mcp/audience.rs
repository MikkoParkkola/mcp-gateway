// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350: what one caller is shown of one backend, as a fingerprint. A
//! `tools/list_changed` is owed to a listener only when this moved for it, so
//! a change to a tool the caller cannot see tells it nothing.

use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::visibility::InvokeScope;
use crate::gateway::streaming::ViewDigest;
use crate::protocol::{RequestId, Tool};

impl MetaMcp {
    /// What `scope` is shown of `backend`, as two digests that move
    /// independently:
    /// - (a) the served `tools/list` result itself (`served_tools_list`, the one
    ///   builder, so meta-tool counts, surfaced and promoted tools follow the
    ///   same predicates the listing uses);
    /// - (b) the backend's own listing as discovery shows it: the caller's slot
    ///   on a per-user backend, the shared slot otherwise, or a capability
    ///   catalogue, each filtered by `shows_tool`.
    ///
    /// Cache reads only: it never mints a credential and never fetches, so a
    /// cold per-user slot contributes nothing (design B3'/D4).
    pub(crate) fn visible_digest(
        &self,
        backend: &str,
        scope: InvokeScope<'_>,
        session_id: Option<&str>,
    ) -> ViewDigest {
        let served = self.served_tools_list(RequestId::Number(0), session_id, scope);
        let served = serde_json::to_string(&served.result).unwrap_or_default();
        // Code Mode serves two fixed meta-tools and no discovery listing, so
        // a backend's own tools are not part of what the caller can see.
        let shown: Vec<Tool> =
            if self.code_mode_enabled || !self.admits_backend(backend, scope, session_id) {
                Vec::new()
            } else if let Some(b) = self.backends.get(backend) {
                self.listing_snapshot(&b, scope)
                    .map(|(tools, _)| {
                        tools
                            .iter()
                            .filter(|t| self.shows_tool(backend, t, scope, session_id))
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default()
            } else {
                self.capability_tools(backend)
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|t| self.shows_tool(backend, t, scope, session_id))
                    .collect()
            };
        ViewDigest {
            served: crate::hashing::sha256_hex(served.as_bytes()),
            shown: if shown.is_empty() {
                String::new()
            } else {
                crate::hashing::sha256_hex(
                    serde_json::to_string(&shown).unwrap_or_default().as_bytes(),
                )
            },
        }
    }
}
