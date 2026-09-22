// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How discovery gets a backend's tool list, and from whose pool slot.
//!
//! Split out of `search.rs` because these four are one concern — which slot a
//! discovery read comes from, and who is allowed to refresh it — and because
//! `search.rs` is over the file-size ceiling and may not grow.

use super::MetaMcp;
use crate::backend::Backend;
use crate::protocol::Tool;
use std::sync::Arc;
use tracing::debug;

impl MetaMcp {
    /// The tools discovery should show for `backend`, from THIS CALLER's slot.
    ///
    /// `binding` and `headers` come from one `caller_credential_for` resolution
    /// (MIK-7334.CATALOGUE.1). `None`/empty is the identity-free caller and
    /// selects the shared slot, so single-tenant discovery is unchanged.
    ///
    /// The background refresh stays SHARED-only on purpose: it is spawned with
    /// only an `Arc<Backend>` and holds no credential, so letting it fill a
    /// per-user slot would write the static-credential catalogue under a user's
    /// identity — the original bug.
    ///
    /// THE TWO PATHS THEREFORE AGE DIFFERENTLY, and the difference is why the
    /// freshness check below is not symmetric:
    ///
    /// - **Shared**: serve the snapshot and refresh behind it. Something else
    ///   always will, so a stale read costs one interval of staleness and no
    ///   caller waits. Unchanged.
    /// - **Per-user**: NOTHING will ever refresh this slot on its own, because
    ///   the only refresher holds no credential. Serving a stale snapshot here
    ///   serves it forever — and the invoke path refreshes on TTL through
    ///   `get_or_fetch_shared`, so the same caller would see two different views
    ///   of one backend. A per-user slot that has aged out falls through to the
    ///   credentialed refetch below instead.
    ///
    /// An earlier revision claimed the inline refresh while returning above it,
    /// so the read it named was never reached (MIK-7334.CATALOGUE.1 C4).
    pub(super) async fn backend_tools_for_discovery(
        backend: &Arc<Backend>,
        allow_empty_cache_fetch: bool,
        binding: Option<&str>,
        headers: &[(String, String)],
    ) -> Option<Arc<Vec<Tool>>> {
        let tools = backend.get_cached_tools_snapshot_for(binding);
        if !tools.is_empty() {
            if binding.is_none() {
                // Shared: serve now, refresh behind. Byte-for-byte as before.
                Self::refresh_stale_backend_tools_in_background(backend);
                return Some(tools);
            }
            // Per-user: only a FRESH slot may be served from cache.
            if backend.has_cached_tools_for(binding) {
                return Some(tools);
            }
        }

        // A per-user slot fills on its owner's own credentialed read, never on a
        // background task's, so an empty one is always worth filling here.
        if allow_empty_cache_fetch || binding.is_some() {
            return match backend.get_tools_for_binding(binding, headers).await {
                Ok(tools) if !tools.is_empty() => Some(tools),
                Ok(_) => None,
                Err(e) => {
                    debug!(
                        backend = %backend.name,
                        error = %e,
                        "On-demand backend tool-cache fill failed"
                    );
                    None
                }
            };
        }

        None
    }

    pub(super) fn code_mode_backend_candidates(&self, query: &str) -> (Vec<Arc<Backend>>, bool) {
        if let Some((server, _)) = query.split_once(':')
            && !server.is_empty()
            && !server.contains('*')
            && !server.contains('?')
        {
            return self
                .backends
                .get(server)
                .map_or_else(|| (Vec::new(), false), |backend| (vec![backend], true));
        }

        (self.backends.all(), false)
    }

    pub(super) async fn refresh_stale_backend_tools(backend: Arc<Backend>) {
        if let Err(e) = backend.get_tools_shared().await {
            debug!(
                backend = %backend.name,
                error = %e,
                "Background backend tool-cache refresh failed"
            );
        }
    }

    pub(super) fn refresh_stale_backend_tools_in_background(backend: &Arc<Backend>) {
        if !backend.has_cached_tools() {
            let backend = Arc::clone(backend);
            tokio::spawn(Self::refresh_stale_backend_tools(backend));
        }
    }
}
