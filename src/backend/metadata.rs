// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Cached metadata accessors: tools, resources, resource templates, and
//! prompts, each backed by a single-flight [`super::cached_metadata::CachedMetadata`]
//! slot on [`super::Backend`].

use std::sync::Arc;

use serde_json::Value;
use tracing::debug;

use super::Backend;
use super::annotations::prepare_tool_metadata;
use super::cached_metadata::CachedMetadata;
use super::pool::PoolKey;
use crate::Error;
use crate::Result;
use crate::protocol::{
    Prompt, PromptsListResult, Resource, ResourceTemplate, ResourcesListResult,
    ResourcesTemplatesListResult, Tool, ToolsListResult,
};

impl Backend {
    /// The tool cache belonging to `binding`'s pool slot.
    ///
    /// THE ONE PLACE A METADATA CACHE IS SELECTED (MIK-7334.CATALOGUE.1 R3).
    /// No call site constructs a `PoolKey`: readers name a caller binding and
    /// this resolves it through `pool_key_for`, the same computation that
    /// selects the transport. Identity-free readers pass `None` through the
    /// named `*_shared`-style wrappers below, which is how `Shared` stays
    /// reachable without any caller spelling a key.
    fn tools_slot(&self, binding: Option<&str>) -> Arc<super::pool::PooledEntry> {
        self.pooled_entry(&self.pool_key_for(binding))
    }

    /// Whether `binding`'s slot holds a fresh tool cache (non-blocking).
    #[must_use]
    pub fn has_cached_tools_for(&self, binding: Option<&str>) -> bool {
        self.tools_slot(binding)
            .tools_cache
            .is_fresh(self.cache_ttl)
    }

    /// The shared slot's freshness. Used by readers that hold no caller.
    #[must_use]
    pub fn has_cached_tools(&self) -> bool {
        self.has_cached_tools_for(None)
    }

    /// Forget the SHARED slot's tool list so the next fetch reaches the backend.
    ///
    /// The one caller that needs this is warm-start reconfirming an EMPTY list.
    /// An empty result is cached with a fresh timestamp like any other, so
    /// without this a retry re-reads the same empty answer and never re-asks.
    ///
    /// NOT the revocation hook, and deliberately not reachable as one: it
    /// discards an empty list only, so routing revocation through it would be a
    /// silent no-op on every populated cache. Revocation evicts the identity's
    /// slot, which drops its transport and its caches together.
    pub fn invalidate_tools_cache(&self) {
        // Conditional on purpose: only an EMPTY list is discarded. Clearing
        // unconditionally could erase a tool list another reader populated
        // between the caller observing emptiness and acting on it, which would
        // turn a backend that had just become discoverable back into an
        // invisible one. The check happens under the cache's own write lock.
        self.tools_slot(None)
            .tools_cache
            .invalidate_if(Vec::is_empty);
    }

    /// Number of tools cached on `binding`'s slot (non-blocking, no network I/O).
    ///
    /// Returns `0` when that slot's cache is empty or never populated. Stale by
    /// design: it never triggers a refresh.
    #[must_use]
    pub fn cached_tools_count_for(&self, binding: Option<&str>) -> usize {
        self.tools_slot(binding)
            .tools_cache
            .with_cached(|tools| tools.map_or(0, |tools| tools.len()))
    }

    /// The shared slot's count.
    #[must_use]
    pub fn cached_tools_count(&self) -> usize {
        self.cached_tools_count_for(None)
    }

    /// `false` means the shared slot was never populated, not that it is empty.
    #[must_use]
    pub fn cached_tools_known(&self) -> bool {
        self.tools_slot(None).tools_cache.ever_populated()
    }

    /// Both under one guard; use wherever the two travel together.
    #[must_use]
    pub fn cached_tools_count_and_known(&self) -> (usize, bool) {
        self.tools_slot(None)
            .tools_cache
            .with_cached_and_populated(|tools, populated| {
                (tools.map_or(0, |tools| tools.len()), populated)
            })
    }

    /// Names of the tools cached on `binding`'s slot (non-blocking).
    ///
    /// Intended for "did you mean?" suggestions, which is exactly why the
    /// binding is threaded: one caller's tool NAMES surfacing in another
    /// caller's suggestions is this criterion's leak class arriving through the
    /// back door while the front door is sealed.
    #[must_use]
    pub fn get_cached_tool_names_for(&self, binding: Option<&str>) -> Vec<String> {
        self.tools_slot(binding).tools_cache.with_cached(|tools| {
            tools
                .map(|tools| tools.iter().map(|t| t.name.clone()).collect())
                .unwrap_or_default()
        })
    }

    /// The shared slot's tool names.
    #[must_use]
    pub fn get_cached_tool_names(&self) -> Vec<String> {
        self.get_cached_tool_names_for(None)
    }

    /// One tool by exact name from `binding`'s slot (non-blocking).
    #[must_use]
    pub fn get_cached_tool_for(&self, binding: Option<&str>, name: &str) -> Option<Tool> {
        self.tools_slot(binding).tools_cache.with_cached(|tools| {
            tools.and_then(|tools| tools.iter().find(|t| t.name == name).cloned())
        })
    }

    /// One tool by exact name from the shared slot.
    #[must_use]
    pub fn get_cached_tool(&self, name: &str) -> Option<Tool> {
        self.get_cached_tool_for(None, name)
    }

    /// Snapshot of the tools cached on `binding`'s slot (non-blocking).
    #[must_use]
    pub fn get_cached_tools_snapshot_for(&self, binding: Option<&str>) -> Arc<Vec<Tool>> {
        self.tools_slot(binding)
            .tools_cache
            .snapshot_shared()
            .unwrap_or_else(|| Arc::new(Vec::new()))
    }

    /// Snapshot of the shared slot's tools.
    #[must_use]
    pub fn get_cached_tools_snapshot(&self) -> Arc<Vec<Tool>> {
        self.get_cached_tools_snapshot_for(None)
    }

    /// Fill or serve one metadata list ON THE CALLER'S POOL SLOT
    /// (MIK-7334.CATALOGUE.1).
    ///
    /// TAKES A BINDING, NEVER A KEY, AND THAT IS THE GUARANTEE. All four
    /// metadata families come through here, and none of them can name a slot:
    /// the key is derived from `binding` by `pool_key_for`, the same
    /// computation that selects the transport. An earlier revision took a
    /// `&PoolKey`, and three of the four call sites passed the constant
    /// `PoolKey::Shared` — so resources, templates and prompts were filled once
    /// and answered to every caller. With the key derived here rather than
    /// chosen there, per-family drift is a type error rather than a convention
    /// each review has to re-verify.
    ///
    /// THE SLOT IS THE WHOLE POINT. `select` is handed the `PooledEntry` this
    /// fetch runs over, so the cache written and the transport written from are
    /// the same `Arc<PooledEntry>` — not two lookups that agree today. The fill
    /// closure has no way to reach `shared_transport()`, because the transport
    /// it uses is the one `ensure_entry_started(key)` returned for this slot, so
    /// a per-user slot cannot be filled with the static-credential answer.
    ///
    /// `claim_pooled_entry` via `begin_internal_activity_for`, never the
    /// unclaimed `pooled_entry`: the reaper is otherwise free to remove the slot
    /// and close the transport mid-fetch (R3).
    async fn get_cached_list_for<T, S, F>(
        &self,
        binding: Option<&str>,
        select: S,
        method: &str,
        kind: &'static str,
        extra_headers: &[(String, String)],
        parse: F,
    ) -> Result<Arc<Vec<T>>>
    where
        S: Fn(&super::pool::PooledEntry) -> &CachedMetadata<Vec<T>>,
        F: Fn(Value) -> Result<Vec<T>>,
    {
        let key = self.pool_key_for(binding);
        let identity_key = match &key {
            PoolKey::PerUser { binding: slot } => Some(slot.as_str()),
            PoolKey::Shared => None,
        };
        // MINTED HEADERS TRAVEL ONLY TO A SLOT THEIR OWNER HOLDS ALONE.
        // `pool_key_for` grants a private slot to `(per_user, binding)` and
        // nothing else, so a `stateless` backend — and a `per_user` one whose
        // caller resolved no binding — lands on `PoolKey::Shared` while the
        // resolver has still minted that caller a credential. Fetching under it
        // would write ONE caller's private catalogue into the entry every caller
        // reads, and serve it to all of them until TTL. Dropping the headers
        // there restores the identity-free fill the shared slot had before,
        // which is the documented `stateless` gap rather than a disclosure
        // (IDP.5). Closing that gap properly needs an uncached path or a
        // per-identity slot, and both are changes to `pool_key_for`.
        let fetch_headers: &[(String, String)] = match identity_key {
            Some(_) => extra_headers,
            None => &[],
        };
        // Resolve the slot ONCE and keep it for both the cache and the fetch.
        let lease = self.begin_internal_activity_for(&key);
        let entry = Arc::clone(lease.entry());
        select(&entry)
            .get_or_fetch_shared(self.cache_ttl, || async {
                let transport = self.ensure_entry_started(&key).await?;
                let response = transport
                    .request_with_headers(
                        method,
                        None,
                        fetch_headers,
                        identity_key,
                        // A `*/list` is in the side-effect-free allowlist
                        // (`transport::SIDE_EFFECT_FREE_METHODS`), so a retried
                        // fetch cannot duplicate an upstream effect.
                        crate::transport::ResendPermission::Permitted,
                    )
                    .await?;
                if let Some(error) = response.error {
                    return Err(Error::json_rpc(error.code, error.message));
                }
                let items = if let Some(result) = response.result {
                    parse(result)?
                } else {
                    Vec::new()
                };

                debug!(
                    backend = %self.name,
                    kind,
                    count = items.len(),
                    per_user = identity_key.is_some(),
                    "Backend metadata cached"
                );

                Ok(items)
            })
            .await
    }

    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the tools request fails.
    pub async fn get_tools_shared(&self) -> Result<Arc<Vec<Tool>>> {
        self.get_tools_for_binding(None, &[]).await
    }

    /// The tool catalogue THIS CALLER's pool slot serves.
    ///
    /// `binding` is the caller's `PropagatedCredential::cache_binding`, and
    /// `pool_key_for` turns it into a slot: `Some(binding)` on a
    /// `session_mode = per_user` backend selects that identity's own slot;
    /// everything else collapses to `Shared`, so single-tenant behaviour is
    /// byte-for-byte unchanged (IDP.5). `extra_headers` are the same minted
    /// headers the slot's transport was opened with, so the catalogue is fetched
    /// AS that caller rather than under the gateway's static credential — on a
    /// `PerUser` slot ONLY. Collapse to `Shared` and they are dropped: one cache
    /// entry answers every caller, so a fetch made under one caller's
    /// credential would hand that caller's catalogue to all of them.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the tools request fails.
    pub async fn get_tools_for_binding(
        &self,
        binding: Option<&str>,
        extra_headers: &[(String, String)],
    ) -> Result<Arc<Vec<Tool>>> {
        self.get_cached_list_for(
            binding,
            |entry| &entry.tools_cache,
            "tools/list",
            "tools",
            extra_headers,
            |result| {
                let mut tools = serde_json::from_value::<ToolsListResult>(result)?.tools;
                // Discovery is where the explicit annotations are still readable,
                // and it always precedes a `tools/call` (ADR-012 A1). Written to
                // THIS SLOT's set: a backend-wide one would let one identity's
                // catalogue decide another identity's retry policy.
                *self.tools_slot(binding).resend_permitted.write() =
                    prepare_tool_metadata(&self.name, &mut tools);
                Ok(tools)
            },
        )
        .await
    }

    /// Record the tools whose backend-declared annotations grant resend
    /// permission explicitly (ADR-012 A1).
    ///
    /// The internal discovery path writes this from `get_tools_shared`, but the
    /// direct `/mcp/{name}` route forwards `tools/list` itself and never goes
    /// through it. A client that only ever uses that route therefore left the
    /// set empty, and `resend_policy_for` denied retries to explicitly
    /// retry-safe tools. The permitted set must be captured before
    /// `normalize_tool_annotations` runs, which is why the caller passes the
    /// return value of `prepare_tool_metadata` rather than the tools.
    // The direct-route caller in `gateway::router::backend_handlers` is not on
    // this branch yet. `expect` rather than `allow` so the gate errors the
    // moment that caller lands and this marker must come off.
    #[expect(
        dead_code,
        reason = "direct-route caller lands with the resend plumbing"
    )]
    pub(crate) fn set_resend_permitted(&self, permitted: std::collections::HashSet<String>) {
        *self.tools_slot(None).resend_permitted.write() = permitted;
    }

    /// Snapshot of the tools currently recorded as explicitly resend-permitted.
    ///
    /// Clones under the read lock, like [`Self::get_cached_tools_snapshot`], so
    /// the caller never holds a guard. The dispatch-path reader
    /// (`Backend::resend_decision`) deliberately does NOT use this: it passes the
    /// guard straight to `resend_permission`, which is cheaper and runs on every
    /// dispatched request.
    ///
    /// This exists so a route that writes the set can prove it wrote it, which
    /// is a test's job: the production readers all take the guard directly, so
    /// under `--all-targets` the lib target compiles this away rather than
    /// carrying an accessor nothing calls.
    #[cfg(test)]
    #[must_use]
    #[expect(
        dead_code,
        reason = "direct-route caller lands with the resend plumbing"
    )]
    pub(crate) fn resend_permitted_snapshot(&self) -> std::collections::HashSet<String> {
        self.tools_slot(None).resend_permitted.read().clone()
    }

    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the tools request fails.
    pub async fn get_tools(&self) -> Result<Vec<Tool>> {
        self.get_tools_shared()
            .await
            .map(|tools| tools.as_ref().clone())
    }

    /// The resource catalogue the SHARED slot serves.
    ///
    /// For readers that hold no caller: startup prefetch, the operator UI, the
    /// provider adapter and `find_resource_owner`, whose subsequent
    /// `resources/read` runs over the shared transport too.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the resources request fails.
    pub async fn get_resources_shared(&self) -> Result<Arc<Vec<Resource>>> {
        self.get_resources_for_binding(None, &[]).await
    }

    /// The resource catalogue THIS CALLER's pool slot serves.
    ///
    /// Same contract as [`Self::get_tools_for_binding`]: `binding` is the
    /// caller's `PropagatedCredential::cache_binding`, everything that is not a
    /// `session_mode = per_user` backend with a binding collapses to the shared
    /// slot, and `extra_headers` are the headers that slot's transport was
    /// opened with — carried on a `PerUser` slot, dropped on the shared one.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the resources request fails.
    pub async fn get_resources_for_binding(
        &self,
        binding: Option<&str>,
        extra_headers: &[(String, String)],
    ) -> Result<Arc<Vec<Resource>>> {
        self.get_cached_list_for(
            binding,
            |entry| &entry.resources_cache,
            "resources/list",
            "resources",
            extra_headers,
            |result| Ok(serde_json::from_value::<ResourcesListResult>(result)?.resources),
        )
        .await
    }

    /// Get cached resources (or fetch if needed)
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the resources request fails.
    pub async fn get_resources(&self) -> Result<Vec<Resource>> {
        self.get_resources_shared()
            .await
            .map(|resources| resources.as_ref().clone())
    }

    /// The resource-template catalogue the SHARED slot serves.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the templates request fails.
    pub async fn get_resource_templates_shared(&self) -> Result<Arc<Vec<ResourceTemplate>>> {
        self.get_resource_templates_for_binding(None, &[]).await
    }

    /// The resource-template catalogue THIS CALLER's pool slot serves.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the templates request fails.
    pub async fn get_resource_templates_for_binding(
        &self,
        binding: Option<&str>,
        extra_headers: &[(String, String)],
    ) -> Result<Arc<Vec<ResourceTemplate>>> {
        self.get_cached_list_for(
            binding,
            |entry| &entry.resource_templates_cache,
            "resources/templates/list",
            "resource_templates",
            extra_headers,
            |result| {
                Ok(
                    serde_json::from_value::<ResourcesTemplatesListResult>(result)?
                        .resource_templates,
                )
            },
        )
        .await
    }

    /// Get cached resource templates (or fetch if needed)
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the templates request fails.
    pub async fn get_resource_templates(&self) -> Result<Vec<ResourceTemplate>> {
        self.get_resource_templates_shared()
            .await
            .map(|templates| templates.as_ref().clone())
    }

    /// The prompt catalogue the SHARED slot serves.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the prompts request fails.
    pub async fn get_prompts_shared(&self) -> Result<Arc<Vec<Prompt>>> {
        self.get_prompts_for_binding(None, &[]).await
    }

    /// The prompt catalogue THIS CALLER's pool slot serves.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the prompts request fails.
    pub async fn get_prompts_for_binding(
        &self,
        binding: Option<&str>,
        extra_headers: &[(String, String)],
    ) -> Result<Arc<Vec<Prompt>>> {
        self.get_cached_list_for(
            binding,
            |entry| &entry.prompts_cache,
            "prompts/list",
            "prompts",
            extra_headers,
            |result| Ok(serde_json::from_value::<PromptsListResult>(result)?.prompts),
        )
        .await
    }

    /// Get cached prompts (or fetch if needed)
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the prompts request fails.
    pub async fn get_prompts(&self) -> Result<Vec<Prompt>> {
        self.get_prompts_shared()
            .await
            .map(|prompts| prompts.as_ref().clone())
    }
}
