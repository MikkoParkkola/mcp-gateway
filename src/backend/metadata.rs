// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Cached metadata accessors: tools, resources, resource templates, and
//! prompts, each backed by a single-flight [`super::cached_metadata::CachedMetadata`]
//! slot on [`super::Backend`].

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::Value;
use tracing::debug;

use super::Backend;
use super::annotations::{PreparedTools, prepare_tool_metadata};
use super::cached_metadata::CachedMetadata;
use super::fill_check::{
    Completeness, FillBound, FillEnd, FillGuard, LIST_FILL_COOLDOWN, admit_fill, run_bounded,
};
use super::list_drain::drain_list_pages;
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
    ///
    /// A LOOKUP, NEVER A CREATE (#2300). Every reader here only reads, so a
    /// caller with no slot yet reads a cold entry that is never inserted:
    /// probes cannot fill the identity-slot cap. Fills go through
    /// `begin_internal_activity_for`, which admits the slot.
    fn tools_slot(&self, binding: Option<&str>) -> Arc<super::pool::PooledEntry> {
        self.pool.get(&self.pool_key_for(binding)).map_or_else(
            || {
                Arc::new(super::pool::PooledEntry::new(
                    &self.name,
                    &self.failsafe_config,
                ))
            },
            |slot| Arc::clone(slot.value()),
        )
    }

    /// Whether a stale hit's refresh on `binding`'s slot failed within the
    /// cooldown (A4), so a stale hit is judged from the held schema at once.
    pub(super) fn stale_refresh_cooling(&self, binding: Option<&str>) -> bool {
        self.tools_slot(binding)
            .tools_refresh_failed_at
            .lock()
            .is_some_and(|at| at.elapsed() < LIST_FILL_COOLDOWN)
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
        // "Empty" is what callers are served: a list whose every tool has
        // since been blocked reads as empty, so it is discarded too (#1441).
        self.tools_slot(None)
            .tools_cache
            .invalidate_if(|tools| self.all_blocked(tools));
    }

    /// Number of tools cached on `binding`'s slot (non-blocking, no network I/O).
    ///
    /// Returns `0` when that slot's cache is empty or never populated. Stale by
    /// design: it never triggers a refresh.
    #[must_use]
    pub fn cached_tools_count_for(&self, binding: Option<&str>) -> usize {
        self.tools_slot(binding).tools_cache.with_cached(|tools| {
            tools.map_or(0, |tools| {
                tools
                    .iter()
                    .filter(|t| !self.is_blocked_tool(&t.name))
                    .count()
            })
        })
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

    /// The shared slot's tools and truncated flag under one read guard. The
    /// fill writes the flag under the store's write guard, so this pair is
    /// never a truncated list beside a clear flag.
    #[must_use]
    pub(crate) fn cached_tools_snapshot_and_truncated(&self) -> (Arc<Vec<Tool>>, bool) {
        let slot = self.tools_slot(None);
        let (tools, truncated) = slot.tools_cache.with_cached(|tools| {
            (
                tools.map_or_else(|| Arc::new(Vec::new()), Arc::clone),
                slot.tools_truncated.load(Ordering::SeqCst),
            )
        });
        (self.without_blocked(tools), truncated)
    }

    /// Both under one guard; use wherever the two travel together.
    #[must_use]
    pub fn cached_tools_count_and_known(&self) -> (usize, bool) {
        self.tools_slot(None)
            .tools_cache
            .with_cached_and_populated(|tools, populated| {
                let count = tools.map_or(0, |tools| {
                    tools
                        .iter()
                        .filter(|t| !self.is_blocked_tool(&t.name))
                        .count()
                });
                (count, populated)
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
        let names: Vec<String> = self.tools_slot(binding).tools_cache.with_cached(|tools| {
            tools
                .map(|tools| tools.iter().map(|t| t.name.clone()).collect())
                .unwrap_or_default()
        });
        names
            .into_iter()
            .filter(|name| !self.is_blocked_tool(name))
            .collect()
    }

    /// The shared slot's tool names.
    #[must_use]
    pub fn get_cached_tool_names(&self) -> Vec<String> {
        self.get_cached_tool_names_for(None)
    }

    /// One tool by exact name from `binding`'s slot (non-blocking).
    #[must_use]
    pub fn get_cached_tool_for(&self, binding: Option<&str>, name: &str) -> Option<Tool> {
        self.with_cached_tool_for(binding, name, Tool::clone)
    }

    /// Read one tool by exact name from `binding`'s slot in place
    /// (non-blocking), under the same withheld-name rule as
    /// [`Self::get_cached_tool_for`]. Per-call readers take only what they
    /// need instead of cloning the whole tool, schemas included
    /// (NFR.WORKLOAD.1). `read` runs under the cache's read guard.
    pub(crate) fn with_cached_tool_for<R>(
        &self,
        binding: Option<&str>,
        name: &str,
        read: impl FnOnce(&Tool) -> R,
    ) -> Option<R> {
        if self.is_blocked_tool(name) {
            return None;
        }
        self.tools_slot(binding).tools_cache.with_cached(|tools| {
            tools.and_then(|tools| tools.iter().find(|t| t.name == name).map(read))
        })
    }

    /// One tool by exact name from the shared slot.
    #[must_use]
    pub fn get_cached_tool(&self, name: &str) -> Option<Tool> {
        self.get_cached_tool_for(None, name)
    }

    /// The list `binding`'s slot holds now, fresh or not, with its
    /// completeness, read under one cache guard; `None` when empty.
    pub(super) fn held_tools_for(
        &self,
        binding: Option<&str>,
    ) -> Option<(Arc<Vec<Tool>>, Completeness)> {
        let slot = self.tools_slot(binding);
        slot.tools_cache.with_cached(|held| {
            let completeness = Completeness::held(slot.tools_truncated.load(Ordering::SeqCst));
            held.map(|list| (Arc::clone(list), completeness))
        })
    }

    /// Snapshot of the tools cached on `binding`'s slot (non-blocking).
    #[must_use]
    pub fn get_cached_tools_snapshot_for(&self, binding: Option<&str>) -> Arc<Vec<Tool>> {
        self.without_blocked(
            self.tools_slot(binding)
                .tools_cache
                .snapshot_shared()
                .unwrap_or_else(|| Arc::new(Vec::new())),
        )
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
    ///
    /// `bound` is `DrainBudget` for every caller but R2's check (F13), which
    /// passes `CallTimeout`: see [`super::fill_check`] for what that adds.
    async fn get_cached_list_for<T, S, F>(
        &self,
        binding: Option<&str>,
        select: S,
        family: ListFamily,
        extra_headers: &[(String, String)],
        bound: FillBound,
        parse: F,
    ) -> Result<Arc<Vec<T>>>
    where
        S: Fn(&super::pool::PooledEntry) -> &CachedMetadata<Vec<T>>,
        F: Fn(Value) -> Result<(Vec<T>, Option<PreparedTools>)>,
    {
        let key = self.pool_key_for(binding);
        let identity_key = match &key {
            PoolKey::PerUser { binding: slot } => Some(slot.as_str()),
            PoolKey::Shared => None,
        };
        // MINTED HEADERS TRAVEL ONLY TO A SLOT THEIR OWNER HOLDS ALONE.
        // `pool_key_for` grants a private slot to a propagation-configured
        // backend whose caller resolved a binding, and nothing else — so a
        // caller with no resolved binding lands on `PoolKey::Shared` while the
        // resolver may still have minted a credential for somebody. Fetching
        // under it would write ONE caller's private catalogue into the entry
        // every caller reads, and serve it to all of them until TTL. Dropping
        // the headers there keeps the shared slot's fill identity-free (IDP.5).
        //
        // DEFENCE IN DEPTH AFTER MIK-7334.CATALOGUE.1, not a live guard: no
        // production path now produces non-empty headers with a `None` binding
        // — `PropagatedCredential::cache_binding` is a `String`, not an
        // `Option`, and both sites where a `None` binding arises return empty
        // headers with it. `stateless_tools_slot_tests` keeps a cell that fails
        // if this is deleted, because every other cell would still pass.
        let fetch_headers: &[(String, String)] = match identity_key {
            Some(_) => extra_headers,
            None => &[],
        };
        // Resolve the slot ONCE and keep it for both the cache and the fetch.
        let lease = self.begin_internal_activity_for(&key)?;
        let entry = Arc::clone(lease.entry());
        select(&entry)
            .get_or_fetch_shared_then(
                self.cache_ttl,
                || async {
                    // F13: breaker, cooldown, token, in that order, before the
                    // guard is armed, so a refusal here never stamps.
                    let refresh_failed = || entry.tools_refresh_failed_at.lock();
                    if family.stale_hit
                        && refresh_failed().is_some_and(|at| at.elapsed() < LIST_FILL_COOLDOWN)
                    {
                        return Err(Error::BackendUnavailable(format!(
                            "{}: a stale tools refresh failed within the last {}s",
                            self.name,
                            LIST_FILL_COOLDOWN.as_secs()
                        )));
                    }
                    admit_fill(&entry, &self.name, bound, family.cooldown)?;
                    let mut guard = family.cooldown.then(|| FillGuard::arm(Arc::clone(&entry)));
                    let drained = run_bounded(&entry, &self.name, bound, async {
                        // A cold fill on the dispatch path has sent no tools/call
                        // yet, so a failed start is a pre-send refusal (MIK-7979).
                        let transport = self
                            .ensure_entry_started(&key)
                            .await
                            .map_err(|e| super::lifecycle::pre_send_start_error(&self.name, e))?;
                        let (merged, truncated) = drain_list_pages(
                            transport.as_ref(),
                            &self.name,
                            &family,
                            fetch_headers,
                            identity_key,
                        )
                        .await?;
                        let (items, prepared) = match merged {
                            Some(result) => parse(result)?,
                            None => (Vec::new(), None),
                        };
                        Ok((items, truncated, prepared))
                    })
                    .await;
                    let end = match &drained {
                        Ok(_) => FillEnd::Drained,
                        Err(e) => match super::fill_check::Replay::of(e) {
                            None if super::fill_check::is_transport_failure(e) => {
                                FillEnd::Unreplayable
                            }
                            transport => FillEnd::Failed { transport },
                        },
                    };
                    if family.stale_hit && drained.is_err() {
                        *refresh_failed() = Some(tokio::time::Instant::now());
                    }
                    if let Some(guard) = guard.as_mut() {
                        guard.end(end);
                    }
                    let (items, truncated, prepared) = drained?;

                    debug!(
                        backend = %self.name,
                        kind = family.kind,
                        count = items.len(),
                        per_user = identity_key.is_some(),
                        "Backend metadata cached"
                    );

                    Ok((items, (truncated, guard, prepared)))
                },
                |(truncated, guard, prepared)| {
                    // Written only once the store is accepted, and on every
                    // accepted store, so a complete fill clears it (design D).
                    if let Some(flag) = family.truncated_flag {
                        flag(&entry).store(truncated, Ordering::SeqCst);
                    }
                    // Only this accepted store's own set and verdicts (F13,
                    // #1441).
                    if let Some(prepared) = prepared {
                        *entry.resend_permitted.write() = prepared.resend_permitted;
                        let listing = if truncated {
                            super::descriptor_gate::Listing::Truncated
                        } else {
                            super::descriptor_gate::Listing::Complete
                        };
                        self.commit_verdicts(
                            identity_key.unwrap_or(""),
                            listing,
                            prepared.verdicts,
                        );
                    }
                    // The only place a guard reaches `Stored`: a voided store
                    // drops it unrun, still `Drained`, and so stamps (F13).
                    if let Some(mut guard) = guard {
                        guard.end(FillEnd::Stored);
                    }
                },
            )
            .await
    }

    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the tools request fails.
    pub async fn get_tools_shared(&self) -> Result<Arc<Vec<Tool>>> {
        self.get_tools_for_binding(None, &[]).await
    }

    /// Startup warm-up's fill: recorded on the breaker, never admitted or
    /// charged a token (#1300). Warm-start is its only caller.
    pub(crate) async fn warm_tools(&self) -> Result<Arc<Vec<Tool>>> {
        self.tools_fill(None, &[], FillBound::Warmup, false).await
    }

    /// The tool catalogue THIS CALLER's pool slot serves.
    ///
    /// `binding` is the caller's `PropagatedCredential::cache_binding`, and
    /// `pool_key_for` turns it into a slot: `Some(binding)` on any
    /// propagation-configured backend — `per_user` or `stateless` — selects that
    /// identity's own slot; everything else collapses to `Shared`, so
    /// single-tenant behaviour is byte-for-byte unchanged (IDP.5, which ADR-007
    /// scopes to ABSENT propagation config). `extra_headers` are the same minted
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
        let tools = self
            .tools_fill(binding, extra_headers, FillBound::DrainBudget, false)
            .await?;
        Ok(self.without_blocked(tools))
    }

    /// [`Self::get_tools_for_binding`] under an explicit bound; R2's check
    /// passes `CallTimeout` through [`Self::tools_for_check`]. The list is
    /// returned as the slot stored it, withheld names included: the check
    /// compares it by pointer with what the slot holds, and re-checks the
    /// name against the blocked set itself.
    async fn tools_fill(
        &self,
        binding: Option<&str>,
        extra_headers: &[(String, String)],
        bound: FillBound,
        stale_hit: bool,
    ) -> Result<Arc<Vec<Tool>>> {
        self.get_cached_list_for(
            binding,
            |entry| &entry.tools_cache,
            ListFamily {
                method: "tools/list",
                kind: "tools",
                list_key: "tools",
                truncated_flag: Some(tools_truncated_flag),
                cooldown: true,
                stale_hit,
            },
            extra_headers,
            bound,
            |result| {
                // Entry by entry: one malformed entry must neither fail the
                // fill nor hide its siblings from judging; a named one that
                // does not parse is withheld (#1441).
                let (mut tools, unparseable) = match result.get("tools").and_then(Value::as_array) {
                    Some(raw) => super::descriptor_gate::parse_listed(raw),
                    None => (
                        serde_json::from_value::<ToolsListResult>(result)?.tools,
                        Vec::new(),
                    ),
                };
                // Discovery is where the explicit annotations are still readable,
                // and it always precedes a `tools/call` (ADR-012 A1). The resend
                // set and the verdicts travel with THIS fill's result and are
                // published by its accepted store only, so a voided fill can
                // neither restore a revoked resend nor commit a block (F13,
                // #1441). Judged here, on the raw list, before any redaction.
                let mut prepared = prepare_tool_metadata(
                    &self.name,
                    self.flagged_tool_pins(),
                    super::Judging::Judge,
                    &mut tools,
                );
                prepared.verdicts.add_unparseable(unparseable);
                Ok((tools, Some(prepared)))
            },
        )
        .await
    }

    /// The caller's tool list for R2's check, and whether it is the slot's
    /// whole catalogue (design §2 step 2).
    ///
    /// A leading caller's fill is bounded by `timeout`, a waiter's by
    /// `timeout` plus `LIST_FILL_WAIT_GRACE`. Only a list the slot still holds
    /// (`Arc::ptr_eq`, read under its guard) is `Complete` or `Truncated`, so
    /// a voided store is `Unknown`. Beside `tools_slot` so neither widens.
    pub(crate) async fn tools_for_check(
        &self,
        binding: Option<&str>,
        headers: &[(String, String)],
        stale_hit: bool,
    ) -> Result<(Arc<Vec<Tool>>, Completeness)> {
        let limit = self.config.timeout;
        let fill = self.tools_fill(binding, headers, FillBound::CallTimeout(limit), stale_hit);
        let tools = tokio::time::timeout(limit + super::fill_check::LIST_FILL_WAIT_GRACE, fill)
            .await
            .unwrap_or_else(|_| Err(super::fill_check::list_timeout(&self.name, limit)))?;
        let slot = self.tools_slot(binding);
        let completeness = slot.tools_cache.with_cached(|current| match current {
            Some(held) if Arc::ptr_eq(held, &tools) => {
                Completeness::held(slot.tools_truncated.load(Ordering::SeqCst))
            }
            _ => Completeness::Unknown,
        });
        Ok((tools, completeness))
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
    /// For readers that hold no caller: startup prefetch, the operator UI and
    /// the provider adapter.
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
    /// propagating backend with a binding collapses to the shared slot, and `extra_headers` are the headers that slot's transport was
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
            ListFamily {
                method: "resources/list",
                kind: "resources",
                list_key: "resources",
                truncated_flag: Some(resources_truncated_flag),
                cooldown: false,
                stale_hit: false,
            },
            extra_headers,
            FillBound::DrainBudget,
            |result| {
                Ok((
                    serde_json::from_value::<ResourcesListResult>(result)?.resources,
                    None,
                ))
            },
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
            ListFamily {
                method: "resources/templates/list",
                kind: "resource_templates",
                list_key: "resourceTemplates",
                truncated_flag: None,
                cooldown: false,
                stale_hit: false,
            },
            extra_headers,
            FillBound::DrainBudget,
            |result| {
                let templates = serde_json::from_value::<ResourcesTemplatesListResult>(result)?;
                Ok((templates.resource_templates, None))
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
            ListFamily {
                method: "prompts/list",
                kind: "prompts",
                list_key: "prompts",
                truncated_flag: None,
                cooldown: false,
                stale_hit: false,
            },
            extra_headers,
            FillBound::DrainBudget,
            |result| {
                Ok((
                    serde_json::from_value::<PromptsListResult>(result)?.prompts,
                    None,
                ))
            },
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

/// One `*/list` family as the shared cache fill sees it.
#[derive(Clone, Copy)]
pub(super) struct ListFamily {
    pub(super) method: &'static str,
    kind: &'static str,
    /// The result's array key; `resourceTemplates` differs from its `kind`.
    pub(super) list_key: &'static str,
    /// Only the tools family records truncation (MIK 7570 PAGING.1 design D).
    truncated_flag: Option<fn(&super::pool::PooledEntry) -> &AtomicBool>,
    /// Only the tools family keeps a failure cooldown (F13): a resources or
    /// prompts failure must never make a tools fill fail fast.
    cooldown: bool,
    /// A stale hit's refresh (A4): it honours `tools_refresh_failed_at` at
    /// admission, so a caller waiting inside the fill does not retry a
    /// failure the cooldown already covers, and it stamps that on failure.
    stale_hit: bool,
}

/// The resources family's truncated flag (the events listener's snapshot).
fn resources_truncated_flag(entry: &super::pool::PooledEntry) -> &AtomicBool {
    &entry.resources_truncated
}

/// The tools family's truncated flag; the other three families keep their
/// pages without one (MIK 7570 PAGING.1 design D).
fn tools_truncated_flag(entry: &super::pool::PooledEntry) -> &AtomicBool {
    &entry.tools_truncated
}
