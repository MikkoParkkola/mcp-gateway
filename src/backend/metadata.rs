// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Cached metadata accessors: tools, resources, resource templates, and
//! prompts, each backed by a single-flight [`super::cached_metadata::CachedMetadata`]
//! slot on [`super::Backend`]. The tools path lives here; the resources,
//! resource-template and prompts accessors are in `metadata_catalogues.rs`.

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

#[path = "metadata_stored_view.rs"]
mod stored_view;
use crate::Error;
use crate::Result;
use crate::oauth::login_gate::{Provenance, fill_scope};
use crate::protocol::{Tool, ToolsListResult};

// MIK-8014 PERF.12: the fresh-slot answer and completeness `tools_for_check` reads.
#[path = "metadata_fresh_check.rs"]
mod fresh_check;
#[cfg(feature = "webui")]
#[path = "metadata_preview.rs"]
mod preview;
// MIK-8393: the response cache's admission, read from the slot this file resolves.
#[path = "metadata_read_only.rs"]
mod read_only;
#[cfg(feature = "webui")]
pub(crate) use preview::{PreviewListing, list_tools_for_preview};
// The resources, resource-template and prompts accessors.
#[path = "metadata_catalogues.rs"]
mod catalogues;

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

    /// How many list fills on this backend have passed admission, or were
    /// joined while under way (any slot, any caller). A change across a check
    /// means a fill may have started, contacted the backend or been waited on
    /// meanwhile, possibly another caller's: read as an effect, that errs
    /// toward keeping a nonce spent (MIK-8353, r4 §70).
    pub(crate) fn list_fills(&self) -> u64 {
        self.list_fills.load(std::sync::atomic::Ordering::SeqCst)
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

    /// The tools and truncated flag of the slot `binding` selects (`None`: the
    /// shared one; MIK-8356) under one read guard. The fill writes the flag under
    /// the store's write guard, so the pair is never a truncated list beside a clear flag.
    #[must_use]
    pub(crate) fn cached_tools_snapshot_and_truncated(
        &self,
        binding: Option<&str>,
    ) -> (Arc<Vec<Tool>>, bool) {
        let slot = self.tools_slot(binding);
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

    /// F13: a stale-hit refresh that failed within [`LIST_FILL_COOLDOWN`] is
    /// refused before the guard is armed, so a refusal here never stamps.
    fn refuse_during_refresh_cooldown(
        &self,
        entry: &super::pool::PooledEntry,
        family: &ListFamily,
    ) -> Result<()> {
        let recent = || {
            let failed = entry.tools_refresh_failed_at.lock();
            failed.is_some_and(|at| at.elapsed() < LIST_FILL_COOLDOWN)
        };
        if family.stale_hit && recent() {
            return Err(Error::BackendUnavailable(format!(
                "{}: a stale tools refresh failed within the last {}s",
                self.name,
                LIST_FILL_COOLDOWN.as_secs()
            )));
        }
        Ok(())
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
        let fetch_headers: &[(String, String)] = identity_key.map_or(&[], |_| extra_headers);
        // Resolve the slot ONCE and keep it for both the cache and the fetch.
        let lease = self.begin_internal_activity_for(&key)?;
        let entry = Arc::clone(lease.entry());
        // A lent-only slot's fill, its start included, sends as this caller.
        let _loan = self.lend_to_slot(&key, &entry, fetch_headers)?;
        // MIK-8399: what a tools fill read, for the permit's abandon hook.
        let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let tools = family.truncated_flag.is_some();
        let on_abandon =
            tools.then(|| self.abandoned_fill_hook(Arc::clone(&entry), Arc::clone(&seen)));
        // Boxed: the fill's state is large, and every caller of this (and of
        // its callers) would otherwise carry it inline (clippy large_futures).
        // The log sink lives inside the box too: held in this frame across the
        // await, it grew every caller's boxed copy of this future past the
        // allocator's 2 KiB size class (ALLOC.2).
        Box::pin(async {
            // Log lines decided on under the cache's write guard, written after it.
            let pending_logs = crate::backend::descriptor_gate::PendingSink::default();
            let stored = select(&entry)
                .get_or_fetch_shared_then(
                    self.cache_ttl,
                    |mark| {
                        fill_scope(mark, async {
                            // F13: breaker, cooldown, token, in that order, before the
                            // guard is armed, so a refusal here never stamps.
                            self.refuse_during_refresh_cooldown(&entry, &family)?;
                            // A fill that would have to start a refused shared slot is
                            // refused before its admission, so it charges and counts
                            // nothing; one over a transport already in place starts
                            // nothing and is not a start.
                            if entry.transport.read().is_none() {
                                self.refuse_shared_start(&key)?;
                            }
                            let counted = (self.name.as_str(), &self.list_fills);
                            admit_fill(&entry, counted, bound, family.cooldown)?;
                            let mut guard =
                                family.cooldown.then(|| FillGuard::arm(Arc::clone(&entry)));
                            let drained = run_bounded(&entry, &self.name, bound, async {
                                // A cold fill on the dispatch path has sent no tools/call
                                // yet, so a failed start is a pre-send refusal (MIK-7979).
                                let transport =
                                    self.ensure_entry_started(&key).await.map_err(|e| {
                                        super::lifecycle::pre_send_start_error(&self.name, e)
                                    })?;
                                Provenance::mark_started();
                                let (merged, truncated) = drain_list_pages(
                                    transport.as_ref(),
                                    &self.name,
                                    &family,
                                    (fetch_headers, identity_key),
                                    tools.then_some(&*seen),
                                )
                                .await?;
                                let (items, prepared) = match merged {
                                    Some(result) => parse(result)?,
                                    None => (Vec::new(), None),
                                };
                                Ok((items, truncated, prepared))
                            })
                            .await;
                            let end = FillEnd::of(&drained);
                            if family.stale_hit
                                && drained.is_err()
                                && !matches!(end, FillEnd::Pending)
                            {
                                *entry.tools_refresh_failed_at.lock() =
                                    Some(tokio::time::Instant::now());
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
                        })
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
                            let logs =
                                self.store_prepared(&entry, identity_key, truncated, prepared);
                            pending_logs.store(logs);
                        }
                        // The only place a guard reaches `Stored`: a voided store
                        // drops it unrun, still `Drained`, and so stamps (F13).
                        if let Some(mut guard) = guard {
                            guard.end(FillEnd::Stored);
                        }
                    },
                    // A joiner classifies its deadline by this fill (MIK-8046), and
                    // counts as a fill: waiting on another request's fill under way is
                    // an effect, so a check that joined one keeps the nonce spent
                    // (MIK-8353, r4 §70). `None` is this caller running the fill
                    // itself, already counted by `admit_fill`.
                    |mark| {
                        if mark.is_some() {
                            self.list_fills.fetch_add(1, Ordering::SeqCst);
                        }
                        Provenance::joined(mark);
                    },
                    on_abandon,
                )
                .await;
            pending_logs.emit();
            stored
        })
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

    /// The longest one fill for a check may take: the backend's call timeout
    /// and the list wait's grace.
    pub(crate) fn tools_fill_bound(&self) -> std::time::Duration {
        self.config.timeout + super::fill_check::LIST_FILL_WAIT_GRACE
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
        // A fresh slot fetches nothing, so no lease, hook or deadline (PERF.12).
        if let Some(held) = self.fresh_tools_for_check(binding) {
            return Ok(held);
        }
        let limit = self.config.timeout;
        let fill = self.tools_fill(binding, headers, FillBound::CallTimeout(limit), stale_hit);
        // MIK-7982 C3/C4: both deadlines below read this caller's provenance.
        let bounded = async {
            tokio::time::timeout(self.tools_fill_bound(), fill)
                .await
                .unwrap_or_else(|_| {
                    Err(Provenance::expired(
                        &self.name,
                        super::fill_check::list_timeout(&self.name, limit),
                    ))
                })
        };
        let tools = Provenance::scope(&self.login_gate, bounded).await?;
        let completeness = self.held_completeness(binding, &tools);
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
