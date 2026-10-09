// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Capability backend - integrates capabilities with the gateway
//!
//! This module provides a bridge between the capability system and the
//! gateway's backend infrastructure, allowing capabilities to appear
//! as tools via the Meta-MCP interface.
//!
//! # Hot Reload
//!
//! The backend supports hot-reloading of capabilities. When capability
//! files change, call `reload()` to refresh the registry without
//! restarting the gateway.
//!
//! # O(1) Lookup
//!
//! Capability lookup by name is O(1) via a `HashMap<String, usize>` index
//! that maps tool names to positions in the ordered `Vec`.  The tool MCP
//! representation is pre-built once and cached so `get_tools()` is a cheap
//! `Vec::clone()` rather than N calls to `to_mcp_tool()`.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use serde_json::Value;
use tracing::{debug, info, warn};

use super::hash::compute_capability_hash;
use super::schema_validator::validate_arguments;
use super::{
    CapabilityDefinition, CapabilityExecutionContext, CapabilityExecutor, CapabilityLoader,
    validate_capability_account_binding, validate_oauth_isolation,
    validate_personal_capability_identity,
};
use crate::Result;
use crate::protocol::{Content, Tool, ToolsCallResult};

mod definition_access;
mod initial_scan;
mod path_selector;

use path_selector::path_selector_type_error;

/// Ordered capability store with an O(1) name-to-index lookup layer.
///
/// Maintaining both a `Vec` (for stable iteration order) and a `HashMap`
/// index (for O(1) lookup) costs one extra word per entry and one
/// `HashMap` lookup per `get()` / `has_capability()` call — a trade-off
/// that is strictly beneficial once the collection exceeds ~4 entries.
///
/// The pre-built `tools` cache amortises `to_mcp_tool()` across all
/// `get_tools()` callers: the conversion runs exactly once per load/reload,
/// not once per call.
#[derive(Default)]
struct IndexedCapabilities {
    /// Stable insertion-order storage.
    entries: Vec<CapabilityDefinition>,
    /// O(1) name → `entries` index.
    index: HashMap<String, usize>,
    /// Pre-built MCP `Tool` representations — rebuilt whenever `entries` changes.
    tools: Vec<Tool>,
    /// Read yet absent: gate refusals (rebuilt by each reload) and unloads (until admitted).
    refused: std::collections::HashSet<String>,
    unloaded: std::collections::HashSet<String>,
}

/// True when `new` differs from `old` in any serialised field. A definition
/// that cannot be serialised is treated as changed (revoke rather than keep).
fn definition_changed(old: &CapabilityDefinition, new: &CapabilityDefinition) -> bool {
    match (serde_json::to_value(old), serde_json::to_value(new)) {
        (Ok(a), Ok(b)) => a != b,
        _ => true,
    }
}

impl IndexedCapabilities {
    /// Insert or replace a capability, maintaining index and tool cache consistency.
    fn upsert(&mut self, cap: CapabilityDefinition) {
        let tool = cap.to_mcp_tool();
        if let Some(&pos) = self.index.get(&cap.name) {
            self.entries[pos] = cap;
            self.tools[pos] = tool;
        } else {
            let pos = self.entries.len();
            self.index.insert(cap.name.clone(), pos);
            self.entries.push(cap);
            self.tools.push(tool);
        }
    }

    /// Replace all entries atomically, rebuilding both index and tool cache.
    fn replace_all(&mut self, caps: Vec<CapabilityDefinition>) {
        self.index.clear();
        self.tools.clear();
        self.entries = Vec::with_capacity(caps.len());
        self.tools = Vec::with_capacity(caps.len());
        self.index = HashMap::with_capacity(caps.len());
        for cap in caps {
            let tool = cap.to_mcp_tool();
            let pos = self.entries.len();
            self.index.insert(cap.name.clone(), pos);
            self.entries.push(cap);
            self.tools.push(tool);
        }
    }

    /// O(1) capability lookup by name.
    #[inline]
    fn get(&self, name: &str) -> Option<&CapabilityDefinition> {
        self.index.get(name).map(|&i| &self.entries[i])
    }

    /// O(1) existence check.
    #[inline]
    fn contains(&self, name: &str) -> bool {
        self.index.contains_key(name)
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ============================================================================
// CapabilityBackend
// ============================================================================

/// The outcome of loading one capability directory.
///
/// `rejected` holds one rendered refusal per capability the account admission
/// gate turned away, so a caller that must not serve a partially admitted
/// catalogue can fail instead of only logging.
#[derive(Debug, Default, Clone)]
pub struct DirectoryLoad {
    /// Capabilities that entered the tool surface.
    pub admitted: usize,
    /// `"<capability>: <error>"` for each refused capability, in load order.
    pub rejected: Vec<String>,
}

/// Backend that exposes capabilities as MCP tools
///
/// This backend is thread-safe and supports hot-reloading via the
/// `reload()` method.
pub struct CapabilityBackend {
    /// Backend name (for gateway integration)
    pub name: String,
    /// Executor for running capabilities
    executor: Arc<CapabilityExecutor>,
    /// Indexed capability store — O(1) name lookup + pre-built tool cache.
    capabilities: RwLock<IndexedCapabilities>,
    /// Directories to load capabilities from
    directories: RwLock<Vec<String>>,
    /// Capability names currently quarantined by a rug-pull detection event.
    ///
    /// Populated by the file watcher when an on-disk YAML's `sha256:` pin no
    /// longer matches its content. Quarantined names are removed from the
    /// active tool set and will NOT be automatically re-loaded by `reload()`
    /// until the operator clears the state (e.g. by re-running
    /// `mcp-gateway cap pin` after reviewing the diff).
    rug_pull_state: RwLock<HashMap<String, RugPullRecord>>,
    /// Declares whether the owning gateway serves more than one principal
    /// (ADR-008 INV-2 parity, MIK-6751). Mirrors `MetaMcp::multi_user`;
    /// `MetaMcp::set_multi_user`/`set_capabilities` keep the two in sync since
    /// they may be set in either order at startup. Read by
    /// [`validate_oauth_isolation`] inside `call_tool_with_context`.
    multi_user: std::sync::atomic::AtomicBool,
    initial_scan: std::sync::atomic::AtomicU8,
    /// Moves at every catalogue write, under the write lock (MIK-8037).
    catalogue_generation: std::sync::atomic::AtomicU64,
}

/// Record of a detected rug-pull event for a single capability.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RugPullRecord {
    /// Capability name that was quarantined.
    pub capability: String,
    /// File that failed hash verification.
    pub file: String,
    /// Pinned hash that was expected.
    pub expected: String,
    /// Hash actually observed on disk at detection time.
    pub actual: String,
}

impl CapabilityBackend {
    /// Create a new capability backend
    pub fn new(name: &str, executor: Arc<CapabilityExecutor>) -> Self {
        Self {
            name: name.to_string(),
            executor,
            capabilities: RwLock::new(IndexedCapabilities::default()),
            directories: RwLock::new(Vec::new()),
            rug_pull_state: RwLock::new(HashMap::new()),
            multi_user: std::sync::atomic::AtomicBool::new(false),
            initial_scan: std::sync::atomic::AtomicU8::new(1), // bits, see initial_scan.rs
            catalogue_generation: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Declare whether the owning gateway serves more than one principal
    /// (ADR-008 INV-2 parity, MIK-6751). Called by
    /// `MetaMcp::set_multi_user`/`set_capabilities` to keep this backend's
    /// view in sync with `MetaMcp::multi_user` regardless of setter order.
    pub fn set_multi_user(&self, multi_user: bool) {
        self.multi_user
            .store(multi_user, std::sync::atomic::Ordering::Relaxed);
        self.executor.set_multi_user(multi_user);
    }

    /// Whether the capability backend is currently considered healthy by its
    /// outbound-transport health tracker (owned by the executor).
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.executor.is_healthy()
    }

    /// Remove a capability from the live tool set.
    ///
    /// Used by the file watcher when a rug-pull is detected so that the
    /// tampered capability is no longer callable until the operator
    /// explicitly re-pins it.
    ///
    /// A removal is a live-policy mutation, so it bumps the shared policy
    /// epoch while the write lock is still held — exactly as `reload()` does.
    /// Without that, outer and inner cache entries for the quarantined
    /// capability stay servable under the unchanged epoch; the watcher happens
    /// to call `reload()` immediately afterwards, but this method is `pub` and
    /// no caller is obliged to.
    pub fn unload_capability(&self, name: &str) -> bool {
        let mut caps = self.capabilities.write();
        let removed = if let Some(&pos) = caps.index.get(name) {
            caps.entries.remove(pos);
            caps.tools.remove(pos);
            caps.index.remove(name);
            caps.unloaded.insert(name.to_owned());
            // Shift remaining indices down.
            for idx in caps.index.values_mut() {
                if *idx > pos {
                    *idx -= 1;
                }
            }
            // Published, and the lock still held: no reader can observe the
            // removal under the old epoch.
            self.executor.bump_policy_epoch();
            self.executor.bump_mcp_generation(name);
            self.bump_catalogue_generation(&caps);
            true
        } else {
            false
        };
        drop(caps);
        // After the epoch bump: a call that started before it is stopped here,
        // and one that starts after it is refused at `acquire`.
        self.executor.stop_unloaded_mcp(&|loaded| loaded != name);
        removed
    }

    /// Mark a capability as quarantined by a rug-pull event.
    ///
    /// Records the expected vs. actual hashes so operators have an audit
    /// trail when they come to review the incident.
    pub fn mark_rug_pull(&self, record: RugPullRecord) {
        self.rug_pull_state
            .write()
            .insert(record.capability.clone(), record);
    }

    /// Check whether a capability is currently quarantined.
    pub fn is_rug_pulled(&self, name: &str) -> bool {
        self.rug_pull_state.read().contains_key(name)
    }

    /// Snapshot all active rug-pull records (e.g. for status / observability).
    pub fn rug_pull_records(&self) -> Vec<RugPullRecord> {
        self.rug_pull_state.read().values().cloned().collect()
    }

    /// Pre-register watched directories without loading any capability YAMLs.
    ///
    /// Used at startup so the file watcher (`CapabilityWatcher::start`) can
    /// see the configured directory list synchronously, before the async
    /// `load_from_directory` task has had a chance to push paths via
    /// the loader path. Without this, the watcher races the loader and
    /// logs "No capability directories to watch" because the spawned
    /// loader has not yet populated `self.directories`.
    ///
    /// Duplicates are skipped; safe to call repeatedly.
    pub fn register_directories(&self, paths: &[String]) {
        let mut dirs = self.directories.write();
        for path in paths {
            if !dirs.contains(path) {
                dirs.push(path.clone());
            }
        }
    }

    /// Load capabilities from a directory
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be loaded.
    pub async fn load_from_directory(&self, path: &str) -> Result<usize> {
        Ok(self.load_from_directory_reporting(path).await?.admitted)
    }

    /// Load a directory and REPORT, rather than only log, every capability the
    /// account admission gate refused.
    ///
    /// `load_from_directory` keeps its log-and-drop behaviour for the hot-reload
    /// and account-less paths. Startup uses this variant so an invalid
    /// `auth.account` binding present in the INITIAL catalogue can be turned
    /// into a startup failure instead of a warning behind a serving listener.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory itself cannot be loaded. A refused
    /// capability is not an error here — it is reported in
    /// [`DirectoryLoad::rejected`] so the caller decides.
    pub async fn load_from_directory_reporting(&self, path: &str) -> Result<DirectoryLoad> {
        let loaded = CapabilityLoader::load_directory(path).await?;
        let mut report = DirectoryLoad {
            admitted: loaded.len(),
            rejected: Vec::new(),
        };

        // Register directory for future hot-reloads.
        {
            let mut dirs = self.directories.write();
            if !dirs.contains(&path.to_string()) {
                dirs.push(path.to_string());
            }
        }

        // Upsert each capability into the indexed store, through the account
        // admission gate. A refused capability is LOGGED and dropped rather
        // than published: the operator gets a named error, and no caller gets a
        // tool whose account reference cannot resolve.
        for cap in loaded {
            let capability = cap.name.clone();
            if let Err(error) = self.register_capability(cap) {
                warn!(
                    backend = %self.name,
                    capability = %capability,
                    error = %error,
                    "Capability refused: its account binding does not resolve"
                );
                report.admitted -= 1;
                self.note_refused(&capability);
                report.rejected.push(format!("{capability}: {error}"));
            }
            tokio::task::yield_now().await;
        }

        info!(backend = %self.name, count = report.admitted, path = path, "Loaded capabilities");
        Ok(report)
    }

    /// Reload all capabilities from registered directories
    ///
    /// This is the hot-reload entry point. It re-reads all capability
    /// files from the registered directories and updates the registry.
    ///
    /// # Errors
    ///
    /// Returns an error if reloading fails for all directories.
    pub async fn reload(&self) -> Result<usize> {
        let dirs: Vec<String> = self.directories.read().clone();

        if dirs.is_empty() {
            debug!(backend = %self.name, "No directories to reload");
            return Ok(0);
        }

        let mut all_caps = Vec::new();
        let mut total = 0;
        // A directory that could not be read leaves the catalogue partial:
        // its capabilities are missing from this load, not deleted (MIK-8028).
        let mut partial = false;

        for dir in &dirs {
            match CapabilityLoader::load_directory(dir).await {
                Ok(loaded) => {
                    total += loaded.len();
                    all_caps.extend(loaded);
                }
                Err(e) => {
                    partial = true;
                    warn!(backend = %self.name, directory = %dir, error = %e, "Failed to reload directory");
                }
            }
        }

        // The same admission gate the initial load applies.
        let mut admitted = Vec::with_capacity(all_caps.len());
        let mut refused = std::collections::HashSet::new();
        for cap in all_caps {
            match validate_capability_account_binding(&cap, self.executor.account_strategies()) {
                Ok(()) => admitted.push(cap),
                Err(error) => {
                    total -= 1;
                    refused.insert(cap.name.clone());
                    warn!(
                        backend = %self.name,
                        capability = %cap.name,
                        error = %error,
                        "Capability refused on reload: its account binding does not resolve"
                    );
                }
            }
        }

        // Atomic swap: rebuild index and tool cache in one write lock, then
        // bump the shared policy epoch while that lock is still held.
        {
            let mut caps = self.capabilities.write();
            let incoming: HashMap<&str, &CapabilityDefinition> =
                admitted.iter().map(|c| (c.name.as_str(), c)).collect();
            // Revoke the in-flight calls of a capability that is gone OR edited,
            // and stop its children: a call holding the old definition must not
            // start or replace a child under the new one (MIK-7870, MIK-7925).
            let mut revoked = std::collections::HashSet::new();
            for (name, &pos) in &caps.index {
                if incoming
                    .get(name.as_str())
                    .is_none_or(|new| definition_changed(&caps.entries[pos], new))
                {
                    self.executor.bump_mcp_generation(name);
                    revoked.insert(name.clone());
                }
            }
            caps.replace_all(admitted);
            caps.settle_absent(refused);
            // With the swap, under the same lock: `catalogue_snapshot` never
            // sees one without the other.
            self.set_catalogue_partial(partial);
            self.bump_catalogue_generation(&caps);
            self.executor.bump_policy_epoch();
            self.executor.stop_unloaded_mcp(&|name| {
                !revoked.contains(name) && caps.index.contains_key(name)
            });
        }

        info!(backend = %self.name, count = total, directories = dirs.len(), "Hot-reloaded capabilities");
        Ok(total)
    }

    /// Get the tools clients are shown (pre-built MCP tool representations).
    ///
    /// A capability whose required login is missing is left out until it is
    /// supplied (MIK-7787 D4): the catalogue is a library, and a tool that
    /// can only fail is noise in every listing.
    pub fn get_tools(&self) -> Vec<Tool> {
        let caps = self.capabilities.read();
        let mut oauth_seen = HashMap::new();
        caps.entries
            .iter()
            .zip(caps.tools.iter())
            .filter(|(entry, _tool)| {
                self.executor
                    .missing_credential(&entry.auth, &mut oauth_seen)
                    .is_none()
            })
            .map(|(_entry, tool)| tool.clone())
            .collect()
    }

    /// Get tools visible in `current_state`.
    ///
    /// A capability is included when its `visible_in_states` list is **empty**
    /// (always visible — backward compat) or when it contains `current_state`.
    ///
    /// Also leaves out a capability whose required login is missing, as
    /// [`Self::get_tools`] does.
    pub fn get_tools_for_state(&self, current_state: &str) -> Vec<Tool> {
        let caps = self.capabilities.read();
        let mut oauth_seen = HashMap::new();
        caps.entries
            .iter()
            .zip(caps.tools.iter())
            .filter(|(entry, _tool)| {
                (entry.visible_in_states.is_empty()
                    || entry.visible_in_states.iter().any(|s| s == current_state))
                    && self
                        .executor
                        .missing_credential(&entry.auth, &mut oauth_seen)
                        .is_none()
            })
            .map(|(_entry, tool)| tool.clone())
            .collect()
    }

    /// Whether clients are shown the capability `name`: it exists and its
    /// required login (if any) is in place. A name this backend does not hold
    /// is not its to hide, so it counts as listed.
    pub fn is_listed(&self, name: &str) -> bool {
        self.is_listed_in(name, &mut HashMap::new())
    }

    /// [`Self::is_listed`] for a pass over many names: `seen` memoises the
    /// per-provider OAuth lookups, so one listing or search reads each
    /// provider's token once however many capabilities use it.
    pub fn is_listed_in(&self, name: &str, seen: &mut HashMap<String, bool>) -> bool {
        self.capabilities.read().get(name).is_none_or(|entry| {
            self.executor
                .missing_credential(&entry.auth, seen)
                .is_none()
        })
    }

    /// The names clients are shown now, sorted. A change between two calls is
    /// a change of what `tools/list` answers.
    pub fn listed_names(&self) -> Vec<String> {
        let mut seen = HashMap::new();
        let mut names: Vec<String> = self
            .capabilities
            .read()
            .entries
            .iter()
            .filter(|entry| {
                self.executor
                    .missing_credential(&entry.auth, &mut seen)
                    .is_none()
            })
            .map(|entry| entry.name.clone())
            .collect();
        names.sort();
        names
    }

    /// Get a specific capability by name — O(1) via the name index.
    pub fn get(&self, name: &str) -> Option<CapabilityDefinition> {
        self.capabilities.read().get(name).cloned()
    }

    /// The definition and the MCP revocation generation, read under one lock so
    /// an unload cannot fall between them.
    fn get_with_generation(&self, name: &str) -> Option<(CapabilityDefinition, u64)> {
        let caps = self.capabilities.read();
        let generation = self.executor.mcp_generation(name);
        caps.get(name).cloned().map(|def| (def, generation))
    }

    /// List all capability names in insertion order.
    pub fn list(&self) -> Vec<String> {
        self.capabilities
            .read()
            .entries
            .iter()
            .map(|c| c.name.clone())
            .collect()
    }

    /// List all capability definitions (cloned, insertion order).
    pub fn list_capabilities(&self) -> Vec<CapabilityDefinition> {
        self.capabilities.read().entries.clone()
    }

    /// Execute a capability (call a tool).
    ///
    /// Arguments are validated against the capability's input schema before
    /// any HTTP request is made.  Unknown parameters, wrong types, missing
    /// required parameters, and invalid enum values are all rejected with an
    /// LLM-friendly error message returned as a tool error content block.
    ///
    /// # Errors
    ///
    /// Returns an error if the capability is not found or execution fails.
    pub async fn call_tool(&self, name: &str, arguments: Value) -> Result<ToolsCallResult> {
        self.call_tool_with_context(name, arguments, CapabilityExecutionContext::default())
            .await
    }

    /// Execute a capability with request-scoped identity context.
    ///
    /// # Errors
    ///
    /// Returns an error if the capability is not found, identity validation
    /// fails, or execution fails.
    pub async fn call_tool_with_context(
        &self,
        name: &str,
        arguments: Value,
        mut context: CapabilityExecutionContext,
    ) -> Result<ToolsCallResult> {
        debug!(capability = %name, "Executing capability");

        // O(1) lookup; clone releases the read lock before the async executor call.
        let (capability, generation) = self
            .get_with_generation(name)
            .ok_or_else(|| crate::Error::Config(format!("Capability not found: {name}")))?;
        context.mcp_generation = Some(generation);
        super::read_only_call::refuse_unless_read_only(&capability)?;
        validate_personal_capability_identity(&capability, &context)?;

        let multi_user = self.multi_user.load(std::sync::atomic::Ordering::Relaxed);
        // A capability bound to an account descriptor is the one shape whose
        // per-user OAuth isolation cannot be decided before the account is
        // resolved: whether a per-caller credential exists at all is the
        // registry's answer, not the YAML's. Every OTHER shape keeps the guard
        // exactly where it has always been — first, ahead of argument
        // validation — so no unbound call's error changes or moves.
        let descriptor_bound = capability.auth.account.is_some();
        if !(multi_user && descriptor_bound) {
            validate_oauth_isolation(&capability, &context, multi_user)?;
        }

        // Selector values choose an outbound URL path, so preserve their
        // declared string type instead of allowing generic schema coercion
        // (for example, JSON `1` becoming the string `"1"`).
        if let Some(error_result) = path_selector_type_error(&capability, &arguments) {
            return Ok(error_result);
        }

        // Validate arguments against the YAML schema before making any HTTP call.
        let input_schema = &capability.schema.input;
        let validation = validate_arguments(&arguments, input_schema);
        if !validation.is_valid() {
            let error_text = validation.format_error(input_schema);
            tracing::warn!(
                capability = %name,
                violations = validation.violations.len(),
                "Schema validation failed for capability call"
            );
            return Ok(ToolsCallResult {
                content: vec![Content::Text {
                    text: error_text,
                    annotations: None,
                }],
                structured_content: None,
                is_error: true,
            });
        }

        // THE ACCOUNT IS RESOLVED ONLY ONCE THE CALL IS WELL FORMED (a lease for a
        // rejected call would spend a real credential), through the executor's
        // own `prepare_account_context`, on EVERY descriptor-bound call so this
        // site still holds the managed lease when a 401 comes back (A11-e′). The
        // isolation guard stays multi-user only; the context it consented to is
        // the one the inner cache key and the egress are keyed on.
        let context = if descriptor_bound {
            let context = self
                .executor
                .prepare_account_context(&capability, context)
                .await?;
            if multi_user {
                validate_oauth_isolation(&capability, &context, multi_user)?;
            }
            context
        } else {
            context
        };

        // Coerced arguments; the executor records transport health (MIK-5080).
        let held = context.account_credential.clone();
        let result = match self
            .executor
            .execute_with_context(&capability, validation.coerced, context)
            .await
        {
            // A11-c: a 401 on a managed credential forces at most one refresh.
            Err(e) if crate::security::http_diagnostics::is_upstream_unauthorized(&e) => {
                return Err(match held {
                    Some(held) => held.after_upstream_401(e).await,
                    None => e,
                });
            }
            result => result?,
        };

        Ok(build_success_tool_result(&capability, result))
    }

    /// Register one capability through the account-binding admission gate.
    ///
    /// A capability whose `auth.account` does not name a configured descriptor,
    /// or whose `auth.key` is not `oauth:<descriptor.provider>`, never enters
    /// the tool surface. Descriptorless capabilities are unaffected.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Config`] naming the unresolved reference, or the key the
    /// descriptor's provider requires.
    ///
    /// Replacing a definition of the same name ends its `mcp` children's
    /// process trees at once, from any thread and without a Tokio runtime,
    /// even when the runtime that started them is idle or gone and a call
    /// still holds the child; that call fails, uncertain if it was already
    /// sent (MIK-7923).
    pub fn register_capability(&self, capability: CapabilityDefinition) -> Result<()> {
        validate_capability_account_binding(&capability, self.executor.account_strategies())?;
        let name = capability.name.clone();
        let mut caps = self.capabilities.write();
        let replaced = caps.contains(&name);
        caps.upsert(capability);
        caps.unloaded.remove(&name);
        self.bump_catalogue_generation(&caps);
        if replaced {
            // A replacement is a live-policy change (MIK-7814): children
            // started under the old definition stop, and its cached answers
            // are stranded. The cache key also carries the definition's
            // fingerprint, which covers a first registration on a shared
            // executor; this bump is defence in depth. Under the lock, as in
            // unload.
            self.executor.bump_policy_epoch();
            self.executor.bump_mcp_generation(&name);
            self.executor.stop_mcp(&name);
        }
        Ok(())
    }

    /// Check if a capability exists — O(1) via the name index.
    pub fn has_capability(&self, name: &str) -> bool {
        self.capabilities.read().contains(name)
    }

    /// Get capability count.
    pub fn len(&self) -> usize {
        self.capabilities.read().len()
    }

    /// Check if backend has no capabilities.
    pub fn is_empty(&self) -> bool {
        self.capabilities.read().is_empty()
    }

    /// Get backend status.
    pub fn status(&self) -> CapabilityBackendStatus {
        let caps = self.capabilities.read();
        let health = self.executor.health_metrics();
        CapabilityBackendStatus {
            name: self.name.clone(),
            capabilities_count: caps.len(),
            capabilities: caps.entries.iter().map(|c| c.name.clone()).collect(),
            healthy: health.healthy,
            consecutive_failures: health.consecutive_failures,
            latency_p95_ms: health.latency_p95_ms,
            loaded: self.initial_scan_complete(),
        }
    }

    /// Get watched directories.
    pub fn watched_directories(&self) -> Vec<String> {
        self.directories.read().clone()
    }
}

fn build_success_tool_result(capability: &CapabilityDefinition, result: Value) -> ToolsCallResult {
    let text = serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string());
    ToolsCallResult {
        content: vec![Content::Text {
            text,
            annotations: None,
        }],
        structured_content: (!capability.schema.output.is_null())
            .then(|| super::published_output(&capability.schema.output, result)),
        is_error: false,
    }
}

#[path = "backend_rug_pull.rs"]
mod rug_pull;

/// Status information for a capability backend
#[derive(Debug, Clone, serde::Serialize)]
pub struct CapabilityBackendStatus {
    /// Backend name
    pub name: String,
    /// Number of loaded capabilities
    pub capabilities_count: usize,
    /// List of capability names
    pub capabilities: Vec<String>,
    /// Health-tracker liveness for outbound execution (MIK-5080). Flips false
    /// after consecutive execution failures (e.g. upstream timeouts).
    pub healthy: bool,
    /// Consecutive execution failures recorded by the health tracker.
    pub consecutive_failures: u64,
    /// 95th percentile execution latency in milliseconds, if any samples exist.
    pub latency_p95_ms: Option<u64>,
    /// Whether the startup scan has loaded every directory (MIK-7268).
    pub loaded: bool,
}

#[cfg(test)]
#[path = "backend_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "backend_pin_tests.rs"]
mod pin_tests;

#[cfg(test)]
#[path = "backend_output_root_tests.rs"]
mod output_root_tests;
