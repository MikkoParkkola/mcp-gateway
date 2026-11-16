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
    validate_capability_account_binding, validate_cli_templates, validate_oauth_isolation,
    validate_personal_capability_identity,
};
use crate::Result;
use crate::config_reload::revision::{CapabilityPart, PartDigest, part_digest};
use crate::protocol::{Content, Tool, ToolsCallResult};

mod definition_access;
mod handoff;
mod indexed;
mod initial_scan;
mod path_selector;
mod revision_part;

use indexed::{IndexedCapabilities, OperationUnread, ServedSource, definition_changed, part_from};
use path_selector::path_selector_type_error;
#[cfg(test)]
use revision_part::{DeliveryObserver, take_delivery_observer};

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
    /// Files in this directory that could not be read or parsed, in walk order.
    ///
    /// The directory itself being unreadable is not here: that is the `Err`
    /// the load returned. The catalogue still serves the files it read. The
    /// caller records both with [`CapabilityBackend::note_unreadable`], which
    /// is what makes the served part partial.
    pub unreadable: Vec<String>,
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
    /// Rug-pull records by capability file, from a detection event.
    ///
    /// Populated by the file watcher when an on-disk YAML's `sha256:` pin no
    /// longer matches its content. A quarantined capability is removed from
    /// the active tool set. This map does not keep it out: `reload()` never
    /// reads it, and the loader's own pin check is what skips the file until
    /// its pin matches again (e.g. after `mcp-gateway cap pin`).
    rug_pull_state: RwLock<HashMap<String, RugPullRecord>>,
    /// The name each file was last loaded under, its pin having matched.
    loaded_from: RwLock<HashMap<String, String>>,
    /// Declares whether the owning gateway serves more than one principal
    /// (ADR-008 INV-2 parity, MIK-6751). Mirrors `MetaMcp::multi_user`;
    /// `MetaMcp::set_multi_user`/`set_capabilities` keep the two in sync since
    /// they may be set in either order at startup. Read by
    /// [`validate_oauth_isolation`] inside `call_tool_with_context`.
    multi_user: std::sync::atomic::AtomicBool,
    initial_scan: Arc<std::sync::atomic::AtomicU8>,
    /// Derived revision key for capability-file digests. Absent on a backend
    /// that is not the HTTP or stdio startup catalogue: the load still runs,
    /// and the source map then has a path and no digest.
    revision_key: Option<[u8; 32]>,
    /// The catalogue operation now recording unreadable paths. Not what a
    /// snapshot reads: that reads the set stored on the catalogue.
    recording: parking_lot::Mutex<OperationUnread>,
    /// Park, attach and publish share this mutex. Nothing is called while
    /// that mutex is held.
    handoff: handoff::Handoff,
    /// The one lock a catalogue operation holds for its whole load, swap and
    /// publish. Released when the operation returns, after the delivery is
    /// recorded, so a second operation cannot publish an older catalogue
    /// over a newer one.
    operation: tokio::sync::Mutex<()>,
    /// The next load sequence. Zero until the first operation takes one, so
    /// that operation publishes seq 1. Taken under the catalogue write lock
    /// together with the snapshot, after the catalogue it names is installed.
    revision_seq: std::sync::atomic::AtomicU64,
    /// Installed by a row that must try the catalogue lock from inside a
    /// delivery.
    #[cfg(test)]
    delivery_observer: parking_lot::Mutex<Option<DeliveryObserver>>,
    /// Moves at every catalogue write, under the write lock (MIK-8037).
    catalogue_generation: std::sync::atomic::AtomicU64,
    /// What was listed when a listing change was last announced.
    listing: parking_lot::Mutex<Option<Vec<String>>>,
    /// Wakes the listing watch when the catalogue changes.
    listing_wake: tokio::sync::Notify,
    /// Test-only: the HTTP startup scan panics after its first directory,
    /// so a row can prove the scan's exit guard still completes it.
    #[cfg(test)]
    pub(crate) scan_panics_after_first_dir: std::sync::atomic::AtomicBool,
    /// Test-only: how many pin-mismatch records existed at the moment the
    /// initial scan was marked complete, so a row can prove the startup
    /// check ran before readiness without racing it.
    #[cfg(test)]
    pub(crate) records_at_scan_complete: std::sync::OnceLock<usize>,
    /// How many times the scan was marked complete. The flag cannot tell one
    /// completion from two. Shared with the handoff, which completes a scan
    /// the startup function does not.
    #[cfg(test)]
    scan_completions: Arc<std::sync::atomic::AtomicUsize>,
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
    /// The name this file was last loaded under while its pin matched, when
    /// it ever was: `capability` comes from the changed bytes and is not.
    pub loaded_as: Option<String>,
}

impl CapabilityBackend {
    /// Create a new capability backend
    pub fn new(name: &str, executor: Arc<CapabilityExecutor>) -> Self {
        // One set, shared, until an operation replaces it. A note before any
        // operation has started is on the catalogue a snapshot would read.
        let unread = OperationUnread::default();
        let catalogue = IndexedCapabilities {
            unread: unread.clone(),
            ..IndexedCapabilities::default()
        };
        // Shared with the handoff: it marks a scan complete, and the bit the
        // rest of the backend reads has to be this one.
        let initial_scan = Arc::new(std::sync::atomic::AtomicU8::new(1));
        let handoff = handoff::Handoff::new(Arc::clone(&initial_scan));
        #[cfg(test)]
        let scan_completions = handoff.share_completions();
        Self {
            name: name.to_string(),
            executor,
            capabilities: RwLock::new(catalogue),
            directories: RwLock::new(Vec::new()),
            rug_pull_state: RwLock::new(HashMap::new()),
            loaded_from: RwLock::new(HashMap::new()),
            multi_user: std::sync::atomic::AtomicBool::new(false),
            initial_scan,
            revision_key: None,
            recording: parking_lot::Mutex::new(unread),
            handoff,
            operation: tokio::sync::Mutex::new(()),
            revision_seq: std::sync::atomic::AtomicU64::new(0),
            #[cfg(test)]
            delivery_observer: parking_lot::Mutex::new(take_delivery_observer()),
            catalogue_generation: std::sync::atomic::AtomicU64::new(0),
            listing: parking_lot::Mutex::new(None),
            listing_wake: tokio::sync::Notify::new(),
            #[cfg(test)]
            scan_panics_after_first_dir: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            records_at_scan_complete: std::sync::OnceLock::new(),
            #[cfg(test)]
            scan_completions,
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
            caps.sources.remove(pos);
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
        self.catalogue_changed();
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
            .insert(record.file.clone(), record);
    }

    /// Check whether a capability is currently quarantined.
    pub fn is_rug_pulled(&self, name: &str) -> bool {
        let state = self.rug_pull_state.read();
        state
            .values()
            .any(|r| r.loaded_as.as_deref().unwrap_or(&r.capability) == name)
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
        let loaded = CapabilityLoader::load_directory_with_paths(path).await?;
        let mut report = DirectoryLoad {
            admitted: loaded.files.len(),
            rejected: Vec::new(),
            unreadable: loaded
                .failures
                .iter()
                .map(|failure| failure.path.clone())
                .collect(),
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
        for file in loaded.files {
            let capability = file.definition.name.clone();
            // Digest outside the catalogue lock. The bytes are not stored.
            let source = self.source_of(&file.path, &file.bytes);
            if let Err(error) = self.admit_from(file.path, file.definition, Some(source)) {
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
        // Held through the publish; this reload's log lines are written after
        // it is released, so a blocked log write never holds up the next
        // catalogue operation.
        let _operation = self.lock_operation().await;
        let dirs: Vec<String> = self.directories.read().clone();
        let mut failed_dirs: Vec<(String, String)> = Vec::new();
        let mut refused_logs: Vec<(String, String)> = Vec::new();

        // Before any note, so this reload's set is not the one still stored
        // on the catalogue. Install below is what stores it. An empty
        // directory list still installs: the fresh set replaces a partial
        // one left by an earlier operation.
        self.begin_reload_coverage();

        let mut loaded_files = Vec::new();
        let mut total = 0;
        // A directory that could not be read leaves the catalogue partial:
        // its capabilities are missing from this load, not deleted (MIK-8028).
        // A file that could not be read does not: the directory was listed,
        // and that file is simply not served. Coverage hears both.
        let mut partial = false;

        for dir in &dirs {
            match CapabilityLoader::load_directory_with_paths(dir).await {
                Ok(loaded) => {
                    total += loaded.files.len();
                    for failure in &loaded.failures {
                        self.note_unreadable(&failure.path);
                    }
                    loaded_files.extend(loaded.files);
                }
                Err(e) => {
                    partial = true;
                    self.note_unreadable(dir);
                    failed_dirs.push((dir.clone(), e.to_string()));
                }
            }
        }

        // The same admission gate the initial load applies.
        let (mut admitted, mut trusted) = (Vec::with_capacity(loaded_files.len()), Vec::new());
        let mut refused = std::collections::HashSet::new();
        for file in loaded_files {
            match validate_capability_account_binding(
                &file.definition,
                self.executor.account_strategies(),
            ) {
                Ok(()) => {
                    let source = self.source_of(&file.path, &file.bytes);
                    trusted.push((file.path, file.definition.name.clone()));
                    admitted.push((file.definition, Some(source)));
                }
                Err(error) => {
                    total -= 1;
                    refused.insert(file.definition.name.clone());
                    refused_logs.push((file.definition.name.clone(), error.to_string()));
                }
            }
        }

        // Atomic swap: rebuild index and tool cache in one write lock, then
        // bump the shared policy epoch while that lock is still held.
        // The seq and the snapshot are taken here, after install, and the
        // publish below runs only once this guard has dropped.
        let (seq, part) = {
            let mut caps = self.capabilities.write();
            let incoming: HashMap<&str, &CapabilityDefinition> = admitted
                .iter()
                .map(|(cap, _)| (cap.name.as_str(), cap))
                .collect();
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
            // A row holds the swap here, before the catalogue is replaced,
            // while this write lock is still held.
            #[cfg(test)]
            super::op_gate::reach(super::op_gate::Step::Swap);
            caps.install(admitted);
            caps.settle_absent(refused);
            // With the entries, under the same lock: the part names this
            // catalogue and the coverage of the operation that wrote it.
            caps.unread = self.recording.lock().clone();
            // With the swap, under the same lock: `catalogue_snapshot` never
            // sees one without the other.
            self.set_catalogue_partial(partial);
            self.bump_catalogue_generation(&caps);
            self.executor.bump_policy_epoch();
            self.executor.stop_unloaded_mcp(&|name| {
                !revoked.contains(name) && caps.index.contains_key(name)
            });
            // After install, still under this lock: the seq and the part name
            // the catalogue this swap wrote, not the one it replaced.
            let seq = self.alloc_seq();
            let part = part_from(&caps);
            (seq, part)
        };
        // The catalogue lock is released. A row holds this gap. The publish
        // runs with that lock free; the operation lock is still held.
        #[cfg(test)]
        super::op_gate::reach(super::op_gate::Step::BeforePublish);
        self.publish_revision(seq, part);
        self.catalogue_changed();
        self.note_admitted(trusted, !partial);
        drop(_operation);

        if dirs.is_empty() {
            debug!(backend = %self.name, "No directories to reload");
        }
        for (dir, error) in &failed_dirs {
            warn!(backend = %self.name, directory = %dir, error = %error, "Failed to reload directory");
        }
        for (capability, error) in &refused_logs {
            warn!(
                backend = %self.name,
                capability = %capability,
                error = %error,
                "Capability refused on reload: its account binding does not resolve"
            );
        }
        info!(backend = %self.name, count = total, directories = dirs.len(), "Hot-reloaded capabilities");
        Ok(total)
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
        // The read-only refusal is the call's answer: its record says so.
        super::read_only_call::refuse_unless_read_only(&capability)
            .inspect_err(|_| crate::gateway::delivery_facts::refused_while_vouched())?;
        // U12: a web UI call is judged by the definition about to run, so a
        // reload after the dispatch gate cannot turn it into a write.
        #[cfg(feature = "webui")]
        crate::gateway::ui_call::gate_capability(capability.metadata.read_only)?;
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
        validate_cli_templates(&capability)?;
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
        drop(caps);
        self.catalogue_changed();
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

#[path = "backend_listing.rs"]
mod listing;
#[cfg(test)]
pub(crate) use listing::listing_watches_started;
#[path = "backend_rug_pull.rs"]
mod rug_pull;

#[path = "backend_status.rs"]
mod status;
pub use status::CapabilityBackendStatus;

#[cfg(test)]
#[path = "backend_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "backend_pin_tests.rs"]
mod pin_tests;

#[cfg(test)]
#[path = "backend_output_root_tests.rs"]
mod output_root_tests;

#[cfg(test)]
#[path = "backend_snapshot_tests.rs"]
mod snapshot_tests;
