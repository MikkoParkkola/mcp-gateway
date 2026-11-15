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
    /// One slot per `entries` entry, in the same order, including two files
    /// that share a name. `None` is a capability registered with no file.
    sources: Vec<Option<ServedSource>>,
    /// O(1) name → `entries` index.
    index: HashMap<String, usize>,
    /// Pre-built MCP `Tool` representations — rebuilt whenever `entries` changes.
    tools: Vec<Tool>,
    /// Read yet absent: gate refusals (rebuilt by each reload) and unloads (until admitted).
    refused: std::collections::HashSet<String>,
    unloaded: std::collections::HashSet<String>,
    /// Directories and files the operation that installed this catalogue
    /// could not read. Empty means that operation read every configured
    /// directory and every file in them. The snapshot reads this, not the
    /// set an operation is still filling.
    unread: OperationUnread,
}

/// The unreadable paths of one catalogue operation.
///
/// Each operation gets its own. A reload keeps it aside until it installs
/// the catalogue, then stores it there. A scan stores it on the catalogue
/// at the start, because that catalogue is the one the scan is installing
/// and a note arrives after the upsert it belongs to. A later operation
/// that reads everything stores an empty one, and the part is loaded again.
#[derive(Clone)]
struct OperationUnread(Arc<parking_lot::Mutex<Vec<String>>>);

impl Default for OperationUnread {
    fn default() -> Self {
        Self(Arc::new(parking_lot::Mutex::new(Vec::new())))
    }
}

impl OperationUnread {
    fn note(&self, path: &str) {
        self.0.lock().push(path.to_owned());
    }

    fn is_empty(&self) -> bool {
        self.0.lock().is_empty()
    }
}

/// The file one served capability was loaded from, and the digest of the
/// bytes the parse accepted. The bytes themselves are not kept. `digest` is
/// absent when this backend was built without a revision key.
struct ServedSource {
    /// Configured directory as written, joined with the walk's relative path.
    path: String,
    /// Digest of the bytes the parse accepted, when a revision key was set.
    digest: Option<PartDigest>,
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
        self.upsert_sourced(cap, None);
    }

    /// [`Self::upsert`] recording which file `cap` came from.
    ///
    /// A name already served is replaced in place, so one name still has one
    /// slot. A second file of the same name stays only when [`Self::install`]
    /// rebuilds the vec.
    fn upsert_sourced(&mut self, cap: CapabilityDefinition, source: Option<ServedSource>) {
        let tool = cap.to_mcp_tool();
        if let Some(&pos) = self.index.get(&cap.name) {
            self.entries[pos] = cap;
            self.tools[pos] = tool;
            self.sources[pos] = source;
        } else {
            let pos = self.entries.len();
            self.index.insert(cap.name.clone(), pos);
            self.entries.push(cap);
            self.tools.push(tool);
            self.sources.push(source);
        }
    }

    /// Replace all entries atomically, rebuilding both index and tool cache.
    ///
    /// No file: callers that install definitions they did not read from a path.
    fn replace_all(&mut self, caps: Vec<CapabilityDefinition>) {
        self.install(caps.into_iter().map(|cap| (cap, None)).collect());
    }

    /// [`Self::replace_all`] that keeps every pair, including two files that
    /// share a capability name. The name index points at the last of them.
    fn install(&mut self, caps: Vec<(CapabilityDefinition, Option<ServedSource>)>) {
        self.index.clear();
        self.tools.clear();
        self.entries = Vec::with_capacity(caps.len());
        self.sources = Vec::with_capacity(caps.len());
        self.tools = Vec::with_capacity(caps.len());
        self.index = HashMap::with_capacity(caps.len());
        for (cap, source) in caps {
            let tool = cap.to_mcp_tool();
            let pos = self.entries.len();
            self.index.insert(cap.name.clone(), pos);
            self.entries.push(cap);
            self.tools.push(tool);
            self.sources.push(source);
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

/// The capability part for `caps`. The caller holds the catalogue lock, so
/// the entries and the coverage set are one catalogue. A source with no
/// digest was loaded without a revision key and contributes no pair.
fn part_from(caps: &IndexedCapabilities) -> CapabilityPart<PartDigest> {
    let mut entries = Vec::new();
    for source in caps.sources.iter().flatten() {
        let Some(digest) = source.digest else {
            continue;
        };
        entries.push((source.path.clone(), digest));
    }
    // Under the lock: a note that lands during this read is this catalogue's.
    let partial = !caps.unread.is_empty();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    if partial {
        CapabilityPart::Partial(entries)
    } else {
        CapabilityPart::Loaded(entries)
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
    /// Files in this directory that could not be read or parsed, in walk order.
    ///
    /// The directory itself being unreadable is not here: that is the `Err`
    /// the load returned. The catalogue still serves the files it read. The
    /// caller records both with [`CapabilityBackend::note_unreadable`], which
    /// is what makes the served part partial.
    pub unreadable: Vec<String>,
}

/// A row's look at one delivery. The publish stub never calls it.
#[cfg(test)]
type DeliveryObserver = Arc<dyn Fn(&CapabilityBackend) + Send + Sync>;

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
        let mut catalogue = IndexedCapabilities::default();
        catalogue.unread = unread.clone();
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

    /// Digest capability bytes with `key`. The caller derived it. Digests are
    /// taken at load, outside the catalogue lock.
    #[must_use]
    pub(crate) fn with_revision_key(mut self, key: [u8; 32]) -> Self {
        self.revision_key = Some(key);
        self
    }

    /// The file `path`'s bytes digest to, when this backend has a revision key.
    fn source_of(&self, path: &str, bytes: &[u8]) -> ServedSource {
        ServedSource {
            path: path.to_string(),
            digest: self.revision_key.map(|key| part_digest(&key, bytes)),
        }
    }

    /// The capability part for what is served now.
    ///
    /// Under the catalogue read lock: one `(path, digest)` per served entry
    /// that has a file, both files when two directories hold one name, and
    /// nothing for an entry registered without a file. A source with no
    /// digest was loaded on a backend with no revision key, so it has no
    /// pair to contribute. Refused and rug-pulled capabilities are absent
    /// because their slots are gone. `Partial` when the operation that
    /// installed this catalogue left a path unread; the entries are the same
    /// either way.
    pub(crate) fn capability_snapshot(&self) -> CapabilityPart<PartDigest> {
        let caps = self.capabilities.read();
        part_from(&caps)
    }

    /// The next load sequence. The caller holds the catalogue write lock, so
    /// the number and the snapshot name one catalogue.
    fn alloc_seq(&self) -> u64 {
        self.revision_seq
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
            + 1
    }

    /// Snapshot and sequence under the catalogue write lock. For a scan that
    /// has already installed its catalogue: the lock is the swap, and the
    /// publish happens after this returns.
    pub(crate) fn take_served_revision(&self) -> (u64, CapabilityPart<PartDigest>) {
        let caps = self.capabilities.write();
        let seq = self.alloc_seq();
        let part = part_from(&caps);
        (seq, part)
    }

    /// The operation lock, taken immediately after the test's Acquire step.
    /// Hold the guard across the load, the swap and the publish.
    pub(crate) async fn lock_operation(&self) -> tokio::sync::MutexGuard<'_, ()> {
        #[cfg(test)]
        super::op_gate::reach(super::op_gate::Step::Acquire);
        self.operation.lock().await
    }

    /// A configured directory, or a file in a readable directory, could not
    /// be read. Recorded on the operation in progress, which is the set a
    /// snapshot reads only once that operation has stored it on the catalogue.
    pub(crate) fn note_unreadable(&self, path: &str) {
        self.recording.lock().note(path);
    }

    /// The HTTP scan or the stdio startup is starting. Its catalogue is the
    /// one it is about to install, so the unreadable set starts empty and
    /// notes land on it. A reload does not use this: clearing here would
    /// relabel the catalogue still being served.
    pub(crate) fn begin_incremental_coverage(&self) {
        let unread = OperationUnread::default();
        let mut caps = self.capabilities.write();
        caps.unread = unread.clone();
        *self.recording.lock() = unread;
    }

    /// A reload is starting. Its notes stay off the catalogue until install
    /// stores them with the entries it writes.
    fn begin_reload_coverage(&self) {
        *self.recording.lock() = OperationUnread::default();
    }

    /// Publish `(seq, part)` after a catalogue swap, with no catalogue lock held.
    ///
    /// The handoff records the part and, once a live config is attached,
    /// delivers it after its own mutex is released. The observer runs after
    /// that, so it can take the catalogue write lock.
    pub(crate) fn publish_revision(&self, seq: u64, part: CapabilityPart<PartDigest>) {
        self.handoff.publish(seq, part);
        #[cfg(test)]
        self.notify_delivery();
    }

    /// The startup scan's publish and its end, one handoff acquisition.
    ///
    /// `true` when this call marked the scan complete. Unattached, the scan
    /// stays parked and this is `false`.
    pub(crate) fn publish_initial_scan(&self, seq: u64, part: CapabilityPart<PartDigest>) -> bool {
        let transitioned = self.handoff.publish_and_end(seq, part);
        #[cfg(test)]
        self.notify_delivery();
        transitioned
    }

    /// Arm the observer the next [`Self::new`] on this thread copies in.
    /// Taken once, so a later backend on the same thread does not keep it.
    #[cfg(test)]
    pub(crate) fn install_next_delivery_observer(observer: DeliveryObserver) {
        NEXT_DELIVERY_OBSERVER.with(|slot| *slot.borrow_mut() = Some(observer));
    }

    /// Arm the observer on a backend the row already holds.
    #[cfg(test)]
    pub(crate) fn set_delivery_observer(&self, observer: DeliveryObserver) {
        *self.delivery_observer.lock() = Some(observer);
    }

    /// `true` while some caller holds the operation lock. The guard from a
    /// free lock is dropped here, so the check does not keep it.
    #[cfg(test)]
    pub(crate) fn operation_lock_held(&self) -> bool {
        let guard = self.operation.try_lock();
        let held = guard.is_err();
        drop(guard);
        held
    }

    /// `true` when the catalogue write lock is free. The guard is dropped
    /// here, so the check does not keep it.
    #[cfg(test)]
    pub(crate) fn catalogue_write_free(&self) -> bool {
        let guard = self.capabilities.try_write();
        let free = guard.is_some();
        drop(guard);
        free
    }

    /// A publish calls this after the catalogue lock and the handoff mutex
    /// are both dropped. The observer tries the catalogue write lock from
    /// inside the delivery.
    #[cfg(test)]
    fn notify_delivery(&self) {
        let observer = self.delivery_observer.lock().clone();
        if let Some(observer) = observer {
            observer(self);
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
        // Held until this function returns, which is after the publish.
        let _operation = self.lock_operation().await;
        let dirs: Vec<String> = self.directories.read().clone();

        if dirs.is_empty() {
            debug!(backend = %self.name, "No directories to reload");
        }

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
                    warn!(backend = %self.name, directory = %dir, error = %e, "Failed to reload directory");
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
                    warn!(
                        backend = %self.name,
                        capability = %file.definition.name,
                        error = %error,
                        "Capability refused on reload: its account binding does not resolve"
                    );
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

    /// Get a specific capability by name — O(1) via the name index.
    pub fn get(&self, name: &str) -> Option<CapabilityDefinition> {
        self.capabilities.read().get(name).cloned()
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

#[cfg(test)]
thread_local! {
    static NEXT_DELIVERY_OBSERVER: std::cell::RefCell<Option<DeliveryObserver>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn take_delivery_observer() -> Option<DeliveryObserver> {
    NEXT_DELIVERY_OBSERVER.with(|slot| slot.borrow_mut().take())
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
