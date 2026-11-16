// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The catalogue a capability backend serves: entries in load order, the
//! file each came from, and what the operation that installed it could not
//! read. Split from the backend so its file stays under the size ceiling.

use super::{Arc, CapabilityDefinition, CapabilityPart, HashMap, PartDigest, Tool};

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
pub(super) struct IndexedCapabilities {
    /// Stable insertion-order storage.
    pub(super) entries: Vec<CapabilityDefinition>,
    /// One slot per `entries` entry, in the same order, including two files
    /// that share a name. `None` is a capability registered with no file.
    pub(super) sources: Vec<Option<ServedSource>>,
    /// O(1) name → `entries` index.
    pub(super) index: HashMap<String, usize>,
    /// Pre-built MCP `Tool` representations — rebuilt whenever `entries` changes.
    pub(super) tools: Vec<Tool>,
    /// Read yet absent: gate refusals (rebuilt by each reload) and unloads (until admitted).
    pub(super) refused: std::collections::HashSet<String>,
    pub(super) unloaded: std::collections::HashSet<String>,
    /// Directories and files the operation that installed this catalogue
    /// could not read. Empty means that operation read every configured
    /// directory and every file in them. The snapshot reads this, not the
    /// set an operation is still filling.
    pub(super) unread: OperationUnread,
}

/// The unreadable paths of one catalogue operation.
///
/// Each operation gets its own. A reload keeps it aside until it installs
/// the catalogue, then stores it there. A scan stores it on the catalogue
/// at the start, because that catalogue is the one the scan is installing
/// and a note arrives after the upsert it belongs to. A later operation
/// that reads everything stores an empty one, and the part is loaded again.
#[derive(Clone)]
pub(super) struct OperationUnread(Arc<parking_lot::Mutex<Vec<String>>>);

impl Default for OperationUnread {
    fn default() -> Self {
        Self(Arc::new(parking_lot::Mutex::new(Vec::new())))
    }
}

impl OperationUnread {
    pub(super) fn note(&self, path: &str) {
        self.0.lock().push(path.to_owned());
    }

    pub(super) fn is_empty(&self) -> bool {
        self.0.lock().is_empty()
    }
}

/// The file one served capability was loaded from, and the digest of the
/// bytes the parse accepted. The bytes themselves are not kept. `digest` is
/// absent when this backend was built without a revision key.
pub(super) struct ServedSource {
    /// Configured directory as written, joined with the walk's relative path.
    pub(super) path: String,
    /// Digest of the bytes the parse accepted, when a revision key was set.
    pub(super) digest: Option<PartDigest>,
}

/// True when `new` differs from `old` in any serialised field. A definition
/// that cannot be serialised is treated as changed (revoke rather than keep).
pub(super) fn definition_changed(old: &CapabilityDefinition, new: &CapabilityDefinition) -> bool {
    match (serde_json::to_value(old), serde_json::to_value(new)) {
        (Ok(a), Ok(b)) => a != b,
        _ => true,
    }
}

impl IndexedCapabilities {
    /// Insert or replace a capability, maintaining index and tool cache consistency.
    pub(super) fn upsert(&mut self, cap: CapabilityDefinition) {
        self.upsert_sourced(cap, None);
    }

    /// [`Self::upsert`] recording which file `cap` came from.
    ///
    /// A name already served is replaced in place, so one name still has one
    /// slot. A second file of the same name stays only when [`Self::install`]
    /// rebuilds the vec.
    pub(super) fn upsert_sourced(
        &mut self,
        cap: CapabilityDefinition,
        source: Option<ServedSource>,
    ) {
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
    pub(super) fn replace_all(&mut self, caps: Vec<CapabilityDefinition>) {
        self.install(caps.into_iter().map(|cap| (cap, None)).collect());
    }

    /// [`Self::replace_all`] that keeps every pair, including two files that
    /// share a capability name. The name index points at the last of them.
    pub(super) fn install(&mut self, caps: Vec<(CapabilityDefinition, Option<ServedSource>)>) {
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
    pub(super) fn get(&self, name: &str) -> Option<&CapabilityDefinition> {
        self.index.get(name).map(|&i| &self.entries[i])
    }

    /// O(1) existence check.
    #[inline]
    pub(super) fn contains(&self, name: &str) -> bool {
        self.index.contains_key(name)
    }

    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The capability part for `caps`. The caller holds the catalogue lock, so
/// the entries and the coverage set are one catalogue. A source with no
/// digest was loaded without a revision key and contributes no pair.
pub(super) fn part_from(caps: &IndexedCapabilities) -> CapabilityPart<PartDigest> {
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
