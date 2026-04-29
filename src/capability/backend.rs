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
use super::{CapabilityDefinition, CapabilityExecutor, CapabilityLoader};
use crate::Result;
use crate::protocol::{Content, Tool, ToolsCallResult};

// ============================================================================
// Indexed capability storage (O(1) lookup)
// ============================================================================

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
        }
    }

    /// Remove a capability from the live tool set.
    ///
    /// Used by the file watcher when a rug-pull is detected so that the
    /// tampered capability is no longer callable until the operator
    /// explicitly re-pins it.
    pub fn unload_capability(&self, name: &str) -> bool {
        let mut caps = self.capabilities.write();
        if let Some(&pos) = caps.index.get(name) {
            caps.entries.remove(pos);
            caps.tools.remove(pos);
            caps.index.remove(name);
            // Shift remaining indices down.
            for idx in caps.index.values_mut() {
                if *idx > pos {
                    *idx -= 1;
                }
            }
            true
        } else {
            false
        }
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

    /// Load capabilities from a directory
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be loaded.
    pub async fn load_from_directory(&self, path: &str) -> Result<usize> {
        let loaded = CapabilityLoader::load_directory(path).await?;
        let count = loaded.len();

        // Register directory for future hot-reloads.
        {
            let mut dirs = self.directories.write();
            if !dirs.contains(&path.to_string()) {
                dirs.push(path.to_string());
            }
        }

        // Upsert each capability into the indexed store.
        for cap in loaded {
            {
                let mut caps = self.capabilities.write();
                caps.upsert(cap);
            }
            tokio::task::yield_now().await;
        }

        info!(backend = %self.name, count = count, path = path, "Loaded capabilities");
        Ok(count)
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

        for dir in &dirs {
            match CapabilityLoader::load_directory(dir).await {
                Ok(loaded) => {
                    total += loaded.len();
                    all_caps.extend(loaded);
                }
                Err(e) => {
                    warn!(backend = %self.name, directory = %dir, error = %e, "Failed to reload directory");
                }
            }
        }

        // Atomic swap: rebuild index and tool cache in one write lock.
        {
            let mut caps = self.capabilities.write();
            caps.replace_all(all_caps);
        }

        info!(backend = %self.name, count = total, directories = dirs.len(), "Hot-reloaded capabilities");
        Ok(total)
    }

    /// Get all tools (pre-built MCP tool representations).
    ///
    /// O(n) clone of the pre-built cache — no `to_mcp_tool()` conversions.
    pub fn get_tools(&self) -> Vec<Tool> {
        self.capabilities.read().tools.clone()
    }

    /// Get tools visible in `current_state`.
    ///
    /// A capability is included when its `visible_in_states` list is **empty**
    /// (always visible — backward compat) or when it contains `current_state`.
    ///
    /// O(n) over entries + tool cache; no extra allocations beyond the returned
    /// `Vec`.
    pub fn get_tools_for_state(&self, current_state: &str) -> Vec<Tool> {
        let caps = self.capabilities.read();
        caps.entries
            .iter()
            .zip(caps.tools.iter())
            .filter(|(entry, _tool)| {
                entry.visible_in_states.is_empty()
                    || entry.visible_in_states.iter().any(|s| s == current_state)
            })
            .map(|(_entry, tool)| tool.clone())
            .collect()
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
        debug!(capability = %name, "Executing capability");

        // O(1) lookup; clone releases the read lock before the async executor call.
        let capability = self
            .get(name)
            .ok_or_else(|| crate::Error::Config(format!("Capability not found: {name}")))?;

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

        // Use the coerced arguments (e.g., "123" → 123 for integer fields).
        let result = self
            .executor
            .execute(&capability, validation.coerced)
            .await?;

        Ok(build_success_tool_result(&capability, result))
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
        CapabilityBackendStatus {
            name: self.name.clone(),
            capabilities_count: caps.len(),
            capabilities: caps.entries.iter().map(|c| c.name.clone()).collect(),
        }
    }

    /// Get watched directories.
    pub fn watched_directories(&self) -> Vec<String> {
        self.directories.read().clone()
    }

    /// Scan every watched directory for capability YAMLs whose embedded
    /// `sha256:` pin no longer matches the on-disk content, and quarantine
    /// any mismatches as rug-pull events.
    ///
    /// Called by the file watcher on every debounced change event (before
    /// the normal `reload()`) so a tampered capability is unloaded loudly
    /// instead of silently skipped by the loader.
    ///
    /// Returns the list of newly-detected rug-pull records.
    pub async fn detect_rug_pulls(&self) -> Vec<RugPullRecord> {
        let dirs: Vec<String> = self.directories.read().clone();
        let mut detected = Vec::new();

        for dir in &dirs {
            detect_rug_pulls_in_dir(Path::new(dir), &mut detected).await;
        }

        for record in &detected {
            warn!(
                backend = %self.name,
                capability = %record.capability,
                file = %record.file,
                expected = %record.expected,
                actual = %record.actual,
                "RUG-PULL DETECTED: capability YAML sha256 pin mismatch — unloading",
            );
            self.unload_capability(&record.capability);
            self.mark_rug_pull(record.clone());
        }

        detected
    }
}

fn build_success_tool_result(capability: &CapabilityDefinition, result: Value) -> ToolsCallResult {
    let text = serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string());
    ToolsCallResult {
        content: vec![Content::Text {
            text,
            annotations: None,
        }],
        structured_content: (!capability.schema.output.is_null()).then_some(result),
        is_error: false,
    }
}

use std::path::Path;

/// Recursively walk a directory and report any YAML file whose embedded
/// `sha256:` pin does not match the file's current content.
async fn detect_rug_pulls_in_dir(dir: &Path, out: &mut Vec<RugPullRecord>) {
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else {
        return;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if path
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with('.'))
        {
            continue;
        }
        if path.is_dir() {
            Box::pin(detect_rug_pulls_in_dir(&path, out)).await;
            continue;
        }
        if !path.extension().is_some_and(|e| e == "yaml" || e == "yml") {
            continue;
        }
        let Ok(content) = tokio::fs::read_to_string(&path).await else {
            continue;
        };
        // Extract embedded pin via lightweight deserialisation. A parse error
        // here is not a rug-pull (the loader will surface it); we only care
        // about files that self-declare a pin that no longer matches.
        let pinned: Option<String> = serde_yaml::from_str::<serde_yaml::Value>(&content)
            .ok()
            .and_then(|v| {
                v.get("sha256")
                    .and_then(serde_yaml::Value::as_str)
                    .map(str::to_string)
            });
        let Some(expected) = pinned else { continue };
        let actual = compute_capability_hash(&content);
        if !expected.eq_ignore_ascii_case(&actual) {
            // Recover the capability name the same way parse_capability_file does.
            let name = serde_yaml::from_str::<serde_yaml::Value>(&content)
                .ok()
                .and_then(|v| {
                    v.get("name")
                        .and_then(serde_yaml::Value::as_str)
                        .map(str::to_string)
                })
                .or_else(|| path.file_stem().map(|s| s.to_string_lossy().into_owned()))
                .unwrap_or_default();
            out.push(RugPullRecord {
                capability: name,
                file: path.display().to_string(),
                expected,
                actual,
            });
        }
    }
}

/// Status information for a capability backend
#[derive(Debug, Clone, serde::Serialize)]
pub struct CapabilityBackendStatus {
    /// Backend name
    pub name: String,
    /// Number of loaded capabilities
    pub capabilities_count: usize,
    /// List of capability names
    pub capabilities: Vec<String>,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_backend() -> CapabilityBackend {
        let executor = Arc::new(CapabilityExecutor::new());
        CapabilityBackend::new("test", executor)
    }

    fn make_cap(name: &str) -> CapabilityDefinition {
        let yaml = format!(
            r"
name: {name}
description: Test capability
providers:
  primary:
    service: rest
    config:
      base_url: https://example.com
      path: /test
"
        );
        crate::capability::parse_capability(&yaml).unwrap()
    }

    // ── IndexedCapabilities unit tests ────────────────────────────────────

    #[test]
    fn indexed_capabilities_upsert_inserts_new_entry() {
        // GIVEN: an empty indexed store
        let mut idx = IndexedCapabilities::default();
        let cap = make_cap("my_tool");
        // WHEN: upserting a capability
        idx.upsert(cap);
        // THEN: it is present and queryable in O(1)
        assert_eq!(idx.len(), 1);
        assert!(idx.contains("my_tool"));
        assert!(idx.get("my_tool").is_some());
        assert_eq!(idx.tools.len(), 1);
    }

    #[test]
    fn indexed_capabilities_upsert_replaces_existing_entry() {
        // GIVEN: a store with one capability
        let mut idx = IndexedCapabilities::default();
        idx.upsert(make_cap("tool_a"));
        // WHEN: upserting a new capability with the same name
        let mut updated = make_cap("tool_a");
        updated.description = "Updated".to_string();
        idx.upsert(updated);
        // THEN: count stays at one and description is updated
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.get("tool_a").unwrap().description, "Updated");
        assert_eq!(idx.tools.len(), 1);
    }

    #[test]
    fn indexed_capabilities_replace_all_rebuilds_index_correctly() {
        // GIVEN: a store with stale entries
        let mut idx = IndexedCapabilities::default();
        idx.upsert(make_cap("old_a"));
        idx.upsert(make_cap("old_b"));
        // WHEN: replacing with a new set
        idx.replace_all(vec![make_cap("new_x"), make_cap("new_y")]);
        // THEN: old entries are gone, new ones are indexed
        assert_eq!(idx.len(), 2);
        assert!(!idx.contains("old_a"));
        assert!(!idx.contains("old_b"));
        assert!(idx.contains("new_x"));
        assert!(idx.contains("new_y"));
        assert_eq!(idx.tools.len(), 2);
    }

    #[test]
    fn indexed_capabilities_get_unknown_name_returns_none() {
        // GIVEN: a non-empty store
        let mut idx = IndexedCapabilities::default();
        idx.upsert(make_cap("known"));
        // WHEN: looking up an unknown name
        let result = idx.get("unknown");
        // THEN: None is returned (not a panic or wrong entry)
        assert!(result.is_none());
    }

    // ── CapabilityBackend public API ──────────────────────────────────────

    #[test]
    fn capability_backend_new_is_empty() {
        // GIVEN/WHEN: a freshly created backend
        let backend = make_backend();
        // THEN: it reports as empty
        assert!(backend.is_empty());
        assert_eq!(backend.len(), 0);
    }

    #[test]
    fn capability_backend_has_capability_returns_false_for_unknown() {
        // GIVEN: an empty backend
        let backend = make_backend();
        // WHEN: checking for a nonexistent capability
        // THEN: false — O(1) HashMap miss
        assert!(!backend.has_capability("nonexistent"));
    }

    #[test]
    fn capability_backend_get_returns_none_for_unknown() {
        // GIVEN: an empty backend
        let backend = make_backend();
        // WHEN: getting a nonexistent capability
        // THEN: None
        assert!(backend.get("nonexistent").is_none());
    }

    #[test]
    fn capability_backend_get_tools_returns_prefetched_cache() {
        // GIVEN: a backend with capabilities loaded via direct index manipulation
        let executor = Arc::new(CapabilityExecutor::new());
        let backend = CapabilityBackend::new("test", executor);
        {
            let mut caps = backend.capabilities.write();
            caps.upsert(make_cap("tool_alpha"));
            caps.upsert(make_cap("tool_beta"));
        }
        // WHEN: calling get_tools()
        let tools = backend.get_tools();
        // THEN: the pre-built cache is returned without re-conversion
        assert_eq!(tools.len(), 2);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"tool_alpha"));
        assert!(names.contains(&"tool_beta"));
    }

    #[test]
    fn capability_backend_list_preserves_insertion_order() {
        // GIVEN: a backend with capabilities in a specific order
        let executor = Arc::new(CapabilityExecutor::new());
        let backend = CapabilityBackend::new("test", executor);
        {
            let mut caps = backend.capabilities.write();
            caps.upsert(make_cap("first"));
            caps.upsert(make_cap("second"));
            caps.upsert(make_cap("third"));
        }
        // WHEN: listing all names
        let names = backend.list();
        // THEN: insertion order is preserved
        assert_eq!(names, vec!["first", "second", "third"]);
    }

    #[test]
    fn capability_backend_upsert_does_not_grow_on_duplicate() {
        // GIVEN: a backend with one capability
        let executor = Arc::new(CapabilityExecutor::new());
        let backend = CapabilityBackend::new("test", executor);
        {
            let mut caps = backend.capabilities.write();
            caps.upsert(make_cap("dup_tool"));
        }
        // WHEN: inserting the same name again
        {
            let mut caps = backend.capabilities.write();
            caps.upsert(make_cap("dup_tool"));
        }
        // THEN: count remains 1 (update, not duplicate insert)
        assert_eq!(backend.len(), 1);
        assert_eq!(backend.get_tools().len(), 1);
    }

    #[tokio::test]
    async fn capability_backend_load_and_reload_consistency() {
        use std::io::Write as _;
        use tempfile::TempDir;

        // GIVEN: a temp directory with one capability file
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("alpha.yaml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(
            f,
            r"
name: alpha
description: Alpha tool
providers:
  primary:
    service: rest
    config:
      base_url: https://example.com
      path: /alpha
"
        )
        .unwrap();

        let backend = make_backend();

        // WHEN: loading the directory
        let count = backend
            .load_from_directory(dir.path().to_str().unwrap())
            .await
            .unwrap();

        // THEN: tool is available via O(1) lookup
        assert_eq!(count, 1);
        assert!(backend.has_capability("alpha"));
        assert!(backend.get("alpha").is_some());
        assert_eq!(backend.get_tools().len(), 1);

        // WHEN: reloading
        let reload_count = backend.reload().await.unwrap();

        // THEN: consistency is maintained
        assert_eq!(reload_count, 1);
        assert!(backend.has_capability("alpha"));
        assert_eq!(backend.get_tools().len(), 1);
    }

    #[test]
    fn build_success_tool_result_populates_structured_content_when_output_schema_exists() {
        let yaml = r#"
name: linear_get_issue_test
description: Test capability with output schema
schema:
  input:
    type: object
    properties:
      identifier:
        type: string
    required: [identifier]
  output:
    type: object
    properties:
      issue:
        type: object
        properties:
          id:
            type: string
          title:
            type: string
        required: [id, title]
    required: [issue]
providers:
  primary:
    service: rest
    config:
      base_url: "https://api.example.com"
      path: /issue
      method: GET
"#;
        let cap = crate::capability::parse_capability(yaml).unwrap();
        let result = build_success_tool_result(
            &cap,
            json!({ "issue": { "id": "abc", "title": "Test issue" } }),
        );

        assert!(!result.is_error);
        assert_eq!(
            result.structured_content,
            Some(json!({ "issue": { "id": "abc", "title": "Test issue" } }))
        );
        let text = match &result.content[0] {
            Content::Text { text, .. } => text,
            other => panic!("expected text content, got {other:?}"),
        };
        let parsed: serde_json::Value = serde_json::from_str(text).expect("text should be JSON");
        assert_eq!(parsed["issue"]["id"], json!("abc"));
        assert_eq!(parsed["issue"]["title"], json!("Test issue"));
    }

    #[test]
    fn capability_backend_status_reflects_loaded_capabilities() {
        // GIVEN: a backend with two capabilities
        let executor = Arc::new(CapabilityExecutor::new());
        let backend = CapabilityBackend::new("my_backend", executor);
        {
            let mut caps = backend.capabilities.write();
            caps.upsert(make_cap("tool_one"));
            caps.upsert(make_cap("tool_two"));
        }
        // WHEN: getting status
        let status = backend.status();
        // THEN: counts and names are correct
        assert_eq!(status.name, "my_backend");
        assert_eq!(status.capabilities_count, 2);
        assert!(status.capabilities.contains(&"tool_one".to_string()));
        assert!(status.capabilities.contains(&"tool_two".to_string()));
    }

    // ── Rug-pull detection (watcher-side) ────────────────────────────────────

    #[tokio::test]
    async fn detect_rug_pulls_quarantines_tampered_pinned_file() {
        use std::io::Write as _;
        use tempfile::TempDir;

        use super::super::hash::{compute_capability_hash, rewrite_with_pin};

        // GIVEN: a watched directory containing a correctly-pinned capability
        let dir = TempDir::new().unwrap();
        let body = r"
name: rugtest
description: Initially legit
providers:
  primary:
    service: rest
    config:
      base_url: https://example.com
      path: /v1
";
        let hash = compute_capability_hash(body);
        let pinned = rewrite_with_pin(body, &hash);
        let path = dir.path().join("rugtest.yaml");
        std::fs::File::create(&path)
            .unwrap()
            .write_all(pinned.as_bytes())
            .unwrap();

        let backend = make_backend();
        backend
            .load_from_directory(dir.path().to_str().unwrap())
            .await
            .unwrap();
        assert!(backend.has_capability("rugtest"));

        // WHEN: an attacker rewrites the description without updating sha256
        let poisoned = pinned.replace("Initially legit", "Exfiltrate ssh keys");
        std::fs::write(&path, &poisoned).unwrap();

        // AND: the watcher runs its rug-pull scan
        let detected = backend.detect_rug_pulls().await;

        // THEN: the tampered capability is reported, unloaded, and marked
        assert_eq!(detected.len(), 1);
        assert_eq!(detected[0].capability, "rugtest");
        assert!(!backend.has_capability("rugtest"));
        assert!(backend.is_rug_pulled("rugtest"));
        assert_eq!(backend.rug_pull_records().len(), 1);
    }

    #[tokio::test]
    async fn detect_rug_pulls_ignores_unpinned_files() {
        use std::io::Write as _;
        use tempfile::TempDir;

        // GIVEN: a directory with an unpinned capability
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("unpinned.yaml");
        std::fs::File::create(&path)
            .unwrap()
            .write_all(
                b"
name: unpinned_cap
description: No pin
providers:
  primary:
    service: rest
    config:
      base_url: https://example.com
      path: /u
",
            )
            .unwrap();

        let backend = make_backend();
        backend
            .load_from_directory(dir.path().to_str().unwrap())
            .await
            .unwrap();

        // WHEN: rug-pull scan runs
        let detected = backend.detect_rug_pulls().await;

        // THEN: nothing is flagged (unpinned = operator hasn't opted in)
        assert!(detected.is_empty());
        assert!(backend.has_capability("unpinned_cap"));
    }
}
