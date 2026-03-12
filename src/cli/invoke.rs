//! Direct tool invocation for the `mcp-gateway tool invoke` command.
//!
//! Loads capabilities from the configured directory, resolves the requested
//! tool, and executes it via [`CapabilityExecutor`].  JSON arguments may be
//! supplied on the command line or piped through stdin.
//!
//! # Design
//!
//! This module deliberately reuses [`CapabilityLoader`] and
//! [`CapabilityExecutor`] from the gateway core — no duplication of dispatch
//! logic.  The only CLI-specific code is argument parsing (JSON merge) and
//! exit-code mapping.

use std::io::{self, IsTerminal, Read};
use std::sync::Arc;

use serde_json::Value;

use crate::capability::{CapabilityDefinition, CapabilityExecutor, CapabilityLoader};
use crate::registry::{Registry, RegistryEntry};
use crate::{Error, Result};

// ── public entry-point types ──────────────────────────────────────────────────

/// Resolved tool catalogue: capability definitions indexed for fast lookup.
pub struct ToolCatalogue {
    capabilities: Vec<CapabilityDefinition>,
}

impl ToolCatalogue {
    /// Load capabilities from `capabilities_dir`.
    ///
    /// Silently skips non-YAML files; returns an error only when the directory
    /// itself is inaccessible.
    ///
    /// # Errors
    ///
    /// Propagates I/O or parse errors from [`CapabilityLoader`].
    pub async fn load(capabilities_dir: &str) -> Result<Self> {
        let caps = CapabilityLoader::load_directory(capabilities_dir).await?;
        Ok(Self { capabilities: caps })
    }

    /// Return all capability definitions.
    #[must_use]
    pub fn all(&self) -> &[CapabilityDefinition] {
        &self.capabilities
    }

    /// Find a capability by exact name.
    #[must_use]
    pub fn find(&self, name: &str) -> Option<&CapabilityDefinition> {
        self.capabilities.iter().find(|c| c.name == name)
    }

    /// List `(name, description, requires_key)` triples for display.
    #[must_use]
    pub fn list_entries(&self) -> Vec<(String, String, bool)> {
        self.capabilities
            .iter()
            .map(|c| (c.name.clone(), c.description.clone(), c.auth.required))
            .collect()
    }

    /// Count of loaded capabilities.
    #[must_use]
    pub fn len(&self) -> usize {
        self.capabilities.len()
    }

    /// Whether the catalogue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.capabilities.is_empty()
    }
}

// ── argument resolution ───────────────────────────────────────────────────────

/// Resolve tool arguments from the CLI and/or stdin.
///
/// Priority (later wins):
/// 1. JSON piped on stdin (when stdin is not a TTY)
/// 2. `--args` / positional JSON string on the command line
/// 3. Individual `key=value` pairs from `kv_args`
///
/// # Errors
///
/// Returns a parse error if any JSON source is malformed.
pub fn resolve_args(
    args_json: Option<&str>,
    kv_args: &[String],
    read_stdin: bool,
) -> Result<Value> {
    let mut merged = Value::Object(serde_json::Map::new());

    // Layer 1: stdin JSON
    if read_stdin && !io::stdin().is_terminal() {
        let mut buf = String::new();
        io::stdin()
            .lock()
            .read_to_string(&mut buf)
            .map_err(|e| Error::Config(format!("Failed to read stdin: {e}")))?;
        let buf = buf.trim();
        if !buf.is_empty() {
            let stdin_val: Value = serde_json::from_str(buf)
                .map_err(|e| Error::Config(format!("Invalid JSON from stdin: {e}")))?;
            merge_json(&mut merged, stdin_val);
        }
    }

    // Layer 2: --args JSON blob
    if let Some(json_str) = args_json {
        let val: Value = serde_json::from_str(json_str)
            .map_err(|e| Error::Config(format!("Invalid JSON args: {e}")))?;
        merge_json(&mut merged, val);
    }

    // Layer 3: key=value pairs
    for kv in kv_args {
        let (k, v) = parse_kv(kv)?;
        if let Value::Object(ref mut map) = merged {
            map.insert(k, v);
        }
    }

    Ok(merged)
}

/// Execute a tool by name with the given arguments.
///
/// # Errors
///
/// - `Error::Config` if the tool name is not found in the catalogue.
/// - Propagates execution errors from the capability executor.
pub async fn execute_tool(
    catalogue: &ToolCatalogue,
    tool_name: &str,
    args: Value,
) -> Result<Value> {
    let cap = catalogue
        .find(tool_name)
        .ok_or_else(|| Error::Config(format!("Tool not found: '{tool_name}'")))?;

    let executor = Arc::new(CapabilityExecutor::new());
    executor.execute(cap, args).await
}

/// Build registry entries from the catalogue (for completion / listing).
#[must_use]
pub fn catalogue_to_registry_entries(catalogue: &ToolCatalogue) -> Vec<RegistryEntry> {
    catalogue
        .all()
        .iter()
        .map(|c| RegistryEntry {
            name: c.name.clone(),
            description: c.description.clone(),
            path: String::new(),
            tags: c.metadata.tags.clone(),
            requires_key: c.auth.required,
        })
        .collect()
}

/// Build a [`Registry`]-backed index from a path (for shell completions).
///
/// Returns an empty index when the directory does not exist rather than
/// propagating an error — completions should degrade gracefully.
pub async fn build_completion_tool_names(capabilities_dir: &str) -> Vec<String> {
    let registry = Registry::new(capabilities_dir);
    match registry.build_index().await {
        Ok(index) => index.capabilities.into_iter().map(|e| e.name).collect(),
        Err(_) => vec![],
    }
}

// ── JSON helpers ──────────────────────────────────────────────────────────────

/// Merge `src` into `dst` (shallow — top-level keys of objects are merged).
fn merge_json(dst: &mut Value, src: Value) {
    match (dst, src) {
        (Value::Object(d), Value::Object(s)) => {
            for (k, v) in s {
                d.insert(k, v);
            }
        }
        (dst, src) => *dst = src,
    }
}

/// Parse a `key=value` string into a JSON key+value pair.
///
/// Values that look like JSON scalars (numbers, booleans, `null`, quoted
/// strings, arrays, objects) are parsed as JSON.  Everything else is treated
/// as a plain string.
fn parse_kv(kv: &str) -> Result<(String, Value)> {
    let eq = kv
        .find('=')
        .ok_or_else(|| Error::Config(format!("Expected key=value, got: {kv}")))?;
    let key = kv[..eq].to_string();
    let raw = &kv[eq + 1..];
    let value = try_parse_scalar(raw);
    Ok((key, value))
}

/// Attempt to parse `raw` as a JSON scalar; fall back to plain string.
fn try_parse_scalar(raw: &str) -> Value {
    // Numeric, boolean, null, array or object — delegate to serde_json
    if raw.starts_with('{')
        || raw.starts_with('[')
        || raw == "true"
        || raw == "false"
        || raw == "null"
    {
        return serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.to_string()));
    }
    // Pure number?
    if let Ok(v) = serde_json::from_str::<Value>(raw) {
        if v.is_number() {
            return v;
        }
    }
    Value::String(raw.to_string())
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── parse_kv ─────────────────────────────────────────────────────────────

    #[test]
    fn parse_kv_plain_string_value() {
        // GIVEN: a key=value pair with a plain string
        let (k, v) = parse_kv("query=rust async").unwrap();
        // THEN: key is extracted and value is a string
        assert_eq!(k, "query");
        assert_eq!(v, json!("rust async"));
    }

    #[test]
    fn parse_kv_integer_value() {
        let (k, v) = parse_kv("limit=10").unwrap();
        assert_eq!(k, "limit");
        assert_eq!(v, json!(10));
    }

    #[test]
    fn parse_kv_boolean_true() {
        let (k, v) = parse_kv("verbose=true").unwrap();
        assert_eq!(v, json!(true));
        drop(k);
    }

    #[test]
    fn parse_kv_boolean_false() {
        let (k, v) = parse_kv("debug=false").unwrap();
        assert_eq!(v, json!(false));
        drop(k);
    }

    #[test]
    fn parse_kv_null_value() {
        let (k, v) = parse_kv("token=null").unwrap();
        assert_eq!(v, json!(null));
        drop(k);
    }

    #[test]
    fn parse_kv_missing_equals_is_error() {
        // GIVEN: a string with no '='
        let result = parse_kv("badarg");
        // THEN: returns an error
        assert!(result.is_err());
    }

    #[test]
    fn parse_kv_value_with_equals_in_value() {
        // GIVEN: a value that contains '='
        let (k, v) = parse_kv("url=https://example.com?a=1").unwrap();
        assert_eq!(k, "url");
        assert_eq!(v, json!("https://example.com?a=1"));
    }

    // ── merge_json ────────────────────────────────────────────────────────────

    #[test]
    fn merge_json_merges_object_keys() {
        let mut dst = json!({"a": 1});
        merge_json(&mut dst, json!({"b": 2}));
        assert_eq!(dst, json!({"a": 1, "b": 2}));
    }

    #[test]
    fn merge_json_later_key_wins() {
        let mut dst = json!({"a": 1});
        merge_json(&mut dst, json!({"a": 99}));
        assert_eq!(dst["a"], json!(99));
    }

    #[test]
    fn merge_json_non_object_src_replaces_dst() {
        let mut dst = json!({"a": 1});
        merge_json(&mut dst, json!([1, 2, 3]));
        assert_eq!(dst, json!([1, 2, 3]));
    }

    // ── resolve_args ─────────────────────────────────────────────────────────

    #[test]
    fn resolve_args_json_blob_parsed() {
        let result = resolve_args(Some(r#"{"q": "test"}"#), &[], false).unwrap();
        assert_eq!(result["q"], json!("test"));
    }

    #[test]
    fn resolve_args_kv_overrides_json_blob() {
        // GIVEN: --args JSON and a kv override
        let result = resolve_args(Some(r#"{"limit": 5}"#), &["limit=20".to_string()], false).unwrap();
        assert_eq!(result["limit"], json!(20));
    }

    #[test]
    fn resolve_args_invalid_json_returns_error() {
        let result = resolve_args(Some("not-json"), &[], false);
        assert!(result.is_err());
    }

    #[test]
    fn resolve_args_empty_produces_empty_object() {
        let result = resolve_args(None, &[], false).unwrap();
        assert!(result.as_object().map_or(false, |m| m.is_empty()));
    }

    // ── try_parse_scalar ─────────────────────────────────────────────────────

    #[test]
    fn try_parse_scalar_json_array() {
        let v = try_parse_scalar("[1,2,3]");
        assert_eq!(v, json!([1, 2, 3]));
    }

    #[test]
    fn try_parse_scalar_json_object() {
        let v = try_parse_scalar(r#"{"x":1}"#);
        assert_eq!(v, json!({"x": 1}));
    }

    #[test]
    fn try_parse_scalar_plain_string_stays_string() {
        let v = try_parse_scalar("hello world");
        assert_eq!(v, json!("hello world"));
    }

    // ── ToolCatalogue ─────────────────────────────────────────────────────────

    #[test]
    fn catalogue_find_returns_none_for_unknown_name() {
        let cat = ToolCatalogue { capabilities: vec![] };
        assert!(cat.find("nonexistent").is_none());
    }

    #[test]
    fn catalogue_is_empty_on_empty_vec() {
        let cat = ToolCatalogue { capabilities: vec![] };
        assert!(cat.is_empty());
        assert_eq!(cat.len(), 0);
    }
}
