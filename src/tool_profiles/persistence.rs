// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Profile persistence for RFC-0073.
//!
//! Saves/loads a `PersistedProfiles` snapshot to a JSON file.
//! Follows the same pattern as `cost_accounting/persistence.rs`.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::ToolSuggestion;

// ── PersistedProfiles ─────────────────────────────────────────────────────────

/// All profile data serialised to disk.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PersistedProfiles {
    /// Unix timestamp (seconds) when this snapshot was written.
    pub saved_at: u64,
    /// Per-user profile data, keyed by `user_id`.
    pub profiles: HashMap<String, PersistedUserProfile>,
}

/// A single user's persisted profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedUserProfile {
    /// User identifier (redundant with map key, kept for ergonomics).
    pub user_id: String,
    /// Unix timestamp (seconds) when the profile was first created, null
    /// when undated (MIK-8202 P4b).
    #[serde(default)]
    pub created_at: Option<u64>,
    /// Per-tool usage records: the same row the live profile reports, so the
    /// file holds `tool_name`, `call_count` and `last_used_secs` (MIK-8667).
    pub tools: Vec<ToolSuggestion>,
}

// ── I/O ───────────────────────────────────────────────────────────────────────

/// Save profiles to `path`, creating parent directories as needed.
///
/// # Errors
///
/// Returns an error if the directory cannot be created or the file
/// cannot be written.
// In-place on purpose: keeps the inode, owner, group and ACLs; atomic replace is MIK-8700.
pub fn save(path: &Path, profiles: &PersistedProfiles) -> crate::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| crate::Error::Config(format!("Failed to create profiles dir: {e}")))?;
    }
    let json = serde_json::to_string_pretty(profiles)
        .map_err(|e| crate::Error::Config(format!("Failed to serialize profiles: {e}")))?;
    std::fs::write(path, json)
        .map_err(|e| crate::Error::Config(format!("Failed to write profiles: {e}")))?;
    tracing::info!(path = %path.display(), users = profiles.profiles.len(), "Saved tool profiles");
    Ok(())
}

/// Load profiles from `path`.
///
/// Returns `PersistedProfiles::default()` when the file does not exist
/// (first run after the feature is enabled).
///
/// # Errors
///
/// Returns an error if the file exists but cannot be parsed as valid JSON.
pub fn load(path: &Path) -> crate::Result<PersistedProfiles> {
    if !path.exists() {
        return Ok(PersistedProfiles::default());
    }
    let json = std::fs::read_to_string(path)
        .map_err(|e| crate::Error::Config(format!("Failed to read profiles: {e}")))?;
    let profiles: PersistedProfiles = serde_json::from_str(&json)
        .map_err(|e| crate::Error::Config(format!("Failed to parse profiles.json: {e}")))?;
    tracing::info!(
        path = %path.display(),
        users = profiles.profiles.len(),
        "Loaded tool profiles"
    );
    Ok(profiles)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_profiles() -> PersistedProfiles {
        let mut profiles = PersistedProfiles {
            saved_at: 1_700_000_000,
            profiles: HashMap::new(),
        };
        profiles.profiles.insert(
            "alice".to_string(),
            PersistedUserProfile {
                user_id: "alice".to_string(),
                created_at: Some(1_699_000_000),
                tools: vec![
                    ToolSuggestion {
                        tool_name: "search".to_string(),
                        call_count: 42,
                        last_used_secs: Some(1_700_000_000),
                    },
                    ToolSuggestion {
                        tool_name: "summarise".to_string(),
                        call_count: 7,
                        last_used_secs: Some(1_699_900_000),
                    },
                ],
            },
        );
        profiles
    }

    #[test]
    fn persist_save_and_load_roundtrip() {
        // GIVEN: a populated PersistedProfiles
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profiles.json");
        let original = sample_profiles();

        // WHEN: saved then loaded
        save(&path, &original).unwrap();
        let loaded = load(&path).unwrap();

        // THEN: data is identical
        assert_eq!(loaded.saved_at, 1_700_000_000);
        assert_eq!(loaded.profiles.len(), 1);
        let alice = loaded.profiles.get("alice").unwrap();
        assert_eq!(alice.tools.len(), 2);
        assert_eq!(alice.tools[0].tool_name, "search");
        assert_eq!(alice.tools[0].call_count, 42);
    }

    #[test]
    fn persist_load_missing_file_returns_default() {
        // GIVEN: a path that does not exist
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.json");

        // WHEN: loaded
        let result = load(&path).unwrap();

        // THEN: default (empty) is returned
        assert_eq!(result.saved_at, 0);
        assert!(result.profiles.is_empty());
    }

    #[test]
    fn persist_load_corrupt_file_returns_error() {
        // GIVEN: a file with invalid JSON
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profiles.json");
        std::fs::write(&path, b"{{not json}}").unwrap();

        // WHEN: loaded
        let result = load(&path);

        // THEN: error is returned
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("parse") || msg.contains("profiles"),
            "Error should mention parsing: {msg}"
        );
    }

    #[test]
    fn persist_save_creates_parent_directories() {
        // GIVEN: a deeply-nested path whose parents do not exist
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("a")
            .join("b")
            .join("c")
            .join("profiles.json");
        let profiles = PersistedProfiles::default();

        // WHEN: saved
        save(&path, &profiles).unwrap();

        // THEN: the file exists
        assert!(path.exists());
    }

    /// DUPC-10.PR10.4: a profiles file this build writes round-trips to the
    /// same bytes. One user only: the profiles live in a map.
    #[test]
    fn a_saved_profiles_file_is_byte_identical() {
        const ONE_USER: &str = "{\n  \"saved_at\": 7,\n  \"profiles\": {\n    \"u\": {\n      \"user_id\": \"u\",\n      \"created_at\": 5,\n      \"tools\": [\n        {\n          \"tool_name\": \"search\",\n          \"call_count\": 2,\n          \"last_used_secs\": 9\n        }\n      ]\n    }\n  }\n}";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profiles.json");
        std::fs::write(&path, ONE_USER).unwrap();
        save(&path, &load(&path).unwrap()).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), ONE_USER);
    }

    /// DUPC-10.PR10.4: a tool row written before the timestamp existed loads,
    /// with no timestamp.
    #[test]
    fn a_tool_row_without_last_used_secs_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profiles.json");
        std::fs::write(
            &path,
            r#"{"saved_at":1,"profiles":{"u":{"user_id":"u","tools":[{"tool_name":"t","call_count":3}]}}}"#,
        )
        .unwrap();
        let loaded = load(&path).unwrap();
        let tool = &loaded.profiles["u"].tools[0];
        assert_eq!((tool.tool_name.as_str(), tool.call_count), ("t", 3));
        assert_eq!(tool.last_used_secs, None);
    }
}
