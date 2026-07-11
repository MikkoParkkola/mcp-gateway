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
    /// Unix timestamp (seconds) when the profile was first created.
    pub created_at: u64,
    /// Per-tool usage records.
    pub tools: Vec<PersistedToolUsage>,
}

/// Usage data for one tool belonging to a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedToolUsage {
    /// Tool name.
    pub tool_name: String,
    /// Number of invocations.
    pub call_count: u64,
    /// Unix timestamp (seconds) of the last invocation.
    pub last_used_secs: u64,
}

impl From<ToolSuggestion> for PersistedToolUsage {
    fn from(s: ToolSuggestion) -> Self {
        Self {
            tool_name: s.tool_name,
            call_count: s.call_count,
            last_used_secs: s.last_used_secs,
        }
    }
}

// ── I/O ───────────────────────────────────────────────────────────────────────

/// Save profiles to `path`, creating parent directories as needed.
///
/// # Errors
///
/// Returns an error if the directory cannot be created or the file
/// cannot be written.
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
                created_at: 1_699_000_000,
                tools: vec![
                    PersistedToolUsage {
                        tool_name: "search".to_string(),
                        call_count: 42,
                        last_used_secs: 1_700_000_000,
                    },
                    PersistedToolUsage {
                        tool_name: "summarise".to_string(),
                        call_count: 7,
                        last_used_secs: 1_699_900_000,
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

    #[test]
    fn persisted_tool_usage_converts_from_suggestion() {
        // GIVEN: a ToolSuggestion
        let suggestion = crate::tool_profiles::ToolSuggestion {
            tool_name: "read_file".to_string(),
            call_count: 5,
            last_used_secs: 1_700_000_000,
        };

        // WHEN: converted
        let usage: PersistedToolUsage = suggestion.into();

        // THEN: all fields are preserved
        assert_eq!(usage.tool_name, "read_file");
        assert_eq!(usage.call_count, 5);
        assert_eq!(usage.last_used_secs, 1_700_000_000);
    }
}
