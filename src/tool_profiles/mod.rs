// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Per-user tool usage profiles (RFC-0073).
//!
//! Tracks how often each user invokes each tool, when they last used it,
//! and which tools are their favourites.  The registry is a single
//! `Arc<ProfileRegistry>` shared across the gateway.
//!
//! # Design
//!
//! ```text
//! ProfileRegistry
//!   └── profiles : DashMap<user_id, ToolProfile>
//!         └── usage  : DashMap<tool_name, UsageEntry>
//! ```
//!
//! `record_usage` is the single write path; everything else is read-only.
//!
//! # Example
//!
//! ```rust
//! # #[cfg(feature = "tool-profiles")]
//! # {
//! use mcp_gateway::tool_profiles::ProfileRegistry;
//!
//! let registry = ProfileRegistry::new();
//! registry.record_usage("alice", "search");
//! registry.record_usage("alice", "search");
//! registry.record_usage("alice", "summarise");
//!
//! let suggestions = registry.suggest_tools("alice", 5);
//! assert_eq!(suggestions[0].tool_name, "search"); // most-used first
//! # }
//! ```

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

// ── Time helpers ──────────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

// ── UsageEntry ────────────────────────────────────────────────────────────────

/// Atomic counters for a single (user, tool) pair.
#[derive(Debug)]
struct UsageEntry {
    count: AtomicU64,
    last_used_secs: AtomicU64,
}

impl UsageEntry {
    fn new() -> Self {
        Self {
            count: AtomicU64::new(1),
            last_used_secs: AtomicU64::new(now_secs()),
        }
    }

    fn increment(&self) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.last_used_secs.store(now_secs(), Ordering::Relaxed);
    }

    fn snapshot(&self) -> (u64, u64) {
        (
            self.count.load(Ordering::Relaxed),
            self.last_used_secs.load(Ordering::Relaxed),
        )
    }
}

// ── ToolProfile ───────────────────────────────────────────────────────────────

/// Per-user tool usage profile.
pub struct ToolProfile {
    /// User identifier.
    pub user_id: String,
    /// Per-tool usage counters and timestamps.
    usage: DashMap<String, UsageEntry>,
    /// Tracks when the profile was first created.
    pub created_at: u64,
}

impl ToolProfile {
    fn new(user_id: &str) -> Self {
        Self {
            user_id: user_id.to_string(),
            usage: DashMap::new(),
            created_at: now_secs(),
        }
    }

    fn record(&self, tool_name: &str) {
        if let Some(entry) = self.usage.get(tool_name) {
            entry.increment();
        } else {
            self.usage
                .entry(tool_name.to_string())
                .or_insert_with(UsageEntry::new);
        }
    }

    /// Return all (`tool_name`, count, `last_used_secs`) triples, sorted by count descending.
    fn sorted_usage(&self) -> Vec<(String, u64, u64)> {
        let mut entries: Vec<(String, u64, u64)> = self
            .usage
            .iter()
            .map(|kv| {
                let (count, last) = kv.value().snapshot();
                (kv.key().clone(), count, last)
            })
            .collect();
        entries.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| b.2.cmp(&a.2)));
        entries
    }

    /// The tool with the highest usage count (or `None` if no tools recorded).
    pub fn favourite_tool(&self) -> Option<String> {
        self.sorted_usage()
            .into_iter()
            .next()
            .map(|(name, _, _)| name)
    }

    /// Total number of tool invocations for this user.
    pub fn total_calls(&self) -> u64 {
        self.usage
            .iter()
            .map(|kv| kv.value().count.load(Ordering::Relaxed))
            .sum()
    }

    /// Unix timestamp (seconds) of the most recent tool call, or `None`.
    pub fn last_active_secs(&self) -> Option<u64> {
        self.usage
            .iter()
            .map(|kv| kv.value().last_used_secs.load(Ordering::Relaxed))
            .max()
    }
}

// ── ToolSuggestion ────────────────────────────────────────────────────────────

/// A suggested tool, ranked by usage frequency.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolSuggestion {
    /// Tool name.
    pub tool_name: String,
    /// Number of times the user has called this tool.
    pub call_count: u64,
    /// Unix timestamp (seconds) of the most recent call.
    pub last_used_secs: u64,
}

// ── ProfileRegistry ───────────────────────────────────────────────────────────

/// Global registry of all user tool-usage profiles.
///
/// Designed to be wrapped in `Arc` and shared across the gateway.
#[derive(Default)]
pub struct ProfileRegistry {
    profiles: DashMap<String, ToolProfile>,
}

impl ProfileRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            profiles: DashMap::new(),
        }
    }

    /// Record one invocation of `tool_name` by `user_id`.
    ///
    /// Creates the profile on first use; thread-safe.
    pub fn record_usage(&self, user_id: &str, tool_name: &str) {
        if let Some(profile) = self.profiles.get(user_id) {
            profile.record(tool_name);
        } else {
            let profile = self
                .profiles
                .entry(user_id.to_string())
                .or_insert_with(|| ToolProfile::new(user_id));
            profile.record(tool_name);
        }
    }

    /// Return up to `limit` tool suggestions for `user_id`, sorted by frequency.
    ///
    /// Returns an empty `Vec` when the user has no recorded usage.
    #[must_use]
    pub fn suggest_tools(&self, user_id: &str, limit: usize) -> Vec<ToolSuggestion> {
        let Some(profile) = self.profiles.get(user_id) else {
            return Vec::new();
        };
        profile
            .sorted_usage()
            .into_iter()
            .take(limit)
            .map(|(name, count, last)| ToolSuggestion {
                tool_name: name,
                call_count: count,
                last_used_secs: last,
            })
            .collect()
    }

    /// Look up an existing profile by `user_id`.
    ///
    /// Returns `None` when the user has never made a tool call.
    #[must_use]
    pub fn get_profile(&self, user_id: &str) -> Option<ProfileSnapshot> {
        self.profiles.get(user_id).map(|p| ProfileSnapshot {
            user_id: p.user_id.clone(),
            created_at: p.created_at,
            total_calls: p.total_calls(),
            last_active_secs: p.last_active_secs(),
            favourite_tool: p.favourite_tool(),
            top_tools: p
                .sorted_usage()
                .into_iter()
                .map(|(n, c, l)| ToolSuggestion {
                    tool_name: n,
                    call_count: c,
                    last_used_secs: l,
                })
                .collect(),
        })
    }

    /// Number of distinct users in the registry.
    #[must_use]
    pub fn user_count(&self) -> usize {
        self.profiles.len()
    }

    /// Iterate over all profile snapshots.  Used by `analytics` and `persistence`.
    #[must_use]
    pub fn all_snapshots(&self) -> Vec<ProfileSnapshot> {
        self.profiles
            .iter()
            .map(|kv| {
                let p = kv.value();
                ProfileSnapshot {
                    user_id: p.user_id.clone(),
                    created_at: p.created_at,
                    total_calls: p.total_calls(),
                    last_active_secs: p.last_active_secs(),
                    favourite_tool: p.favourite_tool(),
                    top_tools: p
                        .sorted_usage()
                        .into_iter()
                        .map(|(n, c, l)| ToolSuggestion {
                            tool_name: n,
                            call_count: c,
                            last_used_secs: l,
                        })
                        .collect(),
                }
            })
            .collect()
    }
}

// ── ProfileSnapshot ───────────────────────────────────────────────────────────

/// Serialisable snapshot of a user's tool-usage profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileSnapshot {
    /// User identifier.
    pub user_id: String,
    /// Unix timestamp (seconds) when the profile was first created.
    pub created_at: u64,
    /// Total tool calls by this user.
    pub total_calls: u64,
    /// Unix timestamp (seconds) of the most recent call, if any.
    pub last_active_secs: Option<u64>,
    /// Most frequently used tool, if any.
    pub favourite_tool: Option<String>,
    /// All tools, sorted by frequency descending.
    pub top_tools: Vec<ToolSuggestion>,
}

// ── Sub-modules ───────────────────────────────────────────────────────────────

pub mod analytics;
pub mod persistence;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
