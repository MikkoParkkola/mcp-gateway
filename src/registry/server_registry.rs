// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Static curated registry of popular MCP servers.
//!
//! Provides compile-time metadata for well-known MCP servers so commands
//! like `mcp-gateway add <name>` can bootstrap a backend entry without the
//! user needing to know the exact `npx` incantation or required env vars.
//!
//! # Examples
//!
//! ```rust
//! use mcp_gateway::registry::server_registry;
//!
//! let entry = server_registry::lookup("tavily").unwrap();
//! assert_eq!(entry.category, "search");
//!
//! let results = server_registry::search("database");
//! assert!(!results.is_empty());
//!
//! let all = server_registry::all();
//! assert!(all.len() >= 20);
//! ```

/// Transport type for a registry entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Launched via a child process (npx / binary).
    Stdio,
    /// Connected via HTTP; carries a default URL that works out of the box.
    Http {
        /// The default HTTP URL to use when none is configured.
        default_url: &'static str,
    },
}

/// A single entry in the curated MCP server registry.
#[derive(Debug, Clone, Copy)]
pub struct RegistryEntry {
    /// Short identifier used to look up this entry (e.g. `"tavily"`).
    pub name: &'static str,
    /// Human-readable description shown in `add` and `setup` output.
    pub description: &'static str,
    /// The shell command (or `npx` incantation) used to launch the server.
    pub command: &'static str,
    /// Environment variables that **must** be set for the server to function.
    pub required_env: &'static [&'static str],
    /// Environment variables that are optional but may enhance functionality.
    pub optional_env: &'static [&'static str],
    /// Transport mechanism for this server.
    pub transport: Transport,
    /// Functional category (e.g. `"search"`, `"filesystem"`, `"database"`).
    pub category: &'static str,
    /// Project homepage or npm registry URL.
    pub homepage: &'static str,
}

#[path = "server_registry_entries.rs"]
mod entries;
use entries::REGISTRY;

// ── Public API ────────────────────────────────────────────────────────────────

/// Return the registry entry for the given name, or `None` if not found.
///
/// Lookup is case-insensitive and checks exact name matches only.
#[must_use]
pub fn lookup(name: &str) -> Option<&'static RegistryEntry> {
    let lower = name.to_lowercase();
    REGISTRY
        .iter()
        .find(|e| e.name.eq_ignore_ascii_case(&lower))
}

/// Search the registry by matching `query` against name, description, and category.
///
/// The comparison is case-insensitive substring matching. Results are returned
/// in registry definition order.
#[must_use]
pub fn search(query: &str) -> Vec<&'static RegistryEntry> {
    let lower = query.to_lowercase();
    REGISTRY
        .iter()
        .filter(|e| {
            e.name.to_lowercase().contains(&lower)
                || e.description.to_lowercase().contains(&lower)
                || e.category.to_lowercase().contains(&lower)
        })
        .collect()
}

/// Return all registry entries in definition order.
#[must_use]
pub fn all() -> &'static [RegistryEntry] {
    REGISTRY
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "server_registry_tests.rs"]
mod tests;
