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
        /// Which HTTP dialect the endpoint speaks.
        flavor: HttpFlavor,
    },
}

/// The HTTP dialect of a hosted endpoint, recorded per entry rather than
/// guessed from its URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpFlavor {
    /// Streamable HTTP: direct POST, no SSE handshake.
    Streamable,
    /// The legacy SSE handshake.
    Sse,
}

/// What a user must supply before the server works.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Auth {
    /// Works with no account, key or login.
    None,
    /// A stdio server that reads the entry's `required_env` variables.
    EnvVars,
    /// A hosted server that logs in through the gateway's backend OAuth flow
    /// (protected-resource metadata, then dynamic client registration).
    OAuth,
    /// A hosted server that takes a credential in one request header. `value`
    /// is a template whose `${VAR}` names appear in `required_env`.
    Header {
        /// Header name, e.g. `Authorization`.
        name: &'static str,
        /// Header value template, e.g. `Bearer ${GITHUB_TOKEN}`.
        value: &'static str,
    },
}

/// Which addresses the server can be made to reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// Its own vendor's API or a local resource the user names.
    Bounded,
    /// Any address or path it is given (a browser, a URL fetcher, git without
    /// a pinned repository). The gateway's
    /// private-network egress guard covers REST capabilities only, not a
    /// backend's own requests, so these are added disabled.
    Arbitrary {
        /// Shown by `add` and `list --available`.
        reason: &'static str,
    },
}

/// Whether the server starts with nothing more than its registry command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Setup {
    /// Starts as listed.
    Ready,
    /// Needs arguments appended to its command (paths, a repository).
    NeedsArgs {
        /// What to append.
        hint: &'static str,
    },
    /// Needs something outside the gateway: a service running to point at (a
    /// database server), or a program the server launches (a browser).
    NeedsService {
        /// What it connects to.
        hint: &'static str,
    },
}

/// The reason printed for every [`Reach::Arbitrary`] entry.
pub const ARBITRARY_REACH_REASON: &str = "This server can open any address it is given. A prompt \
     injection in a page or tool result can steer it to your local network or a cloud metadata \
     address, and the gateway's private-network guard covers REST capabilities only, not this \
     server. It is added disabled; set `enabled: true` on it if you accept that.";

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
    /// What a user must supply before the server works.
    pub auth: Auth,
    /// Which addresses the server can be made to reach.
    pub reach: Reach,
    /// Whether it starts with nothing more than its command.
    pub setup: Setup,
}

impl RegistryEntry {
    /// True when the server needs an account, key or login.
    #[must_use]
    pub fn needs_login(&self) -> bool {
        !matches!(self.auth, Auth::None)
    }

    /// Whether this entry's reach lets it be written enabled. The one product
    /// switch for arbitrary-reach servers (operator decision, 2026-10-02:
    /// off): `add` and `init` both read it; `reach` stays recorded.
    #[must_use]
    pub fn reach_allows_on(&self) -> bool {
        matches!(self.reach, Reach::Bounded)
    }

    /// The starter set `mcp-gateway init` writes enabled: no login, a reach
    /// that allows it, nothing to configure.
    #[must_use]
    pub fn default_enabled(&self) -> bool {
        !self.needs_login() && self.reach_allows_on() && matches!(self.setup, Setup::Ready)
    }
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
