// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Agent registration and in-memory store.
//!
//! An agent is a registered OAuth 2.0 client that receives a `client_id` and
//! a list of permitted tool scopes.  The `AgentRegistry` stores agent
//! definitions and is used by the JWT validation middleware to:
//!
//! 1. Look up the shared secret (HS256) or public key (RS256) for token
//!    signature verification.
//! 2. Return the granted scopes to the middleware once the token is valid.

use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use super::scopes::Scope;

/// A registered agent definition.
#[derive(Clone, Serialize, Deserialize)]
pub struct AgentDefinition {
    /// Unique client identifier (issued at registration).
    pub client_id: String,
    /// Human-readable display name.
    pub name: String,
    /// Shared secret for HS256 token signing.
    ///
    /// Exactly one of `hs256_secret` or `rs256_public_key` must be provided.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hs256_secret: Option<String>,
    /// PEM-encoded RSA public key for RS256 token verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rs256_public_key: Option<String>,
    /// Scopes granted to this agent.
    ///
    /// Scope strings are parsed at registration time; invalid strings are
    /// silently dropped.
    pub scopes: Vec<String>,
    /// Optional expected issuer (`iss` claim).
    #[serde(default)]
    pub issuer: Option<String>,
    /// Optional expected audience (`aud` claim).
    #[serde(default)]
    pub audience: Option<String>,
}

// Manual `Debug` that redacts the HS256 shared secret (CWE-532, mirrors PR
// #323). A derived `Debug` would print the token-signing secret verbatim; the
// RSA *public* key is not secret and stays visible.
impl std::fmt::Debug for AgentDefinition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redact_opt = |v: &Option<String>| if v.is_some() { "<redacted>" } else { "None" };
        f.debug_struct("AgentDefinition")
            .field("client_id", &self.client_id)
            .field("name", &self.name)
            .field("hs256_secret", &redact_opt(&self.hs256_secret))
            .field("rs256_public_key", &self.rs256_public_key)
            .field("scopes", &self.scopes)
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .finish()
    }
}

impl AgentDefinition {
    /// Return the parsed scopes.
    pub fn parsed_scopes(&self) -> Vec<Scope> {
        self.scopes.iter().filter_map(|s| Scope::parse(s)).collect()
    }
}

/// Thread-safe agent registry backed by a `DashMap`.
///
/// The gateway fills it once at startup from `agent_auth.agents`; a change to
/// that section waits for a restart, which ends every stream. A held agent
/// token is re-validated against it at every delivery, with no cached verdict,
/// so an embedder that mutates it mid-stream is seen at the next delivery,
/// subject only to check-then-act: a removal landing just after a check, as
/// for an API key revoked just after its check.
#[derive(Default, Clone)]
pub struct AgentRegistry {
    inner: Arc<DashMap<String, AgentDefinition>>,
    /// Seconds added to the wall clock this registry's tokens are judged by,
    /// so a row can move a stream's view of time past a token's `exp`. Shared
    /// by clones, as the map is; production has no such field.
    #[cfg(test)]
    skew: Arc<std::sync::atomic::AtomicU64>,
}

impl AgentRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
            #[cfg(test)]
            skew: Arc::default(),
        }
    }

    /// The time, in Unix seconds, a token is judged at: the wall clock, which
    /// tests may move forward. A method so every judgement reads the clock of
    /// the registry it validates against; only test builds read `self`.
    #[cfg_attr(not(test), allow(clippy::unused_self))]
    pub(crate) fn now(&self) -> u64 {
        let now = jsonwebtoken::get_current_timestamp();
        #[cfg(test)]
        let now = now.saturating_add(self.skew.load(std::sync::atomic::Ordering::SeqCst));
        now
    }

    /// Move this registry's clock `secs` forward.
    #[cfg(test)]
    pub(crate) fn advance_clock(&self, secs: u64) {
        self.skew
            .fetch_add(secs, std::sync::atomic::Ordering::SeqCst);
    }

    /// Register (or replace) an agent definition.
    pub fn register(&self, def: AgentDefinition) {
        self.inner.insert(def.client_id.clone(), def);
    }

    /// Look up an agent by `client_id`.
    pub fn get(&self, client_id: &str) -> Option<AgentDefinition> {
        self.inner.get(client_id).map(|e| e.clone())
    }

    /// Remove an agent from the registry.
    pub fn remove(&self, client_id: &str) -> Option<AgentDefinition> {
        self.inner.remove(client_id).map(|(_, v)| v)
    }

    /// Return the number of registered agents.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Return `true` if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Iterate over all registered agents (returns cloned snapshots).
    pub fn all(&self) -> Vec<AgentDefinition> {
        self.inner.iter().map(|e| e.clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_agent(id: &str) -> AgentDefinition {
        AgentDefinition {
            client_id: id.to_string(),
            name: format!("Agent {id}"),
            hs256_secret: Some("supersecret".to_string()),
            rs256_public_key: None,
            scopes: vec![
                "tools:surreal:*".to_string(),
                "tools:brave:search:read".to_string(),
            ],
            issuer: None,
            audience: None,
        }
    }

    #[test]
    fn register_and_get_agent() {
        let reg = AgentRegistry::new();
        reg.register(make_agent("agent-001"));

        let got = reg.get("agent-001").unwrap();
        assert_eq!(got.client_id, "agent-001");
        assert_eq!(got.name, "Agent agent-001");
    }

    #[test]
    fn get_missing_agent_returns_none() {
        let reg = AgentRegistry::new();
        assert!(reg.get("no-such-id").is_none());
    }

    #[test]
    fn register_replaces_existing_agent() {
        let reg = AgentRegistry::new();
        reg.register(make_agent("agent-001"));

        let mut updated = make_agent("agent-001");
        updated.name = "Updated".to_string();
        reg.register(updated);

        assert_eq!(reg.get("agent-001").unwrap().name, "Updated");
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn remove_agent() {
        let reg = AgentRegistry::new();
        reg.register(make_agent("agent-001"));
        let removed = reg.remove("agent-001");

        assert!(removed.is_some());
        assert_eq!(removed.unwrap().client_id, "agent-001");
        assert!(reg.is_empty());
    }

    #[test]
    fn parsed_scopes_parses_valid_entries() {
        let def = make_agent("agent-001");
        let scopes = def.parsed_scopes();
        assert_eq!(scopes.len(), 2);
    }

    #[test]
    fn parsed_scopes_drops_invalid_entries() {
        let def = AgentDefinition {
            client_id: "x".to_string(),
            name: "x".to_string(),
            hs256_secret: None,
            rs256_public_key: None,
            scopes: vec!["invalid".to_string(), "tools:*".to_string()],
            issuer: None,
            audience: None,
        };
        let scopes = def.parsed_scopes();
        assert_eq!(scopes.len(), 1);
    }

    #[test]
    fn all_returns_all_registered_agents() {
        let reg = AgentRegistry::new();
        reg.register(make_agent("a1"));
        reg.register(make_agent("a2"));
        assert_eq!(reg.all().len(), 2);
    }

    #[test]
    fn registry_is_clone_shared() {
        let reg = AgentRegistry::new();
        let reg2 = reg.clone();
        reg.register(make_agent("a1"));

        // Both should see the same underlying store
        assert_eq!(reg2.len(), 1);
    }
}

#[cfg(test)]
mod cwe532_debug_redaction {
    use super::*;

    const SENTINEL: &str = "SENTINEL_SECRET_a1b2c3";

    // AgentDefinition::Debug must redact the HS256 secret while keeping the
    // (non-secret) RSA public key visible.
    #[test]
    fn agent_definition_debug_redacts_hs256_secret() {
        let agent = AgentDefinition {
            client_id: "agent-1".to_string(),
            name: "Agent One".to_string(),
            hs256_secret: Some(SENTINEL.to_string()),
            rs256_public_key: Some("-----BEGIN PUBLIC KEY-----".to_string()),
            scopes: vec!["tools:*".to_string()],
            issuer: None,
            audience: None,
        };
        let dbg = format!("{agent:?}");
        assert!(!dbg.contains(SENTINEL), "leaked hs256_secret: {dbg}");
        assert!(
            dbg.contains("<redacted>"),
            "missing redaction marker: {dbg}"
        );
        assert!(
            dbg.contains("BEGIN PUBLIC KEY"),
            "public key is not secret and should stay visible: {dbg}"
        );
    }
}
