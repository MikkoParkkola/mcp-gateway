// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Cross-feature integration tests for mcp-gateway v2.6.0.
//!
//! Each test exercises two or more feature-gated modules together, verifying
//! that their interactions are correct when all features are enabled.
//!
//! Run with: `cargo test --all-features --test cross_feature_tests`

// ─── Test 1: Cost Governance + Firewall ──────────────────────────────────────
//
// Verifies that a blocked request (shell injection) produces no cost record,
// while a clean request can be recorded successfully.

#[cfg(all(feature = "cost-governance", feature = "firewall"))]
mod cost_governance_and_firewall {
    use mcp_gateway::cost_accounting::config::CostGovernanceConfig;
    use mcp_gateway::cost_accounting::registry::CostRegistry;
    use mcp_gateway::cost_accounting::{CostTracker, DEFAULT_PRICE_PER_MILLION};
    use mcp_gateway::security::firewall::{Firewall, FirewallConfig};
    use serde_json::json;

    fn make_firewall() -> Firewall {
        Firewall::from_config(FirewallConfig::default(), None)
    }

    fn make_cost_registry() -> CostRegistry {
        let mut cfg = CostGovernanceConfig::default();
        cfg.tool_costs.insert("search_tool".to_string(), 0.005);
        CostRegistry::new(&cfg)
    }

    /// Firewall blocks shell injection → caller must skip cost recording.
    ///
    /// This test models the gateway hot-path: check the request first; only
    /// record cost when the firewall allows it.
    #[test]
    fn blocked_request_does_not_incur_cost() {
        // GIVEN: a firewall and a fresh cost tracker
        let fw = make_firewall();
        let tracker = CostTracker::new();

        // WHEN: a shell-injection request is submitted
        let args = json!({ "cmd": "; rm -rf / " });
        let verdict = fw.check_request("sess-fw-cost-1", "backend", "search_tool", &args, "alice");

        // THEN: the firewall blocks it — the caller must NOT record cost
        assert!(!verdict.allowed, "shell injection must be blocked");

        // Caller contract: skip record() when !allowed
        if verdict.allowed {
            tracker.record(
                "sess-fw-cost-1",
                Some("alice"),
                "backend",
                "search_tool",
                100,
                DEFAULT_PRICE_PER_MILLION,
            );
        }

        // THEN: no session cost entry was created
        let snapshot = tracker.session_snapshot("sess-fw-cost-1");
        assert!(
            snapshot.is_none(),
            "blocked request must not create a cost record; got: {snapshot:?}"
        );
    }

    /// Clean request passes the firewall → cost IS recorded.
    #[test]
    fn allowed_request_records_cost() {
        // GIVEN: a firewall and a cost tracker with a known tool price
        let fw = make_firewall();
        let registry = make_cost_registry();
        let tracker = CostTracker::new();

        // WHEN: a clean request passes the firewall
        let args = json!({ "query": "rust async patterns" });
        let verdict = fw.check_request("sess-fw-cost-2", "backend", "search_tool", &args, "bob");

        assert!(verdict.allowed, "clean request must be allowed");

        // THEN: the caller records cost (using price from CostRegistry)
        let price = registry.cost_for("search_tool");
        assert!(
            (price - 0.005).abs() < 1e-9,
            "registry must resolve the tool price"
        );

        let tokens = 42_u64;
        tracker.record(
            "sess-fw-cost-2",
            Some("bob"),
            "backend",
            "search_tool",
            tokens,
            price * 1_000_000.0, // registry returns USD/call; tracker wants USD/million-tokens
        );

        let snapshot = tracker
            .session_snapshot("sess-fw-cost-2")
            .expect("session must exist after recording");
        assert_eq!(snapshot.call_count, 1, "exactly one call must be recorded");
        assert_eq!(snapshot.total_tokens, tokens);
        assert!(
            snapshot.total_cost_usd > 0.0,
            "cost must be positive for a non-free tool"
        );
    }

    /// Firewall `is_free` check can short-circuit cost recording for zero-cost tools.
    #[test]
    fn free_tool_skips_cost_enforcement() {
        // GIVEN: a registry where "ping" costs nothing
        let cfg = CostGovernanceConfig::default(); // default_cost = 0.0
        let registry = CostRegistry::new(&cfg);

        // THEN: is_free() reports true, allowing the hot-path to skip budget checks
        assert!(
            registry.is_free("ping"),
            "unknown tool with default_cost=0.0 must be free"
        );
        assert!(
            registry.is_free("health_check"),
            "unknown tool with default_cost=0.0 must be free"
        );
    }
}

// ─── Test 2: Tool Profiles + Semantic Search ──────────────────────────────────
//
// Verifies that the tools suggested by a user's usage profile overlap with the
// tools returned by a semantic search on the same topic.

#[cfg(all(feature = "tool-profiles", feature = "semantic-search"))]
mod tool_profiles_and_semantic_search {
    use mcp_gateway::semantic_search::SemanticIndex;
    use mcp_gateway::tool_profiles::ProfileRegistry;

    fn populated_index() -> SemanticIndex {
        let mut idx = SemanticIndex::new();
        idx.index_tool(
            "brave_search",
            "Search the web with Brave Search",
            r#"{"query":"string","count":"integer"}"#,
        );
        idx.index_tool(
            "exa_search",
            "AI-powered semantic web search",
            r#"{"query":"string","num_results":"integer"}"#,
        );
        idx.index_tool(
            "read_file",
            "Read content from a file on disk",
            r#"{"path":"string"}"#,
        );
        idx.index_tool(
            "write_file",
            "Write content to a file on disk",
            r#"{"path":"string","content":"string"}"#,
        );
        idx
    }

    /// Tools from the profile's top suggestions must appear in a semantically
    /// relevant search result set.
    #[test]
    fn profile_suggestions_overlap_with_semantic_search_results() {
        // GIVEN: a user who frequently uses search tools
        let registry = ProfileRegistry::new();
        registry.record_usage("alice", "brave_search");
        registry.record_usage("alice", "brave_search");
        registry.record_usage("alice", "brave_search");
        registry.record_usage("alice", "exa_search");

        let idx = populated_index();

        // WHEN: profile suggests the top 2 tools for "alice"
        let suggestions = registry.suggest_tools("alice", 2);
        assert_eq!(
            suggestions.len(),
            2,
            "alice must have 2 distinct tools recorded"
        );
        assert_eq!(
            suggestions[0].tool_name, "brave_search",
            "most-used tool must rank first"
        );

        // AND: semantic search for "web search" returns results
        let search_results = idx.search("web search query", 5);
        let search_names: Vec<&str> = search_results
            .iter()
            .map(|r| r.tool_name.as_str())
            .collect();

        // THEN: at least one suggested tool appears in the search results
        let overlap = suggestions
            .iter()
            .any(|s| search_names.contains(&s.tool_name.as_str()));
        assert!(
            overlap,
            "suggested tools {suggestions:?} must overlap with search results {search_names:?}"
        );
    }

    /// A tool that the user has never called must not appear in profile suggestions
    /// even if it ranks first in semantic search.
    #[test]
    fn profile_suggestions_exclude_unseen_tools() {
        // GIVEN: a user who has only ever used read_file
        let registry = ProfileRegistry::new();
        registry.record_usage("bob", "read_file");

        // WHEN: asking for suggestions
        let suggestions = registry.suggest_tools("bob", 10);

        // THEN: only read_file appears — not brave_search, exa_search, write_file
        assert_eq!(suggestions.len(), 1);
        assert_eq!(suggestions[0].tool_name, "read_file");
    }

    /// Feedback recorded in the semantic index does not affect profile counts.
    #[test]
    fn semantic_feedback_is_independent_of_profile_counts() {
        // GIVEN: a profile with 5 calls to exa_search
        let registry = ProfileRegistry::new();
        for _ in 0..5 {
            registry.record_usage("carol", "exa_search");
        }

        let idx = populated_index();

        // WHEN: we record semantic feedback favouring brave_search
        idx.record_selection("web search", "brave_search");
        idx.record_selection("web search", "brave_search");

        // THEN: profile suggestions still rank exa_search first (5 calls vs 0)
        let suggestions = registry.suggest_tools("carol", 5);
        assert_eq!(
            suggestions[0].tool_name, "exa_search",
            "profile must be driven by actual usage, not semantic feedback"
        );

        // AND: semantic search rewards the feedback-boosted tool
        let results = idx.search("web search", 5);
        let top_semantic = &results[0].tool_name;
        assert_eq!(
            top_semantic, "brave_search",
            "semantic search must boost the feedback-selected tool"
        );
    }
}

// ─── Test 3: Semantic Search + Firewall ──────────────────────────────────────
//
// Verifies that the Firewall's input scanner detects injection attempts that
// could be embedded in a semantic search query before it reaches the index.

#[cfg(all(feature = "semantic-search", feature = "firewall"))]
mod semantic_search_and_firewall {
    use mcp_gateway::security::firewall::{Firewall, FirewallAction, FirewallConfig, ScanType};
    use mcp_gateway::semantic_search::SemanticIndex;
    use serde_json::json;

    fn default_fw() -> Firewall {
        Firewall::from_config(FirewallConfig::default(), None)
    }

    fn populated_index() -> SemanticIndex {
        let mut idx = SemanticIndex::new();
        idx.index_tool("read_file", "Read a file from disk", r#"{"path":"string"}"#);
        idx.index_tool(
            "search_web",
            "Search the web for information",
            r#"{"query":"string"}"#,
        );
        idx.index_tool(
            "run_shell",
            "Execute a shell command",
            r#"{"cmd":"string"}"#,
        );
        idx
    }

    /// A shell-injection payload embedded in a search query must be caught by
    /// the firewall before the query reaches the semantic index.
    #[test]
    fn firewall_catches_injection_in_search_query() {
        // GIVEN: a firewall guarding a semantic index
        let fw = default_fw();
        let idx = populated_index();

        // WHEN: a client submits a search query containing shell injection
        let malicious_query = "; rm -rf / ";
        let args = json!({ "query": malicious_query });
        let verdict =
            fw.check_request("sess-sem-fw-1", "backend", "search_tool", &args, "attacker");

        // THEN: the firewall blocks the request
        assert!(
            !verdict.allowed,
            "shell injection in search query must be blocked"
        );
        assert_eq!(verdict.action, FirewallAction::Block);
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.scan_type == ScanType::ShellInjection),
            "must report ShellInjection finding; findings: {:?}",
            verdict.findings
        );

        // AND: the semantic index is never queried (caller contract)
        // We verify this by showing the index still returns normal results
        // — it is not corrupted by the blocked input.
        let clean_results = idx.search("read file", 5);
        assert!(
            !clean_results.is_empty(),
            "index must remain usable after blocked query"
        );
        assert_eq!(clean_results[0].tool_name, "read_file");
    }

    /// A path traversal in a search query is also caught.
    #[test]
    fn firewall_catches_path_traversal_in_search_query() {
        let fw = default_fw();
        let args = json!({ "query": "../../../etc/passwd" });
        let verdict =
            fw.check_request("sess-sem-fw-2", "backend", "search_tool", &args, "attacker");

        assert!(!verdict.allowed);
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.scan_type == ScanType::PathTraversal),
            "path traversal in search query must be detected"
        );
    }

    /// A clean search query passes the firewall and the index returns results.
    #[test]
    fn clean_search_query_passes_firewall_and_returns_results() {
        // GIVEN: the full pipeline
        let fw = default_fw();
        let idx = populated_index();

        // WHEN: a clean query is submitted
        let args = json!({ "query": "read a file" });
        let verdict = fw.check_request("sess-sem-fw-3", "backend", "search_tool", &args, "alice");

        // THEN: the firewall allows it
        assert!(verdict.allowed);
        assert_eq!(verdict.action, FirewallAction::Allow);
        assert!(verdict.findings.is_empty());

        // AND: the semantic index returns relevant results
        let results = idx.search("read a file", 5);
        assert!(!results.is_empty(), "index must find read_file");
        assert_eq!(results[0].tool_name, "read_file");
    }

    /// SQL injection in a search query produces a Warn verdict (not Block),
    /// consistent with the firewall's medium-severity mapping.
    #[test]
    fn sql_injection_in_search_query_warns_not_blocks() {
        let fw = default_fw();
        let args = json!({ "query": "' OR 1=1" });
        let verdict =
            fw.check_request("sess-sem-fw-4", "backend", "search_tool", &args, "attacker");

        // SQL injection is MEDIUM → Warn but still allowed
        assert!(verdict.allowed, "SQL injection is warn-level, not block");
        assert_eq!(verdict.action, FirewallAction::Warn);
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.scan_type == ScanType::SqlInjection)
        );
    }
}

// ─── Test 4: Cost Governance + Tool Profiles ─────────────────────────────────
//
// Verifies that the cost registry can price every tool that the profile
// registry has seen, and that the two registries operate independently.

#[cfg(all(feature = "cost-governance", feature = "tool-profiles"))]
mod cost_governance_and_tool_profiles {
    use mcp_gateway::cost_accounting::config::CostGovernanceConfig;
    use mcp_gateway::cost_accounting::registry::CostRegistry;
    use mcp_gateway::tool_profiles::ProfileRegistry;

    fn make_registry_with_prices() -> CostRegistry {
        let mut cfg = CostGovernanceConfig::default();
        cfg.tool_costs.insert("brave_search".to_string(), 0.005);
        cfg.tool_costs.insert("exa_deep".to_string(), 0.05);
        cfg.default_cost = 0.001; // fallback for unpriced tools
        CostRegistry::new(&cfg)
    }

    /// Every tool in a profile can be priced via the cost registry.
    #[test]
    fn cost_registry_prices_all_profiled_tools() {
        // GIVEN: a user who has used three different tools
        let profiles = ProfileRegistry::new();
        profiles.record_usage("alice", "brave_search");
        profiles.record_usage("alice", "brave_search");
        profiles.record_usage("alice", "exa_deep");
        profiles.record_usage("alice", "read_file"); // not in cost config → fallback

        let costs = make_registry_with_prices();

        // WHEN: we iterate the user's profiled tools and look up each cost
        let suggestions = profiles.suggest_tools("alice", 10);
        assert_eq!(
            suggestions.len(),
            3,
            "alice must have 3 distinct profiled tools"
        );

        for suggestion in &suggestions {
            let price = costs.cost_for(&suggestion.tool_name);
            // THEN: every tool has a non-negative price (fallback is 0.001)
            assert!(
                price >= 0.0,
                "cost for '{}' must be non-negative, got {price}",
                suggestion.tool_name
            );
        }
    }

    /// Explicit config prices take precedence over the fallback default.
    #[test]
    fn explicit_config_price_wins_over_default() {
        let costs = make_registry_with_prices();

        assert!(
            (costs.cost_for("brave_search") - 0.005).abs() < 1e-9,
            "brave_search must use its explicit config price"
        );
        assert!(
            (costs.cost_for("exa_deep") - 0.05).abs() < 1e-9,
            "exa_deep must use its explicit config price"
        );
        // read_file is not in config → default_cost applies
        assert!(
            (costs.cost_for("read_file") - 0.001).abs() < 1e-9,
            "read_file must fall back to default_cost"
        );
    }

    /// Profile and cost registries are independent: clearing one does not
    /// affect the other.
    #[test]
    fn registries_are_independent_data_stores() {
        let profiles = ProfileRegistry::new();
        let costs = make_registry_with_prices();

        // Record some profile usage
        profiles.record_usage("dave", "brave_search");

        // Cost registry unaffected: still prices brave_search correctly
        assert!(
            (costs.cost_for("brave_search") - 0.005).abs() < 1e-9,
            "cost registry must be unaffected by profile operations"
        );

        // Profile unaffected by cost look-ups
        let snap = profiles
            .get_profile("dave")
            .expect("dave must have a profile");
        assert_eq!(snap.total_calls, 1);
        assert_eq!(snap.favourite_tool.as_deref(), Some("brave_search"));
    }

    /// `register_from_capability` fills in prices for tools the config omits,
    /// without overriding explicit config values.
    #[test]
    fn capability_registration_fills_gaps_without_overriding_config() {
        let mut cfg = CostGovernanceConfig::default();
        cfg.tool_costs.insert("brave_search".to_string(), 0.005);
        let costs = CostRegistry::new(&cfg);

        // Capability YAML says brave_search costs $0.02 — config must win
        costs.register_from_capability("brave_search", 0.02);
        assert!(
            (costs.cost_for("brave_search") - 0.005).abs() < 1e-9,
            "config price must not be overridden by capability registration"
        );

        // Capability YAML says new_tool costs $0.003 — capability value used
        costs.register_from_capability("new_tool", 0.003);
        assert!(
            (costs.cost_for("new_tool") - 0.003).abs() < 1e-9,
            "capability price must be used for tools absent from config"
        );
    }
}

// ─── Test 5: Per-feature smoke tests ─────────────────────────────────────────
//
// Verifies that each feature module's primary type can be instantiated and
// performs a minimal operation, gated individually so CI catches missing
// feature compilations.

#[cfg(feature = "cost-governance")]
mod feature_smoke_cost_governance {
    use mcp_gateway::cost_accounting::config::CostGovernanceConfig;
    use mcp_gateway::cost_accounting::registry::CostRegistry;

    #[test]
    fn cost_registry_instantiates_with_default_config() {
        let cfg = CostGovernanceConfig::default();
        let reg = CostRegistry::new(&cfg);
        // Default config has no explicit costs and default_cost = 0.0
        assert!(reg.is_free("any_tool"));
        assert_eq!(reg.snapshot().len(), 0);
    }
}

#[cfg(feature = "firewall")]
mod feature_smoke_firewall {
    use mcp_gateway::security::firewall::{Firewall, FirewallAction, FirewallConfig};
    use serde_json::json;

    #[test]
    fn firewall_instantiates_and_allows_clean_request() {
        let fw = Firewall::from_config(FirewallConfig::default(), None);
        let verdict = fw.check_request("s1", "srv", "tool", &json!({ "key": "value" }), "caller");
        assert!(verdict.allowed);
        assert_eq!(verdict.action, FirewallAction::Allow);
    }
}

#[cfg(feature = "semantic-search")]
mod feature_smoke_semantic_search {
    use mcp_gateway::semantic_search::SemanticIndex;

    #[test]
    fn semantic_index_instantiates_and_returns_results() {
        let mut idx = SemanticIndex::new();
        idx.index_tool(
            "send_email",
            "Send an email to a recipient",
            r#"{"to":"string"}"#,
        );
        let results = idx.search("email", 5);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].tool_name, "send_email");
    }
}

#[cfg(feature = "tool-profiles")]
mod feature_smoke_tool_profiles {
    use mcp_gateway::tool_profiles::ProfileRegistry;

    #[test]
    fn profile_registry_instantiates_and_records_usage() {
        let reg = ProfileRegistry::new();
        reg.record_usage("user-a", "brave_search");
        reg.record_usage("user-a", "brave_search");
        let suggestions = reg.suggest_tools("user-a", 5);
        assert_eq!(suggestions.len(), 1);
        assert_eq!(suggestions[0].tool_name, "brave_search");
        assert_eq!(suggestions[0].call_count, 2);
    }
}

#[cfg(feature = "discovery")]
mod feature_smoke_discovery {
    use mcp_gateway::discovery::AutoDiscovery;

    #[test]
    fn auto_discovery_instantiates() {
        // AutoDiscovery::new() is infallible; async discover_all() requires
        // an async runtime.  We just verify construction succeeds.
        let _discovery = AutoDiscovery::new();
    }
}
