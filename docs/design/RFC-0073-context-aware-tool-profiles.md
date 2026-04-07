# RFC-0073: Context-Aware Tool Profiles

**Status**: Proposed
**Date**: 2026-03-13
**Author**: Mikko Parkkola
**LOC Budget**: ~400-600

---

## 1. Problem Statement

### The Noise Problem

With 180+ tools (target 500+), even ranked search returns results from irrelevant
domains. An LLM doing a code review sees weather APIs. When researching a topic,
it sees npm package tools. The signal-to-noise ratio degrades with tool count.

Current `routing_profile/` (already implemented) provides per-session
allow/deny filters -- but these are **auth scopes** managed by operators, not
**task contexts** managed by the LLM itself. The distinction:

| Dimension | Routing Profiles (existing) | Tool Profiles (this RFC) |
|-----------|---------------------------|--------------------------|
| Who configures | Operator (config.yaml) | Operator defines, LLM activates |
| Granularity | Backend + tool allow/deny | Declarative task categories |
| Activation | Per API key or `gateway_set_profile` | LLM calls `gateway_set_tool_profile` with task context |
| Purpose | Security boundary | Relevance filter |
| Composability | Flat (one profile) | Hierarchical (`extends`) |
| Auto-detection | None | Inferred from recent tool usage |

### Why This Matters

Without explicit profiles, mcp-gateway dumps all 180+ tools into every search,
wasting LLM context tokens and degrading result quality.

### Concrete Failure Cases

1. **Query: "search for code review tools"** -- returns 15 results including
   `brave_search`, `exa_search`, `wikipedia_search` alongside the desired
   `github_create_review`, `github_list_reviews`. The LLM cannot distinguish
   which "search" tools are code-relevant.

2. **Query: "send a notification"** -- returns `gmail_send`, `slack_send`,
   `telegram_send`, `push_notify`, `webhook_send`. If the user is clearly in
   a Slack workflow, only `slack_send` should surface first.

3. **Tool list bloat** -- `gateway_list_tools` returns ALL 180+ tools. An LLM
   that calls this pays ~2000 tokens for the response. With a "coding" profile
   active, this drops to ~400 tokens (5x savings).

---

## 2. Access Control Decision Matrix

Three systems control tool access. They operate at different layers:

| System | Purpose | Blocks invocation? | Blocks discovery? | Scope |
|--------|---------|-------------------|-------------------|-------|
| **Routing Profiles** (auth) | Per-client backend/tool restrictions | YES | YES | Security boundary |
| **Tool Profiles** (relevance) | Context-aware tool filtering | NO | YES | UX optimization |
| **Firewall** (security) | Pattern-based request/response scanning | YES | NO | Security enforcement |

**Evaluation order**: Routing Profile -> Tool Profile -> Firewall -> Invoke

**Tool profiles are NOT a security boundary.** They filter discovery only. An LLM that knows a tool name can always invoke it regardless of active profile. Use routing profiles or firewall rules for access control.

---

## 3. Design

### 3.1 Architecture Overview

```
config.yaml                          Runtime
+-----------------------+            +---------------------------+
| tool_profiles:        |            |  ProfileRegistry          |
|   research:           |  startup   |  (immutable HashMap)      |
|     description: ...  | --------> |  "research" -> compiled   |
|     tools: [brave_*]  |            |  "coding"  -> compiled    |
|     priority: 1       |            |  "finance" -> compiled    |
|   coding:             |            +---------------------------+
|     description: ...  |                       |
|     tools: [github_*] |                       v
|   full_stack_dev:     |            +---------------------------+
|     extends: [coding] |            |  SessionProfileStore      |
|     tools: [docker_*] |            |  (per-session active)     |
+-----------------------+            |  "sess-123" -> "coding"   |
                                     |  "sess-456" -> "research" |
                                     +---------------------------+
                                                |
                         +-----------+----------+----------+
                         |           |                     |
                    list_tools  search_tools          invoke_tool
                    (filtered)  (scope+fallback)      (NEVER blocked)
```

### 3.2 Key Design Decisions

**Decision 1: Profiles complement routing profiles, not replace them.**

Routing profiles (`RoutingProfile` in `src/routing_profile/mod.rs`) are the
security boundary -- they can DENY access. Tool profiles are a relevance
filter -- they scope search/list but NEVER block invocation. The evaluation
order is:

```
Request -> RoutingProfile.check(backend, tool) -> [DENY = error 403]
                                               -> [ALLOW]
        -> ToolProfile.is_visible(tool)        -> [HIDDEN from list/search]
                                               -> [VISIBLE in list/search]
        -> gateway_invoke                      -> ALWAYS executes (profile-blind)
```

This is a critical safety property. Tool profiles are a convenience, not a
security mechanism. An LLM that knows a tool exists can always invoke it
directly, regardless of the active tool profile.

**Decision 2: `ToolProfileConfig` is a superset of `RoutingProfileConfig`.**

`ToolProfileConfig` has the same `allow_tools`, `deny_tools`, `allow_backends`,
`deny_backends` fields with full glob support, plus additional fields (`extends`,
`priority`, `auto_detectable`). It is NOT a reuse of `RoutingProfileConfig` --
it is a separate type that converts to `RoutingProfile` internally for pattern
evaluation. This avoids coupling the two config types while reusing the compiled
`RoutingProfile` for efficient O(k) pattern matching at runtime.

**Decision 3: `extends` is single-level only, resolved at compile time.**

Extends resolves one level only. Profile A extending B gets B's tools directly;
if B extends C, A does NOT inherit C's tools. This is intentional -- single-level
is simpler and covers documented use cases (composite profiles like
`full_stack_dev` extending atomic profiles like `coding`, `research`, `devops`).
Transitive inheritance adds complexity (ordering, diamond merges) with no clear
benefit at current scale.

Profile inheritance is flattened into a single `RoutingProfile` during
compilation. There is no runtime traversal of `extends` chains. This keeps the
hot path (search/list) at O(k) where k = number of patterns, with no
indirection.

### 3.3 Config Schema

```yaml
# config.yaml -- new top-level key
tool_profiles:
  research:
    description: "Web research, search, and data gathering"
    allow_tools: ["brave_*", "tavily_*", "exa_*", "wikipedia_*", "nab_*", "arxiv_*"]
    priority: 1

  coding:
    description: "Software development and code management"
    allow_tools: ["github_*", "npm_*", "pypi_*", "context7_*", "semantic_*"]
    priority: 1

  finance:
    description: "Financial data, stock quotes, SEC filings"
    allow_tools: ["yahoo_*", "sec_*", "stock_*", "exchange_*"]
    priority: 2

  communication:
    description: "Email, chat, calendar"
    allow_tools: ["gmail_*", "slack_*", "calendar_*", "telegram_*"]
    priority: 2

  data:
    description: "Databases and data management"
    allow_tools: ["surreal_*", "postgres_*", "sqlite_*", "redis_*"]
    priority: 2

  devops:
    description: "Infrastructure, deployment, monitoring"
    allow_tools: ["docker_*", "k8s_*", "grafana_*", "prometheus_*"]
    priority: 3

  # Composite profiles
  full_stack_dev:
    description: "Full-stack development: coding + research + devops"
    extends: ["coding", "research", "devops"]
    allow_tools: ["docker_*", "k8s_*"]  # Additional tools beyond extended profiles
    priority: 1

  all:
    description: "All tools (unrestricted)"
    allow_tools: ["*"]
    priority: 0
    auto_detectable: false  # Wildcard profiles are excluded from auto-detection by default
```

### 3.4 Rust Types

```rust
// src/tool_profile/mod.rs

use std::collections::HashMap;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use crate::routing_profile::{RoutingProfile, RoutingProfileConfig};

// ============================================================================
// Configuration (deserialized from YAML)
// ============================================================================

/// Tool profile configuration declared in `config.yaml`.
///
/// A superset of routing profile fields with additional profile-specific
/// metadata: `extends` for inheritance, `priority` for auto-detection ranking,
/// and `auto_detectable` to control auto-detection eligibility.
/// Converts to `RoutingProfile` internally for pattern evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ToolProfileConfig {
    /// Human-readable description (shown by `gateway_list_profiles`).
    #[serde(default)]
    pub description: String,

    /// If `Some`, only tools whose names match are visible in search/list.
    /// Supports glob patterns. Identical semantics to `RoutingProfileConfig.allow_tools`.
    #[serde(default)]
    pub allow_tools: Option<Vec<String>>,

    /// If `Some`, tools whose names match are hidden from search/list.
    #[serde(default)]
    pub deny_tools: Option<Vec<String>>,

    /// If `Some`, only these backends' tools are visible.
    #[serde(default)]
    pub allow_backends: Option<Vec<String>>,

    /// If `Some`, these backends' tools are hidden.
    #[serde(default)]
    pub deny_backends: Option<Vec<String>>,

    /// Names of other tool profiles to inherit tools from.
    /// The union of all extended profiles' allow/deny lists is computed.
    #[serde(default)]
    pub extends: Vec<String>,

    /// Auto-detection priority (higher = preferred when scores are equal).
    /// Used by the auto-detect algorithm when inferring context from recent
    /// tool usage.
    #[serde(default = "default_priority")]
    pub priority: u32,

    /// Whether this profile is eligible for auto-detection.
    /// Defaults to true for specific profiles, but false for profiles
    /// whose `allow_tools` contains a bare wildcard `"*"` (since they
    /// match everything and would always win auto-detection).
    #[serde(default)]
    pub auto_detectable: Option<bool>,
}

fn default_priority() -> u32 { 1 }

/// Determine if a profile is auto-detectable based on config.
///
/// If `auto_detectable` is explicitly set, use that value.
/// Otherwise, default to false if allow_tools contains `"*"` (wildcard
/// profiles match all tools and are not useful for auto-detection).
fn is_auto_detectable(config: &ToolProfileConfig) -> bool {
    if let Some(explicit) = config.auto_detectable {
        return explicit;
    }
    // Default: exclude wildcard profiles
    if let Some(ref tools) = config.allow_tools {
        if tools.iter().any(|t| t == "*") {
            return false;
        }
    }
    true
}

// ============================================================================
// Compiled profile registry
// ============================================================================

/// Immutable registry of compiled tool profiles.
///
/// Built once at startup (or hot-reload). Each profile is flattened from
/// its `extends` chain into a single `RoutingProfile` for O(k) evaluation.
#[derive(Debug)]
pub struct ToolProfileRegistry {
    /// Compiled profiles by name.
    profiles: HashMap<String, CompiledToolProfile>,
    /// Default profile name (from config or "all").
    default_profile: String,
}

/// A compiled tool profile with metadata.
#[derive(Debug, Clone)]
pub struct CompiledToolProfile {
    /// The flattened routing profile (handles allow/deny evaluation).
    pub filter: RoutingProfile,
    /// Profile priority for auto-detection.
    pub priority: u32,
    /// Original profile names that were composed into this profile.
    pub composed_from: Vec<String>,
    /// Whether this profile is eligible for auto-detection.
    /// False for wildcard profiles (allow_tools: ["*"]) unless overridden.
    pub auto_detectable: bool,
}

impl ToolProfileRegistry {
    /// Build the registry from config, resolving `extends` chains.
    ///
    /// Cycles in `extends` are detected and broken (the cyclic reference
    /// is simply skipped with a warning log).
    pub fn from_config(
        configs: &HashMap<String, ToolProfileConfig>,
        default: &str,
    ) -> Self {
        let mut profiles = HashMap::new();

        for (name, config) in configs {
            let resolved = resolve_extends(name, config, configs);
            let routing_config = RoutingProfileConfig {
                description: config.description.clone(),
                allow_tools: resolved.allow_tools,
                deny_tools: resolved.deny_tools,
                allow_backends: resolved.allow_backends,
                deny_backends: resolved.deny_backends,
            };
            profiles.insert(name.clone(), CompiledToolProfile {
                filter: RoutingProfile::from_config(name, &routing_config),
                priority: config.priority,
                composed_from: resolved.composed_from,
                auto_detectable: is_auto_detectable(config),
            });
        }

        Self {
            profiles,
            default_profile: default.to_string(),
        }
    }

    /// Get a compiled profile by name.
    ///
    /// Returns an unrestricted profile if the name is unknown.
    pub fn get(&self, name: &str) -> Option<&CompiledToolProfile> {
        self.profiles.get(name)
    }

    /// Get the default profile name.
    pub fn default_name(&self) -> &str {
        &self.default_profile
    }

    /// List all profile names and descriptions (for `gateway_list_profiles`).
    pub fn summaries(&self) -> Vec<serde_json::Value> {
        let mut summaries: Vec<serde_json::Value> = self.profiles.iter()
            .map(|(name, p)| serde_json::json!({
                "name": name,
                "description": p.filter.description.clone(),
                "priority": p.priority,
                "composed_from": p.composed_from,
            }))
            .collect();
        summaries.sort_by(|a, b| {
            let pa = a["priority"].as_u64().unwrap_or(0);
            let pb = b["priority"].as_u64().unwrap_or(0);
            pb.cmp(&pa)  // higher priority first
                .then_with(|| {
                    let na = a["name"].as_str().unwrap_or("");
                    let nb = b["name"].as_str().unwrap_or("");
                    na.cmp(nb)
                })
        });
        summaries
    }

    /// Detect which profile best matches the given set of recently-used tools.
    ///
    /// Scores each profile by counting how many of the `recent_tools` match
    /// its allow patterns. Returns the profile name with the highest score
    /// (ties broken by `priority`).
    ///
    /// Returns `None` if no profile matches more than 0 tools.
    pub fn auto_detect(&self, recent_tools: &[String]) -> Option<String> {
        if recent_tools.is_empty() {
            return None;
        }

        let mut best_name: Option<String> = None;
        let mut best_score: usize = 0;
        let mut best_priority: u32 = 0;

        for (name, profile) in &self.profiles {
            // Skip wildcard and explicitly non-detectable profiles
            if !profile.auto_detectable {
                continue;
            }

            let score = recent_tools.iter()
                .filter(|tool| profile.filter.tool_allowed(tool))
                .count();

            if score > best_score
                || (score == best_score && profile.priority > best_priority)
            {
                best_score = score;
                best_priority = profile.priority;
                best_name = Some(name.clone());
            }
        }

        if best_score > 0 { best_name } else { None }
    }

    /// Number of registered profiles.
    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }
}

// ============================================================================
// Extends resolution
// ============================================================================

/// Result of resolving the `extends` chain for a profile.
struct ResolvedConfig {
    allow_tools: Option<Vec<String>>,
    deny_tools: Option<Vec<String>>,
    allow_backends: Option<Vec<String>>,
    deny_backends: Option<Vec<String>>,
    composed_from: Vec<String>,
}

/// Resolve `extends` for a single profile (single-level only).
///
/// Union of all `allow_*` lists from directly extended profiles. Deny lists
/// are also unioned. The profile's own lists take precedence (appended last).
/// If an extended profile itself has `extends`, those are NOT followed
/// (single-level resolution is intentional; see Decision 3).
///
/// Cycle detection: tracks visited names and skips already-seen profiles.
fn resolve_extends(
    name: &str,
    config: &ToolProfileConfig,
    all_configs: &HashMap<String, ToolProfileConfig>,
) -> ResolvedConfig {
    let mut visited = std::collections::HashSet::new();
    visited.insert(name.to_string());

    let mut allow_tools: Vec<String> = Vec::new();
    let mut deny_tools: Vec<String> = Vec::new();
    let mut allow_backends: Vec<String> = Vec::new();
    let mut deny_backends: Vec<String> = Vec::new();
    let mut composed_from = vec![name.to_string()];

    // Collect from extended profiles first
    for parent_name in &config.extends {
        if !visited.insert(parent_name.clone()) {
            tracing::warn!(
                "Tool profile '{name}': cycle detected in extends chain at '{parent_name}', skipping"
            );
            continue;
        }
        if let Some(parent) = all_configs.get(parent_name) {
            composed_from.push(parent_name.clone());
            if let Some(ref at) = parent.allow_tools {
                allow_tools.extend(at.iter().cloned());
            }
            if let Some(ref dt) = parent.deny_tools {
                deny_tools.extend(dt.iter().cloned());
            }
            if let Some(ref ab) = parent.allow_backends {
                allow_backends.extend(ab.iter().cloned());
            }
            if let Some(ref db) = parent.deny_backends {
                deny_backends.extend(db.iter().cloned());
            }
        } else {
            tracing::warn!(
                "Tool profile '{name}': extended profile '{parent_name}' not found"
            );
        }
    }

    // Append this profile's own lists (take precedence by being last in union)
    if let Some(ref at) = config.allow_tools {
        allow_tools.extend(at.iter().cloned());
    }
    if let Some(ref dt) = config.deny_tools {
        deny_tools.extend(dt.iter().cloned());
    }
    if let Some(ref ab) = config.allow_backends {
        allow_backends.extend(ab.iter().cloned());
    }
    if let Some(ref db) = config.deny_backends {
        deny_backends.extend(db.iter().cloned());
    }

    ResolvedConfig {
        allow_tools: if allow_tools.is_empty() { None } else { Some(allow_tools) },
        deny_tools: if deny_tools.is_empty() { None } else { Some(deny_tools) },
        allow_backends: if allow_backends.is_empty() { None } else { Some(allow_backends) },
        deny_backends: if deny_backends.is_empty() { None } else { Some(deny_backends) },
        composed_from,
    }
}

// ============================================================================
// Per-session profile state
// ============================================================================

/// Thread-safe per-session tool profile state.
///
/// Each session can have an active tool profile that filters search/list
/// results. The profile is set via `gateway_set_tool_profile` and reset on
/// session teardown.
///
/// **Session teardown**: `SessionToolProfiles::remove(session_id)` MUST be called
/// on client disconnect. Register via the session lifecycle hook in
/// `src/gateway/server.rs`. Without this, long-running gateways leak memory
/// proportional to unique session count.
pub struct SessionToolProfiles {
    /// session_id -> active tool profile name
    active: DashMap<String, String>,
}

impl SessionToolProfiles {
    /// Create an empty store.
    pub fn new() -> Self {
        Self { active: DashMap::new() }
    }

    /// Get the active tool profile name for a session.
    pub fn get(&self, session_id: &str) -> Option<String> {
        self.active.get(session_id).map(|v| v.clone())
    }

    /// Set the active tool profile for a session.
    pub fn set(&self, session_id: &str, profile: &str) {
        self.active.insert(session_id.to_string(), profile.to_string());
    }

    /// Remove a session (teardown).
    pub fn remove(&self, session_id: &str) {
        self.active.remove(session_id);
    }
}

impl Default for SessionToolProfiles {
    fn default() -> Self {
        Self::new()
    }
}
```

### 3.5 How It Affects Existing Meta-Tools

#### `gateway_list_tools`

```
Before: Lists ALL tools (filtered by RoutingProfile only).
After:  If tool profile is active, intersects with profile filter.
        Includes profile metadata in response.
```

```json
{
  "tools": [...],
  "total": 42,
  "active_profile": "coding",
  "profile_tool_count": 42,
  "total_available": 183
}
```

#### `gateway_search_tools`

```
Before: Searches ALL tools, ranks by keyword + usage.
After:  Stage 1: Search within active profile.
        Stage 2: If <3 results in profile, also search globally with
                 annotation "outside_profile: true".
        Includes profile recommendation when non-active profile scores higher.
```

```json
{
  "query": "stock price",
  "matches": [
    {"server": "cap", "tool": "yahoo_stock_quote", "score": 12.0}
  ],
  "total": 1,
  "profile_hint": "Tip: activate 'finance' profile for more financial tools (3 additional matches)"
}
```

The `profile_hint` is generated by running the search against all profiles and
finding the one with the most matches for this query. Only emitted when:
- A non-active profile scores 2+ more matches than the active profile
- The suggestion is different from the currently active profile

#### `gateway_invoke`

```
Before: Invokes the tool (subject to RoutingProfile security check).
After:  UNCHANGED. Tool profiles NEVER block invocation.
```

This is the critical safety invariant. An LLM that has discovered a tool via
any means (direct name, previous search, hardcoded) can always invoke it.

#### `gateway_set_tool_profile` (new meta-tool)

A dedicated meta-tool for activating tool profiles. This is separate from
`gateway_set_profile` (which sets routing profiles for backward compatibility)
to avoid naming collisions in a shared namespace.

```rust
/// Handle gateway_set_tool_profile.
///
/// Sets the active tool profile for the current session. The tool profile
/// filters list_tools and search_tools results but NEVER blocks invocation.
pub(super) async fn set_tool_profile(
    &self,
    args: &Value,
    session_id: Option<&str>,
) -> Result<Value> {
    let name = extract_required_str(args, "profile")?;
    let sid = session_id.unwrap_or("default");

    let registry = self.tool_profile_registry.as_ref()
        .ok_or_else(|| Error::json_rpc(-32602, "No tool profiles configured"))?;

    if registry.get(name).is_none() {
        return Err(Error::json_rpc(
            -32602,
            format!("Unknown tool profile '{name}'. Use gateway_list_tool_profiles to see available profiles."),
        ));
    }

    self.session_tool_profiles.set(sid, name);

    Ok(json!({
        "tool_profile": name,
        "active": true,
    }))
}
```

#### `gateway_list_tool_profiles` (new meta-tool)

Lists available tool profiles with descriptions and priority.

```rust
/// Handle gateway_list_tool_profiles.
///
/// Returns all configured tool profiles. Separate from gateway_list_profiles
/// (which lists routing profiles) to keep the namespaces distinct.
pub(super) async fn list_tool_profiles(
    &self,
    session_id: Option<&str>,
) -> Result<Value> {
    let sid = session_id.unwrap_or("default");
    let active = self.session_tool_profiles.get(sid);

    let profiles = self.tool_profile_registry.as_ref()
        .map(|r| r.summaries())
        .unwrap_or_default();

    Ok(json!({
        "tool_profiles": profiles,
        "active_tool_profile": active,
    }))
}
```

#### `gateway_set_profile` (existing, unchanged)

Continues to set routing profiles only. Kept for backward compatibility.
Routing profiles and tool profiles are independent dimensions with distinct
meta-tools.

#### `gateway_list_profiles` (existing, unchanged)

Continues to list routing profiles only. Tool profiles are listed via the
separate `gateway_list_tool_profiles` meta-tool.

```json
{
  "routing_profiles": [
    {"name": "default", "description": "All tools (unrestricted)"}
  ],
  "active_routing_profile": "default"
}
```

The `gateway_list_tool_profiles` response:

```json
{
  "tool_profiles": [
    {"name": "research", "description": "Web research, search, and data gathering", "priority": 1},
    {"name": "coding", "description": "Software development and code management", "priority": 1},
    {"name": "finance", "description": "Financial data, stock quotes, SEC filings", "priority": 2},
    {"name": "full_stack_dev", "description": "Full-stack development", "priority": 1, "composed_from": ["full_stack_dev", "coding", "research", "devops"]}
  ],
  "active_tool_profile": null
}
```

### 3.6 Auto-Detection Algorithm

Auto-detection uses transition data from `TransitionTracker` to infer context:

```rust
/// Suggest a tool profile based on recent invocations.
///
/// Called lazily when `gateway_search_tools` or `gateway_list_tools` is
/// invoked and no tool profile is explicitly set.
///
/// Algorithm:
/// 1. Get the last N tools invoked in this session from TransitionTracker.
/// 2. For each tool profile, count how many of those tools match.
/// 3. Return the profile with the highest match count (ties: higher priority).
/// 4. If the best profile matches <30% of recent tools, return None (ambiguous).
///
/// This is advisory only -- included in the response as `suggested_profile`
/// but never automatically activated.
pub fn suggest_profile(
    &self,
    session_id: &str,
    recent_tools: &[String],
) -> Option<String> {
    let registry = self.tool_profile_registry.as_ref()?;
    let suggestion = registry.auto_detect(recent_tools)?;

    // Only suggest if >=30% of recent tools match
    let profile = registry.get(&suggestion)?;
    let match_count = recent_tools.iter()
        .filter(|t| profile.filter.tool_allowed(t))
        .count();

    if match_count * 100 / recent_tools.len().max(1) >= 30 {
        Some(suggestion)
    } else {
        None
    }
}
```

---

## 4. Integration Points (Exact File Paths)

### New Files

| File | LOC | Purpose |
|------|-----|---------|
| `src/tool_profile/mod.rs` | ~250 | `ToolProfileConfig`, `ToolProfileRegistry`, `SessionToolProfiles`, `resolve_extends()` |
| `src/tool_profile/tests.rs` | ~200 | Unit tests |

### Modified Files

| File | Change | LOC Delta |
|------|--------|-----------|
| `src/lib.rs` | Add `pub mod tool_profile;` | +1 |
| `src/config/features.rs` | Add `ToolProfileConfig` to `GatewayConfig` | +15 |
| `src/gateway/meta_mcp/search.rs` | In `search_tools()` and `list_tools()`: check active tool profile, add `profile_hint` generation | +40 |
| `src/gateway/meta_mcp/protocol.rs` | Add `set_tool_profile()` and `list_tool_profiles()` handlers | +35 |
| `src/gateway/meta_mcp_tool_defs.rs` | Register `gateway_set_tool_profile` and `gateway_list_tool_profiles` meta-tool definitions | +20 |

**Estimated total: ~350-550 LOC** (within budget).

### Integration with Existing `RoutingProfile`

The key principle: **tool profiles and routing profiles are orthogonal**.

```
Visibility = RoutingProfile.tool_allowed(tool) AND ToolProfile.tool_allowed(tool)
Invocation = RoutingProfile.check(backend, tool)  [tool profile not checked]
```

The tool profile is ONLY consulted for `list_tools` and `search_tools`. The
`invoke_tool` path remains unchanged -- it checks the routing profile for
security but not the tool profile.

---

## 5. Design Characteristics

### 5.1 Composable Profiles via `extends`

The `extends` keyword allows operators to define atomic domain profiles
(research, coding, finance) and compose them into role profiles
(full_stack_dev = coding + research + devops) without duplicating pattern lists.

This is the **Unix philosophy** applied to tool scoping: small, composable
units that combine via a simple rule (union of allow lists).

### 5.2 Profile Recommendations in Search Results

When a query matches a non-active profile better than the active one, the
response includes a `profile_hint`. This is contextual intelligence that no
competing gateway provides:

```json
"profile_hint": "Tip: activate 'finance' profile for more financial tools (3 additional matches)"
```

This guides the LLM without requiring it to know all profiles upfront. The
LLM discovers profiles organically through its search interactions.

### 5.3 Auto-Detection from Invocation History

The `suggested_profile` field uses `TransitionTracker` data to infer what the
LLM is doing. If the last 5 invocations were all `github_*` tools, the system
suggests "coding". This is implicit context awareness without requiring the LLM
to explicitly manage its profile.

### 5.4 Safety Invariant: Profiles Never Block Invocation

This is a deliberate design choice that distinguishes tool profiles from
security mechanisms. An LLM that has learned a tool name from any source
(documentation, previous conversation, hardcoded prompt) can always invoke it.
Profiles only affect discoverability, not capability. This prevents a class of
bugs where profile misconfiguration silently breaks tool access.

### 5.5 Token Savings Compound with Tool Count

| Tools | Without Profile | With Profile (coding) | Savings |
|-------|-----------------|----------------------|---------|
| 180 | ~2000 tokens (list_tools) | ~400 tokens | 80% |
| 500 | ~5500 tokens | ~600 tokens | 89% |
| 1000 | ~11000 tokens | ~700 tokens | 94% |

This directly serves the gateway's core value proposition: context token savings.

---

## 6. Testing Strategy

### Unit Tests (src/tool_profile/tests.rs)

1. **ToolProfileRegistry::from_config** -- build registry from 3 profiles,
   verify all are present, verify default profile.

2. **resolve_extends** -- profile A extends B; verify A has union of A+B allow
   lists. Verify B's tools are included.

3. **resolve_extends cycle detection** -- A extends B, B extends A. Verify no
   infinite loop, warning logged, both profiles still compile.

4. **resolve_extends missing parent** -- A extends "nonexistent". Verify warning
   logged, A still compiles with its own lists only.

5. **CompiledToolProfile::filter.tool_allowed** -- test glob matching: prefix,
   suffix, contains, exact, wildcard.

6. **auto_detect** -- given recent tools `[github_create_pr, github_list_reviews]`,
   verify "coding" profile is suggested (not "finance" or "research").

7. **auto_detect ambiguous** -- given tools from 3 different domains, verify
   `None` is returned (below 30% threshold).

8. **auto_detect priority tiebreak** -- two profiles match equally; the one with
   higher priority wins.

9. **SessionToolProfiles** -- set, get, remove. Verify session isolation.

10. **Profile does not block invocation** -- explicit test that `invoke_tool`
    path does NOT consult tool profile.

### Integration Tests

11. **search_tools with active profile** -- set "coding" profile, search for
    "search". Verify only coding-related search tools appear.

12. **search_tools fallback** -- set "finance" profile, search for "github".
    0 results in profile, but global fallback shows github tools with
    `outside_profile: true`.

13. **list_tools with profile** -- set "research" profile, verify tool count
    matches only research-allowed tools.

14. **profile_hint generation** -- set "coding" profile, search "stock price".
    Verify `profile_hint` suggests "finance".

15. **set_tool_profile unknown** -- call `gateway_set_tool_profile` with nonexistent
    name. Verify error -32602.

16. **list_tool_profiles** -- verify response includes all tool profiles with
    correct structure, separate from routing profiles.

17. **Hot-reload** -- modify config.yaml to add a new tool profile, trigger
    reload, verify new profile appears in `gateway_list_profiles`.

---

## 7. Migration Path

### Phase 1: Core Registry (days 1-2)
- Add `src/tool_profile/mod.rs` with config types, registry, and extends resolution.
- Add `ToolProfileConfig` to gateway config.
- Unit tests for registry and extends.

### Phase 2: Wire into Meta-Tools (days 3-4)
- Modify `search_tools` to intersect with tool profile.
- Modify `list_tools` to intersect with tool profile.
- Add `gateway_set_tool_profile` and `gateway_list_tool_profiles` meta-tools.
- Integration tests.

### Phase 3: Intelligence Layer (days 5-6)
- Add `profile_hint` generation in search results.
- Add `suggested_profile` via auto-detection.
- Add `outside_profile: true` annotations for fallback results.

---

## 8. Risk Register

| # | Risk | Likelihood | Impact | Mitigation |
|---|------|-----------|--------|------------|
| R1 | Profile misconfiguration hides tools the LLM needs | Medium | Medium | Profiles never block invocation. Search falls back to global on <3 results. `profile_hint` guides toward correct profile. |
| R2 | `extends` chains create confusing allow/deny interactions | Low | Medium | Cycle detection at compile time. Flat resolution (no runtime traversal). `gateway_get_profile` shows the resolved filter for debugging. |
| R3 | Auto-detection suggests wrong profile | Medium | Low | Suggestions are advisory only (never auto-activated). 30% threshold prevents noisy suggestions. |
| R4 | Naming collision between routing profiles and tool profiles | Low | Low | Mitigated: distinct meta-tools (`gateway_set_tool_profile` / `gateway_list_tool_profiles` for tool profiles, existing `gateway_set_profile` / `gateway_list_profiles` for routing profiles). |
| R5 | Token savings claims depend on profile specificity | Low | Low | Operators control profile granularity. Even a broad profile (50% of tools) delivers 50% token savings on list_tools. |
| R6 | LOC budget exceeded | Low | Low | Core is ~250 LOC. Integration is ~150 LOC. Tests ~200 LOC. Total ~600 LOC is at the upper bound but within budget. |

---

## 9. Shared Prerequisites

**Prerequisite**: Implement session disconnect callback in `src/gateway/server.rs` that notifies all per-session state holders. All RFCs adding per-session DashMap entries MUST register a cleanup handler.

---

## 10. ADR: Architecture Decision Record

### ADR-0073: Context-Aware Tool Profiles for Discovery Scoping

**Status**: Proposed
**Date**: 2026-03-13
**Deciders**: Mikko Parkkola

#### Context

With 180+ tools growing to 500+, tool search and listing produce noisy results
that waste LLM context tokens and degrade relevance. Existing routing profiles
are security scopes (operator-managed), not task contexts (LLM-managed).

#### Decision

Implement declarative tool profiles that:
1. Are defined by operators in config.yaml with glob-based tool patterns.
2. Are activated by LLMs via `gateway_set_tool_profile` (distinct from routing's `gateway_set_profile`).
3. Filter `list_tools` and `search_tools` results but NEVER block `invoke_tool`.
4. Support composition via `extends` (resolved at startup, not runtime).
5. Provide auto-detection suggestions based on recent invocation history.
6. Include `profile_hint` in search results when a better profile exists.

#### Consequences

**Positive**:
- 80-94% token savings on `list_tools` at scale.
- LLM-driven context switching (LLM activates the profile it needs).
- Composable profiles reduce operator configuration burden.
- Fallback to global search prevents tool discovery failures.
- `ToolProfileConfig` converts to `RoutingProfile` internally for efficient pattern evaluation.

**Negative**:
- Adds a second "profile" concept alongside routing profiles (mitigated by distinct meta-tool names: `gateway_set_tool_profile` vs `gateway_set_profile`).
- `extends` resolution adds startup complexity.
- Auto-detection is heuristic (may suggest wrong profile).

**Neutral**:
- No new dependencies.
- No breaking changes to existing API (additive fields in responses).
- Feature is opt-in (no `tool_profiles` key = no change in behavior).

---

## 11. Related RFCs

- **RFC-0072 (Semantic Tool Search)**: Tool profiles interact with semantic
  search. When a tool profile is active, semantic search scopes to the
  profile's tool set first, then falls back to global with annotations.
  The `profile_hint` in search results is generated by RFC-0073 logic but
  applies to both keyword and semantic search paths. See RFC-0072 section 10
  for the detailed interaction model.
