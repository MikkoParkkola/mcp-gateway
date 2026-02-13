# v2.2.0 Feature Design: Validate CLI + Transforms + Playbooks

## Design Thesis

Three features, one principle: **make every token count**.

- **Validate** catches bad tool design *before* it wastes tokens at runtime
- **Transforms** strip noise from responses *after* the call, reducing what the LLM must parse
- **Playbooks** collapse multi-call sequences into one tool invocation, eliminating round-trips

Together these form a pipeline: author capabilities (validate) -> call them (playbooks) -> shape the output (transforms). Each ships independently; none depends on the others.

---

## 1. Validate CLI — Rules Engine Extension

### What exists today

`src/validator/` has a working rules engine with the `Rule` trait, 6 agent-UX rules (AX-001..AX-006), `ValidationReport`, and `ValidationResult`. The CLI command `mcp-gateway cap validate <file>` currently calls `parse_capability_file` + `validate_capability` for structural correctness only — it does not run the agent-UX rules engine.

### What changes

1. **New top-level command**: `mcp-gateway validate` (alongside `serve`, `cap`, `init`, `stats`)
2. **Wires the rules engine to the CLI** — loads capability YAMLs, converts to `Tool` via `to_mcp_tool()`, runs `AgentUxValidator`
3. **New rules**: cross-capability conflict detection, schema completeness, naming consistency across a directory
4. **Output formats**: human text (default), JSON, SARIF (for CI integration)

### CLI Design

```
mcp-gateway validate [OPTIONS] <PATHS>...

Arguments:
  <PATHS>...  Files or directories to validate (YAML capabilities)

Options:
  -f, --format <FORMAT>    Output format [default: text] [possible: text, json, sarif]
  -s, --severity <LEVEL>   Minimum severity to report [default: info] [possible: fail, warn, info]
  --fix                    Auto-fix issues where possible (rewrites YAML in place)
  --no-color               Disable colored output
```

### New Rust Types

```rust
// ── src/validator/mod.rs (EXTEND existing) ──────────────────────

/// Output format for validation reports
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    Sarif,
}

/// Minimum severity filter
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum SeverityFilter {
    Fail,
    Warn,
    Info,
}

/// Configuration for a validation run
pub struct ValidateConfig {
    pub format: OutputFormat,
    pub min_severity: SeverityFilter,
    pub auto_fix: bool,
    pub color: bool,
}

// ── src/validator/rules.rs (EXTEND existing) ─────────────────────

/// AX-007: Schema Completeness
/// Every input property must have: type, description; required array must exist
struct SchemaCompletenessRule;

/// AX-008: Cross-Capability Conflict Detection
/// Detects duplicate tool names, overlapping functionality
struct ConflictDetectionRule;

/// AX-009: Naming Consistency
/// Enforces consistent naming patterns within a directory
struct NamingConsistencyRule;

// ── src/validator/fix.rs (NEW file) ──────────────────────────────

/// Suggested fix for a validation issue
pub struct SuggestedFix {
    /// Rule that produced this fix
    pub rule_code: String,
    /// Description of what the fix does
    pub description: String,
    /// The field path to modify (e.g., "schema.input.properties.query")
    pub field_path: String,
    /// The suggested new value (serialized YAML fragment)
    pub suggested_value: serde_json::Value,
}

/// Apply fixes to a capability definition
pub struct CapabilityFixer;

// ── src/validator/sarif.rs (NEW file) ────────────────────────────

/// SARIF 2.1.0 output types for CI integration
pub struct SarifReport {
    pub version: String,   // "2.1.0"
    pub runs: Vec<SarifRun>,
}

pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

pub struct SarifTool {
    pub driver: SarifDriver,
}

pub struct SarifDriver {
    pub name: String,
    pub version: String,
    pub rules: Vec<SarifRuleDescriptor>,
}

pub struct SarifRuleDescriptor {
    pub id: String,
    pub name: String,
    pub short_description: SarifMessage,
}

pub struct SarifResult {
    pub rule_id: String,
    pub level: String,  // "error", "warning", "note"
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
}

pub struct SarifMessage {
    pub text: String,
}

pub struct SarifLocation {
    pub physical_location: SarifPhysicalLocation,
}

pub struct SarifPhysicalLocation {
    pub artifact_location: SarifArtifactLocation,
}

pub struct SarifArtifactLocation {
    pub uri: String,
}
```

### Integration Points

| Touchpoint | File | Change |
|---|---|---|
| CLI enum | `src/cli.rs` | Add `Validate` variant to `Command` enum |
| Command dispatch | `src/main.rs` | Add `Command::Validate { .. }` match arm |
| Validator module | `src/validator/mod.rs` | Add `OutputFormat`, `ValidateConfig`, re-exports |
| Rules engine | `src/validator/rules.rs` | Add AX-007, AX-008, AX-009 rules |
| New: auto-fix | `src/validator/fix.rs` | `CapabilityFixer` struct |
| New: SARIF | `src/validator/sarif.rs` | SARIF 2.1.0 output formatter |
| Module tree | `src/lib.rs` | No change needed (validator already declared) |

---

## 2. Transforms — Response Filtering Pipeline

### Problem

API responses contain 50-200 fields. LLMs only need 5-10. Every extra field is wasted context tokens. The existing `response_path` in `RestConfig` is a single jq-like path — useful but limited to extraction, not transformation.

### Architecture

Transforms sit between the executor response and the MCP response. They are configured per-capability in the YAML `transform` section. The pipeline runs synchronously (transforms are CPU-bound JSON manipulation, not I/O).

```
Executor Response
      │
      ▼
┌─────────────┐
│  Transform  │──▶ project ──▶ rename ──▶ redact ──▶ format
│  Pipeline   │
└─────────────┘
      │
      ▼
MCP Response (lean)
```

### YAML Schema

```yaml
# In any capability YAML file:
transform:
  # Field projection — keep only these paths (allowlist)
  project:
    - "web.results[].title"
    - "web.results[].url"
    - "web.results[].description"
    - "query.original"

  # Field renaming — output uses new names
  rename:
    "web.results": "results"
    "query.original": "query"

  # PII redaction — mask matching patterns
  redact:
    - pattern: "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b"
      replacement: "[EMAIL]"
    - pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b"
      replacement: "[SSN]"

  # Format conversion — reshape output structure
  format:
    type: flat           # "flat" | "nested" | "template"
    # For type=template:
    # template: "Found {{results.length}} results for '{{query}}'"
```

### Rust Types

```rust
// ── src/transform.rs (NEW file) ─────────────────────────────────

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Complete transform configuration for a capability
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransformConfig {
    /// Field projection (allowlist of JSON paths to keep)
    #[serde(default)]
    pub project: Vec<String>,

    /// Field renaming map (old_path -> new_name)
    #[serde(default)]
    pub rename: std::collections::HashMap<String, String>,

    /// PII/sensitive data redaction rules
    #[serde(default)]
    pub redact: Vec<RedactRule>,

    /// Output format conversion
    #[serde(default)]
    pub format: Option<FormatConfig>,
}

/// A single redaction rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactRule {
    /// Regex pattern to match
    pub pattern: String,
    /// Replacement string
    pub replacement: String,
}

/// Output format configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormatConfig {
    /// Format type
    #[serde(rename = "type")]
    pub format_type: FormatType,
    /// Template string (for type=template)
    #[serde(default)]
    pub template: Option<String>,
}

/// Supported format transformations
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FormatType {
    /// Flatten nested objects to top-level keys
    Flat,
    /// Keep nested structure (default, noop)
    Nested,
    /// Apply a Handlebars-style template
    Template,
}

/// Compiled transform pipeline (ready to execute)
pub struct TransformPipeline {
    /// Projection paths (parsed)
    projections: Vec<JsonPath>,
    /// Rename map
    renames: Vec<(JsonPath, String)>,
    /// Compiled regexes for redaction
    redactions: Vec<CompiledRedaction>,
    /// Format step
    format: Option<FormatConfig>,
}

/// Parsed JSON path segment
#[derive(Debug, Clone)]
pub enum JsonPathSegment {
    /// Object key: "foo"
    Key(String),
    /// Array wildcard: "[]"
    ArrayWildcard,
    /// Array index: "[0]"
    ArrayIndex(usize),
}

/// A parsed JSON path like "web.results[].title"
pub type JsonPath = Vec<JsonPathSegment>;

/// Compiled redaction (regex pre-compiled)
struct CompiledRedaction {
    regex: regex::Regex,
    replacement: String,
}
```

### Integration Points

| Touchpoint | File | Change |
|---|---|---|
| New module | `src/transform.rs` | All transform types and pipeline logic |
| Module tree | `src/lib.rs` | Add `pub mod transform;` |
| Capability def | `src/capability/definition.rs` | Add `transform: TransformConfig` field to `CapabilityDefinition` |
| Executor | `src/capability/executor.rs` | After REST response, apply `TransformPipeline` if configured |
| YAML parsing | Automatic via serde | `#[serde(default)]` means existing YAMLs keep working |

### Key Design Decisions

- **Allowlist, not blocklist**: `project` specifies what to KEEP, not what to remove. Safer default — new API fields don't leak through.
- **Order is fixed**: project -> rename -> redact -> format. This prevents confusing interactions (you project first so renames use the projected paths).
- **No runtime cost for unconfigured**: `TransformConfig::default()` has empty vecs. `TransformPipeline::is_noop()` returns true, executor skips entirely.

---

## 3. Playbooks — Multi-Step Tool Chains

### Problem

Many agent workflows require 3-5 sequential tool calls with data flowing between them. Each round-trip costs ~500 tokens of overhead (tool call + response framing). A 5-step workflow wastes ~2,500 tokens just on framing. Worse, the LLM can make mistakes in the intermediate plumbing.

### Architecture

A playbook is a YAML-defined sequence of steps that executes server-side as a single meta-tool invocation. Variable passing between steps uses a simple `$step_name.path` syntax. The playbook engine reuses the existing `CapabilityExecutor` and `MetaMcp::invoke_tool` for actual execution.

```
Agent calls: gateway_run_playbook(name="research", inputs={query: "Rust MCP"})
      │
      ▼
┌──────────────────────────────────────────────────┐
│  Playbook Engine                                  │
│                                                   │
│  Step 1: brave_search(query=$inputs.query)        │
│       │ result → $search                          │
│       ▼                                           │
│  Step 2: brave_grounding(query=$search.results[0].title) │
│       │ result → $detail                          │
│       ▼                                           │
│  Step 3: (conditional: if $detail.confidence > 0.8)│
│       │ result → $final                           │
│       ▼                                           │
│  Return: { summary: $detail.answer,               │
│            sources: $search.results[].url }        │
└──────────────────────────────────────────────────┘
      │
      ▼
Single MCP response (all steps collapsed)
```

### YAML Schema

Playbooks live in a `playbooks/` directory (parallel to `capabilities/`).

```yaml
# playbooks/research.yaml
playbook: "1.0"
name: research_topic
description: >
  Search for a topic, ground the top result, and return a verified summary.
  Saves 3 round-trips vs calling each tool individually.

# Input schema (same format as capability inputs)
inputs:
  type: object
  properties:
    query:
      type: string
      description: "Research query"
    depth:
      type: string
      enum: [quick, thorough]
      default: quick
  required: [query]

# Execution steps
steps:
  - name: search
    tool: brave_search
    server: capabilities    # "capabilities" = local capability backend
    arguments:
      query: "$inputs.query"
      count: 5

  - name: ground
    tool: brave_grounding
    server: capabilities
    arguments:
      query: "$search.web.results[0].title"
    # Only run if search returned results
    condition: "$search.web.results | length > 0"

  - name: deep_search
    tool: brave_search
    server: capabilities
    arguments:
      query: "$inputs.query site:$search.web.results[0].url"
      count: 3
    # Only run for thorough depth
    condition: "$inputs.depth == 'thorough'"

# Output shaping — what to return to the agent
output:
  type: object
  properties:
    summary:
      path: "$ground.answer"
      fallback: "No grounding available"
    sources:
      path: "$search.web.results[].url"
    confidence:
      path: "$ground.confidence"
      fallback: 0.0

# Error handling
on_error: continue   # "continue" | "abort" | "retry"
max_retries: 1
timeout: 60          # Total playbook timeout in seconds
```

### Rust Types

```rust
// ── src/playbook.rs (NEW file) ──────────────────────────────────

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// A playbook definition loaded from YAML
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookDefinition {
    /// Format version
    #[serde(default = "default_playbook_version")]
    pub playbook: String,

    /// Unique name (becomes the tool name suffix: gateway_run_{name})
    pub name: String,

    /// Human-readable description
    pub description: String,

    /// Input schema (JSON Schema)
    #[serde(default)]
    pub inputs: Value,

    /// Ordered execution steps
    pub steps: Vec<PlaybookStep>,

    /// Output mapping
    #[serde(default)]
    pub output: Option<PlaybookOutput>,

    /// Error handling strategy
    #[serde(default = "default_on_error")]
    pub on_error: ErrorStrategy,

    /// Maximum retries per step
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Total timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

fn default_playbook_version() -> String { "1.0".to_string() }
fn default_on_error() -> ErrorStrategy { ErrorStrategy::Abort }
fn default_max_retries() -> u32 { 1 }
fn default_timeout() -> u64 { 60 }

/// A single step in a playbook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookStep {
    /// Step name (used as variable prefix: $name.path)
    pub name: String,

    /// Tool to invoke
    pub tool: String,

    /// Server/backend that hosts the tool
    #[serde(default = "default_server")]
    pub server: String,

    /// Arguments with variable interpolation ($step.path syntax)
    #[serde(default)]
    pub arguments: HashMap<String, Value>,

    /// Condition expression (skip step if evaluates to false)
    #[serde(default)]
    pub condition: Option<String>,
}

fn default_server() -> String { "capabilities".to_string() }

/// Output mapping definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookOutput {
    /// JSON Schema type
    #[serde(rename = "type", default)]
    pub output_type: String,

    /// Property mappings
    #[serde(default)]
    pub properties: HashMap<String, OutputMapping>,
}

/// Single output field mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputMapping {
    /// Variable path to extract ($step.json.path)
    pub path: String,

    /// Fallback value if path resolves to null
    #[serde(default)]
    pub fallback: Option<Value>,
}

/// Error handling strategy
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ErrorStrategy {
    /// Stop playbook on first error
    Abort,
    /// Skip failed step, continue with next
    Continue,
    /// Retry failed step up to max_retries
    Retry,
}

/// Runtime state during playbook execution
pub struct PlaybookContext {
    /// Input arguments
    inputs: Value,
    /// Results from completed steps, keyed by step name
    step_results: HashMap<String, Value>,
    /// Errors from failed steps
    step_errors: HashMap<String, String>,
}

/// Result of a playbook execution
pub struct PlaybookResult {
    /// Final output (after output mapping)
    pub output: Value,
    /// Steps that executed successfully
    pub steps_completed: Vec<String>,
    /// Steps that were skipped (condition=false)
    pub steps_skipped: Vec<String>,
    /// Steps that failed
    pub steps_failed: Vec<String>,
    /// Total execution time
    pub duration_ms: u64,
}

/// Engine that loads and executes playbooks
pub struct PlaybookEngine {
    /// Loaded playbook definitions
    definitions: HashMap<String, PlaybookDefinition>,
}

// ── src/playbook/interpolation.rs (or section within playbook.rs) ──

/// Variable reference in a playbook argument
/// Examples: "$inputs.query", "$search.web.results[0].title"
#[derive(Debug, Clone)]
pub struct VarRef {
    /// Step name ("inputs" for playbook inputs)
    pub step: String,
    /// JSON path within the step's result
    pub path: Vec<JsonPathSegment>,
}

// Reuse JsonPathSegment from transform.rs via crate-level type
```

### Meta-Tool Registration

The playbook engine exposes a single meta-tool:

```
gateway_run_playbook
  Arguments:
    name: string       — Playbook name
    arguments: object  — Playbook inputs
```

This is registered alongside the existing 4-5 meta-tools in `build_meta_tools()`.

### Integration Points

| Touchpoint | File | Change |
|---|---|---|
| New module | `src/playbook.rs` | All playbook types and engine |
| Module tree | `src/lib.rs` | Add `pub mod playbook;` |
| Meta-tool list | `src/gateway/meta_mcp_helpers.rs` | Add `gateway_run_playbook` tool definition to `build_meta_tools()` |
| Meta-tool dispatch | `src/gateway/meta_mcp.rs` | Add `"gateway_run_playbook"` arm in `handle_tools_call` match |
| Config | `src/config.rs` | Add `playbooks: PlaybooksConfig` with `enabled: bool`, `directories: Vec<String>` |
| Capability backend | `src/capability/backend.rs` | Playbook engine needs access to `CapabilityBackend::call_tool` |
| Main startup | `src/main.rs` | Load playbook definitions from configured directories |

---

## File Ownership Map

Two implementers work in parallel. Clear boundaries prevent merge conflicts.

### validate-builder (Task #2)

**Owns exclusively:**
- `src/validator/mod.rs` (extend existing)
- `src/validator/rules.rs` (extend existing — add AX-007, AX-008, AX-009)
- `src/validator/fix.rs` (new)
- `src/validator/sarif.rs` (new)
- `tests/validate_cli_tests.rs` (new)

**Touches (shared, non-conflicting sections):**
- `src/cli.rs` — Add `Validate` variant to `Command` enum (after existing `Stats` variant)
- `src/main.rs` — Add `Command::Validate { .. }` match arm in the main match (new arm, no existing code modified)

### pipeline-builder (Task #3)

**Owns exclusively:**
- `src/transform.rs` (new)
- `src/playbook.rs` (new)
- `tests/transform_tests.rs` (new)
- `tests/playbook_tests.rs` (new)
- `playbooks/` directory (new, at project root)

**Touches (shared, non-conflicting sections):**
- `src/lib.rs` — Add `pub mod transform;` and `pub mod playbook;` lines
- `src/capability/definition.rs` — Add `#[serde(default)] pub transform: TransformConfig` field to `CapabilityDefinition`
- `src/capability/executor.rs` — Add transform pipeline application after REST response
- `src/gateway/meta_mcp_helpers.rs` — Add `gateway_run_playbook` to `build_meta_tools()`
- `src/gateway/meta_mcp.rs` — Add `"gateway_run_playbook"` dispatch arm
- `src/config.rs` — Add `PlaybooksConfig` to gateway config
- `src/main.rs` — Add playbook loading during startup (in `run_server`, distinct from validate-builder's `Command::Validate` arm)

### Conflict-Free Guarantee

The two builders touch `src/main.rs` in different locations:
- **validate-builder** adds a new `Command::Validate` arm in the `match cli.command` block (line ~36-44)
- **pipeline-builder** adds playbook loading inside `run_server()` (line ~450+)

The two builders touch `src/lib.rs` with additive-only changes (adding `pub mod` lines). These merge cleanly.

No other files overlap.

---

## Shared Types

Both transforms and playbooks use JSON path traversal. To avoid duplication:

```rust
// ── src/transform.rs exports JsonPathSegment and JsonPath ──
// ── src/playbook.rs imports: use crate::transform::{JsonPath, JsonPathSegment}; ──
```

This creates a one-directional dependency: `playbook` depends on `transform` (for the path types). Transform has zero dependencies on playbook.

---

## YAML Backward Compatibility

All new YAML fields use `#[serde(default)]`:

- Existing capability YAMLs without `transform:` section deserialize to `TransformConfig::default()` (all empty vecs, no-op)
- Existing configs without `playbooks:` section get `PlaybooksConfig { enabled: false, directories: vec![] }`
- The new `mcp-gateway validate` command is additive — `mcp-gateway cap validate` continues to work unchanged

---

## Token Savings Analysis

| Feature | Token savings mechanism | Estimated impact |
|---|---|---|
| Validate | Prevents verbose/redundant tool descriptions from reaching LLM | 200-500 tokens/tool (preventive) |
| Transforms | Strips 60-90% of API response fields before LLM sees them | 2,000-10,000 tokens/call (active) |
| Playbooks | Eliminates round-trip framing for multi-step workflows | 500 tokens/step * N steps (structural) |

A typical 5-tool, 3-step workflow saves: **~15,000 tokens per interaction** (transforms on each call + playbook collapsing 3 round-trips).

At $15/M tokens (Opus 4.6): **$0.225 saved per interaction**.

---

## Testing Strategy

### validate-builder tests
- Unit: each new rule (AX-007, AX-008, AX-009) with good/bad fixtures
- Unit: SARIF output matches schema
- Unit: auto-fix applies correct YAML modifications
- Integration: `mcp-gateway validate capabilities/` on real capability directory
- CLI: exit codes (0 = pass, 1 = failures found, 2 = parse error)

### pipeline-builder tests
- Unit: `TransformPipeline` projection, rename, redact, format individually
- Unit: JSON path parsing and traversal
- Unit: variable interpolation in playbook arguments
- Unit: playbook condition evaluation
- Unit: error strategy behavior (abort vs continue vs retry)
- Integration: end-to-end playbook with mock executor
- Integration: transform applied to real capability execution result

---

## Implementation Order

Both builders can start immediately after this design is approved.

**validate-builder** critical path:
1. Add `Command::Validate` to CLI (10 min)
2. Wire `AgentUxValidator` to the new command (30 min)
3. Add AX-007, AX-008, AX-009 rules (1 hr)
4. Add SARIF output (30 min)
5. Add auto-fix (1 hr)

**pipeline-builder** critical path:
1. `src/transform.rs` — types + pipeline + tests (1.5 hr)
2. Wire transform into `CapabilityDefinition` + executor (30 min)
3. `src/playbook.rs` — types + engine + interpolation + tests (2 hr)
4. Wire playbook meta-tool into gateway (30 min)
5. Add playbook loading to config + startup (30 min)

Total: ~4 hours each, fully parallel.
