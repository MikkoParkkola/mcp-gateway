# Boundary Protocol Description (BPD) DSL for MCP Cross-Platform Ports

**Status**: Proposed
**Date**: 2026-04-16
**Author**: Mikko Parkkola
**Ticket**: MIK-2888
**Origin**: Ruach Tov Collective -- Boundary Protocol Description specification

---

## 1. Problem Statement

MCP servers are proliferating across platforms (Claude Code, Cursor, Windsurf, VS Code + Copilot, custom agents). Each server has implicit boundaries -- what it does, what it refuses, which transports it requires, how it fails, what security guarantees it provides. These boundaries are undocumented or scattered across READMEs, config files, and source code.

When porting an MCP server to a new platform, or evaluating whether two servers are functionally equivalent, there is no machine-readable format for comparing boundary surfaces. An operator cannot answer "does this MCP server on platform A cover the same capabilities and constraints as the one on platform B?" without reading all the source.

**BPD solves this.** It is a declarative DSL for describing the complete boundary surface of an MCP server: what it exposes, what it blocks, what transports it speaks, how it degrades, and what security contracts it enforces.

### Why BPD Matters for mcp-gateway

mcp-gateway is a meta-server: it proxies requests to N backend MCP servers and adds its own boundary layer (kill switch, circuit breaker, error budget, tool policy, cost governance, firewall). The gateway's boundary is the _composition_ of its own policies and its backends' boundaries. BPD gives us:

1. **Portability documentation** -- a single file that describes what mcp-gateway does and does not do, enabling accurate reimplementation on other platforms.
2. **Backend comparison** -- when adding a new backend, compare its BPD against existing ones to detect overlap, gaps, or incompatible constraints.
3. **Automated validation** -- `mcp-gateway bpd generate` can produce a BPD from `gateway.yaml` + runtime capability scan, then `mcp-gateway bpd validate` can check that the live system conforms to its declared boundaries.
4. **Cross-platform porting contracts** -- when someone ports mcp-gateway's Meta-MCP surface to another framework, the BPD serves as the acceptance-test specification.

---

## 2. What BPD Describes

A BPD document covers six boundary dimensions:

| Dimension | What it captures |
|-----------|-----------------|
| **Identity** | Server name, version, protocol versions supported, authorship |
| **Capabilities** | Tools exposed, resources served, prompts offered -- with cardinality and schema references |
| **Exclusions** | What the server explicitly does NOT do (negative boundaries) |
| **Transport** | Required and supported transports (stdio, HTTP+SSE, Streamable HTTP), TLS requirements, mTLS |
| **Failure modes** | Circuit breaker behavior, retry semantics, error budget, degradation path |
| **Security** | Auth requirements, input sanitization, SSRF protection, tool policy, prompt injection defenses |

---

## 3. Syntax Proposal

BPD uses YAML because mcp-gateway's entire ecosystem is YAML-native (`gateway.yaml`, capability definitions, playbooks, tool profiles). No new parser required.

### 3.1 Top-Level Structure

```yaml
bpd: "1.0"
origin: "Ruach Tov Collective"

identity:
  name: mcp-gateway
  version: "2.7.0"
  description: >
    Universal MCP gateway that multiplexes N backend MCP servers behind
    a compact Meta-MCP tool surface with discovery, caching, failsafes,
    and security enforcement.
  protocols:
    - "2024-10-07"
    - "2024-11-05"
    - "2025-03-26"
    - "2025-06-18"
    - "2025-11-25"
  license: MIT
  maintainer: maintainer@example.com
```

### 3.2 Capabilities

```yaml
capabilities:
  meta_tools:
    description: >
      The gateway exposes a fixed set of meta-tools to clients. Clients
      never see backend tools directly; they discover and invoke through
      these meta-tools.
    tools:
      - name: gateway_search_tools
        description: Keyword search across all backends with ranked results
        always_present: true
        idempotent: true
        cacheable: true

      - name: gateway_invoke
        description: Call any tool on any backend
        always_present: true
        idempotent: false
        side_effects: true
        supports:
          - idempotency_key
          - response_caching
          - kill_switch_check
          - error_budget_tracking
          - transition_prediction

      - name: gateway_list_servers
        description: List all registered backends with status and circuit state
        always_present: true
        idempotent: true

      - name: gateway_list_tools
        description: List tools from one or all backends
        always_present: true
        idempotent: true
        cacheable: true

      - name: gateway_run_playbook
        description: Execute a multi-step tool chain as a single call
        always_present: true
        idempotent: false
        side_effects: true

      - name: gateway_kill_server
        description: Operator kill switch -- immediately disable a backend
        always_present: true
        destructive: true

      - name: gateway_revive_server
        description: Re-enable a killed backend and reset error budget
        always_present: true

      - name: gateway_get_stats
        description: Usage stats, cache hits, token savings, cost
        always_present: false
        condition: "config.stats.enabled"

      - name: gateway_webhook_status
        description: Webhook endpoint and delivery stats
        always_present: false
        condition: "config.webhooks.enabled"

  backend_proxying:
    description: >
      The gateway proxies tool calls to backend MCP servers. It does NOT
      re-expose backend tools as its own tools. Clients must use
      gateway_search_tools to discover and gateway_invoke to call.
    tool_count: dynamic
    tool_count_range: "0..unbounded"

  capability_system:
    description: >
      YAML-defined REST API integrations (Fulcrum format) that appear
      as native tools alongside MCP backend tools. Hot-reloaded from
      capability directories.
    schema_format: fulcrum/1.0
    directories_configurable: true
    hot_reload: true
    schema_validation: true

  server_to_client:
    description: >
      The gateway proxies server-to-client MCP capabilities back to
      connected clients.
    methods:
      - sampling/createMessage
      - elicitation/create
      - roots/list
      - notifications/roots/list_changed

  resources: none
  prompts: none
```

### 3.3 Exclusions (Negative Boundaries)

```yaml
exclusions:
  - id: no-direct-tool-exposure
    description: >
      The gateway does NOT re-expose backend tools as top-level MCP tools.
      All backend tool invocation goes through gateway_invoke. This is a
      deliberate design choice for token efficiency.

  - id: no-llm-api
    description: >
      The gateway does NOT expose a chat-completions, embeddings, or
      inference API. It routes MCP tool calls, not LLM requests. If a
      backend internally calls an LLM, that is opaque to the gateway.

  - id: no-persistent-state
    description: >
      The gateway is stateless across restarts except for usage.json and
      transitions.json. No database dependency.

  - id: no-multi-tenant-isolation
    description: >
      All clients share the same backend pool. Per-client backend
      isolation requires separate gateway instances or routing profiles.
```

### 3.4 Transport

```yaml
transport:
  client_facing:
    - type: http
      path: /mcp
      methods: [POST]
      content_type: application/json
      protocol: jsonrpc/2.0
      streaming:
        supported: true
        mechanism: sse
        session_header: Mcp-Session-Id

    - type: http
      path: /health
      methods: [GET]
      auth_required: false

  backend_facing:
    - type: stdio
      description: >
        Spawns backend as a child process, communicates over stdin/stdout
        with JSON-RPC messages.
      lifecycle: managed
      idle_timeout: configurable

    - type: http
      description: >
        Connects to remote MCP servers via HTTP POST or SSE.
      lifecycle: external
      supports_sse: true

  tls:
    mtls_supported: true
    mtls_required: false
    configurable: true
    client_cert_policies: true
    crl_support: true
```

### 3.5 Failure Modes

```yaml
failure_modes:
  circuit_breaker:
    scope: per-backend
    states: [closed, open, half_open]
    configurable: true
    parameters:
      failure_threshold: integer
      success_threshold: integer
      reset_timeout: duration
    auto_recovery: true
    recovery_mechanism: timeout-based

  error_budget:
    scope: per-backend
    mechanism: sliding-window
    parameters:
      window_size: integer
      window_duration: duration
      threshold: float  # 0.0-1.0
    auto_kill: true
    recovery_mechanism: manual  # requires gateway_revive_server
    warning_at: 0.8  # 80% of threshold

  rate_limiting:
    scope: global
    algorithm: token-bucket
    parameters:
      requests_per_second: integer
      burst_size: integer

  retry:
    scope: per-request
    parameters:
      max_attempts: integer
      initial_backoff: duration
      max_backoff: duration
      multiplier: float

  idempotency:
    mechanism: sha256-keyed-state-machine
    states: [in_flight, completed]
    ttl:
      in_flight: 5m
      completed: 24h
    duplicate_behavior: return-cached-or-409

  degradation_path:
    description: >
      When a backend fails: circuit opens -> requests rejected for that
      backend -> reset_timeout elapses -> half-open probe -> success
      threshold reached -> closed. If error budget exhausted: auto-kill
      -> all requests to that backend rejected -> operator must call
      gateway_revive_server.
    total_gateway_failure: >
      If all backends are killed or circuit-open, meta-tools still respond
      (gateway_list_servers shows status). The gateway itself does not crash.
```

### 3.6 Security Boundaries

```yaml
security:
  authentication:
    bearer_token: optional
    api_keys: optional
    oauth2:
      supported: true
      flow: authorization_code_pkce
      scope: per-backend
    agent_auth:
      supported: true
      mechanism: oauth2-agent-scoped
    key_server:
      supported: true
      mechanism: oidc-to-temporary-api-key

  input_protection:
    sanitize_input: true
    xss_prevention: true
    ssrf_protection: true

  tool_policy:
    default_action: configurable  # allow or deny
    allow_list: configurable
    deny_list: configurable
    default_deny_mode: true
    audit_logging: true

  firewall:
    request_scanning: true
    response_scanning: true
    prompt_injection_detection: true
    credential_redaction: true
    anomaly_detection: optional

  secrets:
    resolution:
      - keychain  # macOS Keychain
      - env       # environment variables
      - oauth     # OAuth token refresh
    never_in_config: true  # secrets must use resolution, not literals
```

### 3.7 Cost Governance (Optional Boundary)

```yaml
cost_governance:
  supported: true
  feature_gated: true  # requires cargo feature "cost-governance"
  budgets:
    daily: optional
    per_tool: optional
    per_key: optional
  enforcement:
    - at: 50%
      action: log
    - at: 80%
      action: notify
    - at: 100%
      action: block
  alternatives: >
    When a tool is blocked by budget, the gateway can suggest cheaper
    alternative tools if configured.
```

---

## 4. Full BPD Example for mcp-gateway

The sections above (3.1 through 3.7) compose into a single file. In practice, the BPD for mcp-gateway would live at:

```
docs/bpd/mcp-gateway.bpd.yaml
```

The file is the concatenation of all sections above under a single document root, approximately 200 lines of YAML.

---

## 5. CLI Integration: `mcp-gateway bpd generate`

### 5.1 Proposed Subcommands

```
mcp-gateway bpd generate [--output <path>]    # Generate BPD from gateway.yaml + capability scan
mcp-gateway bpd validate [--bpd <path>]       # Validate running gateway conforms to BPD
mcp-gateway bpd diff <a.bpd.yaml> <b.bpd.yaml>  # Compare two BPDs (e.g., before/after upgrade)
mcp-gateway bpd lint <path>                   # Check BPD syntax and completeness
```

### 5.2 Generation Strategy

`bpd generate` would:

1. **Load `gateway.yaml`** -- extract server config, auth, security, failsafe, transport settings.
2. **Scan capability directories** -- enumerate all Fulcrum YAML files, extract tool names, schemas, categories.
3. **Probe running backends** (if `--live` flag) -- call `tools/list` on each backend to capture actual tool surface.
4. **Merge** -- combine gateway-level boundaries (meta-tools, security, failure modes) with backend-level tool inventories.
5. **Emit BPD YAML** to stdout or `--output` path.

### 5.3 Validation Strategy

`bpd validate` would:

1. Load the BPD file.
2. Connect to the running gateway at `http://{host}:{port}/mcp`.
3. Call `gateway_list_servers` and `gateway_list_tools` -- verify all declared capabilities exist.
4. Check that declared exclusions hold (e.g., confirm no direct tool exposure).
5. Verify transport endpoints respond (health check, SSE).
6. Report pass/fail per BPD section.

### 5.4 Diff Strategy

`bpd diff` would:

1. Parse both BPD files.
2. Produce a structured diff showing:
   - Added/removed/changed tools.
   - Changed failure mode parameters.
   - Changed security boundaries.
   - Changed transport requirements.
3. Output as YAML diff or human-readable table.

This is the primary use case for cross-platform porting: "I ported mcp-gateway's surface to a Python implementation -- does the BPD match?"

---

## 6. Integration with Existing Systems

### 6.1 Capability System

Each Fulcrum capability YAML already describes a tool's schema, auth requirements, and cost. BPD generation would extract these into the `capabilities` section automatically. No changes to the Fulcrum format are needed.

### 6.2 Tool Profiles (RFC-0073)

Tool profiles define context-aware filtering. BPD captures the _full_ boundary; tool profiles capture _active_ boundaries for a session. A BPD could reference which tool profiles are defined:

```yaml
tool_profiles:
  defined:
    - coding
    - research
    - communication
  activation: client-driven  # LLM calls gateway_set_tool_profile
```

### 6.3 Routing Profiles

Routing profiles are security boundaries (allow/deny per API key). BPD captures their existence and semantics, not their per-key configuration:

```yaml
routing_profiles:
  supported: true
  scope: per-session
  mechanism: allow-deny-lists
  activation: per-api-key-or-meta-tool
```

### 6.4 Playbooks

Playbooks are multi-step tool chains. BPD captures the _pattern_, not individual playbook definitions:

```yaml
playbooks:
  supported: true
  format: yaml
  variable_interpolation: true
  error_strategies: [stop, continue, retry]
  hot_reload: true
```

---

## 7. Design Decisions

### 7.1 Why YAML, not a Custom Grammar

- mcp-gateway operators already know YAML (gateway.yaml, capabilities, playbooks).
- YAML has mature parsers in every language (Rust: `serde_yaml`, Python: `PyYAML`, JS: `js-yaml`).
- BPD files can be validated with JSON Schema, reusing the same tooling as OpenAPI.
- No lexer/parser to maintain.

### 7.2 Why Declarative, not Executable

BPD describes boundaries, it does not enforce them. Enforcement is the gateway's responsibility. BPD is the _specification_; the gateway is the _implementation_. This separation lets BPD be used for documentation, comparison, and testing without coupling it to runtime code.

### 7.3 Why "Exclusions" Are First-Class

Negative boundaries ("what this server does NOT do") are as important as positive boundaries for cross-platform porting. If a porter does not know that mcp-gateway deliberately avoids direct tool exposure, they might implement it differently and break the token-savings design.

### 7.4 BPD Versioning

The `bpd: "1.0"` field at the top allows schema evolution. Parsers should reject unknown major versions and warn on unknown minor-version fields.

---

## 8. Ruach Tov Collective Reference

BPD originates from the Ruach Tov Collective's work on MCP server interoperability. The core insight is that MCP servers have implicit boundaries that become explicit bugs when porting across platforms. By making boundaries declarative and machine-readable, the collective enables:

- **Automated compatibility checking** between MCP server implementations.
- **Port validation** -- "does my Python reimplementation of an MCP server match the original Rust version's boundary surface?"
- **Registry enrichment** -- MCP server registries (like the community capability registry in mcp-gateway) can index BPD files for searchable boundary metadata.

This design document adapts the Ruach Tov BPD concept to mcp-gateway's specific architecture and YAML-native ecosystem.

---

## 9. Implementation Scope

This is a **design document only**. No implementation is proposed in this ticket. Future work:

| Phase | Scope | Estimated LOC |
|-------|-------|---------------|
| 1 | BPD YAML schema (JSON Schema for validation) | ~150 |
| 2 | `bpd generate` subcommand | ~300-400 |
| 3 | `bpd validate` subcommand | ~200-300 |
| 4 | `bpd diff` subcommand | ~200 |
| 5 | `bpd lint` subcommand | ~100 |

Total estimated: ~950-1150 LOC across 4 subcommands plus schema.

---

## 10. Open Questions

1. **Should BPD include per-backend boundaries?** Currently it describes the gateway as a whole. Individual backends could have their own BPD files, composed into the gateway's BPD via `$ref` or `includes`.

2. **Should BPD capture performance boundaries?** (e.g., "this server handles 100 req/s" or "tool X has p99 latency of 2s"). This is useful for porting but harder to declare statically.

3. **Should BPD be embeddable in `gateway.yaml` itself?** A `bpd:` top-level key in `gateway.yaml` would keep everything in one file, but mixes configuration with specification.

4. **Interop with MCP server metadata proposals.** The MCP specification may eventually include server metadata fields that overlap with BPD. If so, BPD should defer to the official spec for overlapping concerns and focus on the boundary/exclusion/failure dimensions that the spec does not cover.
