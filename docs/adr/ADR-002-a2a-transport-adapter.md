# ADR-002: A2A Transport Adapter

**Date**: 2026-04-16
**Status**: Proposed
**Deciders**: Mikko Parkkola
**References**: [AP2/Galileo Evaluation](../evaluations/AP2_AND_GALILEO_EVALUATION.md), [A2A Specification](https://a2a-protocol.org/latest/specification/)

## Amendment 2026-10-07 (MIK-8063): what 4.0.0 ships

This amendment supersedes the body below wherever the two disagree.

- **Outbound only.** An MCP client delegates to an A2A agent through the gateway. The gateway-as-A2A-server phase (Phase 2 below) is not built: A2A-native frameworks already consume MCP directly, so it adds no access or governance they lack.
- **A `Transport`, not a `Provider`.** An `a2a_url` backend starts in `Backend::start` as `A2aTransport`, so each delegation passes the same invoke path, pool, budgets, audit, firewall, relay detection and response gates as any tool call. A separate provider path would have bypassed them. The `A2aProvider` sketched below was never wired, and is removed.
- **Pinned wire: A2A 1.0, JSON-RPC binding** (specification tag v1.0.1).
  - The card is read at `/.well-known/agent-card.json`. The endpoint is the first JSONRPC 1.x entry in the card's `supportedInterfaces`.
  - Calls use `SendMessage` with a fresh `messageId`, a `ROLE_USER` role, `A2A-Version: 1.0`, and `TASK_STATE_*` states.
  - The `agent.json` path and `message/send` method below are pre-1.0 vocabulary.
- **One tool per agent** (`send_message`). `SendMessage` cannot address a skill, so the skills become description text.
- **Outbound policy.**
  - Requests use the backend HTTP client: pinned resolution, and every redirect same-origin and SSRF-checked.
  - The endpoint the card advertises must share the origin of `a2a_url`, so configured credentials never leave the configured origin.
- **No caller-supplied `context_id`.** One caller could otherwise name another caller's conversation at the agent.

---

## Context

### Why A2A matters for mcp-gateway

mcp-gateway is a universal MCP gateway that multiplexes AI clients to 500+ backend tools through a compact Meta-MCP surface. Today it supports three transport types: stdio (subprocess), HTTP/SSE, and WebSocket. All backends speak MCP (JSON-RPC 2.0 with MCP-specific methods like `tools/list`, `tools/call`, `initialize`).

Google's Agent2Agent (A2A) protocol is an open standard (Apache 2.0, Linux Foundation) for inter-agent communication. It uses JSON-RPC 2.0 over HTTP(S) but with fundamentally different semantics than MCP:

| Dimension | MCP | A2A |
|-----------|-----|-----|
| **Purpose** | Agent-to-tool (transparent tool invocation) | Agent-to-agent (opaque task delegation) |
| **Discovery** | `initialize` + `tools/list` | Agent Cards at `/.well-known/agent.json` |
| **Invocation** | `tools/call` (stateless, synchronous) | `message/send` (stateful task lifecycle) |
| **State model** | Stateless | submitted -> working -> completed/failed/canceled/input-required |
| **Data exchange** | Content (text, image, resource) | Parts and Artifacts (text, file, data) |
| **Multi-turn** | Not native | `input-required` state with context IDs |
| **Streaming** | SSE notifications | SSE + push notifications (webhooks) |

The AP2/Galileo evaluation (MIK-2895) rated A2A support for mcp-gateway as **ADOPT** with a "STRONG" fit assessment. A2A and MCP are explicitly designed as complementary protocols -- MCP is the "tool layer" and A2A is the "agent layer". Adding A2A support would make mcp-gateway a true multi-protocol gateway rather than an MCP-only router.

### Enterprise momentum

A2A has backing from Google Cloud, Salesforce, SAP, Atlassian, MongoDB, and others. SDKs exist for Python, Go, JavaScript, Java, and .NET. As enterprise A2A agents proliferate, a gateway that can proxy both MCP tools and A2A agents from a single MCP client surface becomes a significant differentiator.

---

## Decision

Add A2A as a transport/backend type with two modes of operation:

1. **A2A-as-backend** (Phase 1): The gateway discovers and proxies A2A agents as if they were MCP tool backends. MCP clients call tools through the gateway's existing Meta-MCP surface; the gateway translates to A2A `message/send` operations on the backend side.

2. **Gateway-as-A2A-server** (Phase 2): The gateway exposes itself as an A2A agent, publishing an Agent Card at `/.well-known/agent.json`. External A2A clients can delegate tasks to the gateway, which routes them to any registered backend (MCP or A2A).

Phase 1 is the priority. Phase 2 is additive and can be deferred without blocking Phase 1.

---

## Design

### Protocol mapping: MCP to A2A (Phase 1)

When the gateway proxies an A2A backend, it must translate between MCP semantics and A2A semantics at the boundary.

#### Discovery: `tools/list` -> Agent Card skills

When a client calls `tools/list` (or the Meta-MCP `gateway_tools` enumerates an A2A backend), the gateway fetches the Agent Card from the backend's well-known URL, parses the `skills` array, and synthesizes MCP `Tool` definitions:

```
A2A Agent Card                          MCP Tool
─────────────────                       ────────
skill.id                            ->  tool.name (prefixed with backend namespace)
skill.name                          ->  tool.title
skill.description                   ->  tool.description
skill.tags                          ->  tool.annotations (custom metadata)
skill.inputModes / skill.outputModes ->  tool.inputSchema (synthesized)
```

The `inputSchema` for synthesized tools is constructed as:

```json
{
  "type": "object",
  "properties": {
    "message": {
      "type": "string",
      "description": "Message to send to the agent"
    },
    "context_id": {
      "type": "string",
      "description": "Optional context ID for multi-turn conversations"
    }
  },
  "required": ["message"]
}
```

This schema reflects A2A's opaque delegation model -- the caller sends a natural-language message, not structured arguments. The `context_id` field enables multi-turn interactions.

#### Invocation: `tools/call` -> `message/send` -> Task lifecycle

When a client calls a synthesized A2A tool via `gateway_invoke`, the gateway:

1. Extracts `message` and optional `context_id` from the tool arguments.
2. Constructs an A2A `SendMessageRequest`:
   ```json
   {
     "jsonrpc": "2.0",
     "id": "<gateway-request-id>",
     "method": "message/send",
     "params": {
       "message": {
         "role": "user",
         "parts": [{"kind": "text", "text": "<message>"}],
         "contextId": "<context_id or generated>"
       },
       "configuration": {
         "acceptedOutputModes": ["text/plain", "application/json"],
         "blocking": true
       }
     }
   }
   ```
3. Waits for the A2A response. The response contains a `Task` with a status and optional artifacts.
4. Maps the A2A result back to MCP content:

```
A2A Task                                MCP tools/call result
────────                                ──────────────────────
task.status.state == "completed"    ->  is_error: false
task.status.state == "failed"       ->  is_error: true
task.artifacts[].parts[].text       ->  Content::Text { text }
task.artifacts[].parts[].file       ->  Content::Resource { uri, mime_type }
task.artifacts[].parts[].data       ->  Content::Text { json_serialized }
task.status.state == "input-required" -> Content::Text with prompt + context_id for follow-up
```

#### Task state handling

A2A tasks can be long-running. The gateway handles this with the following strategy:

- **Blocking mode** (default): Set `configuration.blocking: true` in the `SendMessageRequest`. The A2A server holds the HTTP connection until the task reaches a terminal state or `input-required`. The gateway respects its configured backend timeout (`BackendConfig.timeout`).
- **Non-blocking mode** (future): For backends with `capabilities.pushNotifications: true`, the gateway could register a webhook and poll via `tasks/get`. This is deferred to a later iteration.
- **Streaming** (future): For backends with `capabilities.streaming: true`, the gateway could forward SSE events from the A2A backend through its own notification multiplexer. Also deferred.

#### Authentication

A2A Agent Cards declare authentication requirements in `securitySchemes`. The gateway maps these to its existing auth mechanisms:

| A2A Security Scheme | Gateway Mapping |
|---------------------|-----------------|
| `apiKey` | `BackendConfig.headers` (inject API key header) |
| `http` (bearer) | `BackendConfig.headers` (inject Authorization header) |
| `oauth2` | `BackendConfig.oauth` (existing OAuth flow) |
| `openIdConnect` | `BackendConfig.oauth` (OIDC discovery) |

### Gateway as A2A server (Phase 2)

The gateway exposes an Agent Card at `GET /.well-known/agent.json` describing:
- All registered backend tools as A2A skills
- Gateway capabilities (streaming, push notifications based on gateway config)
- Authentication requirements matching the gateway's auth config

A2A JSON-RPC endpoints are added to the Axum router:
- `POST /a2a` -- Handles `message/send`, `message/stream`, `tasks/get`, `tasks/cancel`
- The gateway parses incoming A2A messages, maps them to `gateway_invoke` calls on the appropriate backend, and wraps results in A2A Task/Artifact responses.

---

## Implementation Sketch

### New files

| File | Purpose |
|------|---------|
| `src/a2a/mod.rs` | Module root, re-exports |
| `src/a2a/types.rs` | A2A protocol types: `AgentCard`, `Skill`, `Task`, `TaskState`, `Message`, `Part`, `Artifact`, `SendMessageRequest`, `SendMessageResponse` |
| `src/a2a/client.rs` | A2A HTTP client: fetch Agent Card, send messages, get/cancel tasks |
| `src/a2a/provider.rs` | `A2aProvider` implementing `Provider` trait -- adapts A2A backend to gateway's provider abstraction |
| `src/a2a/mapping.rs` | Bidirectional mapping functions: MCP Tool <-> A2A Skill, MCP Content <-> A2A Part/Artifact, tool call args -> A2A message |
| `src/a2a/server.rs` | (Phase 2) A2A server endpoints: Agent Card generation, message/send handler, task state store |
| `src/a2a/tests/` | Unit and integration tests |

### Modified files

| File | Change |
|------|--------|
| `src/lib.rs` | Add `pub mod a2a;` (behind `a2a` feature flag) |
| `src/config/mod.rs` | Add `A2a` variant to `TransportConfig` enum |
| `src/config/mod.rs` | `TransportConfig::transport_type()` returns `"a2a"` for the new variant |
| `src/main.rs` | Backend startup: detect `transport: a2a` and create `A2aProvider` instead of `McpProvider` |
| `src/gateway/router/mod.rs` | (Phase 2) Mount `/.well-known/agent.json` and `/a2a` routes |
| `Cargo.toml` | Add `a2a` feature flag; no new dependencies needed (`reqwest`, `serde`, `serde_json`, `tokio` already present) |

### Config shape

A2A backends are configured alongside existing backends using a new transport variant:

```yaml
backends:
  travel-agent:
    description: "External travel planning A2A agent"
    enabled: true
    transport: a2a
    a2a_url: "https://travel.example.com"
    # Agent Card fetched from: https://travel.example.com/.well-known/agent.json
    # Alternative: explicit agent card path
    # a2a_agent_card_path: "/custom/agent.json"
    idle_timeout: 300s
    timeout: 60s
    headers:
      Authorization: "Bearer ${TRAVEL_AGENT_API_KEY}"
```

The `TransportConfig` enum gains a third variant:

```rust
/// A2A transport (Agent2Agent protocol).
A2a {
    /// Base URL of the A2A agent.
    a2a_url: String,
    /// Custom path for the Agent Card (default: /.well-known/agent.json).
    #[serde(default)]
    a2a_agent_card_path: Option<String>,
}
```

### A2aProvider implementation

```rust
pub struct A2aProvider {
    name: String,
    client: A2aClient,
    agent_card: RwLock<Option<AgentCard>>,
    context_ids: DashMap<String, String>,  // tool_call_id -> context_id for multi-turn
}

#[async_trait]
impl Provider for A2aProvider {
    fn name(&self) -> &str { &self.name }

    async fn list_tools(&self) -> Result<Vec<Tool>> {
        let card = self.client.fetch_agent_card().await?;
        let tools = card.skills.iter().map(|s| skill_to_tool(s, &self.name)).collect();
        *self.agent_card.write() = Some(card);
        Ok(tools)
    }

    async fn invoke(&self, tool: &str, args: Value) -> Result<Value> {
        let message = args.get("message")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Protocol("A2A tools require a 'message' argument".into()))?;

        let context_id = args.get("context_id")
            .and_then(Value::as_str)
            .map(String::from);

        let response = self.client.send_message(message, context_id.as_deref()).await?;

        task_to_value(&response.task)
    }

    async fn health(&self) -> ProviderHealth {
        match self.client.fetch_agent_card().await {
            Ok(_) => ProviderHealth::Healthy,
            Err(e) => ProviderHealth::Unavailable(format!("Agent Card unreachable: {e}")),
        }
    }
}
```

### A2aClient core

```rust
pub struct A2aClient {
    http: reqwest::Client,
    base_url: String,
    agent_card_path: String,
    headers: HeaderMap,
}

impl A2aClient {
    /// Fetch and parse the Agent Card from the well-known URL.
    pub async fn fetch_agent_card(&self) -> Result<AgentCard> { ... }

    /// Send a message to the A2A agent (blocking mode).
    pub async fn send_message(
        &self,
        text: &str,
        context_id: Option<&str>,
    ) -> Result<SendMessageResponse> { ... }

    /// Get task status by ID.
    pub async fn get_task(&self, task_id: &str) -> Result<Task> { ... }

    /// Cancel a running task.
    pub async fn cancel_task(&self, task_id: &str) -> Result<Task> { ... }
}
```

### Feature flag

The A2A module is gated behind a Cargo feature to keep the default build lean:

```toml
[features]
a2a = []  # No new deps -- reqwest, serde, tokio already in tree
default = ["a2a", ...]  # Included by default
```

---

## Consequences

### Positive

- **Multi-protocol gateway**: mcp-gateway becomes the first gateway (to our knowledge) that can proxy both MCP and A2A backends through a unified client surface. This is the primary differentiator.
- **Zero breaking changes**: A2A is a new transport variant. Existing stdio, HTTP, and WebSocket backends continue to work identically. The `TransportConfig` enum gains a variant; `serde(untagged)` deserialization is backward compatible.
- **No new dependencies**: The A2A protocol uses JSON-RPC 2.0 over HTTP -- the same primitives mcp-gateway already uses. `reqwest`, `serde`, `serde_json`, `tokio`, and `dashmap` are already in `Cargo.toml`. The A2A types are simple structs that can be defined inline.
- **Provider trait alignment**: The existing `Provider` trait (`list_tools`, `invoke`, `health`) maps cleanly to A2A operations. `A2aProvider` is a peer of `McpProvider` and `CapabilityProvider` -- no architectural changes needed.
- **Enterprise adoption path**: As organizations deploy A2A agents (via Google ADK, LangGraph, CrewAI, or custom implementations), mcp-gateway can immediately integrate them without requiring MCP wrappers.
- **Multi-turn capability**: A2A's `input-required` state and context IDs enable conversational interactions that MCP's stateless `tools/call` cannot express natively. The gateway surfaces this through the `context_id` argument.

### Negative / Risks

- **Semantic impedance mismatch**: MCP tools are transparent (structured inputs, deterministic schemas). A2A agents are opaque (natural-language messages, unpredictable outputs). The synthesized `inputSchema` with a single `message` string field is correct but loses the structured-input affordance that MCP clients expect. Mitigation: document clearly that A2A-backed tools are "agent delegation" tools, not traditional structured tools.
- **Timeout complexity**: A2A tasks can run for minutes or hours. The gateway's 30-second default timeout is appropriate for MCP tools but may be too short for A2A agents. Mitigation: A2A backends should configure longer `timeout` values in `BackendConfig`, and the gateway documentation should highlight this.
- **State management**: MCP is stateless; A2A is stateful (tasks persist, context IDs maintain conversation state). The gateway must store context-ID-to-task-ID mappings for multi-turn flows. This is in-memory state that is lost on gateway restart. Mitigation: context IDs are optional; single-turn interactions work without state. For durable multi-turn, a future iteration could persist context maps.
- **Agent Card caching**: Agent Cards should be cached (they change infrequently), but the cache TTL must balance freshness against discovery latency. Mitigation: reuse the existing `meta_mcp.cache_ttl` configuration (default 5 minutes).
- **Phase 2 complexity**: Exposing the gateway as an A2A server introduces a second protocol surface to maintain and secure. This includes Agent Card generation, A2A JSON-RPC endpoint routing, and task state management. Mitigation: Phase 2 is explicitly deferred and gated behind separate configuration.

### Not addressed by this ADR

- **A2A streaming (SSE)**: Forwarding A2A SSE events through the gateway's notification multiplexer. Requires integration with `src/gateway/streaming.rs`. Deferred to Phase 1b.
- **A2A push notifications**: Registering webhooks with A2A backends for long-running tasks. Requires the gateway to expose a webhook receiver endpoint. Deferred.
- **Extended Agent Cards**: Fetching post-authentication Agent Cards via `GetExtendedAgentCard`. Straightforward extension once basic Agent Card fetching works.
- **A2A-to-A2A routing**: The gateway routing A2A requests to A2A backends without MCP translation. Out of scope -- the gateway's value proposition is the MCP client surface.
- **Multi-hop signing**: ADR-001 (message signing) covers gateway-to-client HMAC integrity. Signing A2A backend responses before forwarding to MCP clients would require extending the message signing pipeline to cover the A2A translation boundary. Future work.

---

## Alternatives Considered

| Alternative | Why rejected |
|-------------|-------------|
| **Wrap A2A agents in MCP shims** | Requires deploying a separate MCP wrapper process per A2A agent. Defeats the purpose of a multi-protocol gateway. Operational burden scales linearly with agent count. |
| **A2A-only mode (no MCP translation)** | Breaks the gateway's core contract: MCP clients connect to the gateway and see MCP tools. A2A-only mode would require clients to speak A2A, which most MCP clients (Claude Code, Cursor, etc.) do not support. |
| **Use the A2A Go SDK directly** | mcp-gateway is Rust. FFI to Go adds complexity, build-time overhead, and runtime safety concerns. The A2A protocol is simple enough (JSON-RPC 2.0 over HTTP) to implement natively in Rust with existing dependencies. |
| **Wait for MCP to absorb A2A concepts** | The protocols are explicitly designed as complementary, not convergent. MCP handles tool/context integration; A2A handles agent delegation. Waiting means missing the enterprise adoption window. |
| **Implement only Phase 2 (gateway as A2A server)** | Less valuable without Phase 1. The primary use case is consuming external A2A agents through the MCP surface, not exposing the gateway to A2A clients (which already speaks MCP). |

---

## Implementation Plan

| Phase | Scope | Effort | Deliverables |
|-------|-------|--------|--------------|
| **1a** | A2A types + client + provider (read-only discovery) | 1 week | `src/a2a/types.rs`, `client.rs`, `provider.rs` with `list_tools()` working |
| **1b** | Tool invocation (blocking mode) | 1 week | `invoke()` with MCP-to-A2A translation, content mapping, error handling |
| **1c** | Config integration + tests | 1 week | `TransportConfig::A2a`, backend startup, integration tests with mock A2A server |
| **2a** | Agent Card generation + A2A server endpoint | 1-2 weeks | `/.well-known/agent.json`, `POST /a2a` with `message/send` |
| **2b** | Streaming + push notifications | 1-2 weeks | SSE forwarding, webhook registration |

Total: 4-6 weeks for full bidirectional support. 3 weeks for Phase 1 (A2A-as-backend only).

---

## References

- [A2A Protocol Specification](https://a2a-protocol.org/latest/specification/)
- [A2A GitHub Repository](https://github.com/a2aproject/a2a-spec)
- [AP2/Galileo Evaluation (MIK-2895/MIK-2896)](../evaluations/AP2_AND_GALILEO_EVALUATION.md)
- [mcp-gateway Provider trait](../../src/provider/mod.rs)
- [mcp-gateway Transport trait](../../src/transport/mod.rs)
- [mcp-gateway Config (TransportConfig)](../../src/config/mod.rs)
- [ADR-001: Inter-Agent Message Signing](./ADR-001-inter-agent-message-signing.md)
