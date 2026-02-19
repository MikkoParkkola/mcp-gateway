# Issue #73: MCP 2025-11-25 Missing Capabilities Implementation Plan

## Executive Summary

The mcp-gateway currently only implements `tools/*` and `ping` methods at the Meta-MCP
layer. This plan adds support for the remaining MCP 2025-11-25 capabilities:

1. **Resources** (resources/list, resources/read, resources/templates/list, resources/subscribe, resources/unsubscribe)
2. **Prompts** (prompts/list, prompts/get)
3. **Logging** (logging/setLevel, notifications/message)
4. **Elicitation** (elicitation/create - form and URL modes) -- client-side, proxied
5. **Sampling with tools** (sampling/createMessage with tool_choice) -- client-side, proxied
6. **Roots** (roots/list, notifications/roots/list_changed) -- client-side, proxied

## Architecture Decision

The gateway is a **proxy/aggregator**. For server-side capabilities (resources, prompts, logging),
the gateway aggregates responses from backends -- similar to how it aggregates tools today.
For client-side capabilities (elicitation, sampling, roots), the gateway forwards requests
from backends to the connected client and relays responses back.

### Proxy Strategy

| Capability   | Direction       | Gateway Role                                        |
|-------------|-----------------|-----------------------------------------------------|
| Resources   | client→server   | Aggregate from all backends, prefix URIs with backend name |
| Prompts     | client→server   | Aggregate from all backends, prefix names with backend name |
| Logging     | client→server   | Forward setLevel to backends; relay notifications to client |
| Elicitation | server→client   | Forward backend requests to client, relay response back |
| Sampling    | server→client   | Forward backend requests to client, relay response back |
| Roots       | server→client   | Forward backend requests to client, relay response back |

---

## Existing Code Analysis

### Type Definitions (`src/protocol/types.rs`)

Already has:
- `Resource` (uri, name, title, description, mime_type, size) -- line 51-69
- `Prompt` (name, title, description, arguments) -- line 72-85
- `PromptArgument` (name, description, required) -- line 88-98
- `Content` enum (Text, Image, Audio, ResourceLink, Resource) -- line 101-164
- `ResourceContents` enum (Text, Blob) -- line 167-190
- `Annotations` (audience, priority) -- line 193-201
- `ServerCapabilities` with `resources`, `prompts`, `logging` fields -- line 219-242
- `ResourcesCapability` (subscribe, list_changed) -- line 287-295
- `PromptsCapability` (list_changed) -- line 279-284
- `ClientCapabilities` with `elicitation`, `roots`, `sampling` -- line 306-323
- `ElicitationCapability` (form, url) -- line 326-334
- `SamplingCapability` (context, tools) -- line 337-345
- `RootsCapability` (list_changed) -- line 389-394

**Missing types to add:**
- `ResourceTemplate` (uriTemplate, name, title, description, mimeType, icons)
- `ResourceIcon` (src, mimeType, sizes) -- used by Resource, Prompt, ResourceTemplate
- `PromptMessage` (role, content)
- `Root` (uri, name)
- `LoggingLevel` enum (debug, info, notice, warning, error, critical, alert, emergency)
- `ModelPreferences` (hints, costPriority, speedPriority, intelligencePriority)
- `ModelHint` (name)
- `SamplingMessage` (role, content)
- `ToolChoice` (mode: auto/required/none)

### Message Types (`src/protocol/messages.rs`)

Already has:
- `ResourcesListParams`, `ResourcesListResult` -- line 249-264
- `PromptsListParams`, `PromptsListResult` -- line 271-286

**Missing message types to add:**
- `ResourcesReadParams` (uri), `ResourcesReadResult` (contents)
- `ResourcesTemplatesListParams`, `ResourcesTemplatesListResult`
- `ResourcesSubscribeParams` (uri), `ResourcesUnsubscribeParams` (uri)
- `PromptsGetParams` (name, arguments), `PromptsGetResult` (description, messages)
- `LoggingSetLevelParams` (level)
- `ElicitationCreateParams` (mode, message, requestedSchema?, url?, elicitationId?)
- `ElicitationCreateResult` (action, content?)
- `SamplingCreateMessageParams` (messages, tools?, toolChoice?, modelPreferences?, systemPrompt?, maxTokens, ...)
- `SamplingCreateMessageResult` (role, content, model, stopReason)
- `RootsListResult` (roots)

### Router (`src/gateway/router.rs`)

The `meta_mcp_handler` function (line 248-456) routes methods via a `match` at line 363-446:
```rust
match method.as_str() {
    "initialize" => MetaMcp::handle_initialize(id, params.as_ref()),
    "tools/list" => state.meta_mcp.handle_tools_list(id),
    "tools/call" => { ... },
    "ping" => JsonRpcResponse::success(id, json!({})),
    _ => JsonRpcResponse::error(Some(id), -32601, format!("Method not found: {method}")),
}
```

**New routes to add:**
- `"resources/list"` -> aggregate from all backends
- `"resources/read"` -> route to correct backend based on URI prefix
- `"resources/templates/list"` -> aggregate from all backends
- `"resources/subscribe"` -> route to correct backend
- `"resources/unsubscribe"` -> route to correct backend
- `"prompts/list"` -> aggregate from all backends
- `"prompts/get"` -> route to correct backend based on name prefix
- `"logging/setLevel"` -> broadcast to all backends

### Meta-MCP (`src/gateway/meta_mcp.rs`)

Handles tool aggregation from backends. New handler methods will follow the same pattern.

### Initialize Result (`src/gateway/meta_mcp_helpers.rs`)

`build_initialize_result` (line 30-53) currently only advertises `tools` capability:
```rust
capabilities: ServerCapabilities {
    tools: Some(ToolsCapability { list_changed: true }),
    ..Default::default()
},
```

**Must update to also advertise:** `resources`, `prompts`, `logging`.

### Backend (`src/backend/mod.rs`)

The `Backend::request` method (line 270) is a generic JSON-RPC proxy. It already supports
forwarding **any** method to backends, so no changes are needed here. We just need to call
`backend.request("resources/list", params)` etc.

The `Backend` struct also caches tools in `tools_cache`. We should add similar caching for
resources and prompts:
- `resources_cache: RwLock<Option<Vec<Resource>>>`
- `prompts_cache: RwLock<Option<Vec<Prompt>>>`

---

## Implementation Plan

### Phase 1: Type Additions (`src/protocol/types.rs` and `src/protocol/messages.rs`)

#### New Types in `types.rs`

```rust
/// Resource template (parameterized resource with URI template)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceTemplate {
    /// URI template (RFC 6570)
    #[serde(rename = "uriTemplate")]
    pub uri_template: String,
    /// Template name
    pub name: String,
    /// Human-readable title
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Template description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// MIME type
    #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// Prompt message in a prompt response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptMessage {
    /// Role: "user" or "assistant"
    pub role: String,
    /// Content (text, image, audio, or embedded resource)
    pub content: Content,
}

/// Root definition (filesystem boundary)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Root {
    /// Root URI (must be file://)
    pub uri: String,
    /// Human-readable name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Logging level (RFC 5424 severity)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LoggingLevel {
    Debug,
    Info,
    Notice,
    Warning,
    Error,
    Critical,
    Alert,
    Emergency,
}
```

#### New Message Types in `messages.rs`

```rust
// Resources
pub struct ResourcesReadParams { pub uri: String }
pub struct ResourcesReadResult { pub contents: Vec<ResourceContents> }
pub struct ResourcesTemplatesListParams { pub cursor: Option<String> }
pub struct ResourcesTemplatesListResult { pub resource_templates: Vec<ResourceTemplate>, pub next_cursor: Option<String> }
pub struct ResourcesSubscribeParams { pub uri: String }
pub struct ResourcesUnsubscribeParams { pub uri: String }

// Prompts
pub struct PromptsGetParams { pub name: String, pub arguments: Option<HashMap<String, String>> }
pub struct PromptsGetResult { pub description: Option<String>, pub messages: Vec<PromptMessage> }

// Logging
pub struct LoggingSetLevelParams { pub level: LoggingLevel }

// Roots
pub struct RootsListResult { pub roots: Vec<Root> }
```

### Phase 2: Resources + Prompts Handler (`src/gateway/meta_mcp.rs`)

Add these methods to `MetaMcp`:

```rust
/// Handle resources/list - aggregate from all backends
pub async fn handle_resources_list(&self, id: RequestId, params: Option<&Value>) -> JsonRpcResponse

/// Handle resources/read - route to correct backend based on URI
pub async fn handle_resources_read(&self, id: RequestId, params: Option<&Value>) -> JsonRpcResponse

/// Handle resources/templates/list - aggregate from all backends
pub async fn handle_resources_templates_list(&self, id: RequestId, params: Option<&Value>) -> JsonRpcResponse

/// Handle resources/subscribe - route to correct backend
pub async fn handle_resources_subscribe(&self, id: RequestId, params: Option<&Value>) -> JsonRpcResponse

/// Handle resources/unsubscribe - route to correct backend
pub async fn handle_resources_unsubscribe(&self, id: RequestId, params: Option<&Value>) -> JsonRpcResponse

/// Handle prompts/list - aggregate from all backends
pub async fn handle_prompts_list(&self, id: RequestId, params: Option<&Value>) -> JsonRpcResponse

/// Handle prompts/get - route to correct backend based on name prefix
pub async fn handle_prompts_get(&self, id: RequestId, params: Option<&Value>) -> JsonRpcResponse
```

#### Resource URI Namespacing

To avoid collisions across backends, the gateway prefixes resource URIs:
- Backend "filesystem" with resource `file:///project/README.md`
- Gateway exposes as `gateway://filesystem/file:///project/README.md`
- On `resources/read`, gateway strips the prefix and routes to the correct backend

Alternative (simpler): Use a query param like `?backend=filesystem` or a separate params field.

**Recommended approach**: Keep URIs transparent. Backend resources already have unique URIs
in most cases. If collision detection is needed, add backend name metadata in the resource
response rather than modifying URIs. The `resources/list` response will include a
`_gateway_backend` annotation field for routing.

**Simplest approach (chosen)**: Use a routing map. When aggregating resources from backends,
store a `HashMap<String, String>` mapping `resource_uri -> backend_name`. On `resources/read`,
look up which backend owns the URI and route there.

#### Prompt Name Namespacing

Similar approach: prefix prompt names with `backend_name/` on aggregation.
- Backend "code-review" has prompt "review_code"
- Gateway exposes as "code-review/review_code"
- On `prompts/get`, split on first `/` to get backend name and original prompt name.

### Phase 3: Logging Handler

Add to `MetaMcp`:

```rust
/// Handle logging/setLevel - broadcast to all backends
pub async fn handle_logging_set_level(&self, id: RequestId, params: Option<&Value>) -> JsonRpcResponse
```

The gateway stores the current log level and forwards `logging/setLevel` to all running backends.
When backends send `notifications/message`, the gateway filters by the current level and
forwards to the client via the SSE stream (NotificationMultiplexer).

### Phase 4: Client-Side Capability Proxying (Elicitation, Sampling, Roots)

These are **server→client** requests. When a backend sends `elicitation/create`,
`sampling/createMessage`, or `roots/list`, the gateway must forward them to the
connected client.

**Implementation approach:**

The gateway already has the `NotificationMultiplexer` for SSE streaming. For these
bidirectional capabilities, we need a new mechanism:

1. **Request-response proxying**: When a backend sends a JSON-RPC request (not notification)
   to the gateway, the gateway forwards it to the client via the SSE stream and waits for
   the client's response.

2. **Session association**: Each SSE session is associated with a client. When a backend
   request comes in, we need to know which client session to forward it to.

**For v1, scope to:**
- Forward `elicitation/create`, `sampling/createMessage`, `roots/list` as notifications
  to the client (fire-and-forget via SSE).
- The client responds via POST /mcp with the response.
- The gateway matches the response ID and forwards back to the backend.

**File changes:**
- `src/gateway/streaming.rs`: Add request-response matching for proxied requests
- `src/gateway/meta_mcp.rs`: Add proxy handlers

### Phase 5: Router Wiring (`src/gateway/router.rs`)

Update the `match method.as_str()` block in `meta_mcp_handler`:

```rust
match method.as_str() {
    "initialize" => MetaMcp::handle_initialize(id, params.as_ref()),

    // Tools
    "tools/list" => state.meta_mcp.handle_tools_list(id),
    "tools/call" => { /* existing */ },

    // Resources (NEW)
    "resources/list" => state.meta_mcp.handle_resources_list(id, params.as_ref()).await,
    "resources/read" => state.meta_mcp.handle_resources_read(id, params.as_ref()).await,
    "resources/templates/list" => state.meta_mcp.handle_resources_templates_list(id, params.as_ref()).await,
    "resources/subscribe" => state.meta_mcp.handle_resources_subscribe(id, params.as_ref()).await,
    "resources/unsubscribe" => state.meta_mcp.handle_resources_unsubscribe(id, params.as_ref()).await,

    // Prompts (NEW)
    "prompts/list" => state.meta_mcp.handle_prompts_list(id, params.as_ref()).await,
    "prompts/get" => state.meta_mcp.handle_prompts_get(id, params.as_ref()).await,

    // Logging (NEW)
    "logging/setLevel" => state.meta_mcp.handle_logging_set_level(id, params.as_ref()).await,

    // Existing
    "ping" => JsonRpcResponse::success(id, json!({})),
    _ => JsonRpcResponse::error(Some(id), -32601, format!("Method not found: {method}")),
}
```

### Phase 6: Initialize Capabilities Advertisement

Update `build_initialize_result` in `src/gateway/meta_mcp_helpers.rs`:

```rust
capabilities: ServerCapabilities {
    tools: Some(ToolsCapability { list_changed: true }),
    resources: Some(ResourcesCapability {
        subscribe: true,
        list_changed: true,
    }),
    prompts: Some(PromptsCapability {
        list_changed: true,
    }),
    logging: Some(HashMap::new()),  // Empty object = logging supported
    ..Default::default()
},
```

---

## File Change Summary

### Modified Files

| File | Changes |
|------|---------|
| `src/protocol/types.rs` | Add ResourceTemplate, PromptMessage, Root, LoggingLevel types |
| `src/protocol/messages.rs` | Add ResourcesRead*, ResourcesTemplatesList*, ResourcesSubscribe*, PromptsGet*, LoggingSetLevel*, RootsListResult message types |
| `src/gateway/router.rs` | Add resources/*, prompts/*, logging/* routes to match block |
| `src/gateway/meta_mcp.rs` | Add handle_resources_*, handle_prompts_*, handle_logging_* methods |
| `src/gateway/meta_mcp_helpers.rs` | Update build_initialize_result to advertise new capabilities; add pure helper functions for resource/prompt aggregation |
| `src/backend/mod.rs` | Add resources_cache and prompts_cache fields; add get_resources() and get_prompts() methods |

### New Files

None required for Phase 1-3 (resources, prompts, logging). The existing module structure
is sufficient.

For Phase 4 (elicitation/sampling/roots proxying), if the implementation grows large enough:
- `src/gateway/proxy.rs` -- client-side capability proxying (elicitation, sampling, roots)

---

## Test Strategy

### Unit Tests

1. **Type serialization/deserialization** (`src/protocol/`):
   - Round-trip tests for all new types (ResourceTemplate, PromptMessage, Root, LoggingLevel)
   - Test serde rename attributes (uriTemplate, mimeType, listChanged, etc.)
   - Test optional field skipping

2. **Helper functions** (`src/gateway/meta_mcp_helpers.rs`):
   - Test `build_initialize_result` includes new capabilities
   - Test resource URI routing (extract backend name from resource map)
   - Test prompt name namespacing (split on `/`)
   - Test logging level ordering/filtering

3. **Router parsing** (`src/gateway/router.rs`):
   - Test parse_request for new method names
   - Test notification handling for resources/prompts/logging notifications

### Integration Tests

4. **Resources aggregation** (`tests/`):
   - Mock two backends with different resources
   - Call resources/list, verify aggregation
   - Call resources/read with specific URI, verify routing to correct backend
   - Call resources/templates/list, verify aggregation

5. **Prompts aggregation** (`tests/`):
   - Mock two backends with different prompts
   - Call prompts/list, verify aggregation with name prefixing
   - Call prompts/get with prefixed name, verify routing and prefix stripping

6. **Logging** (`tests/`):
   - Call logging/setLevel, verify forwarded to backends
   - Verify log level filtering on notifications

### Property Tests

7. **Resource URI handling**:
   - Property: any valid URI can be stored and retrieved via the routing map
   - Property: prompt name namespacing is reversible (prefix then strip)

---

## Priority Order

1. **P0**: Resources (resources/list, resources/read) + Prompts (prompts/list, prompts/get)
   - These are the most commonly used missing capabilities
   - Required for MCP spec compliance

2. **P1**: Logging (logging/setLevel) + Resource Templates
   - Logging is simple to implement
   - Templates are a natural extension of resources

3. **P2**: Resource subscriptions (resources/subscribe, resources/unsubscribe)
   - Requires notification forwarding infrastructure

4. **P3**: Client-side proxying (elicitation, sampling, roots)
   - Complex bidirectional request-response proxying
   - Can be deferred to a follow-up issue

---

## Notifications Forwarding

The gateway already has `NotificationMultiplexer` in `src/gateway/streaming.rs` that handles
SSE streaming of notifications from backends to clients. The following notifications need
to be recognized and forwarded:

| Notification | Source | Action |
|-------------|--------|--------|
| `notifications/resources/list_changed` | Backend | Forward to all connected clients |
| `notifications/resources/updated` | Backend | Forward to subscribed clients |
| `notifications/prompts/list_changed` | Backend | Forward to all connected clients |
| `notifications/message` | Backend | Filter by log level, forward to client |
| `notifications/roots/list_changed` | Client | Forward to all backends |
| `notifications/elicitation/complete` | Backend | Forward to requesting client |

The multiplexer already forwards all notifications. We may need to add log level filtering
for `notifications/message`.

---

## Estimated Scope

| Phase | Effort | Files Changed | New Lines |
|-------|--------|---------------|-----------|
| Phase 1: Types | Small | 2 | ~150 |
| Phase 2: Resources + Prompts | Medium | 3 | ~400 |
| Phase 3: Logging | Small | 2 | ~80 |
| Phase 4: Client proxying | Large | 3 | ~300 |
| Phase 5: Router wiring | Small | 1 | ~30 |
| Phase 6: Initialize caps | Trivial | 1 | ~10 |
| Tests | Medium | 3-4 | ~500 |
| **Total** | | **~10 files** | **~1,500 lines** |
