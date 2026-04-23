# MCP Gateway in 2 Minutes

Get from zero to a working gateway with tools your AI can use.

## The fast way (recommended)

```bash
brew install MikkoParkkola/tap/mcp-gateway   # 1. install
mcp-gateway setup wizard --configure-client  # 2. import existing servers + wire up clients
mcp-gateway serve                            # 3. run
mcp-gateway doctor                           # 4. verify
```

The wizard scans Claude Desktop, Claude Code, Cursor, Windsurf, Zed, Continue.dev, and Codex for existing MCP servers, imports them into `gateway.yaml`, and writes the gateway entry back into each client. Done.

> **Nothing to import yet?** `mcp-gateway init --with-examples` writes a starter `gateway.yaml` with free capabilities (weather, Wikipedia) so you can confirm the gateway works.

## The manual way (learn what's happening)

<details>
<summary>Step-by-step setup with explanation</summary>

### Prerequisites

- **Rust toolchain** (1.88+): [rustup.rs](https://rustup.rs), or use Homebrew

### 1. Install

```bash
# Homebrew (macOS/Linux, recommended)
brew install MikkoParkkola/tap/mcp-gateway

# Or from crates.io
cargo install mcp-gateway
```

### 2. Create a Config

```bash
mcp-gateway init --with-examples
```

This writes `gateway.yaml` with sensible defaults and two free capabilities. Or create it manually:

```yaml
server:
  port: 39400

meta_mcp:
  enabled: true

capabilities:
  enabled: true
  directories:
    - ./capabilities

backends: {}
```

### 3. Add Capabilities

The `init --with-examples` command creates these automatically. If you're writing config by hand, create a `capabilities/` directory and add capability YAML files (no API keys needed):

**capabilities/weather.yaml**
```yaml
fulcrum: "1.0"
name: weather
description: Get current weather for a location (free, no API key)

schema:
  input:
    type: object
    properties:
      latitude:
        type: number
        description: Latitude coordinate
      longitude:
        type: number
        description: Longitude coordinate
    required: [latitude, longitude]

providers:
  primary:
    service: rest
    cost_per_call: 0
    config:
      base_url: https://api.open-meteo.com
      path: /v1/forecast
      method: GET
      params:
        latitude: "{latitude}"
        longitude: "{longitude}"
        current_weather: "true"
      response_path: current_weather

cache:
  strategy: exact
  ttl: 300

auth:
  required: false

metadata:
  category: weather
  tags: [weather, forecast, free]
```

**capabilities/wikipedia.yaml**
```yaml
fulcrum: "1.0"
name: wikipedia_summary
description: Get a Wikipedia article summary (free, no API key)

schema:
  input:
    type: object
    properties:
      title:
        type: string
        description: Article title (use underscores for spaces, e.g. "Albert_Einstein")
    required: [title]

providers:
  primary:
    service: rest
    cost_per_call: 0
    config:
      base_url: https://en.wikipedia.org
      path: /api/rest_v1/page/summary/{title}
      method: GET
      headers:
        Accept: "application/json"

cache:
  strategy: exact
  ttl: 86400

auth:
  required: false

metadata:
  category: knowledge
  tags: [wikipedia, encyclopedia, free]
```

## 4. Start the Gateway

```bash
mcp-gateway --config gateway.yaml
```

You should see:

```
INFO  mcp_gateway: Starting MCP Gateway on 127.0.0.1:39400
INFO  mcp_gateway: Meta-MCP enabled (compact gateway tool surface)
INFO  mcp_gateway: Loaded 2 capabilities
```

## 5. Test It

Search for tools:

```bash
curl -s http://localhost:39400/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "gateway_search_tools",
      "arguments": { "query": "weather" }
    }
  }' | python3 -m json.tool
```

Invoke the weather tool:

```bash
curl -s http://localhost:39400/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "gateway_invoke",
      "arguments": {
        "server": "fulcrum",
        "tool": "weather",
        "arguments": { "latitude": 60.17, "longitude": 24.94 }
      }
    }
  }' | python3 -m json.tool
```

### 6. Connect to your AI client

```bash
mcp-gateway setup export --target all          # auto-write to all detected clients
mcp-gateway setup export --target claude-code  # or a specific client
mcp-gateway setup export --target all --dry-run  # preview first
```

Or manually — add to your client config:

```json
{
  "mcpServers": {
    "gateway": {
      "type": "http",
      "url": "http://localhost:39400/mcp"
    }
  }
}
```

Restart your client. The gateway's compact Meta-MCP surface (12-15 tools) replaces every backend tool definition.

See [examples/claude-desktop.json](../examples/claude-desktop.json) for a full example config.

</details>

## Next Steps

- **Add more backends**: `mcp-gateway add tavily` (48 servers in the built-in registry). Or `mcp-gateway add my-server -- npx -y @some/mcp-server`.
- **Add more capabilities**: Copy any YAML from the `capabilities/` directory that ships with the gateway. 110+ work with zero config.
- **Import OpenAPI specs**: `mcp-gateway cap import stripe-openapi.yaml --output capabilities/`
- **Add remote backends**: For a zero-auth remote backend you can try in seconds, see [Adding remote MCP backends](REMOTE_BACKENDS.md).
- **Enable caching**: Add `cache: { enabled: true, default_ttl: 60s }` to your config.
- **Enable auth**: Add `auth: { enabled: true, bearer_token: "auto" }` for token-based access control.
- **Install from registry**: Run `mcp-gateway cap search finance` and `mcp-gateway cap install stock_quote`.
- **Check health**: `mcp-gateway doctor` diagnoses config, port, env vars, and backend status. `mcp-gateway doctor --fix` auto-fixes where possible.
- **Full config reference**: See the [README](../README.md) or [examples/gateway-full.yaml](../examples/gateway-full.yaml).
