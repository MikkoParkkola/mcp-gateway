# MCP Gateway in 5 Minutes

Get from zero to a working gateway with tools your AI can use.

## Prerequisites

- **Rust toolchain** (1.85+): [rustup.rs](https://rustup.rs)

## 1. Install

```bash
cargo install mcp-gateway
```

Or via Homebrew (macOS/Linux):

```bash
brew tap MikkoParkkola/tap
brew install mcp-gateway
```

## 2. Create a Config

Save this as `gateway.yaml`:

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

## 3. Add Capabilities

Create a `capabilities/` directory and add two free capabilities (no API keys needed):

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
INFO  mcp_gateway: Meta-MCP enabled (4 meta-tools)
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

## 6. Connect to Claude Desktop

Add this to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

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

Restart Claude Desktop. You now have access to all gateway tools via the 4 meta-tools.

See [examples/claude-desktop.json](../examples/claude-desktop.json) for a full example config.

## Next Steps

- **Add more capabilities**: Copy any YAML from the `capabilities/` directory that ships with the gateway. 25+ work with zero config.
- **Add MCP server backends**: Point `backends:` at existing MCP servers (stdio, HTTP, or SSE).
- **Enable caching**: Add `cache: { enabled: true, default_ttl: 60s }` to your config.
- **Enable auth**: Add `auth: { enabled: true, bearer_token: "auto" }` for token-based access control.
- **Install from registry**: Run `mcp-gateway cap search finance` and `mcp-gateway cap install stock_quote`.
- **Full config reference**: See the [README](../README.md#configuration-reference) or [examples/gateway-full.yaml](../examples/gateway-full.yaml).
