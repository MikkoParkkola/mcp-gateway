# MCP Gateway

[![PyPI version](https://badge.fury.io/py/mcp-gateway.svg)](https://badge.fury.io/py/mcp-gateway)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Universal Model Context Protocol (MCP) Gateway** - Single-port multiplexing with Meta-MCP for ~95% context token savings.

## The Problem

MCP is powerful, but scaling to many servers creates problems:

| Without Gateway | With Gateway |
|----------------|--------------|
| 100+ tool definitions in context | 4 meta-tools |
| ~15,000 tokens overhead | ~400 tokens |
| Multiple ports to manage | Single port |
| Session loss on reconnect | Persistent proxy |

## The Solution

```
┌─────────────────────────────────────────────────────────────────┐
│                     MCP Gateway (:39400)                         │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  Meta-MCP Mode: 4 Tools → Access 100+ Tools Dynamically  │    │
│  │  • gateway_list_servers    • gateway_search_tools        │    │
│  │  • gateway_list_tools      • gateway_invoke              │    │
│  └─────────────────────────────────────────────────────────┘    │
│                              │                                   │
│         ┌────────────────────┼────────────────────┐             │
│         ▼                    ▼                    ▼             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │   Tavily    │    │  Context7   │    │   Pieces    │         │
│  │  (stdio)    │    │   (http)    │    │   (sse)     │         │
│  └─────────────┘    └─────────────┘    └─────────────┘         │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Installation

```bash
pip install mcp-gateway
```

### Basic Usage

```bash
# Start with configuration file
mcp-gateway --config servers.yaml --port 39400
```

### Configuration

Create `servers.yaml`:

```yaml
port: 39400
enable_meta_mcp: true

backends:
  tavily:
    command: "npx -y @anthropic/mcp-server-tavily"
    description: "Web search"
    env:
      TAVILY_API_KEY: "${TAVILY_API_KEY}"

  context7:
    http_url: "http://localhost:8080/mcp"
    description: "Documentation lookup"

  pieces:
    http_url: "http://localhost:39300/sse"
    description: "Long-term memory"
```

### Client Configuration

Point your MCP client to the gateway:

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

## Features

### Meta-MCP Mode (~95% Token Savings)

Instead of loading 100+ tool definitions, Meta-MCP exposes 4 meta-tools:

| Meta-Tool | Purpose |
|-----------|---------|
| `gateway_list_servers` | List available backends |
| `gateway_list_tools` | List tools from a specific backend |
| `gateway_search_tools` | Search tools by keyword across all backends |
| `gateway_invoke` | Invoke any tool on any backend |

**Token Math:**
- Traditional: 100 tools × 150 tokens = 15,000 tokens
- Meta-MCP: 4 tools × 100 tokens = 400 tokens
- **Savings: 97%**

### Transport Support

| Transport | Description | Example |
|-----------|-------------|---------|
| **stdio** | Subprocess with JSON-RPC | `command: "npx server"` |
| **http** | HTTP POST | `http_url: "http://localhost:8080/mcp"` |
| **sse** | Server-Sent Events | `http_url: "http://localhost:8080/sse"` |

### Operational Features

- **Lazy Loading**: Backends start on first access
- **Idle Timeout**: Hibernate unused backends (configurable)
- **Auto-Reconnect**: Survives client context compaction
- **Health Aggregation**: Single `/health` endpoint
- **Tool Caching**: Cached for session persistence

## API Reference

### HTTP Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check with backend status |
| `POST /mcp` | Meta-MCP mode (dynamic discovery) |
| `POST /mcp/{backend}` | Direct backend access |

### Environment Variables

Configuration values support environment variable expansion:

```yaml
backends:
  tavily:
    command: "npx -y @anthropic/mcp-server-tavily"
    env:
      TAVILY_API_KEY: "${TAVILY_API_KEY}"  # Expanded at runtime
```

### CLI Options

```
mcp-gateway [OPTIONS]

Options:
  -c, --config PATH       YAML configuration file
  -p, --port PORT         Port to listen on (default: 39400)
  --host HOST             Host to bind to (default: 127.0.0.1)
  --log-level LEVEL       DEBUG, INFO, WARNING, ERROR
  --no-meta-mcp           Disable Meta-MCP mode
  --version               Show version
  --help                  Show help
```

## Programmatic Usage

```python
import asyncio
from mcp_gateway import Gateway, GatewayConfig, BackendConfig

# Create configuration
config = GatewayConfig(
    port=39400,
    enable_meta_mcp=True,
    backends={
        "tavily": BackendConfig(
            name="tavily",
            command="npx -y @anthropic/mcp-server-tavily",
            description="Web search",
        )
    }
)

# Or load from YAML
config = GatewayConfig.from_yaml("servers.yaml")

# Create and run gateway
gateway = Gateway(config)
asyncio.run(gateway.run())
```

## Production Deployment

### systemd Service

```ini
[Unit]
Description=MCP Gateway
After=network.target

[Service]
Type=simple
User=mcp
ExecStart=/usr/local/bin/mcp-gateway --config /etc/mcp-gateway/servers.yaml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### macOS launchd

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.mcp.gateway</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/mcp-gateway</string>
        <string>--config</string>
        <string>/etc/mcp-gateway/servers.yaml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

### Docker

```dockerfile
FROM python:3.12-slim

RUN pip install mcp-gateway

COPY servers.yaml /etc/mcp-gateway/
EXPOSE 39400

CMD ["mcp-gateway", "--config", "/etc/mcp-gateway/servers.yaml", "--host", "0.0.0.0"]
```

## Metrics & Monitoring

### Health Endpoint

```bash
curl http://localhost:39400/health
```

```json
{
  "status": "healthy",
  "backends": {
    "tavily": {
      "running": true,
      "restart_count": 1,
      "tools_cached": 3
    }
  }
}
```

### Prometheus Metrics (Optional)

Install with metrics support:

```bash
pip install mcp-gateway[metrics]
```

## Troubleshooting

### Backend Won't Start

1. Check the command is correct: `npx -y @package/name`
2. Verify environment variables are set
3. Check logs with `--log-level DEBUG`

### Tool Not Found

1. Use `gateway_search_tools` to verify tool exists
2. Check backend is running: `gateway_list_servers`
3. Verify backend has started: check `/health`

### Session Issues

The gateway caches tool lists on startup. If a backend restarts:

1. Tools are re-cached automatically
2. Check `restart_count` in health endpoint

## Contributing

```bash
git clone https://github.com/MikkoParkkola/mcp-gateway
cd mcp-gateway
pip install -e ".[dev]"
pytest
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Credits

Created by [Mikko Parkkola](https://github.com/MikkoParkkola)

Inspired by the need to scale MCP beyond a handful of servers without drowning in context tokens.
