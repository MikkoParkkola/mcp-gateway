"""
MCP Gateway - Universal Model Context Protocol Multiplexer
==========================================================

A production-grade gateway that multiplexes multiple MCP servers through a single HTTP endpoint,
with Meta-MCP mode for ~95% context token savings.

Features:
    - Single-port multiplexing for all MCP backends
    - Meta-MCP mode: 4 meta-tools instead of 100+ individual tools
    - Lazy loading: servers start on first access
    - Idle timeout: hibernate unused servers
    - Auto-reconnect: survives client context compaction
    - Health aggregation: single /health endpoint
    - Hot reload: add/remove servers without restart

Example:
    >>> from mcp_gateway import Gateway, GatewayConfig
    >>> config = GatewayConfig.from_yaml("servers.yaml")
    >>> gateway = Gateway(config)
    >>> await gateway.run()

Or via CLI:
    $ mcp-gateway --config servers.yaml --port 39400
"""

from mcp_gateway.config import BackendConfig, GatewayConfig
from mcp_gateway.gateway import Gateway
from mcp_gateway.version import __version__

__all__ = [
    "BackendConfig",
    "Gateway",
    "GatewayConfig",
    "__version__",
]
