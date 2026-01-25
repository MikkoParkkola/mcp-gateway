# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2025-01-24

### Added

- Initial release of MCP Gateway
- **Meta-MCP Mode**: 4 meta-tools for dynamic tool discovery with ~95% token savings
  - `gateway_list_servers`: List available backend servers
  - `gateway_list_tools`: List tools from a specific backend
  - `gateway_search_tools`: Search tools across all backends
  - `gateway_invoke`: Invoke any tool on any backend
- **Transport Support**:
  - stdio: Subprocess with JSON-RPC over stdin/stdout
  - HTTP: Streamable HTTP POST
  - SSE: Server-Sent Events with session management
- **Operational Features**:
  - Lazy loading: Backends start on first access
  - Idle timeout: Automatic hibernation of unused backends
  - Tool caching: Cached tool lists for performance
  - Auto-reconnect: Survives client context compaction
  - Health aggregation: Single `/health` endpoint
- **Configuration**:
  - YAML-based configuration with environment variable expansion
  - Pydantic validation for type safety
  - Command-line overrides for all settings
- **Production Ready**:
  - systemd service template
  - macOS launchd plist template
  - Docker support
  - Comprehensive test suite
  - Full type annotations

[Unreleased]: https://github.com/MikkoParkkola/mcp-gateway/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/MikkoParkkola/mcp-gateway/releases/tag/v1.0.0
