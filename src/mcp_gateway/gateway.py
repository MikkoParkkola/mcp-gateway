"""
Main Gateway server - HTTP multiplexer for MCP backends.

Features:
    - Path-based routing: /mcp/{backend_name}
    - Meta-MCP mode: /mcp with dynamic tool discovery
    - Health aggregation: /health
    - Lazy loading with idle timeout
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import TYPE_CHECKING, Any

from aiohttp import web

from mcp_gateway.backend import MCPBackend

if TYPE_CHECKING:
    from mcp_gateway.config import GatewayConfig

logger = logging.getLogger(__name__)


class Gateway:
    """Universal MCP Gateway server.

    Provides:
        - Single-port multiplexing for multiple MCP backends
        - Meta-MCP mode with 4 meta-tools for ~95% token savings
        - Automatic session management and reconnection
        - Health monitoring and idle timeout

    Example:
        >>> config = GatewayConfig.from_yaml("servers.yaml")
        >>> gateway = Gateway(config)
        >>> await gateway.run()
    """

    def __init__(self, config: GatewayConfig) -> None:
        """Initialize the gateway.

        Args:
            config: Gateway configuration
        """
        self.config = config
        self.backends: dict[str, MCPBackend] = {}
        self._running = False
        self._background_tasks: set[asyncio.Task[None]] = set()

        # Initialize backends from config
        for name, backend_config in config.get_enabled_backends().items():
            self.backends[name] = MCPBackend(config=backend_config)

    async def start(self) -> None:
        """Start the gateway server."""
        self._running = True

        # Start background tasks
        task = asyncio.create_task(self._idle_checker())
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

        logger.info("=" * 60)
        logger.info("MCP GATEWAY v1.0")
        logger.info("=" * 60)
        logger.info(f"Port: {self.config.port}")
        logger.info(f"Backends: {len(self.backends)}")
        logger.info("")

        if self.config.enable_meta_mcp:
            logger.info("META-MCP (saves ~95% context tokens):")
            logger.info(f"  http://localhost:{self.config.port}/mcp")
            logger.info("")

        logger.info("Direct backend access:")
        for name in self.backends:
            logger.info(f"  /mcp/{name}")

        logger.info("=" * 60)

    async def stop(self) -> None:
        """Stop the gateway and all backends."""
        self._running = False
        for backend in self.backends.values():
            await backend.stop()
        logger.info("Gateway stopped")

    async def _idle_checker(self) -> None:
        """Background task to hibernate idle backends."""
        while self._running:
            await asyncio.sleep(60)
            now = time.time()

            for backend in self.backends.values():
                if backend.is_running:
                    idle_time = now - backend.last_used
                    if idle_time > backend.config.idle_timeout:
                        logger.info(f"[{backend.name}] Hibernating (idle {idle_time:.0f}s)")
                        await backend.stop()

    def create_app(self) -> web.Application:
        """Create the aiohttp web application."""
        app = web.Application()

        # Routes
        app.router.add_get("/health", self._handle_health)
        app.router.add_route("*", "/mcp", self._handle_meta_mcp)
        app.router.add_route("*", "/mcp/{name:.*}", self._handle_mcp)

        # Lifecycle
        app.on_startup.append(lambda _: self.start())
        app.on_cleanup.append(lambda _: self.stop())

        return app

    async def run(self) -> None:
        """Run the gateway server."""
        app = self.create_app()
        runner = web.AppRunner(app)
        await runner.setup()

        site = web.TCPSite(runner, self.config.host, self.config.port)
        await site.start()

        logger.info(f"Gateway running on http://{self.config.host}:{self.config.port}")

        # Keep running until interrupted
        try:
            while True:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            pass
        finally:
            await runner.cleanup()

    # =========================================================================
    # HTTP Handlers
    # =========================================================================

    async def _handle_health(self, _request: web.Request) -> web.Response:
        """Health check endpoint."""
        backends_status: dict[str, dict[str, Any]] = {}

        for name, backend in self.backends.items():
            backends_status[name] = {
                "running": backend.is_running,
                "restart_count": backend.restart_count,
                "tools_cached": len(backend.get_cached_tools()),
            }

        status = {
            "status": "healthy",
            "backends": backends_status,
        }

        return web.json_response(status)

    async def _handle_mcp(self, request: web.Request) -> web.Response:
        """Handle requests to specific backend: /mcp/{name}"""
        name = request.match_info.get("name", "")

        # Handle Meta-MCP at /mcp (no backend name)
        if not name:
            return await self._handle_meta_mcp(request)

        # Find backend
        backend = self.backends.get(name)
        if not backend:
            return web.json_response(
                {
                    "jsonrpc": "2.0",
                    "error": {"code": -32001, "message": f"Unknown backend: {name}"},
                    "id": None,
                },
                status=404,
            )

        # Ensure backend is started
        if not await backend.start():
            return web.json_response(
                {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32000,
                        "message": f"Backend unavailable: {name}",
                    },
                    "id": None,
                },
                status=503,
            )

        # Forward request
        try:
            body = await request.json()
            response = await backend.send_request(body)
            return web.json_response(response)
        except json.JSONDecodeError:
            return web.json_response(
                {
                    "jsonrpc": "2.0",
                    "error": {"code": -32700, "message": "Parse error"},
                    "id": None,
                },
                status=400,
            )

    async def _handle_meta_mcp(self, request: web.Request) -> web.Response:
        """Handle Meta-MCP requests at /mcp.

        Meta-MCP provides 4 meta-tools for dynamic discovery:
            - gateway_list_servers: List available backends
            - gateway_list_tools: List tools from a specific backend
            - gateway_search_tools: Search tools across all backends
            - gateway_invoke: Invoke a tool on any backend
        """
        if not self.config.enable_meta_mcp:
            return web.json_response(
                {"error": "Meta-MCP disabled"},
                status=403,
            )

        try:
            body = await request.json()
        except json.JSONDecodeError:
            return web.json_response(
                {
                    "jsonrpc": "2.0",
                    "error": {"code": -32700, "message": "Parse error"},
                    "id": None,
                },
                status=400,
            )

        method = body.get("method", "")
        request_id = body.get("id")

        # Route to appropriate handler
        if method == "initialize":
            return web.json_response(self._meta_initialize(request_id))
        elif method == "tools/list":
            return web.json_response(await self._meta_tools_list(request_id))
        elif method == "tools/call":
            return web.json_response(await self._meta_tools_call(body, request_id))
        elif method.startswith("notifications/"):
            return web.json_response({"jsonrpc": "2.0", "result": None, "id": request_id})
        else:
            return web.json_response(
                {
                    "jsonrpc": "2.0",
                    "error": {"code": -32601, "message": f"Unknown method: {method}"},
                    "id": request_id,
                }
            )

    # =========================================================================
    # Meta-MCP Implementation
    # =========================================================================

    def _meta_initialize(self, request_id: Any) -> dict[str, Any]:
        """Handle MCP initialize for Meta-MCP mode."""
        return {
            "jsonrpc": "2.0",
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": "mcp-gateway",
                    "version": "1.0.0",
                    "description": "Universal MCP Gateway with Meta-MCP for dynamic tool discovery",
                },
            },
            "id": request_id,
        }

    async def _meta_tools_list(self, request_id: Any) -> dict[str, Any]:
        """Return the 4 meta-tools for dynamic discovery."""
        tools = [
            {
                "name": "gateway_list_servers",
                "description": "List all available MCP backend servers",
                "inputSchema": {"type": "object", "properties": {}, "required": []},
            },
            {
                "name": "gateway_list_tools",
                "description": "List all tools from a specific backend server",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "server": {
                            "type": "string",
                            "description": "Name of the backend server",
                        }
                    },
                    "required": ["server"],
                },
            },
            {
                "name": "gateway_search_tools",
                "description": "Search for tools across all backends by keyword",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Search keyword",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Max results (default 10)",
                            "default": 10,
                        },
                    },
                    "required": ["query"],
                },
            },
            {
                "name": "gateway_invoke",
                "description": "Invoke a tool on a specific backend",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "server": {
                            "type": "string",
                            "description": "Backend server name",
                        },
                        "tool": {
                            "type": "string",
                            "description": "Tool name to invoke",
                        },
                        "arguments": {
                            "type": "object",
                            "description": "Tool arguments",
                            "default": {},
                        },
                    },
                    "required": ["server", "tool"],
                },
            },
        ]

        return {
            "jsonrpc": "2.0",
            "result": {"tools": tools},
            "id": request_id,
        }

    async def _meta_tools_call(self, body: dict[str, Any], request_id: Any) -> dict[str, Any]:
        """Handle tool invocations for meta-tools."""
        params = body.get("params", {})
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        if tool_name == "gateway_list_servers":
            return await self._call_list_servers(request_id)
        elif tool_name == "gateway_list_tools":
            return await self._call_list_tools(arguments, request_id)
        elif tool_name == "gateway_search_tools":
            return await self._call_search_tools(arguments, request_id)
        elif tool_name == "gateway_invoke":
            return await self._call_invoke(arguments, request_id)
        else:
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"},
                "id": request_id,
            }

    async def _call_list_servers(self, request_id: Any) -> dict[str, Any]:
        """List all available backend servers."""
        servers = []

        for name, backend in self.backends.items():
            servers.append(
                {
                    "name": name,
                    "description": backend.config.description,
                    "transport": backend.config.transport_type,
                    "running": backend.is_running,
                    "tools_count": len(backend.get_cached_tools()),
                }
            )

        return {
            "jsonrpc": "2.0",
            "result": {
                "content": [{"type": "text", "text": json.dumps({"servers": servers}, indent=2)}]
            },
            "id": request_id,
        }

    async def _call_list_tools(self, arguments: dict[str, Any], request_id: Any) -> dict[str, Any]:
        """List tools from a specific backend."""
        server_name = arguments.get("server")
        if not server_name:
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32602, "message": "Missing 'server' parameter"},
                "id": request_id,
            }

        backend = self.backends.get(server_name)
        if not backend:
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32001, "message": f"Unknown server: {server_name}"},
                "id": request_id,
            }

        # Ensure backend is started to get tools
        await backend.start()
        tools = backend.get_cached_tools()

        return {
            "jsonrpc": "2.0",
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps({"server": server_name, "tools": tools}, indent=2),
                    }
                ]
            },
            "id": request_id,
        }

    async def _call_search_tools(
        self, arguments: dict[str, Any], request_id: Any
    ) -> dict[str, Any]:
        """Search tools across all backends."""
        query = arguments.get("query", "").lower()
        limit = arguments.get("limit", 10)

        if not query:
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32602, "message": "Missing 'query' parameter"},
                "id": request_id,
            }

        matches = []

        for name, backend in self.backends.items():
            await backend.start()
            for tool in backend.get_cached_tools():
                tool_name = tool.get("name", "")
                tool_desc = tool.get("description", "")

                if query in tool_name.lower() or query in tool_desc.lower():
                    matches.append(
                        {
                            "server": name,
                            "tool": tool_name,
                            "description": tool_desc[:200],  # Truncate
                        }
                    )

                if len(matches) >= limit:
                    break

            if len(matches) >= limit:
                break

        return {
            "jsonrpc": "2.0",
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {"query": query, "matches": matches, "total": len(matches)},
                            indent=2,
                        ),
                    }
                ]
            },
            "id": request_id,
        }

    async def _call_invoke(self, arguments: dict[str, Any], request_id: Any) -> dict[str, Any]:
        """Invoke a tool on a specific backend."""
        server_name = arguments.get("server")
        tool_name = arguments.get("tool")
        tool_args = arguments.get("arguments", {})

        if not server_name:
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32602, "message": "Missing 'server' parameter"},
                "id": request_id,
            }

        if not tool_name:
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32602, "message": "Missing 'tool' parameter"},
                "id": request_id,
            }

        backend = self.backends.get(server_name)
        if not backend:
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32001, "message": f"Unknown server: {server_name}"},
                "id": request_id,
            }

        # Forward the tool call to the backend
        call_request = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": request_id,
            "params": {
                "name": tool_name,
                "arguments": tool_args,
            },
        }

        return await backend.send_request(call_request)
