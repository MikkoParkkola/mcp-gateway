"""
MCP Backend management - handles communication with individual MCP servers.

Supports three transport types:
    - stdio: Subprocess with JSON-RPC over stdin/stdout
    - http: HTTP POST with JSON-RPC
    - sse: Server-Sent Events with session management
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import aiohttp

if TYPE_CHECKING:
    from mcp_gateway.config import BackendConfig

logger = logging.getLogger(__name__)


@dataclass
class MCPBackend:
    """Manages connection to a single MCP backend server.

    Handles:
        - Process lifecycle for stdio backends
        - Session management for HTTP/SSE backends
        - Tool caching for performance
        - Automatic reconnection
    """

    config: BackendConfig

    # Runtime state
    process: subprocess.Popen[bytes] | None = None
    last_used: float = field(default_factory=time.time)
    restart_count: int = 0

    # Session state
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    _initialized: bool = False
    _tools_cache: dict[str, Any] | None = None
    _http_session_id: str | None = None
    _sse_message_url: str | None = None

    @property
    def name(self) -> str:
        """Backend name from config."""
        return self.config.name

    @property
    def is_http(self) -> bool:
        """Check if this is an HTTP/SSE backend."""
        return self.config.http_url is not None

    @property
    def is_running(self) -> bool:
        """Check if backend is currently running."""
        if self.is_http:
            return self._initialized
        return self.process is not None and self.process.poll() is None

    async def start(self) -> bool:
        """Start the backend if not running.

        For stdio backends, spawns the subprocess.
        For HTTP backends, initializes the session.

        Returns:
            True if backend is ready, False on failure
        """
        if self.is_http:
            if not self._initialized:
                return await self._init_http_session()
            return True

        return await self._start_stdio()

    async def _start_stdio(self) -> bool:
        """Start stdio subprocess backend."""
        async with self._lock:
            if self.process and self.process.poll() is None:
                return True

            command = self.config.command_list
            if not command:
                logger.error(f"[{self.name}] No command configured")
                return False

            try:
                logger.info(f"[{self.name}] Starting: {' '.join(command)}")

                # Build environment
                proc_env = os.environ.copy()
                proc_env.update(self.config.env)

                # Resolve working directory
                cwd = Path(self.config.cwd).expanduser() if self.config.cwd else None

                self.process = subprocess.Popen(
                    command,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    bufsize=0,
                    env=proc_env,
                    cwd=cwd,
                )
                self.restart_count += 1
                self.last_used = time.time()
                self._initialized = False

                logger.info(f"[{self.name}] Started (PID: {self.process.pid})")

                # Perform MCP handshake
                await self._mcp_handshake_stdio()
                return True

            except Exception as e:
                logger.error(f"[{self.name}] Failed to start: {e}")
                return False

    async def _mcp_handshake_stdio(self) -> None:
        """Perform MCP initialize handshake for stdio backend."""
        if not self.process or not self.process.stdin or not self.process.stdout:
            return

        try:
            init_request = {
                "jsonrpc": "2.0",
                "method": "initialize",
                "id": 0,
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "mcp-gateway", "version": "1.0"},
                },
            }

            # Send initialize
            self.process.stdin.write((json.dumps(init_request) + "\n").encode())
            self.process.stdin.flush()

            # Wait for response
            import select

            ready, _, _ = select.select([self.process.stdout], [], [], 5.0)
            if ready:
                response = self.process.stdout.readline()
                if response:
                    logger.info(f"[{self.name}] MCP initialized")
                    self._initialized = True

                    # Cache tools/list
                    await self._fetch_tools_stdio()

        except Exception as e:
            logger.warning(f"[{self.name}] MCP handshake failed: {e}")

    async def _fetch_tools_stdio(self) -> None:
        """Fetch and cache tools/list for stdio backend."""
        if not self.process or not self.process.stdin or not self.process.stdout:
            return

        try:
            tools_request = {"jsonrpc": "2.0", "method": "tools/list", "id": 1}
            self.process.stdin.write((json.dumps(tools_request) + "\n").encode())
            self.process.stdin.flush()

            import select

            ready, _, _ = select.select([self.process.stdout], [], [], 5.0)
            if ready:
                response = self.process.stdout.readline()
                if response:
                    result = json.loads(response.decode())
                    if "result" in result:
                        self._tools_cache = result
                        tool_count = len(result.get("result", {}).get("tools", []))
                        logger.info(f"[{self.name}] Cached {tool_count} tools")

        except Exception as e:
            logger.warning(f"[{self.name}] Failed to cache tools: {e}")

    async def _init_http_session(self) -> bool:
        """Initialize HTTP or SSE session."""
        if self.config.http_url and self.config.http_url.endswith("/sse"):
            return await self._init_sse_session()
        return await self._init_streamable_http()

    async def _init_streamable_http(self) -> bool:
        """Initialize Streamable HTTP transport."""
        try:
            logger.info(f"[{self.name}] Initializing HTTP session...")

            init_request = {
                "jsonrpc": "2.0",
                "method": "initialize",
                "id": 0,
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "mcp-gateway", "version": "1.0"},
                },
            }

            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                **self.config.headers,
            }

            async with (
                aiohttp.ClientSession() as session,
                session.post(
                    self.config.http_url,  # type: ignore
                    json=init_request,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp,
            ):
                if resp.status == 200:
                    if "mcp-session-id" in resp.headers:
                        self._http_session_id = resp.headers["mcp-session-id"]
                        logger.info(f"[{self.name}] Session: {self._http_session_id}")

                    await self._fetch_tools_http()
                    self._initialized = True
                    return True
                else:
                    # Some servers don't need sessions
                    self._initialized = True
                    return True

        except Exception as e:
            logger.warning(f"[{self.name}] HTTP init failed: {e}")
            self._initialized = True  # Continue anyway
            return True

    async def _init_sse_session(self) -> bool:
        """Initialize MCP SSE transport.

        Protocol:
        1. GET /sse -> receive 'endpoint' event with message URL
        2. POST to that endpoint with JSON-RPC requests
        """
        try:
            logger.info(f"[{self.name}] Initializing SSE session...")
            base_url = self.config.http_url.rsplit("/sse", 1)[0]  # type: ignore

            async with (
                aiohttp.ClientSession() as session,
                session.get(
                    self.config.http_url,  # type: ignore
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp,
            ):
                if resp.status != 200:
                    logger.error(f"[{self.name}] SSE connect failed: {resp.status}")
                    return False

                # Read SSE stream to get endpoint
                async for line in resp.content:
                    decoded = line.decode().strip()
                    if decoded.startswith("data: ") and "/message" in decoded:
                        data = decoded[6:]
                        self._sse_message_url = f"{base_url}{data}"
                        logger.info(f"[{self.name}] SSE endpoint: {self._sse_message_url}")
                        break

                if not self._sse_message_url:
                    logger.error(f"[{self.name}] No SSE endpoint received")
                    return False

            # Initialize via message endpoint
            init_request = {
                "jsonrpc": "2.0",
                "method": "initialize",
                "id": 0,
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "mcp-gateway", "version": "1.0"},
                },
            }

            async with (
                aiohttp.ClientSession() as session,
                session.post(
                    self._sse_message_url,
                    json=init_request,
                    headers={"Content-Type": "application/json"},
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp,
            ):
                if resp.status == 200:
                    await self._fetch_tools_http()
                    self._initialized = True
                    return True

            return False

        except Exception as e:
            logger.error(f"[{self.name}] SSE init error: {e}")
            return False

    async def _fetch_tools_http(self) -> None:
        """Fetch and cache tools for HTTP backend."""
        try:
            tools_request = {"jsonrpc": "2.0", "method": "tools/list", "id": 1}
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                **self.config.headers,
            }
            if self._http_session_id:
                headers["mcp-session-id"] = self._http_session_id

            url = self._sse_message_url or self.config.http_url

            async with (
                aiohttp.ClientSession() as session,
                session.post(
                    url,  # type: ignore
                    json=tools_request,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp,
            ):
                if resp.status == 200:
                    result = await resp.json()
                    if "result" in result:
                        self._tools_cache = result
                        tool_count = len(result.get("result", {}).get("tools", []))
                        logger.info(f"[{self.name}] Cached {tool_count} tools")

        except Exception as e:
            logger.warning(f"[{self.name}] Failed to cache tools: {e}")

    async def stop(self) -> None:
        """Stop the backend."""
        if self.is_http:
            self._initialized = False
            self._http_session_id = None
            self._sse_message_url = None
            return

        async with self._lock:
            if self.process:
                logger.info(f"[{self.name}] Stopping (PID: {self.process.pid})")
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                self.process = None
                self._initialized = False

    async def send_request(self, request: dict[str, Any]) -> dict[str, Any]:
        """Send a JSON-RPC request to the backend.

        Args:
            request: JSON-RPC request object

        Returns:
            JSON-RPC response object
        """
        self.last_used = time.time()

        # Return cached tools if available
        if request.get("method") == "tools/list" and self._tools_cache:
            logger.debug(f"[{self.name}] Returning cached tools/list")
            cached = self._tools_cache.copy()
            cached["id"] = request.get("id")
            return cached

        if self.is_http:
            return await self._send_http_request(request)
        return await self._send_stdio_request(request)

    async def _send_http_request(self, request: dict[str, Any]) -> dict[str, Any]:
        """Send request to HTTP backend."""
        try:
            if not self._initialized:
                await self.start()

            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                **self.config.headers,
            }
            if self._http_session_id:
                headers["mcp-session-id"] = self._http_session_id

            url = self._sse_message_url or self.config.http_url

            async with (
                aiohttp.ClientSession() as session,
                session.post(
                    url,  # type: ignore
                    json=request,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp,
            ):
                if "mcp-session-id" in resp.headers:
                    self._http_session_id = resp.headers["mcp-session-id"]

                if "text/event-stream" in resp.content_type:
                    async for line in resp.content:
                        decoded = line.decode().strip()
                        if decoded.startswith("data: "):
                            result: dict[str, Any] = json.loads(decoded[6:])
                            return result

                result = await resp.json()
                return dict(result)

        except Exception as e:
            logger.error(f"[{self.name}] HTTP error: {e}")
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32000, "message": str(e)},
                "id": request.get("id"),
            }

    async def _send_stdio_request(self, request: dict[str, Any]) -> dict[str, Any]:
        """Send request to stdio backend."""
        if not self.is_running and not await self.start():
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32000, "message": "Backend unavailable"},
                "id": request.get("id"),
            }

        is_notification = "id" not in request

        try:
            assert self.process and self.process.stdin and self.process.stdout

            request_bytes = (json.dumps(request) + "\n").encode()
            self.process.stdin.write(request_bytes)
            self.process.stdin.flush()

            if is_notification:
                return {"jsonrpc": "2.0", "result": None}

            # Read response with timeout
            import select

            ready, _, _ = select.select([self.process.stdout], [], [], 30.0)
            if ready:
                response = self.process.stdout.readline()
                if response:
                    result: dict[str, Any] = json.loads(response.decode())
                    return result

            return {
                "jsonrpc": "2.0",
                "error": {"code": -32000, "message": "Timeout waiting for response"},
                "id": request.get("id"),
            }

        except Exception as e:
            logger.error(f"[{self.name}] stdio error: {e}")
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32000, "message": str(e)},
                "id": request.get("id"),
            }

    def get_cached_tools(self) -> list[dict[str, Any]]:
        """Get cached tools list, if available."""
        if self._tools_cache:
            result_data = self._tools_cache.get("result", {})
            if isinstance(result_data, dict):
                tools = result_data.get("tools", [])
                if isinstance(tools, list):
                    return tools
        return []
