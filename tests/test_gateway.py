"""Tests for gateway module."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp import web

from mcp_gateway.backend import MCPBackend
from mcp_gateway.config import GatewayConfig
from mcp_gateway.gateway import Gateway


class TestGatewayInit:
    """Tests for Gateway initialization."""

    def test_creates_backends_from_config(self, sample_gateway_config):
        """Test that backends are created from config."""
        gateway = Gateway(sample_gateway_config)
        assert "test-backend" in gateway.backends
        assert isinstance(gateway.backends["test-backend"], MCPBackend)

    def test_empty_backends(self):
        """Test gateway with no backends."""
        config = GatewayConfig()
        gateway = Gateway(config)
        assert gateway.backends == {}


class TestGatewayMetaMCP:
    """Tests for Meta-MCP implementation."""

    def test_meta_initialize_response(self, sample_gateway_config):
        """Test MCP initialize response format."""
        gateway = Gateway(sample_gateway_config)
        response = gateway._meta_initialize(request_id=1)

        assert response["jsonrpc"] == "2.0"
        assert response["id"] == 1
        assert "result" in response
        assert response["result"]["protocolVersion"] == "2024-11-05"
        assert "serverInfo" in response["result"]

    @pytest.mark.asyncio
    async def test_meta_tools_list(self, sample_gateway_config):
        """Test that meta-tools are returned."""
        gateway = Gateway(sample_gateway_config)
        response = await gateway._meta_tools_list(request_id=1)

        assert response["jsonrpc"] == "2.0"
        tools = response["result"]["tools"]
        assert len(tools) == 4

        tool_names = [t["name"] for t in tools]
        assert "gateway_list_servers" in tool_names
        assert "gateway_list_tools" in tool_names
        assert "gateway_search_tools" in tool_names
        assert "gateway_invoke" in tool_names

    @pytest.mark.asyncio
    async def test_list_servers(self, sample_gateway_config):
        """Test listing servers."""
        gateway = Gateway(sample_gateway_config)
        response = await gateway._call_list_servers(request_id=1)

        assert "result" in response
        content = response["result"]["content"][0]["text"]
        data = json.loads(content)
        assert "servers" in data
        assert len(data["servers"]) == 1
        assert data["servers"][0]["name"] == "test-backend"

    @pytest.mark.asyncio
    async def test_list_tools_missing_server(self, sample_gateway_config):
        """Test list_tools with missing server parameter."""
        gateway = Gateway(sample_gateway_config)
        response = await gateway._call_list_tools({}, request_id=1)

        assert "error" in response
        assert response["error"]["code"] == -32602

    @pytest.mark.asyncio
    async def test_list_tools_unknown_server(self, sample_gateway_config):
        """Test list_tools with unknown server."""
        gateway = Gateway(sample_gateway_config)
        response = await gateway._call_list_tools({"server": "unknown"}, request_id=1)

        assert "error" in response
        assert response["error"]["code"] == -32001

    @pytest.mark.asyncio
    async def test_search_tools_missing_query(self, sample_gateway_config):
        """Test search_tools with missing query."""
        gateway = Gateway(sample_gateway_config)
        response = await gateway._call_search_tools({}, request_id=1)

        assert "error" in response
        assert response["error"]["code"] == -32602

    @pytest.mark.asyncio
    async def test_invoke_missing_params(self, sample_gateway_config):
        """Test invoke with missing parameters."""
        gateway = Gateway(sample_gateway_config)

        # Missing server
        response = await gateway._call_invoke({}, request_id=1)
        assert response["error"]["code"] == -32602

        # Missing tool
        response = await gateway._call_invoke({"server": "test"}, request_id=1)
        assert response["error"]["code"] == -32602

    @pytest.mark.asyncio
    async def test_invoke_unknown_server(self, sample_gateway_config):
        """Test invoke with unknown server."""
        gateway = Gateway(sample_gateway_config)
        response = await gateway._call_invoke({"server": "unknown", "tool": "test"}, request_id=1)
        assert response["error"]["code"] == -32001


class TestGatewayHTTPHandlers:
    """Tests for HTTP request handlers."""

    @pytest.fixture
    def gateway(self, sample_gateway_config):
        """Create a gateway for testing."""
        return Gateway(sample_gateway_config)

    @pytest.mark.asyncio
    async def test_health_endpoint(self, gateway):
        """Test health check response."""
        request = MagicMock()
        response = await gateway._handle_health(request)

        assert response.status == 200
        data = json.loads(response.text)
        assert data["status"] == "healthy"
        assert "backends" in data

    @pytest.mark.asyncio
    async def test_meta_mcp_disabled(self):
        """Test Meta-MCP when disabled."""
        config = GatewayConfig(enable_meta_mcp=False)
        gateway = Gateway(config)

        request = MagicMock()
        request.json = AsyncMock(return_value={})

        response = await gateway._handle_meta_mcp(request)
        assert response.status == 403

    @pytest.mark.asyncio
    async def test_mcp_unknown_backend(self, gateway):
        """Test request to unknown backend."""
        request = MagicMock()
        request.match_info = {"name": "unknown-backend"}

        response = await gateway._handle_mcp(request)
        assert response.status == 404


class TestGatewayApp:
    """Tests for aiohttp application."""

    def test_create_app_returns_application(self, sample_gateway_config):
        """Test that create_app returns an aiohttp Application."""
        gateway = Gateway(sample_gateway_config)
        app = gateway.create_app()

        assert isinstance(app, web.Application)

    def test_routes_registered(self, sample_gateway_config):
        """Test that routes are properly registered."""
        gateway = Gateway(sample_gateway_config)
        app = gateway.create_app()

        # Check that routes exist
        routes = [r.resource.canonical for r in app.router.routes()]
        assert "/health" in routes
        assert "/mcp" in routes


class TestGatewayLifecycle:
    """Tests for gateway lifecycle management."""

    @pytest.mark.asyncio
    async def test_start_logs_info(self, sample_gateway_config):
        """Test that start logs gateway information."""
        gateway = Gateway(sample_gateway_config)
        await gateway.start()

        assert gateway._running is True

    @pytest.mark.asyncio
    async def test_stop_stops_backends(self, sample_gateway_config):
        """Test that stop terminates all backends."""
        gateway = Gateway(sample_gateway_config)
        gateway._running = True

        # Mock backend
        mock_backend = AsyncMock()
        gateway.backends["test"] = mock_backend

        await gateway.stop()

        assert gateway._running is False
        mock_backend.stop.assert_called_once()
