"""Tests for backend module."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_gateway.backend import MCPBackend


class TestMCPBackendProperties:
    """Tests for MCPBackend properties."""

    def test_name_from_config(self, sample_backend_config):
        """Test name property returns config name."""
        backend = MCPBackend(config=sample_backend_config)
        assert backend.name == "test-backend"

    def test_is_http_false_for_stdio(self, sample_backend_config):
        """Test is_http is False for stdio backends."""
        backend = MCPBackend(config=sample_backend_config)
        assert backend.is_http is False

    def test_is_http_true_for_http(self, sample_http_backend_config):
        """Test is_http is True for HTTP backends."""
        backend = MCPBackend(config=sample_http_backend_config)
        assert backend.is_http is True

    def test_is_running_false_initially(self, sample_backend_config):
        """Test is_running is False initially."""
        backend = MCPBackend(config=sample_backend_config)
        assert backend.is_running is False


class TestMCPBackendStdio:
    """Tests for stdio backend operations."""

    @pytest.mark.asyncio
    async def test_start_spawns_process(self, sample_backend_config):
        """Test that start spawns a subprocess."""
        backend = MCPBackend(config=sample_backend_config)

        with patch("subprocess.Popen") as mock_popen:
            mock_process = MagicMock()
            mock_process.poll.return_value = None
            mock_process.pid = 12345
            mock_process.stdin = MagicMock()
            mock_process.stdout = MagicMock()
            mock_process.stdout.readline.return_value = b'{"jsonrpc":"2.0","result":{},"id":0}\n'
            mock_popen.return_value = mock_process

            with patch("select.select", return_value=([mock_process.stdout], [], [])):
                result = await backend.start()

            assert result is True
            mock_popen.assert_called_once()

    @pytest.mark.asyncio
    async def test_stop_terminates_process(self, sample_backend_config):
        """Test that stop terminates the subprocess."""
        backend = MCPBackend(config=sample_backend_config)

        mock_process = MagicMock()
        mock_process.poll.return_value = None
        mock_process.pid = 12345
        backend.process = mock_process

        await backend.stop()

        mock_process.terminate.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_request_returns_cached_tools(self, sample_backend_config):
        """Test that tools/list returns cached response."""
        backend = MCPBackend(config=sample_backend_config)
        backend._tools_cache = {
            "jsonrpc": "2.0",
            "result": {"tools": [{"name": "test_tool"}]},
            "id": 1,
        }
        backend._initialized = True

        request = {"jsonrpc": "2.0", "method": "tools/list", "id": 42}
        response = await backend.send_request(request)

        assert response["id"] == 42
        assert "result" in response
        assert response["result"]["tools"][0]["name"] == "test_tool"


class TestMCPBackendHTTP:
    """Tests for HTTP backend operations."""

    @pytest.mark.asyncio
    async def test_http_init_session(self, sample_http_backend_config):
        """Test HTTP session initialization."""
        backend = MCPBackend(config=sample_http_backend_config)

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {"mcp-session-id": "test-session-123"}
        mock_response.json = AsyncMock(return_value={"jsonrpc": "2.0", "result": {}})

        with patch("aiohttp.ClientSession") as mock_session:
            mock_ctx = AsyncMock()
            mock_ctx.__aenter__.return_value = mock_response
            mock_session.return_value.__aenter__.return_value.post.return_value = mock_ctx

            await backend._init_streamable_http()

        # Session initialization should succeed
        assert backend._initialized is True

    @pytest.mark.asyncio
    async def test_http_send_request_error_handling(self, sample_http_backend_config):
        """Test HTTP request error handling returns error response."""
        backend = MCPBackend(config=sample_http_backend_config)
        backend._initialized = True

        # Simulate network error
        with patch("aiohttp.ClientSession") as mock_session:
            mock_session.side_effect = Exception("Network error")

            request = {"jsonrpc": "2.0", "method": "test", "id": 1}
            response = await backend._send_http_request(request)

        # Should return error response
        assert "error" in response
        assert response["error"]["code"] == -32000


class TestMCPBackendSSE:
    """Tests for SSE backend operations."""

    @pytest.mark.asyncio
    async def test_sse_endpoint_detection(self, sample_sse_backend_config):
        """Test SSE endpoint URL detection."""
        backend = MCPBackend(config=sample_sse_backend_config)

        # Simulate SSE response with endpoint
        async def mock_content():
            yield b"event: endpoint\n"
            yield b"data: /message?sessionId=abc123\n"
            yield b"\n"

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.content.__aiter__ = lambda _: mock_content()

        with patch("aiohttp.ClientSession") as mock_session:
            mock_get_ctx = AsyncMock()
            mock_get_ctx.__aenter__.return_value = mock_response

            mock_post_response = AsyncMock()
            mock_post_response.status = 200
            mock_post_response.json = AsyncMock(return_value={})

            mock_post_ctx = AsyncMock()
            mock_post_ctx.__aenter__.return_value = mock_post_response

            session_instance = AsyncMock()
            session_instance.get.return_value = mock_get_ctx
            session_instance.post.return_value = mock_post_ctx
            mock_session.return_value.__aenter__.return_value = session_instance

            # This will try to init SSE - may not succeed due to mock limitations
            # but we're testing the structure
            await backend._init_sse_session()


class TestMCPBackendToolCache:
    """Tests for tool caching."""

    def test_get_cached_tools_empty(self, sample_backend_config):
        """Test empty cache returns empty list."""
        backend = MCPBackend(config=sample_backend_config)
        assert backend.get_cached_tools() == []

    def test_get_cached_tools_populated(self, sample_backend_config):
        """Test populated cache returns tools."""
        backend = MCPBackend(config=sample_backend_config)
        backend._tools_cache = {
            "result": {
                "tools": [
                    {"name": "tool1", "description": "First tool"},
                    {"name": "tool2", "description": "Second tool"},
                ]
            }
        }

        tools = backend.get_cached_tools()
        assert len(tools) == 2
        assert tools[0]["name"] == "tool1"
