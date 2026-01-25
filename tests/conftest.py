"""Pytest configuration and fixtures."""

from __future__ import annotations

import pytest

from mcp_gateway.config import BackendConfig, GatewayConfig


@pytest.fixture
def sample_backend_config() -> BackendConfig:
    """Create a sample backend configuration for testing."""
    return BackendConfig(
        name="test-backend",
        description="Test backend for unit tests",
        command="echo 'test'",
    )


@pytest.fixture
def sample_http_backend_config() -> BackendConfig:
    """Create a sample HTTP backend configuration."""
    return BackendConfig(
        name="test-http",
        description="Test HTTP backend",
        http_url="http://localhost:8080/mcp",
    )


@pytest.fixture
def sample_sse_backend_config() -> BackendConfig:
    """Create a sample SSE backend configuration."""
    return BackendConfig(
        name="test-sse",
        description="Test SSE backend",
        http_url="http://localhost:8080/sse",
    )


@pytest.fixture
def sample_gateway_config(sample_backend_config: BackendConfig) -> GatewayConfig:
    """Create a sample gateway configuration."""
    return GatewayConfig(
        port=39400,
        backends={"test-backend": sample_backend_config},
    )


@pytest.fixture
def minimal_config_yaml(tmp_path):
    """Create a minimal YAML config file."""
    config_file = tmp_path / "servers.yaml"
    config_file.write_text(
        """
port: 39400
enable_meta_mcp: true

backends:
  echo:
    command: "echo test"
    description: "Echo test"
"""
    )
    return config_file


@pytest.fixture
def full_config_yaml(tmp_path):
    """Create a comprehensive YAML config file."""
    config_file = tmp_path / "servers.yaml"
    config_file.write_text(
        """
port: 8080
host: "0.0.0.0"
enable_meta_mcp: true
log_level: DEBUG

backends:
  stdio-backend:
    command: "npx -y @test/server"
    description: "Stdio transport backend"
    env:
      API_KEY: "test-key"
    idle_timeout: 600

  http-backend:
    http_url: "http://localhost:9000/mcp"
    description: "HTTP transport backend"
    headers:
      Authorization: "Bearer token"

  sse-backend:
    http_url: "http://localhost:9001/sse"
    description: "SSE transport backend"
    enabled: false
"""
    )
    return config_file
