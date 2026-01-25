"""Tests for configuration module."""

from __future__ import annotations

import pytest

from mcp_gateway.config import (
    BackendConfig,
    GatewayConfig,
    create_default_config,
    expand_env_vars,
    merge_configs,
)


class TestExpandEnvVars:
    """Tests for environment variable expansion."""

    def test_expand_braces_syntax(self, monkeypatch):
        """Test ${VAR} syntax expansion."""
        monkeypatch.setenv("TEST_VAR", "test_value")
        result = expand_env_vars("prefix_${TEST_VAR}_suffix")
        assert result == "prefix_test_value_suffix"

    def test_expand_dollar_syntax(self, monkeypatch):
        """Test $VAR syntax expansion."""
        monkeypatch.setenv("MYVAR", "my_value")
        result = expand_env_vars("prefix/$MYVAR/suffix")
        # $VAR syntax matches valid identifiers up to non-identifier chars
        assert result == "prefix/my_value/suffix"

    def test_missing_var_preserved(self):
        """Test that missing variables are preserved."""
        result = expand_env_vars("${NONEXISTENT_VAR_12345}")
        assert result == "${NONEXISTENT_VAR_12345}"

    def test_multiple_vars(self, monkeypatch):
        """Test multiple variable expansion."""
        monkeypatch.setenv("VAR1", "one")
        monkeypatch.setenv("VAR2", "two")
        result = expand_env_vars("${VAR1} and ${VAR2}")
        assert result == "one and two"

    def test_no_vars(self):
        """Test string without variables."""
        result = expand_env_vars("no variables here")
        assert result == "no variables here"


class TestBackendConfig:
    """Tests for BackendConfig."""

    def test_stdio_backend_creation(self):
        """Test creating a stdio backend."""
        config = BackendConfig(
            name="test",
            command="npx -y @test/server",
            description="Test backend",
        )
        assert config.name == "test"
        assert config.transport_type == "stdio"
        assert config.command_list == ["npx", "-y", "@test/server"]

    def test_http_backend_creation(self):
        """Test creating an HTTP backend."""
        config = BackendConfig(
            name="http-test",
            http_url="http://localhost:8080/mcp",
        )
        assert config.transport_type == "http"

    def test_sse_backend_creation(self):
        """Test creating an SSE backend."""
        config = BackendConfig(
            name="sse-test",
            http_url="http://localhost:8080/sse",
        )
        assert config.transport_type == "sse"

    def test_no_transport_raises(self):
        """Test that missing transport raises error."""
        with pytest.raises(ValueError, match="must have either"):
            BackendConfig(name="invalid")

    def test_env_expansion(self, monkeypatch):
        """Test environment variable expansion in config."""
        monkeypatch.setenv("API_KEY", "secret123")
        config = BackendConfig(
            name="test",
            command="server",
            env={"KEY": "${API_KEY}"},
        )
        assert config.env["KEY"] == "secret123"

    def test_command_list_complex(self):
        """Test complex command parsing."""
        config = BackendConfig(
            name="test",
            command='npx -y "@scope/package" --flag="value with spaces"',
        )
        assert config.command_list is not None
        assert len(config.command_list) >= 3

    def test_default_values(self):
        """Test default configuration values."""
        config = BackendConfig(name="test", command="echo")
        assert config.enabled is True
        assert config.idle_timeout == 300.0
        assert config.env == {}
        assert config.headers == {}


class TestGatewayConfig:
    """Tests for GatewayConfig."""

    def test_default_creation(self):
        """Test default gateway configuration."""
        config = GatewayConfig()
        assert config.host == "127.0.0.1"
        assert config.port == 39400
        assert config.enable_meta_mcp is True
        assert config.backends == {}

    def test_from_yaml_minimal(self, minimal_config_yaml):
        """Test loading minimal YAML config."""
        config = GatewayConfig.from_yaml(minimal_config_yaml)
        assert config.port == 39400
        assert "echo" in config.backends

    def test_from_yaml_full(self, full_config_yaml):
        """Test loading comprehensive YAML config."""
        config = GatewayConfig.from_yaml(full_config_yaml)
        assert config.port == 8080
        assert config.host == "0.0.0.0"
        assert config.log_level == "DEBUG"
        assert len(config.backends) == 3

    def test_from_yaml_missing_file(self, tmp_path):
        """Test error on missing config file."""
        with pytest.raises(FileNotFoundError):
            GatewayConfig.from_yaml(tmp_path / "nonexistent.yaml")

    def test_get_enabled_backends(self, full_config_yaml):
        """Test filtering enabled backends."""
        config = GatewayConfig.from_yaml(full_config_yaml)
        enabled = config.get_enabled_backends()
        assert "sse-backend" not in enabled
        assert "stdio-backend" in enabled
        assert "http-backend" in enabled

    def test_from_dict(self):
        """Test creating config from dictionary."""
        data = {
            "port": 8080,
            "backends": {
                "test": {
                    "command": "echo",
                    "description": "Test",
                }
            },
        }
        config = GatewayConfig.from_dict(data)
        assert config.port == 8080
        assert "test" in config.backends


class TestMergeConfigs:
    """Tests for configuration merging."""

    def test_merge_basic(self):
        """Test basic config merge."""
        base = GatewayConfig(port=8080)
        override = GatewayConfig(port=9000)
        merged = merge_configs(base, override)
        assert merged.port == 9000

    def test_merge_backends(self, sample_backend_config):
        """Test merging backend configurations."""
        base = GatewayConfig(backends={"backend1": sample_backend_config})
        new_backend = BackendConfig(name="backend2", command="echo")
        override = GatewayConfig(backends={"backend2": new_backend})
        merged = merge_configs(base, override)
        assert "backend1" in merged.backends
        assert "backend2" in merged.backends


class TestCreateDefaultConfig:
    """Tests for default config creation."""

    def test_creates_valid_config(self):
        """Test that default config is valid."""
        config = create_default_config()
        assert isinstance(config, GatewayConfig)
        assert config.port == 39400
