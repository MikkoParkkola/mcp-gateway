"""
Configuration management for MCP Gateway.

Supports YAML configuration files with environment variable expansion
and validation via Pydantic.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator


def expand_env_vars(value: str) -> str:
    """Expand environment variables in a string.

    Supports both ${VAR} and $VAR syntax.
    """

    def replacer(match: re.Match[str]) -> str:
        var_name = match.group(1) or match.group(2)
        return os.environ.get(var_name, match.group(0))

    pattern = r"\$\{([^}]+)\}|\$([A-Za-z_][A-Za-z0-9_]*)"
    return re.sub(pattern, replacer, value)


class BackendConfig(BaseModel):
    """Configuration for a single MCP backend server."""

    name: str = Field(..., description="Unique identifier for this backend")
    description: str = Field(default="", description="Human-readable description")

    # Transport configuration (exactly one must be set)
    command: str | None = Field(default=None, description="Shell command for stdio transport")
    http_url: str | None = Field(default=None, description="URL for HTTP/SSE transport")

    # Optional settings
    env: dict[str, str] = Field(default_factory=dict, description="Environment variables")
    headers: dict[str, str] = Field(default_factory=dict, description="HTTP headers")
    cwd: str | None = Field(default=None, description="Working directory for stdio")
    idle_timeout: float = Field(default=300.0, ge=0, description="Seconds before hibernation")
    enabled: bool = Field(default=True, description="Whether this backend is active")

    @field_validator("command", "http_url", "cwd", mode="before")
    @classmethod
    def expand_env(cls, v: str | None) -> str | None:
        """Expand environment variables in string fields."""
        if v is None:
            return None
        return expand_env_vars(v)

    @field_validator("env", "headers", mode="before")
    @classmethod
    def expand_dict_values(cls, v: dict[str, str] | None) -> dict[str, str]:
        """Expand environment variables in dict values."""
        if v is None:
            return {}
        return {k: expand_env_vars(str(val)) for k, val in v.items()}

    @model_validator(mode="after")
    def validate_transport(self) -> BackendConfig:
        """Ensure exactly one transport is configured."""
        has_command = self.command is not None
        has_http = self.http_url is not None

        if not has_command and not has_http:
            raise ValueError(f"Backend '{self.name}' must have either 'command' or 'http_url'")

        return self

    @property
    def transport_type(self) -> Literal["stdio", "http", "sse"]:
        """Determine the transport type for this backend."""
        if self.command:
            return "stdio"
        elif self.http_url and self.http_url.endswith("/sse"):
            return "sse"
        else:
            return "http"

    @property
    def command_list(self) -> list[str] | None:
        """Parse command string into list for subprocess."""
        if not self.command:
            return None
        # Use shell parsing for complex commands
        import shlex

        return shlex.split(self.command)


class GatewayConfig(BaseModel):
    """Configuration for the MCP Gateway."""

    # Server settings
    host: str = Field(default="127.0.0.1", description="Host to bind to")
    port: int = Field(default=39400, ge=1, le=65535, description="Port to listen on")

    # Meta-MCP settings
    enable_meta_mcp: bool = Field(default=True, description="Enable Meta-MCP mode")

    # Backend configuration
    backends: dict[str, BackendConfig] = Field(
        default_factory=dict, description="MCP backend configurations"
    )

    # Operational settings
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(
        default="INFO", description="Logging verbosity"
    )
    health_check_interval: float = Field(
        default=30.0, ge=1.0, description="Seconds between health checks"
    )
    request_timeout: float = Field(
        default=30.0, ge=1.0, description="Default request timeout in seconds"
    )

    @classmethod
    def from_yaml(cls, path: str | Path) -> GatewayConfig:
        """Load configuration from a YAML file.

        Args:
            path: Path to YAML configuration file

        Returns:
            Validated GatewayConfig instance

        Raises:
            FileNotFoundError: If config file doesn't exist
            ValueError: If configuration is invalid
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        with path.open() as f:
            raw_config = yaml.safe_load(f)

        return cls.from_dict(raw_config)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GatewayConfig:
        """Create configuration from a dictionary.

        Handles the backends section specially to convert
        the YAML format to BackendConfig instances.
        """
        # Extract gateway-level settings
        gateway_settings = {
            k: v
            for k, v in data.items()
            if k not in ("backends", "servers")  # Support both names
        }

        # Parse backends
        backends_raw = data.get("backends") or data.get("servers") or {}
        backends = {}

        for name, backend_data in backends_raw.items():
            if isinstance(backend_data, dict):
                # Add name to backend config
                backend_data["name"] = name
                backends[name] = BackendConfig(**backend_data)

        gateway_settings["backends"] = backends
        return cls(**gateway_settings)

    def get_enabled_backends(self) -> dict[str, BackendConfig]:
        """Return only enabled backends."""
        return {name: backend for name, backend in self.backends.items() if backend.enabled}


def create_default_config() -> GatewayConfig:
    """Create a minimal default configuration.

    Returns:
        GatewayConfig with sensible defaults and no backends.
    """
    return GatewayConfig()


def merge_configs(base: GatewayConfig, override: GatewayConfig) -> GatewayConfig:
    """Merge two configurations, with override taking precedence.

    Args:
        base: Base configuration
        override: Configuration to overlay

    Returns:
        Merged configuration
    """
    base_dict = base.model_dump()
    override_dict = override.model_dump(exclude_unset=True)

    # Deep merge backends
    if "backends" in override_dict:
        base_dict["backends"].update(override_dict.pop("backends"))

    base_dict.update(override_dict)
    return GatewayConfig.from_dict(base_dict)
