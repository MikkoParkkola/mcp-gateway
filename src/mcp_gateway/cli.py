"""
Command-line interface for MCP Gateway.

Usage:
    mcp-gateway --config servers.yaml --port 39400
    mcp-gateway --help
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys
from pathlib import Path

from mcp_gateway.config import GatewayConfig
from mcp_gateway.gateway import Gateway
from mcp_gateway.version import __version__


def setup_logging(level: str) -> None:
    """Configure logging for the application."""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler()],
    )


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="mcp-gateway",
        description="Universal MCP Gateway - Single-port multiplexing with Meta-MCP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start with config file
  mcp-gateway --config servers.yaml

  # Override port
  mcp-gateway --config servers.yaml --port 8080

  # Enable debug logging
  mcp-gateway --config servers.yaml --log-level DEBUG

Configuration file format (YAML):
  port: 39400
  enable_meta_mcp: true

  backends:
    tavily:
      command: "npx -y @anthropic/mcp-server-tavily"
      description: "Web search"

    context7:
      http_url: "http://localhost:8080/mcp"
      description: "Documentation lookup"
""",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        help="Path to YAML configuration file",
    )

    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=None,
        help="Port to listen on (default: 39400)",
    )

    parser.add_argument(
        "--host",
        type=str,
        default=None,
        help="Host to bind to (default: 127.0.0.1)",
    )

    parser.add_argument(
        "--log-level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default=None,
        help="Logging level (default: INFO)",
    )

    parser.add_argument(
        "--no-meta-mcp",
        action="store_true",
        help="Disable Meta-MCP mode (direct backend access only)",
    )

    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    args = parse_args()

    # Load configuration
    if args.config:
        if not args.config.exists():
            print(f"Error: Config file not found: {args.config}", file=sys.stderr)
            return 1
        config = GatewayConfig.from_yaml(args.config)
    else:
        config = GatewayConfig()

    # Apply command-line overrides
    if args.port is not None:
        config = config.model_copy(update={"port": args.port})
    if args.host is not None:
        config = config.model_copy(update={"host": args.host})
    if args.log_level is not None:
        config = config.model_copy(update={"log_level": args.log_level})
    if args.no_meta_mcp:
        config = config.model_copy(update={"enable_meta_mcp": False})

    # Setup logging
    setup_logging(config.log_level)

    # Validate config
    if not config.backends:
        print("Warning: No backends configured", file=sys.stderr)

    # Create gateway
    gateway = Gateway(config)

    # Setup signal handlers
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def signal_handler(_sig: int, _frame: object) -> None:
        print("\nShutting down...")
        loop.call_soon_threadsafe(loop.stop)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Run
    try:
        loop.run_until_complete(gateway.run())
    except KeyboardInterrupt:
        pass
    finally:
        loop.run_until_complete(gateway.stop())
        loop.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
