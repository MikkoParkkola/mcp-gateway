#!/usr/bin/env python3
"""
MCP Gateway Token Savings Benchmark

Demonstrates the ~95% context token reduction achieved by the meta-MCP
gateway pattern compared to direct tool registration.

Direct approach: Every backend's tools are individually registered in the
LLM's system prompt, consuming context tokens proportional to the total
number of tools across all backends.

Meta-MCP approach: Only 3 gateway tools are registered (gateway_list_servers,
gateway_search_tools, gateway_invoke), regardless of how many backends or
tools exist behind the gateway.

Usage:
    python benchmarks/token_savings.py
    python benchmarks/token_savings.py --backends 10 --tools-per-backend 30
"""

from __future__ import annotations

import argparse
import json
import textwrap

# ---------------------------------------------------------------------------
# Token estimation
# ---------------------------------------------------------------------------
# OpenAI's rule-of-thumb: ~4 characters per token for English text / JSON.
# We use a conservative 3.5 chars/token to avoid under-counting.
CHARS_PER_TOKEN = 3.5


def estimate_tokens(text: str) -> int:
    """Estimate token count from character length."""
    return max(1, int(len(text) / CHARS_PER_TOKEN))


# ---------------------------------------------------------------------------
# Synthetic tool definitions
# ---------------------------------------------------------------------------

def make_tool_definition(backend: str, tool_name: str, n_params: int = 3) -> dict:
    """Generate a realistic MCP tool definition."""
    params = {
        f"param_{i}": {
            "type": "string",
            "description": f"Parameter {i} for {tool_name} — controls the {['query', 'filter', 'format', 'limit', 'offset'][i % 5]} behavior.",
        }
        for i in range(n_params)
    }
    return {
        "name": f"{backend}__{tool_name}",
        "description": (
            f"Tool '{tool_name}' from the '{backend}' backend. "
            f"Performs a specialized operation with {n_params} configurable parameters. "
            f"Returns structured JSON results."
        ),
        "inputSchema": {
            "type": "object",
            "properties": params,
            "required": [f"param_0"],
        },
    }


def generate_backend_tools(backend: str, n_tools: int) -> list[dict]:
    """Generate n_tools definitions for one backend."""
    tool_names = [
        "list_items", "get_item", "create_item", "update_item", "delete_item",
        "search", "filter", "aggregate", "export", "import_data",
        "get_status", "get_config", "set_config", "validate", "transform",
        "notify", "subscribe", "unsubscribe", "get_metrics", "get_logs",
        "get_schema", "list_users", "get_user", "create_user", "delete_user",
        "list_projects", "get_project", "run_query", "get_report", "sync",
    ]
    return [
        make_tool_definition(backend, tool_names[i % len(tool_names)], n_params=3 + (i % 3))
        for i in range(n_tools)
    ]


# ---------------------------------------------------------------------------
# Meta-MCP gateway tool definitions (fixed — always 3)
# ---------------------------------------------------------------------------

GATEWAY_TOOLS = [
    {
        "name": "gateway_list_servers",
        "description": (
            "List all registered MCP backend servers with their names, "
            "descriptions, and tool counts. Use this first to discover "
            "available capabilities."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "gateway_search_tools",
        "description": (
            "Search for tools across all registered backends by keyword. "
            "Returns matching tool names, descriptions, and which backend "
            "they belong to. Use this to find the right tool before invoking."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query to match against tool names and descriptions.",
                },
            },
            "required": ["query"],
        },
    },
    {
        "name": "gateway_invoke",
        "description": (
            "Invoke a specific tool on a specific backend server. "
            "Pass the server name, tool name, and arguments. "
            "The gateway routes the request and returns the result."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "server": {
                    "type": "string",
                    "description": "Name of the backend MCP server.",
                },
                "tool": {
                    "type": "string",
                    "description": "Name of the tool to invoke.",
                },
                "arguments": {
                    "type": "object",
                    "description": "Arguments to pass to the tool.",
                },
            },
            "required": ["server", "tool"],
        },
    },
]


# ---------------------------------------------------------------------------
# Benchmark
# ---------------------------------------------------------------------------

def run_benchmark(n_backends: int, tools_per_backend: int) -> None:
    backend_names = [
        "slack", "github", "jira", "confluence", "linear",
        "notion", "postgres", "stripe", "sendgrid", "datadog",
        "sentry", "pagerduty", "grafana", "elasticsearch", "redis",
        "mongodb", "snowflake", "bigquery", "s3", "cloudflare",
    ]

    # --- Direct approach: all tools in system prompt ---
    all_direct_tools = []
    for i in range(n_backends):
        name = backend_names[i % len(backend_names)]
        if i >= len(backend_names):
            name = f"{name}_{i // len(backend_names)}"
        all_direct_tools.extend(generate_backend_tools(name, tools_per_backend))

    direct_json = json.dumps(all_direct_tools, indent=2)
    direct_tokens = estimate_tokens(direct_json)

    # --- Meta-MCP approach: only 3 gateway tools ---
    gateway_json = json.dumps(GATEWAY_TOOLS, indent=2)
    gateway_tokens = estimate_tokens(gateway_json)

    # --- Results ---
    total_tools = n_backends * tools_per_backend
    savings_pct = (1 - gateway_tokens / direct_tokens) * 100
    ratio = direct_tokens / gateway_tokens

    w = 64  # inner width between ║ borders

    def row(text: str = "") -> str:
        return f"║ {text:<{w}} ║"

    def sep(left: str, fill: str, right: str) -> str:
        return f"{left}{fill * (w + 2)}{right}"

    print(sep("╔", "═", "╗"))
    print(row("MCP Gateway — Token Savings Benchmark".center(w)))
    print(sep("╠", "═", "╣"))
    print(row())
    print(row("Configuration"))
    print(row("─────────────"))
    print(row(f"  Backends:          {n_backends:>4}"))
    print(row(f"  Tools per backend: {tools_per_backend:>4}"))
    print(row(f"  Total tools:       {total_tools:>4}"))
    print(row())
    print(sep("╠", "═", "╣"))
    print(row())
    print(row("Approach              Tools in Prompt    Est. Tokens"))
    print(row("────────              ───────────────    ───────────"))
    print(row(f"Direct (all tools)    {total_tools:>15,}    {direct_tokens:>11,}"))
    print(row(f"Meta-MCP (gateway)    {3:>15,}    {gateway_tokens:>11,}"))
    print(row())
    print(sep("╠", "═", "╣"))
    print(row())
    print(row(f"Token savings:        {savings_pct:>5.1f}%"))
    print(row(f"Reduction ratio:      {ratio:>5.0f}× fewer tokens"))
    print(row(f"Tokens saved:         {direct_tokens - gateway_tokens:>11,}"))
    print(row())
    print(sep("╚", "═", "╝"))
    print()

    # Scaling table
    print("  Scaling comparison:")
    print("  ┌──────────┬───────┬────────────────┬─────────────────┬─────────┐")
    print("  │ Backends │ Tools │ Direct (tokens) │ Gateway (tokens)│ Savings │")
    print("  ├──────────┼───────┼────────────────┼─────────────────┼─────────┤")

    for nb, tpb in [(1, 10), (3, 15), (5, 20), (10, 20), (10, 30), (20, 25)]:
        tools = []
        for i in range(nb):
            name = backend_names[i % len(backend_names)]
            tools.extend(generate_backend_tools(name, tpb))
        d_tok = estimate_tokens(json.dumps(tools, indent=2))
        g_tok = gateway_tokens  # always the same 3 tools
        pct = (1 - g_tok / d_tok) * 100
        total = nb * tpb
        print(f"  │ {nb:>8} │ {total:>5} │ {d_tok:>14,} │ {g_tok:>15,} │ {pct:>5.1f}%  │")

    print("  └──────────┴───────┴────────────────┴─────────────────┴─────────┘")
    print()
    print("  Note: Token estimates use ~3.5 chars/token heuristic.")
    print("  Gateway tools are constant (3) regardless of backend count.")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Benchmark context token savings of the MCP Gateway meta-MCP pattern."
    )
    parser.add_argument(
        "--backends", type=int, default=5,
        help="Number of MCP backend servers (default: 5)",
    )
    parser.add_argument(
        "--tools-per-backend", type=int, default=20,
        help="Number of tools per backend (default: 20)",
    )
    args = parser.parse_args()
    run_benchmark(args.backends, args.tools_per_backend)


if __name__ == "__main__":
    main()
