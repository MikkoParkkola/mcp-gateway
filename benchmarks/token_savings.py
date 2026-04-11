#!/usr/bin/env python3
"""
MCP Gateway Token Savings Benchmark

Demonstrates the context token reduction achieved by the meta-MCP gateway
pattern compared to direct tool registration.

Direct approach: Every backend's tools are individually registered in the
LLM's system prompt, consuming context tokens proportional to the total
number of tools across all backends.

Meta-MCP approach: The discovery quartet stays fixed
(`gateway_list_servers`, `gateway_list_tools`, `gateway_search_tools`,
`gateway_invoke`). The canonical README benchmark adds stats, cost reporting,
playbooks, profiles, kill/revive, disabled-capability visibility, and reload
for a 14-tool surface. Surfacing webhook status raises that operational
surface to 15 (the minimum stripped surface is 12).

Usage:
    python benchmarks/token_savings.py
    python benchmarks/token_savings.py --backends 10 --tools-per-backend 30
    python benchmarks/token_savings.py --scenario readme
    python benchmarks/token_savings.py --scenario readme --json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

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
# Canonical public claims + README benchmark tool surface
# ---------------------------------------------------------------------------

PUBLIC_CLAIMS_PATH = Path(__file__).with_name("public_claims.json")


def load_public_claims() -> dict:
    """Load the canonical machine-readable public claims file."""
    with PUBLIC_CLAIMS_PATH.open(encoding="utf-8") as f:
        return json.load(f)


PUBLIC_CLAIMS = load_public_claims()
README_SCENARIO = PUBLIC_CLAIMS["readme_token_savings"]
META_TOOL_COUNTS = PUBLIC_CLAIMS["meta_tools"]


def make_gateway_tool_definition(
    name: str,
    description: str,
    properties: dict | None = None,
    required: list[str] | None = None,
) -> dict:
    """Generate a realistic gateway tool definition."""
    return {
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": properties or {},
            "required": required or [],
        },
    }


GATEWAY_TOOLS = [
    make_gateway_tool_definition(
        "gateway_list_servers",
        "List all registered MCP backend servers with their names, descriptions, tool counts, and status.",
    ),
    make_gateway_tool_definition(
        "gateway_list_tools",
        "List tools available through the gateway. Supports optional filtering by server to inspect a backend catalog.",
        properties={
            "server": {
                "type": "string",
                "description": "Optional backend MCP server name to filter by.",
            }
        },
    ),
    make_gateway_tool_definition(
        "gateway_search_tools",
        "Search for tools across all registered backends by keyword and return ranked matches with full schemas.",
        properties={
            "query": {
                "type": "string",
                "description": "Search query to match against tool names and descriptions.",
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of results to return (default 10).",
            },
        },
        required=["query"],
    ),
    make_gateway_tool_definition(
        "gateway_invoke",
        "Invoke a specific tool on a specific backend server and return the routed result.",
        properties={
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
        required=["server", "tool"],
    ),
    make_gateway_tool_definition(
        "gateway_get_stats",
        "Get usage statistics including invocations, cache hits, token savings, and top tools.",
        properties={
            "price_per_million": {
                "type": "number",
                "description": "Token price per million for cost calculations.",
            }
        },
    ),
    make_gateway_tool_definition(
        "gateway_cost_report",
        "Return current session and API-key spend with totals and per-tool breakdowns.",
        properties={
            "session_id": {
                "type": "string",
                "description": "Specific session ID to report on.",
            },
            "include_all_sessions": {
                "type": "boolean",
                "description": "Return all active sessions (admin view).",
            },
            "include_all_keys": {
                "type": "boolean",
                "description": "Return all API key accumulators (admin view).",
            },
        },
    ),
    make_gateway_tool_definition(
        "gateway_run_playbook",
        "Execute a multi-step playbook and collapse multiple tool calls into one invocation.",
        properties={
            "name": {
                "type": "string",
                "description": "Playbook name to execute.",
            },
            "arguments": {
                "type": "object",
                "description": "Playbook input arguments.",
            },
        },
        required=["name"],
    ),
    make_gateway_tool_definition(
        "gateway_kill_server",
        "Immediately disable routing to a backend server while leaving its tools visible in search/list.",
        properties={
            "server": {
                "type": "string",
                "description": "Name of the backend server to disable.",
            }
        },
        required=["server"],
    ),
    make_gateway_tool_definition(
        "gateway_revive_server",
        "Re-enable routing to a previously disabled backend server and reset its error budget.",
        properties={
            "server": {
                "type": "string",
                "description": "Name of the backend server to re-enable.",
            }
        },
        required=["server"],
    ),
    make_gateway_tool_definition(
        "gateway_set_profile",
        "Switch the active routing profile for this session.",
        properties={
            "profile": {
                "type": "string",
                "description": "Name of the routing profile to activate.",
            }
        },
        required=["profile"],
    ),
    make_gateway_tool_definition(
        "gateway_get_profile",
        "Show the active routing profile for this session and what it allows or denies.",
    ),
    make_gateway_tool_definition(
        "gateway_list_disabled_capabilities",
        "List capabilities automatically disabled due to high error rate and when they recover.",
    ),
    make_gateway_tool_definition(
        "gateway_list_profiles",
        "List all available routing profiles with their descriptions.",
    ),
    make_gateway_tool_definition(
        "gateway_reload_config",
        "Trigger an immediate config reload and report any fields that still require restart.",
    ),
]

if README_SCENARIO["gateway_tools"] != len(GATEWAY_TOOLS):
    raise RuntimeError(
        "benchmarks/public_claims.json readme_token_savings.gateway_tools must match "
        "the canonical README-benchmark GATEWAY_TOOLS list"
    )


# ---------------------------------------------------------------------------
# Benchmark
# ---------------------------------------------------------------------------

def synthetic_results(n_backends: int, tools_per_backend: int) -> dict:
    """Return synthetic benchmark results for arbitrary backend counts."""
    backend_names = [
        "slack", "github", "jira", "confluence", "linear",
        "notion", "postgres", "stripe", "sendgrid", "datadog",
        "sentry", "pagerduty", "grafana", "elasticsearch", "redis",
        "mongodb", "snowflake", "bigquery", "s3", "cloudflare",
    ]

    all_direct_tools = []
    for i in range(n_backends):
        name = backend_names[i % len(backend_names)]
        if i >= len(backend_names):
            name = f"{name}_{i // len(backend_names)}"
        all_direct_tools.extend(generate_backend_tools(name, tools_per_backend))

    direct_json = json.dumps(all_direct_tools, indent=2)
    direct_tokens = estimate_tokens(direct_json)

    gateway_json = json.dumps(GATEWAY_TOOLS, indent=2)
    gateway_tokens = estimate_tokens(gateway_json)

    total_tools = n_backends * tools_per_backend
    savings_pct = (1 - gateway_tokens / direct_tokens) * 100
    ratio = direct_tokens / gateway_tokens

    return {
        "scenario": "synthetic",
        "backends": n_backends,
        "tools_per_backend": tools_per_backend,
        "total_tools": total_tools,
        "gateway_tools": len(GATEWAY_TOOLS),
        "direct_tokens": direct_tokens,
        "gateway_tokens": gateway_tokens,
        "savings_percent": savings_pct,
        "reduction_ratio": ratio,
        "tokens_saved": direct_tokens - gateway_tokens,
    }


def print_synthetic_results(results: dict) -> None:
    """Pretty-print synthetic benchmark results."""
    total_tools = results["total_tools"]
    direct_tokens = results["direct_tokens"]
    gateway_tokens = results["gateway_tokens"]
    savings_pct = results["savings_percent"]
    ratio = results["reduction_ratio"]

    w = 60  # inner width between | borders

    def row(text: str = "") -> str:
        return f"| {text:<{w}} |"

    def sep(ch: str = "-") -> str:
        return f"+{ch * (w + 2)}+"

    print(sep("="))
    print(row("MCP Gateway - Token Savings Benchmark".center(w)))
    print(sep("="))
    print(row())
    print(row("Configuration"))
    print(row("-------------"))
    print(row(f"  Backends:          {results['backends']:>4}"))
    print(row(f"  Tools per backend: {results['tools_per_backend']:>4}"))
    print(row(f"  Total tools:       {total_tools:>4}"))
    print(row())
    print(sep())
    print(row())
    print(row("Approach              Tools in Prompt    Est. Tokens"))
    print(row("--------              ---------------    -----------"))
    print(row(f"Direct (all tools)    {total_tools:>15,}    {direct_tokens:>11,}"))
    print(row(f"Meta-MCP (gateway)    {len(GATEWAY_TOOLS):>15,}    {gateway_tokens:>11,}"))
    print(row())
    print(sep())
    print(row())
    print(row(f"Token savings:        {savings_pct:>5.1f}%"))
    print(row(f"Reduction ratio:      {ratio:>5.0f}x fewer tokens"))
    print(row(f"Tokens saved:         {results['tokens_saved']:>11,}"))
    print(row())
    print(sep("="))
    print()

    print("  Scaling comparison:")
    print("  Backends  Tools  Direct (tokens)  Gateway (tokens)  Savings")
    print("  --------  -----  --------------  ----------------  -------")

    backend_names = [
        "slack", "github", "jira", "confluence", "linear",
        "notion", "postgres", "stripe", "sendgrid", "datadog",
        "sentry", "pagerduty", "grafana", "elasticsearch", "redis",
        "mongodb", "snowflake", "bigquery", "s3", "cloudflare",
    ]
    for nb, tpb in [(1, 10), (3, 15), (5, 20), (10, 20), (10, 30), (20, 25)]:
        tools = []
        for i in range(nb):
            name = backend_names[i % len(backend_names)]
            tools.extend(generate_backend_tools(name, tpb))
        d_tok = estimate_tokens(json.dumps(tools, indent=2))
        g_tok = gateway_tokens
        pct = (1 - g_tok / d_tok) * 100
        total = nb * tpb
        print(f"  {nb:>8}  {total:>5}  {d_tok:>14,}  {g_tok:>16,}  {pct:>5.1f}%")
    print()
    print("  Note: Token estimates use ~3.5 chars/token heuristic.")
    print(f"  Gateway tools are constant ({len(GATEWAY_TOOLS)}) regardless of backend count.")
    print()


def readme_results() -> dict:
    """Return the exact token/cost scenario published in README.md."""
    direct_tokens = README_SCENARIO["direct_tools"] * README_SCENARIO["direct_tokens_per_tool"]
    gateway_tokens = len(GATEWAY_TOOLS) * README_SCENARIO["gateway_tokens_per_tool"]
    direct_cost = (
        direct_tokens * README_SCENARIO["requests"] / 1_000_000
    ) * README_SCENARIO["input_cost_per_million_usd"]
    gateway_cost = (
        gateway_tokens * README_SCENARIO["requests"] / 1_000_000
    ) * README_SCENARIO["input_cost_per_million_usd"]

    return {
        "scenario": "readme",
        "direct_tools": README_SCENARIO["direct_tools"],
        "gateway_tools": len(GATEWAY_TOOLS),
        "meta_tool_counts": META_TOOL_COUNTS,
        "direct_tokens": direct_tokens,
        "gateway_tokens": gateway_tokens,
        "requests": README_SCENARIO["requests"],
        "input_cost_per_million_usd": README_SCENARIO["input_cost_per_million_usd"],
        "savings_percent": (1 - gateway_tokens / direct_tokens) * 100,
        "direct_cost_usd": direct_cost,
        "gateway_cost_usd": gateway_cost,
        "savings_usd": direct_cost - gateway_cost,
    }


def print_readme_results(results: dict) -> None:
    """Pretty-print the README reference scenario."""
    print("README reference scenario")
    print("=========================")
    print(f"Direct tools:    {results['direct_tools']}")
    print(f"Gateway tools:   {results['gateway_tools']}")
    print(f"Direct tokens:   {results['direct_tokens']:,}")
    print(f"Gateway tokens:  {results['gateway_tokens']:,}")
    print(f"Token savings:   {results['savings_percent']:.1f}%")
    print(f"Direct cost:     ${results['direct_cost_usd']:.0f} / 1K requests")
    print(f"Gateway cost:    ${results['gateway_cost_usd']:.0f} / 1K requests")
    print(f"Savings:         ${results['savings_usd']:.0f} / 1K requests")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Benchmark context token savings of the MCP Gateway meta-MCP pattern."
    )
    parser.add_argument(
        "--scenario",
        choices=("synthetic", "readme"),
        default="synthetic",
        help="Benchmark scenario to run (default: synthetic)",
    )
    parser.add_argument(
        "--backends", type=int, default=5,
        help="Number of MCP backend servers (default: 5)",
    )
    parser.add_argument(
        "--tools-per-backend", type=int, default=20,
        help="Number of tools per backend (default: 20)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of the human-readable report.",
    )
    args = parser.parse_args()
    results = (
        readme_results()
        if args.scenario == "readme"
        else synthetic_results(args.backends, args.tools_per_backend)
    )

    if args.json:
        print(json.dumps(results, indent=2))
    elif args.scenario == "readme":
        print_readme_results(results)
    else:
        print_synthetic_results(results)


if __name__ == "__main__":
    main()
