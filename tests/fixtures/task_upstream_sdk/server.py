# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Pinned real-SDK upstream peer for the I5 vertical proof.

fastmcp 4.0.3 + fastmcp-tasks 4.0.3 + pydocket 0.25.0. The Docket backend is a
REAL Redis instance whose loopback URL is supplied by the caller: nothing here
is ``memory://`` and nothing here is in-process, so the job that outlives a
gateway restart is a job held by an actual task runtime.

Run as::

    python server.py --port N --redis-url redis://127.0.0.1:P/0 --gate-dir DIR

The tool body waits on an EXPLICIT gate rather than a sleep, so "the job is
still running" is a state this fixture reports, never an elapsed time the test
infers:

* ``GET  /gate``     -> ``{"entered", "released", "finished", "expired"}``
* ``POST /release``  -> releases the gate (idempotent)
* ``GET  /counters`` -> ``{"submissions", "queries", "optin", "handles"}``

The gate lives in a caller-owned directory rather than in this process, because
the pinned stack may execute the tool body in a Docket worker task this
process's own memory would not be shared with.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import time
from pathlib import Path

from fastmcp import FastMCP
from fastmcp_tasks import TasksExtension
from starlette.requests import Request
from starlette.responses import JSONResponse

COUNTERS: dict[str, object] = {
    "submissions": 0,
    "queries": 0,
    "optin": 0,
    "handles": [],
}

ARGS = argparse.ArgumentParser()
ARGS.add_argument("--port", type=int, required=True)
ARGS.add_argument("--redis-url", required=True)
ARGS.add_argument("--gate-dir", required=True)
# A bound, not a schedule: the test releases the gate explicitly and this only
# stops a forgotten job from running forever.
ARGS.add_argument("--max-hold-secs", type=float, default=600.0)
OPTIONS = ARGS.parse_args()

GATE = Path(OPTIONS.gate_dir)
GATE.mkdir(parents=True, exist_ok=True)


def _mark(name: str) -> None:
    (GATE / name).write_text(str(time.time()))


def _has(name: str) -> bool:
    return (GATE / name).exists()


mcp = FastMCP("upstream-sdk-peer")
mcp.add_extension(TasksExtension(url=OPTIONS.redis_url))


@mcp.tool(task=True)
async def slow_echo(text: str = "hi") -> str:
    """Task-enabled tool held open by an explicit external gate."""
    _mark("entered")
    deadline = time.monotonic() + OPTIONS.max_hold_secs
    while not _has("release"):
        if time.monotonic() >= deadline:
            _mark("expired")
            raise RuntimeError("gate was never released within the fixture bound")
        await asyncio.sleep(0.05)
    _mark("finished")
    return f"upstream-sdk-answered:{text}"


@mcp.custom_route("/counters", methods=["GET"])
async def counters(_request: Request) -> JSONResponse:
    return JSONResponse(COUNTERS)


@mcp.custom_route("/gate", methods=["GET"])
async def gate(_request: Request) -> JSONResponse:
    return JSONResponse(
        {
            "entered": _has("entered"),
            "released": _has("release"),
            "finished": _has("finished"),
            "expired": _has("expired"),
        }
    )


@mcp.custom_route("/release", methods=["POST"])
async def release(_request: Request) -> JSONResponse:
    _mark("release")
    return JSONResponse({"released": True})


class Counting:
    """Count `tools/call` submissions, `tasks/get` queries, and the opt-in.

    Wrapped around the ASGI app rather than added as MCP middleware so it sees
    the bytes on the wire — which is what "one submission" is a claim about.
    """

    CAPS = "io.modelcontextprotocol/clientCapabilities"
    TASKS = "io.modelcontextprotocol/tasks"

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or scope.get("method") != "POST":
            await self.app(scope, receive, send)
            return
        body = b""
        more = True
        while more:
            message = await receive()
            body += message.get("body", b"")
            more = message.get("more_body", False)
        self._count(body)
        replayed = {"type": "http.request", "body": body, "more_body": False}
        sent = False

        async def replay():
            # The cached body first, then the real channel: an app that keeps
            # reading (SSE keep-alives, disconnect detection) must still get the
            # transport's own events rather than a fabricated disconnect.
            nonlocal sent
            if not sent:
                sent = True
                return replayed
            return await receive()

        await self.app(scope, replay, send)

    def _count(self, body: bytes) -> None:
        try:
            parsed = json.loads(body or b"{}")
        except ValueError:
            return
        method = parsed.get("method")
        params = parsed.get("params") or {}
        if method == "tools/call":
            COUNTERS["submissions"] += 1
            declared = (
                (params.get("_meta") or {}).get(self.CAPS, {}).get("extensions", {})
            )
            if self.TASKS in declared:
                COUNTERS["optin"] += 1
        elif method == "tasks/get":
            COUNTERS["queries"] += 1
            asked = params.get("taskId")
            if isinstance(asked, str):
                COUNTERS["handles"].append(asked)


if __name__ == "__main__":
    import uvicorn

    app = Counting(mcp.http_app(path="/mcp"))
    uvicorn.run(app, host="127.0.0.1", port=OPTIONS.port, log_level="warning")
