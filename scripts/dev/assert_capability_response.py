#!/usr/bin/env python3
"""Assert that a gateway_invoke response carries a real routed capability result.

The gateway answers a failed route with JSON-RPC success whose *inner* payload
carries isError plus a recovery hint. Checking only that the inner payload is a
JSON object therefore passes on a total routing failure, which is how both smoke
scripts reported green while never reaching the capability at all.
"""

import json
import sys
from typing import NoReturn


def fail(message: str) -> NoReturn:
    raise SystemExit(f"capability response check failed: {message}")


def main() -> None:
    payload = json.load(open(sys.argv[1], encoding="utf-8"))
    if "error" in payload:
        fail(f"JSON-RPC error: {payload['error']}")

    content = payload.get("result", {}).get("content", [])
    if not content:
        fail("missing MCP result content")
    text = content[0].get("text")
    if not text:
        fail("missing MCP text content")

    inner = json.loads(text)
    if not isinstance(inner, dict):
        fail("weather_current returned a non-object payload")

    # The routing failure this check exists to catch.
    if inner.get("isError"):
        detail = inner.get("recovery", {}).get("message") or inner.get("content")
        fail(f"gateway_invoke returned an error payload: {detail}")

    # A well-formed envelope is not a routed call. Only upstream data proves one.
    body = inner.get("content") or []
    if not body:
        fail("error-free response carried no capability content")
    observed = json.loads(body[0].get("text", "{}"))
    reading = observed.get("current", {}).get("temperature_2m")
    if not isinstance(reading, (int, float)):
        fail(f"no upstream temperature reading in payload: {sorted(observed)}")

    print(f"routed capability call verified: temperature_2m={reading}")


main()
