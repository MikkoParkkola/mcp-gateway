#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Loopback stand-in for the weather API the first-run smoke routes to.

Binds 127.0.0.1 on a port the kernel picks (or argv[2]:argv[3]), writes that
port to argv[1] once it is listening, and answers GET /v1/forecast with one pinned payload. The
gateway reaches it as its HTTP proxy, so the smoke proves a routed call
without reaching the public internet (#1543).
"""

import json
import pathlib
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

# The reserved name the fixture capability calls (scripts/dev/smoke-fixture-capability.sh).
FIXTURE_HOST = "first-run-fixture.example"
# The value the smoke asserts; no live API answers with this marker.
PINNED_TEMPERATURE = 20.0
PAYLOAD = {
    "latitude": 60.17,
    "longitude": 24.94,
    "fixture": "first-run-smoke",
    "current": {
        "time": "2026-01-01T12:00",
        "temperature_2m": PINNED_TEMPERATURE,
        "relative_humidity_2m": 50,
        "wind_speed_10m": 3.5,
        "weather_code": 0,
    },
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 (http.server naming)
        # Reached as an HTTP proxy, the request line carries the absolute URL:
        # answer only the fixture capability's own request, so a pass proves
        # the gateway routed that capability through the proxy.
        url = urlsplit(self.path)
        if url.netloc != FIXTURE_HOST or url.path != "/v1/forecast":
            self.send_error(404)
            return
        body = json.dumps(PAYLOAD).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def main() -> None:
    # Optional host and port, for a fixture in its own container on a private
    # network (docker-smoke.sh); the default is loopback on a kernel-picked port.
    host = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    server = HTTPServer((host, port), Handler)
    port_file = pathlib.Path(sys.argv[1])
    tmp = port_file.with_suffix(".tmp")
    tmp.write_text(str(server.server_address[1]), encoding="utf-8")
    tmp.replace(port_file)  # the port appears whole or not at all
    server.serve_forever()


if __name__ == "__main__":
    main()
