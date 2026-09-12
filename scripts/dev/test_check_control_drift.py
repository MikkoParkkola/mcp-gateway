#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Tests for check-control-drift.py (NFR.SEC.7, MIK-7265).

Stdlib-only. Run directly:

    python3 scripts/dev/test_check_control_drift.py

The rows here are the fail-first table in
`docs/design/2026-09-11-merged-versus-listening-drift-check.md`. Each probe has
two halves and both decide: a stub that refuses everything must fail the check
exactly like a stub that refuses nothing, because "the control refused this" and
"everything here is refused" are different findings.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_checker():
    path = REPO_ROOT / "scripts" / "dev" / "check-control-drift.py"
    spec = importlib.util.spec_from_file_location("check_control_drift", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


drift = _load_checker()


class _Stub(BaseHTTPRequestHandler):
    """Behaviour is set per-server by `mode` on the server object."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # noqa: D102 - silence the default stderr log
        pass

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler naming
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        mode = self.server.mode
        if mode == "refuses-everything":
            return self._send(403, {"error": "no"})
        if mode == "refuses-nothing":
            return self._send(200, {"result": {"tools": []}})
        # "control-present" and "errors-on-foreign" both single out the request
        # the control exists to refuse; they differ only in how they answer it.
        origin = self.headers.get("Origin")
        host = self.headers.get("Host", "")
        allowed_host = f"127.0.0.1:{self.server.server_address[1]}"
        if origin is not None and origin != f"http://{allowed_host}":
            reason = "origin"
        elif host != allowed_host:
            reason = "host"
        else:
            return self._send(200, {"result": {"tools": []}})
        if mode == "errors-on-foreign":
            return self._send(500, {"error": reason})
        return self._send(403, {"error": reason})

    def _send(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _StubServer:
    def __init__(self, mode):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Stub)
        self.httpd.mode = mode
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def endpoint(self):
        host, port = self.httpd.server_address[:2]
        return f"http://{host}:{port}/mcp"

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


def _manifest(text):
    handle = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
    handle.write(text)
    handle.close()
    return handle.name


def _repo_with_tag():
    """Scratch repo: one commit tagged v3.4.0, one commit after it."""
    root = Path(tempfile.mkdtemp())

    def git(*args):
        subprocess.run(
            ["git", "-C", str(root), *args],
            check=True,
            capture_output=True,
            env={**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"},
        )

    git("init", "-q", "-b", "main")
    git("config", "user.email", "test@example.invalid")
    git("config", "user.name", "test")
    (root / "a").write_text("a")
    git("add", "a")
    git("commit", "-qm", "released")
    released = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True
    ).stdout.strip()
    git("tag", "v3.4.0")
    (root / "b").write_text("b")
    git("add", "b")
    git("commit", "-qm", "after the release")
    later = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True
    ).stdout.strip()
    return root, released, later


BOTH_PROBES = """
[[control]]
id = "origin-guard"
description = "a cross-origin browser request is refused before dispatch"
introduced_in = "5d25f104"
source = "src/gateway/router/origin_guard.rs"
probe = "foreign-origin"

[[control]]
id = "host-guard"
description = "a request carrying a foreign Host header is refused"
introduced_in = "5d25f104"
source = "src/gateway/router/origin_guard.rs"
probe = "foreign-host"
"""

NOTHING_PROBED = """
[[control]]
id = "unsafe-code-denied"
description = "the crate root denies unsafe code"
introduced_in = "5d25f104"
source = "src/lib.rs"
probe = "none"
reason = "a compile-time lint leaves no signal on the wire"
"""


class TestControlDrift(unittest.TestCase):
    # Row 1: a server carrying the controls passes, and says what it probed.
    def test_control_present_passes(self):
        with _StubServer("control-present") as stub:
            code, report = drift.run(_manifest(BOTH_PROBES), stub.endpoint)
        self.assertEqual(code, 0, report)
        self.assertIn("origin-guard", report)
        self.assertIn("host-guard", report)

    # Row 2: the load-bearing one. A server without the control must fail.
    def test_control_absent_fails(self):
        with _StubServer("refuses-nothing") as stub:
            code, report = drift.run(_manifest(BOTH_PROBES), stub.endpoint)
        self.assertNotEqual(code, 0)
        # Per line, not per run: one probe still failing must not cover for the
        # other having quietly stopped discriminating.
        for name in ("origin-guard", "host-guard"):
            line = next(l for l in report.splitlines() if l.startswith(f"{name}:"))
            self.assertIn("FAIL", line)

    # Row 5: refusing everything is not the control firing, and it is not the
    # same finding as an endpoint that never answered.
    def test_refuses_everything_fails_distinctly(self):
        with _StubServer("refuses-everything") as stub:
            code, report = drift.run(_manifest(BOTH_PROBES), stub.endpoint)
        self.assertNotEqual(code, 0)
        self.assertIn("legitimate request", report)

    # Row 6: a handler that errors on the request the control should refuse
    # answers >= 400 without refusing anything. Only 4xx counts as a refusal.
    def test_server_error_on_the_refusable_request_fails(self):
        with _StubServer("errors-on-foreign") as stub:
            code, report = drift.run(_manifest(BOTH_PROBES), stub.endpoint)
        self.assertNotEqual(code, 0)
        self.assertIn("errored 500", report)

    def test_unreachable_endpoint_fails_distinctly(self):
        # Port 1 on loopback: nothing listens, and binding it needs root.
        code, report = drift.run(_manifest(BOTH_PROBES), "http://127.0.0.1:1/mcp")
        self.assertNotEqual(code, 0)
        self.assertIn("unreachable", report)
        self.assertNotIn("legitimate request", report)

    # Row 4: an unprobed control is reported as uncovered, never as passing.
    def test_probe_none_is_uncovered(self):
        with _StubServer("control-present") as stub:
            code, report = drift.run(_manifest(BOTH_PROBES + NOTHING_PROBED), stub.endpoint)
        self.assertEqual(code, 0, report)
        self.assertIn("uncovered", report)

    # A manifest that has rotted until nothing is probed is not a pass.
    def test_manifest_with_nothing_probed_fails(self):
        with _StubServer("control-present") as stub:
            code, report = drift.run(_manifest(NOTHING_PROBED), stub.endpoint)
        self.assertNotEqual(code, 0)
        self.assertIn("no control was probed", report)

    # Row 3: provenance corroborates and never decides. A control commit that is
    # not an ancestor of the build is reported, and the passing probe still wins.
    def test_non_ancestor_commit_is_reported_but_does_not_decide(self):
        # A scratch repository rather than this one: a CI checkout is shallow
        # and carries no tags, so an assertion about real ancestry here could
        # only fail on the runner.
        repo, released, later = _repo_with_tag()
        manifest = BOTH_PROBES.replace(
            'introduced_in = "5d25f104"', f'introduced_in = "{later}"', 1
        ).replace('introduced_in = "5d25f104"', f'introduced_in = "{released}"', 1)
        with _StubServer("control-present") as stub:
            code, report = drift.run(
                manifest_path=_manifest(manifest),
                endpoint=stub.endpoint,
                version="3.4.0",
                repo_root=repo,
            )
        self.assertEqual(code, 0, report)
        self.assertIn(f"{later} is NOT in v3.4.0", report)
        self.assertIn(f"{released} is in v3.4.0", report)

    # The shipped manifest is the one the operator runs; it must parse and every
    # entry must name a probe the checker implements.
    def test_shipped_manifest_is_valid(self):
        controls = drift.load_manifest(REPO_ROOT / "security-controls.toml")
        self.assertTrue(controls)
        for control in controls:
            self.assertIn(control["probe"], set(drift.PROBES) | {"none"})
            if control["probe"] == "none":
                self.assertTrue(control.get("reason"), control["id"])
        # Each probed row keeps the probe that exercises its own control: a
        # remap would leave both rows passing while one control goes unprobed.
        probes = {control["id"]: control["probe"] for control in controls}
        self.assertEqual(probes.get("origin-guard"), "foreign-origin")
        self.assertEqual(probes.get("host-guard"), "foreign-host")


if __name__ == "__main__":
    unittest.main()
