#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Self-test of scripts/ci/check-unlocked-install.sh against stub binaries.

The checker passes an installed gateway only when it both answers /livez and
logs that its key server started (the line logged after the email-hash
self-check passed). Each stub plays one way a binary can behave; the checker
must give each the verdict below, so the gate cannot decay into a green no-op.
"""
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts" / "ci" / "check-unlocked-install.sh"

# A stand-in gateway: serves 200 on /livez from an OS-chosen port, and logs
# what STUB_MODE says. `--config` must name a file the checker wrote.
STUB = r'''#!/usr/bin/env python3
import http.server, os, sys, threading
mode = os.environ["STUB_MODE"]
config = sys.argv[sys.argv.index("--config") + 1]
assert os.path.isfile(config), config
# The self-check runs only when the key server starts: the checker's config
# must turn it on, or the real gate could pass without the check.
assert "key_server:\n  enabled: true\n" in open(config).read(), "the config does not enable the key server"
if mode == "exits":
    print("Error: email hash self-check: known answer 0 missed", flush=True)
    sys.exit(1)
class Livez(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        ok = self.path == "/livez" and mode != "no-livez"
        self.send_response(200 if ok else 404)
        self.end_headers()
    def log_message(self, *args):
        pass
server = http.server.HTTPServer(("127.0.0.1", 0), Livez)
port = server.server_address[1]
if mode == "wrong-port":
    # The banner names a port nothing serves; /livez answers on another.
    other = http.server.HTTPServer(("127.0.0.1", 0), Livez)
    port = other.server_address[1]
    other.server_close()
if mode in ("both", "partial", "no-livez", "wrong-port"):
    print("INFO mcp_gateway::gateway::server::run_steps: Key server enabled", flush=True)
if mode == "partial":
    # The banner never ends its line: the checker must not read it.
    sys.stdout.write(f"INFO mcp_gateway::gateway::server::support: Listening host=127.0.0.1 port={port}")
    sys.stdout.flush()
else:
    print(f"INFO mcp_gateway::gateway::server::support: Listening host=127.0.0.1 port={port}", flush=True)
server.serve_forever()
'''


def run_checker(mode, keep_log=None):
    with tempfile.TemporaryDirectory() as tmp:
        stub = pathlib.Path(tmp) / "mcp-gateway"
        stub.write_text(STUB)
        stub.chmod(0o755)
        env = dict(os.environ, STUB_MODE=mode, UNLOCKED_INSTALL_WAIT="6")
        env.pop("UNLOCKED_INSTALL_LOG", None)
        if keep_log:
            env["UNLOCKED_INSTALL_LOG"] = str(keep_log)
        return subprocess.run(
            ["bash", str(CHECKER), str(stub)],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )


class CheckUnlockedInstall(unittest.TestCase):
    def test_a_binary_that_serves_with_its_key_server_passes(self):
        result = run_checker("both")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ok: the installed gateway started its key server", result.stdout)

    def test_a_binary_that_exits_before_serving_fails_with_its_log(self):
        result = run_checker("exits")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("exited (status 1) before serving", result.stdout)
        self.assertIn("known answer 0 missed", result.stdout)

    def test_serving_without_the_key_server_line_fails(self):
        result = run_checker("livez-only")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("log that its key server started", result.stdout)

    def test_both_lines_without_livez_on_the_banner_port_fail(self):
        for mode in ("no-livez", "wrong-port"):
            result = run_checker(mode)
            self.assertEqual(result.returncode, 1, mode + result.stdout + result.stderr)
            self.assertIn("did not both answer /livez", result.stdout, mode)

    def test_the_log_is_kept_where_the_job_uploads_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            kept = pathlib.Path(tmp) / "gateway.log"
            result = run_checker("both", keep_log=kept)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("Key server enabled", kept.read_text())

    def test_a_banner_line_still_being_written_is_not_read(self):
        result = run_checker("partial")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("did not both answer /livez", result.stdout)

    def test_the_real_gate_keeps_the_full_wait(self):
        # The shortened wait is for these stubs only.
        for path in (
            ROOT / ".github" / "workflows" / "unlocked-install.yml",
            ROOT / "scripts" / "ci" / "packaged-tests.sh",
        ):
            self.assertNotIn("UNLOCKED_INSTALL_WAIT", path.read_text(), path)


if __name__ == "__main__":
    sys.exit(unittest.main())
