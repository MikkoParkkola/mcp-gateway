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


def _has_nul(value):
    if isinstance(value, str):
        return chr(0) in value
    if isinstance(value, dict):
        return any(_has_nul(item) for item in value.values())
    if isinstance(value, list):
        return any(_has_nul(item) for item in value)
    return False


def _body_defect(body):
    """Name the gate this body should meet, or None if it is legitimate."""
    try:
        parsed = json.loads(body)
    except ValueError:
        return "json-well-formedness"
    if _has_nul(parsed):
        return "input-sanitization"
    if not isinstance(parsed, dict) or "method" not in parsed:
        return "jsonrpc-envelope-shape"
    return None


class _Stub(BaseHTTPRequestHandler):
    """Behaviour is set per-server by `mode` on the server object."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # noqa: D102 - silence the default stderr log
        pass

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler naming
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
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
            # Body-shaped controls, in the order the gateway meets them: the
            # JSON parse, then the sanitizer, then the envelope check.
            reason = _body_defect(body)
            if reason is None:
                return self._send(200, {"result": {"tools": []}})
            # A fronting proxy answering the oversized or malformed body with a
            # status of its own is still a 4xx, and is still not this gate.
            status = 413 if mode == "wrong-refusal-status" else 400
            return self._send(status, {"error": reason})
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

BODY_PROBES = """
[[control]]
id = "json-well-formedness"
description = "a body that is not parseable JSON is refused 400"
introduced_in = "v3.5.0"
source = "src/gateway/router/handlers.rs"
probe = "malformed-json"
refusal_status = 400

[[control]]
id = "jsonrpc-envelope-shape"
description = "a JSON-RPC frame missing `method` is refused 400"
introduced_in = "v3.5.0"
source = "src/gateway/router/handlers.rs"
probe = "malformed-envelope"
refusal_status = 400

[[control]]
id = "input-sanitization"
description = "a string carrying a null byte is refused 400"
introduced_in = "v3.5.0"
source = "src/security/sanitize.rs"
probe = "null-byte"
refusal_status = 400
"""

INVENTORY = """
## The set — 2 controls

| # | control | source symbol | refusal test |
|---|---|---|---|
| 1 | first gate | `a` | `t` |
| 2 | second gate | `b` | `t` |

## Controls that are NOT in the set (new in 4.0.0)

| control | refusal test | code |
|---|---|---|
| a later gate | `t` | `-32099` |

## Verdict

Nothing here is a table row.
"""

SCRATCH_MANIFEST = """
[coverage]
inventory = "docs/inventory.md"
module_roots = ["src/security"]

[[coverage.not_a_control]]
module = "src/security/helper.rs"
reason = "a helper, not a gate"

[[control]]
id = "first"
authority = "nfr-sec1:1"
source = "src/security/first.rs"
probe = "none"
reason = "scratch"

[[control]]
id = "second"
authority = "nfr-sec1:2"
source = "src/security/second"
probe = "none"
reason = "scratch"

[[control]]
id = "later"
authority = "nfr-sec1-new:a later gate"
source = "src/security/later.rs"
probe = "none"
reason = "scratch"
"""


def _scratch_repo(inventory=INVENTORY, manifest=SCRATCH_MANIFEST, extra_modules=()):
    """A repo-shaped tree: an authority document and a swept module root."""
    root = Path(tempfile.mkdtemp())
    (root / "docs").mkdir()
    (root / "docs" / "inventory.md").write_text(inventory)
    modules = root / "src" / "security"
    modules.mkdir(parents=True)
    for name in ("first.rs", "later.rs", "helper.rs", "mod.rs", "first_tests.rs", *extra_modules):
        (modules / name).write_text("// scratch\n")
    (modules / "second").mkdir()
    (modules / "second" / "mod.rs").write_text("// scratch\n")
    return root, _manifest(manifest)


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
        self.assertEqual(probes.get("json-well-formedness"), "malformed-json")
        self.assertEqual(probes.get("jsonrpc-envelope-shape"), "malformed-envelope")
        self.assertEqual(probes.get("input-sanitization"), "null-byte")


class TestBodyProbes(unittest.TestCase):
    """The three gates a body shape reaches: parse, sanitize, envelope."""

    def test_body_controls_present_pass(self):
        with _StubServer("control-present") as stub:
            code, report = drift.run(_manifest(BODY_PROBES), stub.endpoint)
        self.assertEqual(code, 0, report)
        for name in ("json-well-formedness", "jsonrpc-envelope-shape", "input-sanitization"):
            self.assertIn(f"{name}: refused 400", report)

    def test_body_controls_absent_fail_per_row(self):
        with _StubServer("refuses-nothing") as stub:
            code, report = drift.run(_manifest(BODY_PROBES), stub.endpoint)
        self.assertNotEqual(code, 0)
        for name in ("json-well-formedness", "jsonrpc-envelope-shape", "input-sanitization"):
            line = next(l for l in report.splitlines() if l.startswith(f"{name}:"))
            self.assertIn("FAIL", line)

    # 4xx is a refusal by someone. A row that names its own status says which
    # someone, so a proxy answering 413 ahead of the gateway's 400 does not
    # read as the gate firing.
    def test_wrong_refusal_status_is_not_the_control(self):
        with _StubServer("wrong-refusal-status") as stub:
            code, report = drift.run(_manifest(BODY_PROBES), stub.endpoint)
        self.assertNotEqual(code, 0)
        self.assertIn("refused 413, but this control refuses 400", report)

    # The bodies must differ where the gates differ: a null-byte probe whose
    # body is merely unparseable would pass against a server that only has the
    # JSON parse, and the sanitizer would go unprobed.
    def test_each_probe_body_reaches_its_own_gate(self):
        self.assertEqual(drift_defect(drift.MALFORMED_JSON_BODY), "json-well-formedness")
        self.assertEqual(drift_defect(drift.MALFORMED_ENVELOPE_BODY), "jsonrpc-envelope-shape")
        self.assertEqual(drift_defect(drift.NULL_BYTE_BODY), "input-sanitization")
        self.assertIsNone(drift_defect(drift.REQUEST_BODY))


drift_defect = _body_defect


class TestCoverage(unittest.TestCase):
    """The manifest may not define its own population."""

    # The shipped manifest against the real authorities. This is the row that
    # holds the first half of NFR.SEC.7: a merged control absent from the
    # manifest is a failure here, not a silent pass in the probe report.
    def test_shipped_manifest_covers_its_authorities(self):
        code, report = drift.check_coverage()
        self.assertEqual(code, 0, report)
        self.assertIn("0 coverage gaps", report)

    def test_scratch_manifest_covers_its_authorities(self):
        root, manifest = _scratch_repo()
        code, report = drift.check_coverage(manifest, root)
        self.assertEqual(code, 0, report)

    def test_authority_row_with_no_control_is_a_gap(self):
        dropped = SCRATCH_MANIFEST.replace('authority = "nfr-sec1:2"', 'authority = "nfr-sec1:1"')
        root, manifest = _scratch_repo(manifest=dropped)
        code, report = drift.check_coverage(manifest, root)
        self.assertNotEqual(code, 0)
        self.assertIn("the authority lists nfr-sec1:2", report)

    # Renumbering the authority must not leave a manifest row pointing at a
    # question nobody asked any more.
    def test_control_claiming_a_row_the_authority_dropped_is_a_gap(self):
        root, manifest = _scratch_repo(
            manifest=SCRATCH_MANIFEST.replace('"nfr-sec1:2"', '"nfr-sec1:9"')
        )
        code, report = drift.check_coverage(manifest, root)
        self.assertNotEqual(code, 0)
        self.assertIn("claims nfr-sec1:9, which the authority does not list", report)

    # The code half: a security module merged without a manifest row fails
    # without anyone remembering to update a document.
    def test_unnamed_security_module_is_a_gap(self):
        root, manifest = _scratch_repo(extra_modules=("brand_new_guard.rs",))
        code, report = drift.check_coverage(manifest, root)
        self.assertNotEqual(code, 0)
        self.assertIn("src/security/brand_new_guard.rs is a security module no control names", report)

    def test_moved_source_is_a_gap(self):
        root, manifest = _scratch_repo(
            manifest=SCRATCH_MANIFEST.replace("src/security/first.rs", "src/security/gone.rs")
        )
        code, report = drift.check_coverage(manifest, root)
        self.assertNotEqual(code, 0)
        self.assertIn("which does not exist", report)

    # Fail closed. A parser that reads zero rows out of a reformatted authority
    # would turn every coverage assertion green at once.
    def test_unreadable_authority_fails_closed(self):
        root, manifest = _scratch_repo(inventory="# no tables here\n")
        code, report = drift.check_coverage(manifest, root)
        self.assertNotEqual(code, 0)
        self.assertIn("the authority could not be read", report)

    def test_missing_authority_document_fails_closed(self):
        root, manifest = _scratch_repo()
        (root / "docs" / "inventory.md").unlink()
        code, report = drift.check_coverage(manifest, root)
        self.assertNotEqual(code, 0)
        self.assertIn("the authority could not be read", report)

    # The real authority must still parse into the rows the manifest claims. A
    # reformat that breaks the parser is caught here rather than by a coverage
    # report that has quietly stopped reading anything.
    def test_real_inventory_parses_to_the_expected_rows(self):
        inventory = drift.read_inventory(
            REPO_ROOT / "docs" / "requirements" / "nfr-sec1-control-inventory.md"
        )
        numbered = {key for key in inventory if key.startswith("nfr-sec1:")}
        self.assertEqual(numbered, {f"nfr-sec1:{n}" for n in range(1, 15)})
        self.assertEqual(len(inventory) - len(numbered), 4)


if __name__ == "__main__":
    unittest.main()
