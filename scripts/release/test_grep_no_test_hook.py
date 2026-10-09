#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""grep_no_test_hook.sh is the one release-binary check for debug-only test
hooks, and every workflow calls it instead of inlining a grep.

- The script passes a clean binary and fails one carrying any hook, an
  unreadable path and a file it cannot inspect, including when the calling
  step runs under `bash -e`.
- Its hook list equals the surface inventory's "debug builds only" rows.
- No workflow names a hook itself (a hand-written copy can lose its positive
  control and go silent), and the three release-binary sites call the script.
"""
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "release" / "grep_no_test_hook.sh"
WORKFLOWS = ROOT / ".github" / "workflows"
SURFACE = ROOT / "docs" / "design" / "surface-4.0.md"


def hooks_in_script() -> list[str]:
    text = SCRIPT.read_text()
    block = re.search(r"^HOOKS=\(\n(.*?)^\)", text, re.S | re.M)
    assert block, "grep_no_test_hook.sh has no HOOKS=( ... ) list"
    return [line.strip() for line in block.group(1).splitlines() if line.strip()]


def run(binary: Path, strict: bool = True) -> subprocess.CompletedProcess:
    """The script as a workflow step runs it: under `bash -e` by default."""
    shell = ["bash", "-e", "-c", '"$0" "$1"'] if strict else ["bash", "-c", '"$0" "$1"']
    return subprocess.run(
        [*shell, str(SCRIPT), str(binary)], capture_output=True, text=True, check=False
    )


class Behaviour(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = Path(self.dir.name)

    def tearDown(self):
        self.dir.cleanup()

    def binary(self, name: str, body: bytes) -> Path:
        path = self.path / name
        path.write_bytes(body)
        return path

    def test_a_clean_binary_passes(self):
        result = run(self.binary("clean", b"\x00mcp-gateway\x00release\x00"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_each_hook_fails(self):
        for hook in hooks_in_script():
            with self.subTest(hook=hook):
                body = b"\x00mcp-gateway\x00" + hook.encode() + b"\x00"
                result = run(self.binary("dirty", body))
                self.assertEqual(result.returncode, 1)
                self.assertIn(hook, result.stdout)

    def test_a_missing_binary_fails(self):
        result = run(self.path / "absent")
        self.assertEqual(result.returncode, 1, result.stdout)

    def test_a_binary_it_cannot_see_into_fails(self):
        # No crate name: an archive, a wrong path, a stripped stub.
        result = run(self.binary("opaque", b"\x1f\x8b\x08\x00compressed"))
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("could not be inspected", result.stdout)

    def test_no_argument_is_a_usage_error(self):
        result = subprocess.run(["bash", str(SCRIPT)], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 2)


class Inventory(unittest.TestCase):
    def test_the_hook_list_is_the_surface_inventory(self):
        rows = re.findall(
            r"^\| `(MCP_GATEWAY_[A-Z0-9_]+)` \| INTERNAL \| test hook compiled into debug builds only",
            SURFACE.read_text(),
            re.M,
        )
        self.assertTrue(rows, "surface-4.0.md lists no debug-only hook")
        self.assertEqual(sorted(hooks_in_script()), sorted(rows))


class Wiring(unittest.TestCase):
    def test_no_workflow_names_a_hook(self):
        names = hooks_in_script()
        offenders = [
            f"{path.name}:{n}"
            for path in sorted(WORKFLOWS.glob("*.yml"))
            for n, line in enumerate(path.read_text().splitlines(), 1)
            if any(name in line for name in names) or "MCP_GATEWAY_TEST_" in line
        ]
        self.assertEqual(offenders, [], "call scripts/release/grep_no_test_hook.sh instead")

    def test_each_release_binary_site_calls_the_script(self):
        call = "scripts/release/grep_no_test_hook.sh"
        release = (WORKFLOWS / "release.yml").read_text()
        docker = (WORKFLOWS / "docker.yml").read_text()
        self.assertIn(f"{call} ${{{{ matrix.artifact }}}}${{{{ matrix.suffix }}}}", release)
        self.assertIn(f"{call} target/release/mcp-gateway", docker)
        self.assertIn(f"{call} image-mcp-gateway", docker)


if __name__ == "__main__":
    sys.exit(unittest.main())
