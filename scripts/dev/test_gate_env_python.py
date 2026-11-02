#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Pin gate-env-python.sh: it names the pinned interpreter, or refuses with
the command that builds the environment, and never installs anything."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "gate-env-python.sh"
REPAIR = "UV_MALWARE_CHECK=1 uv sync --locked --project scripts/gate-env"


def run(env_overrides: dict[str, str]) -> subprocess.CompletedProcess:
    env = {**os.environ, **env_overrides}
    return subprocess.run(["bash", str(SCRIPT)], capture_output=True, text=True, env=env, cwd=SCRIPT.parent)


class GateEnvPython(unittest.TestCase):
    def test_without_uv_it_refuses_with_the_repair_command(self):
        bare = "/usr/bin:/bin"
        self.assertIsNone(shutil.which("uv", path=bare), "premise: no uv on the bare PATH")
        done = run({"PATH": bare})
        self.assertEqual(done.returncode, 1, done)
        self.assertIn(REPAIR, done.stderr)
        self.assertEqual(done.stdout, "")

    def test_a_project_that_is_not_synced_is_refused_and_left_alone(self):
        with tempfile.TemporaryDirectory() as td:
            project = Path(td)
            (project / "pyproject.toml").write_text('[project]\nname = "x"\nversion = "0"\n[tool.uv]\npackage = false\n')
            done = run({"GATE_ENV_DIR": td})
            self.assertEqual(done.returncode, 1, done)
            self.assertIn(REPAIR, done.stderr)
            self.assertFalse((project / ".venv").exists(), "the check installed an environment")
            self.assertFalse((project / "uv.lock").exists(), "the check wrote a lock")


if __name__ == "__main__":
    unittest.main()
