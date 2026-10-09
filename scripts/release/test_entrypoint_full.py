# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The `-full` entrypoint, run as root against stub commands.

The tag-manifest tests read the script's text; these run it. `id`, `timeout`,
`apt-get`, `rm` and `setpriv` are shims on PATH, so the root branch runs on any
host without Docker, without root and without touching the host's apt state.
"""

import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ENTRYPOINT = pathlib.Path(__file__).parents[2] / "docker" / "entrypoint-full.sh"

SHIMS = {
    "id": 'echo 0\n',
    # Record the ceiling it was given, then run the command it bounds.
    "timeout": 'echo "timeout $3" >> "$LOG"\nshift 3\nexec "$@"\n',
    "apt-get": 'echo "apt-get $*" >> "$LOG"\n'
    'case "$1" in update) exit "${APT_UPDATE_STATUS:-0}" ;; install) exit "${APT_INSTALL_STATUS:-0}" ;; esac\n',
    "rm": 'echo "rm $*" >> "$LOG"\n',
    "setpriv": 'echo "setpriv $*" >> "$LOG"\n',
}


class RootStart(unittest.TestCase):
    def run_entrypoint(self, **env):
        tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        for name, body in SHIMS.items():
            shim = bin_dir / name
            shim.write_text("#!/bin/sh\n" + body)
            shim.chmod(0o755)
        log = tmp / "log"
        log.touch()
        full_env = {
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "LOG": str(log),
            **env,
        }
        run = subprocess.run(
            ["sh", str(ENTRYPOINT), "--config", "/config.yaml"],
            env=full_env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return run, log.read_text()

    def test_declared_packages_are_installed_before_the_gateway(self):
        run, log = self.run_entrypoint(EXTRA_APT_PACKAGES="iproute2 jq=1.7.1-3")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("timeout 300", log, "the install runs under its ceiling")
        self.assertIn(
            "apt-get install -y --no-install-recommends iproute2 jq=1.7.1-3", log
        )
        self.assertLess(log.index("apt-get install"), log.index("setpriv"))

    def test_a_failed_install_stops_the_container(self):
        run, log = self.run_entrypoint(
            EXTRA_APT_PACKAGES="iproute2", APT_INSTALL_STATUS="100"
        )
        self.assertNotEqual(run.returncode, 0)
        self.assertNotIn("setpriv", log, "the gateway started without its packages")

    def test_a_failed_or_timed_out_update_stops_the_container(self):
        for status in ("100", "124"):
            with self.subTest(status=status):
                run, log = self.run_entrypoint(
                    EXTRA_APT_PACKAGES="iproute2", APT_UPDATE_STATUS=status
                )
                self.assertNotEqual(run.returncode, 0)
                self.assertNotIn("apt-get install", log)
                self.assertNotIn("setpriv", log)

    def test_the_gateway_runs_as_the_image_identity(self):
        run, log = self.run_entrypoint()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("setpriv --reuid=gateway --regid=gateway --init-groups mcp-gateway --config /config.yaml", log)

    def test_an_apt_option_in_the_package_list_is_refused(self):
        # `--simulate iproute2` makes apt exit 0 and install nothing, so the
        # container would start without the package it declared.
        for value in ("--simulate iproute2", "iproute2 -s", "-o=APT::Get::Simulate=1 x"):
            with self.subTest(value=value):
                run, log = self.run_entrypoint(EXTRA_APT_PACKAGES=value)
                self.assertNotEqual(run.returncode, 0, f"accepted {value!r}")
                self.assertNotIn("apt-get", log)
                self.assertNotIn("setpriv", log)
                self.assertIn("EXTRA_APT_PACKAGES", run.stderr)


if __name__ == "__main__":
    unittest.main()
