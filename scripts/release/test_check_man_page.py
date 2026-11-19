# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""M2 (MIK-9681.CLIUX.20): check_man_page.py PAGE BINARY passes only a page whose subcommands are the binary's own
`--help` command list and whose .TH version is the binary's package version. The fixture binary prints the base
build's real `--help` (fixtures/man_page/help.txt) and a `--version` line with the UI API suffix; the fixture page is
in clap_mangen 0.2.33's format. One fault per case."""

import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).with_name("check_man_page.py")
HELP = (pathlib.Path(__file__).parent / "fixtures" / "man_page" / "help.txt").read_text()
VERSION = "4.0.0"


def commands_in(help_text):
    lines = help_text.splitlines()
    start = lines.index("Commands:") + 1
    out = []
    for line in lines[start:]:
        if not line.strip():
            break
        out.append(line.split()[0])
    return out


def page(names, version=VERSION, program="mcp-gateway"):
    entries = "".join(f".TP\nmcp\\-gateway\\-{n.replace('-', chr(92) + '-')}(1)\nAbout {n}\n" for n in names)
    return (f'.TH {program} 1  "{program} {version}"\n.SH NAME\nmcp\\-gateway \\- gateway\n.SH SYNOPSIS\n'
            f"\\fBmcp\\-gateway\\fR\n.SH SUBCOMMANDS\n{entries}")


class ManPageCheck(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = pathlib.Path(temp.name)
        self.names = commands_in(HELP)
        self.assertGreater(len(self.names), 20, "the help fixture lists the top-level commands")

    def binary(self, help_text=HELP, version_line=f"mcp-gateway {VERSION} (UI API 1)", help_exit=0):
        path = self.root / "mcp-gateway"
        (self.root / "help.txt").write_text(help_text)
        path.write_text(
            "#!/usr/bin/env python3\nimport pathlib, sys\n"
            f"if sys.argv[1:] == ['--version']:\n    print({version_line!r})\n"
            f"else:\n    sys.stdout.write(pathlib.Path({str(self.root / 'help.txt')!r}).read_text())\n"
            f"    sys.exit({help_exit})\n"
        )
        path.chmod(path.stat().st_mode | stat.S_IEXEC)
        return path

    def run_check(self, page_text, binary=None):
        (self.root / "mcp-gateway.1").write_text(page_text)
        binary = binary or self.binary()
        return subprocess.run([sys.executable, str(SCRIPT), str(self.root / "mcp-gateway.1"), str(binary)],
                              capture_output=True, text=True)

    def assert_refused(self, done, message):
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn(message, done.stdout + done.stderr)

    def test_agreeing_page_and_binary_pass(self):
        done = self.run_check(page(self.names))
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_the_page_lacks_a_command(self):
        self.assert_refused(self.run_check(page(self.names[1:])), f"the page lacks {self.names[0]}")

    def test_the_page_lists_an_extra_command(self):
        self.assert_refused(self.run_check(page([*self.names, "phantom"])), "the page lists phantom")

    def test_another_version(self):
        self.assert_refused(self.run_check(page(self.names, version="3.9.0")), "the page names version 3.9.0, the binary 4.0.0")

    def test_no_commands_in_the_page(self):
        self.assert_refused(self.run_check(page([])), "no commands found in the page")

    def test_no_commands_in_the_help(self):
        self.assert_refused(self.run_check(page(self.names), self.binary(help_text="Usage: mcp-gateway\n")),
                            "no commands found in the binary's help")

    def test_a_missing_binary(self):
        self.assert_refused(self.run_check(page(self.names), self.root / "absent"), str(self.root / "absent"))

    def test_a_binary_that_fails_on_help(self):
        self.assert_refused(self.run_check(page(self.names), self.binary(help_exit=3)), "--help exited 3")


if __name__ == "__main__":
    unittest.main()
