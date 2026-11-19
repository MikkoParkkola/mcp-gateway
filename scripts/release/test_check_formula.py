# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""M4 (MIK-9681.CLIUX.20): the formula check passes only a Homebrew formula whose man-page resource carries this
release's url and SHA256SUMS.txt hash and is the resource the install stages. One fault per fixture."""

import pathlib
import subprocess
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).with_name("check_formula.py")
REPO = "MikkoParkkola/mcp-gateway"
VERSION = "4.0.0"
PAGE_SHA = "a" * 64
OTHER_SHA = "b" * 64
URL = f"https://github.com/{REPO}/releases/download/v{VERSION}/mcp-gateway.1"
OLD_URL = f"https://github.com/{REPO}/releases/download/v3.9.0/mcp-gateway.1"


def formula(man_url=URL, man_sha=PAGE_SHA, other_url="https://example.invalid/x", other_sha=OTHER_SHA,
            stage_from="man-page", with_man=True, with_install=True):
    man = (f'  resource "man-page" do\n    url "{man_url}"\n    sha256 "{man_sha}"\n  end\n' if with_man else "")
    install = (f'    resource("{stage_from}").stage {{ man1.install "mcp-gateway.1" }}\n' if with_install else "")
    return (
        'class McpGateway < Formula\n'
        f'{man}'
        f'  resource "other" do\n    url "{other_url}"\n    sha256 "{other_sha}"\n  end\n'
        '  def install\n    bin.install "mcp-gateway"\n'
        f'{install}'
        '  end\nend\n'
    )


class FormulaCheck(unittest.TestCase):
    def run_check(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "mcp-gateway.rb").write_text(text)
            (root / "SHA256SUMS.txt").write_text(f"{PAGE_SHA}  mcp-gateway.1\n{'c' * 64}  mcp-gateway-linux-x86_64\n")
            return subprocess.run(
                [sys.executable, str(SCRIPT), str(root / "mcp-gateway.rb"), VERSION, REPO, str(root / "SHA256SUMS.txt")],
                capture_output=True, text=True,
            )

    def assert_refused(self, text, message):
        done = self.run_check(text)
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn(message, done.stdout + done.stderr)

    def test_the_written_formula_passes(self):
        done = self.run_check(formula())
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_no_man_page_resource(self):
        self.assert_refused(formula(with_man=False), 'no resource "man-page"')

    def test_another_url(self):
        self.assert_refused(formula(man_url=OLD_URL), f'resource "man-page": url is not {URL}')

    def test_another_sha256(self):
        self.assert_refused(formula(man_sha=OTHER_SHA), 'resource "man-page": sha256 is not mcp-gateway.1\'s line in SHA256SUMS.txt')

    def test_no_install_line(self):
        self.assert_refused(formula(with_install=False), 'no resource("man-page").stage { man1.install "mcp-gateway.1" }')

    def test_the_install_staged_from_another_resource(self):
        self.assert_refused(formula(stage_from="other"), 'no resource("man-page").stage { man1.install "mcp-gateway.1" }')

    def test_the_right_url_in_another_resource(self):
        self.assert_refused(formula(man_url=OLD_URL, other_url=URL), f'resource "man-page": url is not {URL}')

    def test_the_right_sha256_in_another_resource(self):
        self.assert_refused(formula(man_sha=OTHER_SHA, other_sha=PAGE_SHA), 'resource "man-page": sha256 is not mcp-gateway.1\'s line in SHA256SUMS.txt')


if __name__ == "__main__":
    unittest.main()
