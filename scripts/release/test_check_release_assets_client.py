# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Client download rows for check_release_assets.py (rows B1, B2): the release
set is exactly the expected binaries, and each product's SBOM names its own
root crate. Driven through the command line so an unknown option counts as a
failed assertion, not an error."""

import contextlib
import importlib.util
import io
import json
import pathlib
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "check_release_assets", pathlib.Path(__file__).with_name("check_release_assets.py")
)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

VERSION = "4.0.0"
FULL = [
    "mcp-gateway-darwin-arm64",
    "mcp-gateway-darwin-x86_64",
    "mcp-gateway-linux-aarch64",
    "mcp-gateway-linux-x86_64",
    "mcp-gateway-windows-x86_64.exe",
]
CLIENT = [name.replace("mcp-gateway-", "mcp-gateway-cli-", 1) for name in FULL]


def spdx(root):
    purls = [f"pkg:cargo/{root}@{VERSION}", "pkg:cargo/tokio@1.47.0"]
    return json.dumps({
        "spdxVersion": "SPDX-2.3",
        "packages": [{"name": p, "externalRefs": [{"referenceType": "purl", "referenceLocator": p}]}
                     for p in purls],
    })


class ClientReleaseSet(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.dir = pathlib.Path(temp.name)
        self.sums = []
        for name in FULL:
            self.add(name, "mcp-gateway")
        for name in CLIENT:
            self.add(name, "mcp-gateway")
        self.write_sums()

    def add(self, name, root):
        for suffix, text in (("", "binary"), (".sigstore.json", "{}"),
                             (".spdx.json", spdx(root)), (".spdx.json.sigstore.json", "{}")):
            (self.dir / (name + suffix)).write_text(text)
        self.sums += [f"0000  {name}", f"0000  {name}.spdx.json"]

    def write_sums(self):
        (self.dir / "SHA256SUMS.txt").write_text("\n".join(self.sums) + "\n")
        (self.dir / "SHA256SUMS.txt.sigstore.json").write_text("{}")

    def run_gate(self, *args, expected=None):
        """(exit code, output) of the gate's command line; argparse exits count."""
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            try:
                rc = gate.main([str(self.dir), "--version", VERSION, *args, *(expected or FULL + CLIENT)])
            except SystemExit as exit_:
                rc = exit_.code
        return rc, out.getvalue()

    # B1: exactly the expected binaries.
    def test_b1_the_ten_binaries_pass(self):
        rc, out = self.run_gate("--client-root", "mcp-gateway")
        self.assertEqual(rc, 0, out)

    def test_b1_an_unexpected_binary_fails(self):
        self.add("mcp-gateway-cli-freebsd-x86_64", "mcp-gateway")
        self.write_sums()
        rc, out = self.run_gate("--client-root", "mcp-gateway")
        self.assertEqual(rc, 1, out)
        self.assertIn("mcp-gateway-cli-freebsd-x86_64: not an expected binary", out)

    def test_b1_a_missing_client_binary_fails(self):
        rc, out = self.run_gate("--client-root", "mcp-gateway", expected=FULL + CLIENT + ["mcp-gateway-cli-extra"])
        self.assertEqual(rc, 1, out)
        self.assertIn("mcp-gateway-cli-extra: expected binary is missing", out)

    # B2: each product's SBOM names the root recorded for this release.
    def test_b2_same_package_client_sbom_rooted_at_the_gateway_passes(self):
        rc, out = self.run_gate("--client-root", "mcp-gateway")
        self.assertEqual(rc, 0, out)

    def test_b2_fallback_client_sbom_rooted_at_the_gateway_fails(self):
        rc, out = self.run_gate("--client-root", "mcp-gateway-cli")
        self.assertEqual(rc, 1, out)
        self.assertIn("mcp-gateway-cli-linux-x86_64.spdx.json: does not describe mcp-gateway-cli 4.0.0", out)

    def test_b2_fallback_client_sbom_rooted_at_the_client_passes(self):
        self.sums = []
        for name in FULL:
            self.add(name, "mcp-gateway")
        for name in CLIENT:
            self.add(name, "mcp-gateway-cli")
        self.write_sums()
        rc, out = self.run_gate("--client-root", "mcp-gateway-cli")
        self.assertEqual(rc, 0, out)

    def test_b2_a_client_rooted_sbom_on_a_full_binary_fails(self):
        self.add("mcp-gateway-linux-x86_64", "mcp-gateway-cli")
        rc, out = self.run_gate("--client-root", "mcp-gateway-cli")
        self.assertEqual(rc, 1, out)
        self.assertIn("mcp-gateway-linux-x86_64.spdx.json: does not describe mcp-gateway 4.0.0", out)

    def test_b2_sbom_only_mode_uses_the_client_root(self):
        rc, out = self.run_gate("--sbom-only", "--client-root", "mcp-gateway-cli",
                                expected=["mcp-gateway-cli-linux-x86_64"])
        self.assertEqual(rc, 1, out)
        self.assertIn("mcp-gateway-cli-linux-x86_64.spdx.json: does not describe mcp-gateway-cli 4.0.0", out)
        rc, out = self.run_gate("--sbom-only", "--client-root", "mcp-gateway",
                                expected=["mcp-gateway-cli-linux-x86_64"])
        self.assertEqual(rc, 0, out)


if __name__ == "__main__":
    unittest.main()
