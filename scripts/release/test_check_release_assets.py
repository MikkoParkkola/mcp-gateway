# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Tests for check_release_assets.py: a release must not go out with a binary
that lacks its signature or SBOM, or an SBOM of some other build."""

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
EXPECTED = [
    "mcp-gateway-darwin-arm64",
    "mcp-gateway-darwin-x86_64",
    "mcp-gateway-linux-aarch64",
    "mcp-gateway-linux-x86_64",
    "mcp-gateway-windows-x86_64.exe",
]


def spdx(*purls):
    return json.dumps(
        {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {"name": p, "externalRefs": [{"referenceType": "purl", "referenceLocator": p}]}
                for p in purls
            ],
        }
    )


GOOD_SBOM = spdx(f"pkg:cargo/mcp-gateway@{VERSION}", "pkg:cargo/tokio@1.47.0")


class ReleaseAssets(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.dir = pathlib.Path(temp.name)
        for name in ("LICENSE", "NOTICE.md", "COMMERCIAL.md"):
            (self.dir / name).write_text("text\n")
        sums = []
        for name in EXPECTED:
            self.write(name, "binary")
            self.write(name + ".sigstore.json", "{}")
            self.write(name + ".spdx.json", GOOD_SBOM)
            self.write(name + ".spdx.json.sigstore.json", "{}")
            sums += [f"0000  {name}", f"0000  {name}.spdx.json"]
        self.write("SHA256SUMS.txt", "\n".join(sums) + "\n")
        self.write("SHA256SUMS.txt.sigstore.json", "{}")

    def write(self, name, text):
        (self.dir / name).write_text(text)

    def drop(self, name):
        (self.dir / name).unlink()

    def problems(self, expected=EXPECTED):
        return gate.problems(self.dir, VERSION, expected)

    def test_complete_release_passes(self):  # T1
        self.assertEqual(self.problems(), [])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(gate.main([str(self.dir), "--version", VERSION, *EXPECTED]), 0)

    def test_binary_without_signature(self):  # T2
        self.drop("mcp-gateway-linux-x86_64.sigstore.json")
        self.assertEqual(self.problems(), ["mcp-gateway-linux-x86_64: no .sigstore.json"])

    def test_binary_without_sbom(self):  # T3
        self.drop("mcp-gateway-darwin-arm64.spdx.json")
        self.drop("mcp-gateway-darwin-arm64.spdx.json.sigstore.json")
        self.assertIn("mcp-gateway-darwin-arm64: no .spdx.json", self.problems())

    def test_sbom_without_signature(self):  # T4
        self.drop("mcp-gateway-linux-aarch64.spdx.json.sigstore.json")
        self.assertEqual(
            self.problems(), ["mcp-gateway-linux-aarch64.spdx.json: no .sigstore.json"]
        )

    def test_sbom_that_is_not_spdx(self):  # T5
        self.write("mcp-gateway-linux-x86_64.spdx.json", "not json")
        self.assertEqual(len(self.problems()), 1)
        self.assertIn("not readable SPDX JSON", self.problems()[0])
        self.write("mcp-gateway-linux-x86_64.spdx.json", json.dumps({"packages": []}))
        self.assertIn("no spdxVersion", self.problems()[0])

    def test_sbom_with_no_crates_means_no_auditable_build(self):  # T6
        self.write("mcp-gateway-windows-x86_64.exe.spdx.json", spdx("pkg:generic/something@1"))
        self.assertEqual(len(self.problems()), 1)
        self.assertIn("lists no pkg:cargo package", self.problems()[0])

    def test_sbom_of_another_crate_or_version(self):  # T7 (P4: otherwise valid)
        self.write("mcp-gateway-darwin-x86_64.spdx.json", spdx("pkg:cargo/tokio@1.47.0"))
        self.assertEqual(
            self.problems(), ["mcp-gateway-darwin-x86_64.spdx.json: does not describe mcp-gateway 4.0.0"]
        )
        self.write(
            "mcp-gateway-darwin-x86_64.spdx.json", spdx("pkg:cargo/mcp-gateway@3.5.1", "pkg:cargo/tokio@1")
        )
        self.assertIn("does not describe mcp-gateway 4.0.0", self.problems()[0])

    def test_checksums(self):  # T8
        self.drop("SHA256SUMS.txt.sigstore.json")
        self.assertEqual(self.problems(), ["SHA256SUMS.txt: no .sigstore.json"])
        self.write("SHA256SUMS.txt.sigstore.json", "{}")
        self.drop("SHA256SUMS.txt")
        self.assertEqual(self.problems(), ["SHA256SUMS.txt: missing"])

    def test_checksums_must_list_every_binary_and_sbom(self):  # T8 + T8b (P4)
        lines = (self.dir / "SHA256SUMS.txt").read_text().splitlines()
        self.write(
            "SHA256SUMS.txt",
            "\n".join(
                l for l in lines
                if not l.endswith("  mcp-gateway-linux-aarch64")
                and not l.endswith("  mcp-gateway-darwin-arm64.spdx.json")
            )
            + "\n",
        )
        self.assertEqual(
            sorted(self.problems()),
            [
                "SHA256SUMS.txt: does not list mcp-gateway-darwin-arm64.spdx.json",
                "SHA256SUMS.txt: does not list mcp-gateway-linux-aarch64",
            ],
        )

    def test_expected_binary_absent(self):  # T9
        for suffix in ("", ".sigstore.json", ".spdx.json", ".spdx.json.sigstore.json"):
            self.drop("mcp-gateway-windows-x86_64.exe" + suffix)
        self.assertEqual(
            self.problems(), ["mcp-gateway-windows-x86_64.exe: expected binary is missing"]
        )

    def test_no_binaries_at_all(self):  # T10
        for path in self.dir.glob("mcp-gateway-*"):
            path.unlink()
        self.assertEqual(self.problems(), [f"{self.dir}: no release binaries"])

    def test_every_problem_is_reported_in_one_run(self):  # T11
        self.drop("mcp-gateway-linux-x86_64.sigstore.json")
        self.drop("SHA256SUMS.txt.sigstore.json")
        self.write("mcp-gateway-darwin-arm64.spdx.json", spdx("pkg:generic/x@1"))
        self.assertEqual(len(self.problems()), 3)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(gate.main([str(self.dir), "--version", VERSION, *EXPECTED]), 1)
        self.assertEqual(len(out.getvalue().splitlines()), 3)

    def test_sbom_only_mode_checks_just_the_crate_list(self):  # per-target rehearsal leg
        out = io.StringIO()
        name = "mcp-gateway-darwin-arm64"
        with contextlib.redirect_stdout(out):
            self.assertEqual(gate.main([str(self.dir), "--version", VERSION, "--sbom-only", name]), 0)
        self.write(name + ".spdx.json", spdx("pkg:generic/x@1"))
        self.drop("SHA256SUMS.txt")  # not this mode's business
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(gate.main([str(self.dir), "--version", VERSION, "--sbom-only", name]), 1)
        self.assertIn("lists no pkg:cargo package", out.getvalue())
        self.assertNotIn("SHA256SUMS", out.getvalue())

    def test_license_files_are_not_binaries(self):  # T12
        self.assertNotIn("LICENSE", gate.binaries(self.dir))
        self.assertEqual(gate.binaries(self.dir), sorted(EXPECTED))


if __name__ == "__main__":
    unittest.main()
