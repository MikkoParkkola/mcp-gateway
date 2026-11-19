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

    def add_page(self):
        """The man page every full check now names with --doc: signed and listed with its real hash."""
        import hashlib

        if (self.dir / "mcp-gateway.1").exists():
            return
        self.write("mcp-gateway.1", PAGE)
        self.write("mcp-gateway.1.sigstore.json", "{}")
        sums = (self.dir / "SHA256SUMS.txt").read_text()
        self.write("SHA256SUMS.txt", sums + f"{hashlib.sha256(PAGE.encode()).hexdigest()}  mcp-gateway.1\n")

    def problems(self, expected=EXPECTED):
        return gate.problems(self.dir, VERSION, expected)

    def test_complete_release_passes(self):  # T1
        self.assertEqual(self.problems(), [])
        self.add_page()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(gate.main([str(self.dir), "--version", VERSION, "--doc", "mcp-gateway.1", *EXPECTED]), 0)

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
        self.add_page()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(gate.main([str(self.dir), "--version", VERSION, "--doc", "mcp-gateway.1", *EXPECTED]), 1)
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




PAGE = '.TH mcp-gateway 1  "mcp-gateway 4.0.0"\n.SH NAME\nmcp\\-gateway\n'


class ReleaseDocuments(ReleaseAssets):
    """M3 (MIK-9681.CLIUX.20): documents named by a repeatable --doc are signed, listed with their real hash and,
    for the man page, carry the release's .TH line. Run through main() so a checker that does not know --doc fails
    on its exit code."""

    def setUp(self):
        super().setUp()
        import hashlib

        self.docs = {"mcp-gateway.1": PAGE, "NOTICE.txt": "notice\n"}
        lines = (self.dir / "SHA256SUMS.txt").read_text().splitlines()
        for name, text in self.docs.items():
            self.write(name, text)
            self.write(name + ".sigstore.json", "{}")
            lines.append(f"{hashlib.sha256(text.encode()).hexdigest()}  {name}")
        self.write("SHA256SUMS.txt", "\n".join(lines) + "\n")

    def run_main(self, *extra, docs=("mcp-gateway.1", "NOTICE.txt")):
        argv = [str(self.dir), "--version", VERSION]
        for doc in docs:
            argv += ["--doc", doc]
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = gate.main([*argv, *extra, *EXPECTED])
            except SystemExit as exit_:
                code = exit_.code
        return code, out.getvalue() + err.getvalue()

    def test_a_complete_set_with_two_documents_passes(self):
        self.assertEqual(self.run_main()[0], 0)

    def assert_fault(self, message):
        code, text = self.run_main()
        self.assertEqual(code, 1, text)
        self.assertIn(message, text)

    def test_a_missing_document(self):
        self.drop("mcp-gateway.1")
        self.assert_fault("mcp-gateway.1: missing")

    def test_a_missing_bundle(self):
        self.drop("mcp-gateway.1.sigstore.json")
        self.assert_fault("mcp-gateway.1: no .sigstore.json")

    def test_a_missing_sums_line(self):
        lines = [l for l in (self.dir / "SHA256SUMS.txt").read_text().splitlines() if not l.endswith("  mcp-gateway.1")]
        self.write("SHA256SUMS.txt", "\n".join(lines) + "\n")
        self.assert_fault("SHA256SUMS.txt: does not list mcp-gateway.1")

    def test_a_document_edited_after_listing(self):
        self.write("mcp-gateway.1", PAGE + ".\\\" edited\n")
        self.assert_fault("SHA256SUMS.txt: the hash of mcp-gateway.1 differs from the file")

    def test_the_second_document_alone_has_a_wrong_line(self):
        self.write("NOTICE.txt", "notice, edited\n")
        self.assert_fault("SHA256SUMS.txt: the hash of NOTICE.txt differs from the file")

    def test_a_page_of_another_version(self):
        self.rewrite_page('.TH mcp-gateway 1  "mcp-gateway 3.9.0"\n')
        self.assert_fault('mcp-gateway.1: the .TH line is not `.TH mcp-gateway 1  "mcp-gateway 4.0.0"`')

    def test_a_page_of_another_program(self):
        self.rewrite_page('.TH other-tool 1  "other-tool 4.0.0"\n')
        self.assert_fault('mcp-gateway.1: the .TH line is not `.TH mcp-gateway 1  "mcp-gateway 4.0.0"`')

    # clap_mangen's real page opens with two quote-macro lines before .TH and ends .TH with a space.
    PREAMBLE = ".ie \\n(.g .ds Aq \\(aq\n.el .ds Aq '\n"

    def test_a_page_as_clap_mangen_writes_it_passes(self):
        self.rewrite_page(self.PREAMBLE + '.TH mcp-gateway 1  "mcp-gateway 4.0.0" \n')
        code, text = self.run_main()
        self.assertEqual(code, 0, text)

    def test_a_page_with_the_preamble_and_another_version(self):
        self.rewrite_page(self.PREAMBLE + '.TH mcp-gateway 1  "mcp-gateway 3.9.0" \n')
        self.assert_fault('mcp-gateway.1: the .TH line is not `.TH mcp-gateway 1  "mcp-gateway 4.0.0"`')

    def rewrite_page(self, th_line):
        import hashlib

        text = th_line + PAGE.split("\n", 1)[1]
        self.write("mcp-gateway.1", text)
        lines = [l for l in (self.dir / "SHA256SUMS.txt").read_text().splitlines() if not l.endswith("  mcp-gateway.1")]
        lines.append(f"{hashlib.sha256(text.encode()).hexdigest()}  mcp-gateway.1")
        self.write("SHA256SUMS.txt", "\n".join(lines) + "\n")

    def test_no_doc_outside_sbom_only_is_a_usage_error(self):
        code, text = self.run_main(docs=())
        self.assertEqual(code, 2, text)
        self.assertIn("--doc", text)

if __name__ == "__main__":
    unittest.main()
