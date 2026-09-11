# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Regression tests for the tag/manifest publish gate and its channel predicate."""

import contextlib
import importlib.util
import io
import pathlib
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location(
    "check_tag_manifest", pathlib.Path(__file__).with_name("check_tag_manifest.py")
)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

MANIFEST = """\
[package]
name = "mcp-gateway"
version = "{version}"
edition = "2024"
"""

LOCKFILE = """\
version = 4

[[package]]
name = "anyhow"
version = "1.0.100"

[[package]]
name = "mcp-gateway"
version = "{version}"
dependencies = [
 "anyhow",
]
"""


@contextlib.contextmanager
def repo(manifest_version, lock_version=None, lock_crate="mcp-gateway"):
    """A throwaway root carrying a manifest and lockfile at the given versions."""
    with tempfile.TemporaryDirectory() as directory:
        root = pathlib.Path(directory)
        (root / "Cargo.toml").write_text(
            MANIFEST.format(version=manifest_version), encoding="utf-8"
        )
        (root / "Cargo.lock").write_text(
            LOCKFILE.format(version=lock_version or manifest_version).replace(
                'name = "mcp-gateway"\nversion', f'name = "{lock_crate}"\nversion'
            ),
            encoding="utf-8",
        )
        yield root


def run(root, tag=None, env=None, output=None):
    """Drive the gate's CLI, returning (exit code, stderr text)."""
    argv = ["check_tag_manifest.py", "--root", str(root)]
    if tag is not None:
        argv += ["--tag", tag]
    environ = {"GITHUB_REF_NAME": ""}
    environ.update(env or {})
    if output is not None:
        environ["GITHUB_OUTPUT"] = str(output)
    stderr = io.StringIO()
    with (
        mock.patch("sys.argv", argv),
        mock.patch.dict(gate.os.environ, environ, clear=True),
        contextlib.redirect_stdout(io.StringIO()),
        contextlib.redirect_stderr(stderr),
    ):
        return gate.main(), stderr.getvalue()


class PrereleasePredicate(unittest.TestCase):
    def test_hyphen_marks_a_prerelease(self):
        self.assertTrue(gate.is_prerelease("4.0.0-rc.1"))

    def test_plain_version_is_stable(self):
        self.assertFalse(gate.is_prerelease("4.0.0"))

    def test_hyphen_in_build_metadata_is_still_stable(self):
        # semver §10: build metadata may carry hyphens and does not make a
        # prerelease. Testing the whole string would misclassify this as an rc
        # and withhold a stable release from every channel.
        self.assertFalse(gate.is_prerelease("4.0.0+build-linux"))

    def test_prerelease_with_build_metadata_is_a_prerelease(self):
        self.assertTrue(gate.is_prerelease("4.0.0-rc.1+build-linux"))


class TagManifestAgreement(unittest.TestCase):
    def test_matching_stable_tag_passes(self):
        with repo("4.0.0") as root:
            code, _ = run(root, tag="v4.0.0")
        self.assertEqual(code, 0)

    def test_matching_prerelease_tag_passes(self):
        with repo("4.0.0-rc.1") as root:
            code, _ = run(root, tag="v4.0.0-rc.1")
        self.assertEqual(code, 0)

    def test_prerelease_tag_on_a_stable_manifest_fails(self):
        # The defect this gate exists for: cargo publish would take 4.0.0 from
        # the manifest and ship the candidate as the final release.
        with repo("4.0.0") as root:
            code, stderr = run(root, tag="v4.0.0-rc.1")
        self.assertEqual(code, 1)
        self.assertIn("Cargo.toml version is '4.0.0'", stderr)

    def test_stable_tag_on_a_prerelease_manifest_fails(self):
        with repo("4.0.0-rc.1") as root:
            code, stderr = run(root, tag="v4.0.0")
        self.assertEqual(code, 1)
        self.assertIn("4.0.0-rc.1", stderr)

    def test_lockfile_disagreeing_with_a_matching_manifest_fails(self):
        with repo("4.0.0-rc.1", lock_version="4.0.0") as root:
            code, stderr = run(root, tag="v4.0.0-rc.1")
        self.assertEqual(code, 1)
        self.assertIn("Cargo.lock", stderr)

    def test_lockfile_without_the_crate_fails(self):
        with repo("4.0.0", lock_crate="something-else") as root:
            code, stderr = run(root, tag="v4.0.0")
        self.assertEqual(code, 1)
        self.assertIn("no entry", stderr)


class EffectiveTag(unittest.TestCase):
    def test_ref_name_is_used_when_no_tag_is_passed(self):
        with repo("4.0.0") as root:
            code, _ = run(root, env={"GITHUB_REF_NAME": "v4.0.0"})
        self.assertEqual(code, 0)

    def test_tag_argument_wins_over_ref_name(self):
        # workflow_dispatch sets GITHUB_REF_NAME to the dispatch branch, so the
        # input has to override it or an rc dispatch is checked against 'main'.
        with repo("4.0.0-rc.1") as root:
            code, _ = run(root, tag="v4.0.0-rc.1", env={"GITHUB_REF_NAME": "main"})
        self.assertEqual(code, 0)

    def test_empty_tag_falls_back_to_ref_name(self):
        # release.yml passes `--tag "$INPUT_TAG"` unconditionally, and
        # inputs.tag renders empty on a tag push. The fallback therefore has to
        # be keyed on emptiness, not on the argument being absent: keyed on
        # absence, the main release path would exit 2 and block every publish.
        with repo("4.0.0") as root:
            code, _ = run(root, tag="", env={"GITHUB_REF_NAME": "v4.0.0"})
        self.assertEqual(code, 0)

    def test_empty_tag_and_ref_name_is_unusable(self):
        with repo("4.0.0") as root:
            code, stderr = run(root, tag="")
        self.assertEqual(code, 2)
        self.assertIn("No tag to check", stderr)

    def test_non_tag_ref_is_unusable(self):
        with repo("4.0.0") as root:
            code, stderr = run(root, env={"GITHUB_REF_NAME": "main"})
        self.assertEqual(code, 2)
        self.assertIn("does not start with 'v'", stderr)

    def test_non_semver_tag_is_unusable(self):
        with repo("4.0.0") as root:
            code, stderr = run(root, tag="v4.0")
        self.assertEqual(code, 2)
        self.assertIn("not a semver version", stderr)


class WorkflowOutputs(unittest.TestCase):
    def outputs(self, manifest_version, tag):
        with repo(manifest_version) as root:
            path = root / "gh-output"
            path.touch()
            code, _ = run(root, tag=tag, output=path)
            return code, dict(
                line.split("=", 1) for line in path.read_text().splitlines()
            )

    def test_prerelease_tag_exports_true(self):
        code, outputs = self.outputs("4.0.0-rc.1", "v4.0.0-rc.1")
        self.assertEqual(code, 0)
        self.assertEqual(
            outputs,
            {"tag": "v4.0.0-rc.1", "version": "4.0.0-rc.1", "is_prerelease": "true"},
        )

    def test_stable_tag_exports_false(self):
        # Lowercase: consumers compare against the string 'true' in a GitHub
        # expression, where Python's 'False' would also be truthy as a string.
        code, outputs = self.outputs("4.0.0", "v4.0.0")
        self.assertEqual(code, 0)
        self.assertEqual(
            outputs,
            {"tag": "v4.0.0", "version": "4.0.0", "is_prerelease": "false"},
        )

    def test_version_output_drops_the_leading_v(self):
        # Both ghcr publishers must agree on the image tag; ci.yml historically
        # pushed ':v4.0.0-rc.1' while docker.yml pushed ':4.0.0-rc.1'.
        _, outputs = self.outputs("4.0.0-rc.1", "v4.0.0-rc.1")
        self.assertEqual(outputs["version"], "4.0.0-rc.1")

    def test_a_mismatch_writes_no_outputs(self):
        with repo("4.0.0") as root:
            path = root / "gh-output"
            path.touch()
            code, _ = run(root, tag="v4.0.0-rc.1", output=path)
            self.assertEqual(code, 1)
            self.assertEqual(path.read_text(), "")


if __name__ == "__main__":
    unittest.main()
