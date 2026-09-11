# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Regression tests for the tag/manifest publish gate and its channel predicate."""

import contextlib
import importlib.util
import io
import pathlib
import re
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


WORKFLOWS = pathlib.Path(__file__).parents[2] / ".github" / "workflows"
JOB_HEADER = re.compile(r"^  ([A-Za-z][\w-]*):\s*$")
NEEDS = re.compile(r"^    needs:\s*(\S.*)$", re.MULTILINE)


def jobs(workflow):
    """Split a workflow's `jobs:` mapping into {name: body text}."""
    lines = (WORKFLOWS / workflow).read_text(encoding="utf-8").splitlines()
    start = lines.index("jobs:") + 1
    found, name, body = {}, None, []
    for line in lines[start:]:
        header = JOB_HEADER.match(line)
        if header:
            if name:
                found[name] = "\n".join(body)
            name, body = header.group(1), []
        elif name:
            body.append(line)
    if name:
        found[name] = "\n".join(body)
    return found


class WorkflowWiring(unittest.TestCase):
    """The gate is only worth what the workflows calling it are wired to do.

    These read the workflow text rather than run it. They cannot prove a
    release publishes correctly — only CI on a real tag does that — but they
    catch the rewiring mistakes that are silent at author time and only visible
    once a release has already gone to the wrong channel.
    """

    def test_every_reader_of_verify_outputs_needs_verify_directly(self):
        # `needs` exposes direct dependencies only. A job that reads
        # needs.verify.outputs.is_prerelease while reaching verify transitively
        # gets the empty string, which is not 'true', so a release candidate
        # publishes down every stable path. Nothing fails at author time.
        for name, body in jobs("release.yml").items():
            if "needs.verify.outputs." not in body:
                continue
            declared = NEEDS.search(body)
            self.assertIsNotNone(declared, f"{name} reads verify's outputs with no needs:")
            self.assertRegex(
                declared.group(1),
                r"\bverify\b",
                f"{name} reads verify's outputs without naming verify in needs:",
            )

    def test_all_three_tag_triggered_workflows_run_the_gate(self):
        # release.yml, ci.yml and docker.yml each fire on the same `v*` tag and
        # none can read another's job outputs, so each has to run the gate
        # itself. Dropping it from one leaves that workflow's publishes
        # ungated while the other two stay green.
        for workflow in ("release.yml", "ci.yml", "docker.yml"):
            text = (WORKFLOWS / workflow).read_text(encoding="utf-8")
            self.assertIn("scripts/release/check_tag_manifest.py", text, workflow)
            self.assertIn("scripts/release/test_check_tag_manifest.py", text, workflow)

    def test_prerelease_skips_are_declared_where_they_are_claimed(self):
        # The three stable-only surfaces. Each is skipped by an expression
        # rather than by a comment; losing the expression publishes a candidate
        # to a channel nobody opted into.
        self.assertRegex(
            jobs("release.yml")["homebrew-update"],
            r"if:.*needs\.verify\.outputs\.is_prerelease != 'true'",
        )
        self.assertRegex(
            jobs("docker.yml")["publish-mcp-registry"],
            r"if:.*needs\.build\.outputs\.is_prerelease != 'true'",
        )
        self.assertRegex(
            jobs("ci.yml")["docker"],
            r"is_prerelease != 'true' && 'ghcr\.io/[^']*:latest'",
        )

    def test_both_ghcr_publishers_sign_what_they_push(self):
        # Both push :VERSION from the same commit on the same tag with no
        # ordering between them, so the name resolves to whichever pushed last.
        # If only one signs, that name can carry no signature at all while the
        # signing workflow's own verify-by-digest still passes.
        for workflow in ("ci.yml", "docker.yml"):
            text = (WORKFLOWS / workflow).read_text(encoding="utf-8")
            self.assertIn("cosign sign --yes", text, workflow)
            # Match the flag, not the line continuation: folding the flags onto
            # one line must not turn this red.
            self.assertRegex(
                text,
                r"cosign verify(?![-\w])[\s\\]*--certificate-identity",
                workflow,
            )

    def test_the_dispatch_tag_is_not_interpolated_into_a_shell_command(self):
        # A dispatch input expanded inside `run:` is substituted before bash
        # parses the line, so shell metacharacters in a tag would execute on the
        # runner holding the publishing credentials.
        for line in (WORKFLOWS / "release.yml").read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or not stripped.startswith("run:"):
                continue
            self.assertNotIn("inputs.tag", stripped, line)
