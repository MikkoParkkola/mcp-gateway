# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The image and release publishing guards of the 3.5.x line (MIK-8831 REL).

ci.yml's docker job is the only image publisher: its build, scan and smoke run
on every push and pull request, and every step that logs in, pushes, signs,
attests or verifies runs only for a pushed `v*` tag. docker.yml publishes
nothing. release.yml's publishing jobs run only for a pushed tag, so a manual
dispatch verifies and builds but publishes nothing.

Read as text, standard library only: each job is the block under its two-space
key, each step the block starting at its `- ` line. The mutation cases show the
checks fail when a guard is removed.
"""

import pathlib
import re
import unittest

WORKFLOWS = pathlib.Path(__file__).parents[2] / ".github" / "workflows"
GUARD = "if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')"

PUBLISH_STEPS = [
    "Extract tag",
    "Log in to GHCR",
    "Build and push",
    "Install cosign",
    "Install syft (SBOM)",
    "Cosign keyless-sign the released image by digest",
    "Generate + attest an SBOM (SPDX JSON) for the released image",
    "Verify the release signature + SBOM attestation",
    "Verify every alias resolves to the signed digest",
]
ALWAYS_STEPS = [
    "Build the image for the scan and smoke (load locally, no push)",
    "Trivy image scan (block on fixable HIGH/CRITICAL CVEs)",
    "Smoke the image",
]
RELEASE_PUBLISHERS = ["release", "publish", "npm-publish", "homebrew-update"]


def job(text, name):
    """The block of job `name`: its key line up to the next job key."""
    match = re.search(rf"^  {re.escape(name)}:\n(.*?)(?=^  \S|\Z)", text, re.M | re.S)
    if match is None:
        raise AssertionError(f"no job {name!r}")
    return match.group(1)


def job_header(block):
    """The job's own keys, before its steps."""
    return block.split("    steps:", 1)[0]


def step(block, name):
    """The step named `name` in a job block."""
    for chunk in re.split(r"^      - ", block, flags=re.M)[1:]:
        if chunk.startswith(f"name: {name}\n"):
            return chunk
    raise AssertionError(f"no step {name!r}")


def check_ci(text):
    docker = job(text, "docker")
    assert "if:" not in job_header(docker), "the docker job itself must run on every push"
    for needed in ("audit", "secrets-scan", "secret-leak-lint", "test", "check"):
        assert re.search(rf"needs: \[[^\]]*\b{needed}\b", docker), f"docker needs {needed}"
    for name in PUBLISH_STEPS:
        assert GUARD in step(docker, name), f"{name!r} is not guarded to a pushed tag"
    for name in ALWAYS_STEPS:
        assert "if:" not in step(docker, name), f"{name!r} must run on every push"
    meta = step(docker, "Extract tag")
    assert 'version="${GITHUB_REF#refs/tags/v}"' in meta
    assert 'echo "major_minor=${version%.*}"' in meta
    assert 'echo "sha=sha-${GITHUB_SHA::7}"' in meta
    tags = step(docker, "Build and push")
    for tag in (
        ":${{ steps.meta.outputs.version }}",
        ":v${{ steps.meta.outputs.version }}",
        ":${{ steps.meta.outputs.major_minor }}",
        ":latest",
        ":${{ steps.meta.outputs.sha }}",
    ):
        assert tag in tags, f"the release pushes {tag}"
    registry = job(text, "publish-mcp-registry")
    assert GUARD in job_header(registry), "the registry publish is guarded to a pushed tag"
    assert "needs: docker" in job_header(registry), "it waits for the verified image"
    audit = job(text, "audit")
    assert "osv-scanner-action" in audit and "--config=.github/osv-scanner.toml" in audit


def check_docker(text):
    head = text.split("\njobs:", 1)[0]
    assert "tags:" not in head, "docker.yml has no tag trigger"
    assert "packages: write" not in text
    assert "login-action" not in text
    assert "push: true" not in text and "push: ${{" not in text
    assert "publish-mcp-registry" not in text


def check_release(text):
    for name in RELEASE_PUBLISHERS:
        assert GUARD in job_header(job(text, name)), f"release.yml job {name!r} is unguarded"


class PublishingGuards(unittest.TestCase):
    def setUp(self):
        self.ci = (WORKFLOWS / "ci.yml").read_text()
        self.docker = (WORKFLOWS / "docker.yml").read_text()
        self.release = (WORKFLOWS / "release.yml").read_text()

    def test_ci_docker_job_is_the_only_publisher_and_guarded(self):
        check_ci(self.ci)

    def test_docker_yml_publishes_nothing(self):
        check_docker(self.docker)

    def test_release_dispatch_publishes_nothing(self):
        check_release(self.release)

    def test_a_removed_step_guard_is_caught(self):
        push = step(job(self.ci, "docker"), "Build and push")
        mutated = self.ci.replace(push, push.replace(f"        {GUARD}\n", "", 1), 1)
        self.assertNotEqual(mutated, self.ci)
        with self.assertRaises(AssertionError):
            check_ci(mutated)

    def test_a_dispatched_release_job_is_caught(self):
        mutated = self.release.replace(
            f"  publish:\n    needs: release\n    {GUARD}\n", "  publish:\n    needs: release\n", 1
        )
        self.assertNotEqual(mutated, self.release)
        with self.assertRaises(AssertionError):
            check_release(mutated)

    def test_a_tag_trigger_on_docker_yml_is_caught(self):
        mutated = self.docker.replace("on:\n  push:\n", "on:\n  push:\n    tags: ['v*']\n", 1)
        with self.assertRaises(AssertionError):
            check_docker(mutated)


if __name__ == "__main__":
    unittest.main()
