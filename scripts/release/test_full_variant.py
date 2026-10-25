# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The image and release publishing guards of the 3.5.x line (MIK-8831 REL).

ci.yml has one read-only image check (`docker-check`: build, Trivy, smoke on
every push and pull request) and one image publisher (`docker`), which runs as
a whole only for a pushed `v*` tag, after every gate and the check. Floating
aliases (`major.minor`, `latest`) go only on a stable `vX.Y.Z` tag, and every
pushed name is verified to resolve to the signed digest. docker.yml publishes
nothing and writes no build cache. release.yml's publishing jobs run only for
a pushed tag, so a manual dispatch verifies and builds but publishes nothing.

Read as text, standard library only. A guard counts only as a whole,
uncommented `if:` line with exactly the expected condition, so a commented-out
or widened guard fails. Mutation cases show each check fails when its guard,
a prerequisite or a permission is removed or weakened.
"""

import pathlib
import re
import unittest

WORKFLOWS = pathlib.Path(__file__).parents[2] / ".github" / "workflows"
GUARD = "if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')"
GATES = [
    "check",
    "test",
    "fmt",
    "audit",
    "secrets-scan",
    "secret-leak-lint",
    "public-claims",
    "public-repo-hygiene",
    "service-template-smoke",
    "usability-smoke",
    "helm-chart-smoke",
    "helm-oci-roundtrip",
    "helm-supply-chain",
    "helm-airgap",
    "docker-check",
]
RELEASE_PUBLISHERS = {
    "release": "build",
    "publish": "release",
    "npm-publish": "release",
    "homebrew-update": "release",
}


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


def guarded(header):
    """Whether `header` holds the guard as one whole, uncommented line."""
    return re.search(rf"^    {re.escape(GUARD)}[ \t]*$", header, re.M) is not None


def needs(header):
    match = re.search(r"^    needs: \[([^\]]*)\]", header, re.M) or re.search(
        r"^    needs: (\S+)", header, re.M
    )
    return {item.strip() for item in match.group(1).split(",")} if match else set()


def permission_lines(header):
    return set(re.findall(r"^      ([a-z-]+): write", header, re.M))


def check_ci(text):
    check = job(text, "docker-check")
    head = job_header(check)
    assert "if:" not in head, "the image check runs on every push and pull request"
    assert permission_lines(head) == set(), "the image check holds no write permission"
    for name in ("Trivy image scan", "Smoke the image"):
        assert f"name: {name}" in check, f"the image check runs {name!r}"
    assert "cache-to" not in check, "an untrusted build writes no shared cache"

    docker = job(text, "docker")
    head = job_header(docker)
    assert guarded(head), "the publisher runs only for a pushed v* tag"
    assert needs(head) >= set(GATES), f"the publisher misses gates: {set(GATES) - needs(head)}"
    assert permission_lines(head) == {"packages", "id-token"}
    assert "cache-to" not in docker
    meta = step(docker, "Extract tag")
    assert r'[[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]' in meta, (
        "floating aliases only on a stable vX.Y.Z tag"
    )
    for alias in ('${image}:${version}', '${image}:v${version}', "${image}:sha-${GITHUB_SHA::7}"):
        assert alias in meta, f"every release gets {alias}"
    stable = meta.split("then", 1)[1].split("fi", 1)[0]
    for alias in ("${image}:${version%.*}", "${image}:latest"):
        assert alias in stable, f"{alias} is applied inside the stable-tag branch only"
    push = step(docker, "Build and push")
    assert "tags: ${{ steps.meta.outputs.tags }}" in push
    verify = step(docker, "Verify every alias resolves to the signed digest")
    assert "TAGS: ${{ steps.meta.outputs.tags }}" in verify, "every pushed name is verified"

    registry = job(text, "publish-mcp-registry")
    head = job_header(registry)
    assert guarded(head), "the registry publish runs only for a pushed v* tag"
    assert needs(head) == {"docker"}, "it waits for the verified image"
    audit = job(text, "audit")
    assert "osv-scanner-action" in audit and "--config=.github/osv-scanner.toml" in audit


def check_docker(text):
    head = text.split("\njobs:", 1)[0]
    assert "tags:" not in head, "docker.yml has no tag trigger"
    for banned in ("packages: write", "id-token: write", "login-action", "push: true", "push: ${{", "cache-to", "publish-mcp-registry"):
        assert banned not in text, f"docker.yml publishes nothing: found {banned!r}"


def check_release(text):
    for name, parent in RELEASE_PUBLISHERS.items():
        head = job_header(job(text, name))
        assert guarded(head), f"release.yml job {name!r} is unguarded"
        assert parent in needs(head), f"release.yml job {name!r} lost its need on {parent!r}"


class PublishingGuards(unittest.TestCase):
    def setUp(self):
        self.ci = (WORKFLOWS / "ci.yml").read_text()
        self.docker = (WORKFLOWS / "docker.yml").read_text()
        self.release = (WORKFLOWS / "release.yml").read_text()

    def test_ci_has_one_guarded_publisher_and_a_read_only_check(self):
        check_ci(self.ci)

    def test_docker_yml_publishes_nothing(self):
        check_docker(self.docker)

    def test_release_dispatch_publishes_nothing(self):
        check_release(self.release)

    def mutated(self, text, old, new):
        result = text.replace(old, new, 1)
        self.assertNotEqual(result, text, f"mutation did not apply: {old!r}")
        return result

    def test_a_removed_publisher_guard_is_caught(self):
        text = self.mutated(self.ci, f"    {GUARD}\n    #\n", "    #\n")
        with self.assertRaises(AssertionError):
            check_ci(text)

    def test_a_commented_out_guard_is_caught(self):
        text = self.mutated(self.ci, f"    {GUARD}\n    #\n", f"    # {GUARD}\n    #\n")
        with self.assertRaises(AssertionError):
            check_ci(text)

    def test_a_guard_widened_to_dispatch_is_caught(self):
        widened = "if: startsWith(github.ref, 'refs/tags/v')"
        text = self.mutated(self.ci, f"    {GUARD}\n    #\n", f"    {widened}\n    #\n")
        with self.assertRaises(AssertionError):
            check_ci(text)

    def test_a_dropped_gate_is_caught(self):
        text = self.mutated(self.ci, "helm-airgap, docker-check]", "helm-airgap]")
        with self.assertRaises(AssertionError):
            check_ci(text)

    def test_write_permission_on_the_check_is_caught(self):
        check_block = job(self.ci, "docker-check")
        widened = check_block.replace(
            "      contents: read\n", "      contents: read\n      packages: write\n", 1
        )
        text = self.mutated(self.ci, check_block, widened)
        with self.assertRaises(AssertionError):
            check_ci(text)

    def test_latest_on_a_pre_release_tag_is_caught(self):
        meta = step(job(self.ci, "docker"), "Extract tag")
        unconditional = meta.replace(
            '${image}:sha-${GITHUB_SHA::7}"',
            '${image}:sha-${GITHUB_SHA::7}\n          ${image}:latest"',
            1,
        ).replace("          ${image}:latest\"\n          fi", "          \"\n          fi", 1)
        text = self.mutated(self.ci, meta, unconditional)
        with self.assertRaises(AssertionError):
            check_ci(text)

    def test_a_dispatched_release_job_is_caught(self):
        text = self.mutated(self.release,
                    f"  publish:\n    needs: release\n    {GUARD}\n",
                    "  publish:\n    needs: release\n")
        with self.assertRaises(AssertionError):
            check_release(text)

    def test_a_release_job_that_lost_its_need_is_caught(self):
        text = self.mutated(self.release,
                    f"  npm-publish:\n    needs: release\n    {GUARD}\n",
                    f"  npm-publish:\n    {GUARD}\n")
        with self.assertRaises(AssertionError):
            check_release(text)

    def test_a_tag_trigger_on_docker_yml_is_caught(self):
        text = self.mutated(self.docker, "on:\n  push:\n", "on:\n  push:\n    tags: ['v*']\n")
        with self.assertRaises(AssertionError):
            check_docker(text)


if __name__ == "__main__":
    unittest.main()
