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

import os
import pathlib
import re
import subprocess
import tempfile
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


def permission_block(header):
    """The job's `permissions:` entries, verbatim, one per line."""
    match = re.search(r"^    permissions:\n((?:      .*\n)+)", header, re.M)
    if match is None:
        return []
    return [line.split("#", 1)[0].strip() for line in match.group(1).splitlines()]


# The publisher's steps, each required, in this order.
PUBLISH_STEPS = [
    "Extract tag",
    "Build the release image (load locally)",
    "Trivy image scan (block on fixable HIGH/CRITICAL CVEs)",
    "Smoke the image",
    "Log in to GHCR",
    "Push the scanned image",
    "Install cosign",
    "Install syft (SBOM)",
    "Cosign keyless-sign the released image by digest",
    "Generate + attest an SBOM (SPDX JSON) for the released image",
    "Verify the release signature + SBOM attestation",
    "Verify every alias resolves to the signed digest",
]
CHECK_STEPS = [
    "Build the image for the scan and smoke (load locally, no push)",
    "Trivy image scan (block on fixable HIGH/CRITICAL CVEs)",
    "Smoke the image",
]


def step_names(block):
    return re.findall(r"^      - name: (.+)$", block, re.M)


def assert_steps(block, names, who):
    found = step_names(block)
    assert [n for n in found if n in names] == names, f"{who} steps out of order or missing: {found}"
    for name in names:
        body = step(block, name)
        assert not re.search(r"^        if:", body, re.M), f"{who} step {name!r} is conditional"
        assert "continue-on-error" not in body, f"{who} step {name!r} may fail open"
        if name.startswith("Trivy"):
            assert 'exit-code: "1"' in body, f"{who}'s scan does not fail the job"


def check_ci(text):
    check = job(text, "docker-check")
    head = job_header(check)
    assert "if:" not in head, "the image check runs on every push and pull request"
    assert permission_block(head) == ["contents: read"], (
        f"the image check holds exactly contents: read, not {permission_block(head)}"
    )
    assert_steps(check, CHECK_STEPS, "the image check")
    assert "cache-to" not in check and "cache-from" not in check, "no shared build cache"

    docker = job(text, "docker")
    head = job_header(docker)
    assert guarded(head), "the publisher runs only for a pushed v* tag"
    assert needs(head) >= set(GATES), f"the publisher misses gates: {set(GATES) - needs(head)}"
    assert permission_block(head) == ["contents: read", "packages: write", "id-token: write"]
    assert "cache-to" not in docker and "cache-from" not in docker
    assert_steps(docker, PUBLISH_STEPS, "the publisher")
    build = step(docker, "Build the release image (load locally)")
    assert "load: true" in build and "push:" not in build, "one local build, pushed after its scan"
    assert "tags: ${{ steps.meta.outputs.tags }}" in build
    verify = step(docker, "Verify every alias resolves to the signed digest")
    assert "TAGS: ${{ steps.meta.outputs.tags }}" in verify, "every pushed name is verified"

    registry = job(text, "publish-mcp-registry")
    head = job_header(registry)
    assert guarded(head), "the registry publish runs only for a pushed v* tag"
    assert needs(head) == {"docker"}, "it waits for the verified image"
    audit = job(text, "audit")
    assert "osv-scanner-action" in audit and "--config=.github/osv-scanner.toml" in audit


def run_script(text, step_name, env, stubs):
    """Run a step's `run:` script from ci.yml with `stubs` ({command: sh}) first
    on PATH. Returns (exit code, GITHUB_OUTPUT text)."""
    body = step(job(text, "docker"), step_name).split("        run: |\n", 1)[1]
    lines = []
    for line in body.split("\n"):
        if line.startswith("          ") or not line.strip():
            lines.append(line[10:])
        else:
            break
    with tempfile.TemporaryDirectory() as tmp:
        bin_dir = pathlib.Path(tmp, "bin")
        bin_dir.mkdir()
        for name, sh in stubs.items():
            path = bin_dir / name
            path.write_text("#!/bin/sh\n" + sh)
            path.chmod(0o755)
        output = pathlib.Path(tmp, "output")
        output.touch()
        full_env = {
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "GITHUB_OUTPUT": str(output),
            **env,
        }
        run = subprocess.run(
            ["bash", "-c", "\n".join(lines)], env=full_env, capture_output=True, text=True, timeout=30
        )
        return run.returncode, output.read_text()


def emitted_tags(output):
    block = output.split("tags<<EOF\n", 1)[1].split("\nEOF", 1)[0]
    return sorted(line for line in block.splitlines() if line)


def remote_tags(*versions):
    """A `git` stub whose ls-remote lists these release tags."""
    lines = "\\n".join(f"0000000000000000000000000000000000000000\\trefs/tags/v{v}" for v in versions)
    return {"git": f'printf "{lines}\\n"\n'}


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
        for extra in ("      packages: write\n", '      packages: "write"\n'):
            widened = check_block.replace("      contents: read\n", "      contents: read\n" + extra, 1)
            text = self.mutated(self.ci, check_block, widened)
            with self.subTest(extra=extra), self.assertRaises(AssertionError):
                check_ci(text)

    def test_a_removed_signing_step_is_caught(self):
        docker = job(self.ci, "docker")
        signing = "      - " + step(docker, "Cosign keyless-sign the released image by digest")
        text = self.mutated(self.ci, signing, "")
        with self.assertRaises(AssertionError):
            check_ci(text)

    def test_a_disabled_scan_is_caught(self):
        scan = step(job(self.ci, "docker"), "Trivy image scan (block on fixable HIGH/CRITICAL CVEs)")
        text = self.mutated(self.ci, scan, scan.replace('exit-code: "1"', 'exit-code: "0"', 1))
        with self.assertRaises(AssertionError):
            check_ci(text)

    def tags_for(self, ref, remote):
        rc, out = run_script(
            self.ci,
            "Extract tag",
            {"GITHUB_REF": ref, "GITHUB_SHA": "1234567890abcdef"},
            remote_tags(*remote),
        )
        self.assertEqual(rc, 0)
        return emitted_tags(out)

    def test_the_highest_stable_release_takes_every_name(self):
        image = "ghcr.io/mikkoparkkola/mcp-gateway"
        self.assertEqual(
            self.tags_for("refs/tags/v3.5.2", ["3.5.1", "3.5.2", "4.0.0-beta.3"]),
            sorted(f"{image}:{t}" for t in ("3.5.2", "v3.5.2", "sha-1234567", "3.5", "latest")),
        )

    def test_a_maintenance_release_of_an_older_line_never_takes_latest(self):
        image = "ghcr.io/mikkoparkkola/mcp-gateway"
        self.assertEqual(
            self.tags_for("refs/tags/v3.5.3", ["3.5.2", "3.5.3", "4.0.0"]),
            sorted(f"{image}:{t}" for t in ("3.5.3", "v3.5.3", "sha-1234567", "3.5")),
        )

    def test_a_pre_release_gets_only_its_own_names(self):
        image = "ghcr.io/mikkoparkkola/mcp-gateway"
        self.assertEqual(
            self.tags_for("refs/tags/v4.0.0-rc.1", ["3.5.2", "4.0.0-rc.1"]),
            sorted(f"{image}:{t}" for t in ("4.0.0-rc.1", "v4.0.0-rc.1", "sha-1234567")),
        )

    def test_an_alias_on_another_digest_fails_the_release(self):
        tags = "ghcr.io/mikkoparkkola/mcp-gateway:3.5.2\nghcr.io/mikkoparkkola/mcp-gateway:latest"
        docker = 'case "$*" in *:latest*) echo \'"sha256:other"\' ;; *) echo \'"sha256:signed"\' ;; esac\n'
        rc, _ = run_script(
            self.ci,
            "Verify every alias resolves to the signed digest",
            {"DIGEST": "sha256:signed", "TAGS": tags},
            {"docker": docker},
        )
        self.assertNotEqual(rc, 0, "a stale alias must fail the release")
        same = 'echo \'"sha256:signed"\'\n'
        rc, _ = run_script(
            self.ci,
            "Verify every alias resolves to the signed digest",
            {"DIGEST": "sha256:signed", "TAGS": tags},
            {"docker": same},
        )
        self.assertEqual(rc, 0, "every alias on the signed digest passes")

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
