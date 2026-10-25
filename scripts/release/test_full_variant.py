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

    assert re.search(r"^    concurrency:\n      group: ghcr-publish\n      cancel-in-progress: false$", head, re.M), (
        "publishers run one at a time and are never cancelled mid-release"
    )

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
            ["bash", "-eo", "pipefail", "-c", "\n".join(lines)], env=full_env, capture_output=True, text=True, timeout=30
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

    def test_a_failed_tag_query_fails_the_release(self):
        rc, _ = run_script(
            self.ci,
            "Extract tag",
            {"GITHUB_REF": "refs/tags/v3.5.2", "GITHUB_SHA": "1234567890abcdef"},
            {"git": "exit 128\n"},
        )
        self.assertNotEqual(rc, 0, "a stable release must not ship without knowing latest")

    def push(self, remote, docker_push_rc=0):
        """Run the push step for 3.5.2 with stub docker and git; returns
        (exit code, outputs, pushed references)."""
        image = "ghcr.io/mikkoparkkola/mcp-gateway"
        tags = "\n".join(f"{image}:{t}" for t in ("3.5.2", "v3.5.2", "sha-1234567", "3.5", "latest"))
        with tempfile.TemporaryDirectory() as tmp:
            log = pathlib.Path(tmp, "pushed")
            docker = (
                f'case "$1" in\n'
                f'  push) echo "$2" >> "{log}"; exit {docker_push_rc} ;;\n'
                f'  inspect) echo "{image}@sha256:abc" ;;\n'
                f"esac\n"
            )
            stubs = {"docker": docker, **remote_tags(*remote)}
            rc, out = run_script(self.ci, "Push the scanned image", {"TAGS": tags, "VERSION": "3.5.2"}, stubs)
            pushed = log.read_text().split() if log.exists() else []
        return rc, out, pushed

    def test_the_push_sends_every_name_latest_last_and_records_the_digest(self):
        rc, out, pushed = self.push(["3.5.1", "3.5.2"])
        self.assertEqual(rc, 0)
        self.assertEqual(pushed[-1], "ghcr.io/mikkoparkkola/mcp-gateway:latest")
        self.assertEqual(len(pushed), 5)
        self.assertIn("digest=sha256:abc", out)
        self.assertIn("latest=true", out)

    def test_a_newer_release_tagged_meanwhile_keeps_latest(self):
        rc, out, pushed = self.push(["3.5.2", "3.5.3"])
        self.assertEqual(rc, 0)
        self.assertNotIn("ghcr.io/mikkoparkkola/mcp-gateway:latest", pushed)
        self.assertIn("latest=false", out)

    def test_a_failed_push_fails_the_release(self):
        rc, _, _ = self.push(["3.5.2"], docker_push_rc=1)
        self.assertNotEqual(rc, 0)

    def test_an_alias_on_another_digest_fails_the_release(self):
        tags = "ghcr.io/mikkoparkkola/mcp-gateway:3.5.2\nghcr.io/mikkoparkkola/mcp-gateway:latest"
        docker = 'case "$*" in *:latest*) echo \'"sha256:other"\' ;; *) echo \'"sha256:signed"\' ;; esac\n'
        rc, _ = run_script(
            self.ci,
            "Verify every alias resolves to the signed digest",
            {"DIGEST": "sha256:signed", "TAGS": tags, "LATEST": "true"},
            {"docker": docker},
        )
        self.assertNotEqual(rc, 0, "a stale alias must fail the release")
        rc, _ = run_script(
            self.ci,
            "Verify every alias resolves to the signed digest",
            {"DIGEST": "sha256:signed", "TAGS": tags, "LATEST": "false"},
            {"docker": docker},
        )
        self.assertEqual(rc, 0, "latest left to a newer release is not this one's to verify")
        same = 'echo \'"sha256:signed"\'\n'
        rc, _ = run_script(
            self.ci,
            "Verify every alias resolves to the signed digest",
            {"DIGEST": "sha256:signed", "TAGS": tags, "LATEST": "true"},
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



# The `-full` variant stage, as main pins it (MIK-8831 REL, ported from
# scripts/release/test_check_tag_manifest.py on main).
DOCKERFILE = pathlib.Path(
    os.environ.get("MCPGW_DOCKERFILE")
    or pathlib.Path(__file__).parents[2] / "Dockerfile"
)
TINI_INSTALLED = r"apt-get install(?:[^&\n\\]|\\.|\\\n)*?\btini\b"


class VariantStage(unittest.TestCase):
    """The third stage, read rather than assumed.

    Docker builds the file’s last stage when a build names none, so the
    variant being last is what makes an untargeted build dangerous -- and what
    makes the base stage’s name load-bearing.
    """

    def setUp(self):
        self.body = DOCKERFILE.read_text()

    def test_the_variant_is_the_last_stage_and_runtime_is_named(self):
        stages = re.findall(r"(?m)^FROM\s+(\S+)(?:\s+AS\s+(\S+))?\s*$", self.body)
        self.assertTrue(stages, "the Dockerfile declares no stage")
        self.assertEqual(
            stages[-1][1],
            "runtime-full",
            "the variant is not the file's last stage",
        )
        names = [name for _, name in stages]
        self.assertIn("runtime", names, "the base stage is no longer named")

    def variant_stage(self):
        # Comments dropped: an instruction installs a tool, a comment naming one
        # installs nothing.
        body = "\n".join(
            line
            for line in self.body.splitlines()
            if not line.lstrip().startswith("#")
        )
        return body[body.index("FROM runtime AS runtime-full") :]

    def test_the_variant_installs_what_its_smoke_gate_exercises(self):
        stage = self.variant_stage()
        for tool in ("nodejs", "git", "openssh-client"):
            self.assertRegex(
                stage,
                rf"apt-get install[^\n]*(?:\n[^\n]*)*?\b{re.escape(tool)}\b",
                f"the variant stage does not apt-get install {tool}",
            )
        self.assertRegex(
            stage,
            r"COPY --from=ghcr\.io/astral-sh/uv:\d+\.\d+\.\d+@sha256:[0-9a-f]{64}\s+/uv\s+/uvx\s",
            "the variant stage does not install uv from a digest-pinned image",
        )

    def test_the_variant_executes_no_downloaded_installer(self):
        # A fetched script runs whatever its URL serves on the day of the build.
        # Node's integrity rests on apt verifying packages against a key whose
        # fingerprint is pinned here, and uv's on an image digest.
        stage = self.variant_stage()
        for script in (r"setup_\d+\.x", r"install\.sh"):
            self.assertNotRegex(
                stage, script, f"the variant stage executes a downloaded {script}"
            )
        self.assertIn(
            "6F71F525282841EEDAF851B42F59B5F99B1BE0B4",
            stage,
            "the variant stage does not pin the NodeSource signing key fingerprint",
        )

    def test_the_nodesource_key_guard_binds_the_primary_fingerprint(self):
        # The pin must name the key apt will trust, which is the key file's one
        # primary key. A subkey's fingerprint is printed too, so a file whose
        # primary is someone else's and which carries NodeSource's key as a
        # subkey would pass a check that matched any `fpr` line. The guard is run
        # as the Dockerfile writes it, against gpg's colon output.
        match = re.search(
            r"gpg --show-keys --with-colons /tmp/nodesource\.key \| awk -F: \\\n\s*'([^']*)'",
            self.variant_stage(),
        )
        self.assertIsNotNone(match, "the variant stage has no NodeSource key guard")
        pinned = "6F71F525282841EEDAF851B42F59B5F99B1BE0B4"
        other = "0123456789ABCDEF0123456789ABCDEF01234567"
        subkey = "0FA5ECC8C0CA58863C0AC5867E9656125E955B26"
        pub = "pub:-:2048:1:2F59B5F99B1BE0B4:1464022864:::-:::scESC::::::23::0:"
        sub = "sub:-:2048:1:7E9656125E955B26:1464022864::::::e::::::23:"
        uid = "uid:-::::1464022864::0::NodeSource <gpg@nodesource.com>::::::::::0:"
        cases = {
            "the published key": ([pub, f"fpr:::::::::{pinned}:", uid, sub, f"fpr:::::::::{subkey}:"], True),
            "another primary key": ([pub, f"fpr:::::::::{other}:", uid], False),
            "two primary keys": ([pub, f"fpr:::::::::{other}:", pub, f"fpr:::::::::{pinned}:"], False),
            "NodeSource's key as a subkey": ([pub, f"fpr:::::::::{other}:", uid, sub, f"fpr:::::::::{pinned}:"], False),
            "an empty key file": ([], False),
        }
        for label, (lines, accepted) in cases.items():
            run = subprocess.run(
                ["awk", "-F:", match.group(1)],
                input="".join(f"{line}\n" for line in lines),
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(run.returncode == 0, accepted, f"{label}: exit {run.returncode}")

    def test_apt_trusts_only_the_pinned_nodesource_key(self):
        # `gpg --show-keys` leaves out a primary key that has no user ID, while
        # `gpg --dearmor` keeps every key in the file, so the guard above cannot
        # see everything apt would trust. A fingerprint in Signed-By makes apt
        # itself select only that key (and its subkeys) from the keyring.
        self.assertRegex(
            self.variant_stage(),
            r"Signed-By: /usr/share/keyrings/nodesource\.gpg 6F71F525282841EEDAF851B42F59B5F99B1BE0B4'",
            "apt trusts every key in the NodeSource keyring, not only the pinned one",
        )

    def test_the_variant_installs_what_a_deployment_declares(self):
        stage = self.variant_stage()
        self.assertRegex(
            stage,
            r"COPY[^\n]*docker/entrypoint-full\.sh",
            "the variant does not copy the entrypoint into the image",
        )
        self.assertRegex(
            stage,
            r"ENTRYPOINT \[[^\]]*entrypoint-full\.sh",
            "the variant does not run its own entrypoint",
        )
        script = (
            pathlib.Path(__file__).parents[2] / "docker" / "entrypoint-full.sh"
        ).read_text()
        self.assertIn(
            "EXTRA_APT_PACKAGES",
            script,
            "the entrypoint ignores the packages a deployment declares",
        )
        self.assertRegex(
            script,
            r"apt-get install",
            "the entrypoint never installs anything",
        )
        # Installing needs root, but the image must not *default* to it: a
        # deployment asks for root itself, and the entrypoint drops back.
        self.assertEqual(
            re.findall(r"(?m)^USER\s+(\S+)\s*$", stage)[-1],
            "gateway",
            "the variant leaves the image declaring root as its user",
        )

    def test_a_deployment_gets_its_startup_steps_before_the_gateway(self):
        script = (
            pathlib.Path(__file__).parents[2] / "docker" / "entrypoint-full.sh"
        ).read_text()
        self.assertRegex(
            script,
            r"/docker-entrypoint\.d",
            "the entrypoint has no drop-in directory for a deployment's steps",
        )
        self.assertRegex(
            script,
            r"\.envsh\)\s*\.\s*\"\$f\"|\.\s*\"\$f\"",
            "the entrypoint does not source an envsh drop-in",
        )
        self.assertRegex(
            script,
            r"\[ ! -x \"\$f\" \]",
            "the entrypoint runs a drop-in that arrived without the exec bit",
        )
        run = script.index("run_dropins\n")
        drop = script.index("setpriv --reuid=gateway")
        self.assertLess(
            run,
            drop,
            "the entrypoint drops privileges before a deployment's steps run, "
            "so a step that needs root would fail",
        )
        self.assertEqual(
            script.count("run_dropins\n"),
            2,
            "a path through the entrypoint skips the drop-ins: root and "
            "non-root each call them once",
        )

    def test_tini_is_pid_1_of_the_variant_only(self):
        # MIK-8352 TINI.1: tini -g in front of the entrypoint, so a stop reaches
        # a sourced step's foreground command. The default image keeps the
        # gateway itself as PID 1.
        stage = self.variant_stage()
        self.assertRegex(
            stage,
            TINI_INSTALLED,
            "the variant does not install tini",
        )
        self.assertRegex(
            stage,
            r'(?m)^ENTRYPOINT \["/usr/bin/tini", "-g", "--", '
            r'"/usr/local/bin/entrypoint-full\.sh"\]$',
            "the variant's PID 1 is not tini -g in front of its entrypoint",
        )
        base = self.body[: self.body.index("FROM runtime AS runtime-full")]
        self.assertRegex(
            base,
            r'(?m)^ENTRYPOINT \["mcp-gateway"\]$',
            "the default image's PID 1 is no longer the gateway",
        )

    def test_the_tini_pin_reads_only_the_install_command(self):
        # The command ends at `&&` or at a newline that is not escaped: a
        # `tini` after it (the ENTRYPOINT, a comment) installs nothing.
        installs = (
            "RUN apt-get install -y \\\n    curl \\\n    tini \\\n    && rm -rf x\n",
            "RUN apt-get install -y curl tini\n",
        )
        for stage in installs:
            with self.subTest(stage=stage):
                self.assertRegex(stage, TINI_INSTALLED)
        installs_nothing = (
            "RUN apt-get install -y curl\n"
            'ENTRYPOINT ["/usr/bin/tini", "-g", "--", "/x"]\n',
            "RUN apt-get install -y curl \\\n    && echo tini\n",
        )
        for stage in installs_nothing:
            with self.subTest(stage=stage):
                self.assertNotRegex(stage, TINI_INSTALLED)

    def test_the_variant_keeps_the_default_invocation(self):
        # An ENTRYPOINT declared in the stage resets the CMD the base stage set.
        # The variant's own invocation carries no arguments, so a variant
        # without it execs a gateway with no config that starts and never exits.
        self.assertRegex(
            self.variant_stage(),
            r'(?m)^CMD \["--config", "/config\.yaml"\]',
            "the variant declares an ENTRYPOINT without the base stage's CMD, "
            "so its default invocation is not the image's",
        )

    def test_a_startup_that_cannot_finish_stops_the_container(self):
        script = self.entrypoint_script()
        self.assertRegex(
            script,
            r"apt-get update[^\n]*&&[^\n]*apt-get install",
            "the entrypoint does not run the update and install as one chain",
        )
        # `set -e` does not end the script on a failing link of an `&&` list, so
        # the chain's status has to be carried to an explicit exit.
        self.assertRegex(
            script,
            r"install failed[^\n]*\n\s*exit 1",
            "the entrypoint does not stop the container when the install fails",
        )
        self.assertRegex(
            script,
            r"DEBIAN_FRONTEND=noninteractive",
            "the entrypoint lets apt prompt, which no container can answer",
        )
        self.assertRegex(
            script,
            r"timeout -k \d+ \"\$INSTALL_TIMEOUT\"",
            "the entrypoint leaves the install unbounded",
        )
        # PID 1 ignores SIGTERM with no handler installed, so without a trap a
        # stop during the install waits out the grace period and SIGKILLs.
        self.assertRegex(
            script,
            r"trap \w+ TERM",
            "the entrypoint does not handle a stop while the install runs",
        )

    def test_the_privilege_drop_names_the_user_it_drops_to(self):
        script = self.entrypoint_script()
        # A numeric group id is whatever this distribution put in it, and Debian
        # puts an unrelated `users` there.
        self.assertRegex(
            script,
            r"setpriv --reuid=gateway --regid=gateway --init-groups",
            "the entrypoint drops to a fixed id rather than the image's user",
        )
        self.assertNotRegex(
            script,
            r"--groups=\d",
            "the entrypoint drops to a fixed group id",
        )

    def test_the_lists_cleanup_removes_the_directory(self):
        script = self.entrypoint_script()
        self.assertRegex(
            script,
            r"(?m)^\s*rm -rf /var/lib/apt/lists\s*$",
            "the entrypoint leaves the apt indexes it fetched in the image",
        )
        self.assertNotRegex(
            script,
            r"/var/lib/apt/lists/\*",
            "the cleanup globs a directory whose indexes stay while globbing is "
            "off in that shell",
        )

    def entrypoint_script(self):
        return (
            pathlib.Path(__file__).parents[2] / "docker" / "entrypoint-full.sh"
        ).read_text()

    def test_the_node_and_npm_assertions_are_at_build_time(self):
        self.assertRegex(
            self.body,
            r"node --version \| grep -q '\^v24\\\.'",
            "the variant stage does not assert the Node major at build time",
        )
        self.assertRegex(
            self.body,
            r'npm install -g \./npm-\d+\.\d+\.\d+\.tgz',
            "the variant stage does not install npm from its verified tarball",
        )

    def test_every_npm_tarball_is_verified_against_a_pinned_hash(self):
        # A pinned version is still the registry's word on the bytes; the
        # sha512 (as in the registry's `dist.integrity`) is this repo's.
        # Continuations folded as Docker folds them, before the shell runs.
        stage = self.variant_stage().replace("\\\n", "")
        found = re.search(r'pins="([^"]*)"', stage)
        self.assertIsNotNone(found, "the variant stage declares no npm pins")
        pins = found.group(1).split()
        self.assertTrue(pins, "the variant stage's npm pin list is empty")
        for pin in pins:
            self.assertRegex(
                pin,
                r"^[a-z0-9._-]+@\d+\.\d+\.\d+:sha512-[A-Za-z0-9+/]{86}==$",
                f"{pin!r} is not name@version:sha512-<integrity>",
            )
        names = {pin.split("@")[0] for pin in pins}
        for name in ("npm", "brace-expansion", "ip-address", "tar", "undici"):
            self.assertIn(name, names, f"{name} is fetched without a pinned hash")
        # A pin that is never compared is text: the tarball must be hashed and
        # the result checked against it, as an exact string.
        self.assertIn("createHash('sha512')", stage)
        self.assertIn('test "${got}" = "${want}"', stage)
        # Every fetch goes through the verified list; a literal spec on an npm
        # command line would bypass it.
        self.assertNotRegex(
            stage,
            r"npm\s+(?:install|i|pack)\b[^\n]*[a-z]@\d",
            "an npm command fetches a spec that is not in the verified list",
        )


if __name__ == "__main__":
    unittest.main()
