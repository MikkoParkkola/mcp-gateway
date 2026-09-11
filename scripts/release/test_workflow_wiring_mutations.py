# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Mutation evidence for the workflow-wiring assertions in the gate's test suite.

An assertion over workflow text can pass for the wrong reason — a presence
check satisfied by a comment, a prefix match satisfied by a longer subcommand —
and nothing about a green suite says which. Each case below breaks one wiring
rule, or rewrites one in an equivalent spelling, and states the verdict the
suite has to return. A detection gap found once cannot return silently.

The suite reads the copied workflows, not the ones in the working tree: a
harness that edited them in place would leave a mutation behind on a crash.
"""

import pathlib
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve()
WORKFLOWS = HERE.parents[2] / ".github" / "workflows"
SUITE = HERE.with_name("test_check_tag_manifest.py")

CAUGHT, TOLERATED = "caught", "tolerated"

# (label, workflow, before, after, expected) — `before` must occur verbatim.
CASES = [
    # Regressions. Each is a rewiring that publishes wrongly or verifies
    # nothing, and each was reachable while the suite stayed green.
    (
        "verify-step-deleted",
        "ci.yml",
        '          cosign verify \\\n            --certificate-identity "${IDENTITY}" \\\n'
        "            --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \\\n"
        '            "ghcr.io/mikkoparkkola/mcp-gateway@${DIGEST}"\n',
        "",
        CAUGHT,
    ),
    (
        "identity-relaxed-to-a-regexp",
        "docker.yml",
        '--certificate-identity "${IDENTITY}"',
        '--certificate-identity-regexp ".*"',
        CAUGHT,
    ),
    (
        "sign-step-loses-its-digest-binding",
        "ci.yml",
        "      - name: Cosign keyless-sign the released image by digest\n"
        "        env:\n          DIGEST: ${{ steps.build.outputs.digest }}\n",
        "      - name: Cosign keyless-sign the released image by digest\n",
        CAUGHT,
    ),
    (
        "digest-rebound-to-a-tag",
        "ci.yml",
        "          DIGEST: ${{ steps.build.outputs.digest }}\n        run: cosign sign",
        "          DIGEST: ${{ steps.meta.outputs.version }}\n        run: cosign sign",
        CAUGHT,
    ),
    (
        "identity-points-at-the-other-publisher",
        "docker.yml",
        "/.github/workflows/docker.yml@${{ github.ref }}",
        "/.github/workflows/ci.yml@${{ github.ref }}",
        CAUGHT,
    ),
    (
        "gate-invocation-commented-out",
        "docker.yml",
        "        run: python3 scripts/release/check_tag_manifest.py",
        "        run: |\n          # python3 scripts/release/check_tag_manifest.py\n          true",
        CAUGHT,
    ),
    (
        "needs-verify-replaced-by-a-comment",
        "release.yml",
        "    needs: [build, verify]",
        "    needs: [build] # verify",
        CAUGHT,
    ),
    (
        "prerelease-skip-deleted",
        "release.yml",
        "needs.verify.outputs.is_prerelease != 'true'",
        "true",
        CAUGHT,
    ),
    (
        "dispatch-tag-moved-into-a-run-block",
        "release.yml",
        "        run: cargo fmt --all -- --check",
        "        run: echo ${{ inputs.tag }}",
        CAUGHT,
    ),
    # Equivalent spellings. A suite that fails these is a suite nobody can
    # reformat a workflow under, which is how textual assertions get deleted.
    (
        "digest-value-quoted",
        "ci.yml",
        "          DIGEST: ${{ steps.build.outputs.digest }}",
        '          DIGEST: "${{ steps.build.outputs.digest }}"',
        TOLERATED,
    ),
    (
        "trailing-comment-on-the-sign-command",
        "docker.yml",
        'run: cosign sign --yes "ghcr.io/mikkoparkkola/mcp-gateway@${DIGEST}"',
        'run: cosign sign --yes "ghcr.io/mikkoparkkola/mcp-gateway@${DIGEST}" # keyless, OIDC',
        TOLERATED,
    ),
    (
        "prerelease-condition-folded",
        "release.yml",
        "    if: needs.verify.outputs.is_prerelease != 'true'",
        "    if: >-\n      needs.verify.outputs.is_prerelease\n      != 'true'",
        TOLERATED,
    ),
    (
        "dispatch-tag-in-an-if-condition",
        "release.yml",
        "  verify:\n",
        "  verify:\n    if: ${{ inputs.tag != '' }}\n",
        TOLERATED,
    ),
    (
        "needs-in-block-form",
        "release.yml",
        "    needs: [build, verify]",
        "    needs:\n      - build\n      - verify",
        TOLERATED,
    ),
]


def verdict(directory, workflow, before, after):
    """Apply one mutation to the copied workflows and run the suite against it."""
    path = directory / workflow
    original = path.read_text(encoding="utf-8")
    if before not in original:
        return None
    path.write_text(original.replace(before, after, 1), encoding="utf-8")
    try:
        done = subprocess.run(
            [sys.executable, str(SUITE)],
            capture_output=True,
            text=True,
            env={"MCPGW_WORKFLOWS_DIR": str(directory), "PATH": "/usr/bin:/bin"},
        )
    finally:
        path.write_text(original, encoding="utf-8")
    return TOLERATED if done.returncode == 0 else CAUGHT


def main():
    failures = []
    with tempfile.TemporaryDirectory() as directory:
        copy = pathlib.Path(directory)
        shutil.copytree(WORKFLOWS, copy, dirs_exist_ok=True)
        for label, workflow, before, after, expected in CASES:
            got = verdict(copy, workflow, before, after)
            if got is None:
                failures.append(f"{label}: its anchor is no longer in {workflow}")
                print(f"STALE {label}")
                continue
            if got != expected:
                failures.append(f"{label}: expected {expected}, got {got}")
            print(f"{'ok   ' if got == expected else 'FAIL '}{label}: {got}")
    print()
    if failures:
        print(f"{len(failures)} of {len(CASES)} mutation cases disagree with the suite:")
        for line in failures:
            print(" -", line)
        return 1
    print(f"{len(CASES)} mutation cases agree with the suite")
    return 0


if __name__ == "__main__":
    sys.exit(main())
