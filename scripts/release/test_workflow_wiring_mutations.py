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
A case counts as caught only when an assertion failed — an exception exits
non-zero too, and reading that as a detection would report a gap as covered.
"""

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve()
WORKFLOWS = HERE.parents[2] / ".github" / "workflows"
SUITE = HERE.with_name("test_check_tag_manifest.py")

CAUGHT, TOLERATED, BROKEN = "caught", "tolerated", "broken"

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
        'cosign verify \\\n            --certificate-identity "${IDENTITY}"',
        'cosign verify \\\n            --certificate-identity-regexp ".*"',
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
    (
        "step-without-a-name-borrows-its-neighbours-digest",
        "ci.yml",
        "      - name: Generate + attest an SBOM (SPDX JSON) for the released image\n"
        "        env:\n          DIGEST: ${{ steps.build.outputs.digest }}\n",
        "      - id: attest\n"
        "        name: Generate + attest an SBOM (SPDX JSON) for the released image\n",
        CAUGHT,
    ),
    (
        "gate-invocation-echoed",
        "ci.yml",
        "        run: python3 scripts/release/check_tag_manifest.py",
        "        run: echo python3 scripts/release/check_tag_manifest.py",
        CAUGHT,
    ),
    (
        "gate-invocation-inside-an-echoed-string",
        "ci.yml",
        "        run: python3 scripts/release/check_tag_manifest.py",
        '        run: echo "skipped; python3 scripts/release/check_tag_manifest.py"',
        CAUGHT,
    ),
    (
        "gate-invocation-commented-out-in-ci",
        "ci.yml",
        "        run: python3 scripts/release/check_tag_manifest.py",
        "        run: |\n          # python3 scripts/release/check_tag_manifest.py\n          true",
        CAUGHT,
    ),
    (
        "gate-invocation-commented-out-in-release",
        "release.yml",
        '        run: python3 scripts/release/check_tag_manifest.py --tag "$INPUT_TAG"',
        "        run: |\n"
        '          # python3 scripts/release/check_tag_manifest.py --tag "$INPUT_TAG"\n'
        "          true",
        CAUGHT,
    ),
    (
        "prerelease-skip-moved-onto-a-step",
        "release.yml",
        "    if: needs.verify.outputs.is_prerelease != 'true'\n"
        "    runs-on: avrea-ubuntu-latest-4-vcpu\n\n"
        "    steps:\n      - name: Download checksums for the verified tag\n",
        "    runs-on: avrea-ubuntu-latest-4-vcpu\n\n"
        "    steps:\n      - name: Download checksums for the verified tag\n"
        "        if: needs.verify.outputs.is_prerelease != 'true'\n",
        CAUGHT,
    ),
    (
        "prerelease-skip-made-optional",
        "release.yml",
        "    if: needs.verify.outputs.is_prerelease != 'true'",
        "    if: needs.verify.outputs.is_prerelease != 'true' || true",
        CAUGHT,
    ),
    (
        "digest-reassigned-in-the-shell",
        "ci.yml",
        '        run: cosign sign --yes "ghcr.io/mikkoparkkola/mcp-gateway@${DIGEST}"',
        "        run: |\n"
        '          DIGEST="${{ steps.meta.outputs.version }}"\n'
        '          cosign sign --yes "ghcr.io/mikkoparkkola/mcp-gateway@${DIGEST}"',
        CAUGHT,
    ),
    (
        "dispatch-tag-in-a-run-comment",
        "release.yml",
        '        run: python3 scripts/release/check_tag_manifest.py --tag "$INPUT_TAG"',
        "        run: |\n"
        "          # releasing ${{ inputs.tag }}\n"
        '          python3 scripts/release/check_tag_manifest.py --tag "$INPUT_TAG"',
        CAUGHT,
    ),
    (
        "folded-if-hides-the-steps-sibling-run",
        "release.yml",
        "      - name: Check formatting\n        run: cargo fmt --all -- --check",
        "      - if: >-\n          true\n        run: echo ${{ inputs.tag }}",
        CAUGHT,
    ),
    (
        "dispatch-tag-in-index-notation",
        "release.yml",
        "        run: cargo fmt --all -- --check",
        "        run: echo ${{ inputs['tag'] }}",
        CAUGHT,
    ),
    (
        "digest-reassigned-inline-in-the-shell",
        "ci.yml",
        '        run: cosign sign --yes "ghcr.io/mikkoparkkola/mcp-gateway@${DIGEST}"',
        '        run: DIGEST="${{ steps.meta.outputs.version }}"; '
        'cosign sign --yes "ghcr.io/mikkoparkkola/mcp-gateway@${DIGEST}"',
        CAUGHT,
    ),
    (
        "digest-reference-single-quoted",
        "docker.yml",
        'run: cosign sign --yes "ghcr.io/mikkoparkkola/mcp-gateway@${DIGEST}"',
        "run: cosign sign --yes 'ghcr.io/mikkoparkkola/mcp-gateway@${DIGEST}'",
        CAUGHT,
    ),
    (
        "prerelease-guard-negated",
        "release.yml",
        "    if: needs.verify.outputs.is_prerelease != 'true'",
        "    if: ${{ !(needs.verify.outputs.is_prerelease != 'true') }}",
        CAUGHT,
    ),
    (
        "prerelease-skip-moved-into-env",
        "release.yml",
        "    if: needs.verify.outputs.is_prerelease != 'true'\n",
        "    env:\n      if: needs.verify.outputs.is_prerelease != 'true'\n",
        CAUGHT,
    ),
    (
        "heredoc-steps-line-hides-a-lost-digest-binding",
        "ci.yml",
        "      - name: Cosign keyless-sign the released image by digest\n"
        "        env:\n          DIGEST: ${{ steps.build.outputs.digest }}\n"
        '        run: cosign sign --yes "ghcr.io/mikkoparkkola/mcp-gateway@${DIGEST}"\n',
        "      - name: Cosign keyless-sign the released image by digest\n"
        "        run: |\n          cat <<'YAML'\n          steps:\n          YAML\n"
        '          cosign sign --yes "ghcr.io/mikkoparkkola/mcp-gateway@${DIGEST}"\n',
        CAUGHT,
    ),
    (
        "signing-step-allowed-to-fail-at-its-name-key",
        "ci.yml",
        "      - name: Cosign keyless-sign the released image by digest\n",
        "      - name: Cosign keyless-sign the released image by digest\n"
        "        continue-on-error: true\n",
        CAUGHT,
    ),
    (
        "gate-step-allowed-to-fail",
        "docker.yml",
        "        run: python3 scripts/release/check_tag_manifest.py\n",
        "        continue-on-error: true\n"
        "        run: python3 scripts/release/check_tag_manifest.py\n",
        CAUGHT,
    ),
    (
        "steps-key-in-a-heredoc-hides-the-signing-step",
        "ci.yml",
        "      - name: Cosign keyless-sign the released image by digest\n"
        "        env:\n          DIGEST: ${{ steps.build.outputs.digest }}\n",
        "      - name: Describe the job\n"
        "        run: |\n"
        "          cat <<'EOF'\n"
        "          steps:\n"
        "          EOF\n"
        "      - name: Cosign keyless-sign the released image by digest\n",
        CAUGHT,
    ),
    # The classification itself. Every guard above reads it from another job;
    # forcing the producer leaves each guard's text intact and its decision
    # meaningless.
    (
        "verify-output-forced-stable",
        "release.yml",
        "      is_prerelease: ${{ steps.channel.outputs.is_prerelease }}",
        "      is_prerelease: false",
        CAUGHT,
    ),
    (
        "verify-output-bound-to-a-missing-step",
        "release.yml",
        "      is_prerelease: ${{ steps.channel.outputs.is_prerelease }}",
        "      is_prerelease: ${{ steps.missing.outputs.is_prerelease }}",
        CAUGHT,
    ),
    (
        "classifying-job-disabled",
        "release.yml",
        "  verify:\n",
        "  verify:\n    if: false\n",
        CAUGHT,
    ),
    (
        "ci-latest-tag-guard-negated",
        "ci.yml",
        "steps.meta.outputs.is_prerelease != 'true' && 'ghcr.io/mikkoparkkola/mcp-gateway:latest'",
        "!steps.meta.outputs.is_prerelease != 'true' && 'ghcr.io/mikkoparkkola/mcp-gateway:latest'",
        CAUGHT,
    ),
    (
        "npm-dist-tag-forced-latest",
        "release.yml",
        "          DIST_TAG: ${{ needs.verify.outputs.is_prerelease == 'true' && 'next' || 'latest' }}",
        "          DIST_TAG: latest",
        CAUGHT,
    ),
    # Equivalent spellings. A suite that fails these is a suite nobody can
    # reformat a workflow under, which is how textual assertions get deleted.
    (
        "digest-value-quoted",
        "ci.yml",
        "          DIGEST: ${{ steps.build.outputs.digest }}\n"
        '        run: cosign sign --yes "ghcr.io/mikkoparkkola/mcp-gateway@${DIGEST}"',
        '          DIGEST: "${{ steps.build.outputs.digest }}"\n'
        '        run: cosign sign --yes "ghcr.io/mikkoparkkola/mcp-gateway@${DIGEST}"',
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
    (
        "digest-expression-without-inner-spaces",
        "ci.yml",
        "          DIGEST: ${{ steps.build.outputs.digest }}\n"
        '        run: cosign sign --yes "ghcr.io/mikkoparkkola/mcp-gateway@${DIGEST}"',
        "          DIGEST: ${{steps.build.outputs.digest}}\n"
        '        run: cosign sign --yes "ghcr.io/mikkoparkkola/mcp-gateway@${DIGEST}"',
        TOLERATED,
    ),
    (
        "digest-reference-unquoted",
        "docker.yml",
        'run: cosign sign --yes "ghcr.io/mikkoparkkola/mcp-gateway@${DIGEST}"',
        "run: cosign sign --yes ghcr.io/mikkoparkkola/mcp-gateway@${DIGEST}",
        TOLERATED,
    ),
    (
        "dispatch-tag-in-a-folded-if",
        "release.yml",
        "  verify:\n",
        "  verify:\n    if: >-\n      ${{ inputs.tag != '' }}\n",
        TOLERATED,
    ),
    (
        "gate-invocation-as-a-quoted-scalar",
        "docker.yml",
        "        run: python3 scripts/release/check_tag_manifest.py",
        "        run: 'python3 scripts/release/check_tag_manifest.py'",
        TOLERATED,
    ),
    (
        "dispatch-input-named-in-a-shell-comment",
        "release.yml",
        "        run: cargo fmt --all -- --check",
        "        run: |\n          # INPUT_TAG comes from inputs.tag\n"
        "          cargo fmt --all -- --check",
        TOLERATED,
    ),
    (
        "gate-invocation-as-an-inline-list-item",
        "docker.yml",
        "        run: python3 scripts/release/check_tag_manifest.py\n",
        "        run: true\n\n      - run: python3 scripts/release/check_tag_manifest.py\n",
        TOLERATED,
    ),
    (
        "unrelated-job-env-expression-with-a-disjunction",
        "release.yml",
        "    if: needs.verify.outputs.is_prerelease != 'true'\n",
        "    if: needs.verify.outputs.is_prerelease != 'true'\n"
        "    env:\n      DISPLAY: ${{ env.DISPLAY || ':0' }}\n",
        TOLERATED,
    ),
    (
        "gate-invocation-as-a-list-item",
        "docker.yml",
        "        run: python3 scripts/release/check_tag_manifest.py",
        "        run: 'true'\n      - run: python3 scripts/release/check_tag_manifest.py",
        TOLERATED,
    ),
    (
        # A prefix match approves a different file: `.bak` is a copy nobody
        # maintains, and a renamed gate is no gate.
        "gate-invocation-with-a-suffixed-filename",
        "docker.yml",
        '        run: python3 scripts/release/check_tag_manifest.py',
        "        run: python3 scripts/release/check_tag_manifest.py.bak",
        CAUGHT,
    ),
    (
        # A heredoc hands its body to `cat` as data. The text reads as the
        # invocation; nothing in it runs.
        "gate-invocation-printed-from-a-heredoc",
        "docker.yml",
        '        run: python3 scripts/release/check_tag_manifest.py',
        "        run: |\n          cat <<'SH'\n"
        "          python3 scripts/release/check_tag_manifest.py\n          SH",
        CAUGHT,
    ),
    (
        # `echo cosign sign` prints a command line. Nothing is signed.
        "cosign-sign-echoed-instead-of-run",
        "docker.yml",
        'run: cosign sign --yes "ghcr.io/mikkoparkkola/mcp-gateway@${DIGEST}"',
        'run: echo cosign sign --yes "ghcr.io/mikkoparkkola/mcp-gateway@${DIGEST}"',
        CAUGHT,
    ),
    (
        # A condition that is false on every run is a deletion that leaves the
        # step in the file for a reader to find.
        "gate-step-disabled-by-a-false-condition",
        "docker.yml",
        "        if: startsWith(github.ref, 'refs/tags/v')\n        run: python3 scripts/release/check_tag_manifest.py",
        "        if: false\n" + '        run: python3 scripts/release/check_tag_manifest.py',
        CAUGHT,
    ),
    (
        # The step's status is its last command's, so `|| true` reports a
        # successful signature over a failed one.
        "cosign-sign-failure-swallowed",
        "docker.yml",
        'run: cosign sign --yes "ghcr.io/mikkoparkkola/mcp-gateway@${DIGEST}"',
        'run: cosign sign --yes "ghcr.io/mikkoparkkola/mcp-gateway@${DIGEST}"' + " || true",
        CAUGHT,
    ),
    (
        # Inside a block scalar the quotes are the shell's: bash looks for one
        # command whose name is the whole quoted string.
        "gate-invocation-quoted-inside-a-block-scalar",
        "docker.yml",
        '        run: python3 scripts/release/check_tag_manifest.py',
        "        run: |\n          'python3 scripts/release/check_tag_manifest.py'",
        CAUGHT,
    ),
    (
        # Single quotes bash keeps: the trailing space inside them makes the
        # whole thing one literal argument the registry cannot resolve, and
        # `${DIGEST}` never expands.
        "digest-reference-single-quoted-with-trailing-space",
        "docker.yml",
        'run: cosign sign --yes "ghcr.io/mikkoparkkola/mcp-gateway@${DIGEST}"',
        "run: cosign sign --yes 'ghcr.io/mikkoparkkola/mcp-gateway@${DIGEST} '",
        CAUGHT,
    ),
    (
        # Equivalent spellings. `true && …` runs the gate, and the gate's exit
        # status is still the step's.
        "gate-invocation-after-an-unquoted-separator",
        "docker.yml",
        '        run: python3 scripts/release/check_tag_manifest.py',
        "        run: true && python3 scripts/release/check_tag_manifest.py",
        TOLERATED,
    ),
    (
        # `''` is YAML's escaped apostrophe, not the end of the scalar, so the
        # `#` after it stays inside the command.
        "gate-invocation-with-a-doubled-apostrophe",
        "docker.yml",
        '        run: python3 scripts/release/check_tag_manifest.py',
        "        run: 'python3 scripts/release/check_tag_manifest.py # don''t # log'",
        TOLERATED,
    ),
    (
        # Parentheses around the same comparison guard the same thing.
        "prerelease-guard-parenthesised",
        "release.yml",
        "    if: needs.verify.outputs.is_prerelease != 'true'",
        "    if: ${{ (needs.verify.outputs.is_prerelease != 'true') }}",
        TOLERATED,
    ),
    (
        # A folded scalar is one command once the folding is undone.
        "gate-invocation-in-a-folded-scalar",
        "docker.yml",
        '        run: python3 scripts/release/check_tag_manifest.py',
        "        run: >-\n          python3\n          scripts/release/check_tag_manifest.py",
        TOLERATED,
    ),
    (
        # The list marker is not part of the key: this condition is evaluated
        # by the expression engine, never handed to a shell.
        "dispatch-tag-in-an-inline-list-item-condition",
        "release.yml",
        "          INPUT_TAG: ${{ inputs.tag }}\n"
        '        run: python3 scripts/release/check_scope_acceptance.py --publish-check',
        "          INPUT_TAG: x\n      - if: ${{ inputs.tag != '' }}\n"
        '        run: python3 scripts/release/check_scope_acceptance.py --publish-check',
        TOLERATED,
    ),
    (
        # A step may open with any key. Written `- env:`, the mapping sits two
        # columns right of the item — and a `DIGEST:` line printed by the run
        # body is not a binding however much it reads like one.
        "digest-binding-printed-by-a-step-opening-with-env",
        "ci.yml",
        "      - name: Cosign keyless-sign the released image by digest\n"
        "        env:\n          DIGEST: ${{ steps.build.outputs.digest }}\n"
        '        run: cosign sign --yes "ghcr.io/mikkoparkkola/mcp-gateway@${DIGEST}"\n',
        "      - env:\n          NOTE: none\n        run: |\n"
        "          DIGEST: ${{ steps.build.outputs.digest }}\n"
        '          cosign sign --yes "ghcr.io/mikkoparkkola/mcp-gateway@${DIGEST}"\n',
        CAUGHT,
    ),
]


def verdict(directory, workflow, before, after):
    """Apply one mutation to the copied workflows and run the suite against it."""
    path = directory / workflow
    original = path.read_text(encoding="utf-8")
    # Exactly once. An anchor matching twice mutates whichever copy comes
    # first, which is not necessarily the one the case is about — and a case
    # that breaks a different rule from the one it names reports coverage it
    # does not have.
    if original.count(before) != 1:
        return None, ""
    path.write_text(original.replace(before, after, 1), encoding="utf-8")
    try:
        done = subprocess.run(
            [sys.executable, str(SUITE), "WorkflowWiring"],
            capture_output=True,
            text=True,
            env={**os.environ, "MCPGW_WORKFLOWS_DIR": str(directory)},
        )
    finally:
        path.write_text(original, encoding="utf-8")
    output = done.stdout + done.stderr
    if done.returncode == 0:
        return TOLERATED, output
    # An exit status alone cannot tell a detection from a crash: an import
    # error, a missing file or a helper raising on mutated text all exit
    # non-zero, and counting those as detections would report a gap as
    # covered. A detection is a failed assertion and nothing else — an
    # `ERROR:` means some assertion never ran, so the verdict is unusable
    # even when another one did fail.
    if "ERROR:" in output or "FAIL:" not in output:
        return BROKEN, output
    return CAUGHT, output


def main():
    failures = []
    with tempfile.TemporaryDirectory() as directory:
        copy = pathlib.Path(directory)
        shutil.copytree(WORKFLOWS, copy, dirs_exist_ok=True)
        for label, workflow, before, after, expected in CASES:
            got, output = verdict(copy, workflow, before, after)
            if got is None:
                failures.append(f"{label}: its anchor is no longer in {workflow}")
                print(f"STALE {label}")
                continue
            if got != expected:
                failures.append(f"{label}: expected {expected}, got {got}")
                # The suite's own output is the only diagnostic there is:
                # which assertion fired, or which exception replaced one.
                print(f"FAIL {label}: {got}")
                print("\n".join(f"    | {line}" for line in output.splitlines()))
                continue
            print(f"ok   {label}: {got}")
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
