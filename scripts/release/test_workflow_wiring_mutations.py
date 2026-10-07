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


Scope: this corpus covers drift and refactors — a gate moved, a condition
rewritten, a flag dropped. It does not cover deliberate obfuscation by someone
with write access to the workflow files, who could equally delete this suite.
A static read of shell inside YAML cannot bound that, and the meta-protection
cannot exceed the review that guards it.
"""

import os
import re
import pathlib
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve()
WORKFLOWS = HERE.parents[2] / ".github" / "workflows"
SUITE = HERE.with_name("test_check_tag_manifest.py")

CAUGHT, TOLERATED, BROKEN = "caught", "tolerated", "broken"

# docker.yml's smoke step and the push step it guards, verbatim. Held apart so
# the reordering case can swap them whole: deleting the gate and moving it
# below the push are different regressions, and only the second one leaves a
# workflow that still names the gate, still blocks on it, and still proves the
# image starts -- about bytes already pushed.
SMOKE_STEP = (
    "      - name: Smoke test the image (it must start and report healthy)\n"
    "        run: scripts/ci/smoke-image.sh"
    ' "${REGISTRY}/mikkoparkkola/mcp-gateway:scan"\n'
)
PUSH_STEP = (
    "      - name: Upload the digest\n"
    "        if: github.event_name != 'pull_request'"
    " && !startsWith(github.ref, 'refs/tags/v')\n"
    "        uses: actions/upload-artifact"
    "@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n"
    "        with:\n"
    "          name: image-digest-${{ matrix.arch }}\n"
    "          path: digests/${{ matrix.arch }}\n"
    "          # Read by the manifest job. Kept for the repository's 14-day retention\n"
    "          # cap so a failed manifest job can be retried without rebuilding the\n"
    "          # legs (RELEASING.md rule 4).\n"
    "          retention-days: 14\n"
    "          if-no-files-found: error\n"
)

# (label, workflow, before, after, expected) — `before` must occur verbatim.
CASES = [
    # Regressions. Each is a rewiring that publishes wrongly or verifies
    # nothing, and each was reachable while the suite stayed green.
    (
        "verify-step-deleted",
        "ci.yml",
        '            cosign verify \\\n'
        '              --certificate-identity "${IDENTITY}" \\\n'
        "              --certificate-oidc-issuer "
        "'https://token.actions.githubusercontent.com' \\\n"
        '              "${IMAGE}@${d}" > /dev/null\n',
        "",
        CAUGHT,
    ),
    (
        "verify-attestation-stdout-back-in-the-log",
        "ci.yml",
        "              --certificate-oidc-issuer "
        "'https://token.actions.githubusercontent.com' \\\n"
        '              "${IMAGE}@${d}" > /dev/null\n'
        "          done\n",
        "              --certificate-oidc-issuer "
        "'https://token.actions.githubusercontent.com' \\\n"
        '              "${IMAGE}@${d}"\n'
        "          done\n",
        CAUGHT,
    ),
    (
        "verify-step-timeout-deleted",
        "ci.yml",
        "        timeout-minutes: 10\n        env:\n          LIST: ${{ steps.list.outputs.list }}\n          AMD64:",
        "        env:\n          LIST: ${{ steps.list.outputs.list }}\n          AMD64:",
        CAUGHT,
    ),
    (
        "verify-attestation-stdout-repointed-to-stderr",
        "ci.yml",
        '              "${IMAGE}@${d}" > /dev/null\n'
        "          done\n",
        '              "${IMAGE}@${d}" > /dev/null >&2\n'
        "          done\n",
        CAUGHT,
    ),
    (
        "verify-attestation-both-streams-dropped-by-amp",
        "ci.yml",
        '              "${IMAGE}@${d}" > /dev/null\n'
        "          done\n",
        '              "${IMAGE}@${d}" > /dev/null &> /dev/null\n'
        "          done\n",
        CAUGHT,
    ),
    (
        "verify-step-timeout-too-tight",
        "ci.yml",
        "        timeout-minutes: 10\n        env:\n          LIST: ${{ steps.list.outputs.list }}\n          AMD64:",
        "        timeout-minutes: 1\n        env:\n          LIST: ${{ steps.list.outputs.list }}\n          AMD64:",
        CAUGHT,
    ),
    (
        "verify-step-stderr-dropped-by-exec",
        "ci.yml",
        "          set -euo pipefail\n          IMAGE=ghcr.io/mikkoparkkola/mcp-gateway\n          for d in \"${LIST}\" \"${AMD64}\" \"${ARM64}\" \"${LIST_FULL}\" \"${AMD64_FULL}\" \"${ARM64_FULL}\"; do\n            cosign verify \\\n",
        "          set -euo pipefail\n          exec 2>/dev/null\n          IMAGE=ghcr.io/mikkoparkkola/mcp-gateway\n          for d in \"${LIST}\" \"${AMD64}\" \"${ARM64}\" \"${LIST_FULL}\" \"${AMD64_FULL}\" \"${ARM64_FULL}\"; do\n            cosign verify \\\n",
        CAUGHT,
    ),
    (
        "verify-step-timeout-raised-to-hours",
        "ci.yml",
        "        timeout-minutes: 10\n        env:\n          LIST: ${{ steps.list.outputs.list }}\n          AMD64:",
        "        timeout-minutes: 360\n        env:\n          LIST: ${{ steps.list.outputs.list }}\n          AMD64:",
        CAUGHT,
    ),
    (
        "verify-attestation-stderr-dropped-too",
        "ci.yml",
        '              "${IMAGE}@${d}" > /dev/null\n'
        "          done\n",
        '              "${IMAGE}@${d}" > /dev/null 2>&1\n'
        "          done\n",
        CAUGHT,
    ),
    (
        "gate-behind-an-exit-on-the-line-above",
        "docker.yml",
        "        run: python3 scripts/release/check_tag_manifest.py",
        "        run: |\n          exit 0\n          python3 scripts/release/check_tag_manifest.py",
        CAUGHT,
    ),
    (
        "gate-behind-an-exec",
        "docker.yml",
        "        run: python3 scripts/release/check_tag_manifest.py",
        "        run: |\n          exec true\n          python3 scripts/release/check_tag_manifest.py",
        CAUGHT,
    ),
    (
        "gate-echoed-as-quoted-data",
        "docker.yml",
        "        run: python3 scripts/release/check_tag_manifest.py",
        "        run: |\n          echo '\n          NOTE: |\n"
        "            python3 scripts/release/check_tag_manifest.py\n          '",
        CAUGHT,
    ),
    (
        # Any signer whose certificate identity is a URL satisfies `.*`, so the
        # check passes for a signature this workflow did not produce.
        "identity-relaxed-to-a-regexp",
        "ci.yml",
        '            cosign verify \\\n              --certificate-identity "${IDENTITY}"',
        '            cosign verify \\\n              --certificate-identity-regexp ".*"',
        CAUGHT,
    ),
    (
        "sign-step-loses-its-digest-binding",
        "ci.yml",
        "      - name: Cosign keyless-sign the list and both children\n"
        "        if: github.event_name == 'push'"
        " && startsWith(github.ref, 'refs/tags/v')\n"
        "        env:\n"
        "          LIST: ${{ steps.list.outputs.list }}\n"
        "          AMD64: ${{ steps.list.outputs.amd64 }}\n"
        "          ARM64: ${{ steps.list.outputs.arm64 }}\n",
        "      - name: Cosign keyless-sign the list and both children\n",
        CAUGHT,
    ),
    (
        # The name still resolves an expression, and the expression still
        # reads a step output. It reads the version, so the signature would
        # cover a tag that moves rather than the bytes that were published.
        "digest-rebound-to-a-tag",
        "ci.yml",
        "      - name: Cosign keyless-sign the list and both children\n"
        "        if: github.event_name == 'push'"
        " && startsWith(github.ref, 'refs/tags/v')\n"
        "        env:\n          LIST: ${{ steps.list.outputs.list }}\n",
        "      - name: Cosign keyless-sign the list and both children\n"
        "        if: github.event_name == 'push'"
        " && startsWith(github.ref, 'refs/tags/v')\n"
        "        env:\n          LIST: ${{ steps.meta.outputs.version }}\n",
        CAUGHT,
    ),
    (
        # The output-name half of the digest binding (#570). The name still
        # reads the `list` step, but its amd64 child: the signature would cover
        # one platform's image instead of the index clients resolve.
        "list-bound-to-the-amd64-output",
        "ci.yml",
        "      - name: Cosign keyless-sign the list and both children\n"
        "        if: github.event_name == 'push'"
        " && startsWith(github.ref, 'refs/tags/v')\n"
        "        env:\n          LIST: ${{ steps.list.outputs.list }}\n",
        "      - name: Cosign keyless-sign the list and both children\n"
        "        if: github.event_name == 'push'"
        " && startsWith(github.ref, 'refs/tags/v')\n"
        "        env:\n          LIST: ${{ steps.list.outputs.amd64 }}\n",
        CAUGHT,
    ),
    (
        # The publisher loses its own gate step while docker-build keeps a
        # byte-identical one; the tags would read an unset version (#570). A
        # presence pin: text attribution catches it too. The attribution
        # witnesses are the echoed and commented-out gate cases above.
        "publisher-gate-step-deleted-builder-twin-kept",
        "ci.yml",
        "      - name: Extract tag\n"
        "        if: github.event_name == 'push'"
        " && startsWith(github.ref, 'refs/tags/v')\n"
        "        id: meta\n"
        "        run: python3 scripts/release/check_tag_manifest.py\n",
        "",
        CAUGHT,
    ),
    (
        # The step still runs the gate, but it is no longer `meta`, so
        # `steps.meta.outputs.version` resolves to the empty string.
        "publisher-gate-step-loses-its-id",
        "ci.yml",
        "        id: meta\n"
        "        run: python3 scripts/release/check_tag_manifest.py\n"
        "\n      - uses: docker/setup-buildx-action",
        "        id: gate\n"
        "        run: python3 scripts/release/check_tag_manifest.py\n"
        "\n      - uses: docker/setup-buildx-action",
        CAUGHT,
    ),
    (
        # The identity names a workflow that no longer signs anything, so the
        # verification can only pass against a signature nothing produces.
        "identity-points-at-the-other-publisher",
        "ci.yml",
        "/.github/workflows/ci.yml@${{ github.ref }}",
        "/.github/workflows/docker.yml@${{ github.ref }}",
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
        "    needs: [build, verify, packaged-suite]",
        "    needs: [build, packaged-suite] # verify",
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
        "      - name: Generate + attest an SBOM (SPDX JSON) per published digest\n"
        "        if: github.event_name == 'push'"
        " && startsWith(github.ref, 'refs/tags/v')\n"
        "        env:\n"
        "          LIST: ${{ steps.list.outputs.list }}\n"
        "          AMD64: ${{ steps.list.outputs.amd64 }}\n"
        "          ARM64: ${{ steps.list.outputs.arm64 }}\n",
        "      - id: attest\n"
        "        name: Generate + attest an SBOM (SPDX JSON) per published digest\n",
        CAUGHT,
    ),
    (
        "gate-invocation-echoed",
        "ci.yml",
        '        id: meta\n        run: python3 scripts/release/check_tag_manifest.py',
        '        id: meta\n        run: echo python3 scripts/release/check_tag_manifest.py',
        CAUGHT,
    ),
    (
        "gate-invocation-inside-an-echoed-string",
        "ci.yml",
        '        id: meta\n        run: python3 scripts/release/check_tag_manifest.py',
        '        id: meta\n        run: echo "skipped; python3 scripts/release/check_tag_manifest.py"',
        CAUGHT,
    ),
    (
        "gate-invocation-commented-out-in-ci",
        "ci.yml",
        '        id: meta\n        run: python3 scripts/release/check_tag_manifest.py',
        '        id: meta\n        run: |\n          # python3 scripts/release/check_tag_manifest.py\n          true',
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
        "    runs-on: ubuntu-latest\n\n"
        "    steps:\n      - name: Download checksums for the verified tag\n",
        "    runs-on: ubuntu-latest\n\n"
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
        '            cosign sign --yes "${IMAGE}@${d}"\n',
        '            LIST="${{ steps.meta.outputs.version }}"\n'
        '            cosign sign --yes "${IMAGE}@${d}"\n',
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
        # The loop variable is what cosign expands, so rebinding `d` redirects
        # every signature in the loop while the three digest bindings above it
        # stay untouched.
        "loop-variable-reassigned-in-the-shell",
        "ci.yml",
        '            cosign sign --yes "${IMAGE}@${d}"\n',
        '            d="${{ steps.meta.outputs.version }}"\n'
        '            cosign sign --yes "${IMAGE}@${d}"\n',
        CAUGHT,
    ),
    (
        # Binding a digest is not signing it: a `for` list that lost its
        # platform children signs the index alone, and the job's own verify
        # loop stays green because it checks what was signed.
        "sign-loop-drops-the-platform-children",
        "ci.yml",
        '          for d in "${LIST}" "${AMD64}" "${ARM64}" "${LIST_FULL}" "${AMD64_FULL}" "${ARM64_FULL}"; do\n'
        '            cosign sign',
        '          for d in "${LIST}"; do\n            cosign sign',
        CAUGHT,
    ),
    (
        "digest-reassigned-inline-in-the-shell",
        "ci.yml",
        '            cosign sign --yes "${IMAGE}@${d}"\n',
        '            LIST="${{ steps.meta.outputs.version }}"; '
        'cosign sign --yes "${IMAGE}@${d}"\n',
        CAUGHT,
    ),
    (
        # Single quotes are the shell's: `${d}` never expands and cosign is
        # handed a literal reference no registry resolves.
        "digest-reference-single-quoted",
        "ci.yml",
        '            cosign sign --yes "${IMAGE}@${d}"',
        "            cosign sign --yes '${IMAGE}@${d}'",
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
        "      - name: Cosign keyless-sign the list and both children\n"
        "        if: github.event_name == 'push'"
        " && startsWith(github.ref, 'refs/tags/v')\n"
        "        env:\n"
        "          LIST: ${{ steps.list.outputs.list }}\n"
        "          AMD64: ${{ steps.list.outputs.amd64 }}\n"
        "          ARM64: ${{ steps.list.outputs.arm64 }}\n"
        "          LIST_FULL: ${{ steps.list.outputs.list_full }}\n"
        "          AMD64_FULL: ${{ steps.list.outputs.amd64_full }}\n"
        "          ARM64_FULL: ${{ steps.list.outputs.arm64_full }}\n"
        "        run: |\n",
        "      - name: Cosign keyless-sign the list and both children\n"
        "        run: |\n          cat <<'YAML'\n          steps:\n          YAML\n",
        CAUGHT,
    ),
    (
        "signing-step-allowed-to-fail-at-its-name-key",
        "ci.yml",
        "      - name: Cosign keyless-sign the list and both children\n",
        "      - name: Cosign keyless-sign the list and both children\n"
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
        "      - name: Cosign keyless-sign the list and both children\n"
        "        if: github.event_name == 'push'"
        " && startsWith(github.ref, 'refs/tags/v')\n"
        "        env:\n"
        "          LIST: ${{ steps.list.outputs.list }}\n"
        "          AMD64: ${{ steps.list.outputs.amd64 }}\n"
        "          ARM64: ${{ steps.list.outputs.arm64 }}\n",
        "      - name: Describe the job\n"
        "        run: |\n"
        "          cat <<'EOF'\n"
        "          steps:\n"
        "          EOF\n"
        "      - name: Cosign keyless-sign the list and both children\n",
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
        "      - name: Cosign keyless-sign the list and both children\n"
        "        if: github.event_name == 'push'"
        " && startsWith(github.ref, 'refs/tags/v')\n"
        "        env:\n          LIST: ${{ steps.list.outputs.list }}\n",
        "      - name: Cosign keyless-sign the list and both children\n"
        "        if: github.event_name == 'push'"
        " && startsWith(github.ref, 'refs/tags/v')\n"
        '        env:\n          LIST: "${{ steps.list.outputs.list }}"\n',
        TOLERATED,
    ),
    (
        # A comment after the command is a comment.
        "trailing-comment-on-the-sign-command",
        "ci.yml",
        '            cosign sign --yes "${IMAGE}@${d}"',
        '            cosign sign --yes "${IMAGE}@${d}" # keyless, OIDC',
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
        "    needs: [build, verify, packaged-suite]",
        "    needs:\n      - build\n      - verify\n      - packaged-suite",
        TOLERATED,
    ),
    (
        "digest-expression-without-inner-spaces",
        "ci.yml",
        "      - name: Cosign keyless-sign the list and both children\n"
        "        if: github.event_name == 'push'"
        " && startsWith(github.ref, 'refs/tags/v')\n"
        "        env:\n          LIST: ${{ steps.list.outputs.list }}\n",
        "      - name: Cosign keyless-sign the list and both children\n"
        "        if: github.event_name == 'push'"
        " && startsWith(github.ref, 'refs/tags/v')\n"
        "        env:\n          LIST: ${{steps.list.outputs.list}}\n",
        TOLERATED,
    ),
    (
        # A digest has no shell metacharacters, so dropping the quotes changes
        # nothing about what is signed.
        "digest-reference-unquoted",
        "ci.yml",
        '            cosign sign --yes "${IMAGE}@${d}"',
        '            cosign sign --yes ${IMAGE}@${d}',
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
        "ci.yml",
        '            cosign sign --yes "${IMAGE}@${d}"',
        '            echo cosign sign --yes "${IMAGE}@${d}"',
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
        "ci.yml",
        '            cosign sign --yes "${IMAGE}@${d}"',
        '            cosign sign --yes "${IMAGE}@${d}"' + " || true",
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
        # `${d}` never expands.
        "digest-reference-single-quoted-with-trailing-space",
        "ci.yml",
        '            cosign sign --yes "${IMAGE}@${d}"',
        "            cosign sign --yes '${IMAGE}@${d} '",
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
        # columns right of the item — and a `LIST:` line printed by the run
        # body is not a binding however much it reads like one.
        "digest-binding-printed-by-a-step-opening-with-env",
        "ci.yml",
        "      - name: Cosign keyless-sign the list and both children\n"
        "        if: github.event_name == 'push'"
        " && startsWith(github.ref, 'refs/tags/v')\n"
        "        env:\n"
        "          LIST: ${{ steps.list.outputs.list }}\n"
        "          AMD64: ${{ steps.list.outputs.amd64 }}\n"
        "          ARM64: ${{ steps.list.outputs.arm64 }}\n"
        "          LIST_FULL: ${{ steps.list.outputs.list_full }}\n"
        "          AMD64_FULL: ${{ steps.list.outputs.amd64_full }}\n"
        "          ARM64_FULL: ${{ steps.list.outputs.arm64_full }}\n"
        "        run: |\n",
        "      - env:\n          NOTE: none\n        run: |\n"
        "          LIST: ${{ steps.list.outputs.list }}\n",
        CAUGHT,
    ),
    # Disarmament in place. The step, its name and its text all survive the
    # mutation — only what actually runs changes — so every assertion that
    # searches the file for the wiring still finds it.
    (
        "gate-short-circuited",
        "docker.yml",
        "        run: python3 scripts/release/check_tag_manifest.py\n",
        "        run: python3 scripts/release/check_tag_manifest.py || true\n",
        CAUGHT,
    ),
    (
        "gate-failure-swallowed",
        "docker.yml",
        "        run: python3 scripts/release/check_tag_manifest.py\n",
        "        run: |\n          set +e\n"
        "          python3 scripts/release/check_tag_manifest.py\n",
        CAUGHT,
    ),
    (
        "gate-replaced-by-help",
        "docker.yml",
        "        run: python3 scripts/release/check_tag_manifest.py\n",
        "        run: python3 scripts/release/check_tag_manifest.py --help\n",
        CAUGHT,
    ),
    (
        # The heredoc hazard one level out: the gate text becomes the value of
        # a variable, which reads as a command and runs nothing.
        "gate-run-moved-into-an-env-note",
        "docker.yml",
        "        run: python3 scripts/release/check_tag_manifest.py\n",
        "        env:\n          NOTE: |\n"
        "            python3 scripts/release/check_tag_manifest.py\n"
        "        run: true\n",
        CAUGHT,
    ),
    (
        # `latest` would follow every release candidate, which is the tag the
        # conditional exists to withhold from prereleases.
        "latest-fallback-made-unconditional",
        "ci.yml",
        "          LATEST_TAG: ${{ steps.meta.outputs.is_prerelease != 'true'"
        " && 'ghcr.io/mikkoparkkola/mcp-gateway:latest' || '' }}\n",
        "          LATEST_TAG: ghcr.io/mikkoparkkola/mcp-gateway:latest\n",
        CAUGHT,
    ),
    (
        # Signing a mutable tag signs whatever it points at later; echoing the
        # digest leaves the binding visible to any search for it.
        "sign-the-tag-then-echo-the-digest",
        "ci.yml",
        '            cosign sign --yes "${IMAGE}@${d}"\n',
        '            cosign sign --yes "${IMAGE}:latest"\n'
        '            echo "${d}"\n',
        CAUGHT,
    ),
    (
        # `declare` is an assignment the command-position read has to see: the
        # loop variable still expands, to a tag rather than a published digest.
        "digest-rebound-by-declare",
        "ci.yml",
        '            cosign sign --yes "${IMAGE}@${d}"\n',
        '            declare LIST="latest"\n'
        '            cosign sign --yes "${IMAGE}@${d}"\n',
        CAUGHT,
    ),
    # Disarmament that survives a search AND a command-position read. Each
    # of these leaves the step, its name and a real invocation in place; what
    # changes is whether the command is reached, whether its failure counts,
    # or which value the surviving expression yields.
    (
        # The shell is gone before the gate is reached. A search for the
        # command finds it, and it is genuinely in a command position.
        "gate-behind-an-exit",
        "docker.yml",
        "        run: python3 scripts/release/check_tag_manifest.py",
        "        run: exit 0; python3 scripts/release/check_tag_manifest.py",
        CAUGHT,
    ),
    (
        # A gate that never fires is a gate that passed. `refs/heads/`
        # matches every branch push and no tag.
        "gate-step-rescoped-to-branches",
        "docker.yml",
        "        if: startsWith(github.ref, 'refs/tags/v')\n"
        "        run: python3 scripts/release/check_tag_manifest.py",
        "        if: startsWith(github.ref, 'refs/heads/')\n"
        "        run: python3 scripts/release/check_tag_manifest.py",
        CAUGHT,
    ),
    (
        # The same disarm folded, where a line-scoped read of the condition
        # sees only the block-scalar indicator.
        "gate-step-condition-folded-to-false",
        "docker.yml",
        "        if: startsWith(github.ref, 'refs/tags/v')\n"
        "        run: python3 scripts/release/check_tag_manifest.py",
        "        if: >-\n          false\n"
        "        run: python3 scripts/release/check_tag_manifest.py",
        CAUGHT,
    ),
    (
        # cosign runs, cosign fails, the step stays green and a tag that
        # resolves to unsigned children is already published.
        "signature-failure-swallowed",
        "ci.yml",
        '            cosign sign --yes "${IMAGE}@${d}"',
        '            cosign sign --yes "${IMAGE}@${d}"' + " || echo ignored",
        CAUGHT,
    ),
    (
        # The heredoc hazard with an explicit indentation indicator. `|2` is
        # the same block scalar as `|`, and a filter matching only `|` and
        # `|-` reads the note's body as the command it replaced.
        "gate-moved-into-an-indented-env-note",
        "docker.yml",
        "        run: python3 scripts/release/check_tag_manifest.py",
        "        env:\n          NOTE: |2\n"
        "            python3 scripts/release/check_tag_manifest.py\n"
        "        run: true",
        CAUGHT,
    ),
    (
        # The producer expression is intact and one character longer. A
        # prerelease now emits `truex`, and every `!= 'true'` guard
        # downstream reads that as a stable release.
        "classification-output-given-a-suffix",
        "release.yml",
        "      is_prerelease: ${{ steps.channel.outputs.is_prerelease }}",
        "      is_prerelease: ${{ steps.channel.outputs.is_prerelease }}x",
        CAUGHT,
    ),
    (
        # The guard still reads a step output. It reads one no step produces,
        # so the expression is empty on every run and decides nothing.
        "latest-guard-reading-a-missing-step",
        "ci.yml",
        "          LATEST_TAG: ${{ steps.meta.outputs.is_prerelease != 'true'"
        " && 'ghcr.io/mikkoparkkola/mcp-gateway:latest' || '' }}\n",
        "          LATEST_TAG: ${{ steps.missing.outputs.is_prerelease != 'true'"
        " && 'ghcr.io/mikkoparkkola/mcp-gateway:latest' || '' }}\n",
        CAUGHT,
    ),
    (
        # The guarded tag is untouched; a second, unguarded one joins it in
        # the argument array. Every assertion that reads the guard still
        # finds it, and :latest moves on a release candidate anyway.
        "latest-tagged-again-unconditionally",
        "ci.yml",
        '          TAGS=(--tag "${IMAGE}:${VERSION}")\n',
        '          TAGS=(--tag "${IMAGE}:${VERSION}" --tag "${IMAGE}:latest")\n',
        CAUGHT,
    ),
    (
        # The channel still decides the dist-tag. It decides it backwards,
        # and `npm install mcp-gateway` resolves to a candidate.
        "npm-dist-tag-branches-swapped",
        "release.yml",
        "          DIST_TAG: ${{ needs.verify.outputs.is_prerelease == 'true'"
        " && 'next' || 'latest' }}",
        "          DIST_TAG: ${{ needs.verify.outputs.is_prerelease == 'true'"
        " && 'latest' || 'next' }}",
        CAUGHT,
    ),
    (
        # The other direction, which a scalar filter gets wrong just as
        # easily: shell text that looks like YAML. The gate runs here, so
        # reading the note's body as structure would fail a green workflow.
        "run-body-quoting-a-yaml-key",
        "docker.yml",
        "        run: python3 scripts/release/check_tag_manifest.py",
        "        run: |\n          echo '\n          NOTE: |\n          '\n"
        "          python3 scripts/release/check_tag_manifest.py",
        TOLERATED,
    ),
    (
        # The shape this PR was reviewed for: the release tag created by the
        # first `imagetools create`, before anything is signed. The tag is
        # then pullable and unsigned for the whole signing span, and the
        # verify-by-digest below passes anyway.
        "release-tag-created-before-signing",
        "ci.yml",
        '          docker buildx imagetools create'
        ' --tag "${IMAGE}:sha-${GITHUB_SHA}${REHEARSAL_SUFFIX}" \\\n',
        '          docker buildx imagetools create --tag "${IMAGE}:${VERSION}" \\\n',
        CAUGHT,
    ),
    (
        # The release copy ALSO run before signing, with the late one left in
        # place: every string the suite looks for is still where it was, and
        # only the step order says the tag existed unsigned first.
        "release-tag-copied-before-signing-as-well",
        "ci.yml",
        '          echo "${label} platforms: ${platforms}"\n',
        '          echo "${label} platforms: ${platforms}"\n'
        '          docker buildx imagetools create "${TAGS[@]}" "${IMAGE}@${LIST}"\n',
        CAUGHT,
    ),
    (
        # The stable major.minor pointer dropped, as the first draft of this
        # job dropped it: consumers pinned to :4.0 stop receiving releases.
        "major-minor-pointer-dropped",
        "ci.yml",
        '            MAJOR_MINOR="$(printf \'%s\' "${VERSION}" | cut -d. -f1,2)"\n'
        '            TAGS+=(--tag "${IMAGE}:${MAJOR_MINOR}")\n',
        "",
        CAUGHT,
    ),
    (
        # The pointer kept but moved out of the stable guard, so a release
        # candidate moves :4.0 for every consumer pinned to it.
        "major-minor-pointer-outside-the-stable-guard",
        "ci.yml",
        '          TAGS=(--tag "${IMAGE}:${VERSION}")\n'
        '          if [ -n "${LATEST_TAG}" ]; then\n'
        '            TAGS+=(--tag "${LATEST_TAG}")\n',
        '          TAGS=(--tag "${IMAGE}:${VERSION}")\n'
        '          MAJOR_MINOR_ALWAYS="$(printf \'%s\' "${VERSION}" | cut -d. -f1,2)"\n'
        '          TAGS+=(--tag "${IMAGE}:${MAJOR_MINOR_ALWAYS}")\n'
        '          if [ -n "${LATEST_TAG}" ]; then\n'
        '            TAGS+=(--tag "${LATEST_TAG}")\n',
        CAUGHT,
    ),
    (
        # The unpinned fetch restored: the binary handed a publish token is
        # whatever the upstream repository shipped most recently.
        "mcp-publisher-back-on-releases-latest",
        "ci.yml",
        '"https://github.com/modelcontextprotocol/registry/releases/download/v1.8.1/${ASSET}"',
        '"https://github.com/modelcontextprotocol/registry/releases/latest/download/${ASSET}"',
        CAUGHT,
    ),
    (
        # Pinned but unverified -- a release asset replaced in place still
        # reaches the token, so the pin alone is not the control.
        "mcp-publisher-pinned-but-not-verified",
        "ci.yml",
        "          printf '%s  %s\\n' \"${SHA256}\" \"${ASSET}\" | sha256sum --check --strict -",
        "          # checksum check removed",
        CAUGHT,
    ),
    (
        # Tolerated by design: `--strict` hardens the check but the assertion
        # is about a checksum running at all, and pinning the exact flag set
        # would fail the next time the line is reasonably reworded.
        "mcp-publisher-checksum-without-strict",
        "ci.yml",
        "| sha256sum --check --strict -",
        "| sha256sum --check -",
        TOLERATED,
    ),
    (
        # The second publisher back on the same name from the same commit.
        # It no longer has a step-level `push:` to reopen -- the build pushes
        # by digest under no name -- so the way back in is the condition that
        # decides whether the manifest job runs at all. Anchored to the line
        # above it: the job-level condition is identical to the step-level ones,
        # so on its own it matches several times and mutates the wrong copy.
        # The mutation re-admits tags beside the main-only pin.
        "docker-yml-pushing-on-a-tag-again",
        "docker.yml",
        "    needs: build\n"
        "    if: github.event_name == 'push' && github.ref == 'refs/heads/main'",
        "    needs: build\n"
        "    if: github.event_name == 'push' && (github.ref == 'refs/heads/main'"
        " || startsWith(github.ref, 'refs/tags/v'))",
        CAUGHT,
    ),
    (
        # Equivalent spelling: the guard written with the negation outside.
        # A workflow nobody can reformat is a workflow whose checks get
        # deleted instead.
        "release-tag-copy-with-the-image-spelled-inline",
        "ci.yml",
        '          docker buildx imagetools create "${TAGS[@]}" "${IMAGE}@${LIST}"',
        '          docker buildx imagetools create "${TAGS[@]}" '
        '"ghcr.io/mikkoparkkola/mcp-gateway@${LIST}"',
        TOLERATED,
    ),
    # NFR.PKG.1's gate. Both publishers fire on the same tag and neither can
    # block the other, so the step has to survive in each of them separately.
    (
        "smoke-gate-deleted-from-the-branch-publisher",
        "docker.yml",
        '        run: scripts/ci/smoke-image.sh'
        ' "${REGISTRY}/mikkoparkkola/mcp-gateway:scan"\n',
        "",
        CAUGHT,
    ),
    (
        "smoke-gate-deleted-from-the-release-publisher",
        "ci.yml",
        '        run: scripts/ci/smoke-image.sh'
        ' "ghcr.io/mikkoparkkola/mcp-gateway@${DIGEST}"\n',
        "",
        CAUGHT,
    ),
    (
        # The variant index built from the base legs. Every gate downstream
        # reads the index by digest and compares it to itself, so this passes
        # all of them while `:latest-full` serves the default image.
        "variant-provenance-index-built-from-the-base-legs",
        "ci.yml",
        '            "${IMAGE}@${FULL_AMD64}" "${IMAGE}@${FULL_ARM64}"\n',
        '            "${IMAGE}@${AMD64}" "${IMAGE}@${ARM64}"\n',
        CAUGHT,
    ),
    (
        "variant-tags-composed-from-the-base-index",
        "ci.yml",
        '          docker buildx imagetools create "${FULL_TAGS[@]}"'
        ' "${IMAGE}@${LIST_FULL}"\n',
        '          docker buildx imagetools create "${FULL_TAGS[@]}"'
        ' "${IMAGE}@${LIST}"\n',
        CAUGHT,
    ),
    (
        "variant-leg-built-from-the-base-stage",
        "ci.yml",
        "            --target runtime-full \\\n",
        "            --target runtime \\\n",
        CAUGHT,
    ),
    (
        "variant-digest-recorded-as-the-base-digest",
        "ci.yml",
        "          printf '%s' \"${DIGEST_FULL}\" > \"digests/${{ matrix.arch }}-full\"\n",
        "          printf '%s' \"${DIGEST}\" > \"digests/${{ matrix.arch }}-full\"\n",
        CAUGHT,
    ),
    (
        "variant-smoke-gate-deleted-from-the-release-publisher",
        "ci.yml",
        '        run: scripts/ci/smoke-full-image.sh'
        ' "ghcr.io/mikkoparkkola/mcp-gateway@${DIGEST}"\n',
        "",
        CAUGHT,
    ),
    (
        "variant-smoke-gate-deleted-from-the-branch-publisher",
        "docker.yml",
        '        run: scripts/ci/smoke-full-image.sh'
        ' "${REGISTRY}/mikkoparkkola/mcp-gateway:scan-full"\n',
        "",
        CAUGHT,
    ),
    (
        "variant-smoke-gate-turned-into-a-log-line",
        "ci.yml",
        '        run: scripts/ci/smoke-full-image.sh'
        ' "ghcr.io/mikkoparkkola/mcp-gateway@${DIGEST}"\n',
        '        continue-on-error: true\n'
        '        run: scripts/ci/smoke-full-image.sh'
        ' "ghcr.io/mikkoparkkola/mcp-gateway@${DIGEST}"\n',
        CAUGHT,
    ),
    (
        "release-publisher-builds-an-untargeted-image",
        "ci.yml",
        "          target: runtime\n",
        "",
        CAUGHT,
    ),
    (
        # Report-only: the image still fails to start, the job still goes green.
        "smoke-gate-turned-into-a-log-line",
        "docker.yml",
        "      - name: Smoke test the image (it must start and report healthy)\n",
        "      - name: Smoke test the image (it must start and report healthy)\n"
        "        continue-on-error: true\n",
        CAUGHT,
    ),
    (
        "smoke-gate-failure-swallowed",
        "ci.yml",
        '        run: scripts/ci/smoke-image.sh'
        ' "ghcr.io/mikkoparkkola/mcp-gateway@${DIGEST}"',
        '        run: scripts/ci/smoke-image.sh'
        ' "ghcr.io/mikkoparkkola/mcp-gateway@${DIGEST}" || true',
        CAUGHT,
    ),
    (
        # No argument is a usage error today, so this is red either way -- but
        # a gate that is only red by accident is one `|| true` from green with
        # no container ever started.
        "smoke-gate-handed-no-image",
        "ci.yml",
        '        run: scripts/ci/smoke-image.sh'
        ' "ghcr.io/mikkoparkkola/mcp-gateway@${DIGEST}"',
        "        run: scripts/ci/smoke-image.sh",
        CAUGHT,
    ),
    (
        # Equivalent spelling: the same script under an explicit interpreter.
        "smoke-gate-spelled-with-an-interpreter",
        "ci.yml",
        '        run: scripts/ci/smoke-image.sh'
        ' "ghcr.io/mikkoparkkola/mcp-gateway@${DIGEST}"',
        '        run: bash scripts/ci/smoke-image.sh'
        ' "ghcr.io/mikkoparkkola/mcp-gateway@${DIGEST}"',
        TOLERATED,
    ),
    (
        # A push added upstream of the gate. The step is untouched and still
        # green; what it proves is now about an image already pullable.
        "scan-build-pushing-before-the-image-is-started",
        "docker.yml",
        "          load: true\n",
        "          load: true\n"
        "          push: ${{ github.event_name != 'pull_request' }}\n",
        CAUGHT,
    ),
    (
        # The case deletion does not cover: the gate is still there, still
        # blocking, still reading the right image -- and the handoff that
        # makes those bytes reachable now runs first. Hoisting a second copy
        # of the upload above it is the smallest edit that reorders the two.
        "smoke-gate-moved-below-the-handoff",
        "docker.yml",
        SMOKE_STEP,
        PUSH_STEP + "\n" + SMOKE_STEP,
        CAUGHT,
    ),
]

# The rehearsal verify (docs/design/2026-09-26-rehearsal-readonly-verify.md)
# repeats the release verify body verbatim, so an anchor inside that body now
# matches twice. These cases are about the release step: each anchor is widened
# with context only that step has, so it still names one site.
RELEASE_VERIFY_HEAD = (
    "          IDENTITY: https://github.com/MikkoParkkola/mcp-gateway/.github/workflows/ci.yml@${{ github.ref }}\n"
    "          LIST_FULL: ${{ steps.list.outputs.list_full }}\n"
    "          AMD64_FULL: ${{ steps.list.outputs.amd64_full }}\n"
    "          ARM64_FULL: ${{ steps.list.outputs.arm64_full }}\n"
    "        run: |\n"
)
RELEASE_VERIFY_LOOP = RELEASE_VERIFY_HEAD + (
    "          set -euo pipefail\n"
    "          IMAGE=ghcr.io/mikkoparkkola/mcp-gateway\n"
    '          for d in "${LIST}" "${AMD64}" "${ARM64}" "${LIST_FULL}" "${AMD64_FULL}" "${ARM64_FULL}"; do\n'
)
RELEASE_VERIFY_TAIL = "\n      # Only now does a release name exist."
IN_RELEASE_VERIFY = {
    "verify-step-deleted",
    "verify-attestation-stdout-back-in-the-log",
    "verify-attestation-stdout-repointed-to-stderr",
    "verify-attestation-both-streams-dropped-by-amp",
    "verify-step-stderr-dropped-by-exec",
    "verify-attestation-stderr-dropped-too",
    "identity-relaxed-to-a-regexp",
}


def _in_release_verify(case):
    label, workflow, before, after, expected = case
    if label not in IN_RELEASE_VERIFY:
        return case
    if before.startswith("          set -euo pipefail"):
        return (label, workflow, RELEASE_VERIFY_HEAD + before, RELEASE_VERIFY_HEAD + after, expected)
    if before.startswith("            cosign verify"):
        return (label, workflow, RELEASE_VERIFY_LOOP + before, RELEASE_VERIFY_LOOP + after, expected)
    if before.endswith("          done\n"):
        return (label, workflow, before + RELEASE_VERIFY_TAIL, after + RELEASE_VERIFY_TAIL, expected)
    raise AssertionError(f"{label}: no release-verify context rule for its anchor")


CASES = [_in_release_verify(case) for case in CASES]

# The read-only rehearsal verify: each case breaks one rule the design names.
REHEARSAL_IF = (
    "        if: github.event_name == 'workflow_dispatch' && (inputs.rehearse_manifest"
    " == true || inputs.rehearse_manifest == 'true')\n        timeout-minutes: 10\n"
)
REHEARSAL_LIST = "          LIST: sha256:1471cafc9f2a88855fd8997da8316b8122335bef3d3886a3bbb64768aebc9638\n"
REHEARSAL_IDENTITY = (
    "          IDENTITY: https://github.com/MikkoParkkola/mcp-gateway/.github/workflows/ci.yml"
    "@refs/tags/v4.0.0-beta.2\n"
)
REHEARSAL_LOOP = (
    "          ARM64_FULL: sha256:d267a3477aeec6f8702b2851e93d9e29ba8fd94cd13920dd158d8cb43e929da9\n"
    "        run: |\n"
    "          set -euo pipefail\n"
    "          IMAGE=ghcr.io/mikkoparkkola/mcp-gateway\n"
    '          for d in "${LIST}" "${AMD64}" "${ARM64}" "${LIST_FULL}" "${AMD64_FULL}" "${ARM64_FULL}"; do\n'
)
REHEARSAL_TAIL = '"${IMAGE}@${d}" > /dev/null\n          done\n\n      - name: Install syft (SBOM)\n'
INSTALLER_IF = (
    "        if: (github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v'))"
    " || (github.event_name == 'workflow_dispatch'"
)
SYFT_IF = (
    "      - name: Install syft (SBOM)\n"
    "        if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')\n"
)
SIGN_IF = (
    "      - name: Cosign keyless-sign the list and both children\n"
    "        if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')\n"
)
CASES += [
    ("rehearsal-verify-deleted", "ci.yml",
     "      - name: Rehearse the release verify against a pinned signed release\n",
     "      - name: Rehearse something else\n", CAUGHT),
    ("rehearsal-verifies-the-build-under-rehearsal", "ci.yml", REHEARSAL_LIST,
     "          LIST: ${{ steps.list.outputs.list }}\n", CAUGHT),
    ("rehearsal-digest-truncated", "ci.yml", REHEARSAL_LIST, REHEARSAL_LIST[:-2] + "\n", CAUGHT),
    ("rehearsal-identity-follows-the-ref", "ci.yml", REHEARSAL_IDENTITY,
     "          IDENTITY: https://github.com/MikkoParkkola/mcp-gateway/.github/workflows/ci.yml"
     "@${{ github.ref }}\n", CAUGHT),
    ("rehearsal-gains-a-cosign-toggle", "ci.yml", REHEARSAL_IDENTITY,
     REHEARSAL_IDENTITY + '          COSIGN_EXPERIMENTAL: "1"\n', CAUGHT),
    ("rehearsal-signs", "ci.yml", REHEARSAL_LOOP,
     REHEARSAL_LOOP + '            cosign sign --yes "${IMAGE}@${d}"\n', CAUGHT),
    ("rehearsal-reassigns-a-subject", "ci.yml", REHEARSAL_LOOP,
     REHEARSAL_LOOP.replace("          for d", '          LIST="$(cat digests/amd64)"\n          for d'), CAUGHT),
    ("rehearsal-drops-a-subject", "ci.yml", REHEARSAL_LOOP,
     REHEARSAL_LOOP.replace(' "${ARM64_FULL}"; do', "; do"), CAUGHT),
    ("rehearsal-stdout-back-in-the-log-alone", "ci.yml", REHEARSAL_TAIL,
     REHEARSAL_TAIL.replace(" > /dev/null", ""), CAUGHT),
    ("rehearsal-timeout-drifts-from-the-release", "ci.yml", REHEARSAL_IF,
     REHEARSAL_IF.replace("timeout-minutes: 10", "timeout-minutes: 12"), CAUGHT),
    ("rehearsal-step-also-runs-on-a-tag", "ci.yml", REHEARSAL_IF,
     REHEARSAL_IF.replace("== 'true')\n", "== 'true') || github.event_name == 'push'\n"), CAUGHT),
    ("rehearsal-step-runs-on-any-dispatch", "ci.yml", REHEARSAL_IF,
     "        if: github.event_name == 'workflow_dispatch'\n        timeout-minutes: 10\n", CAUGHT),
    ("installer-widened-past-a-rehearsal", "ci.yml", INSTALLER_IF,
     INSTALLER_IF.replace("'workflow_dispatch'", "'pull_request'"), CAUGHT),
    ("syft-installer-gains-the-rehearsal", "ci.yml", SYFT_IF,
     SYFT_IF.replace("'refs/tags/v')\n", "'refs/tags/v') || github.event_name == 'workflow_dispatch'\n"), CAUGHT),
    ("sign-guard-split-across-a-disjunct", "ci.yml", SIGN_IF,
     SIGN_IF.replace("&& startsWith(github.ref, 'refs/tags/v')", "&& (startsWith(github.ref, 'refs/tags/v') || github.event_name == 'workflow_dispatch')"), CAUGHT),
]


# Job-handoff retention. Each anchor carries the comment line only its own
# site has, so it names one upload and not the other two.
RELEASE_KEEP = (
    "          # workflow says what actually takes effect (RELEASING.md rule 4).\n"
    "          retention-days: 14\n"
)
CI_KEEP = (
    "          path: digests/\n"
    "          # Read by docker-manifest. Kept for the repository's 14-day retention\n"
    "          # cap so a failed manifest job can be retried without rebuilding the\n"
    "          # legs (RELEASING.md rule 4).\n"
    "          retention-days: 14\n"
)
DOCKER_KEEP = (
    "          # Read by the manifest job. Kept for the repository's 14-day retention\n"
    "          # cap so a failed manifest job can be retried without rebuilding the\n"
    "          # legs (RELEASING.md rule 4).\n"
    "          retention-days: 14\n"
)
CASES += [
    ("release-handoff-expires-in-a-day", "release.yml", RELEASE_KEEP,
     RELEASE_KEEP.replace(": 14", ": 1"), CAUGHT),
    ("ci-digest-handoff-expires-in-a-day", "ci.yml", CI_KEEP,
     CI_KEEP.replace(": 14", ": 1"), CAUGHT),
    ("docker-digest-handoff-expires-in-a-day", "docker.yml", DOCKER_KEEP,
     DOCKER_KEEP.replace(": 14", ": 1"), CAUGHT),
    ("release-handoff-one-day-short", "release.yml", RELEASE_KEEP,
     RELEASE_KEEP.replace(": 14", ": 13"), CAUGHT),
    # Past the repository setting the value is clamped, so the file would
    # promise a re-run window that does not exist.
    ("release-handoff-past-the-repository-cap", "release.yml", RELEASE_KEEP,
     RELEASE_KEEP.replace(": 14", ": 30"), CAUGHT),
    # Unset inherits a repository setting nobody reviews.
    ("release-handoff-retention-unset", "release.yml", RELEASE_KEEP,
     RELEASE_KEEP.replace("          retention-days: 14\n", ""), CAUGHT),
    # Outside `with:` the action never sees the key.
    ("ci-digest-retention-moved-out-of-with", "ci.yml",
     "        with:\n          name: image-digests-${{ matrix.arch }}\n" + CI_KEEP,
     "        retention-days: 14\n        with:\n          name: image-digests-${{ matrix.arch }}\n"
     + CI_KEEP.replace("          retention-days: 14\n", ""), CAUGHT),
    # The scan must keep finding every handoff: a download it can no longer
    # match drops one silently, and the per-workflow guard is what says so.
    ("ci-digest-download-renamed", "ci.yml",
     "          pattern: image-digests-*\n", "          pattern: image-digest-leg-*\n", CAUGHT),
    # `name:` wins over `pattern:` in the action, so a download that names
    # some other artifact takes no digests, whatever its pattern says.
    ("ci-digest-download-named-elsewhere", "ci.yml",
     "          pattern: image-digests-*\n",
     "          name: some-other-artifact\n          pattern: image-digests-*\n", CAUGHT),
]


# The tooling unit tests fail every ref; only live-ledger checks are
# report-only. Each anchor names the new job's own header or steps.
UNIT_JOB = "    name: Release tooling unit tests\n    runs-on: ubuntu-latest\n"
MUTATIONS_STEP = (
    "      - name: Test that the workflow-wiring assertions catch their mutations\n"
    "        run: python3 scripts/release/test_workflow_wiring_mutations.py\n"
)
_CI_TEXT = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
_RC_FIRST = (
    "      - name: Check the release-criteria ledger header against its rows\n"
    "        run: python3 scripts/release/count-release-criteria.py --check\n"
)
_RELEASE_CRITERIA_SPAN = _CI_TEXT[
    _CI_TEXT.index(MUTATIONS_STEP) : _CI_TEXT.index(_RC_FIRST) + len(_RC_FIRST)
]
CASES += [
    ("unit-tests-swallowed", "ci.yml", UNIT_JOB,
     UNIT_JOB + "    continue-on-error: true\n", CAUGHT),
    ("unit-tests-swallowed-off-a-tag", "ci.yml", UNIT_JOB,
     UNIT_JOB + "    continue-on-error: ${{ !startsWith(github.ref, 'refs/tags/v') }}\n", CAUGHT),
    ("unit-tests-explicitly-blocking", "ci.yml", UNIT_JOB,
     UNIT_JOB + "    continue-on-error: false\n", TOLERATED),
    ("publish-gate-test-back-in-the-report-only-job", "ci.yml",
     "      - name: Test the tag/manifest publish gate\n"
     "        run: python3 scripts/release/test_check_tag_manifest.py\n",
     "", CAUGHT),
    ("mutation-harness-dropped", "ci.yml",
     MUTATIONS_STEP + "\n  release-criteria:\n",
     "\n  release-criteria:\n", CAUGHT),
    # Moved, not dropped: still run, but inside the job whose failure is
    # swallowed off a tag. The span runs from the step to the first step of
    # release-criteria, so the edit is one contiguous replacement.
    ("mutation-harness-moved-to-the-report-only-job", "ci.yml",
     _RELEASE_CRITERIA_SPAN,
     _RELEASE_CRITERIA_SPAN.replace(MUTATIONS_STEP, "", 1)
     + MUTATIONS_STEP, CAUGHT),
    ("docker-build-stops-waiting-for-unit-tests", "ci.yml",
     "release-criteria, release-script-tests, package-tests, release-signing-checks]", "release-criteria, package-tests, release-signing-checks]", CAUGHT),
]

# ASI04: release binaries are signed, their SBOMs written, and the draft
# release verified before it is published.
CASES += [
    ("release-built-without-auditable", "release.yml",
     "        run: cargo auditable build --release --target ${{ matrix.target }}\n",
     "        run: cargo build --release --target ${{ matrix.target }}\n", CAUGHT),
    ("release-signing-step-dropped", "release.yml",
     "          scripts/release/sign-release-assets.sh release \"$VERSION\" $BINARIES\n",
     "          true\n", CAUGHT),
    ("release-published-at-once", "release.yml",
     "          draft: true\n", "          draft: false\n", CAUGHT),
    ("draft-check-dropped", "release.yml",
     "          scripts/release/verify-release-assets.sh published \"$VERSION\" $BINARIES\n",
     "          ls published\n", CAUGHT),
    ("publish-despite-a-failed-check", "release.yml",
     "      - name: Publish the release\n",
     "      - name: Publish the release\n        if: always()\n", CAUGHT),
    ("draft-check-swallowed", "release.yml",
     "      - name: Verify the draft release's assets\n",
     "      - name: Verify the draft release's assets\n        continue-on-error: true\n", CAUGHT),
    ("checksums-rewritten-after-signing", "release.yml",
     "      - name: Publish the release\n",
     "      - name: Rewrite checksums\n        run: sha256sum -- release/* > release/SHA256SUMS.txt\n\n"
     "      - name: Publish the release\n", CAUGHT),
    ("identity-from-the-tag-input", "release.yml",
     "      IDENTITY: https://github.com/${{ github.workflow_ref }}\n",
     "      IDENTITY: https://github.com/${{ github.repository }}/.github/workflows/release.yml@refs/tags/${{ inputs.tag }}\n", CAUGHT),
    ("oidc-granted-to-publish", "release.yml",
     "  publish:\n    needs: [release, verify]\n    runs-on: ubuntu-latest\n",
     "  publish:\n    needs: [release, verify]\n    runs-on: ubuntu-latest\n    permissions:\n      id-token: write\n", CAUGHT),
    ("signing-rehearsal-on-every-pr", "ci.yml",
     "    if: github.event_name == 'workflow_dispatch' && (inputs.rehearse_binary_signing",
     "    if: github.event_name == 'pull_request' || (inputs.rehearse_binary_signing", CAUGHT),
    ("signing-rehearsal-publishes", "ci.yml",
     '          gh release create "$DRAFT" release/* --draft --target',
     '          gh release create "$DRAFT" release/* --target', CAUGHT),
    ("signing-checks-swallowed", "ci.yml",
     "    name: Release signing checks\n",
     "    name: Release signing checks\n    continue-on-error: true\n", CAUGHT),
    ("docker-build-stops-waiting-for-signing-checks", "ci.yml",
     "package-tests, release-signing-checks]", "package-tests]", CAUGHT),
    ("sbom-rehearsal-drops-windows", "ci.yml",
     "            artifact: mcp-gateway-windows-x86_64\n            suffix: .exe\n            packages: \"\"\n    runs-on: ${{ matrix.os }}\n",
     "            artifact: mcp-gateway-windows-x86-64\n            suffix: .exe\n            packages: \"\"\n    runs-on: ${{ matrix.os }}\n", CAUGHT),
    ("sbom-rehearsal-plain-build", "ci.yml",
     "        run: cargo auditable build --release --target ${{ matrix.target }}\n      - name: Install syft (SBOM)\n",
     "        run: cargo build --release --target ${{ matrix.target }}\n      - name: Install syft (SBOM)\n", CAUGHT),
    ("sbom-rehearsal-skips-the-check", "ci.yml",
     '          python3 scripts/release/check_release_assets.py sbom --version "$version" --sbom-only "$name"\n',
     '          ls sbom\n', CAUGHT),
    ("published-release-recheck-dropped", "release.yml",
     "          scripts/release/verify-release-assets.sh published-final \"$VERSION\" $BINARIES\n",
     "          ls published-final\n", CAUGHT),
    ("published-release-recheck-only-mentioned", "release.yml",
     "          scripts/release/verify-release-assets.sh published-final \"$VERSION\" $BINARIES\n",
     "          echo scripts/release/verify-release-assets.sh published-final \"$VERSION\" $BINARIES\n", CAUGHT),
    ("published-release-recheck-swallowed", "release.yml",
     "      - name: Verify the published release's assets\n",
     "      - name: Verify the published release's assets\n        continue-on-error: true\n", CAUGHT),
    ("published-release-recheck-step-removed", "release.yml",
     '      - name: Verify the published release\'s assets\n        env:\n          GH_TOKEN: ${{ github.token }}\n          TAG: ${{ needs.verify.outputs.tag }}\n          VERSION: ${{ needs.verify.outputs.version }}\n        run: |\n          set -euo pipefail\n          gh release download "$TAG" --repo "$GITHUB_REPOSITORY" --dir published-final\n          # shellcheck disable=SC2086 # BINARIES is a word list by design\n          scripts/release/verify-release-assets.sh published-final "$VERSION" $BINARIES\n', "", CAUGHT),
    ("published-release-recheck-before-publish", "release.yml",
     '      - name: Publish the release\n        env:\n          GH_TOKEN: ${{ github.token }}\n          TAG: ${{ needs.verify.outputs.tag }}\n        run: gh release edit "$TAG" --repo "$GITHUB_REPOSITORY" --draft=false\n\n      # What the public release serves, checked once more: publishing cannot be\n      # undone here, but an asset changed between the draft check and now fails\n      # the run loudly instead of passing unseen (GH1941.SIGN.1).\n      - name: Verify the published release\'s assets\n        env:\n          GH_TOKEN: ${{ github.token }}\n          TAG: ${{ needs.verify.outputs.tag }}\n          VERSION: ${{ needs.verify.outputs.version }}\n        run: |\n          set -euo pipefail\n          gh release download "$TAG" --repo "$GITHUB_REPOSITORY" --dir published-final\n          # shellcheck disable=SC2086 # BINARIES is a word list by design\n          scripts/release/verify-release-assets.sh published-final "$VERSION" $BINARIES\n',
     '      # What the public release serves, checked once more: publishing cannot be\n      # undone here, but an asset changed between the draft check and now fails\n      # the run loudly instead of passing unseen (GH1941.SIGN.1).\n      - name: Verify the published release\'s assets\n        env:\n          GH_TOKEN: ${{ github.token }}\n          TAG: ${{ needs.verify.outputs.tag }}\n          VERSION: ${{ needs.verify.outputs.version }}\n        run: |\n          set -euo pipefail\n          gh release download "$TAG" --repo "$GITHUB_REPOSITORY" --dir published-final\n          # shellcheck disable=SC2086 # BINARIES is a word list by design\n          scripts/release/verify-release-assets.sh published-final "$VERSION" $BINARIES\n\n      - name: Publish the release\n        env:\n          GH_TOKEN: ${{ github.token }}\n          TAG: ${{ needs.verify.outputs.tag }}\n        run: gh release edit "$TAG" --repo "$GITHUB_REPOSITORY" --draft=false\n', CAUGHT),
    ("published-release-not-refused", "release.yml",
     '        run: scripts/release/refuse-published-release.sh "$GITHUB_REPOSITORY" "$TAG"\n',
     '        run: echo skipping\n', CAUGHT),
    ("published-release-test-dropped", "ci.yml",
     "      - name: Test that an upload onto a published release is refused\n"
     "        run: python3 scripts/release/test_refuse_published_release.py\n", "", CAUGHT),
    ("release-jobs-cancel-each-other", "release.yml",
     "      cancel-in-progress: false\n    permissions:\n      contents: write\n      # Keyless",
     "      cancel-in-progress: true\n    permissions:\n      contents: write\n      # Keyless", CAUGHT),
    ("release-verifier-downgraded", "release.yml",
     "          cosign-release: v2.6.5\n", "          cosign-release: v2.5.2\n", CAUGHT),
    ("fail-closed-test-dropped", "ci.yml",
     "      - name: Test that signing fails closed\n        run: python3 scripts/release/test_sign_release_assets.py\n",
     "", CAUGHT),
]

# #1812: packaged tests build on every ref and run after a merge.
CASES += [
    ("package-tests-swallowed", "ci.yml",
     "    name: Tests build from the packaged crate\n",
     "    name: Tests build from the packaged crate\n    continue-on-error: true\n", CAUGHT),
    ("package-tests-only-on-push", "ci.yml",
     "    name: Tests build from the packaged crate\n",
     "    name: Tests build from the packaged crate\n    if: github.event_name == 'push'\n", CAUGHT),
    ("package-tests-build-step-dropped", "ci.yml",
     "      - name: Build the tests from the packaged crate\n"
     "        run: scripts/ci/packaged-tests.sh build\n", "", CAUGHT),
    ("docker-build-stops-waiting-for-package-tests", "ci.yml",
     "release-script-tests, package-tests, release-signing-checks]", "release-script-tests, release-signing-checks]", CAUGHT),
    ("packaged-suite-leaves-the-release-line", "packaged-suite.yml",
     "    branches: [main, docs/ranking-1-release-line]\n", "    branches: [main]\n", CAUGHT),
    ("packaged-suite-runs-on-every-pr", "packaged-suite.yml",
     "  workflow_dispatch:\n", "  pull_request:\n  workflow_dispatch:\n", CAUGHT),
    ("packaged-suite-builds-instead-of-running", "packaged-suite.yml",
     "scripts/ci/packaged-tests.sh run\n", "scripts/ci/packaged-tests.sh build\n", CAUGHT),
    ("packaged-rehearsal-on-every-pr", "ci.yml",
     "    if: github.event_name == 'workflow_dispatch' && (inputs.rehearse_packaged_suite",
     "    if: github.event_name == 'pull_request' || (inputs.rehearse_packaged_suite", CAUGHT),
    ("release-stops-waiting-for-the-packaged-suite", "release.yml",
     "    needs: [build, verify, packaged-suite]\n", "    needs: [build, verify]\n", CAUGHT),
    ("packaged-suite-dropped-from-the-release", "release.yml",
     "  packaged-suite:\n    needs: resolve\n    uses: ./.github/workflows/packaged-suite.yml\n",
     "  packaged-suite:\n    needs: resolve\n    uses: ./.github/workflows/task-sdk-recovery.yml\n", CAUGHT),
    ("crates-publish-stops-waiting-for-release", "release.yml",
     "  publish:\n    needs: [release, verify]\n", "  publish:\n    needs: [verify]\n", CAUGHT),
    ("test-job-gains-a-skip-the-package-lacks", "ci.yml",
     "      # that job provisions, and the gate below `needs` that job.\n"
     "      - run: cargo test --all-features --no-fail-fast -- --skip a_real_sdk_job_outlives_the_gateway_and_its_owner_reads_the_result --skip mik_7479_full_burst\n",
     "      # that job provisions, and the gate below `needs` that job.\n"
     "      - run: cargo test --all-features --no-fail-fast -- --skip a_real_sdk_job_outlives_the_gateway_and_its_owner_reads_the_result --skip mik_7479_full_burst --skip some_new_skip\n",
     CAUGHT),
]

# The release is the event commit: a case per checkout and called workflow
# that names a ref, and per way the dispatch guard can stop guarding. Each
# checkout anchor runs from the job header to its checkout line, so it names
# one site.
def _release_checkout_sites():
    text = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    sites = []
    for m in re.finditer(r"(?m)^  ([a-z0-9-]+):\n", text):
        nxt = re.search(r"(?m)^  [a-z0-9-]+:\n", text[m.end():])
        body = text[m.start():m.end() + nxt.start() if nxt else len(text)]
        for c in re.finditer(r"(?m)^( +)(?:- )?uses: actions/checkout@\S+ # v\S+\n", body):
            rest = body[c.end():]
            if re.match(r" +with:\n( +(?!ref:)\S.*\n)*? +repository:", rest):
                continue  # another repository (the Homebrew tap)
            anchor = body[:c.end()]
            indent = " " * (len(c.group(1)) + (2 if c.group(0).lstrip().startswith("- ") else 0))
            added = anchor + f"{indent}with:\n{indent}  ref: ${{{{ inputs.tag }}}}\n"
            if rest.startswith(f"{indent}with:\n"):
                anchor += f"{indent}with:\n"  # the ref joins the existing inputs
            sites.append((m.group(1), anchor, added))
    return sites


for _job, _anchor, _added in _release_checkout_sites():
    CASES += [(f"{_job}-checks-out-the-tag-name", "release.yml", _anchor, _added, CAUGHT)]
for _job in ("task-sdk-recovery", "packaged-suite"):
    CASES += [
        (f"{_job}-is-passed-the-tag-name", "release.yml",
         f"  {_job}:\n    needs: resolve\n    uses: ./.github/workflows/{_job}.yml\n",
         f"  {_job}:\n    needs: resolve\n    uses: ./.github/workflows/{_job}.yml\n    with:\n      ref: ${{{{ inputs.tag || github.ref }}}}\n", CAUGHT),
    ]
CASES += [
    ("packaged-suite-stops-waiting-for-resolve", "release.yml",
     "  packaged-suite:\n    needs: resolve\n", "  packaged-suite:\n", CAUGHT),
    ("security-gate-stops-waiting-for-resolve", "release.yml",
     "    name: Security gate (block release on known vulns)\n    needs: resolve\n",
     "    name: Security gate (block release on known vulns)\n", CAUGHT),
    # The guard itself: a dispatch from a branch or another tag, and a second
    # lookup of the tag, must each turn the suite red.
    ("resolve-accepts-a-branch-dispatch", "release.yml",
     '          if [ "$GITHUB_EVENT_NAME" = workflow_dispatch ] && [ "$GITHUB_REF" != "refs/tags/$TAG" ]; then\n', "          if false; then\n", CAUGHT),
    ("resolve-accepts-any-tag-dispatch", "release.yml",
     '          if [ "$GITHUB_EVENT_NAME" = workflow_dispatch ] && [ "$GITHUB_REF" != "refs/tags/$TAG" ]; then\n',
     '          if [ "$GITHUB_EVENT_NAME" = workflow_dispatch ] && [[ "$GITHUB_REF" != refs/tags/* ]]; then\n', CAUGHT),
    ("resolve-looks-the-tag-up-again", "release.yml",
     '          echo "release commit: $GITHUB_SHA"\n',
     '          [ -z "$TAG" ] || GITHUB_SHA="$(git ls-remote "https://github.com/$GITHUB_REPOSITORY.git" "refs/tags/$TAG^{}" | cut -f1)"\n' + '          echo "release commit: $GITHUB_SHA"\n', CAUGHT),
]

# Every installed cosign stays past the verification advisories.
CASES += [
    ("cosign-pin-downgraded", "ci.yml",
     "          cosign-release: v2.6.5\n      - name: Install syft (SBOM)\n        uses: anchore/sbom-action/download-syft@3ad7283483fc7af8ff2b4ea19663c2d5ca935e26 # v0.24.2\n      - name: Validate supply-chain smoke script\n",
     "          cosign-release: v2.6.4\n      - name: Install syft (SBOM)\n        uses: anchore/sbom-action/download-syft@3ad7283483fc7af8ff2b4ea19663c2d5ca935e26 # v0.24.2\n      - name: Validate supply-chain smoke script\n",
     CAUGHT),
    ("cosign-pin-quoted-and-downgraded", "ci.yml",
     "          cosign-release: v2.6.5\n      - name: Install syft (SBOM)\n        uses: anchore/sbom-action/download-syft@3ad7283483fc7af8ff2b4ea19663c2d5ca935e26 # v0.24.2\n      - name: Validate supply-chain smoke script\n",
     "          cosign-release: 'v2.5.2'\n      - name: Install syft (SBOM)\n        uses: anchore/sbom-action/download-syft@3ad7283483fc7af8ff2b4ea19663c2d5ca935e26 # v0.24.2\n      - name: Validate supply-chain smoke script\n", CAUGHT),
    ("cosign-pin-left-to-the-installer-default", "ci.yml",
     "        with:\n          cosign-release: v2.6.5\n      - name: Install syft (SBOM)\n        uses: anchore/sbom-action/download-syft@3ad7283483fc7af8ff2b4ea19663c2d5ca935e26 # v0.24.2\n      - name: Validate supply-chain smoke script\n",
     "      - name: Install syft (SBOM)\n        uses: anchore/sbom-action/download-syft@3ad7283483fc7af8ff2b4ea19663c2d5ca935e26 # v0.24.2\n      - name: Validate supply-chain smoke script\n", CAUGHT),
    ("cosign-pin-quoted-at-the-floor", "ci.yml",
     "          cosign-release: v2.6.5\n      - name: Install syft (SBOM)\n        uses: anchore/sbom-action/download-syft@3ad7283483fc7af8ff2b4ea19663c2d5ca935e26 # v0.24.2\n      - name: Validate supply-chain smoke script\n",
     "          cosign-release: \"v2.6.5\"\n      - name: Install syft (SBOM)\n        uses: anchore/sbom-action/download-syft@3ad7283483fc7af8ff2b4ea19663c2d5ca935e26 # v0.24.2\n      - name: Validate supply-chain smoke script\n", TOLERATED),
    # Any workflow file counts, not only the ones that install cosign today.
    ("cosign-installed-unpinned-in-another-workflow", "mrtr7b-full-burst.yml",
     "      - uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8 # stable\n      - name: Run the full-burst ledger\n",
     "      - uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8 # stable\n"
     "      - uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2\n"
     "      - name: Run the full-burst ledger\n", CAUGHT),
    # A quoted action reference is still the installer and still needs the pin.
    ("cosign-installed-unpinned-with-a-quoted-uses", "mrtr7b-full-burst.yml",
     "      - uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8 # stable\n      - name: Run the full-burst ledger\n",
     "      - uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8 # stable\n"
     "      - uses: \"sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6\" # v4.1.2\n"
     "      - name: Run the full-burst ledger\n", CAUGHT),
    ("cosign-pin-below-the-floor-behind-a-single-quoted-uses", "ci.yml",
     "        uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2\n        with:\n          cosign-release: v2.6.5\n      - name: Install syft (SBOM)\n        uses: anchore/sbom-action/download-syft@3ad7283483fc7af8ff2b4ea19663c2d5ca935e26 # v0.24.2\n      - name: Validate supply-chain smoke script\n",
     "        uses: 'sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6' # v4.1.2\n        with:\n          cosign-release: v2.6.4\n      - name: Install syft (SBOM)\n        uses: anchore/sbom-action/download-syft@3ad7283483fc7af8ff2b4ea19663c2d5ca935e26 # v0.24.2\n      - name: Validate supply-chain smoke script\n", CAUGHT),
    # The push-guard inventory must still see a quoted installer: a second,
    # unnamed one with no tag guard is found only by what it uses.
    ("cosign-installer-quoted-and-unguarded", "ci.yml",
     "      - name: Install cosign\n        if: (github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')) || (github.event_name == 'workflow_dispatch' && (inputs.rehearse_manifest == true || inputs.rehearse_manifest == 'true'))\n",
     "      - uses: \"sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6\" # v4.1.2\n        with:\n          cosign-release: v2.6.5\n"
     "      - name: Install cosign\n        if: (github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')) || (github.event_name == 'workflow_dispatch' && (inputs.rehearse_manifest == true || inputs.rehearse_manifest == 'true'))\n", CAUGHT),
    # A quoted key is the same key.
    ("cosign-installed-unpinned-under-a-quoted-uses-key", "mrtr7b-full-burst.yml",
     "      - uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8 # stable\n      - name: Run the full-burst ledger\n",
     "      - uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8 # stable\n"
     "      - \"uses\": sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2\n"
     "      - name: Run the full-burst ledger\n", CAUGHT),
    # Any run of spaces after the list dash is the same step.
    ("cosign-installed-below-the-floor-after-a-wide-dash", "mrtr7b-full-burst.yml",
     "      - uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8 # stable\n      - name: Run the full-burst ledger\n",
     "      - uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8 # stable\n"
     "      -   uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2\n          with:\n            cosign-release: v2.6.4\n"
     "      - name: Run the full-burst ledger\n", CAUGHT),
    # A flow-style step still installs cosign; its pin cannot be read.
    ("cosign-installed-below-the-floor-as-a-flow-mapping", "mrtr7b-full-burst.yml",
     "      - uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8 # stable\n      - name: Run the full-burst ledger\n",
     "      - uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8 # stable\n"
     "      - { uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6, with: { cosign-release: v2.6.4 } }\n"
     "      - name: Run the full-burst ledger\n", CAUGHT),
    # An alias installs what its anchor names under a name no check reads.
    ("cosign-installer-reused-through-an-alias", "ci.yml",
     "        # cosign-release is pinned so flag behavior can't drift under a v3 default.\n        uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2\n        with:\n          cosign-release: v2.6.5\n",
     "        # cosign-release is pinned so flag behavior can't drift under a v3 default.\n        uses: &cosign_installer sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2\n        with:\n          cosign-release: v2.6.5\n"
     "      - name: Install cosign again\n        uses: *cosign_installer\n        with:\n          cosign-release: v2.5.2\n", CAUGHT),
    ("cosign-installer-reused-through-a-flow-style-alias", "ci.yml",
     "        # cosign-release is pinned so flag behavior can't drift under a v3 default.\n        uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2\n        with:\n          cosign-release: v2.6.5\n",
     "        # cosign-release is pinned so flag behavior can't drift under a v3 default.\n        uses: &cosign_installer sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2\n        with:\n          cosign-release: v2.6.5\n"
     "      - { uses: *cosign_installer, with: { cosign-release: v2.5.2 } }\n", CAUGHT),
    ("cosign-installer-reused-through-a-numeric-alias", "ci.yml",
     "        # cosign-release is pinned so flag behavior can't drift under a v3 default.\n        uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2\n        with:\n          cosign-release: v2.6.5\n",
     "        # cosign-release is pinned so flag behavior can't drift under a v3 default.\n        uses: &1 sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2\n        with:\n          cosign-release: v2.6.5\n"
     "      - uses: *1\n        with:\n          cosign-release: v2.5.2\n", CAUGHT),
    # GitHub matches an action's owner and repository in any case.
    ("cosign-installed-below-the-floor-in-another-case", "mrtr7b-full-burst.yml",
     "      - uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8 # stable\n      - name: Run the full-burst ledger\n",
     "      - uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8 # stable\n      - uses: Sigstore/Cosign-Installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2\n        with:\n          cosign-release: v2.5.2\n      - name: Run the full-burst ledger\n", CAUGHT),
    ("cosign-installer-in-another-case-and-unguarded", "ci.yml",
     "      - name: Install cosign\n        if: (github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')) || (github.event_name == 'workflow_dispatch' && (inputs.rehearse_manifest == true || inputs.rehearse_manifest == 'true'))\n",
     "      - uses: Sigstore/Cosign-Installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2\n        with:\n          cosign-release: v2.6.5\n"
     "      - name: Install cosign\n        if: (github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')) || (github.event_name == 'workflow_dispatch' && (inputs.rehearse_manifest == true || inputs.rehearse_manifest == 'true'))\n", CAUGHT),
    ("cosign-installer-in-another-case-keeps-its-exemption", "ci.yml",
     "        # cosign-release is pinned so flag behavior can't drift under a v3 default.\n        uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2\n",
     "        # cosign-release is pinned so flag behavior can't drift under a v3 default.\n        uses: Sigstore/Cosign-Installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2\n", TOLERATED),
    # A pin inside another input's block scalar is text the action never reads.
    ("cosign-pin-hidden-in-another-inputs-block-scalar", "ci.yml",
     "        with:\n          cosign-release: v2.6.5\n      - name: Install syft (SBOM)\n        uses: anchore/sbom-action/download-syft@3ad7283483fc7af8ff2b4ea19663c2d5ca935e26 # v0.24.2\n      - name: Validate supply-chain smoke script\n",
     "        with:\n          ignored-input: |\n            cosign-release: v2.6.5\n      - name: Install syft (SBOM)\n        uses: anchore/sbom-action/download-syft@3ad7283483fc7af8ff2b4ea19663c2d5ca935e26 # v0.24.2\n      - name: Validate supply-chain smoke script\n", CAUGHT),
    # A shell redirection or a comment is not a YAML anchor.
    ("shell-redirection-and-a-comment-are-not-anchors", "mrtr7b-full-burst.yml",
     "      - uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8 # stable\n      - name: Run the full-burst ledger\n",
     "      - uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8 # stable\n      # see &notes\n      - run: true &>/dev/null\n      - name: Run the full-burst ledger\n", TOLERATED),
    # A double-quoted reference continued after `\\` is one reference to YAML.
    ("cosign-installer-reference-continued-onto-a-second-line", "mrtr7b-full-burst.yml",
     "      - uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8 # stable\n      - name: Run the full-burst ledger\n",
     "      - uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8 # stable\n      - uses: \"sigstore/cosign-\\\n          installer@6f9f17788090df1f26f669e9d70d6ae9567deba6\"\n        with:\n          cosign-release: v2.5.2\n      - name: Run the full-burst ledger\n", CAUGHT),
    ("cosign-installer-reference-spelled-with-an-escape", "mrtr7b-full-burst.yml",
     "      - uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8 # stable\n      - name: Run the full-burst ledger\n",
     "      - uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8 # stable\n      - uses: \"sigstore/cosign\\x2dinstaller@6f9f17788090df1f26f669e9d70d6ae9567deba6\"\n        with:\n          cosign-release: v2.5.2\n      - name: Run the full-burst ledger\n", CAUGHT),
    # The floor reads the parsed workflow: spellings a text scan misses.
    ("cosign-installer-with-escaped-key-and-value-below-the-floor", "mrtr7b-full-burst.yml",
     "      - uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8 # stable\n      - name: Run the full-burst ledger\n",
     "      - uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8 # stable\n      - \"u\\x73es\": \"sigstore/cosign\\x2dinstaller@6f9f17788090df1f26f669e9d70d6ae9567deba6\"\n        with:\n          cosign-release: v2.5.2\n      - name: Run the full-burst ledger\n", CAUGHT),
    ("cosign-installer-flow-step-with-a-quoted-hash-below-the-floor", "mrtr7b-full-burst.yml",
     "      - uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8 # stable\n      - name: Run the full-burst ledger\n",
     "      - uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8 # stable\n      - { name: \"Install #1\", uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6, with: { cosign-release: v2.5.2 } }\n      - name: Run the full-burst ledger\n", CAUGHT),
    # At the floor, only the recogniser check sees it: the inventory and the
    # rehearsal exemption would read past this installer.
    ("cosign-installer-with-escaped-key-at-the-floor", "mrtr7b-full-burst.yml",
     "      - uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8 # stable\n      - name: Run the full-burst ledger\n",
     "      - uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8 # stable\n      - \"u\\x73es\": \"sigstore/cosign\\x2dinstaller@6f9f17788090df1f26f669e9d70d6ae9567deba6\"\n        with:\n          cosign-release: v2.6.5\n      - name: Run the full-burst ledger\n", CAUGHT),
    # PyYAML keeps the last of two keys and flattens `<<`; the strict
    # loader refuses both.
    ("cosign-pin-given-twice", "ci.yml",
     "        with:\n          cosign-release: v2.6.5\n      - name: Install syft (SBOM)\n        uses: anchore/sbom-action/download-syft@3ad7283483fc7af8ff2b4ea19663c2d5ca935e26 # v0.24.2\n      - name: Validate supply-chain smoke script\n",
     "        with:\n          cosign-release: v2.5.2\n          cosign-release: v2.6.5\n      - name: Install syft (SBOM)\n        uses: anchore/sbom-action/download-syft@3ad7283483fc7af8ff2b4ea19663c2d5ca935e26 # v0.24.2\n      - name: Validate supply-chain smoke script\n", CAUGHT),
    ("cosign-pin-through-a-merge-key", "ci.yml",
     "        with:\n          cosign-release: v2.6.5\n      - name: Install syft (SBOM)\n        uses: anchore/sbom-action/download-syft@3ad7283483fc7af8ff2b4ea19663c2d5ca935e26 # v0.24.2\n      - name: Validate supply-chain smoke script\n",
     "        with:\n          <<: { cosign-release: v2.6.5 }\n      - name: Install syft (SBOM)\n        uses: anchore/sbom-action/download-syft@3ad7283483fc7af8ff2b4ea19663c2d5ca935e26 # v0.24.2\n      - name: Validate supply-chain smoke script\n", CAUGHT),
    ("release-runs-the-floor-without-its-parser", "release.yml",
     "      - name: Install PyYAML 6.0.2 (the cosign floor parses workflows)\n        run: python3 -c 'import sys, yaml; sys.exit(yaml.__version__ != \"6.0.2\")' 2>/dev/null || python3 -m pip install --user --quiet 'pyyaml==6.0.2'\n",
     "", CAUGHT),
    # The installer's rehearsal exemption applies to it quoted as well.
    ("cosign-installer-quoted-keeps-its-exemption", "ci.yml",
     "        # cosign-release is pinned so flag behavior can't drift under a v3 default.\n        uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2\n",
     "        # cosign-release is pinned so flag behavior can't drift under a v3 default.\n        uses: 'sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6' # v4.1.2\n", TOLERATED),
    # Under env: the input never reaches the action, which installs its default.
    ("cosign-pin-moved-under-env", "ci.yml",
     "        with:\n          cosign-release: v2.6.5\n      - name: Install syft (SBOM)\n        uses: anchore/sbom-action/download-syft@3ad7283483fc7af8ff2b4ea19663c2d5ca935e26 # v0.24.2\n      - name: Validate supply-chain smoke script\n",
     "        env:\n          cosign-release: v2.6.5\n      - name: Install syft (SBOM)\n        uses: anchore/sbom-action/download-syft@3ad7283483fc7af8ff2b4ea19663c2d5ca935e26 # v0.24.2\n      - name: Validate supply-chain smoke script\n", CAUGHT),
    ("cosign-pin-moved-up-a-major", "ci.yml",
     "          cosign-release: v2.6.5\n      - name: Install syft (SBOM)\n        uses: anchore/sbom-action/download-syft@3ad7283483fc7af8ff2b4ea19663c2d5ca935e26 # v0.24.2\n      - name: Validate supply-chain smoke script\n",
     "          cosign-release: v3.1.3\n      - name: Install syft (SBOM)\n        uses: anchore/sbom-action/download-syft@3ad7283483fc7af8ff2b4ea19663c2d5ca935e26 # v0.24.2\n      - name: Validate supply-chain smoke script\n",
     CAUGHT),
]

# Release jobs restore no cache: one case per way one comes back.
CASES += [
    ("release-verify-restores-the-rust-cache", "release.yml",
     '      # No build cache: a restored cache is input nobody reviewed at the tag.\n', '      - uses: Swatinem/rust-cache@f0d9c3887740aee45f6153b24b3a6b815192ec16 # v2\n', CAUGHT),
    ("release-verify-restores-a-cache-quoted", "release.yml",
     '      # No build cache: a restored cache is input nobody reviewed at the tag.\n', '      - "uses": \'actions/cache/restore@v4\'\n        with:\n          path: target\n          key: release\n', CAUGHT),
    ("called-recovery-restores-the-rust-cache", "task-sdk-recovery.yml",
     '      # No build cache: the release calls this too, and a restored cache is\n      # input nobody reviewed at the tag.\n', '      - uses: Swatinem/rust-cache@f0d9c3887740aee45f6153b24b3a6b815192ec16 # v2\n', CAUGHT),
    ("called-packaged-suite-restores-the-rust-cache", "packaged-suite.yml",
     "      # No build cache: the release calls this, and a restored cache is input\n      # nobody reviewed at the tag.\n", "      - uses: Swatinem/rust-cache@f0d9c3887740aee45f6153b24b3a6b815192ec16 # v2\n", CAUGHT),
    ("release-setup-node-caches-again", "release.yml",
     "          registry-url: 'https://registry.npmjs.org'\n          package-manager-cache: false\n", "          registry-url: 'https://registry.npmjs.org'\n", CAUGHT),
    # Equivalent spellings are not a cache: a quoted callee is still scanned,
    # and YAML's `False` is still off.
    ("release-calls-the-recovery-workflow-quoted", "release.yml",
     "    uses: ./.github/workflows/task-sdk-recovery.yml\n",
     "    uses: './.github/workflows/task-sdk-recovery.yml' # quoted\n", TOLERATED),
    ("release-setup-node-cache-off-capitalised", "release.yml",
     "          package-manager-cache: false\n", "          package-manager-cache: False\n", TOLERATED),
    ("release-setup-node-sets-a-cache", "release.yml",
     "          registry-url: 'https://registry.npmjs.org'\n          package-manager-cache: false\n", "          registry-url: 'https://registry.npmjs.org'\n          package-manager-cache: false\n          cache: npm\n", CAUGHT),
    ("called-full-burst-restores-the-rust-cache", "mrtr7b-full-burst.yml",
     "      - name: Run the full-burst ledger\n",
     "      - uses: Swatinem/rust-cache@f0d9c3887740aee45f6153b24b3a6b815192ec16 # v2\n      - name: Run the full-burst ledger\n", CAUGHT),
]

# The full burst every per-PR job skips gates the release (MIK-7534).
CASES += [
    ("release-verify-drops-the-full-burst", "release.yml",
     "needs: [security-gate, secret-leak-lint, release-criteria, task-sdk-recovery, mrtr7b-full-burst]\n",
     "needs: [security-gate, secret-leak-lint, release-criteria, task-sdk-recovery]\n", CAUGHT),
    ("full-burst-no-longer-callable", "mrtr7b-full-burst.yml", "  workflow_call:\n", "", CAUGHT),
    ("full-burst-runs-another-test", "mrtr7b-full-burst.yml",
     "            mik_7479_full_burst_every_call_reaches_one_terminal_frame --nocapture",
     "            mik_7479_one_call_reaches_one_terminal_frame --nocapture", CAUGHT),
    # MIK-7835: a source PR compiles on both declared toolchains, fatally.
    ("release-compile-drops-the-dockerfile-row", "docker.yml",
     "        source: [dockerfile, rust-version]\n", "        source: [rust-version]\n", CAUGHT),
    ("release-compile-drops-the-rust-version-row", "docker.yml",
     "        source: [dockerfile, rust-version]\n", "        source: [dockerfile]\n", CAUGHT),
    ("release-compile-tolerated", "docker.yml",
     "      - name: Compile as the image does (release, locked, default features)\n",
     "      - name: Compile as the image does (release, locked, default features)\n"
     "        continue-on-error: true\n", CAUGHT),
    ("release-compile-not-selected-by-source", "docker.yml",
     "            compile true \"source changed\"\n", "            echo \"source changed\"\n", CAUGHT),
    ("release-compile-ungated-off", "docker.yml",
     "    if: needs.scope.outputs.compile_check == 'true'\n", "    if: false\n", CAUGHT),
    # MIK-7678: the recursion margin runs in a required job, fatally.
    ("recursion-margin-dropped", "ci.yml", "        run: scripts/ci/check-recursion-margin.sh\n",
     "        run: echo skipped\n", CAUGHT),
    ("recursion-margin-tolerated", "ci.yml", "        run: scripts/ci/check-recursion-margin.sh\n",
     "        continue-on-error: true\n        run: scripts/ci/check-recursion-margin.sh\n", CAUGHT),
    # MIK-7952: the chart is published over the signed image, by this workflow's identity.
    ("chart-publish-stops-waiting-for-the-image", "ci.yml",
     "    name: Publish and sign the Helm chart\n    needs: docker-manifest\n",
     "    name: Publish and sign the Helm chart\n    needs: docker-build\n", CAUGHT),
    ("chart-publish-ignores-a-failed-manifest", "ci.yml",
     "      && needs.docker-manifest.result == 'success'\n", "", CAUGHT),
    ("chart-published-for-a-prerelease", "ci.yml",
     "      && needs.docker-manifest.outputs.is_prerelease == 'false')\n", ")\n", CAUGHT),
    ("chart-pins-the-movable-tag", "ci.yml",
     'image="ghcr.io/mikkoparkkola/mcp-gateway@${SIGNED_LIST}"; repo=oci://ghcr.io/mikkoparkkola/charts\n',
     'image="ghcr.io/mikkoparkkola/mcp-gateway:${GITHUB_REF_NAME#v}"; repo=oci://ghcr.io/mikkoparkkola/charts\n', CAUGHT),
    ("chart-signed-as-a-fixed-identity", "ci.yml",
     "          IDENTITY: https://github.com/${{ github.workflow_ref }}\n",
     "          IDENTITY: https://github.com/MikkoParkkola\n", CAUGHT),
    ("chart-publisher-not-run", "ci.yml",
     '            scripts/release/publish_pinned_chart.sh "$image" "$repo"',
     '            true "$image" "$repo"', CAUGHT),
    ("chart-wrong-identity-check-dropped", "ci.yml",
     '          if cosign verify --certificate-identity "$wrong"',
     '          if false && cosign verify --certificate-identity "$wrong"', CAUGHT),
    ("chart-wrong-identity-any-failure-passes", "ci.yml",
     "          grep -q 'none of the expected identities matched'",
     "          true || grep -q 'none of the expected identities matched'", CAUGHT),
    # MIK-7484: the documented recipe serves a call, on the built image, fatally.
    ("recipe-smoke-dropped", "docker.yml", "        run: scripts/dev/docker-smoke.sh\n",
     "        run: echo skipped\n", CAUGHT),
    ("recipe-smoke-tolerated", "docker.yml", "        run: scripts/dev/docker-smoke.sh\n",
     "        continue-on-error: true\n        run: scripts/dev/docker-smoke.sh\n", CAUGHT),
    ("recipe-smoke-builds-on-the-host", "docker.yml", '          MCP_GATEWAY_INIT_IN_IMAGE: "1"\n',
     '          MCP_GATEWAY_INIT_IN_IMAGE: "0"\n', CAUGHT),
    ("recipe-smoke-rebuilds-the-image", "docker.yml", '          MCP_GATEWAY_DOCKER_BUILD: "0"\n',
     '          MCP_GATEWAY_DOCKER_BUILD: "1"\n', CAUGHT),
    # MIK-7644: the Windows suite skips the full burst, and only the full burst.
    ("windows-runs-the-full-burst", "ci.yml",
     "--no-fail-fast -- --show-output --skip mik_7479_full_burst\n",
     "--no-fail-fast -- --show-output\n", CAUGHT),
    ("windows-skip-also-drops-the-per-pr-burst", "ci.yml",
     "--no-fail-fast -- --show-output --skip mik_7479_full_burst\n",
     "--no-fail-fast -- --show-output --skip mik_7479_full_burst --skip ac_mrtr_7b_every\n", CAUGHT),
]

# Throwaway runs carry the release tooling's Python suites. The hosted job is
# named by its runner line, the trusted one by its env block, so each anchor
# names one job although both run the same steps.
_HOSTED_PY = (
    "    runs-on: ubuntu-latest\n    timeout-minutes: 60\n    permissions:\n      contents: read\n    steps:\n"
    "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n"
    "        with:\n          persist-credentials: false\n"
)
_TRUSTED_HEAD = "    env:\n      CARGO_BUILD_JOBS: 6\n    steps:\n"
_HOSTED_PY_STEP = _HOSTED_PY + (
    "      # The release tooling's Python suites, which `release-script-tests` runs\n"
    '      # but which that job skips here. Without this, a throwaway meant to show\n'
    '      # a workflow-wiring or release-script test going red passes on cargo\n'
    '      # alone. Every suite runs and all failures are reported; seconds, no cargo.\n'
    '      - name: Install PyYAML 6.0.2 (the cosign floor parses workflows)\n'
    '        run: python3 -c \'import sys, yaml; sys.exit(yaml.__version__ != "6.0.2")\' 2>/dev/null || python3 -m pip install --user --quiet \'pyyaml==6.0.2\'\n'
    '      - name: Release tooling Python suites\n'
    '        run: |\n'
    '          set -uo pipefail\n'
    '          fail=0\n'
    '          for suite in scripts/release/test_*.py; do\n'
    '            echo "::group::$suite"\n'
    '            python3 "$suite" || { echo "::error::$suite failed"; fail=1; }\n'
    '            echo "::endgroup::"\n'
    '          done\n'
    '          exit "$fail"\n'
)
CASES += [
    ("throwaway-python-suites-dropped", "ci.yml", _HOSTED_PY_STEP, _HOSTED_PY, CAUGHT),
    ("throwaway-python-failure-swallowed", "ci.yml",
     '          exit "$fail"\n      - uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8 # stable\n'
     "      # Restore only: saving from throwaway runs would evict the entries the\n"
     "      # merge-evidence jobs rely on from the shared 10 GB repository cache.\n"
     "      - uses: Swatinem/rust-cache@f0d9c3887740aee45f6153b24b3a6b815192ec16 # v2\n"
     "        with:\n          save-if: false\n"
     "      # Each skip names the job that runs the test in full, and its ticket:\n"
     "      #   a_real_sdk_job_outlives_...: job `task-sdk-recovery`, MIK-7534.\n"
     "      #   mik_7479_full_burst: workflow mrtr7b-full-burst.yml, MIK-7479;\n"
     "      #   release.yml `verify` needs it green on the released revision.\n"
     "      - run: cargo test --all-features --no-fail-fast -- --skip a_real_sdk_job_outlives_the_gateway_and_its_owner_reads_the_result --skip mik_7479_full_burst\n\n"
     "  # Same run on the self-hosted arm64 runner.",
     '          exit 0\n      - uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8 # stable\n'
     "      # Restore only: saving from throwaway runs would evict the entries the\n"
     "      # merge-evidence jobs rely on from the shared 10 GB repository cache.\n"
     "      - uses: Swatinem/rust-cache@f0d9c3887740aee45f6153b24b3a6b815192ec16 # v2\n"
     "        with:\n          save-if: false\n"
     "      # Each skip names the job that runs the test in full, and its ticket:\n"
     "      #   a_real_sdk_job_outlives_...: job `task-sdk-recovery`, MIK-7534.\n"
     "      #   mik_7479_full_burst: workflow mrtr7b-full-burst.yml, MIK-7479;\n"
     "      #   release.yml `verify` needs it green on the released revision.\n"
     "      - run: cargo test --all-features --no-fail-fast -- --skip a_real_sdk_job_outlives_the_gateway_and_its_owner_reads_the_result --skip mik_7479_full_burst\n\n"
     "  # Same run on the self-hosted arm64 runner.", CAUGHT),
    ("trusted-throwaway-swallows-failures", "ci.yml",
     _TRUSTED_HEAD, "    continue-on-error: true\n" + _TRUSTED_HEAD, CAUGHT),
]

# MIK-7850: the ranking corpus compare runs every ref and fails on a mismatch.
_CORPUS_NAME = "      - name: Ranking corpus regenerates byte for byte (MIK-7850)\n"
_CORPUS_CMP = '          python3 benchmarks/ranking-baseline/gen_corpus.py "$tree" | cmp - benchmarks/ranking-baseline/corpus.json\n'
_CORPUS_STEP = (
    _CORPUS_NAME
    + "        run: |\n"
    + "          set -euo pipefail\n"
    + "          git fetch --no-tags --depth=1 origin f241b464acf6007a88ebc2b576c0825350b018a1\n"
    + "          tree=$(mktemp -d)\n"
    + '          git archive FETCH_HEAD capabilities | tar -x -C "$tree"\n'
    + _CORPUS_CMP
)
CASES += [
    ("corpus-compare-deleted", "ci.yml", _CORPUS_STEP, "", CAUGHT),
    ("corpus-compare-masked", "ci.yml", _CORPUS_CMP, _CORPUS_CMP[:-1] + " || true\n", CAUGHT),
    ("corpus-compare-continues-on-error", "ci.yml",
     _CORPUS_NAME, _CORPUS_NAME + "        continue-on-error: true\n", CAUGHT),
    ("corpus-compare-without-pipefail", "ci.yml",
     "          set -euo pipefail\n          git fetch --no-tags --depth=1 origin f241b464",
     "          git fetch --no-tags --depth=1 origin f241b464", CAUGHT),
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
            # SupplyChain reads the same workflow copies and is one-sided in the
            # same way, so it is mutated by the same corpus. Classes that read
            # the working tree rather than the copy are left out: a mutation
            # cannot reach them, so they would report tolerated for every case.
            [sys.executable, str(SUITE), "WorkflowWiring", "SupplyChain", "RehearsalVerify"],
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
