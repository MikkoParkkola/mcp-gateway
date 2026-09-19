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
        '            cosign verify \\\n'
        '              --certificate-identity "${IDENTITY}" \\\n'
        "              --certificate-oidc-issuer "
        "'https://token.actions.githubusercontent.com' \\\n"
        '              "${IMAGE}@${d}"\n',
        "",
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
        "        env:\n          LIST: ${{ steps.list.outputs.list }}\n",
        "      - name: Cosign keyless-sign the list and both children\n"
        "        env:\n          LIST: ${{ steps.meta.outputs.version }}\n",
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
        "      - name: Generate + attest an SBOM (SPDX JSON) per published digest\n"
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
        '          for d in "${LIST}" "${AMD64}" "${ARM64}"; do\n'
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
        "        env:\n"
        "          LIST: ${{ steps.list.outputs.list }}\n"
        "          AMD64: ${{ steps.list.outputs.amd64 }}\n"
        "          ARM64: ${{ steps.list.outputs.arm64 }}\n"
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
        "        env:\n          LIST: ${{ steps.list.outputs.list }}\n",
        "      - name: Cosign keyless-sign the list and both children\n"
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
        "    needs: [build, verify]",
        "    needs:\n      - build\n      - verify",
        TOLERATED,
    ),
    (
        "digest-expression-without-inner-spaces",
        "ci.yml",
        "      - name: Cosign keyless-sign the list and both children\n"
        "        env:\n          LIST: ${{ steps.list.outputs.list }}\n",
        "      - name: Cosign keyless-sign the list and both children\n"
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
        "        env:\n"
        "          LIST: ${{ steps.list.outputs.list }}\n"
        "          AMD64: ${{ steps.list.outputs.amd64 }}\n"
        "          ARM64: ${{ steps.list.outputs.arm64 }}\n"
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
        '          docker buildx imagetools create --tag "${IMAGE}:sha-${GITHUB_SHA}" \\\n',
        '          docker buildx imagetools create --tag "${IMAGE}:${VERSION}" \\\n',
        CAUGHT,
    ),
    (
        # The release copy ALSO run before signing, with the late one left in
        # place: every string the suite looks for is still where it was, and
        # only the step order says the tag existed unsigned first.
        "release-tag-copied-before-signing-as-well",
        "ci.yml",
        '          echo "published platforms: ${PLATFORMS}"\n',
        '          echo "published platforms: ${PLATFORMS}"\n'
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
        "docker-yml-pushing-on-a-tag-again",
        "docker.yml",
        "        push: ${{ github.event_name != 'pull_request'"
        " && !startsWith(github.ref, 'refs/tags/v') }}",
        "        push: ${{ github.event_name != 'pull_request' }}",
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
            [sys.executable, str(SUITE), "WorkflowWiring", "SupplyChain"],
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
