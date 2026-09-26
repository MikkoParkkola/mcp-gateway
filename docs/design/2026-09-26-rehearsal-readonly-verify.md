# Rehearsal runs the release verify, read-only, against a pinned signed release

Status: FINAL after three design review rounds (grok and glm-5.3: SHIP-WITH-FIXES each round; round-3 correctness fixes applied) · Owner ruling: coordinator ruling 2 (2026-09-26) · Follows #1145

## Problem

A manifest rehearsal (`workflow_dispatch`, `rehearse_manifest=true`) stops at
`.github/workflows/ci.yml:792` ("Everything below this line belongs to a release").
The verify step (`ci.yml:847-878` at e8c8d00be, comment plus step) therefore ran for the first time on the
v4.0.0-beta.2 tag. Its stdout volume wedged the runner, and beta.2 was never published
(run 36193916273; root cause and repro in #1145 / #1143). A rehearsal could not have
caught it, because it never reaches the verify step.

Signing on a rehearsal is ruled out (coordinator ruling 1): every dispatch would leave a
permanent public Rekor entry, and `ci.yml:792-796` plus
`scripts/release/test_check_tag_manifest.py:1760-1814` treat "no release-sensitive step
off a tag" as a deliberate, tested invariant.

## Goal

A rehearsal runs the verify command in the same shape as the release (same cosign
install, same flags, same output handling, same step timeout) against subjects that
are already signed, so the verify path is exercised before a tag exists. It must:
- sign, attest, or write nothing;
- never verify the build under rehearsal;
- change the push-guard invariant only as far as this one step needs.

## Design

**D1. Pinned subject.** The rehearsal verifies the six digests of v4.0.0-beta.2. They
were signed and SBOM-attested by run 36193916273 under
`ci.yml@refs/tags/v4.0.0-beta.2`, and are held by the provenance tags
`sha-7df9eac347c8d1985952580f8803307b31c3dc6c` and its `-full` twin:

| role | digest |
|---|---|
| index | `sha256:1471cafc9f2a88855fd8997da8316b8122335bef3d3886a3bbb64768aebc9638` |
| amd64 | `sha256:e6f42fff9d678367a500d3d3d0177d77edbb6c6d96086c7f8dd7e74952a44cfc` |
| arm64 | `sha256:50ec31205c65ed27a1d30c056960f2b31de34b72bb7efb98440fbf5d4465bdef` |
| index full | `sha256:ce949392883b14034db9ec60ffb2f808c5458f5ce4bb26402ffa42eb45a47a8e` |
| amd64 full | `sha256:9c4712b85974f150874d16ec1b7b7e72c858673093eed33732f91e9b2adde4c5` |
| arm64 full | `sha256:d267a3477aeec6f8702b2851e93d9e29ba8fd94cd13920dd158d8cb43e929da9` |

The digests and the identity are literals in the step's `env:`. Nothing is derived from
the run: no `steps.*.outputs`, no `github.ref`, no `github.sha`. A literal digest cannot
drift onto the build under rehearsal. Bumping the pin to a later release is an ordinary
reviewed edit, and is not required.

**D2. One new step, rehearsal-only.** It is named "Rehearse the release verify against a
pinned signed release". It sits in `docker-manifest` directly after "Install cosign"
(`ci.yml:797-802`) and before "Install syft". It cannot go straight after "Assert the
list carries both platforms" (`ci.yml:768`), because cosign is not installed there yet.
A static test pins the order (T8).

Its condition is exactly the job's rehearsal disjunct:
`github.event_name == 'workflow_dispatch' && (inputs.rehearse_manifest == true || inputs.rehearse_manifest == 'true')`.
On a tag push it is skipped, because the real verify step runs there.

The comments at `ci.yml:658-661` ("a rehearsal ends at the both-platforms assertion") and
`ci.yml:792-796` are amended in the same change. They must name the installer and this
step as the only rehearsal-capable steps below the line, so a later edit does not delete
the step as out of bounds.

**D3. Same shape, enforced.** The body is the release verify loop verbatim: the same
`for d in …` over six values, `set -euo pipefail`, both `cosign verify` and
`cosign verify-attestation --type spdxjson` with `--certificate-identity "${IDENTITY}"`
and the same issuer, and `> /dev/null` on each. It also sets `timeout-minutes: 10`. Only
the `env:` values differ. The image name is the literal
`IMAGE=ghcr.io/mikkoparkkola/mcp-gateway` in the body, as in the release step. A
test asserts that the two `run:` bodies are identical after joining continuations, and
that the ordered list of every cosign invocation is identical, so an added subcommand is caught as well as an
edited flag or redirect. It also asserts that their `timeout-minutes` are equal. The release step has
`timeout-minutes: 10` since #1145. A later
edit to one step without the other fails CI (see T2).

**D4. cosign on a rehearsal.** "Install cosign" (`ci.yml:797-802`) widens its condition
to tag-push OR the rehearsal disjunct, so both paths run the same pinned `cosign-release`.
The installer writes nothing outside the runner. "Install syft" stays tag-only.

**D5. What the rehearsal still does not do.** It runs no `cosign sign` or `cosign attest`,
no `syft`, and no `imagetools create` of a release name. It never reads
`steps.meta.outputs`. The job-level permissions (`packages: write`, `id-token: write`)
are unchanged, because the job already holds them on a rehearsal to push the
provenance-named index. `cosign verify` requests no OIDC token and writes no Rekor
entry.

## Invariant amendment

Today `test_every_release_sensitive_step_carries_the_push_guard`
(`test_check_tag_manifest.py:1760-1814`) inventories steps by what they do (cosign
sign/attest/verify, syft, the gate script, `${VERSION}`, mcp-publisher, the cosign and
syft installers). It requires each one's `if:` to contain the substrings
`github.event_name == 'push'` and `refs/tags/v`.

Two steps get narrow exemptions. Nothing else changes:

- **E1: read-only verify.** A step may carry exactly the rehearsal condition (D2), with
  no tag-push guard, only if ALL of these hold:
  1. its only release-sensitive markers are `cosign verify` or `cosign verify-attestation`;
  2. no piece of it runs `cosign sign`, `cosign attest`, `syft`, `imagetools create`, or
     reads `${VERSION}`;
  3. every value in its `env:` is a literal (no `${{`), and its env keys are exactly the
     release verify step's keys (`LIST AMD64 ARM64 LIST_FULL AMD64_FULL ARM64_FULL
     IDENTITY`). An extra literal key, such as a toggle cosign reads, is rejected, so it
     cannot weaken the rehearsal relative to the release;
  4. its `for d in` list is exactly the six words `"${LIST}" "${AMD64}" "${ARM64}"
     "${LIST_FULL}" "${AMD64_FULL}" "${ARM64_FULL}"`, in the release step's order. Each
     key's value matches `^sha256:[0-9a-f]{64}$`, and the body assigns none of them.
     Dropping one subject loses the exemption;
  5. `IDENTITY` is a literal matching
     `^https://github\.com/MikkoParkkola/mcp-gateway/\.github/workflows/ci\.yml@refs/tags/v[0-9][0-9A-Za-z.-]*$`.
- **E2: the cosign installer.** Its condition may be exactly
  `<tag-push guard> || (<rehearsal disjunct>)`, and nothing else. It is written on one
  unfolded `if:` line, because the site scanner at `test_check_tag_manifest.py:1645-1648`
  reads single lines.

Tightening that comes with the amendment: substring matching already admits
`<tag-push> || anything`, so a disjunct could be widened silently today. With E2
introducing the first legitimate `||`, every non-exempt release-sensitive step must now
carry the tag-push guard as exact top-level conjuncts. `conjuncts()`
(`test_check_tag_manifest.py:689`) must return both
`github.event_name == 'push'` and `startsWith(github.ref, 'refs/tags/v')` as whole
strings, compared by equality rather than substring. That way
`push && (startsWith(…) || always())` fails. A step that runs `cosign sign` or
`cosign attest` is never exempt, whatever its env holds.

A tripwire keeps the release verify step itself non-exempt: at least one
`docker-manifest` step that runs `cosign verify` must carry the exact tag conjuncts.
This makes E1 an addition, never a replacement.

**Second amendment: the site matrix.**
`test_the_publish_sites_admit_one_cell_of_event_by_ref_by_input`
(`test_check_tag_manifest.py:1584-1677`) reads every step-level `if:` in the two
rehearsable jobs, expects exactly 12 sites, and wants every step site to admit only a
tag push. It changes to expect 13 sites, with three want-classes:
- the `docker-build` and `docker-manifest` jobs and `docker-manifest -> Install cosign`
  admit a tag push OR a rehearsal. `publish-mcp-registry (job)` stays tag-push only;
- the rehearsal verify step admits a rehearsal ONLY: not a tag push, and not a dispatch
  with the input unset;
- every other step site stays tag-push only, unchanged.

One site is added (the rehearsal step), and the installer's existing site is
reclassified. Both are named by exact label. A blanket "release or rehearse" want
would green a later edit that signs on a rehearsal.

`imagetools create` stays out of the marker inventory. The rehearsal legitimately
creates the provenance-named index (`ci.yml:744`), and the tag-publishing copy is
already pinned by the ordering test at `test_check_tag_manifest.py:1159`.

## Test plan

All tests are static tests in `scripts/release/test_check_tag_manifest.py`. The
mutation cases go in `scripts/release/test_workflow_wiring_mutations.py`, which CI runs
in the release-criteria job. Red-first means the new tests are pushed before the
workflow edit and fail for their stated reason.

| id | test | red at base because | mutation (must be caught) |
|---|---|---|---|
| T1 | a rehearsal-conditioned step in `docker-manifest` runs `cosign verify` and `verify-attestation` | no such step | delete the step |
| T2 | its cosign pieces equal the release verify step's pieces; its `timeout-minutes` equals the release step's | no such step | drop `> /dev/null` in the rehearsal step only; set its timeout to 30 |
| T3 | E1 conditions 3-5: literal env, pinned `sha256:` subjects, literal tag identity | no such step | subject `${{ steps.list.outputs.list }}`; subject `${LIST}` plus `LIST: ${{ steps.list.outputs.list }}`; identity `…@${{ github.ref }}`; a digest truncated to 63 hex |
| T4 | E1 condition 2: the exemption detector rejects a rehearsal-conditioned step that runs `cosign sign`/`attest`, `syft` or `imagetools create`; checked on inline fixture steps, so it is red-capable at base | detector does not exist | inject a rehearsal-conditioned `cosign sign --yes "${IMAGE}@${d}"` into the rehearsal step |
| T5 | every non-exempt release-sensitive step has `github.event_name == 'push'` and `startsWith(github.ref, 'refs/tags/v')` as exact top-level conjuncts | GREEN at base, not red-first: live guards already are exact conjuncts. Mutation-proved only; the release verify step must also stay non-exempt | `Cosign keyless-sign` `if:` becomes `<tag> \|\| github.event_name == 'workflow_dispatch'`; and `github.event_name == 'push' && (startsWith(github.ref, 'refs/tags/v') \|\| always())` |
| T6 | the installer admits exactly tag OR rehearsal (E2) | the installer is tag-only | installer `if:` gains `\|\| true`-shaped widening; syft installer gains the rehearsal disjunct |
| T7 | rehearsal step condition is exactly the rehearsal disjunct (no tag push) | no such step | condition becomes `always()`; the rehearse input check is dropped |
| T10 | site matrix: 13 sites; docker-build/docker-manifest jobs and installer admit tag OR rehearsal; publish-mcp-registry tag only; rehearsal step admits rehearsal only; every other step tag-push only | expects 12 sites | rehearsal step `if:` gains `\|\| (push && tag)`; the syft installer gains the rehearsal disjunct |
| T8 | in `docker-manifest`, "Install cosign" precedes the rehearsal verify step, and the rehearsal step precedes "Install syft" | no such step | move the rehearsal step above "Install cosign" |
| T9 | E1 conditions 3-4 extras: env keys equal the release step's; `for` words are `"${KEY}"` over pinned keys; the body assigns none | no such step | add `COSIGN_EXPERIMENTAL: "1"` to its env; `LIST="$(…)"` assignment in the body; a `for` word `"$(cat digests/amd64)"` |

Functional proof:
- A dispatch rehearsal (`rehearse_manifest=true`) on the branch shows the new step
  verifying all six pinned digests. Expected runtime is under 1 minute, based on
  #1143's 12 s.
- A throwaway PR whose rehearsal step drops `> /dev/null` shows the step hanging in
  rehearsal. This is the beta.2 failure, caught before a tag. The run is force-cancelled
  once it has passed 10 minutes.

**Found while building: the copy masks deletion of the release verify.** Two existing
tests read "some step runs `cosign verify`", and the rehearsal copy satisfies both. The
ordering test at `test_check_tag_manifest.py:1159` now ignores rehearsal-conditioned
steps, so a release tag must follow the release verify itself. The mutation runner
also runs `RehearsalVerify`, whose T2 reddens when either copy is edited alone. Seven
existing mutation anchors inside the verify body are widened with release-step context,
because the verbatim copy made them match twice.

## Alternatives rejected

- **Sign on rehearsal and verify the rehearsal build:** ruled out by coordinator ruling 1
  (permanent public Rekor entries).
- **Move the verify loop into a shared script called by both steps.** That gives "same
  shape" by construction, but every existing wiring test and mutation anchor reads the
  cosign command in `ci.yml` itself: ordering, the ban on swallowed failures, and the
  #1145 redirect rules. Moving it hides the command from all of them. T2 gets the same
  guarantee while the text stays where the tests look.
- **Verify the pinned digests on every PR:** this puts registry and Rekor round trips on
  the hot path of every PR for a path that only a release uses. A rehearsal is the
  existing pre-release gate.
- **Pin to "the latest release" resolved at run time:** a run-time lookup is a derived
  subject, which is exactly what E1 forbids.

## Risks and residuals

- **The pinned images are deleted from GHCR:** the rehearsal fails loudly ("manifest
  unknown"). The fix is a reviewed pin bump. Accepted.
- **beta.2 was never published under a release tag:** the pin still verifies, because
  the signatures bind digests, not tags. The identity names a tag ref that exists
  (v4.0.0-beta.2).
- **The rehearsal proves the verify path, not the signing path:** a regression in
  `cosign sign` or `cosign attest` still surfaces first on a tag. Accepted, because it
  can't be closed without signing (ruling 1).
- **A wedged runner ignores `timeout-minutes` (#1143):** a regression like beta.2 shows
  up in a rehearsal as a hang the operator must cancel, not as a red step. It still
  surfaces before the tag, which is the goal. The watchdog candidate is recorded and not
  built.
- **Env derivation is still first exercised on a tag:** the rehearsal proves the verify
  command shape, not how the release step derives `IDENTITY` from `github.ref` and its
  digests from `steps.list.outputs`. Regressions there still surface first on a tag.
  The release-step wiring tests cover them statically.
- **A static tripwire is not a shell parser:** deliberate evasion (`eval`, indirection)
  can pass E1's checks. The tests pin the spellings a normal edit would produce.
