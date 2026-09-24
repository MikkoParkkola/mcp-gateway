# Releasing mcp-gateway

This is the operator's runbook for cutting a final release (written for `v4.0.0`) and
for recovering a release that published some artifacts and not others. Every job and
step named here exists in `.github/workflows/release.yml`, `.github/workflows/ci.yml`
or `.github/workflows/docker.yml`, or under `scripts/release/`; if a name here stops
matching, the workflow changed and this file is stale.

For a release candidate (`v4.0.0-rc.N`) see
[`docs/release/v4.0.0-prerelease-channel.md`](docs/release/v4.0.0-prerelease-channel.md),
which lists what each channel does on a prerelease tag.

## What a tag push starts

Pushing a `v*` tag starts three workflows at once. None of them can wait for, or read
outputs from, another:

| Workflow | Publishes | Jobs, in order |
|---|---|---|
| `release.yml` | GitHub release + binaries, crates.io, npm, Homebrew tap | `security-gate`, `secret-leak-lint`, `release-criteria`, `task-sdk-recovery` → `verify` → `build` → `release` → `publish`, `npm-publish`, `homebrew-update` (in parallel) |
| `ci.yml` | ghcr.io images (`:VERSION`, `:latest`, `:MAJOR.MINOR`, each also `-full`), MCP Registry listing | the CI suite plus `release-criteria` → `docker-build` (amd64, arm64) → `docker-manifest` → `publish-mcp-registry` |
| `docker.yml` | nothing on a tag | builds, scans and smoke-tests the image; its push steps are off on tags |

The VS Code and Cursor install buttons in `README.md` are deeplinks that run
`mcp-gateway serve --stdio` from the user's `PATH`. No workflow publishes them, so there
is nothing to publish or recover there. They pick up whichever binary the user installed
through one of the channels above.

**crates.io can publish while the image fails.** `release.yml`'s `publish` job does not
depend on `ci.yml`. If `docker-build` fails Trivy or its smoke test, crates.io, npm,
Homebrew and the GitHub release can all be live with no image. That state is expected
and recoverable; see [Recovery](#recovery-from-a-partial-publish).

**Nothing after the tag asks a human.** No publishing job declares an `environment:`,
so there is no approval step. Once the gates below pass on the tag, `cargo publish` runs.
The tag push is the point of no return.

## Gates on the tag, and what they do not check

`release.yml` `verify` runs `Check tag against manifest and classify the channel`
(`scripts/release/check_tag_manifest.py`). `ci.yml` `docker-build`/`docker-manifest` run
the same script in their `Extract tag` steps. **Exit 0 from `check_tag_manifest.py` is
necessary, not sufficient.** It checks that the tag, `Cargo.toml` and `Cargo.lock` agree
on the version and classifies stable versus prerelease. It says nothing about whether the
release is ready.

Readiness is gated by the `release-criteria` job (in both `release.yml` and `ci.yml`), in
particular `Require completed acceptance in publishing context`, which runs
`scripts/release/check_scope_acceptance.py --publish-check`. On a tag whose version is
`4.0.0` (including `4.0.0-rc.N`) it exits 1 while any scope criterion is pending. That
makes it the gate that keeps an accidental tag push from reaching crates.io. It checks
only what the ledgers record, so it is only as good as their grading.

## Final-release sequence

Run from a clean checkout of the release commit (the tip of the release line).

### 1. Preconditions (before any tag exists)

```sh
git fetch origin && git switch --detach origin/docs/ranking-1-release-line   # or the release branch
git status --short                                  # must print nothing

python3 scripts/release/check_tag_manifest.py --tag v4.0.0   # exit 0 (necessary, not sufficient)
python3 scripts/release/count-release-criteria.py --check    # exit 0: ledger header matches rows
bash scripts/release/check-cited-commits.sh HEAD             # exit 0: every cited commit is on this line
python3 scripts/release/check_scope_acceptance.py --release  # exit 0: no pending scope criterion
```

`check_scope_acceptance.py --release` is the local equivalent of the tag-time
`--publish-check`. If it lists pending criteria, stop: the tag run will fail at
`release-criteria` and publish nothing. Better to find that out here than from a red run. NFR.PKG.1 and
NFR.SEC.7 are among the criteria it reads, so it cannot pass until steps 2 and 3 have run
and their evidence is graded in the ledger. Run steps 2 and 3, then run this block again.

The ledger records a circularity in NFR.PKG.1: as worded it asks for the image a tag
publishes, and the tag is gated on the criterion. Step 2 is the pre-tag evidence the
workflow provides. Whether that evidence is enough to grade the row is the ledger
owner's decision, not this runbook's.

Also check the manual item `release.yml` names in its `secret-leak-lint` comment: no open
P0/P1 security tickets in the tracker. No gate automates that.

The CI run for the release commit must be green on the release branch, including
`public-claims` and the helm/usability smoke jobs, all of which `docker-build` needs.

### 2. Rehearse the container publish (NFR.PKG.1, before the tag)

`docker-build` and `docker-manifest` otherwise run for the first time on the real tag.
`ci.yml`'s `workflow_dispatch` input `rehearse_manifest` runs them on a branch. Each leg
builds natively, pushes by digest, runs `Smoke test the image (it must start and report
healthy)` and `Smoke test the full variant (it must spawn npx and uvx)`, and
`docker-manifest` stops after `Assert the list carries both platforms`. No release tag,
signature or registry listing is created.

```sh
gh workflow run ci.yml --ref docs/ranking-1-release-line -f rehearse_manifest=true
gh run watch "$(gh run list --workflow ci.yml --event workflow_dispatch -L1 --json databaseId -q '.[0].databaseId')"
```

Pass: both `Docker (amd64)` and `Docker (arm64)` green, and `Docker manifest list` green
through `Assert the list carries both platforms`.

### 3. Deploy the release build to the listening gateway (NFR.SEC.7)

NFR.SEC.7 closes when the gateway actually listening on `127.0.0.1:39401` carries the
merged security controls. The cutover is the operator's step. Follow
[`docs/runbooks/nfr-sec-7-cutover.md`](docs/runbooks/nfr-sec-7-cutover.md), not the
superseded `docs/internal/release/2026-09-17-nfr-sec-7-closure-runbook.md`. Before the tag,
use the runbook's self-build option (1b) on the release commit. After the tag (step 6
below), repeat with option 1a against the `v4.0.0` `mcp-gateway-darwin-arm64` asset: set
`NEW` to the release version and check the digest against that release's
`SHA256SUMS.txt` line, not the digest the runbook hard-codes for an older release.

Pass: the runbook's step 7 command exits 0.

```sh
python3 scripts/dev/check-control-drift.py http://127.0.0.1:39401/mcp
```

### 4. Tag and push, once

```sh
git tag -a v4.0.0 -m "mcp-gateway 4.0.0"
git push origin v4.0.0          # this tag only; never `git push --tags`
```

Record the run IDs of the three workflows:

```sh
gh run list --commit "$(git rev-parse HEAD)" --event push --json workflowName,databaseId,status
```

### 5. Watch each stage and verify before trusting the next

| Stage (job) | Verify |
|---|---|
| `release.yml` `verify` | `Check tag against manifest and classify the channel` classified the tag as `stable`; `Verify publish package` (`cargo publish --dry-run`) green |
| `release.yml` `release` | `gh release view v4.0.0` shows 5 binaries, the license files and `SHA256SUMS.txt`; not marked prerelease. Download and run `sha256sum -c SHA256SUMS.txt` |
| `release.yml` `publish` | `cargo search mcp-gateway --limit 1` shows `4.0.0`; `cargo install mcp-gateway --version 4.0.0` succeeds |
| `release.yml` `npm-publish` | `npm view @mikkoparkkola/mcp-gateway dist-tags` shows `latest: 4.0.0`; `npm view @mikkoparkkola/mcp-gateway@4.0.0 dist.attestations` is present |
| `release.yml` `homebrew-update` | `MikkoParkkola/homebrew-tap` has commit `mcp-gateway 4.0.0`; `brew update && brew upgrade mcp-gateway && mcp-gateway --version` prints 4.0.0 |
| `ci.yml` `docker-build` | both legs green, including the Trivy and both smoke-test steps, against the pushed digest |
| `ci.yml` `docker-manifest` | `Verify the release signature + SBOM attestation` and `Assert the release tag resolves to the signed digest` green |
| `ci.yml` `publish-mcp-registry` | `Confirm the published reference resolves before listing it` and `Publish to MCP Registry` green |

### 6. Post-publish checks against the published names

CI evidence is by digest, from inside the run. These checks exercise the names users pull.

**NFR.PKG.1, the published image starts and serves.** `scripts/ci/smoke-image.sh` is the
same gate `docker-build` runs. It starts the container, waits for its `HEALTHCHECK`, makes
an MCP request over a published port from outside the container, and checks the
no-config first run. Run it on a Linux host against the released tag:

```sh
scripts/ci/smoke-image.sh ghcr.io/mikkoparkkola/mcp-gateway:4.0.0
scripts/ci/smoke-full-image.sh ghcr.io/mikkoparkkola/mcp-gateway:4.0.0-full
```

A host only pulls its own architecture. Run it on both an amd64 and an arm64 host, or
cite the per-architecture CI legs (`Docker (amd64)`, `Docker (arm64)`) for the
architecture you did not run. Also confirm the stable pointers moved and are signed:

```sh
for t in 4.0.0 4.0 latest; do crane digest ghcr.io/mikkoparkkola/mcp-gateway:$t; done   # all three equal
cosign verify ghcr.io/mikkoparkkola/mcp-gateway@"$(crane digest ghcr.io/mikkoparkkola/mcp-gateway:4.0.0)" \
  --certificate-identity https://github.com/MikkoParkkola/mcp-gateway/.github/workflows/ci.yml@refs/tags/v4.0.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com   # the identity ci.yml signs with
```

**NFR.SEC.7, deploy the release build to the listening gateway.** Repeat step 3 with the
published `v4.0.0` `mcp-gateway-darwin-arm64` asset (runbook option 1a), then run
`check-control-drift.py http://127.0.0.1:39401/mcp`. Now that the tag exists, its
provenance note can corroborate `v4.0.0`. Pass is exit 0.

Record both results as evidence for the criteria ledger. The ledger owner grades them;
this runbook does not edit the ledger.

## Recovery from a partial publish

### Rules that apply to every target

1. **Re-run failed jobs in the same run. Do not re-push the tag or dispatch a new run.**
   `gh run rerun <run-id> --failed` re-runs only the failed jobs and the jobs that depend
   on them. A fresh run (a re-pushed tag, or `release.yml`'s `workflow_dispatch` with
   `tag: v4.0.0`) repeats every publish that already succeeded. On crates.io and npm that
   is a hard failure, because the version already exists.
2. **A red publish job does not prove nothing was published.** `cargo publish` can upload
   the crate and then fail while it waits for the index. `npm publish` can fail after the
   registry has accepted the tarball. Query the registry (step 5's commands) before any
   re-run.
3. **Do not move or delete the `v4.0.0` git tag once anything is published.** crates.io
   and npm hold the tag's contents for good, and Homebrew and the MCP Registry point at
   that tag's assets and images. A fix ships forward as `4.0.1`.
4. **The build artifacts expire after one day.** `release.yml` `build` uploads with
   `retention-days: 1`. Re-running `release` more than about 24 hours later finds nothing
   to download. A full re-run (`gh run rerun <run-id>`) is safe only in that situation:
   `publish`, `npm-publish` and `homebrew-update` all need `release`, so none of them has
   run yet.

### Per target

| Target (job) | Mutable once published? | Half-finished state | Recovery | Verify |
|---|---|---|---|---|
| Gate jobs, `verify`, `build` (`release.yml`) | Nothing published | Run red before `release` | Fix on the branch, then delete and re-create the tag **only if** `gh release view v4.0.0`, `cargo search` and `npm view` all show no 4.0.0 and `ci.yml` published no image (check `crane digest ...:4.0.0` fails). Otherwise treat it as published and fix forward | Registry queries in step 5 |
| GitHub release (`release`) | Yes: assets can be edited or deleted | Release exists with some or no assets, or the job failed after `Create Release` | `gh run rerun <run-id> --failed` (within the artifact window). Check whether the repository has GitHub immutable releases enabled, and whether `softprops/action-gh-release` replaces existing assets, before relying on a re-run to overwrite them. **Never replace an asset after `homebrew-update` ran**: the formula pins the SHA-256 values from `SHA256SUMS.txt` | `gh release view v4.0.0 --json assets`; `sha256sum -c SHA256SUMS.txt` |
| crates.io (`publish`) | **No.** A version can never be re-published or deleted, only yanked | Published or not; the job's colour does not tell you which (rule 2) | Not published: `gh run rerun <run-id> --failed`. Published but broken: `cargo yank --version 4.0.0 mcp-gateway`, fix, release `4.0.1` through this runbook | `cargo search mcp-gateway`; `cargo info mcp-gateway@4.0.0` |
| npm (`npm-publish`) | **No.** npm refuses to reuse a version number, even after an unpublish ([npm unpublish policy](https://docs.npmjs.com/policies/unpublish)) | Published with or without provenance, or not at all | Not published: re-run failed jobs. Published but broken: `npm deprecate @mikkoparkkola/mcp-gateway@4.0.0 "<reason>"` and ship `4.0.1`. If `latest` points wrong: `npm dist-tag add @mikkoparkkola/mcp-gateway@<good> latest` | `npm view @mikkoparkkola/mcp-gateway dist-tags versions` |
| Homebrew tap (`homebrew-update`) | Yes, it is a git commit | Formula not bumped, or bumped against assets that later changed | Re-run failed jobs. `Commit and push formula bump` exits 0 if the formula is already current, so a re-run is idempotent. A bad bump: `git revert` in `MikkoParkkola/homebrew-tap` | `brew fetch --force mcp-gateway` (checks the SHA-256 values); `brew test mcp-gateway` |
| ghcr.io images (`ci.yml` `docker-build`, `docker-manifest`) | Tags yes, digests no. Signatures and SBOMs attach to digests | `docker-build` red: no release tag exists (legs push by digest only). `docker-manifest` red: the index exists under its provenance `sha-` tag, and `:4.0.0` exists only if `Publish the release tags (copy the verified index by digest)` ran | Re-run failed jobs in the `ci.yml` run. `docker buildx imagetools create` onto the same verified digest is idempotent. If a tag points at the wrong digest, re-point it with `docker buildx imagetools create --tag ghcr.io/mikkoparkkola/mcp-gateway:<tag> ghcr.io/mikkoparkkola/mcp-gateway@<signed digest>`. Delete stray package versions in the GitHub Packages UI | `Assert the release tag resolves to the signed digest` green; step 6 checks |
| MCP Registry (`ci.yml` `publish-mcp-registry`) | Assume not. Check the registry's current documentation before trying to change a published version | Not listed, or listed pointing at `:4.0.0` | Not listed: re-run failed jobs once `:4.0.0` resolves. The job refuses to list an image reference that does not resolve | The registry entry names `ghcr.io/mikkoparkkola/mcp-gateway:4.0.0` |
| VS Code / Cursor | No publisher | None | Nothing to recover; the deeplinks run the installed binary | `mcp-gateway --version` on the installing host |

### If the image fails but everything else shipped

This is the most likely partial state, because the two workflows gate independently. The
binary channels are fine to leave live. Fix the image defect on the branch. If the fix
changes no crate code, re-run `ci.yml` failed jobs where possible. If the image cannot be
built from the `v4.0.0` commit, the image ships with `4.0.1` along with everything else.
Do not push a second tag at the same version.
