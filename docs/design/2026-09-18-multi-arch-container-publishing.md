# Multi-architecture container publishing

Status: proposed, 2026-09-18. Criterion: `NFR.PKG.1`. Ticket: MIK-7482 (second defect).
Predecessor: the startup gate, PR #568 — that closed the first defect and the test gap behind it.

## The defect

`docker manifest inspect ghcr.io/mikkoparkkola/mcp-gateway:4.0.0` lists one platform,
`linux/amd64`, and `platforms:` appears in neither publisher. On an arm64 host — every current
Mac, an increasing share of Linux servers, and a Raspberry Pi — `docker run` either refuses the
image or runs it under emulation with a warning. The operator has declared the container a
first-class run environment, so "runs only on amd64" is a falsified `NFR.PKG.1`, not a nice-to-have.

The startup gate cannot see this. It runs on the runner's own architecture, so an amd64 runner
starting an amd64 image reports healthy and tells us nothing about arm64.

## What makes this more than adding `platforms:`

Two workflows publish the same tag, independently:

| publisher | fires on | gates before it pushes | signs + attests |
|---|---|---|---|
| `.github/workflows/docker.yml` (`build`) | push to `main`, `v*` tag, PR | its own Trivy scan and startup gate | yes, on a tag |
| `.github/workflows/ci.yml` (`docker`) | `v*` tag | 17 upstream jobs, including the full test suite and `release-criteria` | yes |

Both push `ghcr.io/mikkoparkkola/mcp-gateway:<version>`. Today both push an amd64-only image, so
whichever lands last is indistinguishable from the other and the collision is invisible. The moment
one of them produces a two-platform manifest list and the other does not, the last writer decides
whether arm64 users can pull at all — a race whose outcome is a published release artifact. Adding
`platforms:` to one publisher would therefore introduce a defect while fixing one.

A second consequence of the current arrangement is already live: `docker.yml` publishes a tagged
image as soon as its own scan and startup gate pass, which is before the test suite has run.
A release image can exist for a tag whose tests later fail.

## Options

| # | approach | why not / why |
|---|---|---|
| 1 | `platforms: linux/amd64,linux/arm64` on the existing `docker/build-push-action` step, arm64 under QEMU | One line, and it is the wrong line. A release build of this crate under emulated aarch64 is a multi-hour compile against a 6-hour job ceiling, and the emulated container cannot be started for the startup gate any more meaningfully than it is built. Also does nothing about the two-publisher race. |
| 2 | Native matrix (`ubuntu-latest` + `ubuntu-24.04-arm`), each leg pushing by digest, a merge step creating the manifest list | Each leg compiles natively — `release.yml:176` already builds `aarch64-unknown-linux-musl` on `ubuntu-24.04-arm`, so the toolchain and the runner label are proven in this repo — and each leg starts its own image on its own architecture, which is the only way the arm64 gap becomes observable. Chosen. |
| 3 | Cross-compile inside the Dockerfile's builder stage | Keeps one runner but puts a cross toolchain, a second sysroot and per-target linker configuration into the image build, for a build that native runners do for free. Rejected: more moving parts than option 2, and it still leaves the startup gate blind on arm64. |

On the race, given option 2:

| # | who owns the release tag | assessment |
|---|---|---|
| A | Both, as today | Rejected. Two manifests for one tag, last writer wins. |
| B | `docker.yml` publishes the list; `ci.yml`'s `docker` job verifies the published manifest instead of pushing | Removes the race, but leaves publishing gated only on scan + smoke, and makes a `ci.yml` job wait on another workflow it cannot order itself against. |
| C | `ci.yml`'s `docker` job publishes the list; `docker.yml` stops pushing on tags and keeps building, scanning and smoke-testing for `main` and PRs | Chosen. One publisher, and it is the one already gated on the full release suite: an image for a tag cannot exist before the tests that qualify that tag have passed. `docker.yml` keeps every gate it has for the branch and PR path, so a startup break is still caught on the PR that introduces it, not at the tag. |

## The design

In `ci.yml`, the `docker` job becomes three:

1. `docker-build` — matrix `{ubuntu-latest → linux/amd64, ubuntu-24.04-arm → linux/arm64}`.
   Per leg, in this order:
   - build once with
     `outputs: type=image,name=ghcr.io/…/mcp-gateway,push-by-digest=true,name-canonical=true,push=true`
     and record the returned digest;
   - `docker pull ghcr.io/…/mcp-gateway@sha256:<digest>`;
   - Trivy-scan and run `scripts/ci/smoke-image.sh` against that digest reference — natively, so the
     arm64 leg's verdict is a real arm64 verdict;
   - write the digest to a per-arch artifact.

   Building once and starting the pulled digest is deliberate: the alternative — build-and-load,
   smoke, then build-and-push — makes "the bytes that reached `healthy` are the bytes published"
   depend on a build-cache hit across two invocations, and this image runs `apt-get upgrade`, whose
   output is not a function of the Dockerfile. Here the published blob is the tested blob by
   construction. `push-by-digest` publishes it with no tag, so nothing is resolvable by name and a
   failed leg leaves only an untagged, garbage-collectable blob.
2. `docker-manifest` — `needs: docker-build`, reads both digests and runs
   `docker buildx imagetools create --tag …:<version> [--tag …:latest] <digest>@sha256:…` once.
   The tag appears only here, and only after both legs have started their own image.
   `:latest` keeps its existing prerelease condition.
3. Signing, SBOM generation and verification move to `docker-manifest` and run against the manifest
   list's digest, plus each leg's digest — cosign signs what a client resolves, and a client on
   arm64 resolves the arm64 child, so signing only the list would leave the child unverifiable
   under `cosign verify` with a platform-specific reference.

In `docker.yml`, the `Build and push` step's `push:` becomes false for tags — the job keeps
checkout, buildx, metadata, the scan build, Trivy, and the startup gate. Its cosign, SBOM and
verify steps, all of which are `if: startsWith(github.ref, 'refs/tags/v')`, are removed with the
tag push they attest.

## Acceptance

1. `docker buildx imagetools inspect ghcr.io/mikkoparkkola/mcp-gateway:<version>` lists exactly
   `linux/amd64` and `linux/arm64`.
2. Both matrix legs report `starts and its own HEALTHCHECK reports healthy` in their own job log,
   the arm64 line produced on an arm64 runner.
3. `cosign verify` succeeds against the list reference and against
   `<image>:<version>` resolved for each platform.
4. No tag exists in GHCR for a run whose matrix did not complete: kill the arm64 leg deliberately
   on a scratch tag and confirm no tag was created.
5. `docker.yml` on a tag pushes nothing: its own run log shows the scan build and the startup gate
   and no push, and the tag's manifest list has exactly one creator.

## Falsifier

Run the new matrix against a scratch tag (`v0.0.0-archtest`) in a throwaway package, then pull the
resulting list on this arm64 Mac with `--platform linux/arm64` and no emulation warning, and start
it. If the arm64 child does not run natively there, the design has not met the criterion it was
written for, whatever CI says.

## Out of scope, stated

- `main`-branch and PR images stay amd64-only. They are built for the scan and the startup gate and
  are not what `NFR.PKG.1` governs; making the dev path multi-arch doubles every PR's image build
  for no release guarantee. If a developer on arm64 needs a native dev image, that is a separate ask.
- No new platforms beyond `linux/arm64`. `linux/arm/v7` and `linux/s390x` have no stated user.
- Helm chart and air-gap bundle wiring are untouched; they reference the tag, which keeps its name.

## Review record

Both non-Claude reviewers returned SHIP on the startup gate that precedes this design
(`~/.claude/data/reviews/runs/kimi-20260918T165900Z-35177.md`,
`grok-20260918T165900Z-34980.md`). Three findings, all folded in rather than deferred:

| finding | reviewer | disposition |
|---|---|---|
| An image declaring no `HEALTHCHECK` times out at 90s with a misleading message | both | fixed in `9918aa18`, and an unreadable image is now reported as its own fault |
| `Health.Status=unhealthy` should fail on first sight, not burn the remaining budget | grok | fixed: `unhealthy` is the probe's own verdict after its configured retries, so waiting cannot change it |
| The published bytes equal the tested bytes only via a build-cache hit | grok | this design's build order is the fix — push by digest, pull that digest, test it, tag it |

The `docker.yml` path for `main` still builds twice (scan build, then push build), so the third
finding survives there. It is out of this criterion's scope: `main` images are not release
artifacts and `NFR.PKG.1` names the published release image.
