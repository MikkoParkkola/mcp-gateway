# Merged-versus-listening drift check (NFR.SEC.7, MIK-7265)

Status: reviewed and amended, 2026-09-11. Author: automation.

Reviewed by kimi before any code existed; `gpt-review` is credit-exhausted until
2026-09-15 and the grok route returned no verdict. Four findings were taken: the
probe gained a positive half, the discrimination row lost a test-only kill switch,
the checker gained exit semantics for an unprobed manifest, and the admission rule
now says what it meant.

## 1. The gap this closes

`NFR.SEC.7` asks for two things, and the repository has neither:

1. the listening build carries every merged security control;
2. merged-versus-listening drift is detected automatically.

The second is the durable deliverable. The first is a fact about one install at
one moment, and today it is false in a way nothing in the repository can see: the
listening process (`~/.local/libexec/mcp-gateway/3.4.0-f30539af`, 127.0.0.1:39401)
answers `tools/list` with HTTP 200 and the full tool list to a foreign `Origin`
and to a foreign `Host`, sixteen days after the origin guard merged. The guard is
at `src/gateway/router/origin_guard.rs`, wired at `src/gateway/router/mod.rs:313`,
added by `5d25f104` on 2026-08-28; `git merge-base --is-ancestor 5d25f104 f30539af`
is false. Merged, and not listening.

A green suite cannot catch this, and that is the point: every test in this
repository runs against a build made from the tree under test. Drift lives in the
distance between that tree and whatever is actually answering on a port.

## 2. Ruling — probe the behaviour, corroborate with provenance

Two mechanisms were on the table.

**Provenance comparison.** Embed the build commit (a `build.rs`, surfaced on
`/health`), keep a manifest of `control -> commit that introduced it`, and assert
each control commit is an ancestor of the build commit. Cheap, covers every
control at once, and needs no traffic.

**Behavioural probe.** Each probe has two halves, and both decide. The negative half sends the request the
control exists to refuse and requires the refusal. The positive half sends a
legitimate request along the same path and requires it to succeed. Without the
second half a refusal issued for some reason of its own — an auth wall, a reverse
proxy rejecting a foreign `Host` before the gateway ever sees it, a process that
refuses everything because it is wedged — reads as the control firing, and the
check goes green against precisely the stale, proxy-fronted install it exists to
interrogate. "The control refused this" and "everything here is refused" are
different findings and the probe must tell them apart.

The design takes the probe as the verdict and provenance as corroboration, in that
order, because ancestry is a proxy: a control can be merged into the build and
disabled by configuration, shadowed by a later refactor, or wired behind a feature
flag the install does not set. The listening build would then pass an ancestry
check while serving exactly the request the criterion says it must refuse. A
proxy that can be green while the property is false is not the assertion the
criterion asks for.

Provenance still earns its place: when a probe fails, "this build predates the
control by twelve days" is the difference between a diagnosis and a mystery. So
the check reports both, and only the probe decides pass or fail.

## 3. The manifest

One file, `security-controls.toml` at the repository root, one entry per control:

```toml
[[control]]
id = "origin-guard"
description = "a cross-origin browser request is refused before dispatch"
introduced_in = "5d25f104"
source = "src/gateway/router/origin_guard.rs"
probe = "foreign-origin"
```

`probe` names a probe implemented in the checker, not a shell fragment: a probe
has to construct a request, read a response, and decide, and a string in a
manifest cannot be reviewed as code. The manifest carries what changes per
control; the checker carries what it means to test one.

The admission rule is what keeps the manifest honest: **a control is listed as
probed exactly when its absence is observable from outside the process.** A control
whose absence cannot be seen from outside cannot drift detectably, and giving it a
probe would buy a row in a report and no evidence. Such controls are still listed,
as `probe = "none"` with the reason, so the file states its own coverage instead of
implying completeness by omission.

## 4. The checker

`scripts/dev/check-control-drift.py <endpoint>`, exit non-zero on any probe whose
negative half is not refused, whose positive half does not succeed, or when no
listed control was probed at all. A `probe = "none"` row is reported as uncovered
and never contributes to a pass: a manifest that has rotted until nothing is probed
must exit non-zero, because a green with no evidence is the failure mode that makes
the whole check ornamental. Output is one line per control: `id`, both probe halves,
and the provenance note when ancestry is checkable.

Two callers:

- **CI**, against a server started from the tree under test. This does not detect
  drift — there is none by construction — it proves the probes still discriminate.
  A probe that has silently stopped exercising its control is the failure mode
  that makes the whole check ornamental, and running it where the answer is known
  is what catches that.
- **The operator, against a live install.** This is where drift is actually
  found, and it is a command rather than a job because the endpoint, the port and
  the credentials are the operator's.

The seed set is the two controls the ticket measured — foreign `Origin`, foreign
`Host` — because those are the ones with a reproduced failure. Growing the
manifest is per-control work with its own evidence; seeding it with every
plausible control would publish a coverage claim no one has tested.

## 5. Fail-first rows

| row | asserts | fails at HEAD because |
| --- | --- | --- |
| 1 | a probe against a server built from HEAD passes for every manifest control | the checker does not exist |
| 2 | a probe against a server with the origin guard removed **fails** | the checker does not exist; this is the row that proves the probe discriminates |
| 3 | a manifest entry naming a commit that is not an ancestor of the build reports drift in its provenance note, and the probe verdict still decides | no manifest, no provenance reader |
| 4 | a manifest entry with `probe = "none"` is reported as uncovered, not as passing | a checker that counts unprobed controls as green is the failure this row forbids |
| 5 | the checker exits non-zero when the endpoint refuses nothing, and distinguishes that from an endpoint that is not answering at all | an unreachable endpoint reading as "no drift" would make the check silently vacuous |

Row 2 is the load-bearing one, and it is built by compiling a server without the
control — the wiring line removed in a scratch tree — not by a runtime switch. A
test-only way to disable a security control is the "merged but disabled by
configuration" hole this design exists to catch, shipped into the codebase to test
for itself. Where compiling a variant is impractical the row falls back to a stub
server that answers everything, which still discriminates a probe that always
passes.

Row 3 manufactures its ancestry failure the same way: the manifest entry under test
names a commit that is not an ancestor of the build's, which a scratch worktree at a
pre-control commit produces without touching any real install.

## 6. What this does not do

It does not upgrade the operator's install. The first half of `NFR.SEC.7` is a
fact about a deployed process, and moving a listening service is the operator's
call, not a script's. The check makes the gap visible and dated; closing it is a
deployment.

It does not gate merges on a live endpoint. CI has no listening install, and a
job that depends on one would fail for reasons that have nothing to do with the
change under review.
